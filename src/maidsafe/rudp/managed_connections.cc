/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#include "maidsafe/rudp/managed_connections.h"

#include <algorithm>
#include <functional>
#include <iterator>
#include <map>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

// 203.0.113.14:1314
const boost::asio::ip::udp::endpoint kNonRoutable(boost::asio::ip::address_v4(3405803790U), 1314);


namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;
typedef std::shared_ptr<detail::Transport> TransportPtr;

}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(Parameters::thread_count),
      message_received_functor_(),
      connection_lost_functor_(),
      this_node_id_(),
      private_key_(),
      public_key_(),
      connections_(),
      mutex_(),
      local_ip_(),
      nat_type_(NatType::kUnknown) {}

ManagedConnections::~ManagedConnections() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto element : connections_)
      element.second->Close();
  }
//  resilience_transport_.Close();
  asio_service_.Stop();
}

NodeId ManagedConnections::Bootstrap(const std::vector<Endpoint>& bootstrap_endpoints,
                                     bool /*start_resilience_transport*/,
                                     MessageReceivedFunctor message_received_functor,
                                     ConnectionLostFunctor connection_lost_functor,
                                     NodeId this_node_id,
                                     std::shared_ptr<asymm::PrivateKey> private_key,
                                     std::shared_ptr<asymm::PublicKey> public_key,
                                     NatType& nat_type,
                                     Endpoint local_endpoint) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto element : connections_)
      element.second->Close();
//    resilience_transport_.DisconnectSignalsAndClose();
    connections_.clear();
  }

  if (!message_received_functor) {
    LOG(kError) << "You must provide a valid MessageReceivedFunctor.";
    return NodeId();
  }
  if (!connection_lost_functor) {
    LOG(kError) << "You must provide a valid ConnectionLostFunctor.";
    return NodeId();
  }
  if (!this_node_id.IsValid()) {
    LOG(kError) << "You must provide a valid NodeId.";
    return NodeId();
  }
  this_node_id_ = this_node_id;
  if (!private_key || !asymm::ValidateKey(*private_key) ||
      !public_key || !asymm::ValidateKey(*public_key)) {
    LOG(kError) << "You must provide a valid private and public key.";
    return NodeId();
  }
  private_key_ = private_key;
  public_key_ = public_key;

  if (bootstrap_endpoints.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap endpoint.";
    return NodeId();
  }

  asio_service_.Start();

  bool zero_state(detail::IsValid(local_endpoint));

  if (zero_state) {
    local_ip_ = local_endpoint.address();
  } else {
    local_ip_ = GetLocalIp();
    if (local_ip_.is_unspecified()) {
      LOG(kError) << "Failed to retrieve local IP.";
      return NodeId();
    }
    local_endpoint = Endpoint(local_ip_, 0);
  }

  NodeId chosen_bootstrap_node_id;
  if (!StartNewTransport(bootstrap_endpoints, local_endpoint, chosen_bootstrap_node_id)) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return NodeId();
  }
  nat_type = nat_type_;

  // Add callbacks now.
  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;

//  if (start_resilience_transport)
//    asio_service_.service().post([=] { StartResilienceTransport(); });  // NOLINT (Fraser)

//  return (zero_state ? NodeId() : chosen_bootstrap_node_id);
  return chosen_bootstrap_node_id;
}

bool ManagedConnections::StartNewTransport(std::vector<Endpoint> bootstrap_endpoints,
                                           Endpoint local_endpoint,
                                           NodeId& chosen_bootstrap_node_id) {
  TransportPtr transport(new detail::Transport(asio_service_, nat_type_));
  bool bootstrap_off_existing_connection(bootstrap_endpoints.empty());
  boost::asio::ip::address external_address;
  if (bootstrap_off_existing_connection)
    GetBootstrapEndpoints(bootstrap_endpoints, external_address);
  //else
  //  bootstrap_endpoints.insert(bootstrap_endpoints.begin(), Endpoint(local_ip_, kResiliencePort()));

  transport->Bootstrap(
      bootstrap_endpoints,
      this_node_id_,
      public_key_,
      local_endpoint,
      bootstrap_off_existing_connection,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2, _3, _4),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3),
      boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, _1, _2, _3, _4),
      chosen_bootstrap_node_id);
  if (chosen_bootstrap_node_id == NodeId() && nat_type_ != NatType::kSymmetric) {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(kWarning) << "Failed to start a new Transport.";
    transport->Close();
    return false;
  }

  if (!detail::IsValid(transport->external_endpoint()) && !external_address.is_unspecified()) {
    // Means this node's NAT is symmetric or unknown, so guess that it will be mapped to existing
    // external address and local port.
    transport->SetBestGuessExternalEndpoint(Endpoint(external_address,
                                                     transport->local_endpoint().port()));
  }

  LOG(kVerbose) << "Started a new transport on " << transport->external_endpoint() << " / "
                << transport->local_endpoint() << " - NAT: " << static_cast<int>(nat_type_);
  return true;
}

void ManagedConnections::GetBootstrapEndpoints(std::vector<Endpoint>& bootstrap_endpoints,
                                               boost::asio::ip::address& this_external_address) {
  bool external_address_consistent(true);
  // Favour connections which are on a different network to this to allow calculation of the new
  // transport's external endpoint.
  std::vector<Endpoint> secondary_endpoints;
  bootstrap_endpoints.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  secondary_endpoints.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    Endpoint this_endpoint_as_seen_by_peer(element.second->ThisEndpointAsSeenByPeer(element.first));
    if (detail::OnPrivateNetwork(this_endpoint_as_seen_by_peer)) {
      secondary_endpoints.push_back(this_endpoint_as_seen_by_peer);
    } else {
      bootstrap_endpoints.push_back(this_endpoint_as_seen_by_peer);
      if (this_external_address.is_unspecified())
        this_external_address = this_endpoint_as_seen_by_peer.address();
      else if (this_external_address != this_endpoint_as_seen_by_peer.address())
        external_address_consistent = false;
    }
  }
  if (!external_address_consistent)
    this_external_address = boost::asio::ip::address();
  std::random_shuffle(bootstrap_endpoints.begin(), bootstrap_endpoints.end());
  std::random_shuffle(secondary_endpoints.begin(), secondary_endpoints.end());
  bootstrap_endpoints.insert(bootstrap_endpoints.end(),
                             secondary_endpoints.begin(),
                             secondary_endpoints.end());
}

int ManagedConnections::GetAvailableEndpoint(NodeId peer_id,
                                             EndpointPair peer_endpoint_pair,
                                             EndpointPair& this_endpoint_pair,
                                             NatType& this_nat_type) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.empty()) {
      LOG(kError) << "No running Transports.";
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      this_nat_type = NatType::kUnknown;
      return kNotBootstrapped;
    }

    if (GetThisEndpointPair(peer_id, this_endpoint_pair)) {
      this_nat_type = nat_type_;
      return kSuccess;
    }
  }

  bool start_new_transport(false);
  if (nat_type_ == NatType::kSymmetric) {
    if (detail::IsValid(peer_endpoint_pair.external))
      start_new_transport = true;
    else
      start_new_transport = !detail::IsValid(peer_endpoint_pair.local);
  } else {
    start_new_transport = (static_cast<int>(connections_.size()) < Parameters::max_transports);
  }

  if (start_new_transport) {
    NodeId chosen_bootstrap_node_id;
    if (!StartNewTransport(std::vector<Endpoint>(), Endpoint(local_ip_, 0),
                           chosen_bootstrap_node_id)) {
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      std::lock_guard<std::mutex> lock(mutex_);
      this_nat_type = NatType::kUnknown;
      return kTransportStartFailure;
    }
  }

  // Check again in case a previous attempt has completed.
  std::lock_guard<std::mutex> lock(mutex_);
  this_nat_type = nat_type_;
  if (GetThisEndpointPair(peer_id, this_endpoint_pair))
    return kSuccess;

  // Get transport with least connections.
  size_t least_connections(detail::Transport::kMaxConnections());
  TransportPtr selected_transport;
  for (auto element : connections_) {
    if (element.second->NormalConnectionsCount() < least_connections) {
      least_connections = element.second->NormalConnectionsCount();
      selected_transport = element.second;
    }
  }

  if (selected_transport) {
    this_endpoint_pair.local = selected_transport->local_endpoint();
    this_endpoint_pair.external = selected_transport->external_endpoint();
    selected_transport->AddPending(peer_id, peer_endpoint_pair.external);
  } else {
    LOG(kError) << "All connectable Transports are full.";
    this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
    return kFull;
  }
  return kSuccess;
}

bool ManagedConnections::GetThisEndpointPair(const NodeId& peer_id,
                                             EndpointPair& this_endpoint_pair) {
  for (auto element : connections_) {
    if (element.second->HasNormalConnectionTo(peer_id)) {
      this_endpoint_pair.external = element.second->external_endpoint();
      this_endpoint_pair.local = element.second->local_endpoint();
      return true;
    }
  }

  this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
#ifndef NDEBUG
//      } else {
//        std::string msg("Expected to find a connection to ");
//        msg += peer_endpoint.address().to_string() + ":";
//        msg += boost::lexical_cast<std::string>(peer_endpoint.port());
//        msg += " in map, but map only contains\n";
//        for (auto conn : connection_map_) {
//          msg += conn.first.address().to_string() + ":";
//          msg += boost::lexical_cast<std::string>(conn.first.port()) + "\n";
//        }
//        LOG(kInfo) << msg;
#endif
  return false;
}

int ManagedConnections::Add(NodeId peer_id,
                            EndpointPair peer_endpoint_pair,
                            std::string validation_data) {
  if (!peer_id.IsValid()) {
    LOG(kError) << "Invalid peer_id passed.";
    return kInvalidId;
  }
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }
  if (validation_data.empty()) {
    LOG(kError) << "Invalid validation_data passed.";
    return kEmptyValidationData;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    std::shared_ptr<detail::Connection> connection(element.second->GetConnection(peer_id));
    if (connection) {
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        connection->StartSending(validation_data,
                                 [](int result) {
                                   if (result != kSuccess) {
                                     LOG(kWarning) << "Failed to send validation data on bootstrap "
                                                   << "connection.  Result: " << result;
                                   }
                                 });
        return kSuccess;
      } else {
        LOG(kError) << "A managed connection from " << DebugId(this_node_id_) << " to "
                    << DebugId(peer_id) << " already exists";
        return kConnectionAlreadyExists;
      }
    } else {
      if (element.second->RemovePending(peer_id)) {
        element.second->Connect(peer_id, peer_endpoint_pair, validation_data);
        return kSuccess;
      }
    }
  }

  LOG(kError) << "No connection attempt from " << DebugId(this_node_id_) << " to "
              << DebugId(peer_id) << " - ensure GetAvailableEndpoint has been called first.";
  return kNoPendingConnectAttempt;
}

int ManagedConnections::MarkConnectionAsValid(NodeId peer_id, Endpoint& peer_endpoint) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    if (element.second->MakeConnectionPermanent(peer_id, peer_endpoint))
      return kSuccess;
  }
  LOG(kWarning) << "Can't mark connection from " << DebugId(this_node_id_) << " to "
                << DebugId(peer_id) << " as valid - not in map.";
  peer_endpoint = Endpoint();
  return kInvalidConnection;
}

void ManagedConnections::Remove(NodeId peer_id) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    if (element.second->CloseConnection(peer_id))
      return;
  }
  LOG(kWarning) << "Can't remove connection from " << DebugId(this_node_id_) << " to "
                << DebugId(peer_id) << " - not in map.";
}

void ManagedConnections::Send(NodeId peer_id,
                              std::string message,
                              MessageSentFunctor message_sent_functor) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    if (element.second->Send(peer_id, message, message_sent_functor))
      return;
  }
  LOG(kError) << "Can't send from " << DebugId(this_node_id_) << " to " << DebugId(peer_id)
              << " - not in map.";
  if (message_sent_functor) {
    if (!connections_.empty()) {
      asio_service_.service().post([message_sent_functor] {
        message_sent_functor(kInvalidConnection);
      });
    } else {
      // Probably haven't bootstrapped, so asio_service_ won't be running.
      boost::thread(message_sent_functor, kInvalidConnection);
    }
  }
}

//void ManagedConnections::Ping(Endpoint peer_endpoint, PingFunctor ping_functor) {
//  if (!ping_functor) {
//    LOG(kWarning) << "No functor passed - not pinging.";
//    return;
//  }
//
//  if (connections_.empty()) {
//    LOG(kError) << "No running Transports.";
//    // Probably haven't bootstrapped, so asio_service_ won't be running.
//    boost::thread(ping_functor, kNotBootstrapped);
//    return;
//  }
//
//  std::lock_guard<std::mutex> lock(mutex_);
//  // Check this node isn't already connected to peer
//  if (connection_map_.find(peer_endpoint) != connection_map_.end()) {
//    asio_service_.service().post([ping_functor] { ping_functor(kWontPingAlreadyConnected); });  // NOLINT (Fraser)
//    return;
//  }
//
//  // Check we're not trying to ping ourself
//  if (std::find_if(connections_.begin(),
//                   connections_.end(),
//                   [&peer_endpoint](const TransportAndSignalConnections& tprt_and_sigs_conns) {
//                     return tprt_and_sigs_conns.transport->local_endpoint() == peer_endpoint ||
//                            tprt_and_sigs_conns.transport->external_endpoint() == peer_endpoint;
//                   }) != connections_.end()) {
//    LOG(kError) << "Trying to ping ourself.";
//    asio_service_.service().post([ping_functor] { ping_functor(kWontPingOurself); });  // NOLINT (Fraser)
//    return;
//  }
//
//  size_t index(RandomUint32() % connections_.size());
//  connections_[index].transport->Ping(peer_endpoint, ping_functor);
//}
//
//void ManagedConnections::StartResilienceTransport() {
//  resilience_transport_.transport = std::make_shared<detail::Transport>(asio_service_, nat_type_);
//  std::vector<Endpoint> bootstrap_endpoints;
//  boost::asio::ip::address external_address;
//  GetBootstrapEndpoints(Endpoint(local_ip_, 0), bootstrap_endpoints, external_address);
//
//  Endpoint chosen_endpoint;
//  resilience_transport_.transport->Bootstrap(
//      bootstrap_endpoints,
//      public_key_,
//      Endpoint(local_ip_, ManagedConnections::kResiliencePort()),
//      true,
//      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
//      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2),
//      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3, _4),
//      boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, _1, _2, _3, _4),
//      &chosen_endpoint,
//      &resilience_transport_.on_message_connection,
//      &resilience_transport_.on_connection_added_connection,
//      &resilience_transport_.on_connection_lost_connection);
//
//  if (!detail::IsValid(chosen_endpoint))
//    resilience_transport_.DisconnectSignalsAndClose();
//}

void ManagedConnections::OnMessageSlot(const std::string& message) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(kVerbose) << "\n^^^^^^^^^^^^ OnMessageSlot ^^^^^^^^^^^^\n" + DebugString();
  }

  std::string decrypted_message;
  int result(asymm::Decrypt(message, *private_key_, &decrypted_message));
  if (result != kSuccess) {
    LOG(kError) << "Failed to decrypt message.  Result: " << result;
  } else {
    asio_service_.service().post([=] { message_received_functor_(decrypted_message); });  // NOLINT (Fraser)
  }
}

void ManagedConnections::OnConnectionAddedSlot(const NodeId& peer_id,
                                               detail::TransportPtr transport,
                                               bool temporary_connection,
                                               bool& is_duplicate_normal_connection) {
  std::string s("\n++++++++++++ OnConnectionAddedSlot ++++++++++++\nAdding ");
  s += (temporary_connection ? "temporary" : "non-temporary");
  s += " connection from ";
  s += transport->ThisDebugId() + " to " + DebugId(peer_id).substr(0, 7) + '\n' + DebugString();
  LOG(kVerbose) << s;

  is_duplicate_normal_connection = false;
  std::lock_guard<std::mutex> lock(mutex_);
  if (!temporary_connection) {
    auto range(connections_.equal_range(peer_id));
    while (!is_duplicate_normal_connection && (range.first != range.second)) {
      is_duplicate_normal_connection = (*range.first).second->HasNormalConnectionTo(peer_id);
#ifndef NDEBUG
      if (is_duplicate_normal_connection) {
        LOG(kError) << (*range.first).second->ThisDebugId() << " is already connected to "
                    << DebugId(peer_id) << "   Won't make duplicate normal connection on "
                    << transport->ThisDebugId();
      }
#endif
      ++range.first;
    }
  }

  if (!is_duplicate_normal_connection) {
    connections_.insert(std::make_pair(peer_id, transport));
  //pending_connections_.erase(peer_endpoint);
  }
}

void ManagedConnections::OnConnectionLostSlot(const NodeId& peer_id,
                                              detail::TransportPtr transport,
                                              bool temporary_connection) {
  std::string s("\n************ OnConnectionLostSlot ************\nRemoving ");
  s += (temporary_connection ? "temporary" : "non-temporary");
  s += " connection from ";
  s += transport->ThisDebugId() + " to " + DebugId(peer_id).substr(0, 7) + '\n' + DebugString();
  LOG(kVerbose) << s;

  {
    //bool remove_transport(connections_empty && !transport->IsResilienceTransport());
    std::lock_guard<std::mutex> lock(mutex_);
#ifndef NDEBUG
    if (!temporary_connection) {
      auto range(connections_.equal_range(peer_id));
      // Check that there's only a single transport with a normal connection to this peer.
      auto itr(range.first);
      std::set<TransportPtr> transports;
      size_t normal_connection_count(0);
      while (itr != range.second) {
        if (transports.insert((*itr).second).second &&
            (*itr).second->HasNormalConnectionTo(peer_id)) {
          ++normal_connection_count;
        }
        ++itr;
      }
      assert(normal_connection_count == 1U);
    }
#endif
    auto itr(std::find_if(
        connections_.begin(),
        connections_.end(),
        [&](const ConnectionMap::value_type& element) {
          return peer_id == element.first && transport == element.second;
        }));
    assert(temporary_connection ? true : itr != connections_.end());

    if (itr != connections_.end())
      connections_.erase(itr);


//
//      // If this is a temporary connection to allow this node to bootstrap a new transport off an
//      // existing connection, the transport endpoint passed into the slot will not be the same one
//      // that is listed against the peer's endpoint in the connection_map_.
//      if (transport->local_endpoint() == (*connection_itr).second->local_endpoint()) {
//        connection_map_.erase(connection_itr);
//        should_execute_functor = true;
//        LOG(kInfo) << "Removed managed connection from " << transport->local_endpoint() << " to "
//                   << peer_endpoint
//                   << (remove_transport ? " - also removing corresponding transport.  Now have " :
//                                          " - not removing transport.  Now have ")
//                   << connection_map_.size() << " connections.";
//      } else {
//        std::string msg("Not removing managed connection from ");
//        msg += (*connection_itr).second->local_endpoint().address().to_string();
//        msg += ":" + boost::lexical_cast<std::string>(
//                         (*connection_itr).second->local_endpoint().port());
//        msg += " to " + peer_endpoint.address().to_string();
//        msg += ":" + boost::lexical_cast<std::string>(peer_endpoint.port());
//        msg += "  Now have " + boost::lexical_cast<std::string>(connection_map_.size());
//        msg += " connections.";
//        LOG(kInfo) << msg;
////        LOG(kInfo) << "Not removing managed connection from "
////                   << (*connection_itr).second->local_endpoint() << " to " << peer_endpoint
////                   << "  Now have " << connection_map_.size() << " connections.";
//        BOOST_ASSERT_MSG(temporary_connection, msg.c_str());
//        remove_transport = false;
//      }
//    }
//    pending_connections_.erase(peer_endpoint);

  }

  if (!temporary_connection) {
    LOG(kVerbose) << "Firing connection_lost_functor_ for " << DebugId(peer_id);
    asio_service_.service().post([=] { connection_lost_functor_(peer_id); });  // NOLINT (Fraser)
  }
}

void ManagedConnections::OnNatDetectionRequestedSlot(const Endpoint& this_local_endpoint,
                                                     const NodeId& peer_id,
                                                     const Endpoint& peer_endpoint,
                                                     uint16_t& another_external_port) {
  if (nat_type_ == NatType::kUnknown || nat_type_ == NatType::kSymmetric) {
    another_external_port = 0;
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(std::find_if(
      connections_.begin(),
      connections_.end(),
      [&this_local_endpoint](const ConnectionMap::value_type& element) {
        return this_local_endpoint != element.second->local_endpoint();
      }));

  if (itr == connections_.end()) {
    another_external_port = 0;
    return;
  }

  another_external_port = (*itr).second->external_endpoint().port();
  // This node doesn't care about the Ping result, but Ping should not be given a NULL functor.
  (*itr).second->Ping(peer_id, peer_endpoint, [](int) {});  // NOLINT (Fraser)
}


std::string ManagedConnections::DebugString() const {
  std::string s = "This node's peer connections:\n";

  std::set<TransportPtr> transports;
  for (auto connection : connections_) {
    transports.insert(connection.second);
    s += '\t' + DebugId(connection.first).substr(0, 7) + '\n';
  }

  s += "\nThis node's own transports and their peer connections:\n";

  for (auto transport : transports)
    s += transport->DebugString();

  //s += "\nThis node's resilience transport:\n";
  //s += (resilience_transport_.transport ? resilience_transport_.transport->DebugString() :
  //                                        "\tNot running");
  s += "\n\n";

  return s;
}

}  // namespace rudp

}  // namespace maidsafe
