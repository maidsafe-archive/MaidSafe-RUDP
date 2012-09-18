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
      chosen_bootstrap_node_id_(),
      private_key_(),
      public_key_(),
      connections_(),
      pendings_(),
      idle_transports_(),
      mutex_(),
      local_ip_(),
      nat_type_(NatType::kUnknown) {}

ManagedConnections::~ManagedConnections() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto connection_details : connections_)
      connection_details.second->Close();
    connections_.clear();
    for (auto pending : pendings_)
      pending.second->Close();
    pendings_.clear();
    for (auto idle_transport : idle_transports_)
      idle_transport->Close();
    idle_transports_.clear();
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

  std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint>> bootstrap_peers;
  for (auto element : bootstrap_endpoints)
    bootstrap_peers.push_back(std::make_pair(NodeId(), element));
  if (!StartNewTransport(bootstrap_peers, local_endpoint)) {
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
  return chosen_bootstrap_node_id_;
}

bool ManagedConnections::StartNewTransport(std::vector<std::pair<NodeId, Endpoint>> bootstrap_peers,
                                           Endpoint local_endpoint) {
  TransportPtr transport(new detail::Transport(asio_service_, nat_type_));
  bool bootstrap_off_existing_connection(bootstrap_peers.empty());
  boost::asio::ip::address external_address;
  if (bootstrap_off_existing_connection)
    GetBootstrapEndpoints(bootstrap_peers, external_address);
  // else
  //  bootstrap_endpoints.insert(bootstrap_endpoints.begin(),
  //                             Endpoint(local_ip_, kResiliencePort()));

  transport->SetManagedConnectionsDebugPrintout([this]() { return DebugString(); });  // NOLINT (Fraser)
  NodeId chosen_id;
  transport->Bootstrap(
      bootstrap_peers,
      this_node_id_,
      public_key_,
      local_endpoint,
      bootstrap_off_existing_connection,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2, _3, _4),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3),
      boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, _1, _2, _3, _4),
      chosen_id);
  if (chosen_id == NodeId() && nat_type_ != NatType::kSymmetric) {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(kWarning) << "Failed to start a new Transport.";
    transport->Close();
    return false;
  }

  if (chosen_bootstrap_node_id_ == NodeId())
    chosen_bootstrap_node_id_ = chosen_id;

  if (!detail::IsValid(transport->external_endpoint()) && !external_address.is_unspecified()) {
    // Means this node's NAT is symmetric or unknown, so guess that it will be mapped to existing
    // external address and local port.
    transport->SetBestGuessExternalEndpoint(Endpoint(external_address,
                                                     transport->local_endpoint().port()));
  }

  LOG(kVerbose) << "Started a new transport on " << transport->external_endpoint() << " / "
                << transport->local_endpoint() << " behind " << nat_type_;
  return true;
}

void ManagedConnections::GetBootstrapEndpoints(
    std::vector<std::pair<NodeId, Endpoint>>& bootstrap_peers,  // NOLINT (Fraser)
    boost::asio::ip::address& this_external_address) {
  bool external_address_consistent(true);
  // Favour connections which are on a different network to this to allow calculation of the new
  // transport's external endpoint.
  std::vector<std::pair<NodeId, Endpoint>> secondary_peers;
  bootstrap_peers.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  secondary_peers.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  std::set<Endpoint> non_duplicates;
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    std::shared_ptr<detail::Connection> connection(element.second->GetConnection(element.first));
    if (!connection)
      continue;
    if (!non_duplicates.insert(connection->Socket().PeerEndpoint()).second)
      continue;  // Already have this endpoint added to bootstrap_endpoints or secondary_endpoints.
    std::pair<NodeId, Endpoint> peer(connection->Socket().PeerNodeId(),
                                     connection->Socket().PeerEndpoint());
    if (detail::OnPrivateNetwork(connection->Socket().PeerEndpoint())) {
      secondary_peers.push_back(peer);
    } else {
      bootstrap_peers.push_back(peer);
      Endpoint this_endpoint_as_seen_by_peer(
          element.second->ThisEndpointAsSeenByPeer(element.first));
      if (this_external_address.is_unspecified())
        this_external_address = this_endpoint_as_seen_by_peer.address();
      else if (this_external_address != this_endpoint_as_seen_by_peer.address())
        external_address_consistent = false;
    }
  }
  if (!external_address_consistent)
    this_external_address = boost::asio::ip::address();
  std::random_shuffle(bootstrap_peers.begin(), bootstrap_peers.end());
  std::random_shuffle(secondary_peers.begin(), secondary_peers.end());
  bootstrap_peers.insert(bootstrap_peers.end(), secondary_peers.begin(), secondary_peers.end());
}

int ManagedConnections::GetAvailableEndpoint(NodeId peer_id,
                                             EndpointPair peer_endpoint_pair,
                                             EndpointPair& this_endpoint_pair,
                                             NatType& this_nat_type) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }

  // Functor to be used to retrieve a non-resilience, idle transport.
  const auto kGetFromIdles([&]()->bool {  // NOLINT (Fraser)
    if (!idle_transports_.empty()) {
      auto idles_itr(std::find_if_not(idle_transports_.begin(),
                                      idle_transports_.end(),
                                      [](const std::shared_ptr<detail::Transport>& transport) {
                                        return transport->IsResilienceTransport();
                                      }));
      if (idles_itr != idle_transports_.end()) {
        this_endpoint_pair.local = (*idles_itr)->local_endpoint();
        this_endpoint_pair.external = (*idles_itr)->external_endpoint();
        BOOST_VERIFY(pendings_.insert(std::make_pair(peer_id, *idles_itr)).second);
        return true;
      } else {
        LOG(kVerbose) << "Only idle transport is Resilience one - won't provide this in "
                      << "GetAvailableEndpoint";
      }
    }
    return false;
  });

  // Functor to handle resetting parameters in case of failure.
  const auto kFail([&](const std::string& message) {  // NOLINT (Fraser)
    this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
    this_nat_type = NatType::kUnknown;
    if (!message.empty())
      LOG(kError) << message;
  });

  {
    std::lock_guard<std::mutex> lock(mutex_);
    this_nat_type = nat_type_;
    if (connections_.empty() && idle_transports_.empty()) {
      kFail("No running Transports.");
      return kNotBootstrapped;
    }

    // Check for an existing connection attempt
    auto existing_attempt(pendings_.find(peer_id));
    // assert(existing_attempt == pendings_.end());
    if (existing_attempt != pendings_.end()) {
      kFail(std::string("GetAvailableEndpoint has already been called for ") + DebugId(peer_id));
      return kConnectAttemptAlreadyRunning;
    }

    // Check for existing connection to peer and use that transport if it's a bootstrap connection
    // otherwise fail.
    auto itr(connections_.find(peer_id));
    if (itr != connections_.end()) {
      std::shared_ptr<detail::Connection> connection((*itr).second->GetConnection(peer_id));
      if (!connection) {
        LOG(kError) << "Internal ManagedConnections error: mismatch between connections_ and "
                    << "actual connections.";
        connections_.erase(peer_id);
      }
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        this_endpoint_pair.local = (*itr).second->local_endpoint();
        this_endpoint_pair.external = (*itr).second->external_endpoint();
        BOOST_VERIFY(pendings_.insert(std::make_pair(peer_id, (*itr).second)).second);
        return kSuccess;
      } else {
        kFail(std::string("A non-bootstrap managed connection from ") + DebugId(this_node_id_) +
              std::string(" to ") + DebugId(peer_id) + " already exists");
        return kConnectionAlreadyExists;
      }
    }

    // Try to get from an existing idle transport
    if (kGetFromIdles())
      return kSuccess;
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

  if (start_new_transport &&
      !StartNewTransport(std::vector<std::pair<NodeId, Endpoint>>(), Endpoint(local_ip_, 0))) {  // NOLINT (Fraser)
    kFail("Failed to start transport.");
    return kTransportStartFailure;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // Check again for an existing connection attempt in case it was added while mutex unlocked
  // during starting new transport.
  auto existing_attempt(pendings_.find(peer_id));
  assert(existing_attempt == pendings_.end());
  if (existing_attempt != pendings_.end()) {
    kFail(std::string("GetAvailableEndpoint has already been called for ") + DebugId(peer_id));
    return kConnectAttemptAlreadyRunning;
  }

  // NAT type may have just been deduced by newly-started transport
  this_nat_type = nat_type_;
  // Try again to get from an existing idle transport (likely to be just-started one)
  if (kGetFromIdles())
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

  if (!selected_transport) {
    kFail("All connectable Transports are full.");
    return kFull;
  }

  this_endpoint_pair.local = selected_transport->local_endpoint();
  this_endpoint_pair.external = selected_transport->external_endpoint();
  BOOST_VERIFY(pendings_.insert(std::make_pair(peer_id, selected_transport)).second);
  return kSuccess;
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

  std::lock_guard<std::mutex> lock(mutex_);

#ifndef NDEBUG
  for (auto idle_transport : idle_transports_)
    assert(idle_transport->IsIdle());
#endif

  auto itr(pendings_.find(peer_id));
  assert(itr != pendings_.end());
  if (itr == pendings_.end()) {
    LOG(kError) << "No connection attempt from " << DebugId(this_node_id_) << " to "
                << DebugId(peer_id) << " - ensure GetAvailableEndpoint has been called first.";
    return kNoPendingConnectAttempt;
  }
  TransportPtr selected_transport((*itr).second);
  pendings_.erase(itr);

  if (validation_data.empty()) {
    LOG(kError) << "Invalid validation_data passed.";
    return kEmptyValidationData;
  }

  std::shared_ptr<detail::Connection> connection(selected_transport->GetConnection(peer_id));
  if (connection) {
    // If the connection exists, it should be a bootstrapping one.  If the peer used this node,
    // the connection state should be kBootstrapping.  However, if this node bootstrapped off the
    // peer, the peer's validation data will probably already have been received and may have
    // caused the MarkConnectionAsValid to have already been called.  In this case only, the
    // connection will be kPermanent.
    if (connection->state() == detail::Connection::State::kBootstrapping ||
        (chosen_bootstrap_node_id_ == peer_id &&
               connection->state() == detail::Connection::State::kPermanent)) {
      connection->StartSending(validation_data,
                                [](int result) {
                                  if (result != kSuccess) {
                                    LOG(kWarning) << "Failed to send validation data on bootstrap "
                                                  << "connection.  Result: " << result;
                                  }
                                });
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        Endpoint peer_endpoint;
        selected_transport->MakeConnectionPermanent(peer_id, false, peer_endpoint);
        assert(detail::IsValid(peer_endpoint) ?
                    peer_endpoint == connection->Socket().PeerEndpoint() :
                    true);
      }
      return kSuccess;
    } else {
      LOG(kError) << "A managed connection from " << DebugId(this_node_id_) << " to "
                  << DebugId(peer_id) << " already exists, and this node's chosen bootstrap ID is "
                  << DebugId(chosen_bootstrap_node_id_);
      assert(false);
      return kConnectionAlreadyExists;
    }
  }

  selected_transport->Connect(peer_id, peer_endpoint_pair, validation_data);
  return kSuccess;
}

int ManagedConnections::MarkConnectionAsValid(NodeId peer_id, Endpoint& peer_endpoint) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second->MakeConnectionPermanent(peer_id, true, peer_endpoint))
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
  auto itr(connections_.find(peer_id));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Can't remove connection from " << DebugId(this_node_id_) << " to "
                  << DebugId(peer_id) << " - not in map.";
  } else {
    (*itr).second->CloseConnection(peer_id);
  }
}

void ManagedConnections::Send(NodeId peer_id,
                              std::string message,
                              MessageSentFunctor message_sent_functor) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second->Send(peer_id, message, message_sent_functor))
      return;
  }
  LOG(kError) << "Can't send from " << DebugId(this_node_id_) << " to " << DebugId(peer_id)
              << " - not in map.";
  if (message_sent_functor) {
    if (!connections_.empty() || !idle_transports_.empty()) {
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
//  if (connections_.empty() && idle_transports_.empty()) {
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
  LOG(kVerbose) << "\n^^^^^^^^^^^^ OnMessageSlot ^^^^^^^^^^^^\n" + DebugString();

  std::string decrypted_message;
  int result(asymm::Decrypt(message, *private_key_, &decrypted_message));
  if (result != kSuccess)
    LOG(kError) << "Failed to decrypt message.  Result: " << result;
  else
    asio_service_.service().post([&, decrypted_message] { 
                                 if (message_received_functor_)
                                 message_received_functor_(decrypted_message); });  // NOLINT (Fraser)
}

void ManagedConnections::OnConnectionAddedSlot(const NodeId& peer_id,
                                               TransportPtr transport,
                                               bool temporary_connection,
                                               bool& is_duplicate_normal_connection) {
  is_duplicate_normal_connection = false;
  std::lock_guard<std::mutex> lock(mutex_);

  if (temporary_connection) {
    if (transport->IsIdle())
      idle_transports_.insert(transport);
    else
      idle_transports_.erase(transport);
  } else {
    auto result(connections_.insert(std::make_pair(peer_id, transport)));
    is_duplicate_normal_connection = !result.second;
    if (is_duplicate_normal_connection) {
      if (transport->IsIdle())
        idle_transports_.insert(transport);
      else
        idle_transports_.erase(transport);
      LOG(kError) << (*result.first).second->ThisDebugId() << " is already connected to "
                  << DebugId(peer_id) << "   Won't make duplicate normal connection on "
                  << transport->ThisDebugId();
    } else {
      idle_transports_.erase(transport);
    }
  }
}

void ManagedConnections::OnConnectionLostSlot(const NodeId& peer_id,
                                              TransportPtr transport,
                                              bool temporary_connection) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (transport->IsIdle())
    idle_transports_.insert(transport);
  else
    idle_transports_.erase(transport);

  if (temporary_connection)
    return;

  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second != transport) {
      LOG(kError) << "peer_id: " << DebugId(peer_id) << " is connected via "
                  << (*itr).second->local_endpoint() << " not " << transport->local_endpoint();
      assert(false);
    }
    connections_.erase(itr);
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

  std::lock_guard<std::mutex> lock(mutex_);
  std::set<TransportPtr> transports;
  for (auto connection : connections_) {
    transports.insert(connection.second);
    s += '\t' + DebugId(connection.first).substr(0, 7) + '\n';
  }

  s += "\nThis node's own transports and their peer connections:\n";
  for (auto transport : transports)
    s += transport->DebugString();

  s += "\nThis node's idle transports:\n";
  for (auto idle_transport : idle_transports_)
    s += idle_transport->DebugString();

  s += "\nThis node's pending connections:\n";
  for (auto pending : pendings_) {
    s += "\tPending to peer " + DebugId(pending.first).substr(0, 7);
    s += " on this node's transport ";
    s += boost::lexical_cast<std::string>(pending.second->external_endpoint()) + " / ";
    s += boost::lexical_cast<std::string>(pending.second->local_endpoint()) + '\n';
  }
  //s += "\nThis node's resilience transport:\n";
  //s += (resilience_transport_.transport ? resilience_transport_.transport->DebugString() :
  //                                        "\tNot running");
  s += "\n\n";

  return s;
}

}  // namespace rudp

}  // namespace maidsafe
