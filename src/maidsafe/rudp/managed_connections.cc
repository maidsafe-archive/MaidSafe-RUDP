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
typedef std::vector<std::pair<NodeId, Endpoint> > NodeIdEndpointPairs;

}  // unnamed namespace

ManagedConnections::PendingConnection::PendingConnection()
    : node_id(),
      pending_transport(),
      timestamp(),
      connecting(false) {}

ManagedConnections::PendingConnection::PendingConnection(const NodeId& node_id_in,
                                                         const TransportPtr& transport)
    : node_id(node_id_in),
      pending_transport(transport),
      timestamp(GetDurationSinceEpoch()),
      connecting(false) {}


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
      prune_pendings_count_(0),
      idle_transports_(),
      mutex_(),
      local_ip_(),
      nat_type_(NatType::kUnknown) {}

ManagedConnections::~ManagedConnections() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    message_received_functor_ = MessageReceivedFunctor();
    connection_lost_functor_ = ConnectionLostFunctor();
    for (auto connection_details : connections_)
      connection_details.second->Close();
    connections_.clear();
    for (auto pending : pendings_)
      pending.pending_transport->Close();
    pendings_.clear();
    for (auto idle_transport : idle_transports_)
      idle_transport->Close();
    idle_transports_.clear();
  }
  asio_service_.Stop();
}

int ManagedConnections::Bootstrap(const std::vector<Endpoint>& bootstrap_endpoints,
                                  MessageReceivedFunctor message_received_functor,
                                  ConnectionLostFunctor connection_lost_functor,
                                  NodeId this_node_id,
                                  std::shared_ptr<asymm::PrivateKey> private_key,
                                  std::shared_ptr<asymm::PublicKey> public_key,
                                  NodeId& chosen_bootstrap_peer,
                                  NatType& nat_type,
                                  Endpoint local_endpoint) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connections_.empty()) {
      for (auto connection_details : connections_) {
        assert(connection_details.second->GetConnection(connection_details.first)->state() ==
               detail::Connection::State::kBootstrapping);
        connection_details.second->Close();
      }
      connections_.clear();
    }
    pendings_.clear();
    for (auto idle_transport : idle_transports_)
      idle_transport->Close();
    idle_transports_.clear();
  }

  if (!message_received_functor) {
    LOG(kError) << "You must provide a valid MessageReceivedFunctor.";
    return kInvalidParameter;
  }
  if (!connection_lost_functor) {
    LOG(kError) << "You must provide a valid ConnectionLostFunctor.";
    return kInvalidParameter;
  }
  if (this_node_id == NodeId()) {
    LOG(kError) << "You must provide a valid NodeId.";
    return kInvalidParameter;
  }
  this_node_id_ = this_node_id;
  if (!private_key || !asymm::ValidateKey(*private_key) ||
      !public_key || !asymm::ValidateKey(*public_key)) {
    LOG(kError) << "You must provide a valid private and public key.";
    return kInvalidParameter;
  }
  private_key_ = private_key;
  public_key_ = public_key;

  if (bootstrap_endpoints.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap endpoint.";
    return kNoBootstrapEndpoints;
  }

  asio_service_.Start();

  bool zero_state(detail::IsValid(local_endpoint));

  if (zero_state) {
    local_ip_ = local_endpoint.address();
  } else {
    local_ip_ = GetLocalIp();
    if (local_ip_.is_unspecified()) {
      LOG(kError) << "Failed to retrieve local IP.";
      return kFailedToGetLocalAddress;
    }
    local_endpoint = Endpoint(local_ip_, 0);
  }

  std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint>> bootstrap_peers;
  for (auto element : bootstrap_endpoints)
    bootstrap_peers.push_back(std::make_pair(NodeId(), element));
  if (!StartNewTransport(bootstrap_peers, local_endpoint)) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return kTransportStartFailure;
  }
  chosen_bootstrap_peer = chosen_bootstrap_node_id_;
  nat_type = nat_type_;

  // Add callbacks now.
  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;

  return kSuccess;
}

bool ManagedConnections::StartNewTransport(NodeIdEndpointPairs bootstrap_peers,
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
  if (!transport->Bootstrap(bootstrap_peers,
                            this_node_id_,
                            public_key_,
                            local_endpoint,
                            bootstrap_off_existing_connection,
                            boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
                            boost::bind(&ManagedConnections::OnConnectionAddedSlot, this,
                                        _1, _2, _3, _4),
                            boost::bind(&ManagedConnections::OnConnectionLostSlot, this,
                                        _1, _2, _3),
                            boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this,
                                        _1, _2, _3, _4),
                            chosen_id)) {
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

void ManagedConnections::GetBootstrapEndpoints(NodeIdEndpointPairs& bootstrap_peers,
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

  // Functor to handle resetting parameters in case of failure.
  const auto kDoFail([&](const std::string& message) {  // NOLINT (Fraser)
    this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
    this_nat_type = NatType::kUnknown;
    if (!message.empty())
      LOG(kError) << message;
  });

  // Functor to handle setting parameters and inserting into pendings_ in case of success
  const auto kDoSucceed(  // NOLINT (Dan)
      [&] (TransportPtr transport)->bool {
        this_endpoint_pair.local = transport->local_endpoint();
        this_endpoint_pair.external = transport->external_endpoint();
        assert(transport->IsAvailable());
        auto itr(FindPendingTransportWithNodeId(peer_id));
        if (itr != pendings_.end()) {
          kDoFail(std::string("Unexpected insertion failure for ") + DebugId(peer_id));
          assert(false);
          return false;
        }
        PendingConnection connection(peer_id, transport);
        pendings_.push_back(connection);
        return true;
      });

  {
    std::lock_guard<std::mutex> lock(mutex_);
    this_nat_type = nat_type_;
    if (connections_.empty() && idle_transports_.empty()) {
      kDoFail("No running Transports.");
      return kNotBootstrapped;
    }

    // Check for an existing connection attempt
    auto existing_attempt(FindPendingTransportWithNodeId(peer_id));
    if (existing_attempt != pendings_.end()) {
      this_endpoint_pair.local = (*existing_attempt).pending_transport->local_endpoint();
      this_endpoint_pair.external = (*existing_attempt).pending_transport->external_endpoint();
      assert((*existing_attempt).pending_transport->IsAvailable());
      return kSuccess;
    }

    // Check for existing connection to peer and use that transport if it's a bootstrap connection
    // otherwise fail.
    auto itr(connections_.find(peer_id));
    if (itr != connections_.end()) {
      std::shared_ptr<detail::Connection> connection((*itr).second->GetConnection(peer_id));
      assert(connection);
      if (!connection) {
        LOG(kError) << "Internal ManagedConnections error: mismatch between connections_ and "
                    << "actual connections.";
        connections_.erase(peer_id);
      }
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        return kDoSucceed((*itr).second) ? kSuccess : kConnectAttemptAlreadyRunning;
      } else {
        kDoFail(std::string("A non-bootstrap managed connection from ") + DebugId(this_node_id_) +
                std::string(" to ") + DebugId(peer_id) + " already exists");
        return kConnectionAlreadyExists;
      }
    }

    // Try to get from an existing idle transport
    while (!idle_transports_.empty()) {
      if ((*idle_transports_.begin())->IsAvailable())
        return kDoSucceed(*idle_transports_.begin()) ? kSuccess : kConnectAttemptAlreadyRunning;
      else
        idle_transports_.erase(idle_transports_.begin());
    }
  }

  bool start_new_transport(false);
  if (nat_type_ == NatType::kSymmetric &&
      static_cast<int>(connections_.size()) <
          (Parameters::max_transports * detail::Transport::kMaxConnections())) {
    if (detail::IsValid(peer_endpoint_pair.external))
      start_new_transport = true;
    else
      start_new_transport = !detail::IsValid(peer_endpoint_pair.local);
  } else {
    start_new_transport = (static_cast<int>(connections_.size()) < Parameters::max_transports);
  }

  if (start_new_transport &&
      !StartNewTransport(NodeIdEndpointPairs(), Endpoint(local_ip_, 0))) {  // NOLINT (Fraser)
    kDoFail("Failed to start transport.");
    return kTransportStartFailure;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // Check again for an existing connection attempt in case it was added while mutex unlocked
  // during starting new transport.
  auto existing_attempt(std::find_if(pendings_.begin(),
                                     pendings_.end(),
                                     [&peer_id] (const PendingConnection& element) {
                                       return element.node_id == peer_id;
                                     }));
  if (existing_attempt != pendings_.end()) {
    kDoFail(std::string("GetAvailableEndpoint has already been called for ") + DebugId(peer_id));
    return kConnectAttemptAlreadyRunning;
  }

  // NAT type may have just been deduced by newly-started transport
  this_nat_type = nat_type_;
  // Try again to get from an existing idle transport (likely to be just-started one)
  if (connections_.empty() && idle_transports_.empty()) {
    kDoFail("No running Transports.");
    return kNotBootstrapped;
  }

  while (!idle_transports_.empty()) {
    if ((*idle_transports_.begin())->IsAvailable())
      return kDoSucceed(*idle_transports_.begin()) ? kSuccess : kConnectAttemptAlreadyRunning;
    else
      idle_transports_.erase(idle_transports_.begin());
  }

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
    kDoFail("All connectable Transports are full.");
    return kFull;
  }

  return kDoSucceed(selected_transport) ? kSuccess : kConnectAttemptAlreadyRunning;
}

int ManagedConnections::Add(NodeId peer_id,
                            EndpointPair peer_endpoint_pair,
                            std::string validation_data) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }

  std::lock_guard<std::mutex> lock(mutex_);

  auto itr(FindPendingTransportWithNodeId(peer_id));
  if (itr == pendings_.end()) {
    if (connections_.find(peer_id) != connections_.end()) {
      LOG(kWarning) << "A managed connection from " << DebugId(this_node_id_) << " to "
                    << DebugId(peer_id) << " already exists, and this node's chosen BootstrapID is "
                    << DebugId(chosen_bootstrap_node_id_);
      return kConnectionAlreadyExists;
    }
    LOG(kError) << "No connection attempt from " << DebugId(this_node_id_) << " to "
                << DebugId(peer_id) << " - ensure GetAvailableEndpoint has been called first.";
    return kNoPendingConnectAttempt;
  }

  if ((*itr).connecting) {
    LOG(kWarning) << "A connection attempt from " << DebugId(this_node_id_) << " to "
                  << DebugId(peer_id) << " is already happening";
    return kConnectAttemptAlreadyRunning;
  }

  TransportPtr selected_transport((*itr).pending_transport);
  (*itr).connecting = true;

  if (validation_data.empty()) {
    LOG(kError) << "Invalid validation_data passed.";
    pendings_.erase(itr);
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
      pendings_.erase(itr);
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

/*
void ManagedConnections::Ping(Endpoint peer_endpoint, PingFunctor ping_functor) {
  if (!ping_functor) {
    LOG(kWarning) << "No functor passed - not pinging.";
    return;
  }

  if (connections_.empty() && idle_transports_.empty()) {
    LOG(kError) << "No running Transports.";
    // Probably haven't bootstrapped, so asio_service_ won't be running.
    boost::thread(ping_functor, kNotBootstrapped);
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // Check this node isn't already connected to peer
  if (connection_map_.find(peer_endpoint) != connection_map_.end()) {
    asio_service_.service().post([ping_functor] { ping_functor(kWontPingAlreadyConnected); });  // NOLINT (Fraser)
    return;
  }

  // Check we're not trying to ping ourself
  if (std::find_if(connections_.begin(),
                   connections_.end(),
                   [&peer_endpoint](const TransportAndSignalConnections& tprt_and_sigs_conns) {
                     return tprt_and_sigs_conns.transport->local_endpoint() == peer_endpoint ||
                            tprt_and_sigs_conns.transport->external_endpoint() == peer_endpoint;
                   }) != connections_.end()) {
    LOG(kError) << "Trying to ping ourself.";
    asio_service_.service().post([ping_functor] { ping_functor(kWontPingOurself); });  // NOLINT (Fraser)
    return;
  }

  size_t index(RandomUint32() % connections_.size());
  connections_[index].transport->Ping(peer_endpoint, ping_functor);
}
*/

void ManagedConnections::OnMessageSlot(const std::string& message) {
  LOG(kVerbose) << "\n^^^^^^^^^^^^ OnMessageSlot ^^^^^^^^^^^^\n" + DebugString();
  PrunePendingTransports();

  std::string decrypted_message;
  int result(asymm::Decrypt(message, *private_key_, &decrypted_message));
  if (result != kSuccess) {
    LOG(kError) << "Failed to decrypt message.  Result: " << result;
  } else {
    if (message_received_functor_) {
      asio_service_.service().post([this, decrypted_message] {
                                     message_received_functor_(decrypted_message);
                                   });
    }
  }
}

void ManagedConnections::OnConnectionAddedSlot(const NodeId& peer_id,
                                               TransportPtr transport,
                                               bool temporary_connection,
                                               bool& is_duplicate_normal_connection) {
  is_duplicate_normal_connection = false;
  std::lock_guard<std::mutex> lock(mutex_);

  if (temporary_connection) {
    if (transport->IsIdle()) {
      assert(transport->IsAvailable());
      idle_transports_.insert(transport);
    } else {
      idle_transports_.erase(transport);
    }
  } else {
    auto itr(FindPendingTransportWithNodeId(peer_id));
    if (itr != pendings_.end())
      pendings_.erase(itr);

    auto result(connections_.insert(std::make_pair(peer_id, transport)));
    is_duplicate_normal_connection = !result.second;
    if (is_duplicate_normal_connection) {
      if (transport->IsIdle()) {
        assert(transport->IsAvailable());
        idle_transports_.insert(transport);
      } else {
        idle_transports_.erase(transport);
      }
      LOG(kError) << (*result.first).second->ThisDebugId() << " is already connected to "
                  << DebugId(peer_id) << ".  Won't make duplicate normal connection on "
                  << transport->ThisDebugId();
    } else {
      idle_transports_.erase(transport);
    }
  }

#ifndef NDEBUG
  auto itr(idle_transports_.begin());
  while (itr != idle_transports_.end()) {
    assert((*itr)->IsIdle());
    if (!(*itr)->IsAvailable())
      itr = idle_transports_.erase(itr);
    else
      ++itr;
  }
#endif
}

void ManagedConnections::OnConnectionLostSlot(const NodeId& peer_id,
                                              TransportPtr transport,
                                              bool temporary_connection) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (transport->IsIdle()) {
    assert(transport->IsAvailable());
    idle_transports_.insert(transport);
  } else {
    idle_transports_.erase(transport);
  }

  if (temporary_connection)
    return;

  // If this is a bootstrap connection, it may have already had GetAvailableEndpoint called on it,
  // but not yet had Add called, in which case peer_id will be in pendings_.  In all other cases,
  // peer_id should not be in pendings_.
  auto pendings_itr(FindPendingTransportWithNodeId(peer_id));
  if (pendings_itr != pendings_.end())
    pendings_.erase(pendings_itr);

  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second != transport) {
      LOG(kError) << "peer_id: " << DebugId(peer_id) << " is connected via "
                  << (*itr).second->local_endpoint() << " not " << transport->local_endpoint();
      assert(false);
    }
    connections_.erase(itr);
    if (peer_id == chosen_bootstrap_node_id_)
      chosen_bootstrap_node_id_ = NodeId();
    if (connection_lost_functor_) {
      LOG(kVerbose) << "Firing connection_lost_functor_ for " << DebugId(peer_id);
      asio_service_.service().post([=] { connection_lost_functor_(peer_id); });  // NOLINT (Fraser)
    }
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
  auto itr(std::find_if(connections_.begin(),
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
    s += "\tPending to peer " + DebugId(pending.node_id).substr(0, 7);
    s += " on this node's transport ";
    s += boost::lexical_cast<std::string>(pending.pending_transport->external_endpoint()) + " / ";
    s += boost::lexical_cast<std::string>(pending.pending_transport->local_endpoint()) + '\n';
  }
  s += "\n\n";

  return s;
}

std::vector<ManagedConnections::PendingConnection>::iterator
    ManagedConnections::FindPendingTransportWithNodeId(const NodeId& peer_id) {
  return std::find_if(pendings_.begin(),
                      pendings_.end(),
                      [&peer_id] (const PendingConnection& element) {
                        return element.node_id == peer_id;
                      });
}

void ManagedConnections::PrunePendingTransports() {
  std::lock_guard<std::mutex> loch(mutex_);
  // TODO(Team): Based on the amount of traffic received, decide whether 3 iterations are
  //             (enough/too much) to prune a pending transport.
  if (prune_pendings_count_ >= 3) {
    prune_pendings_count_ = 0;
    auto itr(pendings_.begin());
    while (itr != pendings_.end()) {
      boost::posix_time::time_duration now(GetDurationSinceEpoch());
      if ((now.total_milliseconds() - (*itr).timestamp.total_milliseconds()) >
          Parameters::rendezvous_connect_timeout.total_milliseconds()) {
        itr = pendings_.erase(itr);
      } else {
        ++itr;
      }
    }
  } else {
    ++prune_pendings_count_;
  }
}

}  // namespace rudp

}  // namespace maidsafe
