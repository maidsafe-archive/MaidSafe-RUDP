/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

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

typedef ManagedConnections::Endpoint Endpoint;

// 203.0.113.14:1314
const Endpoint kNonRoutable(boost::asio::ip::address_v4(3405803790U), 1314);

void SetDebugPacketLossRate(double constant, double bursty) {
  detail::Multiplexer::SetDebugPacketLossRate(constant, bursty);
}

namespace {

typedef std::vector<std::pair<NodeId, Endpoint>> NodeIdEndpointPairs;

int CheckBootstrappingParameters(const std::vector<Endpoint>& bootstrap_endpoints,
                                 MessageReceivedFunctor message_received_functor,
                                 ConnectionLostFunctor connection_lost_functor, NodeId this_node_id,
                                 std::shared_ptr<asymm::PrivateKey> private_key,
                                 std::shared_ptr<asymm::PublicKey> public_key) {
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
  if (!private_key || !asymm::ValidateKey(*private_key) || !public_key ||
      !asymm::ValidateKey(*public_key)) {
    LOG(kError) << "You must provide a valid private and public key.";
    return kInvalidParameter;
  }
  if (bootstrap_endpoints.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap endpoint.";
    return kNoBootstrapEndpoints;
  }

  return kSuccess;
}

}  // unnamed namespace

ManagedConnections::PendingConnection::PendingConnection(NodeId node_id_in, TransportPtr transport,
                                                         boost::asio::io_service& io_service)
    : node_id(std::move(node_id_in)),
      pending_transport(std::move(transport)),
      timer(io_service,
            bptime::microsec_clock::universal_time() + Parameters::rendezvous_connect_timeout),
      connecting(false) {}

ManagedConnections::ManagedConnections()
    : asio_service_(Parameters::thread_count),
      callback_mutex_(),
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
    for (auto& pending : pendings_)
      pending->pending_transport->Close();
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
                                  NodeId& chosen_bootstrap_peer, NatType& nat_type,
                                  Endpoint local_endpoint) {
  ClearConnectionsAndIdleTransports();
  int result(CheckBootstrappingParameters(bootstrap_endpoints, message_received_functor,
                                          connection_lost_functor, this_node_id, private_key,
                                          public_key));
  if (result != kSuccess) {
    return result;
  }

  this_node_id_ = this_node_id;
  private_key_ = private_key;
  public_key_ = public_key;

  result = TryToDetermineLocalEndpoint(local_endpoint);
  if (result != kSuccess) {
    return result;
  }

  result = AttemptStartNewTransport(bootstrap_endpoints, local_endpoint, chosen_bootstrap_peer,
                                    nat_type);
  if (result != kSuccess) {
    return result;
  }

  // Add callbacks now.
  {
    std::lock_guard<std::mutex> guard(callback_mutex_);
    message_received_functor_ = message_received_functor;
    connection_lost_functor_ = connection_lost_functor;
  }

  return kSuccess;
}

void ManagedConnections::ClearConnectionsAndIdleTransports() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!connections_.empty()) {
    for (auto connection_details : connections_) {
      auto connection_ptr(connection_details.second->GetConnection(connection_details.first));
      if (connection_ptr) {
        assert(connection_ptr->state() == detail::Connection::State::kBootstrapping);
        connection_details.second->Close();
      }
    }
    connections_.clear();
  }
  pendings_.clear();
  for (auto idle_transport : idle_transports_)
    idle_transport->Close();
  idle_transports_.clear();
}

int ManagedConnections::TryToDetermineLocalEndpoint(Endpoint& local_endpoint) {
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
  return kSuccess;
}

int ManagedConnections::AttemptStartNewTransport(const std::vector<Endpoint>& bootstrap_endpoints,
                                                 const Endpoint& local_endpoint,
                                                 NodeId& chosen_bootstrap_peer, NatType& nat_type) {
  NodeIdEndpointPairs bootstrap_peers;
  for (auto element : bootstrap_endpoints)
    bootstrap_peers.push_back(std::make_pair(NodeId(), element));

  ReturnCode result = StartNewTransport(bootstrap_peers, local_endpoint);
  if (result != kSuccess) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return result;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  chosen_bootstrap_peer = chosen_bootstrap_node_id_;
  nat_type = nat_type_;
  return kSuccess;
}

ReturnCode ManagedConnections::StartNewTransport(NodeIdEndpointPairs bootstrap_peers,
                                                 Endpoint local_endpoint) {
  TransportPtr transport(std::make_shared<detail::Transport>(asio_service_, nat_type_));

  transport->SetManagedConnectionsDebugPrintout([this]() { return DebugString(); });

  bool bootstrap_off_existing_connection(bootstrap_peers.empty());
  boost::asio::ip::address external_address;
  if (bootstrap_off_existing_connection)
    GetBootstrapEndpoints(bootstrap_peers, external_address);

  {
    std::lock_guard<std::mutex> lock(mutex_);

    // Should not bootstrap from the transport belonging to the same routing object
    for (const auto& element : idle_transports_) {
      bootstrap_peers.erase(
          std::remove_if(bootstrap_peers.begin(), bootstrap_peers.end(),
                         [&element](const NodeIdEndpointPairs::value_type& entry) {
                           return entry.second == element->local_endpoint();
                         }), bootstrap_peers.end());
    }
  }

  using lock_guard = std::lock_guard<std::mutex>;
  std::promise<ReturnCode> setter;
  auto getter = setter.get_future();

  auto on_bootstrap = [&, transport](ReturnCode bootstrap_result, NodeId chosen_id) {
    if (bootstrap_result != kSuccess) {
      lock_guard lock(mutex_);
      transport->Close();
      return setter.set_value(bootstrap_result);
    }
    {
      lock_guard lock(mutex_);
      if (chosen_bootstrap_node_id_ == NodeId())
        chosen_bootstrap_node_id_ = chosen_id;
    }

    if (!detail::IsValid(transport->external_endpoint()) && !external_address.is_unspecified()) {
      // Means this node's NAT is symmetric or unknown, so guess that it will be mapped to existing
      // external address and local port.
      transport->SetBestGuessExternalEndpoint(
          Endpoint(external_address, transport->local_endpoint().port()));
    }

    lock_guard guard(mutex_);
    return setter.set_value(kSuccess);
  };

  transport->Bootstrap(
      bootstrap_peers, this_node_id_, public_key_, local_endpoint,
      bootstrap_off_existing_connection,
      std::bind(&ManagedConnections::OnMessageSlot, this, args::_1),
      [this](const NodeId & peer_id, TransportPtr transport, bool temporary_connection,
             std::atomic<bool> & is_duplicate_normal_connection) {
        OnConnectionAddedSlot(peer_id, transport, temporary_connection,
                              is_duplicate_normal_connection);
      },
      std::bind(&ManagedConnections::OnConnectionLostSlot, this, args::_1, args::_2, args::_3),
      std::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, args::_1, args::_2,
                args::_3, args::_4),
      on_bootstrap);

  getter.wait();
  { lock_guard guard(mutex_); }
  auto result = getter.get();

  if (result == kSuccess) {
    LOG(kVerbose) << "Started a new transport on " << transport->external_endpoint() << " / "
                  << transport->local_endpoint() << " behind " << nat_type_;
  } else {
    LOG(kWarning) << "Failed to start a new Transport.";
  }

  return result;
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

int ManagedConnections::GetAvailableEndpoint(NodeId peer_id, EndpointPair peer_endpoint_pair,
                                             EndpointPair& this_endpoint_pair,
                                             NatType& this_nat_type) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
    return kOwnId;
  }

  // Functor to handle resetting parameters in case of failure.
  const auto kDoFail([&](const std::string & message, int result)->int {
                       this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
                       this_nat_type = NatType::kUnknown;
                       if (!message.empty())
                         LOG(kError) << message;
                       return result;
  });

  {
    std::lock_guard<std::mutex> lock(mutex_);
    this_nat_type = nat_type_;
    if (connections_.empty() && idle_transports_.empty())
      return kDoFail("No running Transports.", kNotBootstrapped);

    // Check for an existing connection attempt.
    if (ExistingConnectionAttempt(peer_id, this_endpoint_pair))
      return kConnectAttemptAlreadyRunning;

    // Check for existing connection to peer.
    int return_code(kSuccess);
    if (ExistingConnection(peer_id, this_endpoint_pair, return_code)) {
      if (return_code == kConnectionAlreadyExists) {
        return kDoFail(std::string("A non-bootstrap managed connection from ") +
                           DebugId(this_node_id_) + std::string(" to ") + DebugId(peer_id) +
                           " already exists",
                       kConnectionAlreadyExists);
      } else {
        return return_code;
      }
    }

    // Try to use an existing idle transport.
    if (SelectIdleTransport(peer_id, this_endpoint_pair))
      return kSuccess;
  }

  if (ShouldStartNewTransport(peer_endpoint_pair) &&
      StartNewTransport(NodeIdEndpointPairs(), Endpoint(local_ip_, 0)) != kSuccess) {
    return kDoFail("Failed to start transport.", kTransportStartFailure);
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // Check again for an existing connection attempt in case it was added while mutex unlocked
  // during starting new transport.
  if (ExistingConnectionAttempt(peer_id, this_endpoint_pair))
    return kConnectAttemptAlreadyRunning;

  // NAT type may have just been deduced by newly-started transport.
  this_nat_type = nat_type_;

  return SelectAnyTransport(peer_id, this_endpoint_pair)
             ? kSuccess
             : kDoFail("All connectable Transports are full.", kFull);
}

bool ManagedConnections::ExistingConnectionAttempt(const NodeId& peer_id,
                                                   EndpointPair& this_endpoint_pair) const {
  auto existing_attempt(FindPendingTransportWithNodeId(peer_id));
  if (existing_attempt == pendings_.end())
    return false;

  this_endpoint_pair.local = (*existing_attempt)->pending_transport->local_endpoint();
  this_endpoint_pair.external = (*existing_attempt)->pending_transport->external_endpoint();
  assert((*existing_attempt)->pending_transport->IsAvailable());
  return true;
}

bool ManagedConnections::ExistingConnection(const NodeId& peer_id, EndpointPair& this_endpoint_pair,
                                            int& return_code) {
  auto itr(connections_.find(peer_id));
  if (itr == connections_.end())
    return false;

  std::shared_ptr<detail::Connection> connection((*itr).second->GetConnection(peer_id));
  // assert(connection);
  if (!connection) {
    LOG(kError) << "Internal ManagedConnections error: mismatch between connections_ and "
                << "actual connections.";
    connections_.erase(peer_id);
    return false;
  }

  bool bootstrap_connection(connection->state() == detail::Connection::State::kBootstrapping);
  bool unvalidated_connection(connection->state() == detail::Connection::State::kUnvalidated);

  if (bootstrap_connection || unvalidated_connection) {
    this_endpoint_pair.local = (*itr).second->local_endpoint();
    this_endpoint_pair.external = (*itr).second->external_endpoint();
    assert((*itr).second->IsAvailable());
    assert(FindPendingTransportWithNodeId(peer_id) == pendings_.end());
    if (bootstrap_connection) {
      std::unique_ptr<PendingConnection> connection(
          new PendingConnection(peer_id, (*itr).second, asio_service_.service()));
      AddPending(std::move(connection));
      return_code = kBootstrapConnectionAlreadyExists;
    } else {
      return_code = kUnvalidatedConnectionAlreadyExists;
    }
  } else {
    return_code = kConnectionAlreadyExists;
  }
  return true;
}

bool ManagedConnections::SelectIdleTransport(const NodeId& peer_id,
                                             EndpointPair& this_endpoint_pair) {
  while (!idle_transports_.empty()) {
    if ((*idle_transports_.begin())->IsAvailable()) {
      this_endpoint_pair.local = (*idle_transports_.begin())->local_endpoint();
      this_endpoint_pair.external = (*idle_transports_.begin())->external_endpoint();
      assert(FindPendingTransportWithNodeId(peer_id) == pendings_.end());
      std::unique_ptr<PendingConnection> connection(
          new PendingConnection(peer_id, *idle_transports_.begin(), asio_service_.service()));
      AddPending(std::move(connection));
      return true;
    } else {
      idle_transports_.erase(idle_transports_.begin());
    }
  }
  return false;
}

bool ManagedConnections::SelectAnyTransport(const NodeId& peer_id,
                                            EndpointPair& this_endpoint_pair) {
  // Try to get from an existing idle transport (likely to be just-started one).
  if (SelectIdleTransport(peer_id, this_endpoint_pair))
    return true;

  // Get transport with least connections.
  TransportPtr selected_transport(GetAvailableTransport());
  if (!selected_transport)
    return false;

  this_endpoint_pair.local = selected_transport->local_endpoint();
  this_endpoint_pair.external = selected_transport->external_endpoint();
  assert(selected_transport->IsAvailable());
  assert(FindPendingTransportWithNodeId(peer_id) == pendings_.end());
  std::unique_ptr<PendingConnection> connection(
      new PendingConnection(peer_id, selected_transport, asio_service_.service()));
  AddPending(std::move(connection));
  return true;
}

ManagedConnections::TransportPtr ManagedConnections::GetAvailableTransport() const {
  // Get transport with least connections and below kMaxConnections.
  size_t least_connections(detail::Transport::kMaxConnections());
  TransportPtr selected_transport;
  for (auto element : connections_) {
    if (element.second->NormalConnectionsCount() < least_connections) {
      least_connections = element.second->NormalConnectionsCount();
      selected_transport = element.second;
    }
  }
  return selected_transport;
}

bool ManagedConnections::ShouldStartNewTransport(const EndpointPair& peer_endpoint_pair) const {
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
  return start_new_transport;
}

void ManagedConnections::AddPending(std::unique_ptr<PendingConnection> connection) {
  NodeId peer_id(connection->node_id.ToStringEncoded(NodeId::EncodingType::kHex),
                 NodeId::EncodingType::kHex);
  pendings_.push_back(std::move(connection));
  pendings_.back()->timer.async_wait([peer_id, this](const boost::system::error_code & ec) {
    if (ec != boost::asio::error::operation_aborted) {
      std::lock_guard<std::mutex> lock(mutex_);
      RemovePending(peer_id);
    }
  });
}

void ManagedConnections::RemovePending(const NodeId& peer_id) {
  auto itr(FindPendingTransportWithNodeId(peer_id));
  if (itr != pendings_.end())
    pendings_.erase(itr);
}

std::vector<std::unique_ptr<ManagedConnections::PendingConnection>>::const_iterator
    ManagedConnections::FindPendingTransportWithNodeId(const NodeId& peer_id) const {
  return std::find_if(pendings_.cbegin(), pendings_.cend(),
                      [&peer_id](const std::unique_ptr<PendingConnection> &
                                 element) { return element->node_id == peer_id; });
}

std::vector<std::unique_ptr<ManagedConnections::PendingConnection>>::iterator
    ManagedConnections::FindPendingTransportWithNodeId(const NodeId& peer_id) {
  return std::find_if(pendings_.begin(), pendings_.end(),
                      [&peer_id](const std::unique_ptr<PendingConnection> &
                                 element) { return element->node_id == peer_id; });
}

int ManagedConnections::Add(NodeId peer_id, EndpointPair peer_endpoint_pair,
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

  if ((*itr)->connecting) {
    LOG(kWarning) << "A connection attempt from " << DebugId(this_node_id_) << " to "
                  << DebugId(peer_id) << " is already happening";
    return kConnectAttemptAlreadyRunning;
  }

  TransportPtr selected_transport((*itr)->pending_transport);
  (*itr)->connecting = true;

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
      connection->StartSending(validation_data, [](int result) {
        if (result != kSuccess) {
          LOG(kWarning) << "Failed to send validation data on bootstrap "
                        << "connection.  Result: " << result;
        }
      });
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        Endpoint peer_endpoint;
        selected_transport->MakeConnectionPermanent(peer_id, false, peer_endpoint);
        assert(detail::IsValid(peer_endpoint) ? peer_endpoint == connection->Socket().PeerEndpoint()
                                              : true);
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
  TransportPtr transport_to_close;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (peer_id == this_node_id_) {
      LOG(kError) << "Can't use this node's ID (" << DebugId(this_node_id_) << ") as peerID.";
      return;
    }
    auto itr(connections_.find(peer_id));
    if (itr == connections_.end()) {
      LOG(kWarning) << "Can't remove connection from " << DebugId(this_node_id_) << " to "
                    << DebugId(peer_id) << " - not in map.";
      return;
    } else {
      transport_to_close = (*itr).second;
    }
  }
  transport_to_close->CloseConnection(peer_id);
}

void ManagedConnections::Send(NodeId peer_id, std::string message,
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
      std::thread thread(message_sent_functor, kInvalidConnection);
      thread.detach();
    }
  }
}

void ManagedConnections::OnMessageSlot(const std::string& message) {
  LOG(kVerbose) << "\n^^^^^^^^^^^^ OnMessageSlot ^^^^^^^^^^^^\n" + DebugString();

  try {
    std::shared_ptr<std::string> decrypted_message(new std::string(
#ifdef TESTING
        !Parameters::rudp_encrypt ? message :
#endif
            asymm::Decrypt(asymm::CipherText(message), *private_key_).string()));
    MessageReceivedFunctor local_callback;
    {
      std::lock_guard<std::mutex> guard(callback_mutex_);
      local_callback = message_received_functor_;
    }

    if (local_callback) {
      asio_service_.service().post([=] { local_callback(*decrypted_message); });
    }
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to decrypt message: " << e.what();
  }
}

void ManagedConnections::SetConnectionAddedFunctor(const ConnectionAddedFunctor& handler) {
  assert(!connection_added_functor_);
  connection_added_functor_ = handler;
}

void ManagedConnections::OnConnectionAddedSlot(const NodeId& peer_id, TransportPtr transport,
                                               bool temporary_connection,
                                               std::atomic<bool> & is_duplicate_normal_connection) {
  is_duplicate_normal_connection = false;
  std::lock_guard<std::mutex> lock(mutex_);

  if (temporary_connection) {
    UpdateIdleTransports(transport);
  } else {
    RemovePending(peer_id);

    auto result                    = connections_.insert(std::make_pair(peer_id, transport));
    bool inserted                  = result.second;
    is_duplicate_normal_connection = !inserted;

    if (inserted) {
      idle_transports_.erase(transport);
    } else {
      UpdateIdleTransports(transport);

      LOG(kError) << (*result.first).second->ThisDebugId() << " is already connected to "
                  << DebugId(peer_id) << ".  Won't make duplicate normal connection on "
                  << transport->ThisDebugId();
    }

    if (connection_added_functor_) {
      auto f = std::move(connection_added_functor_);
      asio_service_.service().post([f, peer_id]() { f(peer_id); });
    }
  }

#ifndef NDEBUG
  auto itr(idle_transports_.begin());
  while (itr != idle_transports_.end()) {
    // assert((*itr)->IsIdle());
    if (!(*itr)->IsAvailable())
      itr = idle_transports_.erase(itr);
    else
      ++itr;
  }
#endif
}

unsigned ManagedConnections::GetActiveConnectionCount() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<unsigned>(connections_.size());
}

void ManagedConnections::UpdateIdleTransports(const TransportPtr& transport) {
  if (transport->IsIdle()) {
    assert(transport->IsAvailable());
    idle_transports_.insert(transport);
  } else {
    idle_transports_.erase(transport);
  }
}

void ManagedConnections::OnConnectionLostSlot(const NodeId& peer_id, TransportPtr transport,
                                              bool temporary_connection) {
  std::lock_guard<std::mutex> lock(mutex_);
  UpdateIdleTransports(transport);

  if (temporary_connection)
    return;

  // If this is a bootstrap connection, it may have already had GetAvailableEndpoint called on it,
  // but not yet had Add called, in which case peer_id will be in pendings_.  In all other cases,
  // peer_id should not be in pendings_.
  RemovePending(peer_id);

  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second != transport) {
      LOG(kError) << "peer_id: " << DebugId(peer_id) << " is connected via "
                  << (*itr).second->local_endpoint() << " not " << transport->local_endpoint();
      BOOST_ASSERT(false);
    }

    connections_.erase(itr);

    if (peer_id == chosen_bootstrap_node_id_) {
      chosen_bootstrap_node_id_ = NodeId();
    }

    ConnectionLostFunctor local_callback;
    {
      std::lock_guard<std::mutex> guard(callback_mutex_);
      local_callback = connection_lost_functor_;
    }

    if (local_callback) {
      asio_service_.service().post([=] { local_callback(peer_id); });
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
  auto itr(std::find_if(connections_.begin(), connections_.end(),
                        [&this_local_endpoint](const ConnectionMap::value_type & element) {
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
  std::lock_guard<std::mutex> lock(mutex_);
  // Not interested in the log once accumulated enough connections
  if (connections_.size() > 8)
    return "";

//  std::string s = "This node's peer connections:\n";
  std::set<TransportPtr> transports;
  for (auto connection : connections_) {
    transports.insert(connection.second);
//     s += '\t' + DebugId(connection.first).substr(0, 7) + '\n';
  }

  std::string s = "This node's own transports and their peer connections:\n";
  for (auto transport : transports)
    s += transport->DebugString();

  s += "\nThis node's idle transports:\n";
  for (auto idle_transport : idle_transports_)
    s += idle_transport->DebugString();

  s += "\nThis node's pending connections:\n";
  for (auto& pending : pendings_) {
    s += "\tPending to peer " + DebugId(pending->node_id).substr(0, 7);
    s += " on this node's transport ";
    s += boost::lexical_cast<std::string>(pending->pending_transport->external_endpoint()) + " / ";
    s += boost::lexical_cast<std::string>(pending->pending_transport->local_endpoint()) + '\n';
  }
  s += "\n\n";

  return s;
}

}  // namespace rudp

}  // namespace maidsafe
