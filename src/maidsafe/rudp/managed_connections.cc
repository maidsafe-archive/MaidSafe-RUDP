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
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

#ifdef TESTING
void set_debug_packet_loss_rate(double constant, double bursty) {
  detail::Multiplexer::set_debug_packet_loss_rate(constant, bursty);
}
#endif

namespace {

// Legacy functors to be removed
using MessageReceivedFunctor = std::function<void(const std::string& /*message*/)>;
using ConnectionLostFunctor = std::function<void(const connection_id& /*peer_id*/)>;

int CheckBootstrappingParameters(const BootstrapList& bootstrap_list,
                                 std::shared_ptr<managed_connections::listener> listener,
                                 connection_id this_node_id) {
  if (!listener) {
    LOG(kError) << "You must provide a non-null listener.";
    return kInvalidParameter;
  }
  if (!this_node_id.IsValid()) {
    LOG(kError) << "You must provide a valid connection_id.";
    return kInvalidParameter;
  }
  if (bootstrap_list.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap contact.";
    return kNoBootstrapEndpoints;
  }

  return kSuccess;
}

}  // unnamed namespace

managed_connections::PendingConnection::PendingConnection(connection_id node_id_in, TransportPtr transport,
                                                         boost::asio::io_service& io_service)
    : node_id(std::move(node_id_in)),
      pending_transport(std::move(transport)),
      timer(io_service,
            bptime::microsec_clock::universal_time() + Parameters::rendezvous_connect_timeout),
      connecting(false) {}

managed_connections::managed_connections()
    : asio_service_(Parameters::thread_count),
      listener_(),
      this_node_id_(),
      chosen_bootstrap_contact_(),
      keys_(),
      connections_(),
      pendings_(),
      idle_transports_(),
      mutex_(),
      local_ip_(),
      nat_type_(maidsafe::make_unique<nat_type>(nat_type::unknown)) {}

managed_connections::~managed_connections() {
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

int managed_connections::Bootstrap(const BootstrapList& bootstrap_list,
                                  std::shared_ptr<listener> listener, connection_id this_node_id,
                                  asymm::Keys keys, contact& chosen_bootstrap_contact,
                                  endpoint local_endpoint) {
  ClearConnectionsAndIdleTransports();
  int result(CheckBootstrappingParameters(bootstrap_list, listener, this_node_id));
  if (result != kSuccess)
    return result;

  this_node_id_ = std::move(this_node_id);
  keys_ = std::move(keys);

  result = TryToDetermineLocalEndpoint(local_endpoint);
  if (result != kSuccess)
    return result;

  result = AttemptStartNewTransport(bootstrap_list, local_endpoint, chosen_bootstrap_contact);
  if (result != kSuccess)
    return result;

  listener_ = listener;
  return kSuccess;
}

void managed_connections::ClearConnectionsAndIdleTransports() {
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

int managed_connections::TryToDetermineLocalEndpoint(endpoint& local_endpoint) {
  bool zero_state(detail::IsValid(local_endpoint));
  if (zero_state) {
    local_ip_ = local_endpoint.address();
  } else {
    local_ip_ = GetLocalIp();
    if (local_ip_.is_unspecified()) {
      LOG(kError) << "Failed to retrieve local IP.";
      return kFailedToGetLocalAddress;
    }
    local_endpoint = endpoint(local_ip_, 0);
  }
  return kSuccess;
}

int managed_connections::AttemptStartNewTransport(
    const BootstrapList& bootstrap_list, const endpoint& local_endpoint,
    contact& chosen_bootstrap_contact) {
  ReturnCode result = StartNewTransport(bootstrap_list, local_endpoint);
  if (result != kSuccess) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return result;
  }
  chosen_bootstrap_contact = chosen_bootstrap_contact_;
  return kSuccess;
}

ReturnCode managed_connections::StartNewTransport(BootstrapList bootstrap_list,
                                                 endpoint local_endpoint) {
  TransportPtr transport(std::make_shared<detail::Transport>(asio_service_, *nat_type_));

  transport->SetManagedConnectionsDebugPrintout([this]() { return DebugString(); });

  bool bootstrap_off_existing_connection(bootstrap_list.empty());
  boost::asio::ip::address external_address;
  if (bootstrap_off_existing_connection)
    GetBootstrapEndpoints(bootstrap_list, external_address);

  {
    std::lock_guard<std::mutex> lock(mutex_);

    // Should not bootstrap from the transport belonging to the same routing object
    for (const auto& element : idle_transports_) {
      bootstrap_list.erase(std::remove_if(bootstrap_list.begin(), bootstrap_list.end(),
                                          [&element](const BootstrapList::value_type& entry) {
                             return entry.endpoint_pair.local == element->local_endpoint();
                           }),
                           bootstrap_list.end());
    }
  }

  using lock_guard = std::lock_guard<std::mutex>;
  std::promise<ReturnCode> setter;
  auto getter = setter.get_future();

  auto on_bootstrap = [&](ReturnCode bootstrap_result, contact chosen_contact) {
    if (bootstrap_result != kSuccess) {
      lock_guard lock(mutex_);
      transport->Close();
      return setter.set_value(bootstrap_result);
    }

    if (!chosen_bootstrap_contact_.id.IsValid())
      chosen_bootstrap_contact_ = chosen_contact;

    if (!detail::IsValid(transport->external_endpoint()) && !external_address.is_unspecified()) {
      // Means this node's NAT is symmetric or unknown, so guess that it will be mapped to existing
      // external address and local port.
      transport->SetBestGuessExternalEndpoint(
          endpoint(external_address, transport->local_endpoint().port()));
    }

    lock_guard guard(mutex_);
    return setter.set_value(kSuccess);
  };

  transport->Bootstrap(
      bootstrap_list, this_node_id_, keys_.public_key, local_endpoint,
      bootstrap_off_existing_connection,
      std::bind(&managed_connections::OnMessageSlot, this, args::_1),
      [this](const connection_id & peer_id, TransportPtr transport, bool temporary_connection,
             std::atomic<bool> & is_duplicate_normal_connection) {
        OnConnectionAddedSlot(peer_id, transport, temporary_connection,
                              is_duplicate_normal_connection);
      },
      std::bind(&managed_connections::OnConnectionLostSlot, this, args::_1, args::_2, args::_3),
      std::bind(&managed_connections::OnNatDetectionRequestedSlot, this, args::_1, args::_2,
                args::_3, args::_4),
      on_bootstrap);

  getter.wait();
  { lock_guard guard(mutex_); }
  auto result = getter.get();

  if (result == kSuccess) {
    LOG(kVerbose) << "Started a new transport on " << transport->external_endpoint() << " / "
                  << transport->local_endpoint() << " behind " << *nat_type_;
  } else {
    LOG(kWarning) << "Failed to start a new Transport.";
  }

  return result;
}

void managed_connections::GetBootstrapEndpoints(BootstrapList& bootstrap_list,
                                               boost::asio::ip::address& this_external_address) {
  bool external_address_consistent(true);
  // Favour connections which are on a different network to this to allow calculation of the new
  // transport's external endpoint.
  BootstrapList secondary_list;
  bootstrap_list.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  secondary_list.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  std::set<endpoint> non_duplicates;
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto element : connections_) {
    std::shared_ptr<detail::Connection> connection(element.second->GetConnection(element.first));
    if (!connection)
      continue;
    if (!non_duplicates.insert(connection->Socket().PeerEndpoint()).second)
      continue;  // Already have this endpoint added to bootstrap_contacts or secondary_endpoints.
    contact peer(connection->Socket().PeerNodeId(), connection->Socket().PeerEndpoint(),
                 connection->Socket().PeerPublicKey());
    if (detail::OnPrivateNetwork(connection->Socket().PeerEndpoint())) {
      secondary_list.push_back(std::move(peer));
    } else {
      bootstrap_list.push_back(std::move(peer));
      endpoint this_endpoint_as_seen_by_peer(
          element.second->ThisEndpointAsSeenByPeer(element.first));
      if (this_external_address.is_unspecified())
        this_external_address = this_endpoint_as_seen_by_peer.address();
      else if (this_external_address != this_endpoint_as_seen_by_peer.address())
        external_address_consistent = false;
    }
  }
  if (!external_address_consistent)
    this_external_address = boost::asio::ip::address();
  std::random_shuffle(bootstrap_list.begin(), bootstrap_list.end());
  std::random_shuffle(secondary_list.begin(), secondary_list.end());
  bootstrap_list.insert(bootstrap_list.end(), secondary_list.begin(), secondary_list.end());
}

int managed_connections::GetAvailableEndpoint(const contact& peer,
                                             endpoint_pair& this_endpoint_pair) {
  if (peer.id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << this_node_id_ << ") as peerID.";
    return kOwnId;
  }

  // Functor to handle resetting parameters in case of failure.
  const auto kDoFail([&](const std::string & message, int result)->int {
                       this_endpoint_pair.external = this_endpoint_pair.local = endpoint();
                       if (!message.empty())
                         LOG(kError) << message;
                       return result;
  });

  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.empty() && idle_transports_.empty())
      return kDoFail("No running Transports.", kNotBootstrapped);

    // Check for an existing connection attempt.
    if (ExistingConnectionAttempt(peer.id, this_endpoint_pair))
      return kConnectAttemptAlreadyRunning;

    // Check for existing connection to peer.
    int return_code(kSuccess);
    if (ExistingConnection(peer.id, this_endpoint_pair, return_code)) {
      if (return_code == kConnectionAlreadyExists) {
        return kDoFail(std::string("A non-bootstrap managed connection from ") +
                           DebugId(this_node_id_) + std::string(" to ") + DebugId(peer.id) +
                           " already exists",
                       kConnectionAlreadyExists);
      } else {
        return return_code;
      }
    }

    // Try to use an existing idle transport.
    if (SelectIdleTransport(peer.id, this_endpoint_pair))
      return kSuccess;
  }

  if (ShouldStartNewTransport(peer.endpoint_pair) &&
      StartNewTransport(BootstrapList(), endpoint(local_ip_, 0)) != kSuccess) {
    return kDoFail("Failed to start transport.", kTransportStartFailure);
  }

  std::lock_guard<std::mutex> lock(mutex_);
  // Check again for an existing connection attempt in case it was added while mutex unlocked
  // during starting new transport.
  if (ExistingConnectionAttempt(peer.id, this_endpoint_pair))
    return kConnectAttemptAlreadyRunning;

  return SelectAnyTransport(peer.id, this_endpoint_pair)
             ? kSuccess
             : kDoFail("All connectable Transports are full.", kFull);
}

bool managed_connections::ExistingConnectionAttempt(const connection_id& peer_id,
                                                   endpoint_pair& this_endpoint_pair) const {
  auto existing_attempt(FindPendingTransportWithNodeId(peer_id));
  if (existing_attempt == pendings_.end())
    return false;

  this_endpoint_pair.local = (*existing_attempt)->pending_transport->local_endpoint();
  this_endpoint_pair.external = (*existing_attempt)->pending_transport->external_endpoint();
  assert((*existing_attempt)->pending_transport->IsAvailable());
  return true;
}

bool managed_connections::ExistingConnection(const connection_id& peer_id, endpoint_pair& this_endpoint_pair,
                                            int& return_code) {
  auto itr(connections_.find(peer_id));
  if (itr == connections_.end())
    return false;

  std::shared_ptr<detail::Connection> connection((*itr).second->GetConnection(peer_id));
  // assert(connection);
  if (!connection) {
    LOG(kError) << "Internal managed_connections error: mismatch between connections_ and "
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

bool managed_connections::SelectIdleTransport(const connection_id& peer_id,
                                             endpoint_pair& this_endpoint_pair) {
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

bool managed_connections::SelectAnyTransport(const connection_id& peer_id,
                                            endpoint_pair& this_endpoint_pair) {
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

managed_connections::TransportPtr managed_connections::GetAvailableTransport() const {
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

bool managed_connections::ShouldStartNewTransport(const endpoint_pair& peer_endpoint_pair) const {
  bool start_new_transport(false);
  if (*nat_type_ == nat_type::symmetric &&
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

void managed_connections::AddPending(std::unique_ptr<PendingConnection> connection) {
  connection_id peer_id(connection->node_id);
  pendings_.push_back(std::move(connection));
  pendings_.back()->timer.async_wait([peer_id, this](const boost::system::error_code & ec) {
    if (ec != boost::asio::error::operation_aborted) {
      std::lock_guard<std::mutex> lock(mutex_);
      RemovePending(peer_id);
    }
  });
}

void managed_connections::RemovePending(const connection_id& peer_id) {
  auto itr(FindPendingTransportWithNodeId(peer_id));
  if (itr != pendings_.end())
    pendings_.erase(itr);
}

std::vector<std::unique_ptr<managed_connections::PendingConnection>>::const_iterator
    managed_connections::FindPendingTransportWithNodeId(const connection_id& peer_id) const {
  return std::find_if(pendings_.cbegin(), pendings_.cend(),
                      [&peer_id](const std::unique_ptr<PendingConnection> &
                                 element) { return element->node_id == peer_id; });
}

std::vector<std::unique_ptr<managed_connections::PendingConnection>>::iterator
    managed_connections::FindPendingTransportWithNodeId(const connection_id& peer_id) {
  return std::find_if(pendings_.begin(), pendings_.end(),
                      [&peer_id](const std::unique_ptr<PendingConnection> &
                                 element) { return element->node_id == peer_id; });
}

void managed_connections::Add(const contact& peer, ConnectionAddedFunctor connection_added_functor) {
  if (peer.id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << this_node_id_ << ") as peerID.";
    return asio_service_.service().post([=] { connection_added_functor(peer.id, kOwnId); });
  }

  std::lock_guard<std::mutex> lock(mutex_);

  auto itr(FindPendingTransportWithNodeId(peer.id));
  if (itr == pendings_.end()) {
    if (connections_.find(peer.id) != connections_.end()) {
      LOG(kWarning) << "A managed connection from " << this_node_id_ << " to "
                    << peer.id << " already exists, and this node's chosen BootstrapID is "
                    << chosen_bootstrap_contact_.id;
      return asio_service_.service().post(
          [=] { connection_added_functor(peer.id, kConnectionAlreadyExists); });
    }
    LOG(kError) << "No connection attempt from " << this_node_id_ << " to "
                << peer.id << " - ensure GetAvailableEndpoint has been called first.";
    return asio_service_.service().post(
        [=] { connection_added_functor(peer.id, kNoPendingConnectAttempt); });
  }

  if ((*itr)->connecting) {
    LOG(kWarning) << "A connection attempt from " << this_node_id_ << " to "
                  << peer.id << " is already happening";
    return asio_service_.service().post(
        [=] { connection_added_functor(peer.id, kConnectAttemptAlreadyRunning); });
  }

  TransportPtr selected_transport((*itr)->pending_transport);
  (*itr)->connecting = true;

  std::shared_ptr<detail::Connection> connection(selected_transport->GetConnection(peer.id));
  if (connection) {
    // If the connection exists, it should be a bootstrapping one.  If the peer used this node,
    // the connection state should be kBootstrapping.  However, if this node bootstrapped off the
    // peer, the peer's validation data will probably already have been received and may have
    // caused the MarkConnectionAsValid to have already been called.  In this case only, the
    // connection will be kPermanent.
    if (connection->state() == detail::Connection::State::kBootstrapping ||
      (chosen_bootstrap_contact_.id == peer.id &&
      connection->state() == detail::Connection::State::kPermanent)) {
      if (connection->state() == detail::Connection::State::kBootstrapping) {
        endpoint peer_endpoint;
        assert(detail::IsValid(peer_endpoint) ? peer_endpoint == connection->Socket().PeerEndpoint()
          : true);
      }
      return asio_service_.service().post([=] { connection_added_functor(peer.id, kSuccess); });
    } else {
      LOG(kError) << "A managed connection from " << this_node_id_ << " to "
                  << peer.id << " already exists, and this node's chosen bootstrap ID is "
                  << chosen_bootstrap_contact_.id;
      pendings_.erase(itr);
      return asio_service_.service().post(
          [=] { connection_added_functor(peer.id, kConnectionAlreadyExists); });
    }
  }

  selected_transport->Connect(std::move(peer.id), std::move(peer.endpoint_pair),
                              std::move(peer.public_key), connection_added_functor);
}

void managed_connections::Remove(const connection_id& peer_id) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << this_node_id_ << ") as peerID.";
    return;
  }

  TransportPtr transport_to_close;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr(connections_.find(peer_id));
    if (itr == connections_.end()) {
      LOG(kWarning) << "Can't remove connection from " << this_node_id_ << " to "
                    << peer_id << " - not in map.";
      return;
    } else {
      transport_to_close = (*itr).second;
    }
  }
  transport_to_close->CloseConnection(peer_id);
}

void managed_connections::Send(const connection_id& peer_id, std::vector<unsigned char>&& message,
                              MessageSentFunctor message_sent_functor) {
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << this_node_id_ << ") as peerID.";
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connections_.find(peer_id));
  if (itr != connections_.end()) {
    if ((*itr).second->Send(peer_id, std::string(std::begin(message), std::end(message)),
                            message_sent_functor)) {
      return;
    }
  }
  LOG(kError) << "Can't send from " << this_node_id_ << " to " << peer_id << " - not in map.";
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

void managed_connections::OnMessageSlot(const std::string& message) {
  try {
    std::string decrypted_message(
#ifdef TESTING
        !Parameters::rudp_encrypt ? message :
#endif
            asymm::Decrypt(asymm::CipherText(message), keys_.private_key).string());
    if (auto listener = listener_.lock()) {
      listener->message_received(
          std::vector<unsigned char>(std::begin(message), std::end(message)));
    }
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to decrypt message: " << e.what();
  }
}

void managed_connections::OnConnectionAddedSlot(const connection_id& peer_id, TransportPtr transport,
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
                  << peer_id << ".  Won't make duplicate normal connection on "
                  << transport->ThisDebugId();
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

void managed_connections::UpdateIdleTransports(const TransportPtr& transport) {
  if (transport->IsIdle()) {
    assert(transport->IsAvailable());
    idle_transports_.insert(transport);
  } else {
    idle_transports_.erase(transport);
  }
}

void managed_connections::OnConnectionLostSlot(const connection_id& peer_id, TransportPtr transport,
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
      LOG(kError) << "peer_id: " << peer_id << " is connected via "
                  << (*itr).second->local_endpoint() << " not " << transport->local_endpoint();
      BOOST_ASSERT(false);
    }

    connections_.erase(itr);

    if (peer_id == chosen_bootstrap_contact_.id)
      chosen_bootstrap_contact_ = contact();
    
    if (auto listener = listener_.lock())
      listener->connection_lost(peer_id);
  }
}

void managed_connections::OnNatDetectionRequestedSlot(const endpoint& this_local_endpoint,
                                                     const connection_id& peer_id,
                                                     const endpoint& peer_endpoint,
                                                     uint16_t& another_external_port) {
  if (*nat_type_ == nat_type::unknown || *nat_type_ == nat_type::symmetric) {
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

std::string managed_connections::DebugString() const {
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
