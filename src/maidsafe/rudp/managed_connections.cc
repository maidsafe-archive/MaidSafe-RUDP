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
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

// 203.0.113.14:1314
const boost::asio::ip::udp::endpoint kNonRoutable(boost::asio::ip::address_v4(3405803790U), 1314);


namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;
typedef boost::shared_lock<boost::shared_mutex> SharedLock;
typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
typedef boost::upgrade_to_unique_lock<boost::shared_mutex> UpgradeToUniqueLock;

}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(Parameters::thread_count),
      message_received_functor_(),
      connection_lost_functor_(),
      private_key_(),
      public_key_(),
      transports_(),
      connection_map_(),
      pending_connections_(),
      mutex_(),
      local_ip_(),
      nat_type_(NatType::kUnknown),
      resilience_transport_() {}

ManagedConnections::~ManagedConnections() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto transport : transports_)
      transport.DisconnectSignalsAndClose();
  }
  resilience_transport_.DisconnectSignalsAndClose();
  asio_service_.Stop();
}

Endpoint ManagedConnections::Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                                       bool /*start_resilience_transport*/,
                                       MessageReceivedFunctor message_received_functor,
                                       ConnectionLostFunctor connection_lost_functor,
                                       std::shared_ptr<asymm::PrivateKey> private_key,
                                       std::shared_ptr<asymm::PublicKey> public_key,
                                       NatType& nat_type,
                                       Endpoint local_endpoint) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto transport : transports_)
      transport.DisconnectSignalsAndClose();
    transports_.clear();
    resilience_transport_.DisconnectSignalsAndClose();
    connection_map_.clear();
  }

  if (!message_received_functor) {
    LOG(kError) << "You must provide a valid MessageReceivedFunctor.";
    return Endpoint();
  }
  if (!connection_lost_functor) {
    LOG(kError) << "You must provide a valid ConnectionLostFunctor.";
    return Endpoint();
  }
  if (!private_key || !asymm::ValidateKey(*private_key) ||
      !public_key || !asymm::ValidateKey(*public_key)) {
    LOG(kError) << "You must provide a valid private and public key.";
    return Endpoint();
  }
  private_key_ = private_key;
  public_key_ = public_key;

  if (bootstrap_endpoints.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap endpoint.";
    return Endpoint();
  }

  asio_service_.Start();

  if (detail::IsValid(local_endpoint)) {
    local_ip_ = local_endpoint.address();
  } else {
    local_ip_ = detail::GetLocalIp();
    if (local_ip_.is_unspecified()) {
      LOG(kError) << "Failed to retrieve local IP.";
      return Endpoint();
    }
    local_endpoint = Endpoint(local_ip_, 0);
  }
  Endpoint chosen_bootstrap_endpoint;
  EndpointPair this_endpoint_pair;
  if (!StartNewTransport(bootstrap_endpoints, local_endpoint, chosen_bootstrap_endpoint,
                         this_endpoint_pair)) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return Endpoint();
  }

  nat_type = nat_type_;

  // Add callbacks now.
  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;

//  if (start_resilience_transport)
//    asio_service_.service().post([=] { StartResilienceTransport(); });  // NOLINT (Fraser)

  return chosen_bootstrap_endpoint;
}

bool ManagedConnections::StartNewTransport(std::vector<Endpoint> bootstrap_endpoints,
                                           Endpoint local_endpoint,
                                           Endpoint& chosen_bootstrap_endpoint,
                                           EndpointPair& this_endpoint_pair) {
  TransportAndSignalConnections transport_and_signals_connections;
  transport_and_signals_connections.transport =
      std::make_shared<detail::Transport>(asio_service_, nat_type_);
  bool bootstrap_off_existing_connection(bootstrap_endpoints.empty());
  boost::asio::ip::address external_address;
  if (bootstrap_off_existing_connection)
    GetBootstrapEndpoints(local_endpoint, bootstrap_endpoints, external_address);
  //else
  //  bootstrap_endpoints.insert(bootstrap_endpoints.begin(), Endpoint(local_ip_, kResiliencePort()));

  transport_and_signals_connections.transport->Bootstrap(
      bootstrap_endpoints,
      public_key_,
      local_endpoint,
      bootstrap_off_existing_connection,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3, _4),
      boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, _1, _2, _3),
      &chosen_bootstrap_endpoint,
      &transport_and_signals_connections.on_message_connection,
      &transport_and_signals_connections.on_connection_added_connection,
      &transport_and_signals_connections.on_connection_lost_connection);
  if (!detail::IsValid(chosen_bootstrap_endpoint)) {
    std::lock_guard<std::mutex> lock(mutex_);
    LOG(kWarning) << "Failed to start a new Transport.  "
                  << connection_map_.size() << " currently running.";
    transport_and_signals_connections.DisconnectSignalsAndClose();
    return false;
  }

  if (!detail::IsValid(transport_and_signals_connections.transport->external_endpoint()) &&
      !external_address.is_unspecified()) {
    // Means this node's NAT is symmetric or unknown, so guess that it will be mapped to existing
    // external address and local port.
    transport_and_signals_connections.transport->SetBestGuessExternalEndpoint(
        Endpoint(external_address,
                 transport_and_signals_connections.transport->local_endpoint().port()));
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    transports_.push_back(transport_and_signals_connections);
  }

  this_endpoint_pair.local = transport_and_signals_connections.transport->local_endpoint();
  this_endpoint_pair.external = transport_and_signals_connections.transport->external_endpoint();

  LOG(kVerbose) << "Started a new transport on " << this_endpoint_pair.external << " / "
                << this_endpoint_pair.local << " - NAT: " << static_cast<int>(nat_type_);
  return true;
}

void ManagedConnections::GetBootstrapEndpoints(const Endpoint& local_endpoint,
                                               std::vector<Endpoint>& bootstrap_endpoints,
                                               boost::asio::ip::address& this_external_address) {
  bool external_address_consistent(true);
  // Favour connections which are on a different network to this to allow calculation of the new
  // transport's external endpoint.
  std::vector<Endpoint> secondary_endpoints;
  bootstrap_endpoints.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  secondary_endpoints.reserve(Parameters::max_transports * detail::Transport::kMaxConnections());
  std::lock_guard<std::mutex> lock(mutex_);
  std::for_each(connection_map_.begin(),
                connection_map_.end(),
                [&](const ConnectionMap::value_type& entry) {
    if (detail::OnSameLocalNetwork(local_endpoint, entry.first)) {
      secondary_endpoints.push_back(entry.first);
    } else {
      bootstrap_endpoints.push_back(entry.first);
      if (this_external_address.is_unspecified())
        this_external_address = entry.second->external_endpoint().address();
      else if (this_external_address != entry.second->external_endpoint().address())
        external_address_consistent = false;
    }
  });
  if (!external_address_consistent)
    this_external_address = boost::asio::ip::address();
  std::random_shuffle(bootstrap_endpoints.begin(), bootstrap_endpoints.end());
  std::random_shuffle(secondary_endpoints.begin(), secondary_endpoints.end());
  bootstrap_endpoints.insert(bootstrap_endpoints.end(),
                             secondary_endpoints.begin(),
                             secondary_endpoints.end());
}

int ManagedConnections::GetAvailableEndpoint(const Endpoint& peer_endpoint,
                                             EndpointPair& this_endpoint_pair,
                                             NatType& this_nat_type) {
  int transports_size(0);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    transports_size = static_cast<int>(transports_.size());
    if (transports_size == 0) {
      LOG(kError) << "No running Transports.";
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      this_nat_type = NatType::kUnknown;
      return kNotBootstrapped;
    }

    if (detail::IsValid(peer_endpoint)) {
      auto connection_map_itr = connection_map_.find(peer_endpoint);
      if (connection_map_itr != connection_map_.end()) {
        Endpoint this_endpoint =
            (*connection_map_itr).second->ThisEndpointAsSeenByPeer(peer_endpoint);
        if (detail::OnPrivateNetwork(this_endpoint)) {
          this_endpoint_pair.external = Endpoint();
          this_endpoint_pair.local = this_endpoint;
        } else {
          this_endpoint_pair.external = this_endpoint;
          this_endpoint_pair.local = Endpoint();
        }
        this_nat_type = nat_type_;
        return kSuccess;
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
      }
    }
  }

  bool start_new_transport(false);
  if (nat_type_ == NatType::kSymmetric) {
    if (detail::IsValid(peer_endpoint))
      start_new_transport = !detail::OnPrivateNetwork(peer_endpoint);
    else
      start_new_transport = true;
  } else {
    start_new_transport = transports_size < Parameters::max_transports;
  }

  if (start_new_transport) {
    Endpoint chosen_bootstrap_endpoint;
    if (StartNewTransport(std::vector<Endpoint>(), Endpoint(local_ip_, 0),
                          chosen_bootstrap_endpoint, this_endpoint_pair)) {
      std::lock_guard<std::mutex> lock(mutex_);
      this_nat_type = nat_type_;
      return kSuccess;
    } else {
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      std::lock_guard<std::mutex> lock(mutex_);
      this_nat_type = NatType::kUnknown;
      return connection_map_.empty() ? kNotBootstrapped : kTransportStartFailure;
    }
  }

  // Get transport with least connections.  If we were given a valid peer_endpoint, also ensure it
  // is possible to connect (i.e. it's on the same local network, or it's a non-local address and we
  // have established our external address)
  {
    size_t least_connections(detail::Transport::kMaxConnections());
    std::lock_guard<std::mutex> lock(mutex_);
    std::for_each(
        transports_.begin(),
        transports_.end(),
        [&](const TransportAndSignalConnections& element) {
      if (element.transport->ConnectionsCount() < least_connections) {
        if (!detail::IsValid(peer_endpoint) ||
            detail::IsConnectable(peer_endpoint,
                                  element.transport->local_endpoint(),
                                  element.transport->external_endpoint())) {
          least_connections = element.transport->ConnectionsCount();
          this_endpoint_pair.local = element.transport->local_endpoint();
          this_endpoint_pair.external = element.transport->external_endpoint();
        }
      }
    });

    if (!detail::IsValid(this_endpoint_pair.local)) {
      LOG(kError) << "All connectable Transports are full.";
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      return kFull;
    }

    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint& this_endpoint,
                            const Endpoint& peer_endpoint,
                            const std::string& validation_data) {
  if (!detail::IsValid(this_endpoint)) {
    LOG(kError) << "Invalid this_endpoint passed.";
    return kInvalidEndpoint;
  }
  if (!detail::IsValid(peer_endpoint)) {
    LOG(kError) << "Invalid peer_endpoint passed.";
    return kInvalidEndpoint;
  }
  if (validation_data.empty()) {
    LOG(kError) << "Invalid peer_endpoint passed.";
    return kEmptyValidationData;
  }

  detail::TransportPtr transport;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    // Check there's not already an ongoing connection attempt to this endpoint
    auto pending_itr = pending_connections_.find(peer_endpoint);
    if (pending_itr == pending_connections_.end()) {
      pending_connections_.insert(peer_endpoint);
    } else {
      LOG(kWarning) << "Already an ongoing connection attempt to " << peer_endpoint;
      return kConnectAttemptAlreadyRunning;
    }

    auto itr = std::find_if(
        transports_.begin(),
        transports_.end(),
        [&this_endpoint] (const TransportAndSignalConnections& element) {
      return element.transport->external_endpoint() == this_endpoint ||
             element.transport->local_endpoint() == this_endpoint;
    });

    if (itr == transports_.end()) {
      LOG(kError) << "No Transports have endpoint " << this_endpoint
                  << " - ensure GetAvailableEndpoint has been called first.";
      pending_connections_.erase(peer_endpoint);
      return kInvalidTransport;
    }

    transport = (*itr).transport;
    auto connection_map_itr = connection_map_.find(peer_endpoint);
    if (connection_map_itr != connection_map_.end()) {
      if ((*connection_map_itr).second->IsTemporaryConnection(peer_endpoint)) {
        if (transport->Send(peer_endpoint,
                            validation_data,
                            [](int result) {
                              if (result != kSuccess) {
                                LOG(kWarning) << "Failed to send validation data on bootstrap "
                                              << "connection.  Result: " << result;
                              }
                            })) {
          pending_connections_.erase(peer_endpoint);
          return kSuccess;
        } else {
          // There's a good chance that if this error happens, we've already got a temporary
          // (60 second) connection to this peer - i.e. peer bootstrapped off this node, and before
          // the connection was added, this node called GetAvailableEndpoint, the peer's
          // endpoint wasn't found in the map, so a this node started a new transport.  Less likely
          // is the case where this node bootstrapped off peer, but we've called
          // GetAvailableEndpoint with an empty (or different) peer_endpoint, which returned a
          // different transport to the one with the bootstrap connection, or peer bootstrapped
          LOG(kWarning) << "Failed to make existing temporary connection to " << peer_endpoint
                        << " permanent.  Trying to establish new connection.";
        }
      } else {
        LOG(kError) << "A permanent managed connection to " << peer_endpoint << " already exists";
        pending_connections_.erase(peer_endpoint);
        return kConnectionAlreadyExists;
      }
    }
  }

  LOG(kInfo) << "Attempting to connect from "<< transport->local_endpoint() << " to  "
             << peer_endpoint;
  transport->Connect(peer_endpoint, validation_data);
  return kSuccess;
}

Endpoint ManagedConnections::MarkConnectionAsValid(const Endpoint& peer_endpoint) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kWarning) << "Can't mark connection to " << peer_endpoint << " as valid - not in map.";
    return Endpoint();
  }
  return (*itr).second->MakeConnectionPermanent(peer_endpoint);
}

void ManagedConnections::Remove(const Endpoint& peer_endpoint) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kWarning) << "Can't remove " << peer_endpoint << " - not in map.";
    return;
  }
  (*itr).second->CloseConnection(peer_endpoint);
}

void ManagedConnections::Send(const Endpoint& peer_endpoint,
                              const std::string& message,
                              MessageSentFunctor message_sent_functor) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kError) << "Can't send to " << peer_endpoint << " - not in map.";
    if (message_sent_functor) {
      if (!connection_map_.empty()) {
        asio_service_.service().post([message_sent_functor] {
          message_sent_functor(kInvalidConnection);
        });
      } else {
        // Probably haven't bootstrapped, so asio_service_ won't be running.
        boost::thread(message_sent_functor, kInvalidConnection);
      }
    }
    return;
  }
  (*itr).second->Send(peer_endpoint, message, message_sent_functor);
}

void ManagedConnections::Ping(const Endpoint& peer_endpoint, PingFunctor ping_functor) {
  if (!ping_functor) {
    LOG(kWarning) << "No functor passed - not pinging.";
    return;
  }

  if (transports_.empty()) {
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
  if (std::find_if(transports_.begin(),
                   transports_.end(),
                   [&peer_endpoint](const TransportAndSignalConnections& tprt_and_sigs_conns) {
                     return tprt_and_sigs_conns.transport->local_endpoint() == peer_endpoint ||
                            tprt_and_sigs_conns.transport->external_endpoint() == peer_endpoint;
                   }) != transports_.end()) {
    LOG(kError) << "Trying to ping ourself.";
    asio_service_.service().post([ping_functor] { ping_functor(kWontPingOurself); });  // NOLINT (Fraser)
    return;
  }

  size_t index(RandomUint32() % transports_.size());
  transports_[index].transport->Ping(peer_endpoint, ping_functor);
}

void ManagedConnections::StartResilienceTransport() {
  resilience_transport_.transport = std::make_shared<detail::Transport>(asio_service_, nat_type_);
  std::vector<Endpoint> bootstrap_endpoints;
  boost::asio::ip::address external_address;
  GetBootstrapEndpoints(Endpoint(local_ip_, 0), bootstrap_endpoints, external_address);

  Endpoint chosen_endpoint;
  resilience_transport_.transport->Bootstrap(
      bootstrap_endpoints,
      public_key_,
      Endpoint(local_ip_, ManagedConnections::kResiliencePort()),
      true,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3, _4),
      boost::bind(&ManagedConnections::OnNatDetectionRequestedSlot, this, _1, _2, _3),
      &chosen_endpoint,
      &resilience_transport_.on_message_connection,
      &resilience_transport_.on_connection_added_connection,
      &resilience_transport_.on_connection_lost_connection);

  if (!detail::IsValid(chosen_endpoint))
    resilience_transport_.DisconnectSignalsAndClose();
}

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

void ManagedConnections::OnConnectionAddedSlot(const Endpoint& peer_endpoint,
                                               detail::TransportPtr transport) {
  std::lock_guard<std::mutex> lock(mutex_);

    std::string s("\n++++++++++++ OnConnectionAddedSlot to ");
    s += peer_endpoint.address().to_string() + ":";
    s += boost::lexical_cast<std::string>(peer_endpoint.port()) + " ++++++++++++\n" + DebugString();
    LOG(kVerbose) << s;

  auto result(connection_map_.insert(std::make_pair(peer_endpoint, transport)));
  pending_connections_.erase(peer_endpoint);
  if (result.second) {
    LOG(kSuccess) << "Successfully connected from " << transport->external_endpoint() << " / "
                  << transport->local_endpoint() << " to " << peer_endpoint;
  } else {
    LOG(kError) << transport->local_endpoint() << " is already connected to " << peer_endpoint;
  }
}

void ManagedConnections::OnConnectionLostSlot(const Endpoint& peer_endpoint,
                                              detail::TransportPtr transport,
                                              bool connections_empty,
                                              bool temporary_connection) {
  bool should_execute_functor(false);
  {
    bool remove_transport(connections_empty && !transport->IsResilienceTransport());
    std::lock_guard<std::mutex> lock(mutex_);

    std::string s("\n************ OnConnectionLostSlot to ");
    s += peer_endpoint.address().to_string() + ":";
    s += boost::lexical_cast<std::string>(peer_endpoint.port()) + " ************\n" + DebugString();
    LOG(kVerbose) << s;

    auto connection_itr(connection_map_.find(peer_endpoint));
    if (connection_itr == connection_map_.end()) {
      if (temporary_connection)
        remove_transport = false;
      else
        LOG(kWarning) << "Was not connected to " << peer_endpoint;
    } else {
      // If this is a temporary connection to allow this node to bootstrap a new transport off an
      // existing connection, the transport endpoint passed into the slot will not be the same one
      // that is listed against the peer's endpoint in the connection_map_.
      if (transport->local_endpoint() == (*connection_itr).second->local_endpoint()) {
        connection_map_.erase(connection_itr);
        should_execute_functor = true;
        LOG(kInfo) << "Removed managed connection from " << transport->local_endpoint() << " to "
                   << peer_endpoint
                   << (remove_transport ? " - also removing corresponding transport.  Now have " :
                                          " - not removing transport.  Now have ")
                   << connection_map_.size() << " connections.";
      } else {
        std::string msg("Not removing managed connection from ");
        msg += (*connection_itr).second->local_endpoint().address().to_string();
        msg += ":" + boost::lexical_cast<std::string>(
                         (*connection_itr).second->local_endpoint().port());
        msg += " to " + peer_endpoint.address().to_string();
        msg += ":" + boost::lexical_cast<std::string>(peer_endpoint.port());
        msg += "  Now have " + boost::lexical_cast<std::string>(connection_map_.size());
        msg += " connections.";
        LOG(kInfo) << msg;
//        LOG(kInfo) << "Not removing managed connection from "
//                   << (*connection_itr).second->local_endpoint() << " to " << peer_endpoint
//                   << "  Now have " << connection_map_.size() << " connections.";
        BOOST_ASSERT_MSG(temporary_connection, msg.c_str());
        remove_transport = false;
      }
    }
    pending_connections_.erase(peer_endpoint);

    if (remove_transport) {
      auto itr(std::find_if(
          transports_.begin(),
          transports_.end(),
          [&transport](const TransportAndSignalConnections& element) {
            return transport == element.transport;
          }));

      if (itr == transports_.end()) {
        LOG(kError) << "Failed to find transport in vector.";
      } else {
        (*itr).DisconnectSignalsAndClose();
        transports_.erase(itr);
      }
    }
  }

  if (should_execute_functor) {
    LOG(kVerbose) << "Firing connection_lost_functor_ for " << peer_endpoint;
    asio_service_.service().post([=] { connection_lost_functor_(peer_endpoint); });  // NOLINT (Fraser)
  }
}

void ManagedConnections::OnNatDetectionRequestedSlot(const Endpoint& this_local_endpoint,
                                                     const Endpoint& peer_endpoint,
                                                     uint16_t& another_external_port) {
  if (nat_type_ == NatType::kUnknown || nat_type_ == NatType::kSymmetric) {
    another_external_port = 0;
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(std::find_if(
      transports_.begin(),
      transports_.end(),
      [&this_local_endpoint](const TransportAndSignalConnections& element) {
        return this_local_endpoint != element.transport->local_endpoint();
      }));

  if (itr == transports_.end()) {
    another_external_port = 0;
    return;
  }

  another_external_port = (*itr).transport->external_endpoint().port();
  // This node doesn't care about the Ping result, but Ping should not be given a NULL functor.
  (*itr).transport->Ping(peer_endpoint, [](int) {});  // NOLINT (Fraser)
}



ManagedConnections::TransportAndSignalConnections::TransportAndSignalConnections()
    : transport(),
      on_message_connection(),
      on_connection_added_connection(),
      on_connection_lost_connection() {}

void ManagedConnections::TransportAndSignalConnections::DisconnectSignalsAndClose() {
  on_connection_added_connection.disconnect();
  on_connection_lost_connection.disconnect();
  on_message_connection.disconnect();
  if (transport)
    transport->Close();
}

std::string ManagedConnections::DebugString() {
  std::string s = "This node's own transports and their peer connections:\n";
  for (auto t : transports_)
    s += t.transport->DebugString();

  s += "\nThis node's own ConnectionMap:\n";
  for (auto c : connection_map_) {
    s += std::string("\tPeer ") + c.first.address().to_string() + ":";
    s += boost::lexical_cast<std::string>(c.first.port()) + " connected to this node's ";
    s += c.second->external_endpoint().address().to_string() + ":";
    s += boost::lexical_cast<std::string>(c.second->external_endpoint().port()) + " / ";
    s += c.second->local_endpoint().address().to_string() + ":";
    s += boost::lexical_cast<std::string>(c.second->local_endpoint().port()) + "\n";
  }

  s += "\nThis node's pending connections:\n";
  for (auto p : pending_connections_) {
    s += "\t" + p.address().to_string() + ":";
    s += boost::lexical_cast<std::string>(p.port()) + "\n";
  }

  s += "\nThis node's resilience transport:\n";
  s += (resilience_transport_.transport ? resilience_transport_.transport->DebugString() :
                                          "\tNot running");
  s += "\n\n";

  return s;
}

}  // namespace rudp

}  // namespace maidsafe
