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

#include <functional>
#include <iterator>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace {

typedef boost::asio::ip::udp::endpoint Endpoint;
typedef boost::shared_lock<boost::shared_mutex> SharedLock;
typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
typedef boost::upgrade_to_unique_lock<boost::shared_mutex> UpgradeToUniqueLock;

const int kMaxTransports(10);

}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(Parameters::thread_count),
      message_received_functor_(),
      connection_lost_functor_(),
      transports_(),
      connection_map_(),
      shared_mutex_(),
      local_ip_() {}

ManagedConnections::~ManagedConnections() {
  {
    UniqueLock unique_lock(shared_mutex_);
    std::for_each(transports_.begin(),
                  transports_.end(),
                  [](const TransportAndSignalConnections& element) {
      element.on_connection_lost_connection.disconnect();
      element.on_connection_added_connection.disconnect();
      element.on_message_connection.disconnect();
      element.transport->Close();
    });
  }
  asio_service_.Stop();
}

Endpoint ManagedConnections::Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                                       MessageReceivedFunctor message_received_functor,
                                       ConnectionLostFunctor connection_lost_functor,
                                       std::shared_ptr<asymm::PrivateKey> private_key,
                                       std::shared_ptr<asymm::PublicKey> public_key,
                                       boost::asio::ip::udp::endpoint local_endpoint) {
  {
    SharedLock shared_lock(shared_mutex_);
    if (!connection_map_.empty()) {
      LOG(kError) << "Already bootstrapped.";
      return Endpoint();
    }
    BOOST_ASSERT(transports_.empty());
  }

  if (!message_received_functor) {
    LOG(kError) << "You must provide a valid MessageReceivedFunctor.";
    return Endpoint();
  }
  message_received_functor_ = message_received_functor;
  if (!connection_lost_functor) {
    LOG(kError) << "You must provide a valid ConnectionLostFunctor.";
    return Endpoint();
  }
  connection_lost_functor_ = connection_lost_functor;
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

  if (IsValid(local_endpoint)) {
    local_ip_ = local_endpoint.address();
  } else {
    local_ip_ = GetLocalIp();
    if (local_ip_.is_unspecified()) {
      LOG(kError) << "Failed to retrieve local IP.";
      return Endpoint();
    }
    local_endpoint = Endpoint(local_ip_, 0);
  }
  Endpoint new_endpoint(StartNewTransport(bootstrap_endpoints, local_endpoint));
  if (!IsValid(new_endpoint)) {
    LOG(kError) << "Failed to bootstrap managed connections.";
    return Endpoint();
  }

  return new_endpoint;
}

Endpoint ManagedConnections::StartNewTransport(std::vector<Endpoint> bootstrap_endpoints,
                                               Endpoint local_endpoint) {
  TransportAndSignalConnections transport_and_signals_connections;
  transport_and_signals_connections.transport =
      std::make_shared<Transport>(asio_service_, public_key_);
  bool bootstrap_off_existing_connection(bootstrap_endpoints.empty());
  if (bootstrap_off_existing_connection) {
    bootstrap_endpoints.reserve(kMaxTransports * Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        connection_map_.begin(),
        connection_map_.end(),
        [&bootstrap_endpoints](const ConnectionMap::value_type& entry) {
      bootstrap_endpoints.push_back(entry.first);
    });
  }
  Endpoint chosen_endpoint;
  transport_and_signals_connections.transport->Bootstrap(
      bootstrap_endpoints,
      local_endpoint,
      bootstrap_off_existing_connection,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2, _3, _4),
      &chosen_endpoint,
      &transport_and_signals_connections.on_message_connection,
      &transport_and_signals_connections.on_connection_added_connection,
      &transport_and_signals_connections.on_connection_lost_connection);
  if (!IsValid(chosen_endpoint)) {
    SharedLock shared_lock(shared_mutex_);
    LOG(kWarning) << "Failed to start a new Transport.  "
                  << connection_map_.size() << " currently running.";
    transport_and_signals_connections.on_connection_added_connection.disconnect();
    transport_and_signals_connections.on_connection_lost_connection.disconnect();
    transport_and_signals_connections.on_message_connection.disconnect();
    transport_and_signals_connections.transport->Close();
    return Endpoint();
  }

  UniqueLock unique_lock(shared_mutex_);
  transports_.push_back(transport_and_signals_connections);
  return chosen_endpoint;
}

int ManagedConnections::GetAvailableEndpoint(const Endpoint& peer_endpoint,
                                             EndpointPair& this_endpoint_pair) {
  int transports_size(0);
  {
    SharedLock shared_lock(shared_mutex_);
    transports_size = static_cast<int>(transports_.size());

    if (IsValid(peer_endpoint)) {
      auto connection_map_itr = connection_map_.find(peer_endpoint);
      if (connection_map_itr != connection_map_.end()) {
        this_endpoint_pair.external = (*connection_map_itr).second->external_endpoint();
        this_endpoint_pair.local = (*connection_map_itr).second->local_endpoint();
        return kSuccess;
      }
    }
  }

  if (transports_size < kMaxTransports) {
    if (transports_size == 0) {
      LOG(kError) << "No running Transports.";
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      return kNotBootstrapped;
    }

    Endpoint new_endpoint(StartNewTransport(std::vector<Endpoint>(), Endpoint(local_ip_, 0)));
    if (IsValid(new_endpoint)) {
      UniqueLock unique_lock(shared_mutex_);
      this_endpoint_pair.external = (*transports_.rbegin()).transport->external_endpoint();
      this_endpoint_pair.local = (*transports_.rbegin()).transport->local_endpoint();
      return kSuccess;
    } else {
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      SharedLock shared_lock(shared_mutex_);
      return connection_map_.empty() ? kNotBootstrapped : kTransportStartFailure;
    }
  }

  // Get transport with least connections.
  {
    size_t least_connections(Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        transports_.begin(),
        transports_.end(),
        [&](const TransportAndSignalConnections& element) {
      if (element.transport->ConnectionsCount() < least_connections) {
        least_connections = element.transport->ConnectionsCount();
        this_endpoint_pair.external = element.transport->external_endpoint();
        this_endpoint_pair.local = element.transport->local_endpoint();
      }
    });

    if (!IsValid(this_endpoint_pair.external) || !IsValid(this_endpoint_pair.local)) {
      LOG(kError) << "All Transports are full.";
      this_endpoint_pair.external = this_endpoint_pair.local = Endpoint();
      return kFull;
    }

    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint& this_endpoint,
                            const Endpoint& peer_endpoint,
                            const std::string& validation_data) {
  if (!IsValid(this_endpoint)) {
    LOG(kError) << "Invalid this_endpoint passed.";
    return kInvalidEndpoint;
  }
  if (!IsValid(peer_endpoint)) {
    LOG(kError) << "Invalid peer_endpoint passed.";
    return kInvalidEndpoint;
  }
  if (validation_data.empty()) {
    LOG(kError) << "Invalid peer_endpoint passed.";
    return kEmptyValidationData;
  }

  std::vector<TransportAndSignalConnections>::iterator itr;
  {
    UniqueLock unique_lock(shared_mutex_);
    itr = std::find_if(
        transports_.begin(),
        transports_.end(),
        [&this_endpoint] (const TransportAndSignalConnections& element) {
      return element.transport->external_endpoint() == this_endpoint ||
             element.transport->local_endpoint() == this_endpoint;
    });

    if (itr == transports_.end()) {
      LOG(kError) << "No Transports have endpoint " << this_endpoint
                  << " - ensure GetAvailableEndpoint has been called first.";
      return kInvalidTransport;
    }

    auto connection_map_itr = connection_map_.find(peer_endpoint);
    if (connection_map_itr != connection_map_.end()) {
      if ((*connection_map_itr).second->IsTemporaryConnection(peer_endpoint)) {
        (*itr).transport->MakeConnectionPermanent(peer_endpoint, validation_data);
        return kSuccess;
      } else {
        LOG(kError) << "A permanent managed connection to " << peer_endpoint << " already exists";
        return kConnectionAlreadyExists;
      }
    }
  }

  LOG(kInfo) << "Attempting to connect from "<< (*itr).transport->external_endpoint() << " to  "
             << peer_endpoint;
  (*itr).transport->Connect(peer_endpoint, validation_data);
  return kSuccess;
}

void ManagedConnections::Remove(const Endpoint& peer_endpoint) {
  SharedLock shared_lock(shared_mutex_);
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
  SharedLock shared_lock(shared_mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kError) << "Can't send to " << peer_endpoint << " - not in map.";
    if (message_sent_functor) {
      if (!connection_map_.empty()) {
        asio_service_.service().dispatch([message_sent_functor] {
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

void ManagedConnections::Ping(const boost::asio::ip::udp::endpoint& peer_endpoint,
                              PingFunctor ping_functor) {
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

  SharedLock shared_lock(shared_mutex_);
  // Check this node isn't already connected to peer
  if (connection_map_.find(peer_endpoint) != connection_map_.end()) {
    asio_service_.service().dispatch([ping_functor] {
      ping_functor(kWontPingAlreadyConnected);
    });
    return;
  }

  // Check we're not trying to ping ourself
  if (std::find_if(transports_.begin(),
                   transports_.end(),
                   [&peer_endpoint](const TransportAndSignalConnections& tprt_and_sigs_conns) {
                     return tprt_and_sigs_conns.transport->external_endpoint() == peer_endpoint;
                   }) != transports_.end()) {
    LOG(kError) << "Trying to ping ourself.";
    asio_service_.service().dispatch([ping_functor] { ping_functor(kWontPingOurself); });  // NOLINT (Fraser)
    return;
  }

  size_t index(RandomUint32() % transports_.size());
  transports_[index].transport->Ping(peer_endpoint, ping_functor);
}

void ManagedConnections::OnMessageSlot(const std::string& message) {
  std::string decrypted_message;
  int result(asymm::Decrypt(message, *private_key_, &decrypted_message));
  if (result != kSuccess) {
    LOG(kError) << "Failed to decrypt message.  Result: " << result;
  } else {
    message_received_functor_(decrypted_message);
  }
}

void ManagedConnections::OnConnectionAddedSlot(const Endpoint& peer_endpoint,
                                               TransportPtr transport) {
  UniqueLock unique_lock(shared_mutex_);
  auto result(connection_map_.insert(std::make_pair(peer_endpoint, transport)));
  if (result.second) {
    LOG(kInfo) << "Successfully connected from "<< transport->external_endpoint() << " to "
               << peer_endpoint;
  } else {
    LOG(kError) << transport->external_endpoint() << " is already connected to " << peer_endpoint;
  }
}

void ManagedConnections::OnConnectionLostSlot(const Endpoint& peer_endpoint,
                                              TransportPtr transport,
                                              bool connections_empty,
                                              bool temporary_connection) {
  bool should_execute_functor(false);
  {
    bool remove_transport(connections_empty);
    UniqueLock unique_lock(shared_mutex_);
    auto connection_itr(connection_map_.find(peer_endpoint));
    if (connection_itr == connection_map_.end()) {
      LOG(kWarning) << "Was not connected to " << peer_endpoint;
      if (temporary_connection)
        remove_transport = false;
    } else {
      // If this is a temporary connection to allow this node to bootstrap a new transport off an
      // existing connection, the transport endpoint passed into the slot will not be the same one
      // that is listed against the peer's endpoint in the connection_map_.
      if (transport->external_endpoint() == (*connection_itr).second->external_endpoint()) {
        connection_map_.erase(connection_itr);
        should_execute_functor = true;
        LOG(kInfo) << "Removed managed connection from " << transport->external_endpoint() << " to "
                   << peer_endpoint
                   << (remove_transport ? " - also removing corresponding transport.  Now have " :
                                          " - not removing transport.  Now have ")
                   << connection_map_.size() << " connections.";
      } else {
        assert(temporary_connection);
        LOG(kInfo) << "Not removing managed connection from "
                   << (*connection_itr).second->external_endpoint() << " to " << peer_endpoint
                   << "  Now have " << connection_map_.size() << " connections.";
        remove_transport = false;
      }
    }

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
        (*itr).on_message_connection.disconnect();
        (*itr).on_connection_added_connection.disconnect();
        (*itr).on_connection_lost_connection.disconnect();
        (*itr).transport->Close();
        transports_.erase(itr);
      }
    }
  }

  if (should_execute_functor)
    connection_lost_functor_(peer_endpoint);
}

}  // namespace rudp

}  // namespace maidsafe
