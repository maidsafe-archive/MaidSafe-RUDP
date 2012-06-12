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

#include "maidsafe/rudp/common.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace {
const int kMaxTransports(10);
}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(new AsioService(Parameters::thread_count)),
      message_received_functor_(),
      connection_lost_functor_(),
      transports_(),
      connection_map_(),
      shared_mutex_(),
      bootstrap_endpoints_() {}

ManagedConnections::~ManagedConnections() {
  UniqueLock unique_lock(shared_mutex_);
  std::for_each(transports_.begin(),
                transports_.end(),
                [](const TransportAndSignalConnections &element) {
    element.on_connection_lost_connection.disconnect();
    element.on_connection_added_connection.disconnect();
    element.on_message_connection.disconnect();
    element.transport->Close();
  });
  asio_service_->Stop();
}

Endpoint ManagedConnections::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    MessageReceivedFunctor message_received_functor,
    ConnectionLostFunctor connection_lost_functor,
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

  if (bootstrap_endpoints.empty()) {
    LOG(kError) << "You must provide at least one Bootstrap endpoint.";
    return Endpoint();
  }
  bootstrap_endpoints_ = bootstrap_endpoints;

  asio_service_->Start();

  if (IsValid(local_endpoint)) {
    local_ip_ = local_endpoint.address();
  } else {
    // TODO(Prakash): FIXME, Temporarily adding loopback address for tests to pass.
    // Need to fix GetLocalIp().
//                                                         local_ip_ = boost::asio::ip::address_v4::loopback();
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

Endpoint ManagedConnections::StartNewTransport(
    std::vector<Endpoint> bootstrap_endpoints,
    Endpoint local_endpoint) {
  TransportAndSignalConnections transport_and_signals_connections;
  transport_and_signals_connections.transport = std::make_shared<Transport>(asio_service_);
  bool bootstrap_off_existing_connection(bootstrap_endpoints.empty());
  if (bootstrap_off_existing_connection) {
    bootstrap_endpoints.reserve(kMaxTransports * Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        connection_map_.begin(),
        connection_map_.end(),
        [&bootstrap_endpoints](const ConnectionMap::value_type &entry) {
      bootstrap_endpoints.push_back(entry.first);
    });
  }
  if (bootstrap_endpoints.empty())
    bootstrap_endpoints = bootstrap_endpoints_;  // Last resort
  Endpoint chosen_endpoint;
  transport_and_signals_connections.transport->Bootstrap(
      bootstrap_endpoints,
      local_endpoint,
      bootstrap_off_existing_connection,
      boost::bind(&ManagedConnections::OnMessageSlot, this, _1),
      boost::bind(&ManagedConnections::OnConnectionAddedSlot, this, _1, _2),
      boost::bind(&ManagedConnections::OnConnectionLostSlot, this, _1, _2),
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
  LOG(kInfo) << "Inserting " << transport_and_signals_connections.transport->trans_id_ << " in vector"
             << ", chosen_endpoint - " << chosen_endpoint << ", local endpoint - " << transport_and_signals_connections.transport->local_endpoint()
             << ", external_endpoint - " << transport_and_signals_connections.transport->external_endpoint();
  transports_.push_back(transport_and_signals_connections);
  return chosen_endpoint;
}

int ManagedConnections::GetAvailableEndpoint(EndpointPair &endpoint_pair) {
  int transports_size(0);
  {
    SharedLock shared_lock(shared_mutex_);
    transports_size = static_cast<int>(transports_.size());
  }

  if (transports_size < kMaxTransports) {
    if (transports_size == 0) {
      LOG(kError) << "No running Transports.";
      return kNoneAvailable;
    }

    Endpoint new_endpoint(StartNewTransport(std::vector<Endpoint>(), Endpoint(local_ip_, 0)));
    if (IsValid(new_endpoint)) {
      UniqueLock unique_lock(shared_mutex_);
      endpoint_pair.external =
          (*transports_.rbegin()).transport->external_endpoint();
      endpoint_pair.local =
          (*transports_.rbegin()).transport->local_endpoint();
      return kSuccess;
    } else {
      return kTransportStartFailure;
    }
  }

  // Get transport with least connections.
  {
    size_t least_connections(Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        transports_.begin(),
        transports_.end(),
        [&](const TransportAndSignalConnections &element) {
      if (element.transport->ConnectionsCount() < least_connections) {
        least_connections = element.transport->ConnectionsCount();
        endpoint_pair.external = element.transport->external_endpoint();
        endpoint_pair.local = element.transport->local_endpoint();
      }
    });

    if (!IsValid(endpoint_pair.external) || !IsValid(endpoint_pair.local)) {
      LOG(kError) << "All Transports are full.";
      endpoint_pair.external = Endpoint();
      endpoint_pair.local = Endpoint();
      return kFull;
    }

    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint &this_endpoint,
                            const Endpoint &peer_endpoint,
                            const std::string &validation_data) {
  if (!IsValid(this_endpoint)) {
    LOG(kError) << "Invalid this_endpoint passed.";
    return kInvalidEndpoint;
  }
  if (!IsValid(peer_endpoint)) {
    LOG(kError) << "Invalid peer_endpoint passed.";
    return kInvalidEndpoint;
  }

  std::vector<TransportAndSignalConnections>::iterator itr;
  {
    SharedLock shared_lock(shared_mutex_);
    itr = std::find_if(
        transports_.begin(),
        transports_.end(),
        [&this_endpoint] (const TransportAndSignalConnections &element) {
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
      if (peer_endpoint == (*connection_map_itr).second->bootstrap_endpoint()) {
                                // TODO(Fraser#5#): 2012-06-10 - Change this connection from temp to permanent
        return (*itr).transport->Send(peer_endpoint, validation_data);
//        (*connection_map_itr).second->CloseConnection(peer_endpoint);
      } else {
        LOG(kError) << "A managed connection to " << peer_endpoint
                    << " already exists.";
        return kConnectionAlreadyExists;
      }
    }
  }

  LOG(kInfo) << "Add::Connecting "<< (*itr).transport->external_endpoint()
             << " to  " << peer_endpoint;
  (*itr).transport->Connect(peer_endpoint, validation_data);
  return kSuccess;
}

void ManagedConnections::Remove(const Endpoint &peer_endpoint) {
  SharedLock shared_lock(shared_mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kWarning) << "Can't remove " << peer_endpoint << " - not in map.";
    return;
  }
  (*itr).second->CloseConnection(peer_endpoint);
}

int ManagedConnections::Send(const Endpoint &peer_endpoint,
                             const std::string &message,
                             MessageSentFunctor message_sent_functor) const {
  SharedLock shared_lock(shared_mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    LOG(kError) << "Can't send to " << peer_endpoint << " - not in map.";
    return kInvalidConnection;
  }
  return (*itr).second->Send(peer_endpoint, message);
}

bool ManagedConnections::Ping(const Endpoint &peer_endpoint) const {
  return TryConnectTo(std::vector<Endpoint>(1, peer_endpoint), false);
}

void ManagedConnections::OnMessageSlot(const std::string &message) {
  SharedLock shared_lock(shared_mutex_);
  message_received_functor_(message);
}

void ManagedConnections::OnConnectionAddedSlot(const Endpoint &peer_endpoint,
                                               TransportPtr transport) {
  UniqueLock unique_lock(shared_mutex_);
  auto result(connection_map_.insert(std::make_pair(peer_endpoint, transport)));
  if (result.second)
    LOG(kInfo) << "+++++++++++++++++++++++++++++++++++ Added managed connection to " << peer_endpoint;
  else
    LOG(kError) << "Already connected to " << peer_endpoint;
}

void ManagedConnections::OnConnectionLostSlot(const Endpoint &peer_endpoint,
                                              TransportPtr transport) {
  UniqueLock unique_lock(shared_mutex_);
  size_t result(connection_map_.erase(peer_endpoint));
  if (result == 1U) {
    LOG(kInfo) << "Removed managed connection to " << peer_endpoint
               << (transport ? " - also removing corresponding transport" : "");
    connection_lost_functor_(peer_endpoint);
  } else {
    LOG(kError) << "Was not connected to " << peer_endpoint;
  }

  if (!transport)
    return;

  auto itr(std::find_if(
      transports_.begin(),
      transports_.end(),
      [&transport](const TransportAndSignalConnections &element) {
        return transport == element.transport;
      }));

  if (itr == transports_.end()) {
    LOG(kError) << "Failed to find transport in vector.";
    return;
  }
  (*itr).on_message_connection.disconnect();
  (*itr).on_connection_added_connection.disconnect();
  (*itr).on_connection_lost_connection.disconnect();
  (*itr).transport->Close();
  transports_.erase(itr);
}

}  // namespace rudp

}  // namespace maidsafe
