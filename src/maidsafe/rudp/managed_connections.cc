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

#include "maidsafe/rudp/common.h"
#include "maidsafe/rudp/log.h"
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
    : asio_service_(new AsioService),
      message_received_functor_(),
      connection_lost_functor_(),
      transports_(),
      connection_map_(),
      shared_mutex_() {}

Endpoint ManagedConnections::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    MessageReceivedFunctor message_received_functor,
    ConnectionLostFunctor connection_lost_functor) {
  {
    SharedLock shared_lock(shared_mutex_);
    if (!connection_map_.empty()) {
      DLOG(ERROR) << "Already bootstrapped.";
      return Endpoint();
    }
    BOOST_ASSERT(transports_.empty());
  }

  Endpoint new_endpoint(StartNewTransport(bootstrap_endpoints));
  if (!IsValid(new_endpoint)) {
    DLOG(ERROR) << "Failed to bootstrap managed connections.";
    return Endpoint();
  }

  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;
  return new_endpoint;
}

Endpoint ManagedConnections::StartNewTransport(
    std::vector<Endpoint> bootstrap_endpoints) {
  TransportPtr transport(new Transport(asio_service_->service()));

  bool bootstrapping(!bootstrap_endpoints.empty());
  if (!bootstrapping) {
    bootstrap_endpoints.reserve(kMaxTransports * Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        connection_map_.begin(),
        connection_map_.end(),
        [&bootstrap_endpoints](const ConnectionMap::value_type &entry) {
      bootstrap_endpoints.push_back(entry.first);
    });
  }

  Endpoint chosen_endpoint(transport->Bootstrap(bootstrap_endpoints));
  if (!IsValid(chosen_endpoint)) {
    SharedLock shared_lock(shared_mutex_);
    DLOG(WARNING) << "Failed to start a new Transport.  "
                  << connection_map_.size() << " currently running.";
    return Endpoint();
  }

  UniqueLock unique_lock(shared_mutex_);
  transports_.push_back(transport);
  if (bootstrapping) {
    connection_map_.insert(std::make_pair(chosen_endpoint, transport));
  }
  return chosen_endpoint;
}

int ManagedConnections::GetAvailableEndpoint(Endpoint *endpoint) {
  if (!endpoint) {
    DLOG(ERROR) << "Null parameter passed.";
    return kNullParameter;
  }

  size_t transports_size(0);
  {
    SharedLock shared_lock(shared_mutex_);
    transports_size = transports_.size();
  }

  if (transports_size < kMaxTransports) {
    if (transports_size == 0) {
      DLOG(ERROR) << "No running Transports.";
      return kNoneAvailable;
    }

    Endpoint new_endpoint(StartNewTransport(std::vector<Endpoint>()));
    if (IsValid(new_endpoint)) {
      *endpoint = new_endpoint;
      return kSuccess;
    }
  }

  // Get transport with least connections.
  {
    uint32_t least_connections(Transport::kMaxConnections());
    Endpoint chosen_endpoint;
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        transports_.begin(),
        transports_.end(),
        [&least_connections, &chosen_endpoint] (const TransportPtr &transport) {
      if (transport->ConnectionsCount() < least_connections) {
        least_connections = transport->ConnectionsCount();
        chosen_endpoint = transport->this_endpoint();
      }
    });

    if (!IsValid(chosen_endpoint)) {
      DLOG(ERROR) << "All Transports are full.";
      return kFull;
    }

    *endpoint = chosen_endpoint;
    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint &this_endpoint,
                            const Endpoint &peer_endpoint,
                            const std::string &validation_data) {
  std::vector<TransportPtr>::iterator itr;
  {
    SharedLock shared_lock(shared_mutex_);
    itr = std::find_if(transports_.begin(),
                       transports_.end(),
                       [&this_endpoint] (const TransportPtr &transport) {
      return transport->this_endpoint() == this_endpoint;
    });
    if (itr == transports_.end()) {
      DLOG(ERROR) << "No Transports have endpoint " << this_endpoint;
      return kInvalidTransport;
    }

    if (connection_map_.find(peer_endpoint) != connection_map_.end()) {
      DLOG(ERROR) << "A managed connection to " << peer_endpoint
                  << " already exists.";
      return kConnectionAlreadyExists;
    }
  }

  (*itr)->RendezvousConnect(peer_endpoint, validation_data);
  return kSuccess;
}

void ManagedConnections::Remove(const Endpoint &peer_endpoint) {
  SharedLock shared_lock(shared_mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    DLOG(WARNING) << "Can't remove " << peer_endpoint << " - not in map.";
    return;
  }
  (*itr).second->CloseConnection(peer_endpoint);
}

int ManagedConnections::Send(const Endpoint &peer_endpoint,
                             const std::string &message) const {
  SharedLock shared_lock(shared_mutex_);
  auto itr(connection_map_.find(peer_endpoint));
  if (itr == connection_map_.end()) {
    DLOG(ERROR) << "Can't send to " << peer_endpoint << " - not in map.";
    return kInvalidConnection;
  }
  return (*itr).second->Send(peer_endpoint, message);
}

void ManagedConnections::Ping(const Endpoint &/*peer_endpoint*/) const {
  // TODO(Fraser#5#): 2012-04-02 - Do async probe
}

void ManagedConnections::RemoveTransport(std::shared_ptr<Transport> transport) {
  UniqueLock unique_lock(shared_mutex_);
  auto itr(std::find(transports_.begin(), transports_.end(), transport));
  if (itr == transports_.end()) {
    DLOG(ERROR) << "Failed to find transport in vector.";
    return;
  }
  transports_.erase(itr);
}

void ManagedConnections::InsertEndpoint(const Endpoint &peer_endpoint,
                                        std::shared_ptr<Transport> transport) {
  UniqueLock unique_lock(shared_mutex_);
  auto result(connection_map_.insert(std::make_pair(peer_endpoint, transport)));
  if (!result.second)
    DLOG(ERROR) << "Already connected to " << peer_endpoint;
}

void ManagedConnections::RemoveEndpoint(const Endpoint &peer_endpoint) {
  UniqueLock unique_lock(shared_mutex_);
  size_t result(connection_map_.erase(peer_endpoint));
  if (result != 1U)
    DLOG(ERROR) << "Was not connected to " << peer_endpoint;
}

}  // namespace rudp

}  // namespace maidsafe
