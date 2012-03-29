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

#ifndef MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
#define MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/shared_mutex.hpp"

#include "maidsafe/common/asio_service.h"

#include "maidsafe/rudp/version.h"

#if MAIDSAFE_RUDP_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the maidsafe_rudp library.
#endif

namespace maidsafe {

namespace rudp {

struct Endpoint;
class McTransport;

typedef std::function<void(const std::string&)> MessageReceivedFunctor;
typedef std::function<void(const Endpoint&)> ConnectionLostFunctor;


class ManagedConnections {
 public:
  ManagedConnections();

  // Creates new transport objects and bootstraps each to one of the provided
  // bootstrap_endpoints.  All the endpoints to which successful bootstrap
  // connections are made are returned.
  std::vector<Endpoint> Bootstrap(
      const std::vector<Endpoint> &bootstrap_endpoints,
      MessageReceivedFunctor message_received_functor,
      ConnectionLostFunctor connection_lost_functor);

  // Returns one of the transport's external endpoints.  Returns kNoneAvailable
  // if there are no running Managed Connections.  In this case, Bootstrap must
  // be called to start new Managed Connections.  Returns kFull if all
  // Managed Connections already have the maximum number of running sockets.  If
  // there are less than kMaxTransports transports running, a new one will be
  // started and if successful, this will be the returned Endpoint.
  int GetAvailableEndpoint(Endpoint *endpoint);

  int Add(const Endpoint &this_endpoint,
          const Endpoint &peer_endpoint,
          const std::string &this_node_id);
  void Remove(const Endpoint &peer_endpoint);

  int Send(const Endpoint &peer_endpoint, const std::string &message) const;
  void Ping(const Endpoint &peer_endpoint) const;

  friend class McTransport;

 private:
  ManagedConnections(const ManagedConnections&);
  ManagedConnections& operator=(const ManagedConnections&);
  Endpoint StartNewTransport(const std::vector<Endpoint> &bootstrap_endpoints);
  void RemoveTransport();

  std::unique_ptr<AsioService> asio_service_;
  MessageReceivedFunctor message_received_functor_;
  ConnectionLostFunctor connection_lost_functor_;
  boost::posix_time::time_duration keep_alive_interval_;
  std::vector<std::unique_ptr<McTransport>> mc_transports_;
  mutable boost::shared_mutex shared_mutex_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
