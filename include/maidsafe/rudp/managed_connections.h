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

#ifdef FAKE_RUDP
#  include "../../../src/maidsafe/rudp/tests/fake_managed_connections.h"
#else


#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/thread/shared_mutex.hpp"

#include "maidsafe/common/asio_service.h"


namespace maidsafe {

namespace rudp {

namespace test { class ManagedConnectionsTest_BEH_API_Bootstrap_Test; }

class Transport;

typedef std::function<void(const std::string&)> MessageReceivedFunctor;
typedef std::function<void(const boost::asio::ip::udp::endpoint&)> ConnectionLostFunctor;
typedef std::function<void(bool)> MessageSentFunctor;

struct EndpointPair {
  EndpointPair() : local(), external() {}
  boost::asio::ip::udp::endpoint local, external;
};


class ManagedConnections {
 public:
  ManagedConnections();
  ~ManagedConnections();

  static int32_t kMaxMessageSize() { return 67108864; }

  // Creates a new transport object and bootstraps it to one of the provided bootstrap_endpoints.
  // The successfully connected endpoint is returned, or a default endpoint is returned if
  // bootstrapping is unsuccessful.  For zero-state network, pass required local_endpoint.
  boost::asio::ip::udp::endpoint Bootstrap(
      const std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints,
      MessageReceivedFunctor message_received_functor,
      ConnectionLostFunctor connection_lost_functor,
      boost::asio::ip::udp::endpoint local_endpoint = boost::asio::ip::udp::endpoint());

  // Returns a transport's EndpointPair.  Returns kNoneAvailable if there are no running Managed
  // Connections.  In this case, Bootstrap must be called to start new Managed Connections.  Returns
  // kFull if all Managed Connections already have the maximum number of running sockets.  If there
  // are less than kMaxTransports transports running, a new one will be started and if successful,
  // this will be the returned EndpointPair.  If peer_endpoint is known (e.g. if this is being
  // executed by Routing::Service in response to a connection request, or if we want to make a
  // permanent connection to a successful bootstrap endpoint) it should be passed in.  If
  // peer_endpoint is a valid endpoint, it is checked against the current group of peers which have
  // a temporary bootstrap connection, so that the appropriate transport's details can be returned.
  int GetAvailableEndpoint(const boost::asio::ip::udp::endpoint &peer_endpoint,
                           EndpointPair &this_endpoint_pair);

  // Makes a new connection and sends the validation data to the peer which runs its
  // message_received_functor_ with the data.
  int Add(const boost::asio::ip::udp::endpoint &this_endpoint,
          const boost::asio::ip::udp::endpoint &peer_endpoint,
          const std::string &validation_data);

  // Drops the connection with peer.
  void Remove(const boost::asio::ip::udp::endpoint &peer_endpoint);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of true.
  void Send(const boost::asio::ip::udp::endpoint &peer_endpoint,
            const std::string &message,
            MessageSentFunctor message_sent_functor) const;

  friend class Transport;
  friend class test::ManagedConnectionsTest_BEH_API_Bootstrap_Test;
                                                                                                std::string mc_id_;

 private:
  typedef std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<Transport>> ConnectionMap;

  struct TransportAndSignalConnections {
    std::shared_ptr<Transport> transport;
    boost::signals2::connection on_message_connection;
    boost::signals2::connection on_connection_added_connection;
    boost::signals2::connection on_connection_lost_connection;
  };

  ManagedConnections(const ManagedConnections&);
  ManagedConnections& operator=(const ManagedConnections&);
  boost::asio::ip::udp::endpoint StartNewTransport(
      std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints,
      boost::asio::ip::udp::endpoint local_endpoint);

  void OnMessageSlot(const std::string &message);
  void OnConnectionAddedSlot(const boost::asio::ip::udp::endpoint &peer_endpoint,
                             std::shared_ptr<Transport> transport);
  void OnConnectionLostSlot(const boost::asio::ip::udp::endpoint &peer_endpoint,
                            std::shared_ptr<Transport> transport,
                            bool connections_empty,
                            bool temporary_connection);
//  void RemoveTransport(std::shared_ptr<Transport> transport);
//  void InsertEndpoint(const boost::asio::ip::udp::endpoint &peer_endpoint,
//                      std::shared_ptr<Transport> transport);
//  void RemoveEndpoint(const boost::asio::ip::udp::endpoint &peer_endpoint);

  std::shared_ptr<AsioService> asio_service_;
  MessageReceivedFunctor message_received_functor_;
  ConnectionLostFunctor connection_lost_functor_;
  std::vector<TransportAndSignalConnections> transports_;
  ConnectionMap connection_map_;
  mutable boost::shared_mutex shared_mutex_;
  std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints_;
  boost::asio::ip::address local_ip_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // FAKE_RUDP

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
