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
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/connection.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/nat_type.h"


namespace maidsafe {

namespace rudp {

namespace detail { class Transport; }

typedef std::function<void(const std::string&)> MessageReceivedFunctor;
typedef std::function<void(const boost::asio::ip::udp::endpoint&)> ConnectionLostFunctor;
typedef std::function<void(int)> MessageSentFunctor, PingFunctor;  // NOLINT (Fraser)

struct EndpointPair {
  EndpointPair() : local(), external() {}
  boost::asio::ip::udp::endpoint local, external;
};

// Defined as 203.0.113.14:1314 which falls in the 203.0.113.0/24 (TEST-NET-3) range as described in
// RFC 5737 (http://tools.ietf.org/html/rfc5737).
extern const boost::asio::ip::udp::endpoint kNonRoutable;


class ManagedConnections {
 public:
  ManagedConnections();
  ~ManagedConnections();

  static int32_t kMaxMessageSize() { return 67108864; }
  static unsigned short kResiliencePort() { return 5483; }  // NOLINT (Fraser)

  // Creates a new transport object and bootstraps it to one of the provided bootstrap_endpoints.
  // This involves connecting to another endpoint (provided by the bootstrap peer) to establish
  // the local NAT type, which is returned in the nat_type parameter.  The successfully-connected
  // endpoint is returned, or a default endpoint is returned if bootstrapping is unsuccessful.  All
  // messages are decrypted using private_key before being passed up via MessageReceivedFunctor.
  // For zero-state network, pass required local_endpoint.  If there are any existing transports
  // they are destroyed and all connections closed.
  boost::asio::ip::udp::endpoint Bootstrap(
      const std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints,
      MessageReceivedFunctor message_received_functor,
      ConnectionLostFunctor connection_lost_functor,
      std::shared_ptr<asymm::PrivateKey> private_key,
      std::shared_ptr<asymm::PublicKey> public_key,
      NatType& nat_type,
      boost::asio::ip::udp::endpoint local_endpoint = boost::asio::ip::udp::endpoint());

  // Returns a transport's EndpointPair and NatType.  Returns kNotBootstrapped if there are no
  // running Managed Connections.  In this case, Bootstrap must be called to start new Managed
  // Connections.  Returns kFull if all Managed Connections already have the maximum number of
  // running sockets.  If there are less than kMaxTransports transports running, or if this node's
  // NAT type is symmetric and peer_endpoint is non-local, a new transport will be started and if
  // successful, this will be the returned EndpointPair.  If peer_endpoint is known (e.g. if this is
  // being executed by Routing::Service in response to a connection request, or if we want to make a
  // permanent connection to a successful bootstrap endpoint) it should be passed in.  If
  // peer_endpoint is a valid endpoint, it is checked against the current group of peers which have
  // a temporary bootstrap connection, so that the appropriate transport's details can be returned.
  int GetAvailableEndpoint(const boost::asio::ip::udp::endpoint& peer_endpoint,
                           EndpointPair& this_endpoint_pair,
                           NatType& this_nat_type);

  // Makes a new connection and sends the validation data (which cannot be empty) to the peer which
  // runs its message_received_functor_ with the data.  All messages sent via this connection are
  // encrypted for the peer.
  int Add(const boost::asio::ip::udp::endpoint& this_endpoint,
          const boost::asio::ip::udp::endpoint& peer_endpoint,
          const std::string& validation_data);

  // Drops the connection with peer.
  void Remove(const boost::asio::ip::udp::endpoint& peer_endpoint);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of kSuccess.  If there is no existing connection to peer_endpoint,
  // kInvalidConnection is used.
  void Send(const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::string& message,
            MessageSentFunctor message_sent_functor);

  // Try to ping remote_endpoint.  If this node is already connected, ping_functor is invoked with
  // kWontPingAlreadyConnected.  Otherwise, kPingFailed or kSuccess is passed to ping_functor.
  void Ping(const boost::asio::ip::udp::endpoint& peer_endpoint, PingFunctor ping_functor);

  friend class detail::Transport;

 private:
  typedef std::map<boost::asio::ip::udp::endpoint,
                   std::shared_ptr<detail::Transport>> ConnectionMap;

  struct TransportAndSignalConnections {
    TransportAndSignalConnections();
    void DisconnectSignalsAndClose();
    std::shared_ptr<detail::Transport> transport;
    boost::signals2::connection on_message_connection;
    boost::signals2::connection on_connection_added_connection;
    boost::signals2::connection on_connection_lost_connection;
  };

  ManagedConnections(const ManagedConnections&);
  ManagedConnections& operator=(const ManagedConnections&);

  bool StartNewTransport(
      std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints,
      boost::asio::ip::udp::endpoint local_endpoint,
      boost::asio::ip::udp::endpoint& chosen_bootstrap_endpoint,
      EndpointPair& this_endpoint_pair);

  void GetBootstrapEndpoints(const boost::asio::ip::udp::endpoint& local_endpoint,
                             std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
                             boost::asio::ip::address& this_external_address);

  bool DirectConnected(boost::asio::ip::address& this_address) const;
  bool Connectable(const boost::asio::ip::udp::endpoint& peer_endpoint) const;

  void StartResilienceTransport(const boost::asio::ip::address& this_address);

  void OnMessageSlot(const std::string& message);
  void OnConnectionAddedSlot(const boost::asio::ip::udp::endpoint& peer_endpoint,
                             std::shared_ptr<detail::Transport> transport);
  void OnConnectionLostSlot(const boost::asio::ip::udp::endpoint& peer_endpoint,
                            std::shared_ptr<detail::Transport> transport,
                            bool connections_empty,
                            bool temporary_connection);
  // This signal is fired by Session when a connecting peer requests to use this peer for NAT
  // detection.  The peer will attempt to connect to another one of this node's transports using
  // its current transport.  This node (if suitable) will begin pinging the peer.
  void OnNatDetectionRequestedSlot(const boost::asio::ip::udp::endpoint& this_local_endpoint,
                                   const boost::asio::ip::udp::endpoint& peer_endpoint,
                                   uint16_t& another_external_port);

  AsioService asio_service_;
  MessageReceivedFunctor message_received_functor_;
  ConnectionLostFunctor connection_lost_functor_;
  std::shared_ptr<asymm::PrivateKey> private_key_;
  std::shared_ptr<asymm::PublicKey> public_key_;
  std::vector<TransportAndSignalConnections> transports_;
  ConnectionMap connection_map_;
  std::set<boost::asio::ip::udp::endpoint> pending_connections_;
  mutable std::mutex mutex_;
  boost::asio::ip::address local_ip_;
  NatType nat_type_;
  TransportAndSignalConnections resilience_transport_;
#ifdef FAKE_RUDP
  std::vector<boost::asio::ip::udp::endpoint> fake_endpoints_;
#endif
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
