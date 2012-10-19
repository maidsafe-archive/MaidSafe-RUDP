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
#include "maidsafe/common/node_id.h"

#include "maidsafe/rudp/nat_type.h"


namespace maidsafe {

namespace rudp {

namespace detail { class Transport; }

typedef std::function<void(const std::string& /*message*/)> MessageReceivedFunctor;
typedef std::function<void(const NodeId& /*peer_id*/)> ConnectionLostFunctor;
typedef std::function<void(int /*result*/)> MessageSentFunctor, PingFunctor;  // NOLINT (Fraser)

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

  static int32_t kMaxMessageSize() { return 2097152; }
  static unsigned short kResiliencePort() { return 5483; }  // NOLINT (Fraser)

  // Creates a new transport object and bootstraps it to one of the provided bootstrap_endpoints.
  // It first tries bootstrapping to "own_local_address:5483".  Bootstrapping involves connecting to
  // the peer, then connecting again to another endpoint (provided by the same bootstrap peer) to
  // establish the local NAT type, which is returned in the nat_type parameter.  The successfully-
  // connected endpoint is returned, or a default endpoint is returned if bootstrapping is
  // unsuccessful.  If bootstrapping is successful and start_resilience_transport is true, the node
  // starts a transport on port 5483.  All messages are decrypted using private_key before being
  // passed up via MessageReceivedFunctor.  Before bootstrapping begins, if there are any existing
  // transports they are destroyed and all connections closed.  For zero-state network, pass the
  // required local_endpoint.
  int Bootstrap(const std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
                MessageReceivedFunctor message_received_functor,
                ConnectionLostFunctor connection_lost_functor,
                NodeId this_node_id,
                std::shared_ptr<asymm::PrivateKey> private_key,
                std::shared_ptr<asymm::PublicKey> public_key,
                NodeId& chosen_bootstrap_peer,
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
  int GetAvailableEndpoint(NodeId peer_id,
                           EndpointPair peer_endpoint_pair,
                           EndpointPair& this_endpoint_pair,
                           NatType& this_nat_type);

  // Makes a new connection and sends the validation data (which cannot be empty) to the peer which
  // runs its message_received_functor_ with the data.  All messages sent via this connection are
  // encrypted for the peer.
  int Add(NodeId peer_id, EndpointPair peer_endpoint_pair, std::string validation_data);

  // Marks the connection to peer_endpoint as valid.  If it exists and is already permanent, or
  // is successfully upgraded to permanent, then the function is successful.  If the peer is direct-
  // connected, its endpoint is returned.
  // TODO(Fraser#5#): 2012-09-11 - Handle passing back peer_endpoint iff it's direct-connected.
  //                  Currently returned whenever peer_endpoint is a non-private addresses.
  int MarkConnectionAsValid(NodeId peer_id, boost::asio::ip::udp::endpoint& peer_endpoint);

  // Drops the connection with peer.
  void Remove(NodeId peer_id);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of kSuccess.  If there is no existing connection to peer_id,
  // kInvalidConnection is used.
  void Send(NodeId peer_id, std::string message, MessageSentFunctor message_sent_functor);

  // Try to ping remote_endpoint.  If this node is already connected, ping_functor is invoked with
  // kWontPingAlreadyConnected.  Otherwise, kPingFailed or kSuccess is passed to ping_functor.
//  void Ping(boost::asio::ip::udp::endpoint peer_endpoint, PingFunctor ping_functor);

  friend class detail::Transport;

  unsigned GetActiveConnectionCount() const;

 private:
  typedef std::map<NodeId, std::shared_ptr<detail::Transport> > ConnectionMap;
  struct PendingConnection {
    PendingConnection();
    PendingConnection(const NodeId& node_id_in,
                      const std::shared_ptr<detail::Transport>& transport);
    NodeId node_id;
    std::shared_ptr<detail::Transport> pending_transport;
    boost::posix_time::time_duration timestamp;
    bool connecting;
  };

  ManagedConnections(const ManagedConnections&);
  ManagedConnections& operator=(const ManagedConnections&);

  bool StartNewTransport(
      std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint> > bootstrap_peers,  // NOLINT (Fraser)
      boost::asio::ip::udp::endpoint local_endpoint);

  void GetBootstrapEndpoints(
      std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint> >& bootstrap_peers,  // NOLINT (Fraser)
      boost::asio::ip::address& this_external_address);

  void OnMessageSlot(const std::string& message);
  void OnConnectionAddedSlot(const NodeId& peer_id,
                             std::shared_ptr<detail::Transport> transport,
                             bool temporary_connection,
                             bool& is_duplicate_normal_connection);
  void OnConnectionLostSlot(const NodeId& peer_id,
                            std::shared_ptr<detail::Transport> transport,
                            bool temporary_connection);
  // This signal is fired by Session when a connecting peer requests to use this peer for NAT
  // detection.  The peer will attempt to connect to another one of this node's transports using
  // its current transport.  This node (if suitable) will begin pinging the peer.
  void OnNatDetectionRequestedSlot(const boost::asio::ip::udp::endpoint& this_local_endpoint,
                                   const NodeId& peer_id,
                                   const boost::asio::ip::udp::endpoint& peer_endpoint,
                                   uint16_t& another_external_port);
  std::string DebugString() const;
  std::vector<ManagedConnections::PendingConnection>::iterator
      FindPendingTransportWithNodeId(const NodeId& peer_id);
  void PrunePendingTransports();

  AsioService asio_service_;
  std::mutex callback_mutex_;
  MessageReceivedFunctor message_received_functor_;
  ConnectionLostFunctor connection_lost_functor_;
  NodeId this_node_id_, chosen_bootstrap_node_id_;
  std::shared_ptr<asymm::PrivateKey> private_key_;
  std::shared_ptr<asymm::PublicKey> public_key_;
  ConnectionMap connections_;
  std::vector<PendingConnection> pendings_;
  int prune_pendings_count_;
  std::set<std::shared_ptr<detail::Transport> > idle_transports_;
  mutable std::mutex mutex_;
  boost::asio::ip::address local_ip_;
  NatType nat_type_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
