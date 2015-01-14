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

#ifndef MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
#define MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/signals2/connection.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/return_codes.h"

namespace maidsafe {

namespace rudp {

namespace detail {
class Transport;
}

typedef std::function<void(const std::string& /*message*/)> MessageReceivedFunctor;
typedef std::function<void(const NodeId& /*peer_id*/)> ConnectionLostFunctor;
typedef std::function<void(const NodeId& /*peer_id*/)> ConnectionAddedFunctor;
typedef std::function<void(int /*result*/)> MessageSentFunctor;

struct EndpointPair {
  using Endpoint = boost::asio::ip::udp::endpoint;

  Endpoint local, external;

  EndpointPair() : local(), external() {}

  explicit EndpointPair(const Endpoint& both)
    : local(both), external(both) {}

  EndpointPair(const Endpoint& local, const Endpoint& external)
    : local(local), external(external) {}

  bool operator==(const EndpointPair& other) const {
    return local == other.local && external == other.external;
  }
};

// Defined as 203.0.113.14:1314 which falls in the 203.0.113.0/24 (TEST-NET-3) range as described in
// RFC 5737 (http://tools.ietf.org/html/rfc5737).
extern const boost::asio::ip::udp::endpoint kNonRoutable;

// Fail to send a constant and bursty ratio of packets. Useful for debugging. Note that values
// are cumulative, so 0.1 each is 20% of packets overall.
extern void SetDebugPacketLossRate(double constant, double bursty);

class ManagedConnections {
 public:
  using Endpoint = boost::asio::ip::udp::endpoint;

 public:
  ManagedConnections();
  ~ManagedConnections();

  static int32_t kMaxMessageSize() { return 2097152; }
  static unsigned short kResiliencePort() { return kLivePort; }  // NOLINT (Fraser)

  // Creates a new transport object and bootstraps it to one of the provided bootstrap_endpoints.
  // It first tries bootstrapping to "own_local_address:kLivePort".  Bootstrapping involves
  // connecting to the peer, then connecting again to another endpoint (provided by the same
  // bootstrap peer) to establish the local NAT type, which is returned in the nat_type parameter.
  // The successfully connected endpoint is returned, or a default endpoint is returned if
  // bootstrapping is unsuccessful.  If bootstrapping is successful and start_resilience_transport
  // is true, the node starts a transport on port kLivePort.  All messages are decrypted using
  // private_key before being passed up via MessageReceivedFunctor.  Before bootstrapping begins, if
  // there are any existing transports they are destroyed and all connections closed.  For
  // zero-state network, pass the required local_endpoint.
  int Bootstrap(const std::vector<Endpoint>& bootstrap_endpoints,
                MessageReceivedFunctor message_received_functor,
                ConnectionLostFunctor connection_lost_functor, NodeId this_node_id,
                std::shared_ptr<asymm::PrivateKey> private_key,
                std::shared_ptr<asymm::PublicKey> public_key, NodeId& chosen_bootstrap_peer,
                NatType& nat_type,
                Endpoint local_endpoint = Endpoint());

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
  int GetAvailableEndpoint(NodeId peer_id, EndpointPair peer_endpoint_pair,
                           EndpointPair& this_endpoint_pair, NatType& this_nat_type);

  // Makes a new connection and sends the validation data (which cannot be empty) to the peer which
  // runs its message_received_functor_ with the data.  All messages sent via this connection are
  // encrypted for the peer.
  int Add(NodeId peer_id, EndpointPair peer_endpoint_pair, std::string validation_data);

  // Marks the connection to peer_endpoint as valid.  If it exists and is already permanent, or
  // is successfully upgraded to permanent, then the function is successful.  If the peer is direct-
  // connected, its endpoint is returned.
  // TODO(Fraser#5#): 2012-09-11 - Handle passing back peer_endpoint if it's direct-connected.
  //                  Currently returned whenever peer_endpoint is a non-private addresses.
  int MarkConnectionAsValid(NodeId peer_id, Endpoint& peer_endpoint);

  // Drops the connection with peer.
  void Remove(NodeId peer_id);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of kSuccess.  If there is no existing connection to peer_id,
  // kInvalidConnection is used.
  void Send(NodeId peer_id, std::string message, MessageSentFunctor message_sent_functor);

  // Try to ping remote_endpoint.  If this node is already connected, ping_functor is invoked with
  // kWontPingAlreadyConnected.  Otherwise, kPingFailed or kSuccess is passed to ping_functor.
  //  void Ping(Endpoint peer_endpoint, PingFunctor ping_functor);
  unsigned GetActiveConnectionCount() const;

  void SetConnectionAddedFunctor(const ConnectionAddedFunctor&);

 private:
  typedef std::shared_ptr<detail::Transport> TransportPtr;
  typedef std::map<NodeId, TransportPtr> ConnectionMap;
  struct PendingConnection {
    PendingConnection(NodeId node_id_in, TransportPtr transport,
                      boost::asio::io_service& io_service);
    NodeId node_id;
    TransportPtr pending_transport;
    boost::asio::deadline_timer timer;
    bool connecting;
  };

  ManagedConnections(const ManagedConnections&);
  ManagedConnections& operator=(const ManagedConnections&);

  void ClearConnectionsAndIdleTransports();
  int TryToDetermineLocalEndpoint(Endpoint& local_endpoint);
  int AttemptStartNewTransport(
      const std::vector<Endpoint>& bootstrap_endpoints,
      const Endpoint& local_endpoint, NodeId& chosen_bootstrap_peer,
      NatType& nat_type);
  ReturnCode StartNewTransport(
      std::vector<std::pair<NodeId, Endpoint>> bootstrap_peers,
      Endpoint local_endpoint);

  void GetBootstrapEndpoints(
      std::vector<std::pair<NodeId, Endpoint>>& bootstrap_peers,
      boost::asio::ip::address& this_external_address);

  bool ExistingConnectionAttempt(const NodeId& peer_id, EndpointPair& this_endpoint_pair) const;
  bool ExistingConnection(const NodeId& peer_id, EndpointPair& this_endpoint_pair,
                          int& return_code);
  bool SelectIdleTransport(const NodeId& peer_id, EndpointPair& this_endpoint_pair);
  bool SelectAnyTransport(const NodeId& peer_id, EndpointPair& this_endpoint_pair);
  TransportPtr GetAvailableTransport() const;
  bool ShouldStartNewTransport(const EndpointPair& peer_endpoint_pair) const;

  void AddPending(std::unique_ptr<PendingConnection> connection);
  void RemovePending(const NodeId& peer_id);
  std::vector<std::unique_ptr<PendingConnection>>::const_iterator FindPendingTransportWithNodeId(

      const NodeId& peer_id) const;
  std::vector<std::unique_ptr<PendingConnection>>::iterator FindPendingTransportWithNodeId(
      const NodeId& peer_id);

  void OnMessageSlot(const std::string& message);
  void OnConnectionAddedSlot(const NodeId& peer_id, TransportPtr transport,
                             bool temporary_connection,
                             std::atomic<bool> & is_duplicate_normal_connection);
  void OnConnectionLostSlot(const NodeId& peer_id, TransportPtr transport,
                            bool temporary_connection);
  // This signal is fired by Session when a connecting peer requests to use this peer for NAT
  // detection.  The peer will attempt to connect to another one of this node's transports using
  // its current transport.  This node (if suitable) will begin pinging the peer.
  void OnNatDetectionRequestedSlot(const Endpoint& this_local_endpoint,
                                   const NodeId& peer_id,
                                   const Endpoint& peer_endpoint,
                                   uint16_t& another_external_port);

  void UpdateIdleTransports(const TransportPtr&);

 private:
  std::string DebugString() const;

  BoostAsioService asio_service_;
  std::mutex callback_mutex_;
  MessageReceivedFunctor message_received_functor_;
  ConnectionLostFunctor connection_lost_functor_;
  ConnectionAddedFunctor connection_added_functor_;
  NodeId this_node_id_, chosen_bootstrap_node_id_;
  std::shared_ptr<asymm::PrivateKey> private_key_;
  std::shared_ptr<asymm::PublicKey> public_key_;
  ConnectionMap connections_;
  std::vector<std::unique_ptr<PendingConnection>> pendings_;
  std::set<TransportPtr> idle_transports_;
  mutable std::mutex mutex_;
  boost::asio::ip::address local_ip_;
  NatType nat_type_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
