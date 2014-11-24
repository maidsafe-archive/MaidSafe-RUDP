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
#include "boost/optional.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/contact.h"

namespace maidsafe {

namespace rudp {

namespace detail {
class Transport;
}

enum class nat_type : char;

#ifdef TESTING
// Fail to send a constant and bursty ratio of packets. Useful for debugging. Note that values
// are cumulative, so 0.1 each is 20% of packets overall.
extern void set_debug_packet_loss_rate(double constant, double bursty);
#endif

//template <typename Alloc = kernel_side_allocator>
class managed_connections {
 public:
  class listener {
   public:
    virtual ~listener() {}
    virtual void message_received(node_id peer_id, received_message message) = 0;
    virtual void connection_lost(node_id peer_id) = 0;
  };

  managed_connections(/*const Alloc &alloc = Alloc()*/);
  managed_connections(const managed_connections&) = delete;
  managed_connections(managed_connections&&) = delete;
  ~managed_connections();
  managed_connections& operator=(const managed_connections&) = delete;
  managed_connections& operator=(managed_connections&&) = delete;

  static int32_t max_message_size() { return 2097152; }

  // Creates a new transport object and bootstraps it to one of the provided bootstrap_contacts.
  // It first tries bootstrapping to "own_local_address:kLivePort".  Bootstrapping involves
  // connecting to the peer, then connecting again to another endpoint (provided by the same
  // bootstrap peer) to establish the local NAT type, which is returned in the nat_type parameter.
  // The successfully connected endpoint is returned, or a default endpoint is returned if
  // bootstrapping is unsuccessful.  If bootstrapping is successful and start_resilience_transport
  // is true, the node starts a transport on port kLivePort.  All messages are decrypted using
  // private_key before being passed up via MessageReceivedFunctor.  Before bootstrapping begins, if
  // there are any existing transports they are destroyed and all connections closed.  For
  // zero-state network, pass the required local_endpoint.
  void bootstrap(const bootstrap_contacts& bootstrap_list, std::shared_ptr<listener> listener,
                 const node_id& this_node_id, const asymm::Keys& keys,
                 bootstrap_functor handler,
                 endpoint local_endpoint = endpoint());

  // Returns a transport's endpoint_pair and nat_type.  Returns kNotBootstrapped if there are no
  // running Managed Connections.  In this case, Bootstrap must be called to start new Managed
  // Connections.  Returns kFull if all Managed Connections already have the maximum number of
  // running sockets.  If there are less than kMaxTransports transports running, or if this node's
  // NAT type is symmetric and peer_endpoint is non-local, a new transport will be started and if
  // successful, this will be the returned endpoint_pair.  If peer_endpoint is known (e.g. if this is
  // being executed by Routing::Service in response to a connection request, or if we want to make a
  // permanent connection to a successful bootstrap endpoint) it should be passed in.  If
  // peer_endpoint is a valid endpoint, it is checked against the current group of peers which have
  // a temporary bootstrap connection, so that the appropriate transport's details can be returned.
  void get_available_endpoints(const node_id& peer_id,
                               get_available_endpoints_functor handler);

  // Makes a new connection and sends the validation data (which cannot be empty) to the peer which
  // runs its message_received_functor_ with the data.  All messages sent via this connection are
  // encrypted for the peer.
  void add(const contact& peer, connection_added_functor handler);

  // Drops the connection with peer.
  void remove(const node_id& peer_id, connection_removed_functor handler);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of kSuccess.  If there is no existing connection to peer_id,
  // kInvalidConnection is used.
  void send(const node_id& peer_id, sendable_message&& message,
            message_sent_functor handler = nullptr);

 private:
  using TransportPtr = std::shared_ptr<detail::Transport>;
  using ConnectionMap = std::map<node_id, TransportPtr>;
  struct PendingConnection {
    PendingConnection(node_id node_id_in, TransportPtr transport,
                      boost::asio::io_service& io_service);
    node_id peer_id;
    TransportPtr pending_transport;
    boost::asio::deadline_timer timer;
    bool connecting;
  };

  void do_bootstrap(const bootstrap_contacts& bootstrap_list, std::shared_ptr<listener> listener,
                    const node_id& this_node_id, const asymm::Keys& keys, bootstrap_functor handler,
                    endpoint local_endpoint);

  void ClearConnectionsAndIdleTransports();
  int TryToDetermineLocalEndpoint(endpoint& local_endpoint);
  int AttemptStartNewTransport(const bootstrap_contacts& bootstrap_list, const endpoint& local_endpoint,
                               contact& chosen_bootstrap_contact);
  int StartNewTransport(bootstrap_contacts bootstrap_list, endpoint local_endpoint);

  void GetBootstrapEndpoints(bootstrap_contacts& bootstrap_list,
                             boost::asio::ip::address& this_external_address);

  bool ExistingConnectionAttempt(const node_id& peer_id, endpoint_pair& this_endpoint_pair) const;
  bool ExistingConnection(const node_id& peer_id, endpoint_pair& this_endpoint_pair,
                          int& return_code);
  bool SelectIdleTransport(const node_id& peer_id, endpoint_pair& this_endpoint_pair);
  bool SelectAnyTransport(const node_id& peer_id, endpoint_pair& this_endpoint_pair);
  TransportPtr GetAvailableTransport() const;
  bool ShouldStartNewTransport(const endpoint_pair& peer_endpoint_pair) const;

  void AddPending(std::unique_ptr<PendingConnection> connection);
  void RemovePending(const node_id& peer_id);
  std::vector<std::unique_ptr<PendingConnection>>::const_iterator
      FindPendingTransportWithNodeId(const node_id& peer_id) const;
  std::vector<std::unique_ptr<PendingConnection>>::iterator FindPendingTransportWithNodeId(
      const node_id& peer_id);

  void OnMessageSlot(const node_id& peer_id, const std::string& message);
  void OnConnectionAddedSlot(const node_id& peer_id, TransportPtr transport,
                             bool temporary_connection,
                             std::atomic<bool> & is_duplicate_normal_connection);
  void OnConnectionLostSlot(const node_id& peer_id, TransportPtr transport,
                            bool temporary_connection);
  // This signal is fired by Session when a connecting peer requests to use this peer for NAT
  // detection.  The peer will attempt to connect to another one of this node's transports using
  // its current transport.  This node (if suitable) will begin pinging the peer.
  void OnNatDetectionRequestedSlot(const endpoint& this_local_endpoint,
                                   const node_id& peer_id,
                                   const endpoint& peer_endpoint,
                                   uint16_t& another_external_port);

  void UpdateIdleTransports(const TransportPtr&);

  std::string DebugString() const;

  AsioService asio_service_;
  std::weak_ptr<listener> listener_;
  node_id this_node_id_;
  contact chosen_bootstrap_contact_;
  asymm::Keys keys_;
  ConnectionMap connections_;
  std::vector<std::unique_ptr<PendingConnection>> pendings_;
  std::set<TransportPtr> idle_transports_;
  mutable std::mutex mutex_;
  boost::asio::ip::address local_ip_;
  std::unique_ptr<nat_type> nat_type_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
