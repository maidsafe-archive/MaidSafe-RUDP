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

#include "boost/asio/async_result.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/optional.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/contact.h"
#include "maidsafe/rudp/return_codes.h"

namespace maidsafe {

namespace rudp {

enum class NatType : char;

namespace detail {
class Transport;
}  // namespace detail

#ifdef TESTING
// Fail to send a constant and bursty ratio of packets. Useful for debugging. Note that values
// are cumulative, so 0.1 each is 20% of packets overall.
extern void SetDebugPacketLossRate(double constant, double bursty);
#endif

// template <typename Alloc = kernel_side_allocator>
class ManagedConnections {
 public:
  using Error = rudp::error_code;

  class Listener {
   public:
    virtual ~Listener() {}
    virtual void MessageReceived(NodeId peer_id, ReceivedMessage message) = 0;
    virtual void ConnectionLost(NodeId peer_id) = 0;
  };

  ManagedConnections(/*const Alloc &alloc = Alloc()*/);
  ManagedConnections(const ManagedConnections&) = delete;
  ManagedConnections(ManagedConnections&&) = delete;
  ~ManagedConnections();
  ManagedConnections& operator=(const ManagedConnections&) = delete;
  ManagedConnections& operator=(ManagedConnections&&) = delete;

  static int32_t MaxMessageSize() { return 2097152; }

  // Creates a new transport object and bootstraps it to one of the provided BootstrapContacts.
  // It first tries bootstrapping to "own_local_address:kLivePort".  Bootstrapping involves
  // connecting to the peer, then connecting again to another endpoint (provided by the same
  // bootstrap peer) to establish the local NAT type, which is returned in the nat_type parameter.
  // The successfully connected endpoint is returned, or a default endpoint is returned if
  // bootstrapping is unsuccessful.  If bootstrapping is successful and start_resilience_transport
  // is true, the node starts a transport on port kLivePort.  All messages are decrypted using
  // private_key before being passed up via MessageReceivedFunctor.  Before bootstrapping begins, if
  // there are any existing transports they are destroyed and all connections closed.  For
  // zero-state network, pass the required local_endpoint.
  template <typename CompletionToken>
  BootstrapReturn<CompletionToken> Bootstrap(const BootstrapContacts& bootstrap_list,
                                             std::shared_ptr<Listener> listener,
                                             const NodeId& this_node_id, const asymm::Keys& keys,
                                             CompletionToken&& token,
                                             Endpoint local_endpoint = Endpoint());

  // Returns a transport's EndpointPair and NatType.  Returns kNotBootstrapped if there are no
  // running Managed Connections.  In this case, Bootstrap must be called to start new Managed
  // Connections.  Returns kFull if all Managed Connections already have the maximum number of
  // running sockets.  If there are less than kMaxTransports transports running, or if this node's
  // NAT type is symmetric and peer_endpoint is non-local, a new transport will be started and if
  // successful, this will be the returned EndpointPair.  If peer_endpoint is known (e.g. if this
  // is being executed by Routing::Service in response to a connection request, or if we want to
  // make a permanent connection to a successful bootstrap endpoint) it should be passed in.  If
  // peer_endpoint is a valid endpoint, it is checked against the current group of peers which have
  // a temporary bootstrap connection, so that the appropriate transport's details can be returned.
  //template <typename CompletionToken>
  //GetAvailableEndpointsReturn<CompletionToken> GetAvailableEndpoints(const NodeId& peer_id,
  //                                                                   CompletionToken&& token);

  template <typename CompletionToken>
  GetAvailableEndpointsReturn<CompletionToken> GetAvailableEndpoints(
      const NodeId& peer_id, CompletionToken&& token) {
    GetAvailableEndpointsHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
    asio::async_result<decltype(handler)> result(handler);
    asio_service_.service().post([=] { DoGetAvailableEndpoints(peer_id, handler); });
    return result.get();
  }

  // Makes a new connection and sends the validation data (which cannot be empty) to the peer which
  // runs its message_received_functor_ with the data.  All messages sent via this connection are
  // encrypted for the peer.
  template <typename CompletionToken>
  AddReturn<CompletionToken> Add(const Contact& peer, CompletionToken&& token);

  //template <typename CompletionToken>
  //typename boost::asio::async_result
  //  < typename boost::asio::handler_type< CompletionToken
  //                                      , void(boost::system::error_code)
  //                                      >::type
  //  >::type
  //Add(const Contact& , CompletionToken&& token) {
  //  namespace asio = boost::asio;
  //  namespace system = boost::system;

  //  using handler_type = typename asio::handler_type <CompletionToken, void(system::error_code)>::type;
  //  handler_type handler(std::forward<decltype(token)>(token));
  //  boost::asio::async_result<decltype(handler)> result(handler);
  //  asio_service_.service().post([=]() mutable { handler(boost::asio::error::operation_aborted); LOG(kVerbose) << "peter handler called"; });
  //  return result.get();
  //}

  // Drops the connection with peer.
  template <typename CompletionToken>
  RemoveReturn<CompletionToken> Remove(const NodeId& peer_id, CompletionToken&& token);

  // Sends the message to the peer.  If the message is sent successfully, the message_sent_functor
  // is executed with input of kSuccess.  If there is no existing connection to peer_id,
  // kInvalidConnection is used.
  template <typename CompletionToken>
  SendReturn<CompletionToken> Send(const NodeId& peer_id, SendableMessage&& message,
                                   CompletionToken&& token);

 private:
  using TransportPtr = std::shared_ptr<detail::Transport>;
  using ConnectionMap = std::map<NodeId, TransportPtr>;
  struct PendingConnection {
    PendingConnection(NodeId node_id_in, TransportPtr transport,
                      boost::asio::io_service& io_service);
    NodeId node_id;
    TransportPtr pending_transport;
    boost::asio::deadline_timer timer;
    bool connecting;
  };

  template <typename Handler>
  void DoBootstrap(const BootstrapContacts& bootstrap_list, std::shared_ptr<Listener> listener,
                   const NodeId& this_node_id, const asymm::Keys& keys,
                   Handler handler, Endpoint local_endpoint);

  template <typename Handler>
  void DoGetAvailableEndpoints(const NodeId& peer_id, Handler handler);

  void DoAdd(const Contact& peer, ConnectionAddedFunctor handler);

  void DoRemove(const NodeId& peer_id);

  template <typename CompletionToken>
  void DoSend(const NodeId& peer_id, SendableMessage&& message,
              SendHandler<CompletionToken> handler);

  void DoSend(const NodeId& peer_id, SendableMessage&& message, MessageSentFunctor handler);

  int CheckBootstrappingParameters(const BootstrapContacts& bootstrap_list,
                                   std::shared_ptr<Listener> listener, NodeId this_node_id) const;

  void ClearConnectionsAndIdleTransports();
  int TryToDetermineLocalEndpoint(Endpoint& local_endpoint);
  //int AttemptStartNewTransport(const BootstrapContacts& bootstrap_list,
  //                             const Endpoint& local_endpoint,Contact& chosen_bootstrap_contact);
  void AttemptStartNewTransport(const BootstrapContacts& bootstrap_list,
                               const Endpoint& local_endpoint,
                               const std::function<void(Error, const Contact&)>&);

  void StartNewTransport(BootstrapContacts bootstrap_list, Endpoint local_endpoint,
                         const std::function<void(Error, const Contact&)>&);

  void GetBootstrapEndpoints(BootstrapContacts& bootstrap_list,
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

  void OnMessageSlot(const NodeId& peer_id, const std::string& message);
  void OnConnectionAddedSlot(const NodeId& peer_id, TransportPtr transport,
                             bool temporary_connection,
                             std::atomic<bool>& is_duplicate_normal_connection);
  void OnConnectionLostSlot(const NodeId& peer_id, TransportPtr transport,
                            bool temporary_connection);
  // This signal is fired by Session when a connecting peer requests to use this peer for NAT
  // detection.  The peer will attempt to connect to another one of this node's transports using
  // its current transport.  This node (if suitable) will begin pinging the peer.
  void OnNatDetectionRequestedSlot(const Endpoint& this_local_endpoint, const NodeId& peer_id,
                                   const Endpoint& peer_endpoint, uint16_t& another_external_port);

  void UpdateIdleTransports(const TransportPtr&);

  std::string DebugString() const;

  template <typename Handler>
  void InvokeHandler(Handler&& handler, Error error);

  template <typename Handler, typename Args>
  void InvokeHandler(Handler&&, Error, Args&&);

  AsioService asio_service_;
  std::weak_ptr<Listener> listener_;
  NodeId this_node_id_;
  Contact chosen_bootstrap_contact_;
  asymm::Keys keys_;
  ConnectionMap connections_;
  std::vector<std::unique_ptr<PendingConnection>> pendings_;
  std::set<TransportPtr> idle_transports_;
  mutable std::mutex mutex_;
  boost::asio::ip::address local_ip_;
  std::unique_ptr<NatType> nat_type_;
};



template <typename CompletionToken>
BootstrapReturn<CompletionToken> ManagedConnections::Bootstrap(
    const BootstrapContacts& bootstrap_list, std::shared_ptr<Listener> listener,
    const NodeId& this_node_id, const asymm::Keys& keys, CompletionToken&& token,
    Endpoint local_endpoint) {
  BootstrapHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio_service_.service().post(
      [=] { DoBootstrap(bootstrap_list, listener, this_node_id, keys, handler, local_endpoint); });
  return result.get();
}

template <typename Handler>
void ManagedConnections::DoBootstrap(const BootstrapContacts& bootstrap_list,
                                     std::shared_ptr<Listener> listener, const NodeId& this_node_id,
                                     const asymm::Keys& keys,
                                     Handler handler,
                                     Endpoint local_endpoint) {
  ClearConnectionsAndIdleTransports();
  LOG(kVerbose) << "peter ManagedConnections::DoBootstrap";
  if (CheckBootstrappingParameters(bootstrap_list, listener, this_node_id) != kSuccess) {
    return InvokeHandler(std::forward<Handler>(handler), RudpErrors::failed_to_bootstrap,
                         Contact());
  }

  LOG(kVerbose) << "peter ManagedConnections::DoBootstrap";
  this_node_id_ = this_node_id;
  keys_ = keys;

  if (TryToDetermineLocalEndpoint(local_endpoint) != kSuccess) {
    return InvokeHandler(std::forward<Handler>(handler), RudpErrors::failed_to_bootstrap,
                         Contact());
  }

  LOG(kVerbose) << "peter ManagedConnections::DoBootstrap";
  //Contact chosen_bootstrap_contact;

  AttemptStartNewTransport(bootstrap_list, local_endpoint,
      [=](Error error, Contact chosen_contact) mutable {
        if (!error) {
          listener_ = listener;
        }

        handler(error, chosen_contact);
      });
  //if (AttemptStartNewTransport(bootstrap_list, local_endpoint, chosen_bootstrap_contact)
  //    != kSuccess) {
  //  LOG(kVerbose) << "peter -----------";
  //  return InvokeHandler(std::forward<Handler>(handler), RudpErrors::failed_to_bootstrap,
  //                       Contact());
  //}

  //LOG(kVerbose) << "peter -----------";
  //listener_ = listener;
  //handler(Error(), chosen_bootstrap_contact);
}

//template <typename Handler>
//void ManagedConnections::DoGetAvailableEndpoints(const NodeId& , Handler) {
//}
template <typename Handler>
void ManagedConnections::DoGetAvailableEndpoints(const NodeId& peer_id, Handler handler) {
  // FIXME: Error codes
  namespace error = boost::asio::error;

  //using Handler = GetAvailableEndpointsHandler<CompletionToken>;
  if (peer_id == this_node_id_) {
    LOG(kError) << "Can't use this node's ID (" << this_node_id_ << ") as peerID.";
    return InvokeHandler(std::forward<Handler>(handler), RudpErrors::operation_not_supported,
                         EndpointPair());
  }

  EndpointPair this_endpoint_pair;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.empty() && idle_transports_.empty()) {
      LOG(kError) << "No running Transports.";
      return InvokeHandler(std::forward<Handler>(handler), CommonErrors::unable_to_handle_request,
                           EndpointPair());
    }

    // Check for an existing connection attempt.
    if (ExistingConnectionAttempt(peer_id, this_endpoint_pair)) {
      LOG(kError) << "Connection attempt already in progress.";
      return InvokeHandler(std::forward<Handler>(handler),
                           RudpErrors::connection_already_in_progress, EndpointPair());
    }

    // Check for existing connection to peer.
    int return_code(kSuccess);
    if (ExistingConnection(peer_id, this_endpoint_pair, return_code)) {
      if (return_code == kConnectionAlreadyExists) {
        LOG(kError) << "A non-bootstrap managed connection from " << this_node_id_ << " to "
                    << peer_id << " already exists";
        return InvokeHandler(std::forward<Handler>(handler), RudpErrors::already_connected,
                             EndpointPair());
      } else {
        return InvokeHandler(std::forward<Handler>(handler), CommonErrors::unknown, EndpointPair());
      }
    }

    // Try to use an existing idle transport.
    if (SelectIdleTransport(peer_id, this_endpoint_pair))
      return handler(Error(), this_endpoint_pair);
  }

  //if (/*ShouldStartNewTransport(peer.endpoint_pair) &&*/
  //    StartNewTransport(BootstrapContacts(), Endpoint(local_ip_, 0)) != kSuccess) {
  //  LOG(kError) << "Failed to start transport.";
  //  return InvokeHandler(std::forward<Handler>(handler), error::no_descriptors, EndpointPair());
  //  //return InvokeHandler(std::forward<Handler>(handler), make_error_code(CommonErrors::unknown), EndpointPair());
  //}
  StartNewTransport(BootstrapContacts(), Endpoint(local_ip_, 0), [=](Error error, const Contact&) mutable {
      if (error) {
        return handler(error, EndpointPair());
      }

      if (ExistingConnectionAttempt(peer_id, this_endpoint_pair)) {
        LOG(kError) << "Connection attempt already in progress.";
        return handler(RudpErrors::connection_already_in_progress, EndpointPair());
      }

      if (!SelectAnyTransport(peer_id, this_endpoint_pair)) {
        LOG(kError) << "All connectable Transports are full.";
        return handler(CommonErrors::unable_to_handle_request, EndpointPair());
      }

      handler(Error(), this_endpoint_pair);
      });

  ////std::lock_guard<std::mutex> lock(mutex_);
  //// Check again for an existing connection attempt in case it was added while mutex unlocked
  //// during starting new transport.
  //if (ExistingConnectionAttempt(peer_id, this_endpoint_pair)) {
  //  LOG(kError) << "Connection attempt already in progress.";
  //  return InvokeHandler(std::forward<Handler>(handler), make_error_code(RudpErrors::connection_already_in_progress),
  //                       EndpointPair());
  //}

  //if (!SelectAnyTransport(peer_id, this_endpoint_pair)) {
  //  LOG(kError) << "All connectable Transports are full.";
  //  return InvokeHandler(std::forward<Handler>(handler), boost::asio::error::no_descriptors,
  //                       EndpointPair());
  //  //return InvokeHandler(std::forward<Handler>(handler), CommonErrors::unable_to_handle_request,
  //  //                     EndpointPair());
  //}

  //handler(Error(), this_endpoint_pair);
  //handler(make_error_code(CommonErrors::success), this_endpoint_pair);
}

template <typename CompletionToken>
AddReturn<CompletionToken> ManagedConnections::Add(const Contact& peer, CompletionToken&& token) {
  AddHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio_service_.service().post([=]() mutable { DoAdd(peer, handler); });
  return result.get();
}

template <typename CompletionToken>
RemoveReturn<CompletionToken> ManagedConnections::Remove(const NodeId& peer_id,
                                                         CompletionToken&& token) {
  RemoveHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio_service_.service().post([=] {
    DoRemove(peer_id);
    handler(make_error_code(CommonErrors::success));
  });
  return result.get();
}

template <typename CompletionToken>
SendReturn<CompletionToken> ManagedConnections::Send(const NodeId& peer_id,
                                                     SendableMessage&& message,
                                                     CompletionToken&& token) {
  SendHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio_service_.service().post([=] { DoSend(peer_id, std::move(message), handler); });
  return result.get();
}

template <typename CompletionToken>
void ManagedConnections::DoSend(const NodeId& peer_id, SendableMessage&& message,
            SendHandler<CompletionToken> handler) {
  DoSend(peer_id, std::move(message), [=](Error error_code) {
    if (error_code)
      this->InvokeHandler(handler, error_code);
    else  // success case
      handler(error_code);
  });
}

// GCC 4.8 still doesn't support passing variadic argument pack to
// lambda functions.
template <typename Handler>
void ManagedConnections::InvokeHandler(Handler&& handler, Error error) {
  assert(error);
  asio_service_.service().post([handler, error]() mutable { handler(error); });
}

template <typename Handler, typename Arg>
void ManagedConnections::InvokeHandler(Handler&& handler, Error error, Arg&& arg) {
  assert(error);
  asio_service_.service().post(
      [handler, error, arg]() mutable { handler(error, arg); });
}

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_MANAGED_CONNECTIONS_H_
