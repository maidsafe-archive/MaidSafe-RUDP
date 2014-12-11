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

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_TRANSPORT_H_
#define MAIDSAFE_RUDP_TRANSPORT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <mutex>

#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/core/session.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Connection;
class Multiplexer;
class Socket;

class Transport : public std::enable_shared_from_this<Transport> {
 public:
  typedef std::function<void(const std::string&)> OnMessage;

  typedef std::function<void(const NodeId&, std::shared_ptr<Transport>, bool, std::atomic<bool> &)>
      OnConnectionAdded;

  typedef std::function<void(const NodeId&, std::shared_ptr<Transport>, bool, bool)>
      OnConnectionLost;

  using Endpoint        = boost::asio::ip::udp::endpoint;
  using ConnectionPtr   = std::shared_ptr<Connection>;
  using Error           = boost::system::error_code;
  using OnConnect       = std::function<void(const Error&, const ConnectionPtr&)>;
  using Duration        = boost::posix_time::time_duration;
  using IdEndpointPairs = std::vector<std::pair<NodeId, Endpoint>>;
  using OnNatDetected   = Session::OnNatDetectionRequested::slot_function_type;
  using OnBootstrap     = std::function<void(ReturnCode, NodeId)>;

 public:
  Transport(AsioService& asio_service, NatType& nat_type_);

  virtual ~Transport();

  void Bootstrap(const IdEndpointPairs&            bootstrap_peers,
                 const NodeId&                     this_node_id,
                 std::shared_ptr<asymm::PublicKey> this_public_key,
                 Endpoint                          local_endpoint,
                 bool                              bootstrap_off_existing_connection,
                 OnMessage                         on_message_slot,
                 OnConnectionAdded                 on_connection_added_slot,
                 OnConnectionLost                  on_connection_lost_slot,
                 const OnNatDetected&              on_nat_detection_requested_slot,
                 OnBootstrap                       on_bootstrap);

  void Close();

  void Connect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
               const std::string& validation_data);

  // If this causes the size of connected_endpoints_ to drop to 0, this transport will remove
  // itself from ManagedConnections which will cause it to be destroyed.
  bool CloseConnection(const NodeId& peer_id);

  bool Send(const NodeId& peer_id, const std::string& message,
            const std::function<void(int)>& message_sent_functor);  // NOLINT (Fraser)

  void Ping(const NodeId& peer_id, const Endpoint& peer_endpoint,
            const std::function<void(int)>& ping_functor);  // NOLINT (Fraser)

  ConnectionPtr GetConnection(const NodeId& peer_id);

  Endpoint external_endpoint() const;
  Endpoint local_endpoint() const;
  Endpoint ThisEndpointAsSeenByPeer(const NodeId& peer_id);
  void SetBestGuessExternalEndpoint(const Endpoint& external_endpoint);

  bool MakeConnectionPermanent(const NodeId& peer_id, bool validated, Endpoint& peer_endpoint);

  size_t NormalConnectionsCount() const;
  bool IsIdle() const;
  bool IsAvailable() const;

  static int kMaxConnections() { return 50; }

  std::string DebugString() const;
  std::string ThisDebugId() const;
  void SetManagedConnectionsDebugPrintout(std::function<std::string()> functor);

  friend class Connection;
  friend class ConnectionManager;

 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);

  typedef std::shared_ptr<Multiplexer>       MultiplexerPtr;
  typedef std::shared_ptr<ConnectionManager> ConnectionManagerPtr;

  template<class Handler>
  void TryBootstrapping(const IdEndpointPairs& bootstrap_peers,
                        bool bootstrap_off_existing_connection,
                        Handler);

  template<class Iterator, class Handler>
  void ConnectToBootstrapEndpoint(Iterator begin, Iterator end, Duration lifespan, Handler handler);

  template<class Handler>
  void ConnectToBootstrapEndpoint(const NodeId&   bootstrap_node_id,
                                  const Endpoint& bootstrap_endpoint,
                                  const Duration& lifespan,
                                  Handler);

  template<class Handler>
  void DetectNatType(NodeId const& peer_id, Handler);

  void DoConnect(const NodeId& peer_id, const EndpointPair& peer_endpoint_pair,
                 const std::string& validation_data);

  void StartDispatch();
  void HandleDispatch(const boost::system::error_code& ec);

  NodeId node_id() const;
  std::shared_ptr<asymm::PublicKey> public_key() const;

  void SignalMessageReceived(const std::string& message);
  void DoSignalMessageReceived(const std::string& message);
  void AddConnection(ConnectionPtr connection);
  void DoAddConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection, bool timed_out);
  void DoRemoveConnection(ConnectionPtr connection, bool timed_out);

  OnConnect MakeDefaultOnConnectHandler();

 private:
  AsioService&                       asio_service_;
  NatType&                           nat_type_;
  boost::asio::io_service::strand    strand_;
  MultiplexerPtr                     multiplexer_;
  ConnectionManagerPtr               connection_manager_;
  std::mutex                         callback_mutex_;

  OnMessage         on_message_;
  OnConnectionAdded on_connection_added_;
  OnConnectionLost  on_connection_lost_;
  OnNatDetected     on_nat_detection_requested_slot_;

  std::function<std::string()> managed_connections_debug_printout_;
};

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TRANSPORT_H_
