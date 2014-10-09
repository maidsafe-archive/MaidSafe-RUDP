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

#ifndef MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
#define MAIDSAFE_RUDP_CONNECTION_MANAGER_H_

#include <unordered_map>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>

#include "boost/asio/buffer.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"

#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class Transport;
class Connection;
class Multiplexer;
class Socket;
class HandshakePacket;

class ConnectionManager {
 public:
  using Endpoint      = boost::asio::ip::udp::endpoint;
  using ConnectionPtr = std::shared_ptr<Connection>;
  using Error         = boost::system::error_code;
  using OnConnect     = std::function<void(const Error&, const ConnectionPtr&)>;

 public:
  ConnectionManager(std::shared_ptr<Transport> transport,
                    const boost::asio::io_service::strand& strand,
                    std::shared_ptr<Multiplexer> multiplexer, NodeId this_node_id,
                    std::shared_ptr<asymm::PublicKey> this_public_key);
  ~ConnectionManager();

  void Close();

  bool Connect(const NodeId& peer_id, const Endpoint& peer_endpoint,
               const std::string& validation_data,
               const boost::posix_time::time_duration& connect_attempt_timeout,
               const boost::posix_time::time_duration& lifespan,
               const OnConnect& on_connect,
               const std::function<void()>& failure_functor);

  int AddConnection(std::shared_ptr<Connection> connection);
  bool CloseConnection(const NodeId& peer_id);
  void RemoveConnection(std::shared_ptr<Connection> connection);
  std::shared_ptr<Connection> GetConnection(const NodeId& peer_id);

  void Ping(const NodeId& peer_id, const Endpoint& peer_endpoint,
            const std::function<void(int)>& ping_functor);  // NOLINT (Fraser)
  // Returns false if the connection doesn't exist.
  bool Send(const NodeId& peer_id, const std::string& message,
            const std::function<void(int)>& message_sent_functor);  // NOLINT (Fraser)

  bool MakeConnectionPermanent(const NodeId& peer_id, bool validated, Endpoint& peer_endpoint);

  // This node's endpoint as viewed by peer
  Endpoint ThisEndpoint(const NodeId& peer_id);

  // Called by Transport when bootstrapping a new transport but when we don't create a temporary
  // connection to establish external endpoint (i.e this node's NAT is symmetric)
  void SetBestGuessExternalEndpoint(const Endpoint& external_endpoint);

  // Get the remote endpoint offered for NAT detection by peer.
  Endpoint RemoteNatDetectionEndpoint(const NodeId& peer_id);

  // Add a socket. Returns a new unique id for the socket.
  uint32_t AddSocket(Socket* socket);
  void RemoveSocket(uint32_t id);
  // Called by the Dispatcher when a new packet arrives for a socket.  Can return nullptr if no
  // appropriate socket found.
  Socket* GetSocket(const boost::asio::const_buffer& data,
                    const Endpoint& endpoint);

  size_t NormalConnectionsCount() const;

  NodeId node_id() const;
  std::shared_ptr<asymm::PublicKey> public_key() const;

  std::string DebugString();

 private:
  ConnectionManager(const ConnectionManager&);
  ConnectionManager& operator=(const ConnectionManager&);

  bool CanStartConnectingTo(NodeId, Endpoint) const;
  void MarkDoneConnecting(NodeId peer_id, Endpoint peer_ep);

 private:
  typedef std::shared_ptr<Multiplexer> MultiplexerPtr;
  typedef std::set<ConnectionPtr> ConnectionGroup;
  // Map of destination socket id to corresponding socket object.
  typedef std::unordered_map<uint32_t, Socket*> SocketMap;

  void HandlePingFrom(const HandshakePacket& handshake_packet, const Endpoint& endpoint);
  ConnectionGroup::iterator FindConnection(const NodeId& peer_id) const;

  // TODO(PeterJ): Instead of using this set, it would be nicer if we
  // added a "not yet connected connection" into the connetions_ group
  // right a way (before it is connected).
  std::set<std::pair<NodeId, Endpoint>> being_connected_;

  // Because the connections can be in an idle state with no pending async operations, they are kept
  // alive with a shared_ptr in this set, as well as in the async operation handlers.
  ConnectionGroup connections_;
  mutable std::mutex mutex_;
  std::weak_ptr<Transport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<Multiplexer> multiplexer_;
  const NodeId kThisNodeId_;
  std::shared_ptr<asymm::PublicKey> this_public_key_;
  SocketMap sockets_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
