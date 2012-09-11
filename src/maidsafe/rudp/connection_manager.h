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

#ifndef MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
#define MAIDSAFE_RUDP_CONNECTION_MANAGER_H_

#include <unordered_map>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/mutex.hpp"

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
  ConnectionManager(std::shared_ptr<Transport> transport,
                    const boost::asio::io_service::strand& strand,
                    std::shared_ptr<Multiplexer> multiplexer,
                    const NodeId& this_node_id,
                    std::shared_ptr<asymm::PublicKey> this_public_key);
  ~ConnectionManager();

  void Close();

  void Connect(const NodeId& peer_id,
               const boost::asio::ip::udp::endpoint& peer_endpoint,
               const std::string& validation_data,
               const boost::posix_time::time_duration& connect_attempt_timeout,
               const boost::posix_time::time_duration& lifespan);
  bool AddConnection(std::shared_ptr<Connection> connection);
  bool AddPending(const NodeId& peer_id, const boost::asio::ip::udp::endpoint& peer_endpoint);

  // Returns kSuccess if the connection existed and was closed.  Returns
  // kInvalidConnection if the connection didn't exist.
  bool CloseConnection(const NodeId& peer_id);
  void RemoveConnection(std::shared_ptr<Connection> connection,
                        bool& connections_empty,
                        bool& temporary_connection);
  bool RemovePending(const NodeId& peer_id);

  bool HasNormalConnectionTo(const NodeId& peer_id) const;
  std::shared_ptr<Connection> GetConnection(const NodeId& peer_id);

  void Ping(const NodeId& peer_id,
            const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  // Returns false if the connection doesn't exist.
  bool Send(const NodeId& peer_id,
            const std::string& message,
            const std::function<void(int)>& message_sent_functor);  // NOLINT (Fraser)

  //bool IsTemporaryConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);
  bool MakeConnectionPermanent(const NodeId& peer_id);

  // This node's endpoint as viewed by peer
  boost::asio::ip::udp::endpoint ThisEndpoint(const NodeId& peer_id);

  // Called by Transport when bootstrapping a new transport but when we don't create a temporary
  // connection to establish external endpoint (i.e this node's NAT is symmetric)
  void SetBestGuessExternalEndpoint(const boost::asio::ip::udp::endpoint& external_endpoint);

  // Get the remote endpoint offered for NAT detection by peer.
  boost::asio::ip::udp::endpoint RemoteNatDetectionEndpoint(const NodeId& peer_id);

  // Add a socket. Returns a new unique id for the socket.
  uint32_t AddSocket(Socket* socket);
  void RemoveSocket(uint32_t id);
  // Called by the Dispatcher when a new packet arrives for a socket.  Can return nullptr if no
  // appropriate socket found.
  Socket* GetSocket(const boost::asio::const_buffer& data,
                    const boost::asio::ip::udp::endpoint& endpoint);

  size_t NormalConnectionsCount() const;

  NodeId node_id() const;
  std::shared_ptr<asymm::PublicKey> public_key() const;

  std::string DebugString();

 private:
  ConnectionManager(const ConnectionManager&);
  ConnectionManager& operator=(const ConnectionManager&);

  typedef std::shared_ptr<Multiplexer> MultiplexerPtr;
  typedef std::shared_ptr<Connection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionGroup;
  typedef std::map<NodeId, boost::asio::ip::udp::endpoint> PendingsGroup;
  // Map of destination socket id to corresponding socket object.
  typedef std::unordered_map<uint32_t, Socket*> SocketMap;

  void HandlePingFrom(const HandshakePacket& handshake_packet,
                      const boost::asio::ip::udp::endpoint& endpoint);
  ConnectionGroup::iterator FindConnection(const NodeId& peer_id) const;

  // Because the connections can be in an idle state with no pending async operations, they are kept
  // alive with a shared_ptr in this set, as well as in the async operation handlers.
  ConnectionGroup connections_, temporaries_;
  PendingsGroup pendings_;
  mutable boost::mutex mutex_;
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
