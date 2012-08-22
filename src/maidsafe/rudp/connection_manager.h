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

#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace rudp {

namespace detail {

class Transport;
class Connection;
class Multiplexer;
class Socket;


class ConnectionManager {
 public:
  ConnectionManager(std::shared_ptr<Transport> transport,
                    const boost::asio::io_service::strand& strand,
                    std::shared_ptr<Multiplexer> multiplexer,
                    std::shared_ptr<asymm::PublicKey> this_public_key);
  ~ConnectionManager();

  void Close();

  void Connect(const boost::asio::ip::udp::endpoint& peer_endpoint,
               const std::string& validation_data,
               const boost::posix_time::time_duration& lifespan);
  void InsertConnection(std::shared_ptr<Connection> connection);

  // Returns kSuccess if the connection existed and was closed.  Returns
  // kInvalidConnection if the connection didn't exist.
  int CloseConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);
  void RemoveConnection(std::shared_ptr<Connection> connection,
                        bool& connections_empty,
                        bool& temporary_connection);

  void Ping(const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)
  void Send(const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::string& message,
            const std::function<void(int)>& message_sent_functor);  // NOLINT (Fraser)

  bool IsTemporaryConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);
  bool MakeConnectionPermanent(const boost::asio::ip::udp::endpoint& peer_endpoint,
                               const std::string& validation_data);

  // This node's endpoint as viewed by peer
  boost::asio::ip::udp::endpoint ThisEndpoint(const boost::asio::ip::udp::endpoint& peer_endpoint);

  // Add a socket. Returns a new unique id for the socket.
  uint32_t AddSocket(Socket* socket);
  void RemoveSocket(uint32_t id);
  // Called by the Dispatcher when a new packet arrives for a socket.  Can return nullptr if no
  // appropriate socket found.
  Socket* GetSocket(const boost::asio::const_buffer& data,
                    const boost::asio::ip::udp::endpoint& endpoint);

  size_t size() const;

 private:
  ConnectionManager(const ConnectionManager&);
  ConnectionManager& operator=(const ConnectionManager&);

  typedef std::shared_ptr<Multiplexer> MultiplexerPtr;
  typedef std::shared_ptr<Connection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;
  // Map of destination socket id to corresponding socket object.
  typedef std::unordered_map<uint32_t, Socket*> SocketMap;

  void HandlePingFrom(const boost::asio::const_buffer& data,
                      const boost::asio::ip::udp::endpoint& endpoint);
  ConnectionSet::iterator FindConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);

  // Because the connections can be in an idle state with no pending async operations, they are kept
  // alive with a shared_ptr in this set, as well as in the async operation handlers.
  ConnectionSet connections_;
  mutable boost::mutex mutex_;
  std::weak_ptr<Transport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<Multiplexer> multiplexer_;
  std::shared_ptr<asymm::PublicKey> this_public_key_;
  SocketMap sockets_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
