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
// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_CORE_DISPATCHER_H_
#define MAIDSAFE_RUDP_CORE_DISPATCHER_H_

#include <cstdint>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"

extern uint32_t tprt;
extern uint32_t conn;
extern uint32_t disp;

namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Socket;

class Dispatcher {
 public:
  Dispatcher();
                                                                                                  ~Dispatcher();

  void SetConnectionManager(ConnectionManager* connection_manager);

  // Add a socket. Returns a new unique id for the socket.
  uint32_t AddSocket(Socket* socket);

  // Remove the socket corresponding to the given id.
  void RemoveSocket(uint32_t id);

  // Handle a new packet by dispatching to the appropriate socket.
  void HandleReceiveFrom(const boost::asio::const_buffer& data,
                         const boost::asio::ip::udp::endpoint& endpoint);
                                                                                                    uint32_t my_disp_;

 private:
  // Disallow copying and assignment.
  Dispatcher(const Dispatcher&);
  Dispatcher& operator=(const Dispatcher&);

  ConnectionManager* connection_manager_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_DISPATCHER_H_
