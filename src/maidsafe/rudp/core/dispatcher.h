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

#ifndef MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_
#define MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_

#include <unordered_map>
#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class RudpAcceptor;
class RudpSocket;

class RudpDispatcher {
 public:
  RudpDispatcher();

  // Get the one-and-only acceptor.
  RudpAcceptor *GetAcceptor() const;

  // Set the one-and-only acceptor.
  void SetAcceptor(RudpAcceptor *acceptor);

  // Add a socket. Returns a new unique id for the socket.
  boost::uint32_t AddSocket(RudpSocket *socket);

  // Remove the socket corresponding to the given id.
  void RemoveSocket(boost::uint32_t id);

  // Handle a new packet by dispatching to the appropriate socket or acceptor.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

 private:
  // Disallow copying and assignment.
  RudpDispatcher(const RudpDispatcher&);
  RudpDispatcher &operator=(const RudpDispatcher&);

  // The one-and-only acceptor.
  RudpAcceptor* acceptor_;

  // Map of destination socket id to corresponding socket object.
  typedef std::unordered_map<boost::uint32_t, RudpSocket*> SocketMap;
  SocketMap sockets_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_
