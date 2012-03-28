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

#include "maidsafe/transport/rudp_dispatcher.h"

#include <cassert>

#include "maidsafe/transport/rudp_acceptor.h"
#include "maidsafe/transport/rudp_packet.h"
#include "maidsafe/transport/rudp_socket.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

RudpDispatcher::RudpDispatcher()
    : acceptor_(0),
      sockets_() {
}

RudpAcceptor *RudpDispatcher::GetAcceptor() const {
  return acceptor_;
}

void RudpDispatcher::SetAcceptor(RudpAcceptor *acceptor) {
  assert(acceptor == 0 || acceptor_ == 0);
  acceptor_ = acceptor;
}

boost::uint32_t RudpDispatcher::AddSocket(RudpSocket *socket) {
  // Generate a new unique id for the socket.
  boost::uint32_t id = 0;
  while (id == 0 || sockets_.count(id) != 0)
    id = RandomUint32();

  sockets_[id] = socket;
  return id;
}

void RudpDispatcher::RemoveSocket(boost::uint32_t id) {
  if (id)
    sockets_.erase(id);
}

void RudpDispatcher::HandleReceiveFrom(const asio::const_buffer &data,
                                       const ip::udp::endpoint &endpoint) {
  boost::uint32_t id = 0;
  if (RudpPacket::DecodeDestinationSocketId(&id, data)) {
    if (id == 0) {
      // This packet is intended for the acceptor.
      if (acceptor_) {
        acceptor_->HandleReceiveFrom(data, endpoint);
      } else {
        DLOG(ERROR) << "Received a request for a new connection from "
                    << endpoint << " but there is no acceptor" << std::endl;
      }
    } else {
      // This packet is intended for a specific connection.
      SocketMap::iterator socket_iter = sockets_.find(id);
      if (socket_iter != sockets_.end()) {
        socket_iter->second->HandleReceiveFrom(data, endpoint);
      } else {
        const unsigned char *p = asio::buffer_cast<const unsigned char*>(data);
        DLOG(ERROR) << "Received a packet \"0x" << std::hex
                    << static_cast<int>(*p) << std::dec
                    << "\" for unknown connection "
                    << id << " from " << endpoint << std::endl;
      }
    }
  }
}

}  // namespace transport

}  // namespace maidsafe
