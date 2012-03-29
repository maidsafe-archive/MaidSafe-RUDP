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

#include "maidsafe/rudp/core/dispatcher.h"

#include <cassert>

#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/core/acceptor.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/log.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

Dispatcher::Dispatcher()
    : acceptor_(0),
      sockets_() {
}

Acceptor *Dispatcher::GetAcceptor() const {
  return acceptor_;
}

void Dispatcher::SetAcceptor(Acceptor *acceptor) {
  assert(acceptor == 0 || acceptor_ == 0);
  acceptor_ = acceptor;
}

uint32_t Dispatcher::AddSocket(Socket *socket) {
  // Generate a new unique id for the socket.
  uint32_t id = 0;
  while (id == 0 || sockets_.count(id) != 0)
    id = RandomUint32();

  sockets_[id] = socket;
  return id;
}

void Dispatcher::RemoveSocket(uint32_t id) {
  if (id)
    sockets_.erase(id);
}

void Dispatcher::HandleReceiveFrom(const asio::const_buffer &data,
                                   const ip::udp::endpoint &endpoint) {
  uint32_t id = 0;
  if (Packet::DecodeDestinationSocketId(&id, data)) {
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

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
