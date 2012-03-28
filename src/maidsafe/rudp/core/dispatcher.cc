/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

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
