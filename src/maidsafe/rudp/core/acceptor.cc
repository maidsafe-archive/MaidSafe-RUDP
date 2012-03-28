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

#include <cassert>

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_acceptor.h"
#include "maidsafe/transport/rudp_socket.h"
#include "maidsafe/transport/rudp_handshake_packet.h"
#include "maidsafe/transport/rudp_multiplexer.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

RudpAcceptor::RudpAcceptor(RudpMultiplexer &multiplexer)  // NOLINT (Fraser)
  : multiplexer_(multiplexer),
    waiting_accept_(multiplexer.socket_.get_io_service()),
    waiting_accept_socket_(0),
    pending_requests_() {
  waiting_accept_.expires_at(boost::posix_time::pos_infin);
  multiplexer_.dispatcher_.SetAcceptor(this);
}

RudpAcceptor::~RudpAcceptor() {
  if (IsOpen())
    multiplexer_.dispatcher_.SetAcceptor(0);
}

bool RudpAcceptor::IsOpen() const {
  return multiplexer_.dispatcher_.GetAcceptor() == this;
}

void RudpAcceptor::Close() {
  pending_requests_.clear();
  waiting_accept_.cancel();
  if (IsOpen())
    multiplexer_.dispatcher_.SetAcceptor(0);
}

void RudpAcceptor::StartAccept(RudpSocket &socket) {  // NOLINT (Fraser)
  assert(waiting_accept_socket_ == 0);  // Only one accept operation at a time.

  if (!pending_requests_.empty()) {
    socket.peer_.SetEndpoint(pending_requests_.front().remote_endpoint);
    socket.peer_.SetId(pending_requests_.front().remote_id);
    pending_requests_.pop_front();
    waiting_accept_.cancel();
  } else {
    waiting_accept_socket_ = &socket;
  }
}

void RudpAcceptor::HandleReceiveFrom(const asio::const_buffer &data,
                                     const asio::ip::udp::endpoint &endpoint) {
  RudpHandshakePacket packet;
  if (packet.Decode(data)) {
    if (RudpSocket* socket = waiting_accept_socket_) {
      // A socket is ready and waiting to accept the new connection.
      socket->peer_.SetEndpoint(endpoint);
      socket->peer_.SetId(packet.SocketId());
      waiting_accept_socket_ = 0;
      waiting_accept_.cancel();
    } else {
      // There's no socket waiting, queue it for later.
      PendingRequest pending_request;
      pending_request.remote_id = packet.SocketId();
      pending_request.remote_endpoint = endpoint;
      pending_requests_.push_back(pending_request);
    }
  } else {
    DLOG(ERROR) << "Acceptor ignoring invalid packet from " << endpoint;
  }
}

}  // namespace transport

}  // namespace maidsafe

