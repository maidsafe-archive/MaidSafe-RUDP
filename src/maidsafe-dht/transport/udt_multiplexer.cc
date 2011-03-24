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

#include "maidsafe-dht/transport/udt_multiplexer.h"

#include <cassert>
#include <functional>

#include "maidsafe-dht/transport/udt_acceptor.h"
#include "maidsafe-dht/transport/udt_packet.h"
#include "maidsafe-dht/transport/udt_socket.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

UdtMultiplexer::UdtMultiplexer(asio::io_service &asio_service)
  : socket_(asio_service),
    receive_buffer_(kMaxPacketSize) {
}

UdtMultiplexer::~UdtMultiplexer() {
}

TransportCondition UdtMultiplexer::Open(const Endpoint &endpoint) {
  if (socket_.is_open())
    return kAlreadyStarted;

  if (endpoint.port == 0)
    return kInvalidPort;

  bs::error_code ec;
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  socket_.open(ep.protocol(), ec);

  if (ec)
    return kInvalidAddress;

  socket_.bind(ep, ec);

  if (ec)
    return kBindError;

  StartReceive();

  return kSuccess;
}

void UdtMultiplexer::Close() {
  bs::error_code ec;
  socket_.close(ec);
  udt_acceptor_.reset();
  udt_sockets_.clear();
}

std::shared_ptr<UdtAcceptor> UdtMultiplexer::NewAcceptor() {
  // No lazy open for acceptors.
  if (!socket_.is_open())
    return std::shared_ptr<UdtAcceptor>();

  // There can be only one.
  if (!udt_acceptor_.expired())
    return std::shared_ptr<UdtAcceptor>();

  std::shared_ptr<UdtAcceptor> a(new UdtAcceptor(shared_from_this(),
                                                 socket_.get_io_service()));
  udt_acceptor_ = a;
  return a;
}

std::shared_ptr<UdtSocket> UdtMultiplexer::NewClient(const Endpoint &endpoint) {
  // Lazy open as the multiplexer might be used only for outbound connections.
  if (!socket_.is_open()) {
    bs::error_code ec;
    ip::udp::endpoint ep(endpoint.ip, endpoint.port);
    if (socket_.open(ep.protocol(), ec))
      return std::shared_ptr<UdtSocket>();
    StartReceive();
  }

  // Generate a new unique id for the socket.
  boost::uint32_t id = 0;
  while (id == 0 || udt_sockets_.count(id) != 0)
    id = SRandomUint32();

  std::shared_ptr<UdtSocket> c(new UdtSocket(shared_from_this(),
                                             socket_.get_io_service(),
                                             id, endpoint));
  udt_sockets_[id] = c;
  return c;
}

void UdtMultiplexer::StartReceive() {
  assert(socket_.is_open());

  socket_.async_receive_from(asio::buffer(receive_buffer_),
                             sender_endpoint_,
                             std::bind(&UdtMultiplexer::HandleReceive,
                                       shared_from_this(),
                                       arg::_1, arg::_2));
}

void UdtMultiplexer::HandleReceive(const boost::system::error_code &ec,
                                   size_t bytes_transferred) {
  if (!socket_.is_open())
    return;

  if (!ec) {
    boost::uint32_t id = 0;
    asio::const_buffer data = asio::buffer(receive_buffer_, bytes_transferred);
    if (UdtPacket::DecodeDestinationSocketId(&id, data)) {
      if (id == 0) {
        // This packet is intended for the acceptor.
        if (std::shared_ptr<UdtAcceptor> acceptor = udt_acceptor_.lock()) {
          acceptor->HandleReceiveFrom(data, sender_endpoint_);
        } else {
          DLOG(ERROR) << "Received a request for a new connection from "
                      << sender_endpoint_ << " but there is no acceptor"
                      << std::endl;
        }
      } else {
        // This packet is intended for a specific connection.
        SocketMap::iterator socket_iter = udt_sockets_.find(id);
        if (socket_iter != udt_sockets_.end()) {
          if (std::shared_ptr<UdtSocket> socket = socket_iter->second.lock()) {
            socket->HandleReceiveFrom(data, sender_endpoint_);
          } else {
            DLOG(ERROR) << "Received a packet for defunct connection "
                        << id << " from " << sender_endpoint_ << std::endl;
            udt_sockets_.erase(socket_iter);
          }
        } else {
          DLOG(ERROR) << "Received a packet for unknown connection "
                      << id << " from " << sender_endpoint_ << std::endl;
        }
      }
    }
  }

  StartReceive();
}

bool UdtMultiplexer::SendTo(const asio::const_buffer &data,
                            const asio::ip::udp::endpoint &endpoint) {
  if (!socket_.is_open())
    return false;

  bs::error_code ec;
  socket_.send_to(asio::buffer(data), endpoint, 0, ec);
  return !ec;
}

}  // namespace transport

}  // namespace maidsafe

