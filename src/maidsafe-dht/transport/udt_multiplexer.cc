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

#include "maidsafe-dht/transport/udt_socket.h"
#include "maidsafe/common/log.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

UdtMultiplexer::UdtMultiplexer(asio::io_service &asio_service)
  : socket_(asio_service),
    waiting_op_(asio_service),
    receive_buffer_(kMaxPacketSize) {
  waiting_op_.expires_at(boost::posix_time::pos_infin);
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
  accept_queue_ = SocketQueue();
  waiting_op_.cancel();
}

std::shared_ptr<UdtSocket> UdtMultiplexer::NewClient(const Endpoint &endpoint) {
  if (!socket_.is_open()) {
    bs::error_code ec;
    ip::udp::endpoint ep(endpoint.ip, endpoint.port);
    if (socket_.open(ep.protocol(), ec))
      return std::shared_ptr<UdtSocket>();
  }

  return std::shared_ptr<UdtSocket>(new UdtSocket(shared_from_this(),
                                                  socket_.get_io_service(),
                                                  endpoint));
}

void UdtMultiplexer::StartAccept() {
  if (!accept_queue_.empty())
    waiting_op_.cancel();
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
    // Parse packet here.
  }

  StartReceive();
}

}  // namespace transport

}  // namespace maidsafe

