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

#include "maidsafe/transport/rudp_multiplexer.h"
#include "maidsafe/transport/rudp_packet.h"
#include "maidsafe/transport/log.h"

namespace asio = boost::asio;
namespace ip = boost::asio::ip;
namespace bs = boost::system;

namespace maidsafe {

namespace transport {

RudpMultiplexer::RudpMultiplexer(asio::io_service &asio_service) //NOLINT
  : socket_(asio_service),
    receive_buffer_(RudpParameters::max_size),
    sender_endpoint_(),
    dispatcher_() {}

RudpMultiplexer::~RudpMultiplexer() {
}

TransportCondition RudpMultiplexer::Open(const ip::udp &protocol) {
  if (socket_.is_open())
    return kAlreadyStarted;

  bs::error_code ec;
  socket_.open(protocol, ec);

  if (ec)
    return kInvalidAddress;

  ip::udp::socket::non_blocking_io nbio(true);
  socket_.io_control(nbio, ec);

  if (ec)
    return kSetOptionFailure;

  return kSuccess;
}

TransportCondition RudpMultiplexer::Open(const ip::udp::endpoint &endpoint) {
  if (socket_.is_open())
    return kAlreadyStarted;

  if (endpoint.port() == 0)
    return kInvalidPort;

  bs::error_code ec;
  socket_.open(endpoint.protocol(), ec);

  if (ec)
    return kInvalidAddress;

  ip::udp::socket::non_blocking_io nbio(true);
  socket_.io_control(nbio, ec);

  if (ec)
    return kSetOptionFailure;

  socket_.bind(endpoint, ec);

  if (ec)
    return kBindError;

  return kSuccess;
}

bool RudpMultiplexer::IsOpen() const {
  return socket_.is_open();
}

void RudpMultiplexer::Close() {
  bs::error_code ec;
  socket_.close(ec);
}

}  // namespace transport

}  // namespace maidsafe

