/* Copyright (c) 2011 maidsafe.net limited
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

#include <functional>
#include <vector>

#include "maidsafe/common/test.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_acceptor.h"
#include "maidsafe/transport/rudp_multiplexer.h"
#include "maidsafe/transport/rudp_socket.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bs = boost::system;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

namespace test {

const size_t kBufferSize = 1024 * 1024;
const size_t kIterations = 100;

void dispatch_handler(const bs::error_code &ec, RudpMultiplexer *muxer) {
  if (!ec) muxer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, muxer));
}

void tick_handler(const bs::error_code &ec, RudpSocket *sock) {
  if (!ec) sock->AsyncTick(std::bind(&tick_handler, args::_1, sock));
}

void handler1(const bs::error_code &ec, bs::error_code *out_ec) {
  *out_ec = ec;
}

TEST(RudpSocketTest, BEH_Socket) {
  asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;

  RudpMultiplexer server_multiplexer(io_service);
  ip::udp::endpoint server_endpoint(ip::address_v4::loopback(), 2000);
  TransportCondition condition = server_multiplexer.Open(server_endpoint);
  ASSERT_EQ(kSuccess, condition);

  RudpMultiplexer client_multiplexer(io_service);
  condition = client_multiplexer.Open(ip::udp::v4());
  ASSERT_EQ(kSuccess, condition);

  server_multiplexer.AsyncDispatch(std::bind(&dispatch_handler, args::_1,
                                             &server_multiplexer));


  RudpAcceptor server_acceptor(server_multiplexer);
  RudpSocket server_socket(server_multiplexer);
  server_ec = asio::error::would_block;
  server_acceptor.AsyncAccept(server_socket, std::bind(&handler1, args::_1,
                                                       &server_ec));

  RudpSocket client_socket(client_multiplexer);
  client_ec = asio::error::would_block;
  client_socket.AsyncConnect(server_endpoint, std::bind(&handler1, args::_1,
                                                        &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);

  server_ec = asio::error::would_block;
  client_multiplexer.AsyncDispatch(std::bind(&dispatch_handler, args::_1,
                                             &client_multiplexer));

  server_socket.AsyncConnect(std::bind(&handler1, args::_1, &server_ec));

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block ||
           client_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(server_socket.IsOpen());
  ASSERT_TRUE(!client_ec);
  ASSERT_TRUE(client_socket.IsOpen());

  server_socket.AsyncTick(std::bind(&tick_handler, args::_1, &server_socket));

  client_socket.AsyncTick(std::bind(&tick_handler, args::_1, &client_socket));

  for (size_t i = 0; i < kIterations; ++i) {
    std::vector<unsigned char> server_buffer(kBufferSize);
    server_ec = asio::error::would_block;
    server_socket.AsyncRead(asio::buffer(server_buffer), kBufferSize,
                            std::bind(&handler1, args::_1, &server_ec));

    std::vector<unsigned char> client_buffer(kBufferSize, 'A');
    client_ec = asio::error::would_block;
    client_socket.AsyncWrite(asio::buffer(client_buffer),
                            std::bind(&handler1, args::_1, &client_ec));

    do {
      io_service.run_one();
    } while (server_ec == asio::error::would_block ||
             client_ec == asio::error::would_block);
    ASSERT_TRUE(!server_ec);
    ASSERT_TRUE(!client_ec);
  }

  server_ec = asio::error::would_block;
  server_socket.AsyncFlush(std::bind(&handler1, args::_1, &server_ec));

  client_ec = asio::error::would_block;
  client_socket.AsyncFlush(std::bind(&handler1, args::_1, &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block ||
           client_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(!client_ec);
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
