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

#include <functional>
#include <vector>

#include "maidsafe/common/test.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/core/acceptor.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bs = boost::system;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

const size_t kBufferSize = 1024 * 1024;
const size_t kIterations = 100;

void dispatch_handler(const bs::error_code &ec, Multiplexer *muxer) {
  if (!ec) muxer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, muxer));
}

void tick_handler(const bs::error_code &ec, Socket *sock) {
  if (!ec) sock->AsyncTick(std::bind(&tick_handler, args::_1, sock));
}

void handler1(const bs::error_code &ec, bs::error_code *out_ec) {
  *out_ec = ec;
}

TEST(SocketTest, BEH_Socket) {
  asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;

  Multiplexer server_multiplexer(io_service);
  // TODO(Fraser#5#): 2012-04-04 - Use random valid ports.
  ip::udp::endpoint server_endpoint(ip::address_v4::loopback(), 2000);
  ip::udp::endpoint client_endpoint(ip::address_v4::loopback(), 2001);
  ReturnCode condition = server_multiplexer.Open(server_endpoint.protocol());
  ASSERT_EQ(kSuccess, condition);

  Multiplexer client_multiplexer(io_service);
  condition = client_multiplexer.Open(client_endpoint.protocol());
  ASSERT_EQ(kSuccess, condition);

  server_multiplexer.AsyncDispatch(std::bind(&dispatch_handler, args::_1,
                                             &server_multiplexer));


  Acceptor server_acceptor(server_multiplexer);
  Socket server_socket(server_multiplexer);
  server_ec = asio::error::would_block;
  server_acceptor.AsyncAccept(server_socket, std::bind(&handler1, args::_1,
                                                       &server_ec));

  Socket client_socket(client_multiplexer);
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

  server_socket.AsyncConnect(client_endpoint, std::bind(&handler1, args::_1,
                                                        &server_ec));

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

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
