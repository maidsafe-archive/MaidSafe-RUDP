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
#include <memory>
#include <vector>

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"

#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/tests/test_utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bs = boost::system;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

namespace {

const size_t kBufferSize = 256 * 1024;
const size_t kIterations = 50;

}  // unnamed namespace

void dispatch_handler(const bs::error_code& ec, std::shared_ptr<Multiplexer> muxer) {
  if (!ec)
    muxer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, muxer));
}

void tick_handler(const bs::error_code& ec, Socket* sock) {
  if (!ec)
    sock->AsyncTick(std::bind(&tick_handler, args::_1, sock));
}

void handler1(const bs::error_code& ec, bs::error_code* out_ec) {
  *out_ec = ec;
}

TEST(SocketTest, BEH_Socket) {
  asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;
  asymm::Keys server_key_pair, client_key_pair;
  asymm::GenerateKeyPair(&server_key_pair);
  asymm::GenerateKeyPair(&client_key_pair);
  std::shared_ptr<asymm::PublicKey> server_public_key(
      new asymm::PublicKey(server_key_pair.public_key));
  std::shared_ptr<asymm::PublicKey> client_public_key(
      new asymm::PublicKey(client_key_pair.public_key));

  std::shared_ptr<Multiplexer> server_multiplexer(new Multiplexer(io_service));
  ConnectionManager server_connection_manager(std::shared_ptr<Transport>(),
                                              asio::io_service::strand(io_service),
                                              server_multiplexer,
                                              std::shared_ptr<asymm::PublicKey>());
  ip::udp::endpoint server_endpoint(GetLocalIp(), maidsafe::rudp::test::GetRandomPort());
  ip::udp::endpoint client_endpoint(GetLocalIp(), maidsafe::rudp::test::GetRandomPort());
  ReturnCode condition = server_multiplexer->Open(server_endpoint);
  ASSERT_EQ(kSuccess, condition);

  std::shared_ptr<Multiplexer> client_multiplexer(new Multiplexer(io_service));
  ConnectionManager client_connection_manager(std::shared_ptr<Transport>(),
                                              asio::io_service::strand(io_service),
                                              client_multiplexer,
                                              std::shared_ptr<asymm::PublicKey>());
  condition = client_multiplexer->Open(client_endpoint);
  ASSERT_EQ(kSuccess, condition);

  server_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, server_multiplexer));

  client_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, client_multiplexer));

  NatType server_nat_type, client_nat_type;
  Socket server_socket(*server_multiplexer, server_nat_type);
  server_ec = asio::error::would_block;

  Socket client_socket(*client_multiplexer, client_nat_type);
  client_ec = asio::error::would_block;
  auto on_nat_detection_requested_slot(
      [](const boost::asio::ip::udp::endpoint& /*this_local_endpoint*/,
         const boost::asio::ip::udp::endpoint& /*peer_endpoint*/,
         uint16_t& /*another_external_port*/) {});
  client_socket.AsyncConnect(client_public_key,
                             server_endpoint,
                             std::bind(&handler1, args::_1, &client_ec),
                             Session::kNormal,
                             on_nat_detection_requested_slot);
  server_socket.AsyncConnect(server_public_key,
                             client_endpoint,
                             std::bind(&handler1, args::_1, &server_ec),
                             Session::kNormal,
                             on_nat_detection_requested_slot);

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
                             [](int) {},  // NOLINT (Fraser)
                             std::bind(&handler1, args::_1, &client_ec));

    do {
      io_service.run_one();
    } while (server_ec == asio::error::would_block || client_ec == asio::error::would_block);
    ASSERT_TRUE(!server_ec);
    ASSERT_TRUE(!client_ec);
  }

  server_ec = asio::error::would_block;
  server_socket.AsyncFlush(std::bind(&handler1, args::_1, &server_ec));

  client_ec = asio::error::would_block;
  client_socket.AsyncFlush(std::bind(&handler1, args::_1, &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block || client_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(!client_ec);
}

TEST(SocketTest, BEH_AsyncProbe) {
  asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;
  asymm::Keys server_key_pair, client_key_pair;
  asymm::GenerateKeyPair(&server_key_pair);
  asymm::GenerateKeyPair(&client_key_pair);
  std::shared_ptr<asymm::PublicKey> server_public_key(
      new asymm::PublicKey(server_key_pair.public_key));
  std::shared_ptr<asymm::PublicKey> client_public_key(
      new asymm::PublicKey(client_key_pair.public_key));

  std::shared_ptr<Multiplexer> server_multiplexer(new Multiplexer(io_service));
  ConnectionManager server_connection_manager(std::shared_ptr<Transport>(),
                                              asio::io_service::strand(io_service),
                                              server_multiplexer,
                                              std::shared_ptr<asymm::PublicKey>());
  ReturnCode result(kPendingResult);
  ip::udp::endpoint server_endpoint;
  uint8_t attempts(0);
  while ((kSuccess != result) && (attempts < 100)) {
    server_endpoint = ip::udp::endpoint(GetLocalIp(), maidsafe::rudp::test::GetRandomPort());
    result = server_multiplexer->Open(server_endpoint);
    if (kSuccess != result)
      server_multiplexer->Close();
    ++attempts;
  }
  ASSERT_EQ(kSuccess, result);

  std::shared_ptr<Multiplexer> client_multiplexer(new Multiplexer(io_service));
  ConnectionManager client_connection_manager(std::shared_ptr<Transport>(),
                                              asio::io_service::strand(io_service),
                                              client_multiplexer,
                                              std::shared_ptr<asymm::PublicKey>());
  ip::udp::endpoint client_endpoint;
  result = kPendingResult;
  attempts = 0;
  while ((kSuccess != result) && (attempts < 100)) {
    client_endpoint = ip::udp::endpoint(GetLocalIp(), maidsafe::rudp::test::GetRandomPort());
    result = client_multiplexer->Open(client_endpoint);
    if (kSuccess != result)
      client_multiplexer->Close();
    ++attempts;
  }
  ASSERT_EQ(kSuccess, result);

  server_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, server_multiplexer));
  client_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, client_multiplexer));

  NatType not_joined_client_nat_type, client_nat_type, server_nat_type;
  Socket not_joined_client_socket(*client_multiplexer, not_joined_client_nat_type);
  Socket client_socket(*client_multiplexer, client_nat_type);
  Socket server_socket(*server_multiplexer, server_nat_type);

  // Probing when not connected
  client_ec = asio::error::would_block;
  not_joined_client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  do {
    io_service.run_one();
  } while (client_ec == asio::error::would_block);
  EXPECT_EQ(asio::error::not_connected, client_ec);

  // Connecting to peer
  server_ec = asio::error::would_block;
  client_ec = asio::error::would_block;

  auto on_nat_detection_requested_slot(
      [](const boost::asio::ip::udp::endpoint& /*this_local_endpoint*/,
         const boost::asio::ip::udp::endpoint& /*peer_endpoint*/,
         uint16_t& /*another_external_port*/) {});
  client_socket.AsyncConnect(client_public_key,
                             server_endpoint,
                             std::bind(&handler1, args::_1, &client_ec),
                             Session::kNormal,
                             on_nat_detection_requested_slot);
  server_socket.AsyncConnect(server_public_key,
                             client_endpoint,
                             std::bind(&handler1, args::_1, &server_ec),
                             Session::kNormal,
                             on_nat_detection_requested_slot);

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block || client_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(server_socket.IsOpen());
  ASSERT_TRUE(!client_ec);
  ASSERT_TRUE(client_socket.IsOpen());

  server_socket.AsyncTick(std::bind(&tick_handler, args::_1, &server_socket));
  client_socket.AsyncTick(std::bind(&tick_handler, args::_1, &client_socket));
  server_ec = asio::error::would_block;
  client_ec = asio::error::would_block;
  server_socket.AsyncFlush(std::bind(&handler1, args::_1, &server_ec));
  client_socket.AsyncFlush(std::bind(&handler1, args::_1, &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == asio::error::would_block || client_ec == asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(!client_ec);

  // Both ends probing together
  client_ec = asio::error::would_block;
  server_ec = asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  server_socket.AsyncProbe(std::bind(&handler1, args::_1, &server_ec));
  do {
    io_service.run_one();
  } while (client_ec == asio::error::would_block || server_ec == asio::error::would_block);
  EXPECT_TRUE(!client_ec);
  EXPECT_TRUE(!server_ec);

  // Multiple probe
  bs::error_code client_ec_1 = asio::error::would_block;
  bs::error_code client_ec_2 = asio::error::would_block;
  bs::error_code client_ec_3 = asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_1));
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_2));
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_3));
  do {
    io_service.run_one();
  } while (client_ec_1 == asio::error::would_block ||
           client_ec_2 == asio::error::would_block||
           client_ec_3 == asio::error::would_block);
  EXPECT_EQ(asio::error::operation_aborted, client_ec_1);
  EXPECT_EQ(asio::error::operation_aborted, client_ec_2);
  EXPECT_TRUE(!client_ec_3);

  // Probing when peer shuts down
  server_socket.Close();
  client_ec = asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  do {
    io_service.run_one();
  } while (client_ec == asio::error::would_block);
  EXPECT_EQ(asio::error::shut_down, client_ec);

  server_multiplexer->Close();
  client_multiplexer->Close();
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
