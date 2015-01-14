/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include <functional>
#include <memory>
#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/test.h"

#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"
#include "maidsafe/rudp/tests/test_utils.h"

namespace ip = boost::asio::ip;
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

void handler1(const bs::error_code& ec, bs::error_code* out_ec) { *out_ec = ec; }

TEST(SocketTest, BEH_Socket) {
  using Endpoint = ip::udp::endpoint;

  boost::asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;
  NodeId server_node_id(RandomString(NodeId::kSize)), client_node_id(RandomString(NodeId::kSize));
  asymm::Keys server_key_pair(asymm::GenerateKeyPair()), client_key_pair(asymm::GenerateKeyPair());
  std::shared_ptr<asymm::PublicKey> server_public_key(
      std::make_shared<asymm::PublicKey>(server_key_pair.public_key));
  std::shared_ptr<asymm::PublicKey> client_public_key(
      std::make_shared<asymm::PublicKey>(client_key_pair.public_key));

  std::shared_ptr<Multiplexer> server_multiplexer(new Multiplexer(io_service));
  ConnectionManager server_connection_manager(
      std::shared_ptr<Transport>(), boost::asio::io_service::strand(io_service), server_multiplexer,
      server_node_id, std::shared_ptr<asymm::PublicKey>());
  ReturnCode condition = server_multiplexer->Open(Endpoint(AsioToBoostAsio(GetLocalIp()), 0));
  ASSERT_EQ(kSuccess, condition);
  auto server_endpoint = server_multiplexer->local_endpoint();

  std::shared_ptr<Multiplexer> client_multiplexer(new Multiplexer(io_service));
  ConnectionManager client_connection_manager(
      std::shared_ptr<Transport>(), boost::asio::io_service::strand(io_service), client_multiplexer,
      client_node_id, std::shared_ptr<asymm::PublicKey>());
  condition = client_multiplexer->Open(Endpoint(AsioToBoostAsio(GetLocalIp()), 0));
  ASSERT_EQ(kSuccess, condition);
  auto client_endpoint = client_multiplexer->local_endpoint();

  server_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, server_multiplexer));

  client_multiplexer->AsyncDispatch(std::bind(&dispatch_handler, args::_1, client_multiplexer));

  NatType server_nat_type = NatType::kUnknown, client_nat_type = NatType::kUnknown;
  Socket server_socket(*server_multiplexer, server_nat_type);
  server_ec = boost::asio::error::would_block;

  Socket client_socket(*client_multiplexer, client_nat_type);
  client_ec = boost::asio::error::would_block;
  auto on_nat_detection_requested_slot([](
      const Endpoint & /*this_local_endpoint*/, const NodeId & /*peer_id*/,
      const Endpoint & /*peer_endpoint*/,
      uint16_t & /*another_external_port*/) {});
  client_socket.AsyncConnect(client_node_id, client_public_key, server_endpoint, server_node_id,
                             std::bind(&handler1, args::_1, &client_ec), Session::kNormal, 0,
                             on_nat_detection_requested_slot);
  server_socket.AsyncConnect(server_node_id, server_public_key, client_endpoint, client_node_id,
                             std::bind(&handler1, args::_1, &server_ec), Session::kNormal, 0,
                             on_nat_detection_requested_slot);

  do {
    io_service.run_one();
  } while (server_ec == boost::asio::error::would_block ||
           client_ec == boost::asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(server_socket.IsOpen());
  ASSERT_TRUE(!client_ec);
  ASSERT_TRUE(client_socket.IsOpen());

  server_socket.AsyncTick(std::bind(&tick_handler, args::_1, &server_socket));

  client_socket.AsyncTick(std::bind(&tick_handler, args::_1, &client_socket));

  for (size_t i = 0; i < kIterations; ++i) {
    std::vector<unsigned char> server_buffer(kBufferSize);
    server_ec = boost::asio::error::would_block;
    server_socket.AsyncRead(boost::asio::buffer(server_buffer), kBufferSize,
                            std::bind(&handler1, args::_1, &server_ec));

    std::vector<unsigned char> client_buffer(kBufferSize, 'A');
    client_ec = boost::asio::error::would_block;
    client_socket.AsyncWrite(boost::asio::buffer(client_buffer), [](int) {},  // NOLINT (Fraser)
                             std::bind(&handler1, args::_1, &client_ec));

    do {
      io_service.run_one();
    } while (server_ec == boost::asio::error::would_block ||
             client_ec == boost::asio::error::would_block);
    ASSERT_TRUE(!server_ec);
    ASSERT_TRUE(!client_ec);
  }

  server_ec = boost::asio::error::would_block;
  server_socket.AsyncFlush(std::bind(&handler1, args::_1, &server_ec));

  client_ec = boost::asio::error::would_block;
  client_socket.AsyncFlush(std::bind(&handler1, args::_1, &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == boost::asio::error::would_block ||
           client_ec == boost::asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(!client_ec);
}

TEST(SocketTest, BEH_AsyncProbe) {
  using Endpoint = ip::udp::endpoint;

  boost::asio::io_service io_service;
  bs::error_code server_ec;
  bs::error_code client_ec;
  asymm::Keys server_key_pair(asymm::GenerateKeyPair()), client_key_pair(asymm::GenerateKeyPair());
  NodeId server_node_id(RandomString(NodeId::kSize)), client_node_id(RandomString(NodeId::kSize));
  std::shared_ptr<asymm::PublicKey> server_public_key(
      std::make_shared<asymm::PublicKey>(server_key_pair.public_key));
  std::shared_ptr<asymm::PublicKey> client_public_key(
      std::make_shared<asymm::PublicKey>(client_key_pair.public_key));

  std::shared_ptr<Multiplexer> server_multiplexer(new Multiplexer(io_service));
  ConnectionManager server_connection_manager(
      std::shared_ptr<Transport>(), boost::asio::io_service::strand(io_service), server_multiplexer,
      server_node_id, std::shared_ptr<asymm::PublicKey>());
  ReturnCode result(kPendingResult);
  Endpoint server_endpoint;
  uint8_t attempts(0);
  while ((kSuccess != result) && (attempts < 100)) {
    result = server_multiplexer->Open(Endpoint(AsioToBoostAsio(GetLocalIp()), 0));
    server_endpoint = server_multiplexer->local_endpoint();
    if (kSuccess != result)
      server_multiplexer->Close();
    ++attempts;
  }
  ASSERT_EQ(kSuccess, result);

  std::shared_ptr<Multiplexer> client_multiplexer(new Multiplexer(io_service));
  ConnectionManager client_connection_manager(
      std::shared_ptr<Transport>(), boost::asio::io_service::strand(io_service), client_multiplexer,
      client_node_id, std::shared_ptr<asymm::PublicKey>());
  Endpoint client_endpoint;
  result = kPendingResult;
  attempts = 0;
  while ((kSuccess != result) && (attempts < 100)) {
    result = client_multiplexer->Open(Endpoint(AsioToBoostAsio(GetLocalIp()), 0));
    client_endpoint = client_multiplexer->local_endpoint();
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
  client_ec = boost::asio::error::would_block;
  not_joined_client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  do {
    io_service.run_one();
  } while (client_ec == boost::asio::error::would_block);
  EXPECT_EQ(boost::asio::error::not_connected, client_ec);

  // Connecting to peer
  server_ec = boost::asio::error::would_block;
  client_ec = boost::asio::error::would_block;

  auto on_nat_detection_requested_slot([](
      const Endpoint & /*this_local_endpoint*/, const NodeId & /*peer_id*/,
      const Endpoint & /*peer_endpoint*/,
      uint16_t & /*another_external_port*/) {});
  client_socket.AsyncConnect(client_node_id, client_public_key, server_endpoint, server_node_id,
                             std::bind(&handler1, args::_1, &client_ec), Session::kNormal, 0,
                             on_nat_detection_requested_slot);
  server_socket.AsyncConnect(server_node_id, server_public_key, client_endpoint, client_node_id,
                             std::bind(&handler1, args::_1, &server_ec), Session::kNormal, 0,
                             on_nat_detection_requested_slot);

  do {
    io_service.run_one();
  } while (server_ec == boost::asio::error::would_block ||
           client_ec == boost::asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(server_socket.IsOpen());
  ASSERT_TRUE(!client_ec);
  ASSERT_TRUE(client_socket.IsOpen());

  server_socket.AsyncTick(std::bind(&tick_handler, args::_1, &server_socket));
  client_socket.AsyncTick(std::bind(&tick_handler, args::_1, &client_socket));
  server_ec = boost::asio::error::would_block;
  client_ec = boost::asio::error::would_block;
  server_socket.AsyncFlush(std::bind(&handler1, args::_1, &server_ec));
  client_socket.AsyncFlush(std::bind(&handler1, args::_1, &client_ec));

  do {
    io_service.run_one();
  } while (server_ec == boost::asio::error::would_block ||
           client_ec == boost::asio::error::would_block);
  ASSERT_TRUE(!server_ec);
  ASSERT_TRUE(!client_ec);

  // Both ends probing together
  client_ec = boost::asio::error::would_block;
  server_ec = boost::asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  server_socket.AsyncProbe(std::bind(&handler1, args::_1, &server_ec));
  do {
    io_service.run_one();
  } while (client_ec == boost::asio::error::would_block ||
           server_ec == boost::asio::error::would_block);
  EXPECT_TRUE(!client_ec);
  EXPECT_TRUE(!server_ec);

  // Multiple probe
  bs::error_code client_ec_1 = boost::asio::error::would_block;
  bs::error_code client_ec_2 = boost::asio::error::would_block;
  bs::error_code client_ec_3 = boost::asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_1));
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_2));
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec_3));
  do {
    io_service.run_one();
  } while (client_ec_1 == boost::asio::error::would_block ||
           client_ec_2 == boost::asio::error::would_block ||
           client_ec_3 == boost::asio::error::would_block);
  EXPECT_EQ(boost::asio::error::operation_aborted, client_ec_1);
  EXPECT_EQ(boost::asio::error::operation_aborted, client_ec_2);
  EXPECT_TRUE(!client_ec_3);

  // Probing when peer shuts down
  server_socket.Close();
  client_ec = boost::asio::error::would_block;
  client_socket.AsyncProbe(std::bind(&handler1, args::_1, &client_ec));
  do {
    io_service.run_one();
  } while (client_ec == boost::asio::error::would_block);
  EXPECT_EQ(boost::asio::error::shut_down, client_ec);

  server_multiplexer->Close();
  client_multiplexer->Close();
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
