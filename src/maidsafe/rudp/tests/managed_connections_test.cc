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

#include "maidsafe/rudp/managed_connections.h"

#include <atomic>
#include <chrono>
#include <future>
#include <functional>
#include <limits>
#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/error.h"

#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/session.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace test {

namespace {

std::future<std::pair<int, std::string>> GetFuture(std::vector<NodePtr>& nodes, int x, int y) {
  return std::async([&nodes, x, y]()->std::pair<int, std::string> {
    NodeId chosen_node_id;
    EndpointPair endpoint_pair;
    NatType nat_type;
    boost::this_thread::disable_interruption disable_interruption;
    Sleep(std::chrono::milliseconds(RandomUint32() % 100));
    return std::make_pair(
        nodes[x]->managed_connections()->GetAvailableEndpoint(nodes[y]->node_id(), EndpointPair(),
                                                              endpoint_pair, nat_type),
        std::string("GetAvailableEndpoint on ") + nodes[x]->id() + " for " + nodes[y]->id());
  });
}

std::chrono::milliseconds rendezvous_connect_timeout() {
  static const std::chrono::milliseconds timeout(
    Parameters::rendezvous_connect_timeout.total_milliseconds());
  return timeout;
}

boost::chrono::milliseconds boost_rendezvous_connect_timeout() {
  static const boost::chrono::milliseconds timeout(
      Parameters::rendezvous_connect_timeout.total_milliseconds());
  return timeout;
}

}  // unnamed namespace

class ManagedConnectionsTest : public testing::Test {
 public:
  ManagedConnectionsTest()
      : node_(999),
        nodes_(),
        bootstrap_endpoints_(),
        do_nothing_on_message_([](const std::string&) {}),
        do_nothing_on_connection_lost_([](const NodeId&) {}) {}
  ~ManagedConnectionsTest() {}

 protected:
  Node node_;
  std::vector<NodePtr> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
  MessageReceivedFunctor do_nothing_on_message_;
  ConnectionLostFunctor do_nothing_on_connection_lost_;

  void BootstrapAndAdd(size_t index, NodeId& chosen_node, EndpointPair& this_endpoint_pair,
                       NatType& nat_type) {
    ASSERT_EQ(kSuccess,
              node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[index]), chosen_node));
    ASSERT_EQ(nodes_[index]->node_id(), chosen_node);
    Sleep(std::chrono::milliseconds(250));
    nodes_[index]->ResetData();

    EXPECT_EQ(kBootstrapConnectionAlreadyExists,
              node_.managed_connections()->GetAvailableEndpoint(
                  nodes_[index]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
    EndpointPair peer_endpoint_pair;
    EXPECT_EQ(kBootstrapConnectionAlreadyExists,
              nodes_[index]->managed_connections()->GetAvailableEndpoint(
                  node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
    EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

    auto peer_futures(nodes_[index]->GetFutureForMessages(1));
    auto this_node_futures(node_.GetFutureForMessages(1));
    EXPECT_EQ(kSuccess, nodes_[index]->managed_connections()->Add(
                            node_.node_id(), this_endpoint_pair, nodes_[index]->validation_data()));
    EXPECT_EQ(kSuccess, node_.managed_connections()->Add(
                            nodes_[index]->node_id(), peer_endpoint_pair, node_.validation_data()));
    ASSERT_EQ(boost::future_status::ready,
              peer_futures.wait_for(boost_rendezvous_connect_timeout()));
    auto peer_messages(peer_futures.get());
    ASSERT_EQ(boost::future_status::ready,
              this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
    auto this_node_messages(this_node_futures.get());
    ASSERT_EQ(1U, peer_messages.size());
    ASSERT_EQ(1U, this_node_messages.size());
    EXPECT_EQ(node_.validation_data(), peer_messages[0]);
    EXPECT_EQ(nodes_[index]->validation_data(), this_node_messages[0]);
  }
};

TEST_F(ManagedConnectionsTest, BEH_API_RandomSizeSetup) {
  int nodes(8 + RandomUint32() % 16);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, nodes));
}

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap) {
  // All invalid
  NatType nat_type(NatType::kUnknown);
  NodeId chosen_bootstrap;
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(
                std::vector<Endpoint>(), MessageReceivedFunctor(), ConnectionLostFunctor(),
                NodeId(), nullptr, nullptr, chosen_bootstrap, nat_type));
  // Empty bootstrap_endpoints
  EXPECT_EQ(kNoBootstrapEndpoints,
            node_.managed_connections()->Bootstrap(std::vector<Endpoint>(), do_nothing_on_message_,
                                                   do_nothing_on_connection_lost_, node_.node_id(),
                                                   node_.private_key(), node_.public_key(),
                                                   chosen_bootstrap, nat_type));
  // FIXME
  // Unavailable bootstrap_endpoints
  EXPECT_EQ(kTransportStartFailure,
            node_.managed_connections()->Bootstrap(
                std::vector<Endpoint>(1, Endpoint(GetLocalIp(), 10000)), do_nothing_on_message_,
                do_nothing_on_connection_lost_, node_.node_id(), node_.private_key(),
                node_.public_key(), chosen_bootstrap, nat_type));
  // Invalid MessageReceivedFunctor
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(bootstrap_endpoints_, MessageReceivedFunctor(),
                                                   do_nothing_on_connection_lost_, node_.node_id(),
                                                   node_.private_key(), node_.public_key(),
                                                   chosen_bootstrap, nat_type));
  // Invalid ConnectionLostFunctor
  EXPECT_EQ(kInvalidParameter, node_.managed_connections()->Bootstrap(
                                   bootstrap_endpoints_, do_nothing_on_message_,
                                   ConnectionLostFunctor(), node_.node_id(), node_.private_key(),
                                   node_.public_key(), chosen_bootstrap, nat_type));
  // Invalid private key
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), std::shared_ptr<asymm::PrivateKey>(new asymm::PrivateKey),
                node_.public_key(), chosen_bootstrap, nat_type));
  // Invalid public key
  EXPECT_EQ(
      kInvalidParameter,
      node_.managed_connections()->Bootstrap(
          bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
          node_.node_id(), node_.private_key(),
          std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey), chosen_bootstrap, nat_type));
  // NULL private key
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), nullptr, node_.public_key(), chosen_bootstrap, nat_type));
  // NULL public key
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), node_.private_key(), nullptr, chosen_bootstrap, nat_type));
  // Valid
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Bootstrap(
                          bootstrap_endpoints_, do_nothing_on_message_,
                          do_nothing_on_connection_lost_, node_.node_id(), node_.private_key(),
                          node_.public_key(), chosen_bootstrap, nat_type));
  EXPECT_FALSE(chosen_bootstrap.IsZero());
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  //  Before Bootstrapping
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(NodeId::kRandomId), EndpointPair(), this_endpoint_pair, nat_type));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EndpointPair endpoint_pair;
  endpoint_pair.local = endpoint_pair.external =
      Endpoint(ip::address::from_string("1.2.3.4"), 1026);
  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(NodeId::kRandomId), endpoint_pair, this_endpoint_pair, nat_type));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  //  After Bootstrapping
  NodeId chosen_node;
  nat_type = NatType::kUnknown;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), node_.private_key(), node_.public_key(), chosen_node, nat_type));
  EXPECT_FALSE(chosen_node.IsZero());
  //  EXPECT_NE(bootstrap_endpoints_.end(),
  //            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(),
  // chosen_endpoint));

  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(chosen_node, EndpointPair(),
                                                              this_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));

  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(NodeId::kRandomId), EndpointPair(), another_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(another_endpoint_pair.local));
  EXPECT_NE(this_endpoint_pair.local, another_endpoint_pair.local);
}

TEST_F(ManagedConnectionsTest, BEH_API_PendingConnectionsPruning) {
  const int kNodeCount(8);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, kNodeCount));

  std::string message("message1");
  NodeId chosen_node;
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  BootstrapAndAdd(0, chosen_node, this_endpoint_pair, nat_type);

  // Run GetAvailableEndpoint to add elements to pendings_.
  for (int i(1); i != kNodeCount; ++i) {
    EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                            nodes_[i]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
  }

  // Wait for rendezvous_connect_timeout + 500ms to clear the pendings, which should allow for
  // further GetAvailableEndpoint calls to be made. Intermediate calls should return with
  // kConnectAttemptAlreadyRunning.
  EndpointPair test_endpoint_pair;
  for (int i(1); i != kNodeCount; ++i) {
    EXPECT_EQ(kConnectAttemptAlreadyRunning,
              node_.managed_connections()->GetAvailableEndpoint(
                  nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
    EXPECT_EQ(this_endpoint_pair.external, test_endpoint_pair.external);
    EXPECT_EQ(this_endpoint_pair.local, test_endpoint_pair.local);
  }

  Sleep(rendezvous_connect_timeout() / 2);

  // Remove one from the pendings_ by calling Add to complete making the connection.
  const int kSelected((RandomUint32() % (kNodeCount - 1)) + 1);
  EndpointPair peer_endpoint_pair;
  EXPECT_EQ(kSuccess, nodes_[kSelected]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  EXPECT_EQ(kSuccess,
            nodes_[kSelected]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                          nodes_[kSelected]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(nodes_[kSelected]->node_id(), peer_endpoint_pair,
                                             node_.validation_data()));

  for (int i(1); i != kNodeCount; ++i) {
    if (i != kSelected) {
      EXPECT_EQ(kConnectAttemptAlreadyRunning,
                node_.managed_connections()->GetAvailableEndpoint(
                    nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
      EXPECT_EQ(this_endpoint_pair.external, test_endpoint_pair.external);
      EXPECT_EQ(this_endpoint_pair.local, test_endpoint_pair.local);
    }
  }

  Sleep(rendezvous_connect_timeout() / 2 + std::chrono::milliseconds(500));

  for (int i(1); i != kNodeCount; ++i) {
    EXPECT_EQ((i == kSelected ? kUnvalidatedConnectionAlreadyExists : kSuccess),
              node_.managed_connections()->GetAvailableEndpoint(
                  nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
  }
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Valid bootstrap
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  EXPECT_FALSE(chosen_node.IsZero());
  Sleep(std::chrono::milliseconds(250));

  nodes_[0]->ResetData();
  EndpointPair peer_endpoint_pair0, peer_endpoint_pair2, this_endpoint_pair0, this_endpoint_pair1,
      this_endpoint_pair2;
  NatType nat_type0(NatType::kUnknown), nat_type1(NatType::kUnknown);
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(), EndpointPair(),
                                                              this_endpoint_pair0, nat_type1));
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(
                node_.node_id(), this_endpoint_pair0, peer_endpoint_pair0, nat_type0));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair0.local));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair0.local));

  // Case: Own NodeId
  EXPECT_EQ(kOwnId, node_.managed_connections()->Add(node_.node_id(), EndpointPair(),
                                                     node_.validation_data()));
  // Case: Empty endpoint
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(), EndpointPair(),
                                                       node_.validation_data()));
  auto this_node_futures(node_.GetFutureForMessages(1));
  ASSERT_NE(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));

  // Case: Non-existent endpoint
  EndpointPair random_peer_endpoint;
  random_peer_endpoint.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  random_peer_endpoint.external = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());

  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair1, nat_type1));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), random_peer_endpoint,
                                                       node_.validation_data()));
  this_node_futures = node_.GetFutureForMessages(1);
  ASSERT_NE(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));

  // Case: Success
  node_.ResetData();
  nodes_[2]->ResetData();
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[2]->node_id(), EndpointPair(), this_endpoint_pair2, nat_type1));
  EXPECT_EQ(kSuccess, nodes_[2]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair2, peer_endpoint_pair2, nat_type0));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair2.local));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair2.local));
  auto peer_futures(nodes_[2]->GetFutureForMessages(1));
  this_node_futures = node_.GetFutureForMessages(1);
  EXPECT_EQ(kSuccess, nodes_[2]->managed_connections()->Add(node_.node_id(), this_endpoint_pair2,
                                                            nodes_[2]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[2]->node_id(), peer_endpoint_pair2,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  EXPECT_EQ(1, peer_messages.size());
  EXPECT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[2]->validation_data(), this_node_messages[0]);
}

void DispatchHandler(const boost::system::error_code& ec,
                     std::shared_ptr<detail::Multiplexer> muxer) {
  if (!ec)
    muxer->AsyncDispatch(std::bind(&DispatchHandler, args::_1, muxer));
}

void TickHandler(const boost::system::error_code& ec, detail::Socket* sock) {
  if (!ec)
    sock->AsyncTick(std::bind(&TickHandler, args::_1, sock));
}

TEST_F(ManagedConnectionsTest, BEH_API_AddDuplicateBootstrap) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  // Bootstrap node_ off nodes_[0]
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  EXPECT_FALSE(chosen_node.IsZero());
  Sleep(std::chrono::milliseconds(250));

  nodes_[0]->ResetData();
  EndpointPair peer_endpoint_pair, this_endpoint_pair;
  NatType this_nat_type(NatType::kUnknown), peer_nat_type(NatType::kUnknown);

  // Connect node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, this_nat_type));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, peer_nat_type));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  EXPECT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  EXPECT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  EXPECT_EQ(1, peer_messages.size());
  EXPECT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Start new Socket with nodes_[1]'s details
  asio::io_service io_service;
  boost::system::error_code error_code(asio::error::would_block);
  ip::udp::endpoint endpoint(peer_endpoint_pair.local.address(), maidsafe::test::GetRandomPort());
  std::shared_ptr<detail::Multiplexer> multiplexer(new detail::Multiplexer(io_service));
  detail::ConnectionManager connection_manager(std::shared_ptr<detail::Transport>(),
                                               asio::io_service::strand(io_service), multiplexer,
                                               nodes_[1]->node_id(), nodes_[1]->public_key());
  ASSERT_EQ(kSuccess, multiplexer->Open(endpoint));

  multiplexer->AsyncDispatch(std::bind(&DispatchHandler, args::_1, multiplexer));

  detail::Socket socket(*multiplexer, peer_nat_type);
  auto on_nat_detection_requested_slot([](
      const boost::asio::ip::udp::endpoint & /*this_local_endpoint*/, const NodeId & /*peer_id*/,
      const boost::asio::ip::udp::endpoint & /*peer_endpoint*/,
      uint16_t & /*another_external_port*/) {});

  // Try to connect in kBootstrapAndKeep mode to node_'s existing connected Transport.
  socket.AsyncConnect(nodes_[1]->node_id(), nodes_[1]->public_key(), this_endpoint_pair.local,
                      node_.node_id(),
                      [&error_code](const boost::system::error_code & ec) { error_code = ec; },
                      detail::Session::kBootstrapAndKeep, on_nat_detection_requested_slot);

  auto future(std::async(std::launch::async, [&io_service]() { io_service.run_one(); }));
  Sleep(std::chrono::milliseconds(500));
  EXPECT_FALSE(socket.IsConnected());
  socket.Close();
  future.get();
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 4));
  auto wait_for_signals([&](int node_index, unsigned active_connection_count)->bool {
    int count(0);
    do {
      Sleep(std::chrono::milliseconds(100));
      ++count;
    } while ((node_.connection_lost_node_ids().empty() ||
              nodes_[node_index]->connection_lost_node_ids().empty() ||
              node_.managed_connections()->GetActiveConnectionCount() !=
              active_connection_count) && count != 10);
    return (!node_.connection_lost_node_ids().empty() &&
            !nodes_[node_index]->connection_lost_node_ids().empty());
  });

  // Before Bootstrap
  node_.managed_connections()->Remove(nodes_[1]->node_id());
  ASSERT_TRUE(node_.connection_lost_node_ids().empty());

  // Before Add
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[1]), chosen_node));
  EXPECT_EQ(nodes_[1]->node_id(), chosen_node);
  for (unsigned count(0);
       nodes_[1]->managed_connections()->GetActiveConnectionCount() < 4 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));
  EXPECT_EQ(nodes_[1]->managed_connections()->GetActiveConnectionCount(), 4);

  node_.managed_connections()->Remove(chosen_node);
  ASSERT_TRUE(wait_for_signals(1, 3));
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[1]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(chosen_node, node_.connection_lost_node_ids()[0]);
  EXPECT_EQ(nodes_[1]->managed_connections()->GetActiveConnectionCount(), 3);

  // After Add
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  nodes_[0]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  Sleep(std::chrono::milliseconds(250));
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(chosen_node, EndpointPair(),
                                                              this_endpoint_pair, nat_type));
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(
                node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[0]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->validation_data(), this_node_messages[0]);
  nodes_[0]->ResetData();

  // Invalid NodeId
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(NodeId());
  ASSERT_FALSE(wait_for_signals(0, 4));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 4);
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());

  // Unknown endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[2]->node_id());
  ASSERT_FALSE(wait_for_signals(2, 3));
  EXPECT_EQ(nodes_[2]->managed_connections()->GetActiveConnectionCount(), 3);
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[2]->connection_lost_node_ids().empty());

  // Valid
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[0]->node_id());
  ASSERT_TRUE(wait_for_signals(0, 3));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 3);
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());
  EXPECT_EQ(nodes_[0]->connection_lost_node_ids()[0], node_.node_id());

  // Already removed endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[0]->node_id());
  ASSERT_FALSE(wait_for_signals(0, 3));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 3);
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());
}

TEST_F(ManagedConnectionsTest, BEH_API_SimpleSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  for (unsigned count(0);
       nodes_[0]->managed_connections()->GetActiveConnectionCount() < 2 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 2);

  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  node_.ResetData();
  nodes_[1]->ResetData();
  static const int kRepeatCount = 10;
  std::atomic<int> result_arrived_count(0);
  std::atomic<int> result_of_send(kSuccess);
  std::promise<void> done_out;
  auto done_in = done_out.get_future();
  MessageSentFunctor message_sent_functor([&](int result_in) {
    if (result_in != kSuccess)
      result_of_send = result_in;
    if (kRepeatCount == ++result_arrived_count)
      done_out.set_value();
  });
  peer_futures = nodes_[1]->GetFutureForMessages(kRepeatCount);
  const std::string kMessage(RandomAlphaNumericString(256 * 1024));
  for (int i(0); i != kRepeatCount; ++i)
    node_.managed_connections()->Send(nodes_[1]->node_id(), kMessage, message_sent_functor);

  ASSERT_TRUE(std::future_status::timeout != done_in.wait_for(std::chrono::seconds(60)));
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost::chrono::minutes(2)));
  peer_messages = peer_futures.get();
  ASSERT_EQ(static_cast<size_t>(kRepeatCount), peer_messages.size());
  for (auto peer_message : peer_messages)
    EXPECT_EQ(kMessage, peer_message);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ManyTimesSimpleSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  for (unsigned count(0);
       nodes_[0]->managed_connections()->GetActiveConnectionCount() < 2 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 2);

  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  node_.ResetData();
  nodes_[1]->ResetData();
  static int kRepeatCount = 10000;
#if defined(__has_feature)
# if __has_feature(thread_sanitizer)
  // 2014-04-03 ned: Looks like above this we run into hard buffer limits in tsan
  kRepeatCount = 1024;
# endif
#endif
  std::atomic<int> result_arrived_count(0);
  std::atomic<int> result_of_send(kSuccess);
  std::promise<void> done_out;
  auto done_in = done_out.get_future();
  MessageSentFunctor message_sent_functor([&](int result_in) {
    if (result_in != kSuccess)
      result_of_send = result_in;
    if (kRepeatCount == ++result_arrived_count)
      done_out.set_value();
  });
  peer_futures = nodes_[1]->GetFutureForMessages(kRepeatCount);
  const std::string kMessage(RandomAlphaNumericString(1024));
  for (int i(0); i != kRepeatCount; ++i)
    node_.managed_connections()->Send(nodes_[1]->node_id(), kMessage, message_sent_functor);

  ASSERT_TRUE(std::future_status::timeout != done_in.wait_for(std::chrono::seconds(500)))
    << result_arrived_count << " - " << kRepeatCount;
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost::chrono::minutes(2)));
  peer_messages = peer_futures.get();
  ASSERT_EQ(static_cast<size_t>(kRepeatCount), peer_messages.size());
  for (auto peer_message : peer_messages)
    EXPECT_EQ(kMessage, peer_message);
}

TEST_F(ManagedConnectionsTest, FUNC_API_Send) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Before Bootstrap
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message1", MessageSentFunctor());
  int result_of_send(kSuccess);
  std::atomic<bool> result_arrived(false);
  std::promise<int> result_out;
  MessageSentFunctor message_sent_functor([&](int result_in) {
    result_arrived = true;
    result_out.set_value(result_in);
  });
  // MSVC won't accept lambdas with defaulted arguments, so long way round ...
  auto wait_for_result([&]()->bool {
    auto result_in = result_out.get_future();
    return std::future_status::timeout != result_in.wait_for(std::chrono::milliseconds(1000))
           && (result_of_send = result_in.get(), result_arrived);
  });
  auto wait_for_result_timed([&](int wait)->bool {
    auto result_in = result_out.get_future();
    return std::future_status::timeout != result_in.wait_for(std::chrono::milliseconds(wait))
           && (result_of_send = result_in.get(), result_arrived);
  });

  result_of_send = kSuccess;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message2", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Before Add
  // Sending to bootstrap peer should succeed, sending to any other should fail.
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  // Send to non-bootstrap peer
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message3", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message4", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
  // Send to bootstrap peer
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(2));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message5", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message6", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(200)));
  auto messages(future_messages_at_peer.get());
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message5"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message6"));

  // After Add
  nodes_[1]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Unavailable node id
  node_.ResetData();
  nodes_[1]->ResetData();
  node_.managed_connections()->Send(NodeId(NodeId::kRandomId), "message7", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(NodeId(NodeId::kRandomId), "message8", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid Send from node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = nodes_[1]->GetFutureForMessages(2);
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message9", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message10", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message9"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message10"));

  // Valid Send from nodes_[1] to node_
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(2);
  nodes_[1]->managed_connections()->Send(node_.node_id(), "message11", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  result_out = std::promise<int>();
  nodes_[1]->managed_connections()->Send(node_.node_id(), "message12", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message11"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message12"));

  // After Remove
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[0]->node_id());
  int count(0);
  do {
    Sleep(std::chrono::milliseconds(100));
    ++count;
  } while (
      (node_.connection_lost_node_ids().empty() ||
       nodes_[0]->connection_lost_node_ids().empty() ||
       node_.managed_connections()->GetActiveConnectionCount() != 2) &&
      count != 10);
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 2);
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());

  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message13", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  result_out = std::promise<int>();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message14", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid large message
  node_.ResetData();
  nodes_[1]->ResetData();
  std::string sent_message(RandomString(ManagedConnections::kMaxMessageSize()));
  future_messages_at_peer = node_.GetFutureForMessages(1);
  result_of_send = kConnectError;
  result_arrived = false;
  result_out = std::promise<int>();
  nodes_[1]->managed_connections()->Send(node_.node_id(), sent_message, message_sent_functor);
  ASSERT_TRUE(wait_for_result_timed(20000));
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(20)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(sent_message, messages[0]);

  // Excessively large message
  node_.ResetData();
  nodes_[1]->ResetData();
  sent_message += "1";
  result_of_send = kSuccess;
  result_arrived = false;
  result_out = std::promise<int>();
  nodes_[1]->managed_connections()->Send(node_.node_id(), sent_message, message_sent_functor);
  ASSERT_TRUE(wait_for_result_timed(10000));
  EXPECT_EQ(kMessageTooLarge, result_of_send);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ParallelSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  // Bootstrap off nodes_[0]
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);

  // Connect node_ to nodes_[1]
  nodes_[1]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                            nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto peer_messages(peer_futures.get());
  ASSERT_EQ(boost::future_status::ready,
            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Prepare to send
  node_.ResetData();
  nodes_[1]->ResetData();
  const int kMessageCount(10);
  ASSERT_LE(kMessageCount, std::numeric_limits<int8_t>::max());
  auto future_messages_at_peer(nodes_[1]->GetFutureForMessages(kMessageCount));
  std::vector<std::string> sent_messages;
  for (int8_t i(0); i != kMessageCount; ++i)
    sent_messages.push_back(std::string(256 * 1024, 'A' + i));
  std::atomic<int> result_arrived_count(0);
  std::atomic<int> result_of_send(kSuccess);
  std::promise<void> done_out;
  auto done_in = done_out.get_future();
  MessageSentFunctor message_sent_functor([&](int result_in) {
    if (result_in != kSuccess)
      result_of_send = result_in;
    if (kMessageCount == ++result_arrived_count)
      done_out.set_value();
  });

  // Send and assess results
  for (int i(0); i != kMessageCount; ++i) {
    node_.managed_connections()->Send(nodes_[1]->node_id(), sent_messages[i], message_sent_functor);
  }
  ASSERT_TRUE(std::future_status::timeout != done_in.wait_for(std::chrono::seconds(60)));
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(10 * kMessageCount)));
  auto messages(future_messages_at_peer.get());
  ASSERT_EQ(kMessageCount, messages.size());
  for (int i(0); i != kMessageCount; ++i)
    EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), sent_messages[i]));
}

TEST_F(ManagedConnectionsTest, FUNC_API_ParallelReceive) {
  const int kNetworkSize(21);
  ASSERT_LE(kNetworkSize, std::numeric_limits<int8_t>::max());
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, kNetworkSize));

  // Bootstrap off nodes_[kNetworkSize - 1]
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[kNetworkSize - 1]),
                            chosen_node));
  ASSERT_EQ(nodes_[kNetworkSize - 1]->node_id(), chosen_node);

  std::vector<NodeId> this_node_connections;
  // Connect node_ to all others
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Connecting to " + nodes_[i]->id());
    node_.ResetData();
    nodes_[i]->ResetData();
    EndpointPair this_endpoint_pair, peer_endpoint_pair;
    NatType nat_type;
    EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                            nodes_[i]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
    EXPECT_EQ(kSuccess, nodes_[i]->managed_connections()->GetAvailableEndpoint(
                            node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
    auto peer_futures(nodes_[i]->GetFutureForMessages(1));
    auto this_node_futures(node_.GetFutureForMessages(1));
    EXPECT_EQ(kSuccess, nodes_[i]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                              nodes_[i]->validation_data()));
    EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[i]->node_id(), peer_endpoint_pair,
                                                         node_.validation_data()));
    ASSERT_EQ(boost::future_status::ready,
              peer_futures.wait_for(boost_rendezvous_connect_timeout()));
    auto peer_messages(peer_futures.get());
    ASSERT_EQ(boost::future_status::ready,
              this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
    auto this_node_messages(this_node_futures.get());
    ASSERT_EQ(1U, peer_messages.size());
    ASSERT_EQ(1U, this_node_messages.size());
    EXPECT_EQ(node_.validation_data(), peer_messages[0]);
    EXPECT_EQ(nodes_[i]->validation_data(), this_node_messages[0]);
    //    this_node_connections.push_back(this_endpoint_pair.local);
  }

  // Prepare to send
  node_.ResetData();
  auto future_messages(node_.GetFutureForMessages(kNetworkSize - 1));
  std::vector<std::string> sent_messages;
  std::vector<int> result_of_sends(kNetworkSize, kConnectError);
  std::vector<MessageSentFunctor> message_sent_functors;
  std::atomic<int> result_arrived_count(0);
  std::promise<void> done_out;
  auto done_in = done_out.get_future();
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Preparing to send from " + nodes_[i]->id());
    nodes_[i]->ResetData();
    sent_messages.push_back(std::string(256 * 1024, 'A' + static_cast<int8_t>(i)));
    message_sent_functors.push_back([&, i](int result_in) mutable {
      result_of_sends[i] = result_in;
      if (kNetworkSize - 1 == ++result_arrived_count)
        done_out.set_value();
    });
  }

  auto wait_for_result([&] {
    return std::future_status::timeout != done_in.wait_for(std::chrono::seconds(20))
           && result_arrived_count == kNetworkSize - 1;
  });

  // Perform sends
  std::vector<std::thread> threads(kNetworkSize - 1);
  for (int i(0); i != kNetworkSize - 1; ++i) {
    threads[i] =
        std::move(std::thread(&ManagedConnections::Send, nodes_[i]->managed_connections().get(),
                                node_.node_id(), sent_messages[i], message_sent_functors[i]));
  }
  for (auto& thread : threads) {
    while (!thread.joinable()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    thread.join();
  }

  // Assess results
  ASSERT_TRUE(wait_for_result());
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Assessing results of sending from " + nodes_[i]->id());
    EXPECT_EQ(kSuccess, result_of_sends[i]);
  }
  ASSERT_EQ(boost::future_status::ready,
            future_messages.wait_for(boost::chrono::seconds(10 * kNetworkSize)));
  auto messages(future_messages.get());
  ASSERT_EQ(kNetworkSize - 1, messages.size());
  for (int i(0); i != kNetworkSize - 1; ++i)
    EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), sent_messages[i]));
}

TEST_F(ManagedConnectionsTest, BEH_API_BootstrapTimeout) {
  Parameters::bootstrap_connection_lifespan = bptime::seconds(6);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  EXPECT_FALSE(chosen_node.IsZero());

  // Send within bootstrap_disconnection_timeout period from node_ to nodes_[0]
  std::atomic<int> result_of_send(kConnectError);
  std::atomic<bool> result_arrived(false);
  std::promise<void> done_out;
  MessageSentFunctor message_sent_functor([&](int result_in) {
    result_of_send = result_in;
    result_arrived = true;
    done_out.set_value();
  });
  auto wait_for_result([&] {
    auto done_in = done_out.get_future();
    return std::future_status::timeout != done_in.wait_for(std::chrono::milliseconds(1000))
           && result_arrived;
  });
  node_.ResetData();
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message01", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::milliseconds(200)));
  auto messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), "message01");

  // Send within bootstrap_disconnection_timeout period from nodes_[0] to node_
  node_.ResetData();
  nodes_[0]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(1);
  result_of_send = kConnectError;
  result_arrived = false;
  done_out = std::promise<void>();
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(), EndpointPair(),
                                                              this_endpoint_pair, nat_type));
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message02", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::milliseconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), "message02");

  // Sleep for bootstrap_disconnection_timeout to allow connection to timeout and close
  node_.ResetData();
  nodes_[0]->ResetData();
  Sleep(std::chrono::milliseconds(Parameters::bootstrap_connection_lifespan.total_milliseconds()));
  int count(0);
  do {
    Sleep(std::chrono::milliseconds(100));
    ++count;
  } while (
      (node_.connection_lost_node_ids().empty() || nodes_[0]->connection_lost_node_ids().empty()) &&
      count != 10);
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());

  // Send again in both directions - expect failure
  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  done_out = std::promise<void>();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message03", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  done_out = std::promise<void>();
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message04", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ConcurrentGetAvailablesAndAdds) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  for (int node_count(2); node_count <= 10; ++node_count) {
    std::vector<NodePtr> nodes;
    for (int i(0); i != node_count; ++i) {
      nodes.push_back(std::make_shared<Node>(i));
      LOG(kInfo) << nodes[i]->id() << " has NodeId " << nodes[i]->debug_node_id();
    }

    // Set up by bootstrapping new nodes off existing 2 and calling GetAvailableEndpoint from each
    // new node to every other non-bootstrap one.
    // Test by calling Add from each new node to every other non-bootstrap then immediately calling
    // GetAvailableEndpoint again on each.
    std::vector<std::future<std::pair<int, std::string>>> get_avail_ep_futures;  // NOLINT (Fraser)
    for (int i(0); i != node_count; ++i) {
      NodeId chosen_node_id;
      ASSERT_EQ(kSuccess, nodes[i]->Bootstrap(bootstrap_endpoints_, chosen_node_id));

      EndpointPair empty_endpoint_pair, this_endpoint_pair, peer_endpoint_pair;
      NatType nat_type;
      for (int j(0); j != i; ++j) {
        EXPECT_EQ(kSuccess,
                  nodes[i]->managed_connections()->GetAvailableEndpoint(
                      nodes[j]->node_id(), empty_endpoint_pair, this_endpoint_pair, nat_type));
        EXPECT_EQ(kSuccess,
                  nodes[j]->managed_connections()->GetAvailableEndpoint(
                      nodes[i]->node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
        EXPECT_EQ(kSuccess,
                  nodes[j]->managed_connections()->Add(nodes[i]->node_id(), this_endpoint_pair,
                                                       nodes[j]->validation_data()));
        EXPECT_EQ(kSuccess,
                  nodes[i]->managed_connections()->Add(nodes[j]->node_id(), peer_endpoint_pair,
                                                       nodes[i]->validation_data()));
        get_avail_ep_futures.push_back(GetFuture(nodes, i, j));
        get_avail_ep_futures.push_back(GetFuture(nodes, j, i));
      }
    }

    for (auto& get_avail_ep_future : get_avail_ep_futures) {
      std::pair<int, std::string> result(get_avail_ep_future.get());
      if (result.first != kSuccess && result.first != kUnvalidatedConnectionAlreadyExists &&
          result.first != kConnectAttemptAlreadyRunning)
        GTEST_FAIL() << result.second << " returned " << result.first;
    }
  }
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
