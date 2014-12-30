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

#ifndef WIN32
extern "C" char** environ;
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4127)  // conditional expression is constant
#pragma warning(disable : 4267)  // conversion of size_t to int (Boost.Process bug)
#pragma warning(disable : 4702)  // unreachable code
#endif
#include "boost/process.hpp"
#include "boost/iostreams/stream.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#ifndef WIN32
#include "boost/asio/posix/stream_descriptor.hpp"
#endif

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/make_unique.h"

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
  return std::async([&nodes, x, y ]() -> std::pair<int, std::string> {
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
#ifndef MAIDSAFE_APPLE
        do_nothing_on_connection_lost_([](const NodeId&) {}) {
  }
#else
        do_nothing_on_connection_lost_([](const NodeId&) {}),
        rlimit_() {
    SetNumberOfOpenFiles(2048);
  }
#endif

  ~ManagedConnectionsTest() {
#ifdef MAIDSAFE_APPLE
    setrlimit(RLIMIT_NOFILE, &rlimit_);
#endif
  }

 protected:
  Node node_;
  std::vector<NodePtr> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
  MessageReceivedFunctor do_nothing_on_message_;
  ConnectionLostFunctor do_nothing_on_connection_lost_;

#ifdef MAIDSAFE_APPLE
  struct rlimit rlimit_;

  void SetNumberOfOpenFiles(unsigned int open_files) {
    getrlimit(RLIMIT_NOFILE, &rlimit_);
    if (rlimit_.rlim_cur >= open_files)
      return;

    struct rlimit limit;
    limit.rlim_cur = open_files;
    limit.rlim_max = open_files;
    setrlimit(RLIMIT_NOFILE, &limit);
  }
#endif

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

TEST_F(ManagedConnectionsTest, BEH_API_kBootstrapConnectionAlreadyExists) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
  NodeId chosen_node;
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  size_t index(1);

  using lock_guard = std::lock_guard<std::mutex>;
  std::mutex mutex;
  std::promise<void> promise;
  auto future = promise.get_future();

  nodes_[index]->managed_connections()->SetConnectionAddedFunctor([&](NodeId) {
    lock_guard guard(mutex);
    promise.set_value();
  });

  ASSERT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[index]), chosen_node));

  // When the above bootstrap function finishes, the node 'node_' knows it is connected
  // to node 'nodes_[index]' but not the other way around. For that we need to
  // wait till the ConnectionAddedFunctor is executed inside node 'nodes_[index]'.
  future.wait();
  { lock_guard guard(mutex); }

  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            nodes_[index]->managed_connections()->GetAvailableEndpoint(
                node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));

  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(
                nodes_[index]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
}

TEST_F(ManagedConnectionsTest, FUNC_API_RandomSizeSetup) {
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
  // Unavailable bootstrap_endpoints
  {
    asio::io_service io_service;
    boost::asio::ip::udp::socket tmp_socket(io_service, Endpoint(GetLocalIp(), 0));
    int16_t some_used_port = tmp_socket.local_endpoint().port();

    EXPECT_NE(kSuccess, node_.managed_connections()->Bootstrap(
                            std::vector<Endpoint>(1, Endpoint(GetLocalIp(), some_used_port)),
                            do_nothing_on_message_, do_nothing_on_connection_lost_, node_.node_id(),
                            node_.private_key(), node_.public_key(), chosen_bootstrap, nat_type));
  }
  // Unavailable bootstrap_endpoints with kLivePort
  {
    // The tmp_socket opens the kLivePort to make sure no other program using RUDP
    // on this test PC is using it. Though, if some other test PC is using the port
    // already, then the test is pointless.
    asio::io_service io_service;
    boost::system::error_code ec;
    boost::asio::ip::udp::socket tmp_socket(io_service);
    tmp_socket.bind(Endpoint(GetLocalIp(), kLivePort), ec);

    if (!ec) {
      EXPECT_EQ(kTransportStartFailure,
                node_.managed_connections()->Bootstrap(
                    std::vector<Endpoint>(1, Endpoint(GetLocalIp(), kLivePort)),
                    do_nothing_on_message_, do_nothing_on_connection_lost_, node_.node_id(),
                    node_.private_key(), node_.public_key(), chosen_bootstrap, nat_type));
    }
  }

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
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), node_.private_key(),
                std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey), chosen_bootstrap,
                nat_type));
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
  EXPECT_TRUE(chosen_bootstrap.IsValid());
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  //  Before Bootstrapping
  EndpointPair this_endpoint_pair(Endpoint(ip::address::from_string("1.1.1.1"), 1025));
  NatType nat_type;

  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(RandomString(NodeId::kSize)), EndpointPair(), this_endpoint_pair, nat_type));

  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  this_endpoint_pair = EndpointPair(Endpoint(ip::address::from_string("1.1.1.1"), 1025));
  EndpointPair endpoint_pair(Endpoint(ip::address::from_string("1.2.3.4"), 1026));

  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(RandomString(NodeId::kSize)), endpoint_pair, this_endpoint_pair, nat_type));

  EXPECT_EQ(EndpointPair(), this_endpoint_pair);

  //  After Bootstrapping
  NodeId chosen_node;
  nat_type = NatType::kUnknown;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
                node_.node_id(), node_.private_key(), node_.public_key(), chosen_node, nat_type));

  EXPECT_TRUE(chosen_node.IsValid());

  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(chosen_node, EndpointPair(),
                                                              this_endpoint_pair, nat_type));

  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));

  EndpointPair another_endpoint_pair;

  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
                          NodeId(RandomString(NodeId::kSize)), EndpointPair(),
                          another_endpoint_pair, nat_type));

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
  EXPECT_TRUE(chosen_node.IsValid());
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
  EXPECT_TRUE(chosen_node.IsValid());
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
  auto on_nat_detection_requested_slot(
      [](const boost::asio::ip::udp::endpoint& /*this_local_endpoint*/, const NodeId& /*peer_id*/,
         const boost::asio::ip::udp::endpoint& /*peer_endpoint*/,
         uint16_t& /*another_external_port*/) {});

  // Try to connect in kBootstrapAndKeep mode to node_'s existing connected Transport.
  socket.AsyncConnect(nodes_[1]->node_id(), nodes_[1]->public_key(), this_endpoint_pair.local,
                      node_.node_id(),
                      [&error_code](const boost::system::error_code& ec) { error_code = ec; },
                      detail::Session::kBootstrapAndKeep, 0, on_nat_detection_requested_slot);

  auto future(std::async(std::launch::async, [&io_service]() { io_service.run_one(); }));
  Sleep(std::chrono::milliseconds(500));
  EXPECT_FALSE(socket.IsConnected());
  socket.Close();
  future.get();
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 4));
  auto wait_for_signals([&](int node_index, unsigned active_connection_count) -> bool {
    int count(0);
    do {
      Sleep(std::chrono::milliseconds(100));
      ++count;
    } while ((node_.connection_lost_node_ids().empty() ||
              nodes_[node_index]->connection_lost_node_ids().empty() ||
              node_.managed_connections()->GetActiveConnectionCount() != active_connection_count) &&
             count != 10);
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

  using lock_guard = std::lock_guard<std::mutex>;
  std::mutex mutex;

  MessageSentFunctor message_sent_functor([&](int result_in) {
    lock_guard guard(mutex);
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
  { lock_guard guard(mutex); }

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
#if __has_feature(thread_sanitizer)
  // 2014-04-03 ned: Looks like above this we run into hard buffer limits in tsan
  kRepeatCount = 1024;
#endif
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

struct FutureResult {
  struct State {
    std::promise<int> promise;
    std::future<int> future;

    State() : future(promise.get_future()) {}
  };

  std::function<void(int /* result */)> MakeContinuation() {
    _state = std::make_shared<State>();

    auto state_copy = _state;
    return [state_copy](int result) {  // NOLINT
      state_copy->promise.set_value(result);
    };
  }

  bool Wait(int millis) {
    auto duration = std::chrono::milliseconds(millis);

    if (_state->future.wait_for(duration) == std::future_status::timeout) {
      return false;
    }

    return true;
  }

  int Result() const { return _state->future.get(); }

  std::shared_ptr<State> _state;
};

TEST_F(ManagedConnectionsTest, FUNC_API_Send) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Before Bootstrap
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message1", MessageSentFunctor());
  int millis = 1000;

  FutureResult future_result;

  node_.managed_connections()->Send(nodes_[0]->node_id(), "message2",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());

  // Before Add
  // Sending to bootstrap peer should succeed, sending to any other should fail.
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);

  // Send to non-bootstrap peer
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message3", MessageSentFunctor());
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message4",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());

  // Send to bootstrap peer
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(2));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message5", MessageSentFunctor());
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message6",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kSuccess, future_result.Result());
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
  node_.managed_connections()->Send(NodeId(RandomString(NodeId::kSize)), "message7",
                                    MessageSentFunctor());
  node_.managed_connections()->Send(NodeId(RandomString(NodeId::kSize)), "message8",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());

  // Valid Send from node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = nodes_[1]->GetFutureForMessages(2);
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message9", MessageSentFunctor());
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message10",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kSuccess, future_result.Result());
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
  nodes_[1]->managed_connections()->Send(node_.node_id(), "message12",
                                         future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kSuccess, future_result.Result());
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
  } while ((node_.connection_lost_node_ids().empty() ||
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
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message14",
                                    future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());

  // Valid large message
  node_.ResetData();
  nodes_[1]->ResetData();
  std::string sent_message(RandomString(ManagedConnections::kMaxMessageSize()));
  future_messages_at_peer = node_.GetFutureForMessages(1);
  nodes_[1]->managed_connections()->Send(node_.node_id(), sent_message,
                                         future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(20000));
  EXPECT_EQ(kSuccess, future_result.Result());
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::seconds(20)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(sent_message, messages[0]);

  // Excessively large message
  node_.ResetData();
  nodes_[1]->ResetData();
  sent_message += "1";
  nodes_[1]->managed_connections()->Send(node_.node_id(), sent_message,
                                         future_result.MakeContinuation());
  ASSERT_TRUE(future_result.Wait(10000));
  EXPECT_EQ(kMessageTooLarge, future_result.Result());
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

  using lock_guard = std::lock_guard<std::mutex>;
  std::mutex mutex;

  auto done_in = done_out.get_future();
  MessageSentFunctor message_sent_functor([&](int result_in) {
    lock_guard guard(mutex);
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
  { lock_guard guard(mutex); }

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
    std::string validation_data_copy(nodes_[i]->validation_data());
    (void)validation_data_copy[0];  // workaround tsan warning (Niall)
    EXPECT_EQ(kSuccess, nodes_[i]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
                                                              validation_data_copy));
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
  std::shared_ptr<std::promise<void>> done_out = std::make_shared<std::promise<void>>();
  auto done_in = done_out->get_future();
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Preparing to send from " + nodes_[i]->id());
    nodes_[i]->ResetData();
    sent_messages.push_back(std::string(256 * 1024, 'A' + static_cast<int8_t>(i)));
    message_sent_functors.push_back([&, i, done_out](int result_in) mutable {
      result_of_sends[i] = result_in;
      if (kNetworkSize - 1 == ++result_arrived_count)
        done_out->set_value();
    });
  }

  auto wait_for_result([&] {
    return std::future_status::timeout != done_in.wait_for(std::chrono::seconds(20)) &&
           result_arrived_count == kNetworkSize - 1;
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
  EXPECT_TRUE(chosen_node.IsValid());

  FutureResult future_result;
  auto wait_millis = 1000;

  node_.ResetData();
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message01",
                                    future_result.MakeContinuation());

  ASSERT_TRUE(future_result.Wait(wait_millis));
  EXPECT_EQ(kSuccess, future_result.Result());
  ASSERT_EQ(boost::future_status::ready,
            future_messages_at_peer.wait_for(boost::chrono::milliseconds(200)));
  auto messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), "message01");

  // Send within bootstrap_disconnection_timeout period from nodes_[0] to node_
  node_.ResetData();
  nodes_[0]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(1);
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(), EndpointPair(),
                                                              this_endpoint_pair, nat_type));
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message02",
                                         future_result.MakeContinuation());

  ASSERT_TRUE(future_result.Wait(wait_millis));
  EXPECT_EQ(kSuccess, future_result.Result());
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
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message03",
                                    future_result.MakeContinuation());

  ASSERT_TRUE(future_result.Wait(wait_millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());

  node_.ResetData();
  nodes_[0]->ResetData();
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message04",
                                         future_result.MakeContinuation());

  ASSERT_TRUE(future_result.Wait(wait_millis));
  EXPECT_EQ(kInvalidConnection, future_result.Result());
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

// Unfortunately disabled on Windows as ASIO and NT refuses to work well with anonymous pipe handles
// (think win32 exception throws in the kernel, you are about right)
#ifdef WIN32
struct input_watcher {
  typedef HANDLE native_handle_type;
};
#else
struct input_watcher {
  asio::io_service& _service;
  asio::posix::stream_descriptor _h;

 public:
  typedef asio::posix::stream_descriptor::native_handle_type native_handle_type;

 private:
  asio::deadline_timer _timer;
  std::unique_ptr<asio::io_service::work> _work;
  void _init(bool doTimer) {
    _h.async_read_some(asio::null_buffers(),
                       std::bind(&input_watcher::data_available, this, std::placeholders::_1));
    if (doTimer) {
      _timer.async_wait(std::bind(&input_watcher::timed_out, this, std::placeholders::_1));
    }
  }

 protected:
  virtual void data_available(const boost::system::error_code&) = 0;
  virtual void timed_out(const boost::system::error_code&) { cancel(); };
  input_watcher(asio::io_service& service, native_handle_type h)
      : _service(service),
        _h(service, h),
        _timer(service),
        _work(maidsafe::make_unique<asio::io_service::work>(service)) {
    _init(false);
  }
  input_watcher(asio::io_service& service, native_handle_type h, boost::posix_time::ptime timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<asio::io_service::work>(service)) {
    _init(true);
  }
  input_watcher(asio::io_service& service, native_handle_type h,
                boost::posix_time::time_duration timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<asio::io_service::work>(service)) {
    _init(true);
  }

 public:
  ~input_watcher() { _h.release(); }
  asio::io_service& service() { return _service; }
  native_handle_type handle() { return _h.native(); }
  asio::deadline_timer& timer() { return _timer; }
  void cancel() {
    _h.cancel();
    _timer.cancel();
    _work.reset();
  }
};
#endif
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4706)  // assignment within conditional expression
#endif
TEST_F(ManagedConnectionsTest, FUNC_API_500ParallelConnectionsWorker) {
  const char* endpoints = std::getenv("MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS");
  if (endpoints) {
    bootstrap_endpoints_.clear();
    for (const char* s = endpoints, * e = endpoints - 1; (s = e + 1, e = strchr(s, ';'));) {
      const char* colon = strchr(s, ':');
      if (!colon || colon > e) {
        std::cout << "ERROR: Couldn't parse " << endpoints << " so exiting." << std::endl;
        abort();
      }
      bootstrap_endpoints_.push_back(boost::asio::ip::udp::endpoint(
          boost::asio::ip::address::from_string(std::string(s, colon - s)),
          static_cast<uint16_t>(atoi(colon + 1))));
      // std::cerr << "I have bootstrap endpoint " <<
      // bootstrap_endpoints_.back().address().to_string() << ":" <<
      // bootstrap_endpoints_.back().port() << std::endl;
    }
    std::string line;
    do {
      if (!std::getline(std::cin, line)) {
        std::cout << "ERROR: Couldn't read from parent so exiting." << std::endl;
        abort();
      }
    } while (line.compare(0, 8, "NODE_ID:"));
    if (line[line.size() - 1] == 13)
      line.resize(line.size() - 1);
    const size_t my_id = atoi(line.substr(9).c_str());
    Node node(static_cast<int>(my_id));
    std::cout << "NODE_ID: " << node.node_id().ToStringEncoded(NodeId::EncodingType::kHex)
              << std::endl;
    NodeId chosen_node_id, peer_node_id;
    ASSERT_EQ(kSuccess, node.Bootstrap(bootstrap_endpoints_, chosen_node_id));

    std::atomic<bool> sender_thread_done(false);
    std::mutex lock;
    asio::io_service service;
    std::vector<NodeId> peer_node_ids;
    size_t peer_node_ids_idx = 0, messages_sent = 0;
    std::thread sender_thread([&] {
      static std::string bleh(1500, 'n');
      while (!sender_thread_done) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        std::lock_guard<decltype(lock)> g(lock);
        if (peer_node_ids_idx < peer_node_ids.size()) {
          node.managed_connections()->Send(peer_node_ids[peer_node_ids_idx], bleh,
                                           [&](int) {  // NOLINT (Niall)
            std::lock_guard<decltype(lock)> g(lock);
            ++messages_sent;
          });
        }
        if (++peer_node_ids_idx >= peer_node_ids.size())
          peer_node_ids_idx = 0;
      }
    });
    try {
      for (;;) {
        if (!std::getline(std::cin, line)) {
          std::cout << "ERROR: Couldn't read from parent due to state=" << std::cin.rdstate()
                    << " so exiting." << std::endl;
          abort();
        }
        if (line[line.size() - 1] == 13)
          line.resize(line.size() - 1);
        if (!line.compare("QUIT"))
          break;
        if (!line.compare(0, 13, "ENDPOINT_FOR:")) {
          NodeId peer_node_id(line.substr(14), NodeId::EncodingType::kHex);

          EndpointPair empty_endpoint_pair, this_endpoint_pair;
          NatType nat_type;

          // std::cerr << my_id << ": Getting available endpoint for " <<
          // peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex) << std::endl;
          EXPECT_EQ(kSuccess, node.managed_connections()->GetAvailableEndpoint(
                                  peer_node_id, empty_endpoint_pair, this_endpoint_pair, nat_type));
          std::cout << "ENDPOINT: "
                    << this_endpoint_pair.local.address().to_string() + ":" +
                           std::to_string(this_endpoint_pair.local.port()) + ";"
                    << this_endpoint_pair.external.address().to_string() + ":" +
                           std::to_string(this_endpoint_pair.external.port()) + ";" << std::endl;
          // std::cerr << my_id << ": Endpoint obtained (" << this_endpoint_pair.local.port() << ")"
          // << std::endl;
        } else if (!line.compare(0, 8, "CONNECT:")) {
          const char* colon1 = strchr(line.c_str(), ';');
          if (!colon1) {
            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
            abort();
          }
          const char* colon2 = strchr(colon1 + 1, ':');
          if (!colon2) {
            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
            abort();
          }
          const char* colon3 = strchr(colon2 + 1, ';');
          if (!colon3) {
            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
            abort();
          }
          NodeId peer_node_id(std::string(line.c_str() + 9, colon1 - line.c_str() - 9),
                              NodeId::EncodingType::kHex);
          EndpointPair peer_endpoint_pair;
          peer_endpoint_pair.local = boost::asio::ip::udp::endpoint(
              boost::asio::ip::address::from_string(std::string(colon1 + 1, colon2 - colon1 - 1)),
              static_cast<uint16_t>(atoi(colon2 + 1)));
          auto fi = node.GetFutureForMessages(1);
          // std::cerr << my_id << ": Adding connection to node " <<
          // peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex)
          //          << " at endpoint " << peer_endpoint_pair.local.address().to_string()+":" <<
          //          peer_endpoint_pair.local.port()
          //          << std::endl;
          EXPECT_EQ(kSuccess, node.managed_connections()->Add(peer_node_id, peer_endpoint_pair,
                                                              node.validation_data()));
          // std::cerr << my_id << ": Waiting on future" << std::endl;
          fi.get();
          // std::cerr << my_id << ": Connected" << std::endl;
          std::cout << "CONNECTED: " << peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex)
                    << std::endl;
          std::lock_guard<decltype(lock)> g(lock);
          peer_node_ids.push_back(peer_node_id);
        } else if (!line.compare(0, 5, "STATS")) {
          std::lock_guard<decltype(lock)> g(lock);
          std::cout << "STATS: " << messages_sent << std::endl;
        }
      }
    } catch (const std::exception& e) {
      std::cout << "ERROR: Saw exception '" << e.what() << "' so exiting." << std::endl;
    }
    sender_thread_done = true;
    sender_thread.join();
  }
}
TEST_F(ManagedConnectionsTest, FUNC_API_500ParallelConnections) {
  size_t node_count = 23, messages_sent_count = 100000;
  const char* node_count_env = std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_NODE_COUNT");
  if (node_count_env)
    node_count = atoi(node_count_env);
  const char* messages_sent_count_env =
      std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_MESSAGE_COUNT");
  if (messages_sent_count_env)
    messages_sent_count = atoi(messages_sent_count_env);
  const auto self_path = ThisExecutablePath();
  typedef boost::filesystem::path::string_type native_string;
  const std::vector<native_string> args{
      self_path.native(),
#ifdef WIN32
      L"--gtest_filter=ManagedConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
#else
      "--gtest_filter=ManagedConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
#endif
  };

  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
  native_string endpoints(
#ifdef WIN32
      L"MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
#else
      "MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
#endif
  for (auto& i : bootstrap_endpoints_) {
    auto temp = i.address().to_string();
#ifdef WIN32
    endpoints.append(native_string(temp.begin(), temp.end()) + L":" + std::to_wstring(i.port()) +
                     L";");
#else
    endpoints.append(temp + ":" + std::to_string(i.port()) + ";");
#endif
  }
  std::vector<native_string> env{endpoints};
// Boost.Process won't inherit environment at the same time as do custom env,
// so manually propagate our current environment into the custom environment.
// Failure to propagate environment causes child processes to fail due to CryptoPP
// refusing to initialise.
#ifdef WIN32
  for (const TCHAR* e = GetEnvironmentStrings(); *e; e++) {
    env.push_back(e);
    while (*e != 0)
      e++;
  }
#else
  for (char** e = environ; *e; ++e)
    env.push_back(*e);
#endif
  auto getline = [](std::istream & is, input_watcher::native_handle_type h, std::string & str)
      -> std::istream & {
#ifdef WIN32
    // Unfortunately Win32 anonymous pipe handles are a very special not-entirely-working
    // form of HANDLE, indeed I personally never ever use them as named pipe handles work
    // better, albeit not without their quirks/bugs either.
    //
    // So here I'm simply going to wait on the handle with timeout. I've wasted two days on
    // debugging this already, sometimes the easy hack way is better than the right way ...
    str.clear();
    for (;;) {
      char c;
      if (is.rdbuf()->in_avail()) {
        is.get(c);
      } else {
        if (WAIT_TIMEOUT == WaitForSingleObject(h, 30000)) {
          is.setstate(std::ios::badbit);
          return is;
        }
        is.get(c);
      }
      if (c == 10)
        break;
      else
        str.push_back(c);
    }
#else
    asio::io_service service;
    str.clear();
    for (;;) {
      char c;
      if (is.rdbuf()->in_avail()) {
        is.get(c);
      } else {
        // Wait no more than ten seconds for something to turn up
        struct watcher : input_watcher {
          bool have_data;
          watcher(asio::io_service& service, input_watcher::native_handle_type h)
              : input_watcher(service, h, boost::posix_time::seconds(30)), have_data(false) {}
          virtual void data_available(const boost::system::error_code& ec) {
            if (!ec)
              have_data = true;
            cancel();
          }
        } w(service, h);
        service.run();
        if (!w.have_data) {
          is.setstate(std::ios::badbit);
          return is;
        }
        is.get(c);
      }
      if (c == 10)
        break;
      else
        str.push_back(c);
    }
#endif
    if (str[str.size() - 1] == 13)
      str.resize(str.size() - 1);
    return is;
  };

  std::vector<boost::process::child> children;
  // Try to make sure that we don't ever leave zombie child processes around
  struct child_deleter {
    void operator()(boost::iostreams::stream<boost::iostreams::file_descriptor_sink>* c) const {
      *c << "QUIT" << std::endl;
      delete c;
    }
  };
  std::vector<
      std::pair<std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>,
                std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
                                child_deleter>>> childpipes;
  children.reserve(node_count);
  childpipes.reserve(node_count);
  try {
    for (size_t n = 0; n < node_count; n++) {
      boost::system::error_code ec;
      auto childin = boost::process::create_pipe(), childout = boost::process::create_pipe();
      boost::iostreams::file_descriptor_sink sink(childin.sink, boost::iostreams::close_handle);
      boost::iostreams::file_descriptor_source source(childout.source,
                                                      boost::iostreams::close_handle);
      children.push_back(boost::process::execute(boost::process::initializers::run_exe(self_path),
                                                 boost::process::initializers::set_args(args),
                                                 boost::process::initializers::set_env(env),
                                                 boost::process::initializers::bind_stdin(source),
                                                 boost::process::initializers::bind_stdout(sink),
                                                 boost::process::initializers::set_on_error(ec)));
      if (ec) {
        GTEST_FAIL() << "Failed to launch child " << n << " due to error code " << ec << ".";
        return;
      }
      childpipes.push_back(std::make_pair(
          maidsafe::make_unique<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>(
              childin.source, boost::iostreams::never_close_handle),
          std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
                          child_deleter>(
              new boost::iostreams::stream<boost::iostreams::file_descriptor_sink>(
                  childout.sink,
                  boost::iostreams::never_close_handle))  // libstdc++ hasn't implemented the custom
                                                          // deleter implicit conversions for some
                                                          // weird reason
          ));                                             // NOLINT (Niall)
      *childpipes.back().second << "NODE_ID: " << n << std::endl;
    }
    // Prepare to connect node_count nodes to one another, making node_count*(node_count-1) total
    // connections
    std::vector<std::pair<size_t, size_t>> execution_order;
    std::vector<NodeId> child_nodeids;
    child_nodeids.reserve(node_count);
    for (size_t n = 0; n < node_count; n++) {
      boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipes[n].first;
      for (;;) {
        std::string line;
        // ASIO gets upset if the pipe isn't opened on the other side, so use getline for this round
        if (!std::getline(is, line)) {
          GTEST_FAIL() << "Failed to read from child " << n << ".";
          return;
        }
        if (line[line.size() - 1] == 13)
          line.resize(line.size() - 1);
        if (!line.compare(0, 6, "ERROR:")) {
          GTEST_FAIL() << "Failed to launch child " << n << " due to " << line << ".";
          return;
        }
        if (!line.compare(0, 8, "NODE_ID:")) {
          // std::cout << "Child " << n << " returns node id " << line.substr(9) << std::endl;
          child_nodeids.push_back(NodeId(line.substr(9), NodeId::EncodingType::kHex));
          break;
        } else if (line[0] != '[' && !strstr(line.c_str(), "Google Test filter")) {
          std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
        }
      }
      // std::cout << "Child " << n << " has node id " <<
      //  child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex) << std::endl;
      for (size_t i = 0; i < n; i++) {
        execution_order.push_back(std::make_pair(n, i));
      }
    }
    // child_nodeids[n] contains a map of child processes to NodeId
    // child_endpoints[n][i*2] is the endpoint of childprocess n to childprocess i
    // child_endpoints[n][i*2+1] is the endpoint of childprocess i to childprocess n
    std::vector<std::vector<EndpointPair>> child_endpoints;
    child_endpoints.resize(node_count);
    for (auto& i : child_endpoints)
      i.resize((node_count - 1) * 2);
    // We need execution order to maximise distance between each x,x and y,y in each (x,y) pair
    // such that concurrency is maximised. That is the CPU instruction scheduling problem which
    // requires the solution of an unbalanced graph via iterating rebalancing according to longest
    // path analysis, and it has O(N!) complexity with a non-trivial implementation. So here is a
    // poorer quality O(N^2) complexity alternative with a much simpler implementation. It doesn't
    // produce perfect ordering, but it's close enough and doesn't require more code than the whole
    // of this test case.
    {
      std::deque<std::pair<size_t, size_t>> list(std::make_move_iterator(execution_order.begin()),
                                                 std::make_move_iterator(execution_order.end())),
          prevline, line;
      execution_order.clear();
      std::reverse(list.begin(), list.end());
      do {
        prevline = std::move(line);
        // Choose a starting value as far away as possible from any collision in the previous line
        if (prevline.empty()) {
          line.push_back(std::move(list.back()));
          list.pop_back();
        } else {
          do {
            prevline.pop_front();
            for (auto it = list.begin(); it != list.end(); ++it) {
              bool bad = false;
              for (auto& b : prevline) {
                if (it->first == b.first || it->second == b.first || it->first == b.second ||
                    it->second == b.second) {
                  bad = true;
                  break;
                }
              }
              if (!bad) {
                line.push_back(std::move(*it));
                list.erase(it);
                break;
              }
            }
          } while (line.empty());
        }
        // Append all values not colliding into this line
        for (auto it = list.begin(); it != list.end();) {
          bool bad = false;
          for (auto& b : line) {
            if (it->first == b.first || it->second == b.first || it->first == b.second ||
                it->second == b.second) {
              bad = true;
              break;
            }
          }
          if (!bad) {
            line.push_back(std::move(*it));
            it = list.erase(it);
          } else {
            ++it;
          }
        }
        // Copy line into output
        execution_order.insert(execution_order.end(), line.begin(), line.end());
      } while (!list.empty());
    }
    // std::cout << "Execution order will be: ";
    // for (auto& o : execution_order)
    //   std::cout << "[" << o.first << ", " << o.second << "], ";
    // std::cout << std::endl;
    size_t connection_count = 0;
    for (auto& o : execution_order) {
      EndpointPair endpoint;
      size_t n, i;
      std::tie(n, i) = o;
      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os1 = *childpipes[n].second;
      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os2 = *childpipes[i].second;
      os1 << "ENDPOINT_FOR: " << child_nodeids[i].ToStringEncoded(NodeId::EncodingType::kHex)
          << std::endl;
      os2 << "ENDPOINT_FOR: " << child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex)
          << std::endl;
      // std::cout << "Asking child " << n << " for endpoint to child " << i << std::endl;
      // std::cout << "Asking child " << i << " for endpoint to child " << n << std::endl;
      auto drain_endpoint = [&](size_t a) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
            *childpipes[a].first;
        // std::cout << "drain_endpoint(" << a << ")" << std::endl;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            return false;
          }
          if (!line.compare(0, 9, "ENDPOINT:")) {
            bool first = true;
            for (const char* s, * e = line.c_str() + 9; (s = e + 1, e = strchr(s, ';'));
                 first = false) {
              const char* colon = strchr(s, ':');
              if (!colon || colon > e) {
                std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
                abort();
              }
              (first ? endpoint.local : endpoint.external)
                  .address(boost::asio::ip::address::from_string(std::string(s, colon - s)));
              (first ? endpoint.local : endpoint.external)
                  .port(static_cast<uint16_t>(atoi(colon + 1)));
            }
            // std::cout << "Child " << a << " returns endpoints " << line.substr(10) << std::endl;
            return true;
          } else if (line[0] != '[') {
            std::cout << "Child " << a << " sends me unknown line '" << line << "'\n";
          }
        }
      };
      if (!drain_endpoint(n)) {
        GTEST_FAIL() << "Failed to read from child " << n << ".";
        return;
      }
      child_endpoints[n][i * 2] = endpoint;
      if (!drain_endpoint(i)) {
        GTEST_FAIL() << "Failed to read from child " << i << ".";
        return;
      }
      child_endpoints[n][i * 2 + 1] = endpoint;

      os1 << "CONNECT: " << child_nodeids[i].ToStringEncoded(NodeId::EncodingType::kHex) << ";"
          << child_endpoints[n][i * 2 + 1].local.address().to_string() + ":"
          << child_endpoints[n][i * 2 + 1].local.port() << ";" << std::endl;
      os2 << "CONNECT: " << child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex) << ";"
          << child_endpoints[n][i * 2].local.address().to_string() + ":"
          << child_endpoints[n][i * 2].local.port() << ";" << std::endl;
      auto drain_connect = [&](size_t a) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
            *childpipes[a].first;
        // std::cout << "drain_connect(" << a << ")" << std::endl;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            return false;
          }
          if (!line.compare(0, 10, "CONNECTED:")) {
            // std::cout << "Child " << a << " is connected to " << line.substr(11) << std::endl;
            ++connection_count;
            return true;
          } else if (line[0] != '[') {
            std::cout << "Child " << a << " sends me unknown line '" << line << "'" << std::endl;
          }
        }
      };
      if (!drain_connect(n)) {
        GTEST_FAIL() << "Failed to read from child " << n << ".";
        return;
      }
      if (!drain_connect(i)) {
        GTEST_FAIL() << "Failed to read from child " << i << ".";
        return;
      }
    }

    std::cout << node_count << " nodes connected with " << connection_count << " connections."
              << std::endl;

    size_t messages_sent = 0;
    do {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      for (auto& childpipe : childpipes) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os = *childpipe.second;
        os << "STATS" << std::endl;
      }
      messages_sent = 0;
      size_t n = 0;
      for (auto& childpipe : childpipes) {
        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipe.first;
        for (;;) {
          std::string line;
          if (!getline(is, is->handle(), line)) {
            GTEST_FAIL() << "Failed to read from child " << n << ".";
            return;
          }
          if (!line.compare(0, 6, "STATS:")) {
            messages_sent += atoi(line.substr(7).c_str());
            break;
          } else if (line[0] != '[') {
            std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
          }
        }
        ++n;
      }
      std::cout << "Children have now sent " << messages_sent << " messages." << std::endl;
    } while (messages_sent < messages_sent_count);
  } catch (const std::exception& e) {
    GTEST_FAIL() << "Exception thrown '" << e.what() << "'.";
  }

  // Shutdown children
  childpipes.clear();
  for (size_t n = 0; n < node_count; n++) {
    boost::system::error_code ec;
    // std::cout << "Waiting for child " << n << " to exit" << std::endl;
    boost::process::wait_for_exit(children[n], ec);
  }
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
