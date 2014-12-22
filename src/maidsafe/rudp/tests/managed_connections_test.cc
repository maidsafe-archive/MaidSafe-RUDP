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

#include "asio/use_future.hpp"

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

#define ASSERT_THROW_CODE(expr, CODE) \
  try { expr; GTEST_FAIL() << "Expected to throw"; } \
  catch (std::system_error e) { ASSERT_EQ(e.code(), CODE) << "Exception: " << e.what(); }

namespace args = std::placeholders;
namespace Asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace test {

namespace {

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
#ifndef MAIDSAFE_APPLE
        bootstrap_endpoints_()
        //do_nothing_on_message_([](const std::string&) {}),
        //do_nothing_on_connection_lost_([](const NodeId&) {})
  {
  }
#else
        bootstrap_endpoints_(),
        //do_nothing_on_message_([](const std::string&) {}),
        //do_nothing_on_connection_lost_([](const NodeId&) {}),
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
  std::vector<Contact> bootstrap_endpoints_;
  //MessageReceivedFunctor do_nothing_on_message_;
  //ConnectionLostFunctor do_nothing_on_connection_lost_;

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

  void BootstrapAndAdd(size_t index, Contact& chosen_node, EndpointPair& this_endpoint_pair,
                       NatType& /*nat_type*/) {
    ASSERT_NO_THROW(chosen_node = node_.Bootstrap(bootstrap_endpoints_[index]).get());
    ASSERT_EQ(nodes_[index]->node_id(), chosen_node.id);
    Sleep(std::chrono::milliseconds(250));
    nodes_[index]->ResetData();

    ASSERT_THROW_CODE
      ( this_endpoint_pair = node_.GetAvailableEndpoints(nodes_[index]->node_id()).get()
      , RudpErrors::already_connected);

    EndpointPair peer_endpoint_pair;

    ASSERT_THROW_CODE
      ( peer_endpoint_pair = nodes_[index]->GetAvailableEndpoints(node_.node_id()).get();
      , RudpErrors::already_connected);

    //EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
    //EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

    try {
      nodes_[index]->Add(node_.make_contact(this_endpoint_pair)).get();
    }
    catch (std::system_error error) {
      ASSERT_EQ(error.code(), RudpErrors::already_connected);
    }

    try {
      node_.Add(nodes_[index]->make_contact(peer_endpoint_pair)).get();
    }
    catch (std::system_error error) {
      ASSERT_EQ(error.code(), RudpErrors::already_connected);
    }
  }
};

//TEST_F(ManagedConnectionsTest, BEH_API_kBootstrapConnectionAlreadyExists) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
//  NodeId chosen_node;
//  EndpointPair this_endpoint_pair, peer_endpoint_pair;
//  NatType nat_type;
//  size_t index(1);
//
//  using lock_guard = std::lock_guard<std::mutex>;
//  std::mutex mutex;
//  std::promise<void> promise;
//  auto future = promise.get_future();
//
//  nodes_[index]->managed_connections()->SetConnectionAddedFunctor([&](NodeId) {
//    lock_guard guard(mutex);
//    promise.set_value();
//  });
//
//  ASSERT_EQ(kSuccess,
//            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[index]), chosen_node));
//
//  // When the above bootstrap function finishes, the node 'node_' knows it is connected
//  // to node 'nodes_[index]' but not the other way around. For that we need to
//  // wait till the ConnectionAddedFunctor is executed inside node 'nodes_[index]'.
//  future.wait();
//  { lock_guard guard(mutex); }
//
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            nodes_[index]->managed_connections()->GetAvailableEndpoint(
//                node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
//
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            node_.managed_connections()->GetAvailableEndpoint(
//                nodes_[index]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
//}
//
//TEST_F(ManagedConnectionsTest, FUNC_API_RandomSizeSetup) {
//  int nodes(8 + RandomUint32() % 16);
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, nodes));
//}

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap) {
  struct Listener : public ManagedConnections::Listener {
    void MessageReceived(NodeId /*peer_id*/, ReceivedMessage /*message*/) override { }
    void ConnectionLost(NodeId /*peer_id*/) override { }
  };

  auto listener = std::make_shared<Listener>();
//  // All invalid
//  NatType nat_type(NatType::kUnknown);
//  NodeId chosen_bootstrap;
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(
//                std::vector<Endpoint>(), MessageReceivedFunctor(), ConnectionLostFunctor(),
//                NodeId(), nullptr, nullptr, chosen_bootstrap, nat_type));
    try {
      node_.managed_connections()->Bootstrap(
          std::vector<Contact>(), listener, NodeId(), asymm::Keys(), asio::use_future, Endpoint()).get();
      GTEST_FAIL() << "Exception thrown was expected";
    }
    catch(std::system_error e) {
      ASSERT_EQ(e.code(), RudpErrors::failed_to_bootstrap);
    }

//  // Empty bootstrap_endpoints
//  EXPECT_EQ(kNoBootstrapEndpoints,
//            node_.managed_connections()->Bootstrap(std::vector<Endpoint>(), do_nothing_on_message_,
//                                                   do_nothing_on_connection_lost_, node_.node_id(),
//                                                   node_.private_key(), node_.public_key(),
//                                                   chosen_bootstrap, nat_type));
    try {
      node_.managed_connections()->Bootstrap(std::vector<Contact>(), listener, NodeId(), node_.keys(), asio::use_future, Endpoint());
    }
    catch(std::system_error e) {
      ASSERT_EQ(e.code(), RudpErrors::failed_to_bootstrap);
    }
//  // Unavailable bootstrap_endpoints
//  // TODO
//  {
//    Asio::io_service io_service;
//    boost::asio::ip::udp::socket tmp_socket(io_service, Endpoint(GetLocalIp(), 0));
//    int16_t some_used_port = tmp_socket.local_endpoint().port();
//
//    EXPECT_NE(kSuccess, node_.managed_connections()->Bootstrap(
//                            std::vector<Endpoint>(1, Endpoint(GetLocalIp(), some_used_port)),
//                            do_nothing_on_message_, do_nothing_on_connection_lost_, node_.node_id(),
//                            node_.private_key(), node_.public_key(), chosen_bootstrap, nat_type));
//  }
//  // Unavailable bootstrap_endpoints with kLivePort
//  {
//    // The tmp_socket opens the kLivePort to make sure no other program using RUDP
//    // on this test PC is using it. Though, if some other test PC is using the port
//    // already, then the test is pointless.
//    Asio::io_service io_service;
//    boost::system::error_code ec;
//    boost::asio::ip::udp::socket tmp_socket(io_service);
//    tmp_socket.bind(Endpoint(GetLocalIp(), kLivePort), ec);
//
//    if (!ec) {
//      EXPECT_EQ(kTransportStartFailure,
//                node_.managed_connections()->Bootstrap(
//                    std::vector<Endpoint>(1, Endpoint(GetLocalIp(), kLivePort)),
//                    do_nothing_on_message_, do_nothing_on_connection_lost_, node_.node_id(),
//                    node_.private_key(), node_.public_key(), chosen_bootstrap, nat_type));
//    }
//  }
//
//  // Invalid MessageReceivedFunctor
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(bootstrap_endpoints_, MessageReceivedFunctor(),
//                                                   do_nothing_on_connection_lost_, node_.node_id(),
//                                                   node_.private_key(), node_.public_key(),
//                                                   chosen_bootstrap, nat_type));
//  // Invalid ConnectionLostFunctor
//  EXPECT_EQ(kInvalidParameter, node_.managed_connections()->Bootstrap(
//                                   bootstrap_endpoints_, do_nothing_on_message_,
//                                   ConnectionLostFunctor(), node_.node_id(), node_.private_key(),
//                                   node_.public_key(), chosen_bootstrap, nat_type));
//  // Invalid private key
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(
//                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
//                node_.node_id(), std::shared_ptr<asymm::PrivateKey>(new asymm::PrivateKey),
//                node_.public_key(), chosen_bootstrap, nat_type));
//  // Invalid public key
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(
//                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
//                node_.node_id(), node_.private_key(),
//                std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey), chosen_bootstrap,
//                nat_type));
//  // NULL private key
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(
//                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
//                node_.node_id(), nullptr, node_.public_key(), chosen_bootstrap, nat_type));
//  // NULL public key
//  EXPECT_EQ(kInvalidParameter,
//            node_.managed_connections()->Bootstrap(
//                bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
//                node_.node_id(), node_.private_key(), nullptr, chosen_bootstrap, nat_type));
//  // Valid
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Bootstrap(
//                          bootstrap_endpoints_, do_nothing_on_message_,
//                          do_nothing_on_connection_lost_, node_.node_id(), node_.private_key(),
//                          node_.public_key(), chosen_bootstrap, nat_type));
//  EXPECT_FALSE(chosen_bootstrap.IsZero());
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  struct Listener : public ManagedConnections::Listener {
    void MessageReceived(NodeId /*peer_id*/, ReceivedMessage /*message*/) override { }
    void ConnectionLost(NodeId /*peer_id*/) override { }
  };

  //  Before Bootstrapping
  EndpointPair this_endpoint_pair(Endpoint(ip::address::from_string("1.1.1.1"), 1025));

  // TODO?
  //EXPECT_EQ(kNotBootstrapped,
  //          node_.managed_connections()->GetAvailableEndpoint(
  //              NodeId(NodeId::IdType::kRandomId), EndpointPair(), this_endpoint_pair, nat_type));

  //EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  //EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  //this_endpoint_pair = EndpointPair(Endpoint(ip::address::from_string("1.1.1.1"), 1025));
  //EndpointPair endpoint_pair(Endpoint(ip::address::from_string("1.2.3.4"), 1026));

  //EXPECT_EQ(kNotBootstrapped,
  //          node_.managed_connections()->GetAvailableEndpoint(
  //              NodeId(NodeId::IdType::kRandomId), endpoint_pair, this_endpoint_pair, nat_type));

  //EXPECT_EQ(EndpointPair(), this_endpoint_pair);

  //  After Bootstrapping
  Contact chosen_node;
  //EXPECT_EQ(kSuccess,
  //          node_.managed_connections()->Bootstrap(
  //              bootstrap_endpoints_, do_nothing_on_message_, do_nothing_on_connection_lost_,
  //              node_.node_id(), node_.private_key(), node_.public_key(), chosen_node, nat_type));
  try {
    chosen_node = node_.managed_connections()->Bootstrap
                    ( bootstrap_endpoints_
                    , std::make_shared<Listener>()
                    , node_.node_id()
                    , node_.keys()
                    , asio::use_future, Endpoint()).get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Failed to bootstrap";
  }

  EXPECT_TRUE(chosen_node.id.IsValid());

  //EXPECT_EQ(kBootstrapConnectionAlreadyExists,
  //          node_.managed_connections()->GetAvailableEndpoint(chosen_node, EndpointPair(),
  //                                                            this_endpoint_pair, nat_type));
  try {
    node_.managed_connections()->GetAvailableEndpoints(chosen_node.id, asio::use_future).get();
    GTEST_FAIL() << "Expected to fail in GetAvailableEndpoints";
  }
  catch (std::system_error error) {
    EXPECT_EQ(error.code(), RudpErrors::already_connected);
  }

  //EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));

  EndpointPair another_endpoint_pair;

  //EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
  //                        NodeId(NodeId::IdType::kRandomId), EndpointPair(), another_endpoint_pair,
  //                        nat_type));
  try {
    another_endpoint_pair = node_.managed_connections()->GetAvailableEndpoints
                              ( NodeId(RandomString(NodeId::kSize))
                              , asio::use_future
                              ).get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Did not expect exception in GetAvailableEndpoints";
  }

  EXPECT_TRUE(detail::IsValid(another_endpoint_pair.local));
  EXPECT_NE(this_endpoint_pair.local, another_endpoint_pair.local);
}

TEST_F(ManagedConnectionsTest, BEH_API_PendingConnectionsPruning) {
  const int kNodeCount(8);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, kNodeCount));

  std::string message("message1");
  Contact chosen_node;
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  BootstrapAndAdd(0, chosen_node, this_endpoint_pair, nat_type);

  // Run GetAvailableEndpoint to add elements to pendings_.
  for (int i(1); i != kNodeCount; ++i) {
    //EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
    //                        nodes_[i]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
    try {
      this_endpoint_pair = node_.managed_connections()->GetAvailableEndpoints(
          nodes_[i]->node_id(), asio::use_future).get();
    }
    catch (std::system_error error) {
      GTEST_FAIL() << "GetAvailableEndpoints failed";
    }
  }
//
//  // Wait for rendezvous_connect_timeout + 500ms to clear the pendings, which should allow for
//  // further GetAvailableEndpoint calls to be made. Intermediate calls should return with
//  // kConnectAttemptAlreadyRunning.
    EndpointPair test_endpoint_pair;
//  for (int i(1); i != kNodeCount; ++i) {
//    EXPECT_EQ(kConnectAttemptAlreadyRunning,
//              node_.managed_connections()->GetAvailableEndpoint(
//                  nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
//    EXPECT_EQ(this_endpoint_pair.external, test_endpoint_pair.external);
//    EXPECT_EQ(this_endpoint_pair.local, test_endpoint_pair.local);
//  }
    for (int i = 1; i != kNodeCount; ++i) {
      try {
        node_.managed_connections()->GetAvailableEndpoints(nodes_[i]->node_id(), asio::use_future).get();
        GTEST_FAIL() << "GetAvailableEndpoints expected to fail";
      }
      catch (std::system_error error) {
        ASSERT_EQ(error.code(), RudpErrors::connection_already_in_progress);
      }
    }

    Sleep(rendezvous_connect_timeout() / 2);

//  // Remove one from the pendings_ by calling Add to complete making the connection.
  const int kSelected((RandomUint32() % (kNodeCount - 1)) + 1);
//  EndpointPair peer_endpoint_pair;
//  EXPECT_EQ(kSuccess, nodes_[kSelected]->managed_connections()->GetAvailableEndpoint(
//                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
    try {
      this_endpoint_pair = nodes_[kSelected]->managed_connections()->GetAvailableEndpoints(
          node_.node_id(), asio::use_future).get();
    }
    catch (std::system_error error) {
      GTEST_FAIL() << "Exception: " << error.what();
    }
//  EXPECT_EQ(kSuccess,
//            nodes_[kSelected]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
//                                                          nodes_[kSelected]->validation_data()));
//  EXPECT_EQ(kSuccess,
//            node_.managed_connections()->Add(nodes_[kSelected]->node_id(), peer_endpoint_pair,
//                                             node_.validation_data()));
//
//  for (int i(1); i != kNodeCount; ++i) {
//    if (i != kSelected) {
//      EXPECT_EQ(kConnectAttemptAlreadyRunning,
//                node_.managed_connections()->GetAvailableEndpoint(
//                    nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
//      EXPECT_EQ(this_endpoint_pair.external, test_endpoint_pair.external);
//      EXPECT_EQ(this_endpoint_pair.local, test_endpoint_pair.local);
//    }
//  }
//
  Sleep(rendezvous_connect_timeout() / 2 + std::chrono::milliseconds(500));
//
//  for (int i(1); i != kNodeCount; ++i) {
//    EXPECT_EQ((i == kSelected ? kUnvalidatedConnectionAlreadyExists : kSuccess),
//              node_.managed_connections()->GetAvailableEndpoint(
//                  nodes_[i]->node_id(), EndpointPair(), test_endpoint_pair, nat_type));
//  }
    for (int i = 1; i != kNodeCount; ++i) {
      try {
        node_.managed_connections()->GetAvailableEndpoints(
            nodes_[i]->node_id(), asio::use_future).get();
      }
      catch (std::system_error error) {
        GTEST_FAIL() << "Exception: " << error.what();
      }
    }
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Valid bootstrap
  Contact chosen_node;
  //EXPECT_EQ(kSuccess,
  //          node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  try {
    chosen_node = node_.Bootstrap(bootstrap_endpoints_[0]).get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Exception: " << error.what();
  }

  ASSERT_TRUE(chosen_node.id.IsValid());
  Sleep(std::chrono::milliseconds(250));

//// FIXME: Do we need to test the same thing in so many tests? I.e.
////        testing whether a connection already exists is tested multiple
////        times in the tests above. IMO it just makes other tests less
////        readable.
//  nodes_[0]->ResetData();
//  EndpointPair peer_endpoint_pair0, peer_endpoint_pair2, this_endpoint_pair0, this_endpoint_pair1,
//      this_endpoint_pair2;
//  NatType nat_type0(NatType::kUnknown), nat_type1(NatType::kUnknown);
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(), EndpointPair(),
//                                                              this_endpoint_pair0, nat_type1));
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            nodes_[0]->managed_connections()->GetAvailableEndpoint(
//                node_.node_id(), this_endpoint_pair0, peer_endpoint_pair0, nat_type0));
//  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair0.local));
//  EXPECT_TRUE(detail::IsValid(this_endpoint_pair0.local));
//
//  // Case: Own NodeId
//  EXPECT_EQ(kOwnId, node_.managed_connections()->Add(node_.node_id(), EndpointPair(),
//                                                     node_.validation_data()));
    try {
      node_.managed_connections()->Add(Contact{node_.node_id(), Endpoint(), node_.public_key()}, asio::use_future).get();
      GTEST_FAIL() << "Expected to throw exception";
    }
    catch (std::system_error error) {
      EXPECT_EQ(error.code(), RudpErrors::operation_not_supported);
    }

//  // Case: Empty endpoint
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(), EndpointPair(),
//                                                       node_.validation_data()));
    try {
      node_.managed_connections()->Add(Contact{node_.node_id(), Endpoint(), node_.public_key()}, asio::use_future).get();
      GTEST_FAIL() << "Expected to throw exception";
    }
    catch (std::system_error error) {
      EXPECT_EQ(error.code(), RudpErrors::operation_not_supported);
    }
//  auto this_node_futures(node_.GetFutureForMessages(1));
//  ASSERT_NE(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//
    {
      // Case: Non-existent endpoint
      EndpointPair random_peer_endpoint;
      random_peer_endpoint.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
      random_peer_endpoint.external = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());

  //  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
  //                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair1, nat_type1));
      try {
        node_.managed_connections()->GetAvailableEndpoints(
          nodes_[1]->node_id(), asio::use_future).get();
      }
      catch (std::system_error error) {
        GTEST_FAIL() << "Exception: " << error.what(); 
      }
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), random_peer_endpoint,
//                                                       node_.validation_data()));
      try {
        node_.managed_connections()->Add(nodes_[1]->make_contact(random_peer_endpoint), asio::use_future).get();
        GTEST_FAIL() << "Expected to throw";
      }
      catch (std::system_error error) {
        ASSERT_EQ(error.code(), RudpErrors::timed_out) << "Exception: " << error.what(); 
      }
//  this_node_futures = node_.GetFutureForMessages(1);
//  ASSERT_NE(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//
    }
    {
      // Case: Success
      auto& node_a = node_;
      auto& node_b = *nodes_[2];

      node_a.ResetData();
      node_b.ResetData();
//  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
//                          nodes_[2]->node_id(), EndpointPair(), this_endpoint_pair2, nat_type1));
//
      EndpointPair a_eps, b_eps;

      try {
        a_eps = node_a.managed_connections()->GetAvailableEndpoints(
            node_b.node_id(), asio::use_future).get();

        b_eps = node_b.managed_connections()->GetAvailableEndpoints(
            node_a.node_id(), asio::use_future).get();
      }
      catch (std::system_error error) {
        GTEST_FAIL() << "Exception: " << error.what(); 
      }
//  EXPECT_EQ(kSuccess, nodes_[2]->managed_connections()->GetAvailableEndpoint(
//                          node_.node_id(), this_endpoint_pair2, peer_endpoint_pair2, nat_type0));
//  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair2.local));
//  EXPECT_TRUE(detail::IsValid(this_endpoint_pair2.local));
//  auto peer_futures(nodes_[2]->GetFutureForMessages(1));
//  this_node_futures = node_.GetFutureForMessages(1);
//  EXPECT_EQ(kSuccess, nodes_[2]->managed_connections()->Add(node_.node_id(), this_endpoint_pair2,
//                                                            nodes_[2]->validation_data()));
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[2]->node_id(), peer_endpoint_pair2,
//                                                       node_.validation_data()));

      auto a_add = node_a.managed_connections()->Add(node_b.make_contact(b_eps), asio::use_future);
      auto b_add = node_b.managed_connections()->Add(node_a.make_contact(a_eps), asio::use_future);

      try {
        a_add.get();
        b_add.get();
      }
      catch (std::system_error error) {
        GTEST_FAIL() << "Exception: " << error.what();
      }
//  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto peer_messages(peer_futures.get());
//  ASSERT_EQ(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto this_node_messages(this_node_futures.get());
//  EXPECT_EQ(1, peer_messages.size());
//  EXPECT_EQ(1, this_node_messages.size());
//  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
//  EXPECT_EQ(nodes_[2]->validation_data(), this_node_messages[0]);
    }
}

void DispatchHandler(const std::error_code& ec, std::shared_ptr<detail::Multiplexer> muxer) {
  if (!ec)
    muxer->AsyncDispatch(std::bind(&DispatchHandler, args::_1, muxer));
}

//void TickHandler(const boost::system::error_code& ec, detail::Socket* sock) {
//  if (!ec)
//    sock->AsyncTick(std::bind(&TickHandler, args::_1, sock));
//}
//
TEST_F(ManagedConnectionsTest, BEH_API_AddDuplicateBootstrap) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  // Bootstrap node_ off nodes_[0]
  Contact chosen_node;
//  EXPECT_EQ(kSuccess,
//            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
//  EXPECT_FALSE(chosen_node.IsZero());
//  Sleep(std::chrono::milliseconds(250));

  auto& node_a = node_;
  auto& node_b = *nodes_[0];
  auto& node_c = *nodes_[1];

  try {
    node_a.Bootstrap(bootstrap_endpoints_[0] /* node_b endpoint */).get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Exception: " << error.what();
  }

//  EndpointPair peer_endpoint_pair, this_endpoint_pair;
//  NatType this_nat_type(NatType::kUnknown), peer_nat_type(NatType::kUnknown);
//
  // Connect node_ to nodes_[1]
  node_a.ResetData();
  node_b.ResetData();
  node_c.ResetData();

//  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
//                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, this_nat_type));
//  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
//                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, peer_nat_type));
//  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));
//  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  auto get_eps_a = node_a.GetAvailableEndpoints(node_c.node_id());
  auto get_eps_c = node_c.GetAvailableEndpoints(node_a.node_id());

  EndpointPair node_a_eps, node_c_eps;

  try {
    node_a_eps = get_eps_a.get();
    node_c_eps = get_eps_c.get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Exception: " << error.what();
  }

//  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
//  auto this_node_futures(node_.GetFutureForMessages(1));
//  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
//                                                            nodes_[1]->validation_data()));
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
//                                                       node_.validation_data()));
  auto node_a_add = node_a.Add(node_c.make_contact(node_c_eps));
  auto node_c_add = node_c.Add(node_a.make_contact(node_a_eps));

  try {
    node_a_add.get();
    node_c_add.get();
  }
  catch (std::system_error error) {
    GTEST_FAIL() << "Exception: " << error.what();
  }
//  EXPECT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto peer_messages(peer_futures.get());
//  EXPECT_EQ(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto this_node_messages(this_node_futures.get());
//  EXPECT_EQ(1, peer_messages.size());
//  EXPECT_EQ(1, this_node_messages.size());
//  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
//  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);
//
  // Start new Socket with nodes_[1]'s details
  NatType dummy;
  Asio::io_service io_service;
  boost::system::error_code error_code(Asio::error::would_block);
  //ip::udp::endpoint endpoint(peer_endpoint_pair.local.address(), maidsafe::test::GetRandomPort());
  ip::udp::endpoint endpoint(node_c_eps.local.address(), maidsafe::test::GetRandomPort());
  std::shared_ptr<detail::Multiplexer> multiplexer(new detail::Multiplexer(io_service));
  detail::ConnectionManager connection_manager(std::shared_ptr<detail::Transport>(),
                                               Asio::io_service::strand(io_service), multiplexer,
                                               node_c.node_id(), node_c.public_key());
  ASSERT_EQ(kSuccess, multiplexer->Open(endpoint));

  multiplexer->AsyncDispatch([multiplexer](const std::error_code& ec) {
      DispatchHandler(ec, multiplexer);
      });

  detail::Socket socket(*multiplexer, dummy);

  auto on_nat_detection_requested_slot(
      [](const asio::ip::udp::endpoint& /*this_local_endpoint*/, const NodeId& /*peer_id*/,
         const asio::ip::udp::endpoint& /*peer_endpoint*/,
         uint16_t& /*another_external_port*/) {});

  // Try to connect in kBootstrapAndKeep mode to node_'s existing connected Transport.
  socket.AsyncConnect(node_c.node_id(), node_c.public_key(), node_a_eps.local,
                      node_a.node_id(), node_a.public_key(),
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
//  auto wait_for_signals([&](int node_index, unsigned active_connection_count) -> bool {
//    int count(0);
//    do {
//      Sleep(std::chrono::milliseconds(100));
//      ++count;
//    } while ((node_.connection_lost_node_ids().empty() ||
//              nodes_[node_index]->connection_lost_node_ids().empty() ||
//              node_.managed_connections()->GetActiveConnectionCount() != active_connection_count) &&
//             count != 10);
//    return (!node_.connection_lost_node_ids().empty() &&
//            !nodes_[node_index]->connection_lost_node_ids().empty());
//  });
//
  auto& node_a = node_;
  auto& node_b = *nodes_[0];
  auto& node_c = *nodes_[1];
  //auto& node_d = *nodes_[2];
  //auto& node_e = *nodes_[3];

  // Before Bootstrap
  node_a.Remove(node_b.node_id()).get();
  ASSERT_TRUE(node_a.connection_lost_node_ids().empty());

  // Before Add
  Contact chosen_node;
//  EXPECT_EQ(kSuccess,
//            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[1]), chosen_node));
//  EXPECT_EQ(nodes_[1]->node_id(), chosen_node);
  ASSERT_NO_THROW(chosen_node = node_a.Bootstrap(bootstrap_endpoints_[1]).get());
  ASSERT_EQ(node_c.node_id(), chosen_node.id);

  for (unsigned count(0);
       node_c.managed_connections()->GetActiveConnectionCount() < 4 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));

  EXPECT_EQ(node_c.managed_connections()->GetActiveConnectionCount(), 4);

  ASSERT_NO_THROW(node_a.Remove(chosen_node.id).get());

//  ASSERT_TRUE(wait_for_signals(1, 3));
  ASSERT_EQ(node_a.connection_lost_node_ids().size(), 1U);
  //FIXME: Synchronization by sleep is evil.
  Sleep(std::chrono::milliseconds(200));
  ASSERT_EQ(node_c.connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(chosen_node.id, node_a.connection_lost_node_ids()[0]);
  EXPECT_EQ(node_c.managed_connections()->GetActiveConnectionCount(), 3);

  // After Add
//  EXPECT_EQ(kSuccess,
//            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
//  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  ASSERT_NO_THROW(chosen_node = node_a.Bootstrap(bootstrap_endpoints_[0]).get());
  node_b.ResetData();
//  EndpointPair this_endpoint_pair, peer_endpoint_pair;
//  NatType nat_type;
  Sleep(std::chrono::milliseconds(250));
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            node_.managed_connections()->GetAvailableEndpoint(chosen_node, EndpointPair(),
//                                                              this_endpoint_pair, nat_type));
  try {
    node_a.GetAvailableEndpoints(chosen_node.id).get();
    GTEST_FAIL() << "Expected to throw";
  }
  catch (std::system_error error) {
    ASSERT_EQ(error.code(), RudpErrors::already_connected);
  }
//  EXPECT_EQ(kBootstrapConnectionAlreadyExists,
//            nodes_[0]->managed_connections()->GetAvailableEndpoint(
//                node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  try {
    node_b.GetAvailableEndpoints(node_a.node_id()).get();
    GTEST_FAIL() << "Expected to throw";
  }
  catch (std::system_error error) {
    ASSERT_EQ(error.code(), RudpErrors::already_connected);
  }
//  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
//  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));
//
//  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
//  auto this_node_futures(node_.GetFutureForMessages(1));
//  EXPECT_EQ(kSuccess, nodes_[0]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
//                                                            nodes_[0]->validation_data()));
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(), peer_endpoint_pair,
//                                                       node_.validation_data()));
//  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto peer_messages(peer_futures.get());
//  ASSERT_EQ(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto this_node_messages(this_node_futures.get());
//  ASSERT_EQ(1, peer_messages.size());
//  ASSERT_EQ(1, this_node_messages.size());
//  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
//  EXPECT_EQ(nodes_[0]->validation_data(), this_node_messages[0]);
//  nodes_[0]->ResetData();
//

// FIXME: Reenable these tests? The Remove function currently always returns success.
// Invalid NodeId
//  node_a.ResetData();
//  node_b.ResetData();
//  node_.managed_connections()->Remove(NodeId());
//  ASSERT_FALSE(wait_for_signals(0, 4));
//  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 4);
//  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
//  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());
//
//  // Unknown endpoint
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  node_.managed_connections()->Remove(nodes_[2]->node_id());
//  ASSERT_FALSE(wait_for_signals(2, 3));
//  EXPECT_EQ(nodes_[2]->managed_connections()->GetActiveConnectionCount(), 3);
//  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
//  EXPECT_TRUE(nodes_[2]->connection_lost_node_ids().empty());
//
//  // Valid
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  node_.managed_connections()->Remove(nodes_[0]->node_id());
//  ASSERT_TRUE(wait_for_signals(0, 3));
//  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 3);
//  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
//  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
//  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());
//  EXPECT_EQ(nodes_[0]->connection_lost_node_ids()[0], node_.node_id());
//
//  // Already removed endpoint
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  node_.managed_connections()->Remove(nodes_[0]->node_id());
//  ASSERT_FALSE(wait_for_signals(0, 3));
//  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 3);
//  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
//  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());
}

TEST_F(ManagedConnectionsTest, BEH_API_SimpleSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  Contact chosen_node;
  ASSERT_NO_THROW(chosen_node = node_.Bootstrap(bootstrap_endpoints_[0]).get());
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node.id);
  for (unsigned count(0);
       nodes_[0]->managed_connections()->GetActiveConnectionCount() < 2 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));
  EXPECT_EQ(nodes_[0]->managed_connections()->GetActiveConnectionCount(), 2);

  EndpointPair this_endpoint_pair, peer_endpoint_pair;

  ASSERT_NO_THROW(this_endpoint_pair = node_.GetAvailableEndpoints(nodes_[1]->node_id()).get());
  ASSERT_NO_THROW(peer_endpoint_pair = nodes_[1]->GetAvailableEndpoints(node_.node_id()).get());

  ASSERT_TRUE(detail::IsValid(this_endpoint_pair.local));
  ASSERT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));

  auto node_a_add = node_.Add(nodes_[1]->make_contact(peer_endpoint_pair)); 
  auto node_b_add = nodes_[1]->Add(node_.make_contact(this_endpoint_pair));

  ASSERT_NO_THROW(node_a_add.get());
  ASSERT_NO_THROW(node_b_add.get());

  node_.ResetData();
  nodes_[1]->ResetData();
  static const int kRepeatCount = 10;
  std::atomic<int> result_arrived_count(0);
  std::atomic<int> result_of_send(kSuccess);
  std::promise<void> done_out;
  auto done_in = done_out.get_future();

  peer_futures = nodes_[1]->GetFutureForMessages(kRepeatCount);
  const std::string message_str(RandomAlphaNumericString(256 * 1024));
  Node::message_t message(message_str.begin(), message_str.end());

  for (int i(0); i != kRepeatCount; ++i)
    node_.Send(nodes_[1]->node_id(), message).get();

  auto peer_messages = peer_futures.get();
  ASSERT_EQ(static_cast<size_t>(kRepeatCount), peer_messages.size());
  for (auto peer_message : peer_messages)
    EXPECT_EQ(message, peer_message);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ManyTimesSimpleSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  auto& node_a = node_;
  auto& node_b = *nodes_[0];
  auto& node_c = *nodes_[1];

  Contact chosen_node;
//  EXPECT_EQ(kSuccess,
//            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_NO_THROW(chosen_node = node_a.Bootstrap(bootstrap_endpoints_[0]).get());
  ASSERT_EQ(node_b.node_id(), chosen_node.id);
  for (unsigned count(0);
       node_b.managed_connections()->GetActiveConnectionCount() < 2 && count < 10; ++count)
    Sleep(std::chrono::milliseconds(100));
  EXPECT_EQ(node_b.managed_connections()->GetActiveConnectionCount(), 2);

  EndpointPair node_a_eps, node_c_eps;
//  NatType nat_type;
//  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(
//                          nodes_[1]->node_id(), EndpointPair(), this_endpoint_pair, nat_type));
//  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->GetAvailableEndpoint(
//                          node_.node_id(), this_endpoint_pair, peer_endpoint_pair, nat_type));
  ASSERT_NO_THROW(node_a_eps = node_a.GetAvailableEndpoints(node_c.node_id()).get());
  ASSERT_NO_THROW(node_c_eps = node_c.GetAvailableEndpoints(node_a.node_id()).get());

  EXPECT_TRUE(detail::IsValid(node_a_eps.local));
  EXPECT_TRUE(detail::IsValid(node_c_eps.local));

//  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
//  auto this_node_futures(node_.GetFutureForMessages(1));
//  EXPECT_EQ(kSuccess, nodes_[1]->managed_connections()->Add(node_.node_id(), this_endpoint_pair,
//                                                            nodes_[1]->validation_data()));
//  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(), peer_endpoint_pair,
//                                                       node_.validation_data()));
  auto node_a_add = node_a.Add(node_c.make_contact(node_c_eps));
  auto node_c_add = node_c.Add(node_a.make_contact(node_a_eps));

  EXPECT_NO_THROW(node_a_add.get());
  EXPECT_NO_THROW(node_c_add.get());

//  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto peer_messages(peer_futures.get());
//  ASSERT_EQ(boost::future_status::ready,
//            this_node_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto this_node_messages(this_node_futures.get());
//  ASSERT_EQ(1U, peer_messages.size());
//  ASSERT_EQ(1U, this_node_messages.size());
//  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
//  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);
//
  node_a.ResetData();
  node_c.ResetData();
  // FIXME: This was 10000 but seems like this new api made sending a lot
  // slower, so I made it smaller for now.
  static size_t kRepeatCount = 256;
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
  // 2014-04-03 ned: Looks like above this we run into hard buffer limits in tsan
  kRepeatCount = 1024;
#endif
#endif
//  std::atomic<int> result_arrived_count(0);
//  std::atomic<int> result_of_send(kSuccess);
//  std::promise<void> done_out;
//  auto done_in = done_out.get_future();
//  MessageSentFunctor message_sent_functor([&](int result_in) {
//    if (result_in != kSuccess)
//      result_of_send = result_in;
//    if (kRepeatCount == ++result_arrived_count)
//      done_out.set_value();
//  });
  auto peer_futures = nodes_[1]->GetFutureForMessages(kRepeatCount);
  const std::string message_str(RandomAlphaNumericString(1024));
  const Node::message_t message(message_str.begin(), message_str.end());
//  for (int i(0); i != kRepeatCount; ++i)
//    node_.managed_connections()->Send(nodes_[1]->node_id(), kMessage, message_sent_functor);
  for (size_t i(0); i != kRepeatCount; ++i) {
    node_.Send(nodes_[1]->node_id(), message).get();
  }

//  ASSERT_TRUE(std::future_status::timeout != done_in.wait_for(std::chrono::seconds(500)))
//      << result_arrived_count << " - " << kRepeatCount;
//  EXPECT_EQ(kSuccess, result_of_send);
//  ASSERT_EQ(boost::future_status::ready, peer_futures.wait_for(boost::chrono::minutes(2)));
  auto peer_messages = peer_futures.get();
  ASSERT_EQ(kRepeatCount, peer_messages.size());
  for (auto peer_message : peer_messages) {
    EXPECT_EQ(message, peer_message);
  }
}

//struct FutureResult {
//  struct State {
//    std::promise<int> promise;
//    std::future<int> future;
//
//    State() : future(promise.get_future()) {}
//  };
//
//  std::function<void(int /* result */)> MakeContinuation() {
//    _state = std::make_shared<State>();
//
//    auto state_copy = _state;
//    return [state_copy](int result) {  // NOLINT
//      state_copy->promise.set_value(result);
//    };
//  }
//
//  bool Wait(int millis) {
//    auto duration = std::chrono::milliseconds(millis);
//
//    if (_state->future.wait_for(duration) == std::future_status::timeout) {
//      return false;
//    }
//
//    return true;
//  }
//
//  int Result() const { return _state->future.get(); }
//
//  std::shared_ptr<State> _state;
//};

TEST_F(ManagedConnectionsTest, FUNC_API_Send) {
  using boost::chrono::seconds;

  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  auto& node_a = node_;
  auto& node_b = *nodes_[0];
  auto& node_c = *nodes_[1];

  // Before Bootstrap
  node_a.Send(node_b.node_id(), "message1");
  ASSERT_THROW_CODE(node_a.Send(node_b.node_id(), "message2").get(), RudpErrors::not_connected);

  // Before Add
  // Sending to bootstrap peer should succeed, sending to any other should fail.
  Contact chosen_node;
  ASSERT_NO_THROW(chosen_node = node_a.Bootstrap(bootstrap_endpoints_[0]).get());
  ASSERT_EQ(node_b.node_id(), chosen_node.id);

  // Send to non-bootstrap peer
  auto send_msg3 = node_a.Send(node_c.node_id(), "message3");
  auto send_msg4 = node_a.Send(node_c.node_id(), "message4");

  ASSERT_THROW_CODE(send_msg3.get(), RudpErrors::not_connected);
  ASSERT_THROW_CODE(send_msg4.get(), RudpErrors::not_connected);

  // Send to bootstrap peer
  node_b.ResetData();
  auto future_messages_at_peer = node_b.GetFutureForMessages(2);
  ASSERT_NO_THROW(node_a.Send(node_b.node_id(), "message5").get());
  ASSERT_NO_THROW(node_a.Send(node_b.node_id(), "message6").get());
  ASSERT_EQ(boost::future_status::ready, future_messages_at_peer.wait_for(seconds(200)));
  auto messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message5")));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message6")));

  // After Add
  node_c.ResetData();

  EndpointPair node_a_eps, node_c_eps;

  EXPECT_NO_THROW(node_a_eps = node_a.GetAvailableEndpoints(node_c.node_id()).get());
  EXPECT_NO_THROW(node_c_eps = node_c.GetAvailableEndpoints(node_a.node_id()).get());

  EXPECT_TRUE(detail::IsValid(node_a_eps.local));
  EXPECT_TRUE(detail::IsValid(node_c_eps.local));

  auto node_a_futures(node_a.GetFutureForMessages(1));
  auto node_c_futures(node_c.GetFutureForMessages(1));

  auto node_a_add = node_a.Add(node_c.make_contact(node_c_eps));
  auto node_c_add = node_c.Add(node_a.make_contact(node_a_eps));

  ASSERT_NO_THROW(node_a_add.get());
  ASSERT_NO_THROW(node_c_add.get());

//  ASSERT_EQ(boost::future_status::ready, node_c_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto peer_messages(node_c_futures.get());
//  ASSERT_EQ(boost::future_status::ready, node_a_futures.wait_for(boost_rendezvous_connect_timeout()));
//  auto this_node_messages(node_a_futures.get());
//  ASSERT_EQ(1U, peer_messages.size());
//  ASSERT_EQ(1U, this_node_messages.size());
//  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
//  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);
//
//// TODO:
//  // Unavailable node id
//  node_.ResetData();
//  nodes_[1]->ResetData();
//  node_.managed_connections()->Send(NodeId(NodeId::IdType::kRandomId), "message7",
//                                    MessageSentFunctor());
//  node_.managed_connections()->Send(NodeId(NodeId::IdType::kRandomId), "message8",
//                                    future_result.MakeContinuation());
//  ASSERT_TRUE(future_result.Wait(millis));
//  EXPECT_EQ(kInvalidConnection, future_result.Result());

  // Valid Send from node_ to nodes_[1]
  node_a.ResetData();
  node_c.ResetData();
  future_messages_at_peer = node_c.GetFutureForMessages(2);
  node_a.Send(node_c.node_id(), "message9").get();
  node_a.Send(node_c.node_id(), "message10").get();
  ASSERT_EQ(boost::future_status::ready, future_messages_at_peer.wait_for(seconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message9")));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message10")));

  // Valid Send from nodes_[1] to node_
  node_a.ResetData();
  node_c.ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(2);
  node_c.Send(node_a.node_id(), "message11").get();
  node_c.Send(node_a.node_id(), "message12").get();
  ASSERT_EQ(boost::future_status::ready, future_messages_at_peer.wait_for(seconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message11")));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), Node::str_to_msg("message12")));

  // After Remove
  node_a.ResetData();
  node_b.ResetData();
  node_a.Remove(node_b.node_id()).get();
  // FIXME: the Remove future should finish only after the node is removed.
  int count(0);
  do {
    Sleep(std::chrono::milliseconds(100));
    ++count;
  } while ((node_a.connection_lost_node_ids().empty() ||
            node_b.connection_lost_node_ids().empty() ||
            node_a.managed_connections()->GetActiveConnectionCount() != 2) &&
           count != 10);

  EXPECT_EQ(node_b.GetActiveConnectionCount(), 2);
  ASSERT_EQ(node_a.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(node_b.connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_a.connection_lost_node_ids()[0], node_b.node_id());

  node_a.ResetData();
  node_b.ResetData();
  ASSERT_THROW_CODE(node_a.Send(node_b.node_id(), "message13").get(), RudpErrors::not_connected);
  ASSERT_THROW_CODE(node_a.Send(node_b.node_id(), "message14").get(), RudpErrors::not_connected);

  // Valid large message
  node_a.ResetData();
  node_c.ResetData();
  auto sent_message = Node::str_to_msg(RandomString(ManagedConnections::MaxMessageSize()));
  future_messages_at_peer = node_.GetFutureForMessages(1);
  node_c.Send(node_a.node_id(), sent_message).get();
  ASSERT_EQ(boost::future_status::ready, future_messages_at_peer.wait_for(seconds(20)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(sent_message, messages[0]);

  // Excessively large message
  node_a.ResetData();
  node_c.ResetData();
  sent_message.push_back('1');
  ASSERT_THROW_CODE(node_c.Send(node_a.node_id(), sent_message).get(), RudpErrors::message_size);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ParallelSend) {
  using boost::chrono::seconds;

  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  auto& node_a = node_;
  auto& node_b = *nodes_[0];
  auto& node_c = *nodes_[1];

  // Bootstrap off node_b
  Contact chosen_node;
  ASSERT_NO_THROW(chosen_node = node_a.Bootstrap(bootstrap_endpoints_[0]).get());
  ASSERT_EQ(node_b.node_id(), chosen_node.id);

  // Connect node_ to nodes_[1]
  node_c.ResetData();
  EndpointPair node_a_eps, node_c_eps;

  ASSERT_NO_THROW(node_a_eps = node_a.GetAvailableEndpoints(node_c.node_id()).get());
  ASSERT_NO_THROW(node_c_eps = node_c.GetAvailableEndpoints(node_a.node_id()).get());

  auto node_a_add = node_a.Add(node_c.make_contact(node_c_eps));
  auto node_c_add = node_c.Add(node_a.make_contact(node_a_eps));

  ASSERT_NO_THROW(node_a_add.get());
  ASSERT_NO_THROW(node_c_add.get());

  // Prepare to send
  node_a.ResetData();
  node_c.ResetData();
  const int kMessageCount(10);
  ASSERT_LE(kMessageCount, std::numeric_limits<int8_t>::max());
  auto recv_futures(node_c.GetFutureForMessages(kMessageCount));
  std::vector<Node::message_t> sent_messages;
  for (int8_t i(0); i != kMessageCount; ++i)
    sent_messages.push_back(Node::str_to_msg(std::string(256 * 1024, 'A' + i)));

  std::vector<std::future<void>> send_futures;

  // Send and assess results
  for (int i(0); i != kMessageCount; ++i) {
    send_futures.push_back(node_a.Send(node_c.node_id(), sent_messages[i]));
  }

  for (auto& future : send_futures) future.get();

  ASSERT_EQ(boost::future_status::ready, recv_futures.wait_for(seconds(10 * kMessageCount)));

  auto messages(recv_futures.get());
  ASSERT_EQ(kMessageCount, messages.size());
  for (int i(0); i != kMessageCount; ++i)
    EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), sent_messages[i]));
}

TEST_F(ManagedConnectionsTest, FUNC_API_ParallelReceive) {
  using boost::chrono::seconds;
  using std::vector;
  using std::future;

  const int kNetworkSize(4);
  ASSERT_LE(kNetworkSize, std::numeric_limits<int8_t>::max());
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, kNetworkSize));

  // Bootstrap off nodes_[kNetworkSize - 1]
  Contact chosen_node;
  chosen_node = node_.Bootstrap(bootstrap_endpoints_[kNetworkSize - 1]).get();
  ASSERT_EQ(nodes_[kNetworkSize - 1]->node_id(), chosen_node.id);

  vector<NodeId> this_node_connections;
  // Connect node_ to all others
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Connecting to " + nodes_[i]->id());
    node_.ResetData();
    nodes_[i]->ResetData();
    EndpointPair this_endpoint_pair, peer_endpoint_pair;

    this_endpoint_pair = node_.GetAvailableEndpoints(nodes_[i]->node_id()).get();
    peer_endpoint_pair = nodes_[i]->GetAvailableEndpoints(node_.node_id()).get();

    auto this_node_add = node_.Add(nodes_[i]->make_contact(peer_endpoint_pair));
    auto that_node_add = nodes_[i]->Add(node_.make_contact(this_endpoint_pair));

    this_node_add.get();
    that_node_add.get();
  }

  // Prepare to send
  node_.ResetData();
  auto future_messages(node_.GetFutureForMessages(kNetworkSize - 1));
  vector<Node::message_t> sent_messages;
  vector<future<void>> send_futures;

  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Preparing to send from " + nodes_[i]->id());
    nodes_[i]->ResetData();
    auto message = Node::str_to_msg(std::string(256 * 1024, 'A' + static_cast<int8_t>(i)));
    sent_messages.push_back(message);
    send_futures.push_back(nodes_[i]->Send(node_.node_id(), message));
  }

  for (auto& future : send_futures) future.get();

  // Assess results
  ASSERT_EQ(boost::future_status::ready, future_messages.wait_for(seconds(10 * kNetworkSize)));
  auto messages(future_messages.get());
  ASSERT_EQ(kNetworkSize - 1, messages.size());
  for (int i(0); i != kNetworkSize - 1; ++i)
    EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), sent_messages[i]));
}

TEST_F(ManagedConnectionsTest, BEH_API_BootstrapTimeout) {

  Parameters::bootstrap_connection_lifespan = bptime::seconds(6);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  Contact chosen_node;
  ASSERT_NO_THROW(chosen_node = node_.Bootstrap(bootstrap_endpoints_[0]).get());
  ASSERT_TRUE(detail::IsValid(chosen_node.endpoint_pair.local));

//  FutureResult future_result;
  node_.ResetData();
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
  node_.Send(nodes_[0]->node_id(), "message01").get();

  ASSERT_EQ(boost::future_status::ready, future_messages_at_peer.wait_for(boost::chrono::milliseconds(200)));
  auto messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), Node::str_to_msg("message01"));

  // Send within bootstrap_disconnection_timeout period from nodes_[0] to node_
  node_.ResetData();
  nodes_[0]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(1);
  EndpointPair this_endpoint_pair;
  ASSERT_THROW_CODE(node_.GetAvailableEndpoints(nodes_[0]->node_id()).get(), RudpErrors::already_connected);
  nodes_[0]->Send(node_.node_id(), "message02").get();

  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), Node::str_to_msg("message02"));

// TODO: I think the below code no longer applies with the new API.
// If I understand it correctly a bootstrapped node no longer needs to be
// added using the Add function so it is no longer the case that it
// will be removed if Add is not called.
//
//  // Sleep for bootstrap_disconnection_timeout to allow connection to timeout and close
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  Sleep(std::chrono::milliseconds(Parameters::bootstrap_connection_lifespan.total_milliseconds()));
//  std::cerr << "----------------------- " << __LINE__ << "\n";
//  int count(0);
//  do {
//    Sleep(std::chrono::milliseconds(100));
//    ++count;
//  } while (
//      (node_.connection_lost_node_ids().empty() || nodes_[0]->connection_lost_node_ids().empty()) &&
//      count != 10);
//  Sleep(std::chrono::milliseconds(100));
//  ASSERT_EQ(1, node_.connection_lost_node_ids().size());
//  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
//  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());
//
//  // Send again in both directions - expect failure
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  node_.managed_connections()->Send(nodes_[0]->node_id(), "message03",
//                                    future_result.MakeContinuation());
//
//  ASSERT_TRUE(future_result.Wait(wait_millis));
//  EXPECT_EQ(kInvalidConnection, future_result.Result());
//
//  node_.ResetData();
//  nodes_[0]->ResetData();
//  nodes_[0]->managed_connections()->Send(node_.node_id(), "message04",
//                                         future_result.MakeContinuation());
//
//  ASSERT_TRUE(future_result.Wait(wait_millis));
//  EXPECT_EQ(kInvalidConnection, future_result.Result());
}

TEST_F(ManagedConnectionsTest, FUNC_API_ConcurrentGetAvailablesAndAdds) {
  using std::vector;
  using std::future;
  using std::string;
  using std::pair;

  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

   auto GetFuture = [](vector<NodePtr>& nodes, int x, int y) {
    return std::async([&nodes, x, y ]() -> pair<bool, string> {
      boost::this_thread::disable_interruption disable_interruption;
      Sleep(std::chrono::milliseconds(RandomUint32() % 100));
      auto debug_msg = string("GetAvailableEndpoint on ")
                     + nodes[x]->id() + " for " + nodes[y]->id();
      try {
        nodes[x]->GetAvailableEndpoints(nodes[y]->node_id()).get();
      }
      catch (std::system_error error) {
        if (error.code() != RudpErrors::already_connected) {
          return std::make_pair(false, debug_msg);
        }
      }
      return std::make_pair(true, debug_msg);
    });
  };

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
    vector<future<pair<bool, string>>> get_avail_ep_futures;  // NOLINT (Fraser)
    for (int i = 0; i != node_count; ++i) {
      Contact chosen_node;
      EXPECT_NO_THROW(chosen_node = nodes[i]->Bootstrap(bootstrap_endpoints_).get());

      EndpointPair node_i_eps, node_j_eps;

      for (int j = 0; j != i; ++j) {
        ASSERT_NO_THROW(node_i_eps = nodes[i]->GetAvailableEndpoints(nodes[j]->node_id()).get());
        ASSERT_NO_THROW(node_j_eps = nodes[j]->GetAvailableEndpoints(nodes[i]->node_id()).get());

        auto node_i_add = nodes[i]->Add(nodes[j]->make_contact(node_j_eps));
        auto node_j_add = nodes[j]->Add(nodes[i]->make_contact(node_i_eps));

        EXPECT_NO_THROW(node_i_add.get());
        EXPECT_NO_THROW(node_j_add.get());

        get_avail_ep_futures.push_back(GetFuture(nodes, i, j));
        get_avail_ep_futures.push_back(GetFuture(nodes, j, i));
      }
    }

    for (auto& get_avail_ep_future : get_avail_ep_futures) {
      std::pair<bool, std::string> result(get_avail_ep_future.get());
      if (result.first != true)
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
  Asio::io_service& _service;
  Asio::posix::stream_descriptor _h;

 public:
  typedef Asio::posix::stream_descriptor::native_handle_type native_handle_type;

 private:
  Asio::deadline_timer _timer;
  std::unique_ptr<Asio::io_service::work> _work;
  void _init(bool doTimer) {
    _h.async_read_some(Asio::null_buffers(),
                       std::bind(&input_watcher::data_available, this, std::placeholders::_1));
    if (doTimer) {
      _timer.async_wait(std::bind(&input_watcher::timed_out, this, std::placeholders::_1));
    }
  }

 protected:
  virtual void data_available(const boost::system::error_code&) = 0;
  virtual void timed_out(const boost::system::error_code&) { cancel(); };
  input_watcher(Asio::io_service& service, native_handle_type h)
      : _service(service),
        _h(service, h),
        _timer(service),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(false);
  }
  input_watcher(Asio::io_service& service, native_handle_type h, boost::posix_time::ptime timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(true);
  }
  input_watcher(Asio::io_service& service, native_handle_type h,
                boost::posix_time::time_duration timeout)
      : _service(service),
        _h(service, h),
        _timer(service, timeout),
        _work(maidsafe::make_unique<Asio::io_service::work>(service)) {
    _init(true);
  }

 public:
  ~input_watcher() { _h.release(); }
  Asio::io_service& service() { return _service; }
  native_handle_type handle() { return _h.native(); }
  Asio::deadline_timer& timer() { return _timer; }
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
//TEST_F(ManagedConnectionsTest, FUNC_API_500ParallelConnectionsWorker) {
//  const char* endpoints = std::getenv("MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS");
//  if (endpoints) {
//    bootstrap_endpoints_.clear();
//    for (const char* s = endpoints, * e = endpoints - 1; (s = e + 1, e = strchr(s, ';'));) {
//      const char* colon = strchr(s, ':');
//      if (!colon || colon > e) {
//        std::cout << "ERROR: Couldn't parse " << endpoints << " so exiting." << std::endl;
//        abort();
//      }
//      bootstrap_endpoints_.push_back(boost::Asio::ip::udp::endpoint(
//          boost::asio::ip::address::from_string(std::string(s, colon - s)),
//          (uint16_t)atoi(colon + 1)));
//      // std::cerr << "I have bootstrap endpoint " <<
//      // bootstrap_endpoints_.back().address().to_string() << ":" <<
//      // bootstrap_endpoints_.back().port() << std::endl;
//    }
//    std::string line;
//    do {
//      if (!std::getline(std::cin, line)) {
//        std::cout << "ERROR: Couldn't read from parent so exiting." << std::endl;
//        abort();
//      }
//    } while (line.compare(0, 8, "NODE_ID:"));
//    if (line[line.size() - 1] == 13)
//      line.resize(line.size() - 1);
//    const size_t my_id = atoi(line.substr(9).c_str());
//    Node node(static_cast<int>(my_id));
//    std::cout << "NODE_ID: " << node.node_id().ToStringEncoded(NodeId::EncodingType::kHex)
//              << std::endl;
//    NodeId chosen_node_id, peer_node_id;
//    ASSERT_EQ(kSuccess, node.Bootstrap(bootstrap_endpoints_, chosen_node_id));
//
//    std::atomic<bool> sender_thread_done(false);
//    std::mutex lock;
//    Asio::io_service service;
//    std::vector<NodeId> peer_node_ids;
//    size_t peer_node_ids_idx = 0, messages_sent = 0;
//    std::thread sender_thread([&] {
//      static std::string bleh(1500, 'n');
//      while (!sender_thread_done) {
//        std::this_thread::sleep_for(std::chrono::milliseconds(20));
//        std::lock_guard<decltype(lock)> g(lock);
//        if (peer_node_ids_idx < peer_node_ids.size()) {
//          node.managed_connections()->Send(peer_node_ids[peer_node_ids_idx], bleh,
//                                           [&](int) {  // NOLINT (Niall)
//            std::lock_guard<decltype(lock)> g(lock);
//            ++messages_sent;
//          });
//        }
//        if (++peer_node_ids_idx >= peer_node_ids.size())
//          peer_node_ids_idx = 0;
//      }
//    });
//    try {
//      for (;;) {
//        if (!std::getline(std::cin, line)) {
//          std::cout << "ERROR: Couldn't read from parent due to state=" << std::cin.rdstate()
//                    << " so exiting." << std::endl;
//          abort();
//        }
//        if (line[line.size() - 1] == 13)
//          line.resize(line.size() - 1);
//        if (!line.compare("QUIT"))
//          break;
//        if (!line.compare(0, 13, "ENDPOINT_FOR:")) {
//          NodeId peer_node_id(line.substr(14), NodeId::EncodingType::kHex);
//
//          EndpointPair empty_endpoint_pair, this_endpoint_pair;
//          NatType nat_type;
//
//          // std::cerr << my_id << ": Getting available endpoint for " <<
//          // peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex) << std::endl;
//          EXPECT_EQ(kSuccess, node.managed_connections()->GetAvailableEndpoint(
//                                  peer_node_id, empty_endpoint_pair, this_endpoint_pair, nat_type));
//          std::cout << "ENDPOINT: "
//                    << this_endpoint_pair.local.address().to_string() + ":" +
//                           std::to_string(this_endpoint_pair.local.port()) + ";"
//                    << this_endpoint_pair.external.address().to_string() + ":" +
//                           std::to_string(this_endpoint_pair.external.port()) + ";" << std::endl;
//          // std::cerr << my_id << ": Endpoint obtained (" << this_endpoint_pair.local.port() << ")"
//          // << std::endl;
//        } else if (!line.compare(0, 8, "CONNECT:")) {
//          const char* colon1 = strchr(line.c_str(), ';');
//          if (!colon1) {
//            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
//            abort();
//          }
//          const char* colon2 = strchr(colon1 + 1, ':');
//          if (!colon2) {
//            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
//            abort();
//          }
//          const char* colon3 = strchr(colon2 + 1, ';');
//          if (!colon3) {
//            std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
//            abort();
//          }
//          NodeId peer_node_id(std::string(line.c_str() + 9, colon1 - line.c_str() - 9),
//                              NodeId::EncodingType::kHex);
//          EndpointPair peer_endpoint_pair;
//          peer_endpoint_pair.local = boost::asio::ip::udp::endpoint(
//              boost::asio::ip::address::from_string(std::string(colon1 + 1, colon2 - colon1 - 1)),
//              (uint16_t)atoi(colon2 + 1));
//          auto fi = node.GetFutureForMessages(1);
//          // std::cerr << my_id << ": Adding connection to node " <<
//          // peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex)
//          //          << " at endpoint " << peer_endpoint_pair.local.address().to_string()+":" <<
//          //          peer_endpoint_pair.local.port()
//          //          << std::endl;
//          EXPECT_EQ(kSuccess, node.managed_connections()->Add(peer_node_id, peer_endpoint_pair,
//                                                              node.validation_data()));
//          // std::cerr << my_id << ": Waiting on future" << std::endl;
//          fi.get();
//          // std::cerr << my_id << ": Connected" << std::endl;
//          std::cout << "CONNECTED: " << peer_node_id.ToStringEncoded(NodeId::EncodingType::kHex)
//                    << std::endl;
//          std::lock_guard<decltype(lock)> g(lock);
//          peer_node_ids.push_back(peer_node_id);
//        } else if (!line.compare(0, 5, "STATS")) {
//          std::lock_guard<decltype(lock)> g(lock);
//          std::cout << "STATS: " << messages_sent << std::endl;
//        }
//      }
//    } catch (const std::exception& e) {
//      std::cout << "ERROR: Saw exception '" << e.what() << "' so exiting." << std::endl;
//    }
//    sender_thread_done = true;
//    sender_thread.join();
//  }
//}
//TEST_F(ManagedConnectionsTest, FUNC_API_500ParallelConnections) {
//  size_t node_count = 23, messages_sent_count = 100000;
//  const char* node_count_env = std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_NODE_COUNT");
//  if (node_count_env)
//    node_count = atoi(node_count_env);
//  const char* messages_sent_count_env =
//      std::getenv("MAIDSAFE_RUDP_TEST_PARALLEL_CONNECTIONS_MESSAGE_COUNT");
//  if (messages_sent_count_env)
//    messages_sent_count = atoi(messages_sent_count_env);
//  const auto self_path = ThisExecutablePath();
//  typedef boost::filesystem::path::string_type native_string;
//  const std::vector<native_string> args{
//      self_path.native(),
//#ifdef WIN32
//      L"--gtest_filter=ManagedConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
//#else
//      "--gtest_filter=ManagedConnectionsTest.FUNC_API_500ParallelConnectionsWorker"
//#endif
//  };
//
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
//  native_string endpoints(
//#ifdef WIN32
//      L"MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
//#else
//      "MAIDSAFE_RUDP_PARALLEL_CONNECTIONS_BOOTSTRAP_ENDPOINTS=");
//#endif
//  for (auto& i : bootstrap_endpoints_) {
//    auto temp = i.address().to_string();
//#ifdef WIN32
//    endpoints.append(native_string(temp.begin(), temp.end()) + L":" + std::to_wstring(i.port()) +
//                     L";");
//#else
//    endpoints.append(temp + ":" + std::to_string(i.port()) + ";");
//#endif
//  }
//  std::vector<native_string> env{endpoints};
//// Boost.Process won't inherit environment at the same time as do custom env,
//// so manually propagate our current environment into the custom environment.
//// Failure to propagate environment causes child processes to fail due to CryptoPP
//// refusing to initialise.
//#ifdef WIN32
//  for (const TCHAR* e = GetEnvironmentStrings(); *e; e++) {
//    env.push_back(e);
//    while (*e != 0)
//      e++;
//  }
//#else
//  for (char** e = environ; *e; ++e)
//    env.push_back(*e);
//#endif
//  auto getline = [](std::istream & is, input_watcher::native_handle_type h, std::string & str)
//      -> std::istream & {
//#ifdef WIN32
//    // Unfortunately Win32 anonymous pipe handles are a very special not-entirely-working
//    // form of HANDLE, indeed I personally never ever use them as named pipe handles work
//    // better, albeit not without their quirks/bugs either.
//    //
//    // So here I'm simply going to wait on the handle with timeout. I've wasted two days on
//    // debugging this already, sometimes the easy hack way is better than the right way ...
//    str.clear();
//    for (;;) {
//      char c;
//      if (is.rdbuf()->in_avail()) {
//        is.get(c);
//      } else {
//        if (WAIT_TIMEOUT == WaitForSingleObject(h, 30000)) {
//          is.setstate(std::ios::badbit);
//          return is;
//        }
//        is.get(c);
//      }
//      if (c == 10)
//        break;
//      else
//        str.push_back(c);
//    }
//#else
//    Asio::io_service service;
//    str.clear();
//    for (;;) {
//      char c;
//      if (is.rdbuf()->in_avail()) {
//        is.get(c);
//      } else {
//        // Wait no more than ten seconds for something to turn up
//        struct watcher : input_watcher {
//          bool have_data;
//          watcher(Asio::io_service& service, input_watcher::native_handle_type h)
//              : input_watcher(service, h, boost::posix_time::seconds(30)), have_data(false) {}
//          virtual void data_available(const boost::system::error_code& ec) {
//            if (!ec)
//              have_data = true;
//            cancel();
//          }
//        } w(service, h);
//        service.run();
//        if (!w.have_data) {
//          is.setstate(std::ios::badbit);
//          return is;
//        }
//        is.get(c);
//      }
//      if (c == 10)
//        break;
//      else
//        str.push_back(c);
//    }
//#endif
//    if (str[str.size() - 1] == 13)
//      str.resize(str.size() - 1);
//    return is;
//  };
//
//  std::vector<boost::process::child> children;
//  // Try to make sure that we don't ever leave zombie child processes around
//  struct child_deleter {
//    void operator()(boost::iostreams::stream<boost::iostreams::file_descriptor_sink>* c) const {
//      *c << "QUIT" << std::endl;
//      delete c;
//    }
//  };
//  std::vector<
//      std::pair<std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>,
//                std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
//                                child_deleter>>> childpipes;
//  children.reserve(node_count);
//  childpipes.reserve(node_count);
//  try {
//    for (size_t n = 0; n < node_count; n++) {
//      boost::system::error_code ec;
//      auto childin = boost::process::create_pipe(), childout = boost::process::create_pipe();
//      boost::iostreams::file_descriptor_sink sink(childin.sink, boost::iostreams::close_handle);
//      boost::iostreams::file_descriptor_source source(childout.source,
//                                                      boost::iostreams::close_handle);
//      children.push_back(boost::process::execute(boost::process::initializers::run_exe(self_path),
//                                                 boost::process::initializers::set_args(args),
//                                                 boost::process::initializers::set_env(env),
//                                                 boost::process::initializers::bind_stdin(source),
//                                                 boost::process::initializers::bind_stdout(sink),
//                                                 boost::process::initializers::set_on_error(ec)));
//      if (ec) {
//        GTEST_FAIL() << "Failed to launch child " << n << " due to error code " << ec << ".";
//        return;
//      }
//      childpipes.push_back(std::make_pair(
//          maidsafe::make_unique<boost::iostreams::stream<boost::iostreams::file_descriptor_source>>(
//              childin.source, boost::iostreams::never_close_handle),
//          std::unique_ptr<boost::iostreams::stream<boost::iostreams::file_descriptor_sink>,
//                          child_deleter>(
//              new boost::iostreams::stream<boost::iostreams::file_descriptor_sink>(
//                  childout.sink,
//                  boost::iostreams::never_close_handle))  // libstdc++ hasn't implemented the custom
//                                                          // deleter implicit conversions for some
//                                                          // weird reason
//          ));                                             // NOLINT (Niall)
//      *childpipes.back().second << "NODE_ID: " << n << std::endl;
//    }
//    // Prepare to connect node_count nodes to one another, making node_count*(node_count-1) total
//    // connections
//    std::vector<std::pair<size_t, size_t>> execution_order;
//    std::vector<NodeId> child_nodeids;
//    child_nodeids.reserve(node_count);
//    for (size_t n = 0; n < node_count; n++) {
//      boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipes[n].first;
//      for (;;) {
//        std::string line;
//        // ASIO gets upset if the pipe isn't opened on the other side, so use getline for this round
//        if (!std::getline(is, line)) {
//          GTEST_FAIL() << "Failed to read from child " << n << ".";
//          return;
//        }
//        if (line[line.size() - 1] == 13)
//          line.resize(line.size() - 1);
//        if (!line.compare(0, 6, "ERROR:")) {
//          GTEST_FAIL() << "Failed to launch child " << n << " due to " << line << ".";
//          return;
//        }
//        if (!line.compare(0, 8, "NODE_ID:")) {
//          // std::cout << "Child " << n << " returns node id " << line.substr(9) << std::endl;
//          child_nodeids.push_back(NodeId(line.substr(9), NodeId::EncodingType::kHex));
//          break;
//        } else if (line[0] != '[' && !strstr(line.c_str(), "Google Test filter")) {
//          std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
//        }
//      }
//      // std::cout << "Child " << n << " has node id " <<
//      //  child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex) << std::endl;
//      for (size_t i = 0; i < n; i++) {
//        execution_order.push_back(std::make_pair(n, i));
//      }
//    }
//    // child_nodeids[n] contains a map of child processes to NodeId
//    // child_endpoints[n][i*2] is the endpoint of childprocess n to childprocess i
//    // child_endpoints[n][i*2+1] is the endpoint of childprocess i to childprocess n
//    std::vector<std::vector<EndpointPair>> child_endpoints;
//    child_endpoints.resize(node_count);
//    for (auto& i : child_endpoints)
//      i.resize((node_count - 1) * 2);
//    // We need execution order to maximise distance between each x,x and y,y in each (x,y) pair
//    // such that concurrency is maximised. That is the CPU instruction scheduling problem which
//    // requires the solution of an unbalanced graph via iterating rebalancing according to longest
//    // path analysis, and it has O(N!) complexity with a non-trivial implementation. So here is a
//    // poorer quality O(N^2) complexity alternative with a much simpler implementation. It doesn't
//    // produce perfect ordering, but it's close enough and doesn't require more code than the whole
//    // of this test case.
//    {
//      std::deque<std::pair<size_t, size_t>> list(std::make_move_iterator(execution_order.begin()),
//                                                 std::make_move_iterator(execution_order.end())),
//          prevline, line;
//      execution_order.clear();
//      std::reverse(list.begin(), list.end());
//      do {
//        prevline = std::move(line);
//        // Choose a starting value as far away as possible from any collision in the previous line
//        if (prevline.empty()) {
//          line.push_back(std::move(list.back()));
//          list.pop_back();
//        } else {
//          do {
//            prevline.pop_front();
//            for (auto it = list.begin(); it != list.end(); ++it) {
//              bool bad = false;
//              for (auto& b : prevline) {
//                if (it->first == b.first || it->second == b.first || it->first == b.second ||
//                    it->second == b.second) {
//                  bad = true;
//                  break;
//                }
//              }
//              if (!bad) {
//                line.push_back(std::move(*it));
//                list.erase(it);
//                break;
//              }
//            }
//          } while (line.empty());
//        }
//        // Append all values not colliding into this line
//        for (auto it = list.begin(); it != list.end();) {
//          bool bad = false;
//          for (auto& b : line) {
//            if (it->first == b.first || it->second == b.first || it->first == b.second ||
//                it->second == b.second) {
//              bad = true;
//              break;
//            }
//          }
//          if (!bad) {
//            line.push_back(std::move(*it));
//            it = list.erase(it);
//          } else {
//            ++it;
//          }
//        }
//        // Copy line into output
//        execution_order.insert(execution_order.end(), line.begin(), line.end());
//      } while (!list.empty());
//    }
//    // std::cout << "Execution order will be: ";
//    // for (auto& o : execution_order)
//    //   std::cout << "[" << o.first << ", " << o.second << "], ";
//    // std::cout << std::endl;
//    size_t connection_count = 0;
//    for (auto& o : execution_order) {
//      EndpointPair endpoint;
//      size_t n, i;
//      std::tie(n, i) = o;
//      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os1 = *childpipes[n].second;
//      boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os2 = *childpipes[i].second;
//      os1 << "ENDPOINT_FOR: " << child_nodeids[i].ToStringEncoded(NodeId::EncodingType::kHex)
//          << std::endl;
//      os2 << "ENDPOINT_FOR: " << child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex)
//          << std::endl;
//      // std::cout << "Asking child " << n << " for endpoint to child " << i << std::endl;
//      // std::cout << "Asking child " << i << " for endpoint to child " << n << std::endl;
//      auto drain_endpoint = [&](size_t a) {
//        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
//            *childpipes[a].first;
//        // std::cout << "drain_endpoint(" << a << ")" << std::endl;
//        for (;;) {
//          std::string line;
//          if (!getline(is, is->handle(), line)) {
//            return false;
//          }
//          if (!line.compare(0, 9, "ENDPOINT:")) {
//            bool first = true;
//            for (const char* s, * e = line.c_str() + 9; (s = e + 1, e = strchr(s, ';'));
//                 first = false) {
//              const char* colon = strchr(s, ':');
//              if (!colon || colon > e) {
//                std::cout << "ERROR: Couldn't parse " << line << " so exiting." << std::endl;
//                abort();
//              }
//              (first ? endpoint.local : endpoint.external)
//                  .address(boost::asio::ip::address::from_string(std::string(s, colon - s)));
//              (first ? endpoint.local : endpoint.external).port((uint16_t)atoi(colon + 1));
//            }
//            // std::cout << "Child " << a << " returns endpoints " << line.substr(10) << std::endl;
//            return true;
//          } else if (line[0] != '[') {
//            std::cout << "Child " << a << " sends me unknown line '" << line << "'\n";
//          }
//        }
//      };
//      if (!drain_endpoint(n)) {
//        GTEST_FAIL() << "Failed to read from child " << n << ".";
//        return;
//      }
//      child_endpoints[n][i * 2] = endpoint;
//      if (!drain_endpoint(i)) {
//        GTEST_FAIL() << "Failed to read from child " << i << ".";
//        return;
//      }
//      child_endpoints[n][i * 2 + 1] = endpoint;
//
//      os1 << "CONNECT: " << child_nodeids[i].ToStringEncoded(NodeId::EncodingType::kHex) << ";"
//          << child_endpoints[n][i * 2 + 1].local.address().to_string() + ":"
//          << child_endpoints[n][i * 2 + 1].local.port() << ";" << std::endl;
//      os2 << "CONNECT: " << child_nodeids[n].ToStringEncoded(NodeId::EncodingType::kHex) << ";"
//          << child_endpoints[n][i * 2].local.address().to_string() + ":"
//          << child_endpoints[n][i * 2].local.port() << ";" << std::endl;
//      auto drain_connect = [&](size_t a) {
//        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is =
//            *childpipes[a].first;
//        // std::cout << "drain_connect(" << a << ")" << std::endl;
//        for (;;) {
//          std::string line;
//          if (!getline(is, is->handle(), line)) {
//            return false;
//          }
//          if (!line.compare(0, 10, "CONNECTED:")) {
//            // std::cout << "Child " << a << " is connected to " << line.substr(11) << std::endl;
//            ++connection_count;
//            return true;
//          } else if (line[0] != '[') {
//            std::cout << "Child " << a << " sends me unknown line '" << line << "'" << std::endl;
//          }
//        }
//      };
//      if (!drain_connect(n)) {
//        GTEST_FAIL() << "Failed to read from child " << n << ".";
//        return;
//      }
//      if (!drain_connect(i)) {
//        GTEST_FAIL() << "Failed to read from child " << i << ".";
//        return;
//      }
//    }
//
//    std::cout << node_count << " nodes connected with " << connection_count << " connections."
//              << std::endl;
//
//    size_t messages_sent = 0;
//    do {
//      std::this_thread::sleep_for(std::chrono::seconds(5));
//      for (auto& childpipe : childpipes) {
//        boost::iostreams::stream<boost::iostreams::file_descriptor_sink>& os = *childpipe.second;
//        os << "STATS" << std::endl;
//      }
//      messages_sent = 0;
//      size_t n = 0;
//
//      for (auto& childpipe : childpipes) {
//        boost::iostreams::stream<boost::iostreams::file_descriptor_source>& is = *childpipe.first;
//        for (;;) {
//          std::string line;
//          if (!getline(is, is->handle(), line)) {
//            GTEST_FAIL() << "Failed to read from child " << n << ".";
//            return;
//          }
//          if (!line.compare(0, 6, "STATS:")) {
//            messages_sent += atoi(line.substr(7).c_str());
//            break;
//          } else if (line[0] != '[') {
//            std::cout << "Child " << n << " sends me unknown line '" << line << "'" << std::endl;
//          }
//        }
//        ++n;
//      }
//      std::cout << "Children have now sent " << messages_sent << " messages." << std::endl;
//    } while (messages_sent < messages_sent_count);
//  } catch (const std::exception& e) {
//    GTEST_FAIL() << "Exception thrown '" << e.what() << "'.";
//  }
//
//  // Shutdown children
//  childpipes.clear();
//  for (size_t n = 0; n < node_count; n++) {
//    boost::system::error_code ec;
//    // std::cout << "Waiting for child " << n << " to exit" << std::endl;
//    boost::process::wait_for_exit(children[n], ec);
//  }
//}
//#ifdef _MSC_VER
//#pragma warning(pop)
//#endif

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
