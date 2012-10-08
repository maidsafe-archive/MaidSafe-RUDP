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
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace test {


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

  void BootstrapAndAdd(size_t index,
                       NodeId& chosen_node,
                       EndpointPair& this_endpoint_pair,
                       NatType& nat_type) {
    ASSERT_EQ(kSuccess,
              node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[index]), chosen_node));
    ASSERT_EQ(nodes_[index]->node_id(), chosen_node);
    Sleep(boost::posix_time::milliseconds(250));
    nodes_[index]->ResetData();

    EXPECT_EQ(kSuccess,
              node_.managed_connections()->GetAvailableEndpoint(nodes_[index]->node_id(),
                                                                EndpointPair(),
                                                                this_endpoint_pair,
                                                                nat_type));
    EndpointPair peer_endpoint_pair;
    EXPECT_EQ(kSuccess,
              nodes_[index]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                         this_endpoint_pair,
                                                                         peer_endpoint_pair,
                                                                         nat_type));
    EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

    auto peer_futures(nodes_[index]->GetFutureForMessages(1));
    auto this_node_futures(node_.GetFutureForMessages(1));
    EXPECT_EQ(kSuccess,
              nodes_[index]->managed_connections()->Add(node_.node_id(),
                                                        this_endpoint_pair,
                                                        nodes_[index]->validation_data()));
    EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[index]->node_id(),
                                                         peer_endpoint_pair,
                                                         node_.validation_data()));
    ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
    auto peer_messages(peer_futures.get());
    ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
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
  EXPECT_EQ(kInvalidParameter, node_.managed_connections()->Bootstrap(std::vector<Endpoint>(),
                                                                      MessageReceivedFunctor(),
                                                                      ConnectionLostFunctor(),
                                                                      NodeId(),
                                                                      nullptr,
                                                                      nullptr,
                                                                      chosen_bootstrap,
                                                                      nat_type));
  // Empty bootstrap_endpoints
  EXPECT_EQ(kNoBootstrapEndpoints,
            node_.managed_connections()->Bootstrap(std::vector<Endpoint>(),
                                                   do_nothing_on_message_,
                                                   do_nothing_on_connection_lost_,
                                                   node_.node_id(),
                                                   node_.private_key(),
                                                   node_.public_key(),
                                                   chosen_bootstrap,
                                                   nat_type));
  // FIXME
  // Unavailable bootstrap_endpoints
  EXPECT_EQ(kTransportStartFailure,
            node_.managed_connections()->Bootstrap(std::vector<Endpoint>(1,
                                                                         Endpoint(GetLocalIp(),
                                                                                  10000)),
                                                   do_nothing_on_message_,
                                                   do_nothing_on_connection_lost_,
                                                   node_.node_id(),
                                                   node_.private_key(),
                                                   node_.public_key(),
                                                   chosen_bootstrap,
                                                   nat_type));
  // Invalid MessageReceivedFunctor
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                   MessageReceivedFunctor(),
                                                   do_nothing_on_connection_lost_,
                                                   node_.node_id(),
                                                   node_.private_key(),
                                                   node_.public_key(),
                                                   chosen_bootstrap,
                                                   nat_type));
  // Invalid ConnectionLostFunctor
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                   do_nothing_on_message_,
                                                   ConnectionLostFunctor(),
                                                   node_.node_id(),
                                                   node_.private_key(),
                                                   node_.public_key(),
                                                   chosen_bootstrap,
                                                   nat_type));
  // Invalid private key
  EXPECT_EQ(kInvalidParameter, node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_,
                do_nothing_on_message_,
                do_nothing_on_connection_lost_,
                node_.node_id(),
                std::shared_ptr<asymm::PrivateKey>(new asymm::PrivateKey),
                node_.public_key(),
                chosen_bootstrap,
                nat_type));
  // Invalid public key
  EXPECT_EQ(kInvalidParameter, node_.managed_connections()->Bootstrap(
                bootstrap_endpoints_,
                do_nothing_on_message_,
                do_nothing_on_connection_lost_,
                node_.node_id(),
                node_.private_key(),
                std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey),
                chosen_bootstrap,
                nat_type));
  // NULL private key
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                   do_nothing_on_message_,
                                                   do_nothing_on_connection_lost_,
                                                   node_.node_id(),
                                                   nullptr,
                                                   node_.public_key(),
                                                   chosen_bootstrap,
                                                   nat_type));
  // NULL public key
  EXPECT_EQ(kInvalidParameter,
            node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                   do_nothing_on_message_,
                                                   do_nothing_on_connection_lost_,
                                                   node_.node_id(),
                                                   node_.private_key(),
                                                   nullptr,
                                                   chosen_bootstrap,
                                                   nat_type));
  // Valid
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                             do_nothing_on_message_,
                                                             do_nothing_on_connection_lost_,
                                                             node_.node_id(),
                                                             node_.private_key(),
                                                             node_.public_key(),
                                                             chosen_bootstrap,
                                                             nat_type));
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
            node_.managed_connections()->GetAvailableEndpoint(NodeId(NodeId::kRandomId),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EndpointPair endpoint_pair;
  endpoint_pair.local = endpoint_pair.external =
          Endpoint(ip::address::from_string("1.2.3.4"), 1026);
  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                NodeId(NodeId::kRandomId),
                endpoint_pair,
                this_endpoint_pair,
                nat_type));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  //  After Bootstrapping
  NodeId chosen_node;
  nat_type = NatType::kUnknown;
  EXPECT_EQ(kSuccess, node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                             do_nothing_on_message_,
                                                             do_nothing_on_connection_lost_,
                                                             node_.node_id(),
                                                             node_.private_key(),
                                                             node_.public_key(),
                                                             chosen_node,
                                                             nat_type));
  EXPECT_FALSE(chosen_node.IsZero());
//  EXPECT_NE(bootstrap_endpoints_.end(),
//            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(), chosen_endpoint));

  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(chosen_node,
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));

  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(NodeId(NodeId::kRandomId),
                                                              EndpointPair(),
                                                              another_endpoint_pair,
                                                              nat_type));
  EXPECT_TRUE(detail::IsValid(another_endpoint_pair.local));
  EXPECT_NE(this_endpoint_pair.local, another_endpoint_pair.local);
}

TEST_F(ManagedConnectionsTest, BEH_API_PendingTransportPruning) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 8));

  std::string message("message1");
  NodeId chosen_node;
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  BootstrapAndAdd(0, chosen_node, this_endpoint_pair, nat_type);
  LOG(kInfo) << "Setup finished...\n\n\n";

  // Run GetAvailableEndpoint to Node 1 to add a transport to pendings_
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));

  // Wait for rendezvous_connect_timeout, then send 3 messages to node 0 to clear the pending,
  // which should allow for another GetAvailableEndpoint to be run. Intermediate calls
  // should return with kConnectAttemptAlreadyRunning
  boost::posix_time::time_duration wait(Parameters::rendezvous_connect_timeout);
  wait = wait + boost::posix_time::milliseconds(100);
  Sleep(Parameters::rendezvous_connect_timeout);
  node_.ResetData();
  int messages_sent(0);
  std::condition_variable cond_var;
  std::mutex mutex;
  MessageSentFunctor message_sent_functor([&] (int result_in) {
                                            std::lock_guard<std::mutex> lock(mutex);
                                            if (result_in == kSuccess)
                                              ++messages_sent;
                                            cond_var.notify_one();
                                          });
  auto wait_for_result([&] ()->bool {
    std::unique_lock<std::mutex> lock(mutex);
    return cond_var.wait_for(lock,
                             std::chrono::milliseconds(1000),
                             [&messages_sent]() { return messages_sent == 3; });  // NOLINT (Fraser)
  });

  EndpointPair test_endpoint_pair;
  for (int n(0); n != 3; ++n) {
    EXPECT_EQ(kSuccess,
              node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                                EndpointPair(),
                                                                test_endpoint_pair,
                                                                nat_type));
    EXPECT_EQ(this_endpoint_pair.external, test_endpoint_pair.external);
    EXPECT_EQ(this_endpoint_pair.local, test_endpoint_pair.local);
    nodes_[0]->managed_connections()->Send(node_.node_id(), message, message_sent_functor);
  }
  // Messages sent
  ASSERT_TRUE(wait_for_result());

  // Messages received
  std::condition_variable received_cond_var;
  std::mutex received_mutex;
  {
    std::unique_lock<std::mutex> loch(received_mutex);
    ASSERT_TRUE(received_cond_var.wait_for(loch,
                                           std::chrono::milliseconds(1000),
                                           [&] () {
                                             return node_.GetReceivedMessageCount(message) == 3;
                                           }));
  }

  // Running GetAvailableEndpoint to Node 1 to add a transport to pendings_ should succeed again
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Valid bootstrap
  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  EXPECT_FALSE(chosen_node.IsZero());
  Sleep(boost::posix_time::milliseconds(250));

  nodes_[0]->ResetData();
  EndpointPair peer_endpoint_pair0, peer_endpoint_pair2,
               this_endpoint_pair0, this_endpoint_pair1, this_endpoint_pair2;
  NatType nat_type0(NatType::kUnknown), nat_type1(NatType::kUnknown);
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair0,
                                                              nat_type1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                   this_endpoint_pair0,
                                                                   peer_endpoint_pair0,
                                                                   nat_type0));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair0.local));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair0.local));

  // Case: Own NodeId
  EXPECT_EQ(kOwnId, node_.managed_connections()->Add(node_.node_id(),
                                                     EndpointPair(),
                                                     node_.validation_data()));
  // Case: Empty endpoint
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(),
                                                       EndpointPair(),
                                                       node_.validation_data()));
  auto this_node_futures(node_.GetFutureForMessages(1));
  ASSERT_FALSE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));

  // Case: Inexistent endpoint
  EndpointPair random_peer_endpoint;
  random_peer_endpoint.local = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());
  random_peer_endpoint.external = Endpoint(GetLocalIp(), maidsafe::test::GetRandomPort());

  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair1,
                                                              nat_type1));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[1]->node_id(),
                                                       random_peer_endpoint,
                                                       node_.validation_data()));
  this_node_futures = node_.GetFutureForMessages(1);
  ASSERT_FALSE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));

  // Case: Success
  node_.ResetData();
  nodes_[2]->ResetData();
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[2]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair2,
                                                              nat_type1));
  EXPECT_EQ(kSuccess,
            nodes_[2]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                   this_endpoint_pair2,
                                                                   peer_endpoint_pair2,
                                                                   nat_type0));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair2.local));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair2.local));
  auto peer_futures(nodes_[2]->GetFutureForMessages(1));
  this_node_futures = node_.GetFutureForMessages(1);
  EXPECT_EQ(kSuccess, nodes_[2]->managed_connections()->Add(node_.node_id(),
                                                            this_endpoint_pair2,
                                                            nodes_[2]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[2]->node_id(),
                                                       peer_endpoint_pair2,
                                                       node_.validation_data()));
  EXPECT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  EXPECT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto this_node_messages(this_node_futures.get());
  EXPECT_EQ(1, peer_messages.size());
  EXPECT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[2]->validation_data(), this_node_messages[0]);
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 4));
  auto wait_for_signals([&](int node_index)->bool {
    int count(0);
    do {
      Sleep(bptime::milliseconds(100));
      ++count;
    } while ((node_.connection_lost_node_ids().empty() ||
             nodes_[node_index]->connection_lost_node_ids().empty()) &&
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
  node_.managed_connections()->Remove(chosen_node);
  ASSERT_TRUE(wait_for_signals(1));
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[1]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(chosen_node, node_.connection_lost_node_ids()[0]);

  // After Add
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);
  nodes_[0]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  Sleep(boost::posix_time::milliseconds(250));
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(chosen_node,
                                                                        EndpointPair(),
                                                                        this_endpoint_pair,
                                                                        nat_type));
  EXPECT_EQ(kSuccess, nodes_[0]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                             this_endpoint_pair,
                                                                             peer_endpoint_pair,
                                                                             nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess, nodes_[0]->managed_connections()->Add(node_.node_id(),
                                                            this_endpoint_pair,
                                                            nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess, node_.managed_connections()->Add(nodes_[0]->node_id(),
                                                       peer_endpoint_pair,
                                                       node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
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
  ASSERT_FALSE(wait_for_signals(0));
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());

  // Unknown endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[2]->node_id());
  ASSERT_FALSE(wait_for_signals(2));
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[2]->connection_lost_node_ids().empty());

  // Valid
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[0]->node_id());
  ASSERT_TRUE(wait_for_signals(0));
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());
  EXPECT_EQ(nodes_[0]->connection_lost_node_ids()[0], node_.node_id());

  // Already removed endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(nodes_[0]->node_id());
  ASSERT_FALSE(wait_for_signals(0));
  EXPECT_TRUE(node_.connection_lost_node_ids().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_node_ids().empty());
}

TEST_F(ManagedConnectionsTest, BEH_API_SimpleSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  int result_of_send(kSuccess);
  int result_arrived_count(0);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  MessageSentFunctor message_sent_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    ++result_arrived_count;
    cond_var.notify_one();
  });
  auto wait_for_result([&](int count) {
    return cond_var.wait_for(lock,
                             std::chrono::seconds(10),
                             [&]() { return result_arrived_count == count; });  // NOLINT (Fraser)
  });

  NodeId chosen_node;
  EXPECT_EQ(kSuccess,
            node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]), chosen_node));
  ASSERT_EQ(nodes_[0]->node_id(), chosen_node);

  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                   this_endpoint_pair,
                                                                   peer_endpoint_pair,
                                                                   nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(node_.node_id(),
                                                  this_endpoint_pair,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(nodes_[1]->node_id(),
                                             peer_endpoint_pair,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  node_.ResetData();
  nodes_[1]->ResetData();
  const int kRepeatCount(10);
  peer_futures = nodes_[1]->GetFutureForMessages(kRepeatCount);
  const std::string kMessage(RandomAlphaNumericString(256 * 1024));
  for (int i(0); i != kRepeatCount; ++i)
    node_.managed_connections()->Send(nodes_[1]->node_id(), kMessage, message_sent_functor);

  ASSERT_TRUE(wait_for_result(kRepeatCount));
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(120)));
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
  bool result_arrived(false);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  MessageSentFunctor message_sent_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    result_arrived = true;
    cond_var.notify_one();
  });
  auto wait_for_result([&] {
    return cond_var.wait_for(lock,
                             std::chrono::milliseconds(100),
                             [&result_arrived]() { return result_arrived; });  // NOLINT (Fraser)
  });

  result_of_send = kSuccess;
  result_arrived = false;
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
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message4", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
  // Send to bootstrap peer
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(2));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message5", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message6", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  auto messages(future_messages_at_peer.get());
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message5"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message6"));

  // After Add
  nodes_[1]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                   this_endpoint_pair,
                                                                   peer_endpoint_pair,
                                                                   nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(node_.node_id(),
                                                  this_endpoint_pair,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(nodes_[1]->node_id(),
                                             peer_endpoint_pair,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Unavailable node id
  node_.ResetData();
  nodes_[1]->ResetData();
  node_.managed_connections()->Send(NodeId(NodeId::kRandomId),
                                    "message7",
                                    MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(NodeId(NodeId::kRandomId),
                                    "message8",
                                    message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid Send from node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = nodes_[1]->GetFutureForMessages(2);
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message9", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  node_.managed_connections()->Send(nodes_[1]->node_id(), "message10", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message9"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message10"));

  // Valid Send from nodes_[1] to node_
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(2);
  nodes_[1]->managed_connections()->Send(node_.node_id(), "message11",
                                         MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(node_.node_id(), "message12",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
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
    Sleep(bptime::milliseconds(100));
    ++count;
  } while ((node_.connection_lost_node_ids().empty() ||
            nodes_[0]->connection_lost_node_ids().empty()) &&
            count != 10);
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());

  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message13", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message14", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid large message
  node_.ResetData();
  nodes_[1]->ResetData();
  std::string sent_message(std::move(RandomString(8 * 1024 * 1024)));
  future_messages_at_peer = node_.GetFutureForMessages(1);
  result_of_send = kConnectError;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(node_.node_id(),
                                         sent_message,
                                         message_sent_functor);
  ASSERT_TRUE(cond_var.wait_for(lock,
                                std::chrono::seconds(20),
                                [&result_arrived]() { return result_arrived; }));  // NOLINT (Fraser)
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::seconds(20)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(sent_message, messages[0]);

  // Excessively large message
  node_.ResetData();
  nodes_[1]->ResetData();
  sent_message = std::move(RandomString(ManagedConnections::kMaxMessageSize() + 1));
  result_of_send = kSuccess;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(node_.node_id(),
                                         sent_message,
                                         message_sent_functor);
  ASSERT_TRUE(cond_var.wait_for(lock,
                                std::chrono::seconds(10),
                                [&result_arrived]() { return result_arrived; }));  // NOLINT (Fraser)
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
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(nodes_[1]->node_id(),
                                                              EndpointPair(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                   this_endpoint_pair,
                                                                   peer_endpoint_pair,
                                                                   nat_type));
  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(node_.node_id(),
                                                  this_endpoint_pair,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(nodes_[1]->node_id(),
                                             peer_endpoint_pair,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
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
  int result_of_send(kConnectError);
  int result_arrived_count(0);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  MessageSentFunctor message_sent_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    ++result_arrived_count;
    cond_var.notify_one();
  });
  auto wait_for_result([&] {
    return cond_var.wait_for(lock,
                             std::chrono::seconds(20),
                             [kMessageCount, &result_arrived_count] {
                               return result_arrived_count == kMessageCount;
                             });
  });

  // Send and assess results
  for (int i(0); i != kMessageCount; ++i) {
    node_.managed_connections()->Send(nodes_[1]->node_id(),
                                      sent_messages[i],
                                      message_sent_functor);
  }
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::seconds(10 * kMessageCount)));
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
    EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(nodes_[i]->node_id(),
                                                                          EndpointPair(),
                                                                          this_endpoint_pair,
                                                                          nat_type));
    EXPECT_EQ(kSuccess,
              nodes_[i]->managed_connections()->GetAvailableEndpoint(node_.node_id(),
                                                                     this_endpoint_pair,
                                                                     peer_endpoint_pair,
                                                                     nat_type));
    auto peer_futures(nodes_[i]->GetFutureForMessages(1));
    auto this_node_futures(node_.GetFutureForMessages(1));
    EXPECT_EQ(kSuccess,
              nodes_[i]->managed_connections()->Add(node_.node_id(),
                                                    this_endpoint_pair,
                                                    nodes_[i]->validation_data()));
    EXPECT_EQ(kSuccess,
              node_.managed_connections()->Add(nodes_[i]->node_id(),
                                               peer_endpoint_pair,
                                               node_.validation_data()));
    ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
    auto peer_messages(peer_futures.get());
    ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
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
  int results_arrived_count(0);
  std::condition_variable cond_var;
  std::mutex mutex;
  for (int8_t i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Preparing to send from " + nodes_[i]->id());
    nodes_[i]->ResetData();
    sent_messages.push_back(std::string(256 * 1024, 'A' + i));
    message_sent_functors.push_back([&, i](int result_in) {
      std::lock_guard<std::mutex> lock(mutex);
      result_of_sends[i] = result_in;
      ++results_arrived_count;
      cond_var.notify_one();
    });
  }

  std::unique_lock<std::mutex> lock(mutex);
  auto wait_for_result([&] {
    return cond_var.wait_for(lock,
                             std::chrono::seconds(20),
                             [kNetworkSize, &results_arrived_count] {
                               return results_arrived_count == kNetworkSize - 1;
                             });
  });

  // Perform sends
  std::vector<boost::thread> threads(kNetworkSize);
  for (int i(0); i != kNetworkSize - 1; ++i) {
    threads[i] = boost::thread(&ManagedConnections::Send,
                               nodes_[i]->managed_connections().get(),
                               node_.node_id(),
                               sent_messages[i],
                               message_sent_functors[i]);
  }
  for (boost::thread& thread : threads)
    thread.join();

  // Assess results
  ASSERT_TRUE(wait_for_result());
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Assessing results of sending from " + nodes_[i]->id());
    EXPECT_EQ(kSuccess, result_of_sends[i]);
  }
  ASSERT_TRUE(future_messages.timed_wait(bptime::seconds(10 * kNetworkSize)));
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
  int result_of_send(kConnectError);
  bool result_arrived(false);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  MessageSentFunctor message_sent_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    result_arrived = true;
    cond_var.notify_one();
  });
  auto wait_for_result([&] {
    return cond_var.wait_for(lock,
                             std::chrono::milliseconds(100),
                             [&result_arrived]() { return result_arrived; });  // NOLINT (Fraser)
  });
  node_.ResetData();
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message01", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  auto messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), "message01");

  // Send within bootstrap_disconnection_timeout period from nodes_[0] to node_
  node_.ResetData();
  nodes_[0]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(1);
  result_of_send = kConnectError;
  result_arrived = false;
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(nodes_[0]->node_id(),
                                                                        EndpointPair(),
                                                                        this_endpoint_pair,
                                                                        nat_type));
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message02",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(1U, messages.size());
  EXPECT_EQ(*messages.begin(), "message02");

  // Sleep for bootstrap_disconnection_timeout to allow connection to timeout and close
  node_.ResetData();
  nodes_[0]->ResetData();
  boost::this_thread::sleep(Parameters::bootstrap_connection_lifespan);
  int count(0);
  do {
    Sleep(bptime::milliseconds(100));
    ++count;
  } while ((node_.connection_lost_node_ids().empty() ||
            nodes_[0]->connection_lost_node_ids().empty()) &&
            count != 10);
  ASSERT_EQ(node_.connection_lost_node_ids().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_node_ids().size(), 1U);
  EXPECT_EQ(node_.connection_lost_node_ids()[0], nodes_[0]->node_id());

  // Send again in both directions - expect failure
  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(nodes_[0]->node_id(), "message03", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  nodes_[0]->managed_connections()->Send(node_.node_id(), "message04",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
}

/*
TEST_F(ManagedConnectionsTest, DISABLED_BEH_API_Ping) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Without valid functor
  node_.managed_connections()->Ping(bootstrap_endpoints_[0], PingFunctor());

  // Before Bootstrap
  int result_of_ping(kSuccess);
  bool result_arrived(false);
  std::condition_variable cond_var;
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  PingFunctor ping_functor([&](int result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_ping = result_in;
    result_arrived = true;
    cond_var.notify_one();
  });
  auto wait_for_result([&] {
    return cond_var.wait_for(
        lock,
        std::chrono::milliseconds(Parameters::ping_timeout.total_milliseconds() + 1000),
        [&result_arrived]() { return result_arrived; });  // NOLINT (Fraser)
  });
  node_.managed_connections()->Ping(bootstrap_endpoints_[0], ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kNotBootstrapped, result_of_ping);

  // Before Add
  // Pinging bootstrap peer should fail since we're already connected, pinging ourself should fail
  // since that's madness, pinging any other existing peer should succeed.
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  ASSERT_EQ(bootstrap_endpoints_[0], chosen_endpoint);
  // Ping non-bootstrap peer
  result_of_ping = kPingFailed;
  result_arrived = false;
  node_.managed_connections()->Ping(bootstrap_endpoints_[2], ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_ping);
  // Ping ourself (get our existing transport's endpoint)
  EndpointPair this_endpoint_pair;
  NatType nat_type;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(bootstrap_endpoints_[0],
                                                              this_endpoint_pair,
                                                              nat_type));
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(this_endpoint_pair.local, ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kWontPingOurself, result_of_ping);
  // Ping bootstrap peer
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(bootstrap_endpoints_[0], ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kWontPingAlreadyConnected, result_of_ping);
  // Ping non-existent peer
  Endpoint unavailable_endpoint(ip::address::from_string("1.1.1.1"), maidsafe::test::GetRandomPort());
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(unavailable_endpoint, ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kPingFailed, result_of_ping);

  // After Add
  nodes_[1]->ResetData();
  EndpointPair peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(),
                                                              this_endpoint_pair,
                                                              nat_type));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair,
                                                                   nat_type));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(peer_endpoint_pair.local,
                                                  this_endpoint_pair.local,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             peer_endpoint_pair.local,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::rendezvous_connect_timeout));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Ping non-connected peer
  result_of_ping = kPingFailed;
  result_arrived = false;
  node_.managed_connections()->Ping(bootstrap_endpoints_[2], ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_ping);
  // Ping ourself
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(this_endpoint_pair.local, ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kWontPingOurself, result_of_ping);
  // Ping bootstrap peer
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(bootstrap_endpoints_[0], ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kWontPingAlreadyConnected, result_of_ping);
  // Ping non-existent peer
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(unavailable_endpoint, ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kPingFailed, result_of_ping);
}
*/

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
