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
        do_nothing_on_connection_lost_([](const Endpoint&) {}) {}
  ~ManagedConnectionsTest() {}

 protected:
  Node node_;
  std::vector<NodePtr> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
  MessageReceivedFunctor do_nothing_on_message_;
  ConnectionLostFunctor do_nothing_on_connection_lost_;
};

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap) {
  // All invalid
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(std::vector<Endpoint>(),
                                                               MessageReceivedFunctor(),
                                                               ConnectionLostFunctor(),
                                                               nullptr,
                                                               nullptr));
  // Empty bootstrap_endpoints
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(std::vector<Endpoint>(),
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_,
                                                               node_.private_key(),
                                                               node_.public_key()));
  // Unavailable bootstrap_endpoints
  EXPECT_EQ(Endpoint(),
            node_.managed_connections()->Bootstrap(
                std::vector<Endpoint>(1, Endpoint(GetLocalIp(), 10000)),
                do_nothing_on_message_,
                do_nothing_on_connection_lost_,
                node_.private_key(),
                node_.public_key()));
  // Invalid MessageReceivedFunctor
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               MessageReceivedFunctor(),
                                                               do_nothing_on_connection_lost_,
                                                               node_.private_key(),
                                                               node_.public_key()));
  // Invalid ConnectionLostFunctor
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               ConnectionLostFunctor(),
                                                               node_.private_key(),
                                                               node_.public_key()));
  // Invalid private key
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(
                        bootstrap_endpoints_,
                        do_nothing_on_message_,
                        do_nothing_on_connection_lost_,
                        std::shared_ptr<asymm::PrivateKey>(new asymm::PrivateKey),
                        node_.public_key()));
  // Invalid public key
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(
                        bootstrap_endpoints_,
                        do_nothing_on_message_,
                        do_nothing_on_connection_lost_,
                        node_.private_key(),
                        std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey)));
  // NULL private key
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_,
                                                               nullptr,
                                                               node_.public_key()));
  // NULL public key
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_,
                                                               node_.private_key(),
                                                               nullptr));
  // Valid
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));
  Endpoint chosen_endpoint(node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                                  do_nothing_on_message_,
                                                                  do_nothing_on_connection_lost_,
                                                                  node_.private_key(),
                                                                  node_.public_key()));
  EXPECT_TRUE(IsValid(chosen_endpoint));
  EXPECT_NE(bootstrap_endpoints_.end(),
            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(), chosen_endpoint));
  // Already bootstrapped
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_,
                                                               node_.private_key(),
                                                               node_.public_key()));
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  //  Before Bootstrapping
  EndpointPair this_endpoint_pair;
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EXPECT_EQ(kNotBootstrapped,
            node_.managed_connections()->GetAvailableEndpoint(
                Endpoint(ip::address::from_string("1.2.3.4"), 1026), this_endpoint_pair));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  //  After Bootstrapping
  Endpoint chosen_endpoint(node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                                  do_nothing_on_message_,
                                                                  do_nothing_on_connection_lost_,
                                                                  node_.private_key(),
                                                                  node_.public_key()));
  EXPECT_TRUE(IsValid(chosen_endpoint));
  EXPECT_NE(bootstrap_endpoints_.end(),
            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(), chosen_endpoint));

  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(chosen_endpoint, this_endpoint_pair));
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));

  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), another_endpoint_pair));
  EXPECT_TRUE(IsValid(another_endpoint_pair.local));
  EXPECT_TRUE(IsValid(another_endpoint_pair.external));
  EXPECT_NE(this_endpoint_pair.local, another_endpoint_pair.local);
  EXPECT_NE(this_endpoint_pair.external, another_endpoint_pair.external);
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Before bootstrapping
  Endpoint random_this_endpoint(GetLocalIp(), GetRandomPort());
  EXPECT_EQ(kInvalidTransport,
            node_.managed_connections()->Add(random_this_endpoint,
                                             bootstrap_endpoints_[1],
                                             node_.validation_data()));
  // Valid
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  EXPECT_EQ(bootstrap_endpoints_[0], chosen_endpoint);

  nodes_[0]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(chosen_endpoint, this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.external,
                                                                   peer_endpoint_pair));
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->Add(peer_endpoint_pair.external,
                                                  this_endpoint_pair.external,
                                                  nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->validation_data(), this_node_messages[0]);
  nodes_[0]->ResetData();

  // Invalid endpoints
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             Endpoint(),
                                             node_.validation_data()));
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(Endpoint(),
                                             bootstrap_endpoints_[1],
                                             node_.validation_data()));
  // Empty validation_data
  EXPECT_EQ(kEmptyValidationData,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             ""));

  // Unavailable endpoints
  Endpoint unavailable_endpoint(ip::address::from_string("1.1.1.1"), GetRandomPort());
  EXPECT_EQ(kInvalidTransport,
            node_.managed_connections()->Add(unavailable_endpoint,
                                             bootstrap_endpoints_[2],
                                             node_.validation_data()));
  // TODO(Fraser#5#): 2012-06-20 - Wait for this Add attempt to timeout.
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             unavailable_endpoint,
                                             node_.validation_data()));

  // Re-add existing connection, on same transport and new transport
  EXPECT_EQ(kConnectionAlreadyExists,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), another_endpoint_pair));
  EXPECT_TRUE(IsValid(another_endpoint_pair.local));
  EXPECT_TRUE(IsValid(another_endpoint_pair.external));
  EXPECT_NE(another_endpoint_pair.local, this_endpoint_pair.local);
  EXPECT_NE(another_endpoint_pair.external, this_endpoint_pair.external);
  EXPECT_EQ(kConnectionAlreadyExists,
            node_.managed_connections()->Add(another_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 4));
  auto wait_for_signals([&](int node_index)->bool {
    int count(0);
    do {
      Sleep(bptime::milliseconds(100));
      ++count;
    } while ((node_.connection_lost_endpoints().empty() ||
             nodes_[node_index]->connection_lost_endpoints().empty()) &&
             count != 10);
    return (!node_.connection_lost_endpoints().empty() &&
            !nodes_[node_index]->connection_lost_endpoints().empty());
  });

  // Before Bootstrap
  node_.managed_connections()->Remove(bootstrap_endpoints_[1]);
  ASSERT_TRUE(node_.connection_lost_endpoints().empty());

  // Before Add
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[1])));
  EXPECT_EQ(bootstrap_endpoints_[1], chosen_endpoint);
  node_.managed_connections()->Remove(bootstrap_endpoints_[1]);
  ASSERT_TRUE(wait_for_signals(1));
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[1]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(chosen_endpoint, node_.connection_lost_endpoints()[0]);

  // After Add
  chosen_endpoint = node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]));
  EXPECT_EQ(bootstrap_endpoints_[0], chosen_endpoint);
  nodes_[0]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(chosen_endpoint, this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.external,
                                                                   peer_endpoint_pair));
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->Add(peer_endpoint_pair.external,
                                                  this_endpoint_pair.external,
                                                  nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->validation_data(), this_node_messages[0]);
  nodes_[0]->ResetData();

  // Invalid endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(Endpoint());
  ASSERT_FALSE(wait_for_signals(0));
  EXPECT_TRUE(node_.connection_lost_endpoints().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_endpoints().empty());

  // Unknown endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(bootstrap_endpoints_[2]);
  ASSERT_FALSE(wait_for_signals(2));
  EXPECT_TRUE(node_.connection_lost_endpoints().empty());
  EXPECT_TRUE(nodes_[2]->connection_lost_endpoints().empty());

  // Valid
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(peer_endpoint_pair.external);
  ASSERT_TRUE(wait_for_signals(0));
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], peer_endpoint_pair.external);
  EXPECT_EQ(nodes_[0]->connection_lost_endpoints()[0], this_endpoint_pair.external);

  // Already removed endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(peer_endpoint_pair.external);
  ASSERT_FALSE(wait_for_signals(0));
  EXPECT_TRUE(node_.connection_lost_endpoints().empty());
  EXPECT_TRUE(nodes_[0]->connection_lost_endpoints().empty());
}

TEST_F(ManagedConnectionsTest, FUNC_API_Send) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Before Bootstrap
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message1", MessageSentFunctor());
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
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message2", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Before Add
  // Sending to bootstrap peer should succeed, sending to any other should fail.
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  ASSERT_EQ(bootstrap_endpoints_[0], chosen_endpoint);
  // Send to non-bootstrap peer
  node_.managed_connections()->Send(bootstrap_endpoints_[1], "message3", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(bootstrap_endpoints_[1], "message4", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
  // Send to bootstrap peer
  nodes_[0]->ResetData();
  auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(2));
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message5", MessageSentFunctor());
  result_of_send = result_arrived = false;
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message6", message_sent_functor);
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
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.external,
                                                                   peer_endpoint_pair));
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));

  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(peer_endpoint_pair.external,
                                                  this_endpoint_pair.external,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1U, peer_messages.size());
  ASSERT_EQ(1U, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[1]->validation_data(), this_node_messages[0]);

  // Invalid endpoint
  node_.ResetData();
  nodes_[1]->ResetData();
  node_.managed_connections()->Send(Endpoint(), "message7", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(Endpoint(), "message8", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Unavailable endpoint
  node_.ResetData();
  nodes_[1]->ResetData();
  node_.managed_connections()->Send(Endpoint(GetLocalIp(), GetRandomPort()),
                                    "message9",
                                    MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(Endpoint(GetLocalIp(), GetRandomPort()),
                                    "message10",
                                    message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid Send from node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = nodes_[1]->GetFutureForMessages(2);
  node_.managed_connections()->Send(peer_endpoint_pair.external, "message11", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  node_.managed_connections()->Send(peer_endpoint_pair.external, "message12", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message11"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message12"));

  // Valid Send from nodes_[1] to node_
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = node_.GetFutureForMessages(2);
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.external, "message13",
                                         MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.external, "message14",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  ASSERT_TRUE(future_messages_at_peer.timed_wait(bptime::milliseconds(200)));
  messages = future_messages_at_peer.get();
  ASSERT_EQ(2U, messages.size());
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message13"));
  EXPECT_NE(messages.end(), std::find(messages.begin(), messages.end(), "message14"));

  // After Remove
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(bootstrap_endpoints_[0]);
  int count(0);
  do {
    Sleep(bptime::milliseconds(100));
    ++count;
  } while ((node_.connection_lost_endpoints().empty() ||
            nodes_[0]->connection_lost_endpoints().empty()) &&
            count != 10);
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], bootstrap_endpoints_[0]);

  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message15", MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message16", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid large message
  node_.ResetData();
  nodes_[1]->ResetData();
  std::string sent_message(std::move(RandomString(8 * 1024 * 1024)));
  future_messages_at_peer = node_.GetFutureForMessages(1);
  result_of_send = kConnectError;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.external,
                                         sent_message,
                                         message_sent_functor);
  ASSERT_TRUE(cond_var.wait_for(lock,
                                std::chrono::seconds(10),
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
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.external,
                                         sent_message,
                                         message_sent_functor);
  ASSERT_TRUE(cond_var.wait_for(lock,
                                std::chrono::seconds(10),
                                [&result_arrived]() { return result_arrived; }));  // NOLINT (Fraser)
  EXPECT_EQ(kSendFailure, result_of_send);
}

TEST_F(ManagedConnectionsTest, FUNC_API_ParallelSend) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  // Bootstrap off nodes_[0]
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  ASSERT_EQ(bootstrap_endpoints_[0], chosen_endpoint);

  // Connect node_ to nodes_[1]
  nodes_[1]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.external,
                                                                   peer_endpoint_pair));
  auto peer_futures(nodes_[1]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->Add(peer_endpoint_pair.external,
                                                  this_endpoint_pair.external,
                                                  nodes_[1]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
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
    node_.managed_connections()->Send(peer_endpoint_pair.external,
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

TEST_F(ManagedConnectionsTest, BEH_API_BootstrapTimeout) {
  Parameters::bootstrap_disconnection_timeout = bptime::seconds(6);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  EXPECT_TRUE(IsValid(chosen_endpoint));

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
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message01", message_sent_functor);
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
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(bootstrap_endpoints_[0],
                                                                        this_endpoint_pair));
  nodes_[0]->managed_connections()->Send(this_endpoint_pair.external, "message02",
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
  boost::this_thread::sleep(Parameters::bootstrap_disconnection_timeout);
  int count(0);
  do {
    Sleep(bptime::milliseconds(100));
    ++count;
  } while ((node_.connection_lost_endpoints().empty() ||
            nodes_[0]->connection_lost_endpoints().empty()) &&
            count != 10);
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], bootstrap_endpoints_[0]);

  // Send again in both directions - expect failure
  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(bootstrap_endpoints_[0], "message03", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  node_.ResetData();
  nodes_[0]->ResetData();
  result_of_send = kSuccess;
  result_arrived = false;
  nodes_[0]->managed_connections()->Send(this_endpoint_pair.external, "message04",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
