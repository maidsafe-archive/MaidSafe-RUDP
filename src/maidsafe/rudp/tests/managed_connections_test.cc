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
                std::vector<Endpoint>(1, Endpoint(detail::GetLocalIp(), 10000)),
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
  EXPECT_TRUE(detail::IsValid(chosen_endpoint));
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
  EXPECT_TRUE(detail::IsValid(chosen_endpoint));
  EXPECT_NE(bootstrap_endpoints_.end(),
            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(), chosen_endpoint));

  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(chosen_endpoint, this_endpoint_pair));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));

  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), another_endpoint_pair));
  EXPECT_TRUE(detail::IsValid(another_endpoint_pair.local));
  EXPECT_NE(this_endpoint_pair.local, another_endpoint_pair.local);
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 3));

  // Before bootstrapping
  Endpoint random_this_endpoint(detail::GetLocalIp(), GetRandomPort());
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
            nodes_[0]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->Add(peer_endpoint_pair.local,
                                                  this_endpoint_pair.local,
                                                  nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             peer_endpoint_pair.local,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.validation_data(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->validation_data(), this_node_messages[0]);
  nodes_[0]->ResetData();

  // Invalid endpoints
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             Endpoint(),
                                             node_.validation_data()));
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(Endpoint(),
                                             bootstrap_endpoints_[1],
                                             node_.validation_data()));
  // Empty validation_data
  EXPECT_EQ(kEmptyValidationData,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             peer_endpoint_pair.local,
                                             ""));

  // Unavailable endpoints
  Endpoint unavailable_endpoint(ip::address::from_string("1.1.1.1"), GetRandomPort());
  EXPECT_EQ(kInvalidTransport,
            node_.managed_connections()->Add(unavailable_endpoint,
                                             bootstrap_endpoints_[2],
                                             node_.validation_data()));

  node_.ResetData();
  this_node_futures = node_.GetFutureForMessages(1);
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             unavailable_endpoint,
                                             node_.validation_data()));
  ASSERT_FALSE(this_node_futures.timed_wait(Parameters::connect_timeout));

  // Re-add existing connection, on same transport and new transport
  EXPECT_EQ(kConnectionAlreadyExists,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             peer_endpoint_pair.local,
                                             node_.validation_data()));
  EndpointPair another_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), another_endpoint_pair));
  EXPECT_TRUE(detail::IsValid(another_endpoint_pair.local));
  EXPECT_NE(another_endpoint_pair.local, this_endpoint_pair.local);
  EXPECT_EQ(kConnectionAlreadyExists,
            node_.managed_connections()->Add(another_endpoint_pair.local,
                                             peer_endpoint_pair.local,
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
            nodes_[0]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair));
  EXPECT_TRUE(detail::IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(detail::IsValid(peer_endpoint_pair.local));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->Add(peer_endpoint_pair.local,
                                                  this_endpoint_pair.local,
                                                  nodes_[0]->validation_data()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.local,
                                             peer_endpoint_pair.local,
                                             node_.validation_data()));
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
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
  node_.managed_connections()->Remove(peer_endpoint_pair.local);
  ASSERT_TRUE(wait_for_signals(0));
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], peer_endpoint_pair.local);
  EXPECT_EQ(nodes_[0]->connection_lost_endpoints()[0], this_endpoint_pair.local);

  // Already removed endpoint
  node_.ResetData();
  nodes_[0]->ResetData();
  node_.managed_connections()->Remove(peer_endpoint_pair.local);
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
  result_of_send = kConnectError;
  result_arrived = false;
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
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair));
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
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
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
  node_.managed_connections()->Send(Endpoint(detail::GetLocalIp(), GetRandomPort()),
                                    "message9",
                                    MessageSentFunctor());
  result_of_send = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Send(Endpoint(detail::GetLocalIp(), GetRandomPort()),
                                    "message10",
                                    message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);

  // Valid Send from node_ to nodes_[1]
  node_.ResetData();
  nodes_[1]->ResetData();
  future_messages_at_peer = nodes_[1]->GetFutureForMessages(2);
  node_.managed_connections()->Send(peer_endpoint_pair.local, "message11", MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  node_.managed_connections()->Send(peer_endpoint_pair.local, "message12", message_sent_functor);
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
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.local, "message13",
                                         MessageSentFunctor());
  result_of_send = kConnectError;
  result_arrived = false;
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.local, "message14",
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
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.local,
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
  nodes_[1]->managed_connections()->Send(this_endpoint_pair.local,
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
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  ASSERT_EQ(bootstrap_endpoints_[0], chosen_endpoint);

  // Connect node_ to nodes_[1]
  nodes_[1]->ResetData();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair));
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
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
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
    node_.managed_connections()->Send(peer_endpoint_pair.local,
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
  Endpoint chosen_endpoint(node_.Bootstrap(
      std::vector<Endpoint>(1, bootstrap_endpoints_[kNetworkSize - 1])));
  ASSERT_EQ(bootstrap_endpoints_[kNetworkSize - 1], chosen_endpoint);

  std::vector<Endpoint> this_node_endpoints;
  // Connect node_ to all others
  for (int i(0); i != kNetworkSize - 1; ++i) {
    SCOPED_TRACE("Connecting to " + nodes_[i]->id());
    node_.ResetData();
    nodes_[i]->ResetData();
    EndpointPair this_endpoint_pair, peer_endpoint_pair;
    EXPECT_EQ(kSuccess,
              node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
    EXPECT_EQ(kSuccess,
              nodes_[i]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                     peer_endpoint_pair));
    auto peer_futures(nodes_[i]->GetFutureForMessages(1));
    auto this_node_futures(node_.GetFutureForMessages(1));
    EXPECT_EQ(kSuccess,
              nodes_[i]->managed_connections()->Add(peer_endpoint_pair.local,
                                                    this_endpoint_pair.local,
                                                    nodes_[i]->validation_data()));
    EXPECT_EQ(kSuccess,
              node_.managed_connections()->Add(this_endpoint_pair.local,
                                               peer_endpoint_pair.local,
                                               node_.validation_data()));
    ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
    auto peer_messages(peer_futures.get());
    ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
    auto this_node_messages(this_node_futures.get());
    ASSERT_EQ(1U, peer_messages.size());
    ASSERT_EQ(1U, this_node_messages.size());
    EXPECT_EQ(node_.validation_data(), peer_messages[0]);
    EXPECT_EQ(nodes_[i]->validation_data(), this_node_messages[0]);
    this_node_endpoints.push_back(this_endpoint_pair.local);
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
                               this_node_endpoints[i],
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
  Parameters::bootstrap_disconnection_timeout = bptime::seconds(6);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  EXPECT_TRUE(detail::IsValid(chosen_endpoint));

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
  nodes_[0]->managed_connections()->Send(this_endpoint_pair.local, "message02",
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
  nodes_[0]->managed_connections()->Send(this_endpoint_pair.local, "message04",
                                         message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kInvalidConnection, result_of_send);
}

TEST_F(ManagedConnectionsTest, BEH_API_Ping) {
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
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(bootstrap_endpoints_[0],
                                                              this_endpoint_pair));
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
  Endpoint unavailable_endpoint(ip::address::from_string("1.1.1.1"), GetRandomPort());
  result_of_ping = kSuccess;
  result_arrived = false;
  node_.managed_connections()->Ping(unavailable_endpoint, ping_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kPingFailed, result_of_ping);

  // After Add
  nodes_[1]->ResetData();
  EndpointPair peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(kSuccess,
            nodes_[1]->managed_connections()->GetAvailableEndpoint(this_endpoint_pair.local,
                                                                   peer_endpoint_pair));
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
  ASSERT_TRUE(peer_futures.timed_wait(Parameters::connect_timeout));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(Parameters::connect_timeout));
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

// Disabled until we have a way testing using direct-connected nodes (since only direct-connected
// will attempt to start a resilience transport)
TEST_F(ManagedConnectionsTest, DISABLED_BEH_API_Resilience) {
  Parameters::max_transports = 2;
  const int kNetworkSize(3);
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, kNetworkSize));

  Endpoint emergency_endpoint(bootstrap_endpoints_[0].address(),
                              ManagedConnections::kResiliencePort());
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, emergency_endpoint)));
  ASSERT_EQ(emergency_endpoint, chosen_endpoint);

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

  // Don't know which node managed to start the resilience transport - check messages on each.
  std::vector<boost::unique_future<std::vector<std::string>>> future_messages_at_peers;  // NOLINT (Fraser)
  std::for_each(nodes_.begin(),
                nodes_.end(),
                [&future_messages_at_peers](const NodePtr& node) {
                  node->ResetData();
                  future_messages_at_peers.push_back(std::move(node->GetFutureForMessages(1)));
                });
  node_.managed_connections()->Send(emergency_endpoint, "message", message_sent_functor);
  ASSERT_TRUE(wait_for_result());
  EXPECT_EQ(kSuccess, result_of_send);
  bool found_one(false);
  std::for_each(future_messages_at_peers.begin(),
                future_messages_at_peers.end(),
                [&found_one](boost::unique_future<std::vector<std::string>> &future) {
                  if (future.timed_wait(bptime::milliseconds(200))) {
                    found_one = true;
                    auto messages(future.get());
                    ASSERT_EQ(1U, messages.size());
                    EXPECT_EQ("message", messages.front());
                  }
                });
  EXPECT_TRUE(found_one);

  // TODO(Fraser#5#): 2012-07-20 - Can new node make permanent connection on emergency transport?
  //                  Either way, test.
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
