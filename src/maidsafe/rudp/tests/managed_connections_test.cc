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
                                                               ConnectionLostFunctor()));
  // Empty bootstrap_endpoints
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(std::vector<Endpoint>(),
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_));
  // Unavailable bootstrap_endpoints
  EXPECT_EQ(Endpoint(),
            node_.managed_connections()->Bootstrap(
                std::vector<Endpoint>(1, Endpoint(GetLocalIp(), 10000)),
                do_nothing_on_message_,
                do_nothing_on_connection_lost_));
  // Invalid MessageReceivedFunctor
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               MessageReceivedFunctor(),
                                                               do_nothing_on_connection_lost_));
  // Invalid ConnectionLostFunctor
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               ConnectionLostFunctor()));
  // Valid
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));
  Endpoint chosen_endpoint(node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                                  do_nothing_on_message_,
                                                                  do_nothing_on_connection_lost_));
  EXPECT_TRUE(IsValid(chosen_endpoint));
  EXPECT_NE(bootstrap_endpoints_.end(),
            std::find(bootstrap_endpoints_.begin(), bootstrap_endpoints_.end(), chosen_endpoint));
  // Already bootstrapped
  EXPECT_EQ(Endpoint(), node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                               do_nothing_on_message_,
                                                               do_nothing_on_connection_lost_));
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  //  Before Bootstrapping
  EndpointPair this_endpoint_pair;
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EXPECT_EQ(kNoneAvailable,
            node_.managed_connections()->GetAvailableEndpoint(Endpoint(), this_endpoint_pair));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  this_endpoint_pair.external = this_endpoint_pair.local =
      Endpoint(ip::address::from_string("1.1.1.1"), 1025);
  EXPECT_EQ(kNoneAvailable,
            node_.managed_connections()->GetAvailableEndpoint(
                Endpoint(ip::address::from_string("1.2.3.4"), 1026), this_endpoint_pair));
  EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
  EXPECT_EQ(Endpoint(), this_endpoint_pair.external);

  //  After Bootstrapping
  Endpoint chosen_endpoint(node_.managed_connections()->Bootstrap(bootstrap_endpoints_,
                                                                  do_nothing_on_message_,
                                                                  do_nothing_on_connection_lost_));
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
                                             node_.kValidationData()));
  // Valid
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0])));
  EXPECT_EQ(bootstrap_endpoints_[0], chosen_endpoint);

  nodes_[0]->ResetCount();
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
                                                  nodes_[0]->kValidationData()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.kValidationData()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.kValidationData(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->kValidationData(), this_node_messages[0]);
  nodes_[0]->ResetCount();

  // Invalid endpoints
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             Endpoint(),
                                             node_.kValidationData()));
  EXPECT_EQ(kInvalidEndpoint,
            node_.managed_connections()->Add(Endpoint(),
                                             bootstrap_endpoints_[1],
                                             node_.kValidationData()));

  // Unavailable endpoints
  Endpoint unavailable_endpoint(ip::address::from_string("1.1.1.1"), GetRandomPort());
  EXPECT_EQ(kInvalidTransport,
            node_.managed_connections()->Add(unavailable_endpoint,
                                             bootstrap_endpoints_[2],
                                             node_.kValidationData()));
  // TODO(Fraser#5#): 2012-06-20 - Wait for this Add attempt to timeout.
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             unavailable_endpoint,
                                             node_.kValidationData()));

  // Re-add existing connection, on same transport and new transport
  EXPECT_EQ(kConnectionAlreadyExists,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.kValidationData()));
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
                                             node_.kValidationData()));
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 4));

  // Before Bootstrap
  node_.managed_connections()->Remove(bootstrap_endpoints_[1]);
  ASSERT_TRUE(node_.connection_lost_endpoints().empty());

  // Before Add
  Endpoint chosen_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[1])));
  EXPECT_EQ(bootstrap_endpoints_[1], chosen_endpoint);
  node_.managed_connections()->Remove(bootstrap_endpoints_[1]);
                                                                        Sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(chosen_endpoint, node_.connection_lost_endpoints()[0]);
  node_.ResetCount();

  // After Add
  chosen_endpoint = node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[0]));
  EXPECT_EQ(bootstrap_endpoints_[0], chosen_endpoint);
  nodes_[0]->ResetCount();
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
                                                  nodes_[0]->kValidationData()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.kValidationData()));
  ASSERT_TRUE(peer_futures.timed_wait(bptime::seconds(3)));
  auto peer_messages(peer_futures.get());
  ASSERT_TRUE(this_node_futures.timed_wait(bptime::seconds(3)));
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.kValidationData(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->kValidationData(), this_node_messages[0]);
  nodes_[0]->ResetCount();

  // Invalid endpoint
  node_.managed_connections()->Remove(Endpoint());
                                                                        Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node_.connection_lost_endpoints().empty());

  // Unknown endpoint
  node_.managed_connections()->Remove(bootstrap_endpoints_[2]);
                                                                        Sleep(boost::posix_time::milliseconds(100));
  EXPECT_TRUE(node_.connection_lost_endpoints().empty());

  // Valid
  node_.managed_connections()->Remove(peer_endpoint_pair.external);
                                                                        Sleep(boost::posix_time::milliseconds(100));
  int count(0);
  do {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ++count;
  } while (node_.connection_lost_endpoints().empty() &&
           nodes_[0]->connection_lost_endpoints().empty() &&
           count != 20);
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], peer_endpoint_pair.external);
  EXPECT_EQ(nodes_[0]->connection_lost_endpoints()[0], this_endpoint_pair.external);

  // Already removed endpoint
  node_.managed_connections()->Remove(peer_endpoint_pair.external);
                                                                        Sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(node_.connection_lost_endpoints().size(), 1U);
  ASSERT_EQ(nodes_[0]->connection_lost_endpoints().size(), 1U);
  EXPECT_EQ(node_.connection_lost_endpoints()[0], peer_endpoint_pair.external);
  EXPECT_EQ(nodes_[0]->connection_lost_endpoints()[0], this_endpoint_pair.external);
}
/*
TEST_F(ManagedConnectionsTest, BEH_API_Send) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, 2));

  Endpoint bootstrap_endpoint(node_.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints_[1])));
  EXPECT_EQ(bootstrap_endpoints_[1], bootstrap_endpoint);

  nodes_[0]->ResetCount();
  EndpointPair this_endpoint_pair, peer_endpoint_pair;
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->GetAvailableEndpoint(peer_endpoint_pair));
  EXPECT_EQ(kSuccess, node_.managed_connections()->GetAvailableEndpoint(this_endpoint_pair));
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));

  auto peer_futures(nodes_[0]->GetFutureForMessages(1));
  auto this_node_futures(node_.GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            nodes_[0]->managed_connections()->Add(peer_endpoint_pair.external,
                                                  this_endpoint_pair.external,
                                                  nodes_[0]->kValidationData()));
  EXPECT_EQ(kSuccess,
            node_.managed_connections()->Add(this_endpoint_pair.external,
                                             peer_endpoint_pair.external,
                                             node_.kValidationData()));
  auto peer_messages(peer_futures.get());
  auto this_node_messages(this_node_futures.get());
  ASSERT_EQ(1, peer_messages.size());
  ASSERT_EQ(1, this_node_messages.size());
  EXPECT_EQ(node_.kValidationData(), peer_messages[0]);
  EXPECT_EQ(nodes_[0]->kValidationData(), this_node_messages[0]);
  nodes_[0]->ResetCount();


  bool result_of_send(true), result_arrived(false);
  std::condition_variable cond_var;
  std::mutex mutex;
  MessageSentFunctor message_sent_functor([&](bool result_in) {
    std::lock_guard<std::mutex> lock(mutex);
    result_of_send = result_in;
    result_arrived = true;
    cond_var.notify_one();
  });

  // Invalid endpoint
  {
    std::unique_lock<std::mutex> lock(mutex);
    node_.managed_connections()->Send(Endpoint(), "message", message_sent_functor);
    ASSERT_TRUE(cond_var.wait_for(lock,
                                  std::chrono::milliseconds(100),
                                  [&result_arrived]() { return result_arrived; }));
    ASSERT_FALSE(result_of_send);
  }

  // Unavailable endpoint
  {
    result_of_send = true;
    result_arrived = false;
    std::unique_lock<std::mutex> lock(mutex);
    node_.managed_connections()->Send(Endpoint(GetLocalIp(), GetRandomPort()),
                             "message",
                             message_sent_functor);
    ASSERT_TRUE(cond_var.wait_for(lock,
                                  std::chrono::milliseconds(100),
                                  [&result_arrived]() { return result_arrived; }));
    ASSERT_FALSE(result_of_send);
  }

  {  // Valid
    result_of_send = false;
    result_arrived = false;
    std::unique_lock<std::mutex> lock(mutex);
    auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
    node_.managed_connections()->Send(peer_endpoint_pair.external, "message", message_sent_functor);
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("message", messages[0]);
    ASSERT_TRUE(cond_var.wait_for(lock,
                                  std::chrono::milliseconds(100),
                                  [&result_arrived]() { return result_arrived; }));
    ASSERT_TRUE(result_of_send);
    nodes_[0]->ResetCount();
  }

  {  // Valid large messages
    result_of_send = false;
    result_arrived = false;
    std::unique_lock<std::mutex> lock(mutex);
    std::string sent_message(std::move(RandomString(8 * 1024 * 1024)));
    auto future_messages_at_peer(nodes_[0]->GetFutureForMessages(1));
    node_.managed_connections()->Send(peer_endpoint_pair.external, sent_message, message_sent_functor);
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ(sent_message, messages[0]);
    ASSERT_TRUE(cond_var.wait_for(lock,
                                  std::chrono::milliseconds(100),
                                  [&result_arrived]() { return result_arrived; }));
    ASSERT_TRUE(result_of_send);
    nodes_[0]->ResetCount();
  }
}

// Ad-hoc tests. To be removed later
TEST_F(ManagedConnectionsTest, BEH_BootstrapAndSend) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
           endpoint2(GetLocalIp(), GetRandomPort());

  auto future1 = std::async(std::launch::async, [&] {
      return managed_connections1.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                                            message_received_functor_,
                                            connection_lost_functor_,
                                            endpoint1);});  // NOLINT (Fraser)

  auto future2 = std::async(std::launch::async, [&] {
      return managed_connections2.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                            message_received_functor_,
                                            connection_lost_functor_,
                                            endpoint2);});  // NOLINT (Fraser)
  ASSERT_TRUE(WaitUntilReady(future1, std::chrono::milliseconds(3000)));
  ASSERT_TRUE(WaitUntilReady(future2, std::chrono::milliseconds(3000)));
  ASSERT_FALSE(future1.get().address().is_unspecified());
  ASSERT_FALSE(future2.get().address().is_unspecified());
  ASSERT_EQ(1U, managed_connections1.connection_map_.size());
  ASSERT_EQ(1U, managed_connections2.connection_map_.size());

  boost::asio::ip::udp::endpoint bootstrap_endpoint =
      managed_connections3.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                     message_received_functor_,
                                     connection_lost_functor_);

  EXPECT_EQ(endpoint1, bootstrap_endpoint);
  ASSERT_EQ(2U, managed_connections1.connection_map_.size());
  ASSERT_EQ(1U, managed_connections2.connection_map_.size());
  ASSERT_EQ(1U, managed_connections3.connection_map_.size());
  ASSERT_EQ(1U, managed_connections3.transports_.size());

  Endpoint endpoint3((*managed_connections3.transports_.begin()).transport->local_endpoint());
  std::string port1(boost::lexical_cast<std::string>(endpoint1.port()));
  std::string port2(boost::lexical_cast<std::string>(endpoint2.port()));
  std::string port3(boost::lexical_cast<std::string>(endpoint3.port()));

  for (int i(0); i != 200; ++i) {
    Sleep(bptime::milliseconds(1));
    std::string message("Message " + boost::lexical_cast<std::string>(i / 2));
    if (i % 2) {
      managed_connections1.Send(endpoint2,
                                message + " from " + port1 + " to " + port2,
                                MessageSentFunctor());
      managed_connections1.Send(endpoint3,
                                message + " from " + port1 + " to " + port3,
                                MessageSentFunctor());
    } else {
      managed_connections2.Send(endpoint1,
                                message + " from " + port2 + " to " + port1,
                                MessageSentFunctor());
      managed_connections3.Send(endpoint1,
                                message + " from " + port3 + " to " + port1,
                                MessageSentFunctor());
    }
  }

  Sleep(boost::posix_time::milliseconds(10000));

  managed_connections3.Remove(endpoint1);
  int count(0);
  do {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ++count;
  } while (connection_lost_count_ != 2 && count != 20);
  ASSERT_EQ(connection_lost_count_, 2);
}

TEST_F(ManagedConnectionsTest, BEH_GetAvailableEndpoint) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
           endpoint2(GetLocalIp(), GetRandomPort()),
           endpoint3(GetLocalIp(), GetRandomPort());

  auto a1 = std::async(std::launch::async, [&] {
      return managed_connections1.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                                            message_received_functor_,
                                            connection_lost_functor_,
                                            endpoint1);});  // NOLINT (Fraser)

  auto a2 = std::async(std::launch::async, [&] {
      return managed_connections2.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                            message_received_functor_,
                                            connection_lost_functor_,
                                            endpoint2);});  // NOLINT (Fraser)

  ASSERT_EQ(a2.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  ASSERT_EQ(a1.wait_for(std::chrono::seconds(3)), std::future_status::ready);
  EXPECT_FALSE(a2.get().address().is_unspecified());
  EXPECT_FALSE(a1.get().address().is_unspecified());

  boost::asio::ip::udp::endpoint bootstrap_endpoint =
      managed_connections3.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                     message_received_functor_,
                                     connection_lost_functor_);

  EXPECT_FALSE(bootstrap_endpoint.address().is_unspecified());

  EndpointPair new_endpoint_pair, new_endpoint_pair1;
  EXPECT_EQ(kSuccess, managed_connections1.GetAvailableEndpoint(new_endpoint_pair));
  EXPECT_TRUE(IsValid(new_endpoint_pair.external));
  EXPECT_TRUE(IsValid(new_endpoint_pair.local));
  EXPECT_EQ(kSuccess, managed_connections2.GetAvailableEndpoint(new_endpoint_pair1));
  EXPECT_TRUE(IsValid(new_endpoint_pair1.external));
  EXPECT_TRUE(IsValid(new_endpoint_pair1.local));

  managed_connections1.Remove(endpoint2);
  do {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  } while (connection_lost_count_ != 2);
}
*/
}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
