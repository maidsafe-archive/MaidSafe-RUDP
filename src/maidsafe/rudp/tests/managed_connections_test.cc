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

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/utils.h"


namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

typedef boost::asio::ip::udp::endpoint Endpoint;

namespace test {

namespace {

class TestNode {
 public:
  explicit TestNode(uint32_t id)
      : node_id_(id),
        mutex_(),
        connection_lost_endpoints_(),
        messages_(),
        managed_connection_() {}

  void MessageReceived(const std::string &message) {
    DLOG(INFO) << node_id_ << " -- Received: " << message.substr(0, 10);
    std::lock_guard<std::mutex> guard(mutex_);
    messages_.emplace_back(message);
  }

  void ConnectionLost(const Endpoint &endpoint) {
    DLOG(INFO) << node_id_ << " -- Lost connection to " << endpoint;
    std::lock_guard<std::mutex> guard(mutex_);
    connection_lost_endpoints_.emplace_back(endpoint);
  }

  std::vector<Endpoint> connection_lost_endpoints() {
    std::lock_guard<std::mutex> guard(mutex_);
    return connection_lost_endpoints_;
  }

  std::vector<std::string> messages() {
    std::lock_guard<std::mutex> guard(mutex_);
    return messages_;
  }

  ManagedConnections& managed_connection() {
    return managed_connection_;
  }

  Endpoint Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
                     Endpoint local_endpoint) {
    MessageReceivedFunctor message_received_functor =
        std::bind(&TestNode::MessageReceived, this, args::_1);
    ConnectionLostFunctor connection_lost_functor =
        std::bind(&TestNode::ConnectionLost, this, args::_1);

    return managed_connection_.Bootstrap(bootstrap_endpoints,
                                         message_received_functor,
                                         connection_lost_functor,
                                         local_endpoint);
  }

 private:
  uint32_t node_id_;
  std::mutex mutex_;
  std::vector<Endpoint> connection_lost_endpoints_;
  std::vector<std::string> messages_;
  ManagedConnections managed_connection_;
};

typedef std::shared_ptr<TestNode> TestNodePtr;
}  // anonymous namspace

void MessageReceived(const std::string &message) {
  DLOG(INFO) << "Received: " << message;
}

void ConnectionLost(const Endpoint &endpoint, std::atomic<int> *count) {
  DLOG(INFO) << "Lost connection to " << endpoint;
  ++(*count);
}

bool SetupNetwork(const uint16_t &node_count,
                  std::shared_ptr<std::vector<TestNodePtr>> nodes,
                  std::shared_ptr<std::vector<Endpoint>> bootstrap_endpoints) {
  BOOST_ASSERT(nodes);
  BOOST_ASSERT(bootstrap_endpoints);
  BOOST_ASSERT_MSG(node_count > 1, "Network size must be greater than 1");
  nodes->clear();
  bootstrap_endpoints->clear();

  // Setting up first two nodes
  TestNodePtr node1(std::make_shared<TestNode>(1));
  TestNodePtr node2(std::make_shared<TestNode>(2));

  Endpoint endpoint1(ip::address_v4::loopback(), GetRandomPort()),
           endpoint2(ip::address_v4::loopback(), GetRandomPort());
  auto a1 = std::async(std::launch::async, &TestNode::Bootstrap, node1,
                       std::vector<Endpoint>(1, endpoint2), endpoint1);
  auto a2 = std::async(std::launch::async, &TestNode::Bootstrap, node2,
                       std::vector<Endpoint>(1, endpoint1), endpoint2);

  bool result1 = a1.get().address().is_unspecified();
  bool result2 = a2.get().address().is_unspecified();
  EXPECT_FALSE(result1);
  EXPECT_FALSE(result2);
  if (result1 || result2) {
    return false;
  }

  EndpointPair this_endpoint_pair1, this_endpoint_pair2;
  EXPECT_EQ(kSuccess,
            node1->managed_connection().GetAvailableEndpoint(&this_endpoint_pair1));
  EXPECT_EQ(kSuccess,
            node2->managed_connection().GetAvailableEndpoint(&this_endpoint_pair2));

  EXPECT_NE(Endpoint(), this_endpoint_pair1.local);
  EXPECT_NE(Endpoint(), this_endpoint_pair1.external);
  EXPECT_NE(Endpoint(), this_endpoint_pair2.local);
  EXPECT_NE(Endpoint(), this_endpoint_pair2.external);

  EXPECT_EQ(kSuccess,
            node1->managed_connection().Add(this_endpoint_pair1.external, endpoint2,
                                            "validation_data"));
  EXPECT_EQ(kSuccess,
            node2->managed_connection().Add(this_endpoint_pair2.external, endpoint1,
                                            "validation_data"));
  nodes->emplace_back(node1);
  nodes->emplace_back(node2);
  bootstrap_endpoints->push_back(endpoint1);
  bootstrap_endpoints->push_back(endpoint2);
  // Setting up remaining (node_count - 2) nodes
  std::vector<std::future<Endpoint>> results;
  results.reserve(node_count - 2);
  for (uint16_t i = 0; i != node_count - 2; ++i) {
    TestNodePtr node(std::make_shared<TestNode>(i+2));
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    results.emplace_back(
        std::async(std::launch::async, &TestNode::Bootstrap, node,
                   *bootstrap_endpoints, endpoint));
    nodes->emplace_back(node);
    bootstrap_endpoints->push_back(endpoint);
  }
  // Waiting for results
  for (uint16_t i = 0; i != node_count - 2; ++i) {
    bool result = results.at(i).get().address().is_unspecified();
    if (result) {
      nodes->clear();
      bootstrap_endpoints->clear();
      return false;
    }
  }
  return true;
}

TEST(ManagedConnectionsTest, BEH_API_Bootstrap) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(ip::address_v4::loopback(), 9000),
           endpoint2(ip::address_v4::loopback(), 11111),
           endpoint3(ip::address_v4::loopback(), 23456);
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  boost::mutex mutex;
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));

  auto a1 = std::async(std::launch::async, [&] {
      return managed_connections1.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                                            message_received_functor,
                                            connection_lost_functor,
                                            endpoint1);});  // NOLINT (Fraser)

  auto a2 = std::async(std::launch::async, [&] {
      return managed_connections2.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                            message_received_functor,
                                            connection_lost_functor,
                                            endpoint2);});  // NOLINT (Fraser)

  EXPECT_FALSE(a2.get().address().is_unspecified());
  EXPECT_FALSE(a1.get().address().is_unspecified());

  boost::asio::ip::udp::endpoint bootstrap_endpoint =
      managed_connections3.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                     message_received_functor,
                                     connection_lost_functor);

  EXPECT_FALSE(bootstrap_endpoint.address().is_unspecified());

  for (int i(0); i != 200; ++i) {
    Sleep(bptime::milliseconds(10));
    std::string message("Message " + boost::lexical_cast<std::string>(i / 2));
    if (i % 2) {
      managed_connections1.Send(endpoint2, message + " from 9000 to 11111");
      managed_connections1.Send(endpoint3, message + " from 9000 to 23456");
    } else {
      managed_connections2.Send(endpoint1, message + " from 11111 to 9000");
      managed_connections3.Send(endpoint1, message + " from 23456 to 9000");
    }
  }


  DLOG(INFO) << "==================== REMOVING ENDPOINT 2 ====================";
  managed_connections1.Remove(endpoint2);
  boost::mutex::scoped_lock lock(mutex);
  do {
    lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    lock.lock();
  } while (connection_lost_count != 2);
}

TEST(ManagedConnectionsTest, BEH_API_Bootstrap_Network) {
  std::shared_ptr<std::vector<TestNodePtr>>
      nodes(new std::vector<TestNodePtr>());
  std::shared_ptr<std::vector<Endpoint>>
      bootstrap_endpoints(new std::vector<Endpoint>());
  EXPECT_TRUE(SetupNetwork(4, nodes, bootstrap_endpoints));
  EXPECT_EQ(4, nodes->size());
  nodes.reset();
}

TEST(ManagedConnectionsTest, BEH_API_Bootstrap_Parameters) {
  std::shared_ptr<std::vector<TestNodePtr>>
      nodes(new std::vector<TestNodePtr>());
  std::shared_ptr<std::vector<Endpoint>>
      bootstrap_endpoints(new std::vector<Endpoint>());
  EXPECT_TRUE(SetupNetwork(2, nodes, bootstrap_endpoints));
  ASSERT_EQ(2, nodes->size());
  ASSERT_EQ(2, bootstrap_endpoints->size());

  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  {  // Valid
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_NE(Endpoint(), bootstrap_endpoint);
  }
  {  // All invalid
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(),
                                    MessageReceivedFunctor(),
                                    ConnectionLostFunctor(),
                                    Endpoint());
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid bootstrap_endpoints
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(std::vector<Endpoint>(),
                                      message_received_functor,
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Empty bootstrap_endpoints
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    std::vector<Endpoint> empty_bootstrap_endpoints;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(empty_bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Unavailable bootstrap_endpoints
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort()),
             endpoint2(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                                      message_received_functor,
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid MessageReceivedFunctor
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      MessageReceivedFunctor(),
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid ConnectionLostFunctor
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      message_received_functor,
                                      ConnectionLostFunctor(),
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid Endpoint
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor,
                                      Endpoint());
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Already in use Endpoint
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor,
                                      bootstrap_endpoints->at(0));
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  nodes.reset();
}

TEST(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  std::shared_ptr<std::vector<TestNodePtr>>
      nodes(new std::vector<TestNodePtr>());
  std::shared_ptr<std::vector<Endpoint>>
      bootstrap_endpoints(new std::vector<Endpoint>());
  EXPECT_TRUE(SetupNetwork(2, nodes, bootstrap_endpoints));
  ASSERT_EQ(2, nodes->size());
  ASSERT_EQ(2, bootstrap_endpoints->size());
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  {  //  Before Bootstrapping
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    EndpointPair this_endpoint_pair;
    EXPECT_EQ(kNoneAvailable,
              managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
    EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  }
  {  //  After Bootstrapping
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(*bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_NE(Endpoint(), bootstrap_endpoint);
    EndpointPair this_endpoint_pair;
    EXPECT_EQ(kSuccess,
              managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  }
  nodes.reset();
}

TEST(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint2) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(ip::address_v4::loopback(), 9000),
           endpoint2(ip::address_v4::loopback(), 11111),
           endpoint3(ip::address_v4::loopback(), 23456);
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  boost::mutex mutex;
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));

  auto a1 = std::async(std::launch::async, [&] {
      return managed_connections1.Bootstrap(std::vector<Endpoint>(1, endpoint2),
                                            message_received_functor,
                                            connection_lost_functor,
                                            endpoint1);});  // NOLINT (Fraser)

  auto a2 = std::async(std::launch::async, [&] {
      return managed_connections2.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                            message_received_functor,
                                            connection_lost_functor,
                                            endpoint2);});  // NOLINT (Fraser)

  EXPECT_FALSE(a2.get().address().is_unspecified());
  EXPECT_FALSE(a1.get().address().is_unspecified());

  boost::asio::ip::udp::endpoint bootstrap_endpoint =
      managed_connections3.Bootstrap(std::vector<Endpoint>(1, endpoint1),
                                     message_received_functor,
                                     connection_lost_functor);

  EXPECT_FALSE(bootstrap_endpoint.address().is_unspecified());

  EndpointPair new_endpoint_pair, new_endpoint_pair1;
  EXPECT_EQ(kSuccess, managed_connections1.GetAvailableEndpoint(&new_endpoint_pair));
  EXPECT_TRUE(IsValid(new_endpoint_pair.external));
  EXPECT_TRUE(IsValid(new_endpoint_pair.local));
  EXPECT_EQ(kSuccess, managed_connections2.GetAvailableEndpoint(&new_endpoint_pair1));
  EXPECT_TRUE(IsValid(new_endpoint_pair1.external));
  EXPECT_TRUE(IsValid(new_endpoint_pair1.local));

  managed_connections1.Remove(endpoint2);
  boost::mutex::scoped_lock lock(mutex);
  do {
    lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    lock.lock();
  } while (connection_lost_count != 2);
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
