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

uint16_t GetRandomPort() {
  static std::set<uint16_t> already_used_ports;
  bool unique(false);
  uint16_t port(0);
  do {
    port = (RandomUint32() % 48126) + 1025;
    unique = (already_used_ports.insert(port)).second;
  } while (!unique);
  return port;
}

void MessageReceived(const std::string &message) {
  DLOG(INFO) << "Received: " << message;
}

void ConnectionLost(const Endpoint &endpoint, std::atomic<int> *count) {
  DLOG(INFO) << "Lost connection to " << endpoint;
  ++(*count);
}

void WaitForCount(const int &expected_count, std::atomic<int> *count) {
  std::mutex mutex;
  std::unique_lock<std::mutex> lock(mutex);
  while (expected_count != *count) {
    lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    lock.lock();
  }
}

class TestNode {
 public:
  explicit TestNode(uint32_t id)
      : node_id_(id),
        mutex_(),
        connection_lost_endpoints_(),
        messages_(),
        managed_connection_(),
        promised_(false),
        total_message_count_expectation_(0),
        message_promise_() {}

  void MessageReceived(const std::string &message) {
    DLOG(INFO) << node_id_ << " -- Received: " << message.substr(0, 10);
    std::lock_guard<std::mutex> guard(mutex_);
    messages_.emplace_back(message);
    SetPromiseIfDone();
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

  Endpoint local_endpoint() {
    std::lock_guard<std::mutex> guard(mutex_);
    return local_endpoint_;
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
    local_endpoint_ = local_endpoint;
    return managed_connection_.Bootstrap(bootstrap_endpoints,
                                         message_received_functor,
                                         connection_lost_functor,
                                         local_endpoint);
  }

  void reset() {
    std::lock_guard<std::mutex> guard(mutex_);
    connection_lost_endpoints_.clear();
    messages_.clear();
    total_message_count_expectation_ = 0;
  }

  std::future<std::vector<std::string>> GetFutureForMessages(const uint16_t &message_count) {
    BOOST_ASSERT(message_count > 0);
    total_message_count_expectation_ = message_count;
    promised_ = true;
    std::promise<std::vector<std::string>> message_promise;
    message_promise_.swap(message_promise);
    return message_promise_.get_future();
  }

 protected:
  void SetPromiseIfDone() {
    if (promised_ && messages_.size() >= total_message_count_expectation_) {
      message_promise_.set_value(messages_);
      promised_ = false;
      total_message_count_expectation_ = 0;
    }
  }

 private:
  uint32_t node_id_;
  std::mutex mutex_;
  Endpoint local_endpoint_;
  std::vector<Endpoint> connection_lost_endpoints_;
  std::vector<std::string> messages_;
  ManagedConnections managed_connection_;
  bool promised_;
  uint32_t total_message_count_expectation_;
  std::promise<std::vector<std::string>> message_promise_;
};

typedef std::shared_ptr<TestNode> TestNodePtr;
}  // anonymous namspace

class ManagedConnectionsTest : public testing::Test {
 public:
  ManagedConnectionsTest()
      : mutex_(),
        nodes_(),
        bootstrap_endpoints_() {}

 protected:
  bool SetupNetwork(const uint16_t &node_count) {
    std::lock_guard<std::mutex> guard(mutex_);
    BOOST_ASSERT_MSG(node_count > 1, "Network size must be greater than 1");
    nodes_.clear();
    bootstrap_endpoints_.clear();

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
  // TODO(Prakash): Uncomment below after add is fixed
  // EXPECT_EQ(kSuccess,
  //          node1.managed_connection().Add(this_endpoint_pair1.external, endpoint2,
  //                                          "validation_data"));
  // EXPECT_EQ(kSuccess,
  //          node2.managed_connection().Add(this_endpoint_pair2.external, endpoint1,
  //                                          "validation_data"));
    nodes_.push_back(node1);
    nodes_.push_back(node2);
    bootstrap_endpoints_.emplace_back(endpoint1);
    bootstrap_endpoints_.emplace_back(endpoint2);
    // Setting up remaining (node_count - 2) nodes
    std::vector<std::future<Endpoint>> results;
    results.reserve(node_count - 2);
    for (uint16_t i = 0; i != node_count - 2; ++i) {
      TestNodePtr node(std::make_shared<TestNode>(i+2));
      Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
      results.emplace_back(
          std::async(std::launch::async, &TestNode::Bootstrap, node,
                     bootstrap_endpoints_, endpoint));
      nodes_.push_back(node);
      bootstrap_endpoints_.emplace_back(endpoint);
    }
    // Waiting for results
    for (uint16_t i = 0; i != node_count - 2; ++i) {
      bool result = results.at(i).get().address().is_unspecified();
      if (result) {
        nodes_.clear();
        bootstrap_endpoints_.clear();
        return false;
      }
    }
    // TODO(Prakash): Check for validation messages at each node
    if (bootstrap_endpoints_.size() == node_count)
      return true;
    else
      return false;
  }

  std::vector<Endpoint> bootstrap_endpoints() { return bootstrap_endpoints_; }

  std::future<std::vector<std::string>> GetFutureForMessages(const Endpoint &endpoint,
                                                             const uint16_t &message_count) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto itr = std::find_if(nodes_.begin(), nodes_.end(), [endpoint](TestNodePtr node)->bool
                { return (endpoint == node->local_endpoint()); }); //NOLINT (Prakash)
    return (*itr)->GetFutureForMessages(message_count);
  }

  void Reset(const Endpoint endpoint) {
    std::vector<TestNodePtr>::iterator itr;
    {
    std::lock_guard<std::mutex> guard(mutex_);
    itr = std::find_if(nodes_.begin(), nodes_.end(),
            [endpoint](TestNodePtr node)->bool { return (endpoint == node->local_endpoint()); }); //NOLINT (Prakash)
    }
    if (nodes_.end() != itr)
      return (*itr)->reset();
  }

 private:
  std::mutex mutex_;
  std::vector<TestNodePtr> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
};

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(ip::address_v4::loopback(), 9000),
           endpoint2(ip::address_v4::loopback(), 11111);
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

  EXPECT_EQ(endpoint1, bootstrap_endpoint);
  ASSERT_EQ(2U, managed_connections1.connection_map_.size());
  Endpoint endpoint3((*managed_connections1.connection_map_.rbegin()).first);
                                                              std::cout << endpoint3 << std::endl;
  std::string port3(boost::lexical_cast<std::string>(endpoint3.port()));

  for (int i(0); i != 200; ++i) {
    Sleep(bptime::milliseconds(10));
    std::string message("Message " + boost::lexical_cast<std::string>(i / 2));
    if (i % 2) {
      managed_connections1.Send(endpoint2, message + " from 9000 to 11111");
      managed_connections1.Send(endpoint3, message + " from 9000 to " + port3);
    } else {
      managed_connections2.Send(endpoint1, message + " from 11111 to 9000");
      managed_connections3.Send(endpoint1,
                                message + " from " + port3 + " to 9000");
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

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap_Network) {
  ASSERT_TRUE(SetupNetwork(10));
}

TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap_Parameters) {
  const uint8_t kNetworkSize(2);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));

  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  {  // Valid
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
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
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      MessageReceivedFunctor(),
                                      connection_lost_functor,
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid ConnectionLostFunctor
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      ConnectionLostFunctor(),
                                      endpoint);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid Endpoint
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      connection_lost_functor,
                                      Endpoint());
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Already in use Endpoint
    ManagedConnections managed_connections;
    Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      connection_lost_functor,
                                      bootstrap_endpoints().at(0));
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  EXPECT_EQ(0, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint) {
  const uint8_t kNetworkSize(2);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
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
        managed_connections.Bootstrap(bootstrap_endpoints(),
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
  EXPECT_EQ(0, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint2) {
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

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  const uint8_t kNetworkSize(4);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;
  {  // Before bootstrapping
    Endpoint random_this_endpoint(ip::address_v4::loopback(), GetRandomPort());
    EXPECT_NE(kSuccess,
              managed_connections.Add(random_this_endpoint, bootstrap_endpoints().at(1),
                                      "validation_data"));
  }

  Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor,
                                    endpoint);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);
  EndpointPair this_endpoint_pair;
  {  // Valid
    Endpoint peer(bootstrap_endpoints().at(1));
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    auto future_messages_at_peer(GetFutureForMessages(peer, 1));
    EXPECT_EQ(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, peer, "validation_data"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("validation_data", messages.at(0));
    Reset(peer);
  }
  {  // Invalid peer endpoint
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    EXPECT_NE(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, Endpoint(), "validation_data"));
  }
  {  // Invalid this endpoint
    EXPECT_NE(kSuccess,
              managed_connections.Add(Endpoint(), bootstrap_endpoints().at(1), "validation_data"));
  }
  {  // Unavailable peer endpoint
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    Endpoint unavailable_endpoint(ip::address_v4::loopback(), GetRandomPort());
    EXPECT_NE(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, unavailable_endpoint,
                                      "validation_data"));
  }
  {  // Unavailable this endpoint
    Endpoint unavailable_endpoint(ip::address_v4::loopback(), GetRandomPort());
    EXPECT_NE(kSuccess,
              managed_connections.Add(unavailable_endpoint, bootstrap_endpoints().at(2),
                                      "validation_data"));
  }
  EXPECT_EQ(0, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  const uint8_t kNetworkSize(5);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived, args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;

  // Before Bootstrap
  managed_connections.Remove(bootstrap_endpoints().at(1));
  ASSERT_EQ(0, connection_lost_count);

  Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor,
                                    endpoint);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);

  // Before Add
  managed_connections.Remove(bootstrap_endpoints().at(1));
  ASSERT_EQ(0, connection_lost_count);

  EndpointPair this_endpoint_pair;
  for (auto i(1); i< kNetworkSize; ++i) {
    Endpoint peer(bootstrap_endpoints().at(i));
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    auto future_messages_at_peer(GetFutureForMessages(peer, 1));
    EXPECT_EQ(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, peer, "validation_data"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("validation_data", messages.at(0));
    Reset(peer);
  }
  // InValid endpoint
  managed_connections.Remove(Endpoint());
  ASSERT_EQ(0, connection_lost_count);

  // Unknown endpoint
  managed_connections.Remove(Endpoint(ip::address_v4::loopback(), GetRandomPort()));
  ASSERT_EQ(0, connection_lost_count);

  // Valid
  managed_connections.Remove(bootstrap_endpoints().at(1));
  WaitForCount(1, &connection_lost_count);

  // Already removed endpoint
  managed_connections.Remove(bootstrap_endpoints().at(1));
  ASSERT_EQ(1, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_Send) {
  const uint8_t kNetworkSize(4);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived, args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;
  Endpoint endpoint(ip::address_v4::loopback(), GetRandomPort());
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor,
                                    endpoint);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);
  EndpointPair this_endpoint_pair;
  for (auto i(1); i< kNetworkSize; ++i) {
    Endpoint peer(bootstrap_endpoints().at(i));
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(&this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    auto future_messages_at_peer(GetFutureForMessages(peer, 1));
    EXPECT_EQ(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, peer, "validation_data"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("validation_data", messages.at(0));
    Reset(peer);
  }

  // Invalid endpoint
  EXPECT_NE(kSuccess, managed_connections.Send(Endpoint(), "message"));

  // Unavailable endpoint
  EXPECT_NE(kSuccess,
            managed_connections.Send(Endpoint(ip::address_v4::loopback(), GetRandomPort()),
            "message"));
  { // Valid
    Endpoint peer(bootstrap_endpoints().at(0));
    auto future_messages_at_peer(GetFutureForMessages(peer, 1));
    EXPECT_EQ(kSuccess, managed_connections.Send(peer, "message"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("message", messages.at(0));
    Reset(peer);
  }
  { // Valid large messages
    Endpoint peer(bootstrap_endpoints().at(0));
    std::string sent_message(std::move(RandomString(1024 * 1024)));
    auto future_messages_at_peer(GetFutureForMessages(peer, 1));
    EXPECT_EQ(kSuccess, managed_connections.Send(peer, sent_message));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ(sent_message, messages.at(0));
    Reset(peer);
  }
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
