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

#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/tests/test_utils.h"
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

  int GetAvailableEndpoint(EndpointPair &endpoint_pair) {
    return managed_connection_.GetAvailableEndpoint(endpoint_pair);
  }

  int Add(const Endpoint &this_endpoint, const Endpoint &peer_endpoint,
          const std::string &validation_data) {
    return  managed_connection_.Add(this_endpoint, peer_endpoint, validation_data);
  }

  void reset_count() {
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

  ~ManagedConnectionsTest() {}

 protected:
  bool SetupNetwork(const uint16_t &node_count) {
    std::lock_guard<std::mutex> guard(mutex_);
    BOOST_ASSERT_MSG(node_count > 1, "Network size must be greater than 1");
    nodes_.clear();
    bootstrap_endpoints_.clear();

    // Setting up first two nodes
    TestNodePtr node1(std::make_shared<TestNode>(1));
    TestNodePtr node2(std::make_shared<TestNode>(2));
    Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
             endpoint2(GetLocalIp(), GetRandomPort());
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
              node1->managed_connection().GetAvailableEndpoint(this_endpoint_pair1));
    EXPECT_EQ(kSuccess,
              node2->managed_connection().GetAvailableEndpoint(this_endpoint_pair2));
    EXPECT_NE(Endpoint(), this_endpoint_pair1.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair1.external);
    EXPECT_NE(Endpoint(), this_endpoint_pair2.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair2.external);
    EXPECT_EQ(kSuccess,
              node1->managed_connection().Add(this_endpoint_pair1.external,
                                              this_endpoint_pair2.external,
                                              "validation_data"));
    EXPECT_EQ(kSuccess,
              node2->managed_connection().Add(this_endpoint_pair2.external,
                                              this_endpoint_pair1.external,
                                              "validation_data"));
    nodes_.push_back(node1);
    nodes_.push_back(node2);
    bootstrap_endpoints_.push_back(endpoint1);
    bootstrap_endpoints_.push_back(endpoint2);

    DLOG(INFO) << "Setting up remaining " << (node_count - 2) << " nodes";
    // Setting up remaining (node_count - 2) nodes
    std::vector<std::future<Endpoint>> results;
    results.reserve(node_count - 2);
    for (uint16_t i = 0; i != node_count - 2; ++i) {
      TestNodePtr node(std::make_shared<TestNode>(i+2));
      Endpoint endpoint = Endpoint();
      results.emplace_back(
          std::async(std::launch::async, &TestNode::Bootstrap, node,
                     bootstrap_endpoints_, endpoint));
      nodes_.push_back(node);
    }
    // Waiting for results
    for (uint16_t i = 0; i != node_count - 2; ++i) {
      bool failed = results.at(i).get().address().is_unspecified();
      if (failed) {
        nodes_.clear();
        bootstrap_endpoints_.clear();
        return false;
      }
    }
    // TODO(Prakash): Check for validation messages at each node

    // Adding nodes to each other
    EndpointPair endpoint_pair1, endpoint_pair2;
    for (uint16_t i = 2; i != node_count; ++i) {
      for (uint16_t j = 2; j != node_count; ++j) {
        if ((j > i)) {  //  connecting all combination of nodes
          EXPECT_EQ(kSuccess,
                    nodes_.at(i)->managed_connection().GetAvailableEndpoint(endpoint_pair1));
          EXPECT_EQ(kSuccess,
                    nodes_.at(j)->managed_connection().GetAvailableEndpoint(endpoint_pair2));
          EXPECT_NE(Endpoint(), endpoint_pair1.local);
          EXPECT_NE(Endpoint(), endpoint_pair1.external);
          EXPECT_NE(Endpoint(), endpoint_pair2.local);
          EXPECT_NE(Endpoint(), endpoint_pair2.external);
          int return_code1 =
              nodes_.at(i)->managed_connection().Add(endpoint_pair1.external,
                                                     endpoint_pair2.external,
                                                     "validation_data");
          int return_code2 =
              nodes_.at(i)->managed_connection().Add(endpoint_pair2.external,
                                                     endpoint_pair1.external,
                                                     "validation_data");
          if (return_code1 != kSuccess && return_code2 != kSuccess) {
            DLOG(ERROR) << "Failed to add node -" << i << " to node " << j;
            nodes_.clear();
            bootstrap_endpoints_.clear();
            return false;
          }
        }
        bootstrap_endpoints_.push_back(endpoint_pair1.external);
      }
    }
    return true;
  }

  std::vector<Endpoint> bootstrap_endpoints() { return bootstrap_endpoints_; }

  std::vector<TestNodePtr> & nodes() {
    return nodes_;
  }

 private:
  std::mutex mutex_;
  std::vector<TestNodePtr> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
};

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
    Endpoint endpoint(GetLocalIp(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      connection_lost_functor);
    EXPECT_NE(Endpoint(), bootstrap_endpoint);
  }
  {  // All invalid
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(),
                                    MessageReceivedFunctor(),
                                    ConnectionLostFunctor());
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid bootstrap_endpoints
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(std::vector<Endpoint>(),
                                      message_received_functor,
                                      connection_lost_functor);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Empty bootstrap_endpoints
    ManagedConnections managed_connections;
    std::vector<Endpoint> empty_bootstrap_endpoints;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(empty_bootstrap_endpoints,
                                      message_received_functor,
                                      connection_lost_functor);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Unavailable bootstrap_endpoints
    ManagedConnections managed_connections;
    Endpoint endpoint(GetLocalIp(), GetRandomPort());
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(std::vector<Endpoint>(1, endpoint),
                                      message_received_functor,
                                      connection_lost_functor);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid MessageReceivedFunctor
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      MessageReceivedFunctor(),
                                      connection_lost_functor);
    EXPECT_EQ(Endpoint(), bootstrap_endpoint);
  }
  {  // Invalid ConnectionLostFunctor
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      ConnectionLostFunctor());
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
    EndpointPair this_endpoint_pair;
    EXPECT_EQ(kNoneAvailable,
              managed_connections.GetAvailableEndpoint(this_endpoint_pair));
    EXPECT_EQ(Endpoint(), this_endpoint_pair.local);
    EXPECT_EQ(Endpoint(), this_endpoint_pair.external);
  }
  {  //  After Bootstrapping
    ManagedConnections managed_connections;
    Endpoint bootstrap_endpoint =
        managed_connections.Bootstrap(bootstrap_endpoints(),
                                      message_received_functor,
                                      connection_lost_functor);
    EXPECT_NE(Endpoint(), bootstrap_endpoint);
    EndpointPair this_endpoint_pair;
    EXPECT_EQ(kSuccess,
              managed_connections.GetAvailableEndpoint(this_endpoint_pair));
    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  }
  EXPECT_EQ(0, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_Add) {
  const uint8_t kNetworkSize(2);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived,
                                                            args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;
  {  // Before bootstrapping
    Endpoint random_this_endpoint(GetLocalIp(), GetRandomPort());
    EXPECT_NE(kSuccess,
              managed_connections.Add(random_this_endpoint, bootstrap_endpoints().at(1),
                                      "validation_data"));
  }
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);
  {  // Valid
    this->nodes().at(0)->reset_count();
    EndpointPair this_endpoint_pair;
    EndpointPair peer_endpoint_pair;
    EXPECT_EQ(kSuccess, this->nodes().at(0)->GetAvailableEndpoint(peer_endpoint_pair));
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(this_endpoint_pair));

    EXPECT_NE(Endpoint(), this_endpoint_pair.local);
    EXPECT_NE(Endpoint(), this_endpoint_pair.external);
    EXPECT_TRUE(IsValid(this_endpoint_pair.local));
    EXPECT_TRUE(IsValid(this_endpoint_pair.external));
    EXPECT_NE(Endpoint(), peer_endpoint_pair.local);
    EXPECT_NE(Endpoint(), peer_endpoint_pair.external);
    EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
    EXPECT_TRUE(IsValid(peer_endpoint_pair.external));
    auto future_messages_at_peer(this->nodes().at(0)->GetFutureForMessages(1));
    EXPECT_EQ(kSuccess,
              this->nodes().at(0)->Add(peer_endpoint_pair.external, this_endpoint_pair.external,
                                       "validation_data"));
    EXPECT_EQ(kSuccess,
              managed_connections.Add(this_endpoint_pair.external, peer_endpoint_pair.external,
                                      "validation_data"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("validation_data", messages.at(0));

    this->nodes().at(0)->reset_count();
  }
  {  // Invalid peer endpoint
    EndpointPair this_endpoint_pair;
    EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(this_endpoint_pair));
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
  //{  // Unavailable peer endpoint
  //  EndpointPair this_endpoint_pair;
  //  EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(this_endpoint_pair));
  //  EXPECT_NE(Endpoint(), this_endpoint_pair.local);
  //  EXPECT_NE(Endpoint(), this_endpoint_pair.external);
  //  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  //  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  //  Endpoint unavailable_endpoint(GetLocalIp(), GetRandomPort());
  //  EXPECT_NE(kSuccess,
  //            managed_connections.Add(this_endpoint_pair.external, unavailable_endpoint,
  //                                    "validation_data"));
  //}
  //{  // Unavailable this endpoint
  //  Endpoint unavailable_endpoint(GetLocalIp(), GetRandomPort());
  //  EXPECT_NE(kSuccess,
  //            managed_connections.Add(unavailable_endpoint, bootstrap_endpoints().at(2),
  //                                    "validation_data"));
  //}
  EXPECT_EQ(0, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_Remove) {
  const uint8_t kNetworkSize(4);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived, args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;

  // Before Bootstrap
  managed_connections.Remove(bootstrap_endpoints().at(1));
  ASSERT_EQ(0, connection_lost_count);

  Endpoint endpoint(GetLocalIp(), GetRandomPort());
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor,
                                    endpoint);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);

  // Before Add
  managed_connections.Remove(bootstrap_endpoints().at(1));
  ASSERT_EQ(0, connection_lost_count);

  // Add
  this->nodes().at(0)->reset_count();
  EndpointPair this_endpoint_pair;
  EndpointPair peer_endpoint_pair;
  EXPECT_EQ(kSuccess, this->nodes().at(0)->GetAvailableEndpoint(peer_endpoint_pair));
  EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(this_endpoint_pair));

  EXPECT_NE(Endpoint(), this_endpoint_pair.local);
  EXPECT_NE(Endpoint(), this_endpoint_pair.external);
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_NE(Endpoint(), peer_endpoint_pair.local);
  EXPECT_NE(Endpoint(), peer_endpoint_pair.external);
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));
  auto future_messages_at_peer(this->nodes().at(0)->GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            this->nodes().at(0)->Add(peer_endpoint_pair.external, this_endpoint_pair.external,
                                     "validation_data"));
  EXPECT_EQ(kSuccess,
            managed_connections.Add(this_endpoint_pair.external, peer_endpoint_pair.external,
                                    "validation_data"));

  auto messages(future_messages_at_peer.get());
  ASSERT_EQ(1, messages.size());
  EXPECT_EQ("validation_data", messages.at(0));

  this->nodes().at(0)->reset_count();

  // InValid endpoint
  managed_connections.Remove(Endpoint());
  ASSERT_EQ(0, connection_lost_count);

  // Unknown endpoint
  managed_connections.Remove(Endpoint(GetLocalIp(), GetRandomPort()));
  ASSERT_EQ(0, connection_lost_count);

  // Valid
  managed_connections.Remove(peer_endpoint_pair.external);
  WaitForCount(1, &connection_lost_count);

  // Already removed endpoint
  managed_connections.Remove(peer_endpoint_pair.external);
  ASSERT_EQ(1, connection_lost_count);
}

TEST_F(ManagedConnectionsTest, BEH_API_Send) {
  const uint8_t kNetworkSize(2);
  ASSERT_TRUE(SetupNetwork(kNetworkSize));
  MessageReceivedFunctor message_received_functor(std::bind(MessageReceived, args::_1));
  std::atomic<int> connection_lost_count(0);
  ConnectionLostFunctor connection_lost_functor(
      std::bind(ConnectionLost, args::_1, &connection_lost_count));
  ManagedConnections managed_connections;
  Endpoint endpoint(GetLocalIp(), GetRandomPort());
  Endpoint bootstrap_endpoint =
      managed_connections.Bootstrap(std::vector<Endpoint>(1, bootstrap_endpoints().at(0)),
                                    message_received_functor,
                                    connection_lost_functor,
                                    endpoint);
  EXPECT_EQ(bootstrap_endpoints().at(0), bootstrap_endpoint);
  this->nodes().at(0)->reset_count();
  EndpointPair this_endpoint_pair;
  EndpointPair peer_endpoint_pair;
  EXPECT_EQ(kSuccess, this->nodes().at(0)->GetAvailableEndpoint(peer_endpoint_pair));
  EXPECT_EQ(kSuccess, managed_connections.GetAvailableEndpoint(this_endpoint_pair));

  EXPECT_NE(Endpoint(), this_endpoint_pair.local);
  EXPECT_NE(Endpoint(), this_endpoint_pair.external);
  EXPECT_TRUE(IsValid(this_endpoint_pair.local));
  EXPECT_TRUE(IsValid(this_endpoint_pair.external));
  EXPECT_NE(Endpoint(), peer_endpoint_pair.local);
  EXPECT_NE(Endpoint(), peer_endpoint_pair.external);
  EXPECT_TRUE(IsValid(peer_endpoint_pair.local));
  EXPECT_TRUE(IsValid(peer_endpoint_pair.external));
  auto future_messages_at_peer(this->nodes().at(0)->GetFutureForMessages(1));
  EXPECT_EQ(kSuccess,
            this->nodes().at(0)->Add(peer_endpoint_pair.external, this_endpoint_pair.external,
                                     "validation_data"));
  EXPECT_EQ(kSuccess,
            managed_connections.Add(this_endpoint_pair.external, peer_endpoint_pair.external,
                                    "validation_data"));
  auto messages(future_messages_at_peer.get());
  ASSERT_EQ(1, messages.size());
  EXPECT_EQ("validation_data", messages.at(0));

  this->nodes().at(0)->reset_count();

  // Invalid endpoint
  EXPECT_NE(kSuccess, managed_connections.Send(Endpoint(), "message"));

  // Unavailable endpoint
  EXPECT_NE(kSuccess,
            managed_connections.Send(Endpoint(GetLocalIp(), GetRandomPort()),
            "message"));
  { // Valid
    auto future_messages_at_peer(this->nodes().at(0)->GetFutureForMessages(1));
    EXPECT_EQ(kSuccess, managed_connections.Send(peer_endpoint_pair.external, "message"));
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ("message", messages.at(0));
    this->nodes().at(0)->reset_count();
  }
  { // Valid large messages
    std::string sent_message(std::move(RandomString(8 * 1024 * 1024)));
    auto future_messages_at_peer(this->nodes().at(0)->GetFutureForMessages(1));
    EXPECT_EQ(kSuccess, managed_connections.Send(peer_endpoint_pair.external, sent_message));       
    auto messages(future_messages_at_peer.get());
    ASSERT_EQ(1, messages.size());
    EXPECT_EQ(sent_message, messages.at(0));
    this->nodes().at(0)->reset_count();
  }
}

// Ad-hoc tests. To be removed later
TEST_F(ManagedConnectionsTest, BEH_API_Bootstrap) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
           endpoint2(GetLocalIp(), GetRandomPort());
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
  std::string port1(boost::lexical_cast<std::string>(endpoint1.port()));
  std::string port2(boost::lexical_cast<std::string>(endpoint2.port()));
  std::string port3(boost::lexical_cast<std::string>(endpoint3.port()));

  for (int i(0); i != 200; ++i) {
    Sleep(bptime::milliseconds(10));
    std::string message("Message " + boost::lexical_cast<std::string>(i / 2));
    if (i % 2) {
      managed_connections1.Send(endpoint2, message + " from " + port1 + " to " + port2);
      managed_connections1.Send(endpoint3, message + " from " + port1 + " to " + port3);
    } else {
      managed_connections2.Send(endpoint1, message + " from " + port2 + " to " + port1);
      managed_connections3.Send(endpoint1, message + " from " + port3 + " to " + port1);
    }
  }

  managed_connections1.Remove(endpoint2);
  boost::mutex::scoped_lock lock(mutex);
  do {
    lock.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    lock.lock();
  } while (connection_lost_count != 2);
}

TEST_F(ManagedConnectionsTest, BEH_API_GetAvailableEndpoint2) {
  ManagedConnections managed_connections1, managed_connections2,
                     managed_connections3;
  Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
           endpoint2(GetLocalIp(), GetRandomPort()),
           endpoint3(GetLocalIp(), GetRandomPort());
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
  EXPECT_EQ(kSuccess, managed_connections1.GetAvailableEndpoint(new_endpoint_pair));
  EXPECT_TRUE(IsValid(new_endpoint_pair.external));
  EXPECT_TRUE(IsValid(new_endpoint_pair.local));
  EXPECT_EQ(kSuccess, managed_connections2.GetAvailableEndpoint(new_endpoint_pair1));
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
