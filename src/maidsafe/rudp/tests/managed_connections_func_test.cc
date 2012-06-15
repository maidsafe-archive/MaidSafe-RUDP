///*******************************************************************************
// *  Copyright 2012 MaidSafe.net limited                                        *
// *                                                                             *
// *  The following source code is property of MaidSafe.net limited and is not   *
// *  meant for external use.  The use of this code is governed by the licence   *
// *  file licence.txt found in the root of this directory and also on           *
// *  www.maidsafe.net.                                                          *
// *                                                                             *
// *  You are not free to copy, amend or otherwise use this source code without  *
// *  the explicit written permission of the board of directors of MaidSafe.net. *
// ******************************************************************************/                    
//
//#include "maidsafe/rudp/managed_connections.h"
//
//#include <atomic>
//#include <chrono>
//#include <future>
//#include <functional>
//#include <vector>
//
//#include "maidsafe/common/log.h"
//#include "maidsafe/common/test.h"
//#include "maidsafe/common/utils.h"
//
//#include "maidsafe/rudp/return_codes.h"
//#include "maidsafe/rudp/tests/test_utils.h"
//#include "maidsafe/rudp/utils.h"
//
//namespace args = std::placeholders;
//namespace asio = boost::asio;
//namespace bptime = boost::posix_time;
//namespace ip = asio::ip;
//
//namespace maidsafe {
//
//namespace rudp {
//
//typedef boost::asio::ip::udp::endpoint Endpoint;
//
//namespace test {
//
//namespace {
//
//class TestNode {
// public:
//  explicit TestNode(uint32_t id)
//      : node_id_(id),
//        mutex_(),
//        connection_lost_endpoints_(),
//        messages_(),
//        managed_connection_(),
//        promised_(false),
//        total_message_count_expectation_(0),
//        message_promise_() {}
//
//  void MessageReceived(const std::string &message) {
//    LOG(kInfo) << node_id_ << " -- Received: " << message.substr(0, 10);
//    std::lock_guard<std::mutex> guard(mutex_);
//    if ("validation_data" == message)
//      ++validation_data_count_;
//    else
//      messages_.emplace_back(message);
//    SetPromiseIfDone();
//  }
//
//  void ConnectionLost(const Endpoint &endpoint) {
//    LOG(kInfo) << node_id_ << " -- Lost connection to " << endpoint;
//    std::lock_guard<std::mutex> guard(mutex_);
//    connection_lost_endpoints_.emplace_back(endpoint);
//    SetPromiseIfDone();
//  }
//
//  std::vector<Endpoint> connection_lost_endpoints() {
//    std::lock_guard<std::mutex> guard(mutex_);
//    return connection_lost_endpoints_;
//  }
//
//  std::vector<std::string> messages() {
//    std::lock_guard<std::mutex> guard(mutex_);
//    return messages_;
//  }
//
//  std::vector<Endpoint> local_endpoints() {
//    std::lock_guard<std::mutex> guard(mutex_);
//    return local_endpoints_;
//  }
//
//  std::vector<Endpoint> connected_endpoints() {
//    std::lock_guard<std::mutex> guard(mutex_);
//    return connected_endpoints_;
//  }
//
//  ManagedConnections& managed_connection() {
//    return managed_connection_;
//  }
//
//  Endpoint Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints,
//                     Endpoint local_endpoint) {
//    MessageReceivedFunctor message_received_functor =
//        std::bind(&TestNode::MessageReceived, this, args::_1);
//    ConnectionLostFunctor connection_lost_functor =
//        std::bind(&TestNode::ConnectionLost, this, args::_1);
//    local_endpoints_.push_back(local_endpoint);
//    return managed_connection_.Bootstrap(bootstrap_endpoints,
//                                         message_received_functor,
//                                         connection_lost_functor,
//                                         local_endpoint);
//  }
//
//  int GetAvailableEndpoint(EndpointPair &endpoint_pair) {
//    return managed_connection_.GetAvailableEndpoint(endpoint_pair);
//  }
//
//  int Add(const Endpoint &this_endpoint,
//          const Endpoint &peer_endpoint,
//          const std::string &validation_data) {
//    {
//      std::lock_guard<std::mutex> guard(mutex_);
//      connected_endpoints_.push_back(peer_endpoint);
//    }
//    return  managed_connection_.Add(this_endpoint, peer_endpoint, validation_data);
//  }
//
//  void Send(const boost::asio::ip::udp::endpoint &peer_endpoint,
//           const std::string &message,
//           const MessageSentFunctor &message_sent_functor) {
//    managed_connection_.Send(peer_endpoint, message, message_sent_functor);
//  }
//
//  void reset() {
//    std::lock_guard<std::mutex> guard(mutex_);
//    connection_lost_endpoints_.clear();
//    messages_.clear();
//    total_message_count_expectation_ = 0;
//  }
//
//  std::future<bool> GetFutureForMessages(const uint16_t &message_count) {
//    BOOST_ASSERT(message_count > 0);
//    total_message_count_expectation_ = message_count;
//    promised_ = true;
//    std::promise<bool> message_promise;
//    message_promise_.swap(message_promise);
//    return message_promise_.get_future();
//  }
//
//  int GetReceivedMessageCount(const std::string &message) {
//    std::lock_guard<std::mutex> guard(mutex_);
//    return static_cast<int>(std::count(messages_.begin(), messages_.end(), message));
//  }
//
// protected:
//  void SetPromiseIfDone() {
//    if (promised_) {
//      if (messages_.size() >= total_message_count_expectation_) {
//        message_promise_.set_value(true);
//        promised_ = false;
//        total_message_count_expectation_ = 0;
//      } else if (connection_lost_endpoints_.size() != 0) {
//        message_promise_.set_value(true);
//        promised_ = false;
//        total_message_count_expectation_ = 0;
//      }
//    }
//  }
//
// private:
//  uint32_t node_id_;
//  std::mutex mutex_;
//  std::vector<Endpoint> local_endpoints_;
//  std::vector<Endpoint> connected_endpoints_;
//  std::vector<Endpoint> connection_lost_endpoints_;
//  uint16_t validation_data_count_;
//  std::vector<std::string> messages_;
//  ManagedConnections managed_connection_;
//  bool promised_;
//  uint32_t total_message_count_expectation_;
//  std::promise<bool> message_promise_;
//};
//
//typedef std::shared_ptr<TestNode> TestNodePtr;
//}  // anonymous namspace
//
//class ManagedConnectionsFuncTest : public testing::Test {
// public:
//  ManagedConnectionsFuncTest()
//      : mutex_(),
//        nodes_(),
//        bootstrap_endpoints_(),
//        network_size_(0) {}
//
//  ~ManagedConnectionsFuncTest() {}
//
// protected:
//  bool SetupNetwork(const uint16_t &node_count) {
//    network_size_ = node_count;
//    std::lock_guard<std::mutex> guard(mutex_);
//    BOOST_ASSERT_MSG(node_count > 1, "Network size must be greater than 1");
//    nodes_.clear();
//    bootstrap_endpoints_.clear();
//
//    // Setting up first two nodes
//    TestNodePtr node1(std::make_shared<TestNode>(0));
//    TestNodePtr node2(std::make_shared<TestNode>(1));
//    Endpoint endpoint1(GetLocalIp(), GetRandomPort()),
//             endpoint2(GetLocalIp(), GetRandomPort());
//    auto a1 = std::async(std::launch::async, &TestNode::Bootstrap, node1.get(),
//                         std::vector<Endpoint>(1, endpoint2), endpoint1);
//    auto a2 = std::async(std::launch::async, &TestNode::Bootstrap, node2.get(),
//                         std::vector<Endpoint>(1, endpoint1), endpoint2);
//    bool result1 = a1.get().address().is_unspecified();
//    bool result2 = a2.get().address().is_unspecified();
//    EXPECT_FALSE(result1);
//    EXPECT_FALSE(result2);
//    if (result1 || result2) {
//      return false;
//    }
//    LOG(kInfo) << "Calling Add from " << endpoint1 << " to " << endpoint2;
//    EXPECT_EQ(kSuccess,
//              node1->managed_connection().Add(endpoint1, endpoint2,
//                                              "0's validation_data"));
//    LOG(kInfo) << "Calling Add from " << endpoint2 << " to " << endpoint1;
//    EXPECT_EQ(kSuccess,
//              node2->managed_connection().Add(endpoint2, endpoint1,
//                                              "1's validation_data"));
//    nodes_.push_back(node1);
//    nodes_.push_back(node2);
//    bootstrap_endpoints_.push_back(endpoint1);
//    bootstrap_endpoints_.push_back(endpoint2);
//
//    LOG(kInfo) << "Setting up remaining " << (node_count - 2) << " nodes";
//    // Setting up remaining (node_count - 2) nodes
//    std::vector<std::future<Endpoint>> results;
//    results.reserve(node_count - 2);
//    for (uint16_t i = 0; i != node_count - 2; ++i) {
//      TestNodePtr node(std::make_shared<TestNode>(i+2));
//      Endpoint endpoint = Endpoint();
//      results.emplace_back(
//          std::async(std::launch::async, [=] () {return node->Bootstrap(bootstrap_endpoints_,
//                                                                        endpoint); }));
//      nodes_.push_back(node);
//    }
//    // Waiting for results
//    for (uint16_t i = 0; i != node_count - 2; ++i) {
//      bool failed = results.at(i).get().address().is_unspecified();
//      if (failed) {
//        nodes_.clear();
//        bootstrap_endpoints_.clear();
//        return false;
//      }
//    }
//    // TODO(Prakash): Check for validation messages at each node
//    bootstrap_endpoints_.clear();
//    // Adding nodes to each other
//    EndpointPair endpoint_pair1, endpoint_pair2;
//    for (uint16_t i = 0; i != node_count; ++i) {
//      for (uint16_t j = 0; j != node_count; ++j) {
//        if ((j > i)) {  //  connecting all combination of nodes
//          EXPECT_EQ(kSuccess, nodes_.at(i)->GetAvailableEndpoint(endpoint_pair1));
//          EXPECT_EQ(kSuccess, nodes_.at(j)->GetAvailableEndpoint(endpoint_pair2));
//          EXPECT_NE(Endpoint(), endpoint_pair1.local);
//          EXPECT_NE(Endpoint(), endpoint_pair1.external);
//          EXPECT_NE(Endpoint(), endpoint_pair2.local);
//          EXPECT_NE(Endpoint(), endpoint_pair2.external);
//          int return_code1 =  nodes_.at(i)->Add(endpoint_pair1.external, endpoint_pair2.external,
//                                                "validation_data");
//          int return_code2 = nodes_.at(j)->Add(endpoint_pair2.external, endpoint_pair1.external,
//                                               "validation_data");
//          if (return_code1 != kSuccess || return_code2 != kSuccess) {
//            LOG(kError) << "Failed to add node -" << i << " to node " << j;
//            nodes_.clear();
//            bootstrap_endpoints_.clear();
//            return false;
//          }
//        }
//      }
//      bootstrap_endpoints_.push_back(endpoint_pair1.external);
//    }
//    return true;
//  }
//
//  // Each node sending n messsages to all other connected nodes.
//  void RunNetworkTest(const uint16_t &num_messages, const int &messages_size) {
//                                                                              std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // to allow actual connection between nodes
//    uint16_t messages_received_per_node = num_messages * (network_size_ - 1);
//    std::vector<std::string> sent_messages;
//    std::vector<std::future<bool>> futures;
//
//    // Generate_messages
//    for (uint16_t i = 0; i != nodes_.size(); ++i) {
//      sent_messages.emplace_back(std::move(RandomString(messages_size)));
//    }
//
//    // Get futures for messages from individual nodes
//    for (uint16_t i = 0; i != nodes_.size(); ++i) {
//      futures.emplace_back(nodes_.at(i)->GetFutureForMessages(messages_received_per_node));
//    }
//
//    // Sending messages
//    for (uint16_t i = 0; i != nodes_.size(); ++i) {
//      std::vector<Endpoint> peers(nodes_.at(i)->connected_endpoints());
//      LOG(kInfo)<< "// Size of peers---" << peers.size();
//      std::for_each(peers.begin(), peers.end(), [&](const Endpoint& peer) {
//        // TODO(Fraser#5#): 2012-06-14 - Use valid MessageSentFunctor and check results
//        for (uint16_t j = 0; j != num_messages; ++j)
//          nodes_.at(i)->Send(peer, sent_messages.at(i), MessageSentFunctor());
//      });
//    }
//    // Waiting for all results (promises)
//    std::vector<bool> results;
//    for (uint16_t i = 0; i != nodes_.size(); ++i) {
//      if (futures.at(i).wait_for(std::chrono::milliseconds(1000)) ==
//        std::future_status::timeout) {
//        LOG(kError) << "Timed out !!!!!!!!!!";
//        results.push_back(false);
//      } else {
//        results.push_back(futures.at(i).get());
//        EXPECT_TRUE(results.at(i));
//      }
//    }
//    // Check messages
//    for (uint16_t i = 0; i != nodes_.size(); ++i) {
//      for (uint16_t j = 0; j != sent_messages.size(); ++j) {
//        if (i != j) {
//          EXPECT_EQ(num_messages, nodes_.at(i)->GetReceivedMessageCount(sent_messages.at(j)));
//        }
//      }
//    }
//  }
//
//  std::vector<Endpoint> bootstrap_endpoints() { return bootstrap_endpoints_; }
//
// private:
//  std::mutex mutex_;
//  std::vector<TestNodePtr> nodes_;
//  std::vector<Endpoint> bootstrap_endpoints_;
//  uint16_t network_size_;
//};
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSmallMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(1, 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_Network256KBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(1, 1024 * 1024 * 256);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_Network512KBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(1, 1024 * 1024 * 512);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_Network1MBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(1, 1024 * 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_Network2MBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(1, 1024 * 1024 * 2);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultipleSmallMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(10, 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple256KBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(10, 1024 * 1024 * 256);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple512KBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(10, 1024 * 1024 * 512);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple1MBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(10, 1024 * 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple2MBMessages) {
//  ASSERT_TRUE(SetupNetwork(4));
//  RunNetworkTest(10, 1024 * 1024 * 2);
//}
//
//}  // namespace test
//
//}  // namespace rudp
//
//}  // namespace maidsafe
