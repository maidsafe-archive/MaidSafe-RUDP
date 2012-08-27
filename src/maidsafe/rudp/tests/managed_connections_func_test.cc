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
#include <deque>
#include <functional>
#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

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

class ManagedConnectionsFuncTest : public testing::Test {
 public:
  ManagedConnectionsFuncTest() : nodes_(), bootstrap_endpoints_(), network_size_(4), mutex_() {}
  ~ManagedConnectionsFuncTest() {}

 protected:
  // Each node sending n messsages to all other connected nodes.
  void RunNetworkTest(const uint16_t& num_messages, const int& messages_size) {
    uint16_t messages_received_per_node = num_messages * (network_size_ - 1);
    std::vector<std::vector<std::string>> sent_messages;
    std::vector<boost::unique_future<std::vector<std::string>>> futures;  // NOLINT (Fraser)

    // Generate_messages
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      sent_messages.push_back(std::vector<std::string>());
      std::string message_prefix(std::string("Msg from ") + nodes_[i]->id() + " ");
      for (uint8_t j = 0; j != num_messages; ++j) {
        sent_messages[i].push_back(
            message_prefix + std::string(messages_size - message_prefix.size(), 'A' + j));
      }
    }

    // Get futures for messages from individual nodes
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      nodes_.at(i)->ResetData();
      futures.emplace_back(nodes_.at(i)->GetFutureForMessages(messages_received_per_node));
    }

    // Sending messages
    std::vector<std::vector<std::vector<int>>> send_results(                      // NOLINT (Fraser)
        nodes_.size(),
        std::vector<std::vector<int>>(                                            // NOLINT (Fraser)
            nodes_.size() - 1,
            std::vector<int>(num_messages, kReturnCodeLimit)));
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      std::vector<Endpoint> peers(nodes_.at(i)->GetConnectedEndPoints());
      ASSERT_EQ(nodes_.size() - 1, peers.size());
      for (uint16_t j = 0; j != peers.size(); ++j) {
        for (uint16_t k = 0; k != num_messages; ++k) {
          nodes_.at(i)->managed_connections()->Send(peers.at(j),
                                                    sent_messages[i][k],
                                                    [=, &send_results](int result_in) {
                                                      send_results[i][j][k] = result_in;
                                                    });
        }
      }
    }

    // Waiting for all results (promises)
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      bptime::milliseconds timeout((num_messages * messages_size / 20) + 5000);
      if (futures.at(i).timed_wait(timeout)) {
        auto messages(futures.at(i).get());
        EXPECT_TRUE(!messages.empty());
      } else {
        EXPECT_FALSE(true) << "Timed out on " << nodes_.at(i)->id();
      }
    }

    // Check send results
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      for (uint16_t j = 0; j != nodes_.size(); ++j) {
        for (uint16_t k = 0; k != num_messages; ++k) {
          if (j != nodes_.size() - 1) {
            EXPECT_EQ(kSuccess, send_results[i][j][k])
                << "send_results[" << i << "][" << j << "][" << k << "]: " << send_results[i][j][k];
          }
          if (i != j) {
            EXPECT_EQ(1U, nodes_.at(i)->GetReceivedMessageCount(sent_messages[j][k]))
                << nodes_.at(i)->id() << " didn't receive " << sent_messages[j][k].substr(0, 20);
          }
        }
      }
    }
  }

  std::vector<std::shared_ptr<Node>> nodes_;
  std::vector<Endpoint> bootstrap_endpoints_;
  uint16_t network_size_;

 private:
  std::mutex mutex_;
};

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle1kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(1, 1024);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle256kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(1, 1024 * 256);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle512kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(1, 1024 * 512);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle1MBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(1, 1024 * 1024);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle2MBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(1, 1024 * 1024 * 2);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple1kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(10, 1024);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple256kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(10, 1024 * 256);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple512kBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(10, 1024 * 512);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple1MBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(10, 1024 * 1024);
}

TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple2MBMessages) {
  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
  RunNetworkTest(10, 1024 * 1024 * 2);
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
