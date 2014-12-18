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
#include <deque>
#include <functional>
#include <vector>

#include "asio/use_future.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace Asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = Asio::ip;

namespace std {
std::ostream& operator<<(std::ostream& os, const std::vector<unsigned char>& data) {
  bool is_printable(true);
  for (const auto& elem : data) {
    if (elem < 32) { is_printable = false; break; }
  }

  std::string str(data.begin(), data.end());

  if (is_printable) {
    os << "[vector: \"" << str.substr(0,30) << "\"]";
  }
  else {
    os << "[vector: " << maidsafe::HexEncode(str.substr(0,30)) << "]";
  }

  return os;
}
} // std::namespace

namespace maidsafe {

namespace rudp {

typedef Asio::ip::udp::endpoint Endpoint;

namespace test {

class ManagedConnectionsFuncTest : public testing::Test {
 public:
  ManagedConnectionsFuncTest() : nodes_(), bootstrap_endpoints_(), network_size_(4), mutex_() {}

 protected:
  // Each node sending n messsages to all other connected nodes.
  void RunNetworkTest(uint8_t num_messages, int messages_size) {
    LOG(kVerbose) << "peter RunNetworkTest";
    using std::vector;

    uint16_t messages_received_per_node = num_messages * (network_size_ - 1);
    vector<Node::messages_t> sent_messages;
    vector<boost::future<Node::messages_t>> futures;

    // Generate_messages
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      sent_messages.push_back(Node::messages_t());
      std::string message_prefix(std::string("Msg from ") + nodes_[i]->id() + " ");
      for (uint8_t j = 0; j != num_messages; ++j) {
        auto message = message_prefix + std::string(messages_size - message_prefix.size(), 'A' + j);

        sent_messages[i].push_back(Node::message_t(message.begin(), message.end()));
      }
    }

    // Get futures for messages from individual nodes
    for (auto node_ptr : nodes_) {
      node_ptr->ResetData();
      futures.emplace_back(node_ptr->GetFutureForMessages(messages_received_per_node));
    }

    // FIXME: Wait for the send futures somewhere below receiving.
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      vector<NodeId> peers(nodes_.at(i)->GetConnectedNodeIds());
      ASSERT_EQ(nodes_.size() - 1, peers.size());
      for (uint16_t j = 0; j != peers.size(); ++j) {
        for (uint8_t k = 0; k != num_messages; ++k) {
          Sleep(std::chrono::seconds(1));
          try {
            nodes_.at(i)->managed_connections()->Send(
                peers.at(j), sent_messages[i][k], asio::use_future).get();
          }
          catch (std::system_error e) {
            LOG(kVerbose) << "Can't send "
                          << nodes_.at(i)->id() << " " << nodes_.at(j)->id()
                          << " " << e.what();
          }
        }
      }
    }

    // Waiting for all results (promises)
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      boost::chrono::seconds timeout(
          (i == 0 ? num_messages * nodes_.size()
                  : (nodes_.size() - i))
          * (messages_size > (128 * 1024) ? messages_size / (128 * 1024) 
                                          : 1));

      if (futures.at(i).wait_for(timeout) == boost::future_status::ready) {
        auto messages(futures.at(i).get());
        EXPECT_FALSE(messages.empty()) << "Something";
      } else {
        EXPECT_FALSE(true) << "Timed out on " << nodes_.at(i)->id();
      }
    }

    // Check send results
    for (uint16_t i = 0; i != nodes_.size(); ++i) {
      for (uint16_t j = 0; j != nodes_.size(); ++j) {
        for (uint8_t k = 0; k != num_messages; ++k) {
          if (i != j) {
            EXPECT_EQ(1U, nodes_.at(i)->GetReceivedMessageCount(sent_messages[j][k]))
                << nodes_.at(i)->id() << " didn't receive";
          }
        }
      }
    }
  }

  std::vector<NodePtr> nodes_;
  std::vector<Contact> bootstrap_endpoints_;
  uint16_t network_size_;

 private:
  std::mutex mutex_;
};

//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle1kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(1, 1024);
//}

//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle256kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(1, 1024 * 256);
//}

//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle512kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(1, 1024 * 512);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle1MBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(1, 1024 * 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkSingle2MBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(1, 1024 * 1024 * 2);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple1kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(10, 1024);
//}

//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple256kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(10, 1024 * 256);
//}

//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple512kBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(10, 1024 * 512);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple1MBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(10, 1024 * 1024);
//}
//
//TEST_F(ManagedConnectionsFuncTest, FUNC_API_NetworkMultiple2MBMessages) {
//  ASSERT_TRUE(SetupNetwork(nodes_, bootstrap_endpoints_, network_size_));
//  RunNetworkTest(10, 1024 * 1024 * 2);
//}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
