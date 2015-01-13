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

#include <vector>
#include <asio/use_future.hpp> // NOLINT

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/tests/get_within.h"
#include "maidsafe/rudp/async_queue.h"
#include "maidsafe/rudp/utils.h"

namespace Asio = boost::asio;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

using std::chrono::milliseconds;
using message_t = std::vector<unsigned char>;

milliseconds to_std(const boost::posix_time::time_duration& d) {
  return milliseconds(d.total_milliseconds());
}

struct PromiseHandler {
  std::shared_ptr<std::promise<void>> promise;

  PromiseHandler()
    : promise(std::make_shared<std::promise<void>>()) {}

  std::future<void> get_future() { return promise->get_future(); }

  void operator()(std::error_code e) const {
    try {
      if (e) throw std::system_error(e);
      return promise->set_value();
    } catch (const std::exception& ex) {
      promise->set_exception(std::current_exception());
    }
  }
};

class RudpTransportTest : public testing::Test {
 public:
  RudpTransportTest()
      : transports_(),
        network_size_(2),
        kTimeOut_(Parameters::keepalive_interval *
                  (Parameters::maximum_keepalive_failures + 1)) {}

  ~RudpTransportTest() {}

 protected:
  struct TestPeer {
    TestPeer() : local_endpoint(GetLocalIp(), maidsafe::test::GetRandomPort()),
                 asio_service(Parameters::thread_count),
                 node_id(RandomString(NodeId::kSize)),
                 nat_type(NatType::kUnknown) {
      key_pair = asymm::GenerateKeyPair();
      transport.reset(new Transport(asio_service, nat_type));
      auto promise = std::make_shared<std::promise<void>>();

      transport->Bootstrap(
          std::vector<Contact>(),
          node_id,
          key_pair.public_key,
          local_endpoint,
          true,
          boost::bind(&TestPeer::OnMessageSlot, this, _1, _2),
          boost::bind(&TestPeer::OnConnectionAddedSlot, this, _1, _2, _3, _4),
          boost::bind(&TestPeer::OnConnectionLostSlot, this, _1, _2, _3, _4),
          boost::bind(&TestPeer::OnNatDetectionRequestedSlot, this, _1, _2, _3, _4),
          [=](ReturnCode, Contact) {
            promise->set_value();
          });

      promise->get_future().get();
    }

    ~TestPeer() {
       transport->Close();
       asio_service.Stop();
    }

    std::future<message_t> Receive() { return recv_queue.async_pop(asio::use_future); }
    std::future<NodeId> LostFuture() { return lost_queue.async_pop(asio::use_future); }

    void OnMessageSlot(NodeId, std::vector<unsigned char> message) {
      recv_queue.push(std::move(message));
    }

    void OnConnectionAddedSlot(const NodeId&, TransportPtr /*transport*/, bool,
                               Transport::ConnectionPtr) {
    }

    void OnConnectionLostSlot(const NodeId& peer, TransportPtr /*transport*/, bool, bool) {
      lost_queue.push(peer);
    }

    void OnNatDetectionRequestedSlot(const Endpoint& /*this_local_endpoint*/,
                                     const NodeId& /*peer_endpoint*/,
                                     const Endpoint&,
                                     uint16_t& /*another_external_port*/) {
    }

    Endpoint local_endpoint;
    asymm::Keys key_pair;
    std::mutex mutex;
    boost::condition_variable cond_var_connection_added;
    boost::condition_variable cond_var_connection_lost;
    boost::condition_variable cond_var_msg_received;
    async_queue<message_t> recv_queue;
    async_queue<NodeId> lost_queue;
    BoostAsioService asio_service;
    NodeId node_id;
    NatType nat_type;
    std::shared_ptr<Transport> transport;
    std::vector<std::string> messages_received;
    std::vector<NodeId> peers_added;
    std::vector<NodeId> peers_lost;
  };

  void SetUp() {
    for (int i(0); i < network_size_; ++i) {
      std::shared_ptr<TestPeer> test_peer(new TestPeer());
      transports_.push_back(test_peer);
    }
  }

  void TearDown() {
    transports_.clear();
  }

  void ConnectTestPeers() {
    auto promise1 = PromiseHandler();
    auto promise2 = PromiseHandler();

    transports_[0]->transport->Connect(transports_[1]->node_id,
                                       EndpointPair(transports_[1]->local_endpoint),
                                       transports_[1]->key_pair.public_key,
                                       promise1);

    transports_[1]->transport->Connect(transports_[0]->node_id,
                                       EndpointPair(transports_[0]->local_endpoint),
                                       transports_[0]->key_pair.public_key,
                                       promise2);

    promise1.get_future().get();
    promise2.get_future().get();
  }

  std::vector<std::shared_ptr<TestPeer> > transports_;
  uint16_t network_size_;
  bptime::time_duration kTimeOut_;
};

TEST_F(RudpTransportTest, BEH_Connection) {
  ConnectTestPeers();

  std::string msg_content(RandomString(256));

  message_t message;
  PromiseHandler promise;
  transports_[0]->transport->Send(transports_[1]->node_id, msg_content, promise);
  EXPECT_NO_THROW(get_within(promise.get_future(), to_std(kTimeOut_)));
  EXPECT_NO_THROW(message = get_within(transports_[1]->Receive(), to_std(kTimeOut_)));
  EXPECT_EQ(msg_content, std::string(message.begin(), message.end()));
}

TEST_F(RudpTransportTest, BEH_CloseConnection) {
  ConnectTestPeers();
  transports_[1]->transport->CloseConnection(transports_[0]->node_id);
  NodeId lost_peer;
  ASSERT_NO_THROW(lost_peer = get_within(transports_[0]->LostFuture(), to_std(kTimeOut_)));
  EXPECT_EQ(transports_[1]->node_id, lost_peer);

  std::string msg_content("testing msg from node 0");
  PromiseHandler promise;
  transports_[0]->transport->Send(transports_[1]->node_id, msg_content, promise);

  try {
    get_within(promise.get_future(), to_std(kTimeOut_));
    GTEST_FAIL() << "Expected to throw";
  }
  catch (const std::system_error& e) {
    ASSERT_EQ(e.code(), RudpErrors::not_connected) << "Got: " << e.what();
  }
  catch (const std::exception& e) {
    GTEST_FAIL() << "Expected system_error exception. Got: " << e.what();
  }
}

TEST_F(RudpTransportTest, BEH_DropConnection) {
  ConnectTestPeers();
  auto dropped_node(transports_[0]->node_id);
  transports_.erase(transports_.begin());

  NodeId lost_node;
  ASSERT_NO_THROW(lost_node = get_within(transports_[0]->LostFuture(), to_std(kTimeOut_)));

  EXPECT_EQ(lost_node, dropped_node);

  std::string msg_content("testing msg from node 0");

  PromiseHandler promise;

  transports_[0]->transport->Send(dropped_node, msg_content, promise);

  try {
    get_within(promise.get_future(), to_std(kTimeOut_));
    GTEST_FAIL() << "Expected to throw";
  }
  catch (const std::system_error& e) {
    ASSERT_EQ(e.code(), RudpErrors::not_connected) << "Got: " << e.what();
  }
  catch (const std::exception& e) {
    GTEST_FAIL() << "Expected system_error exception. Got: " << e.what();
  }
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
