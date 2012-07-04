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

#include <vector>

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/tests/test_utils.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace rudp {

typedef asio::ip::udp::endpoint Endpoint;

namespace test {

class RudpTransportTest : public testing::Test {
 public:
  RudpTransportTest()
      : transports_(),
        network_size_(2),
        kTimeOut_(Parameters::keepalive_interval * Parameters::maximum_keepalive_failures) {}

  ~RudpTransportTest() {}

 protected:
  struct TestPeer {
    TestPeer() : local_endpoint(GetLocalIp(), GetRandomPort()),
                 mutex(),
                 cond_var_connection_added(),
                 cond_var_connection_lost(),
                 cond_var_msg_received(),
                 asio_service(Parameters::thread_count),
                 transport(new Transport(asio_service)),
                 messages_received(),
                 peers_added(),
                 peers_lost() {
      Endpoint chosen_endpoint;
      std::vector<Endpoint> bootstrap_endpoints;
      boost::signals2::connection on_message_connection;
      boost::signals2::connection on_connection_added_connection;
      boost::signals2::connection on_connection_lost_connection;
      transport->Bootstrap(bootstrap_endpoints, local_endpoint, true,
                           boost::bind(&TestPeer::OnMessageSlot, this, _1),
                           boost::bind(&TestPeer::OnConnectionAddedSlot, this, _1, _2),
                           boost::bind(&TestPeer::OnConnectionLostSlot, this, _1, _2, _3, _4),
                           &chosen_endpoint,
                           &on_message_connection,
                           &on_connection_added_connection,
                           &on_connection_lost_connection);
      asio_service.Start();
    }

    ~TestPeer() {
       transport->Close();
       asio_service.Stop();
    }

    void OnMessageSlot(const std::string &message) {
      boost::mutex::scoped_lock lock(mutex);
      messages_received.push_back(message);
      cond_var_msg_received.notify_one();
    }

    void OnConnectionAddedSlot(const Endpoint &peer_endpoint, TransportPtr /*transport*/) {
      boost::mutex::scoped_lock lock(mutex);
      peers_added.push_back(peer_endpoint);
      cond_var_connection_added.notify_one();
    }

    void OnConnectionLostSlot(const Endpoint &peer_endpoint,
                              TransportPtr /*transport*/,
                              bool /*connections_empty*/,
                              bool /*temporary_connection*/) {
      boost::mutex::scoped_lock lock(mutex);
      peers_lost.push_back(peer_endpoint);
      cond_var_connection_lost.notify_one();
    }

    Endpoint local_endpoint;
    boost::mutex mutex;
    boost::condition_variable cond_var_connection_added;
    boost::condition_variable cond_var_connection_lost;
    boost::condition_variable cond_var_msg_received;
    AsioService asio_service;
    std::shared_ptr<Transport> transport;
    std::vector<std::string> messages_received;
    std::vector<Endpoint> peers_added;
    std::vector<Endpoint> peers_lost;
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
    transports_[0]->transport->Connect(transports_[1]->local_endpoint,
                                      "validation data from node 0");
    transports_[1]->transport->Connect(transports_[0]->local_endpoint,
                                      "validation data from node 1");
    boost::mutex::scoped_lock lock(transports_[1]->mutex);
    EXPECT_TRUE(transports_[1]->cond_var_msg_received.timed_wait(lock, kTimeOut_));
  }

  std::vector<std::shared_ptr<TestPeer> > transports_;
  uint16_t network_size_;
  bptime::time_duration kTimeOut_;
};

TEST_F(RudpTransportTest, BEH_Connection) {
  ConnectTestPeers();
  bool send_result(false);
  transports_[1]->messages_received.clear();
  std::string msg_content(RandomString(256));
  transports_[0]->transport->Send(transports_[1]->local_endpoint, msg_content,
                                  [&](bool result) { send_result = result; });  // NOLINT (Fraser)
  boost::mutex::scoped_lock lock(transports_[1]->mutex);
  EXPECT_TRUE(transports_[1]->cond_var_msg_received.timed_wait(lock, kTimeOut_));
  EXPECT_TRUE(send_result);
  EXPECT_EQ(1U, transports_[1]->messages_received.size());
  EXPECT_EQ(msg_content, transports_[1]->messages_received[0]);
}

TEST_F(RudpTransportTest, BEH_CloseConnection) {
  ConnectTestPeers();
  transports_[1]->transport->CloseConnection(transports_[0]->local_endpoint);
  {
    boost::mutex::scoped_lock lock(transports_[0]->mutex);
    EXPECT_TRUE(transports_[0]->cond_var_connection_lost.timed_wait(lock, kTimeOut_));
  }
  EXPECT_EQ(1U, transports_[0]->peers_lost.size());
  EXPECT_EQ(transports_[1]->local_endpoint, transports_[0]->peers_lost[0]);

// TODO(Team): removing following testing block will cause a segmentation failure

  bool send_result(true);
  transports_[1]->messages_received.clear();
  std::string msg_content("testing msg from node 0");
  transports_[0]->transport->Send(transports_[1]->local_endpoint, msg_content,
                                  [&](bool result) { send_result = result; });  // NOLINT (Fraser)
  boost::mutex::scoped_lock lock(transports_[1]->mutex);
  EXPECT_FALSE(transports_[1]->cond_var_msg_received.timed_wait(lock, kTimeOut_));
  EXPECT_FALSE(send_result);
  EXPECT_EQ(0, transports_[1]->messages_received.size());
}

TEST_F(RudpTransportTest, BEH_DropConnection) {
  ConnectTestPeers();
  Endpoint dropped_endpoint(transports_[0]->local_endpoint);
  int attempts(0);
  while ((attempts < 10) && (transports_[0]->messages_received.size() == 0)) {
    ++attempts;
    Sleep(bptime::milliseconds(100));
  }
  transports_.erase(transports_.begin());

  boost::mutex::scoped_lock lock(transports_[0]->mutex);
  EXPECT_TRUE(transports_[0]->cond_var_connection_lost.timed_wait(lock, kTimeOut_));

  ASSERT_EQ(1U, transports_[0]->peers_lost.size());
  EXPECT_EQ(dropped_endpoint, transports_[0]->peers_lost[0]);

  bool send_result(true);
  transports_[0]->messages_received.clear();
  std::string msg_content("testing msg from node 0");
  transports_[0]->transport->Send(dropped_endpoint, msg_content,
                                  [&](bool result) { send_result = result; });  // NOLINT (Fraser)
  EXPECT_FALSE(transports_[0]->cond_var_msg_received.timed_wait(lock, kTimeOut_));
  EXPECT_FALSE(send_result);
  EXPECT_EQ(0, transports_[0]->messages_received.size());
}

}  // namespace test

}  // namespace rudp

}  // namespace maidsafe
