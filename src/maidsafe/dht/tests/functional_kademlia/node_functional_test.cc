/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <cstdint>
#include <functional>
#include <exception>
#include <list>
#include <set>
#include <vector>
#include "boost/asio/deadline_timer.hpp"
#include <boost/numeric/conversion/cast.hpp>

#include "boost/asio.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127)
#endif
#include "boost/date_time/posix_time/posix_time.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
// #include "maidsafe-dht/common/routing_table.h"
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/securifier.h"

namespace fs = boost::filesystem;
namespace arg = std::placeholders;

namespace maidsafe {

namespace kademlia {

namespace test_node {

const int kProbes = 4;
const dht::transport::Port kStartingPort = 8000;
const std::string kLocalIp = "127.0.0.1";
const size_t kNetworkSize = 10;
const size_t kMaxRestartCycles = 5;

struct StartStop;

struct NodeContainer {
  NodeContainer()
      : asio_service(),
        work(),
        thread_group(),
        securifier(),
        transport(),
        message_handler(),
        alternative_store(),
        node() {}
  NodeContainer(const std::string &key_id,
                const std::string &public_key,
                const std::string &private_key,
                bool client_only_node,
                uint16_t k,
                uint16_t alpha,
                uint16_t beta,
                const boost::posix_time::time_duration &mean_refresh_interval)
      : asio_service(),
        work(),
        thread_group(),
        securifier(),
        transport(),
        message_handler(),
        node() {
    // set up ASIO service and thread pool
    work.reset(
        new boost::asio::io_service::work(asio_service));
    thread_group.reset(new boost::thread_group());
    thread_group->create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service));
    // set up data containers
    securifier.reset(new dht::Securifier(key_id, public_key, private_key));
    // set up and connect transport and message handler
    transport.reset(new dht::transport::TcpTransport(asio_service));
    message_handler.reset(new dht::kademlia::MessageHandler(securifier));
    transport->on_message_received()->connect(
        dht::transport::OnMessageReceived::element_type::slot_type(
            &dht::kademlia::MessageHandler::OnMessageReceived,
            message_handler.get(),
            _1, _2, _3, _4).track_foreign(message_handler));
    
//    timer.reset(new boost::asio::deadline_timer(asio_service));
//    strand.reset(new boost::asio::io_service::strand(asio_service));
    // create actual node
    node.reset(new dht::kademlia::Node(asio_service, transport, message_handler,
                                       securifier, alternative_store,
                                       client_only_node, k, alpha, beta,
                                       mean_refresh_interval));
  }
  dht::kademlia::AsioService asio_service;
/*  std::shared_ptr<boost::asio::deadline_timer> timer;
  std::shared_ptr<boost::asio::io_service::strand> strand;*/
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread_group> thread_group;
  std::shared_ptr<dht::Securifier> securifier;
  std::shared_ptr<dht::transport::Transport> transport;
  std::shared_ptr<dht::kademlia::MessageHandler> message_handler;
  dht::kademlia::AlternativeStorePtr alternative_store;
  std::shared_ptr<dht::kademlia::Node> node;
  std::vector<std::shared_ptr<StartStop> > time_table;
};

struct StartStop {
  StartStop() : start(0),
                stop(0) {}
  StartStop(size_t stop, size_t start) : stop(stop),
                                         start(start) {}
  size_t start;
  size_t stop;
};

class FunctionalKNodeTest : public testing::Test {
 public:
  void JoinCallback(size_t index,
                    int result,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var,
                    size_t *joined_nodes,
                    size_t *failed_nodes) {
    boost::mutex::scoped_lock lock(*mutex);
    if (result >= 0) {
      if (index > 0 && index < kNetworkSize)
        bootstrap_contacts_.push_back(nodes_[index]->node->contact());
      DLOG(INFO) << "Node " << (index + 1) << " joined.";
      ++(*joined_nodes);
    } else {
      DLOG(ERROR) << "Node " << (index + 1) << " failed to join.";
      ++(*failed_nodes);
    }
    cond_var->notify_one();
  }
  
  void HandleStart(const int index) {
    size_t joined_nodes(0), failed_nodes(0);    
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (++total_finished_ == total_restart_count_) {
        cond_var_.notify_one();
        return;
      }
    }
    dht::kademlia::JoinFunctor join_callback(std::bind(
        &FunctionalKNodeTest::JoinCallback, this, 0, arg::_1, &join_mutex_,
        &join_cond_var_, &joined_nodes, &failed_nodes));
    EXPECT_FALSE(nodes_[sample_nodes_[index]]->node->joined());
    timers[index]->expires_from_now(
        boost::posix_time::millisec(nodes_[sample_nodes_[index]]->time_table.front()->stop));
    nodes_[sample_nodes_[index]]->node->Join(
        nodes_[sample_nodes_[index]]->node->contact().node_id(), 
        bootstrap_contacts_, join_callback);
    {
      boost::mutex::scoped_lock lock(join_mutex_);
      join_cond_var_.wait(lock);
    }
    EXPECT_FALSE(nodes_[sample_nodes_[index]]->node->joined());
    timers[index]->async_wait(strands[index]->wrap(
      std::bind(&FunctionalKNodeTest::HandleStop, this, index)));
  }
  
  void HandleStop(const int index) {
    ASSERT_FALSE(nodes_[sample_nodes_[index]]->time_table.empty());
    EXPECT_TRUE(nodes_[index]->node->joined());
    nodes_[sample_nodes_[index]]->node->Leave(NULL);
    timers[index]->expires_from_now(
        boost::posix_time::millisec(nodes_[sample_nodes_[index]]->time_table.front()->start));
    nodes_[sample_nodes_[index]]->time_table.erase(nodes_[sample_nodes_[index]]->time_table.begin());
    timers[index]->async_wait(
      strands[index]->wrap(std::bind(&FunctionalKNodeTest::HandleStart, this,
                                     index)));
    EXPECT_FALSE(nodes_[index]->node->joined());
  }

 protected:
  FunctionalKNodeTest() : nodes_(),
               kAlpha_(3),
               kBeta_(2),
               kReplicationFactor_(4),
               total_finished_(0),
               total_restart_count_(0),
               kMeanRefreshInterval_(boost::posix_time::hours(1)),
               bootstrap_contacts_() {}

  virtual void SetUp() {
    size_t joined_nodes(0), failed_nodes(0);
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
    dht::kademlia::JoinFunctor join_callback(std::bind(
        &FunctionalKNodeTest::JoinCallback, this, 0, arg::_1, &mutex_, &cond_var_,
        &joined_nodes, &failed_nodes));
    dht::transport::Endpoint endpoint(kLocalIp, kStartingPort);
    std::vector<dht::transport::Endpoint> local_endpoints;
    local_endpoints.push_back(endpoint);
    dht::kademlia::Contact contact(node_id, endpoint,
                                   local_endpoints, endpoint, false, false,
                                   node_id.String(), key_pair.public_key(), "");
    bootstrap_contacts_.push_back(contact);
    EXPECT_FALSE(nodes_[0]->node->joined());
    ASSERT_EQ(dht::transport::kSuccess,
              nodes_[0]->transport->StartListening(endpoint));
    nodes_[0]->node->Join(node_id, bootstrap_contacts_, join_callback);
    for (size_t index = 1; index < kNetworkSize; ++index) {
      crypto::RsaKeyPair tmp_key_pair;
      tmp_key_pair.GenerateKeys(4096);
      dht::kademlia::NodeId nodeid(dht::kademlia::NodeId::kRandomId);
      nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
          nodeid.String(), tmp_key_pair.public_key(),
          tmp_key_pair.private_key(), false, kReplicationFactor_, kAlpha_,
          kBeta_, kMeanRefreshInterval_)));
      dht::transport::Endpoint endpoint(kLocalIp,
          static_cast<dht::transport::Port>(kStartingPort + index));
      ASSERT_EQ(dht::transport::kSuccess,
                nodes_[index]->transport->StartListening(endpoint));
      std::vector<dht::kademlia::Contact> bootstrap_contacts;
      {
        boost::mutex::scoped_lock lock(mutex_);
        bootstrap_contacts = bootstrap_contacts_;
      }
      nodes_[index]->node->Join(nodeid, bootstrap_contacts, join_callback);
      {
        boost::mutex::scoped_lock lock(mutex_);
        while (joined_nodes + failed_nodes <= index)
          cond_var_.wait(lock);
      }
    }

    {
      boost::mutex::scoped_lock lock(mutex_);
      while (joined_nodes + failed_nodes < kNetworkSize)
        cond_var_.wait(lock);
    }
    EXPECT_EQ(0, failed_nodes);
    for (int index = 0; index < nodes_.size(); ++index) {
      std::shared_ptr<boost::asio::deadline_timer> timer(
        new boost::asio::deadline_timer(nodes_[index]->asio_service));
      timers.push_back(timer);
      std::shared_ptr<boost::asio::io_service::strand> strand(
           new boost::asio::io_service::strand(nodes_[index]->asio_service));
      strands.push_back(strand);
    }
  }

  virtual void TearDown() {
    for (auto itr(nodes_.begin()); itr != nodes_.end(); ++itr) {
      if ((*itr)->node->joined()) {
//      DLOG(INFO) << "Shutting down client " << (index + 1) << " of "
//                 << nodes_.size() << " ...";
//      if (std::find(nodes_left_.begin(), nodes_left_.end(),
//          index) == nodes_left_.end()) {
        (*itr)->node->Leave(NULL);
        (*itr)->work.reset();
        (*itr)->asio_service.stop();
        (*itr)->thread_group->join_all();
        (*itr)->thread_group.reset();
      }
    }
  }

  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::mutex join_mutex_;
  boost::condition_variable join_cond_var_;  
  std::vector<std::shared_ptr<NodeContainer> > nodes_;
  boost::thread_group thread_group_;
  const uint16_t kAlpha_;
  const uint16_t kBeta_;
  const uint16_t kReplicationFactor_;
  const boost::posix_time::time_duration kMeanRefreshInterval_;
  std::vector<dht::kademlia::Contact> bootstrap_contacts_;
  std::vector<dht::kademlia::NodeId> nodes_id_;
  size_t total_finished_;
  size_t total_restart_count_;
  std::vector<int> sample_nodes_;
  std::vector<std::shared_ptr<boost::asio::deadline_timer> > timers;
  std::vector<std::shared_ptr<boost::asio::io_service::strand> > strands;
};

TEST_F(FunctionalKNodeTest, FUNC_KAD_StartStopRandomNodes) {
  int index = 0;
  while (sample_nodes_.size() < kNetworkSize) {
//    int random = RandomUint32() % kNetworkSize;
//    if (std::find(sample_nodes_.begin(), sample_nodes_.end(), random) ==
//        sample_nodes_.end()) 
      sample_nodes_.push_back(index++);
  }
  for (int index = 0; index < sample_nodes_.size(); ++index) {
    uint32_t random = RandomUint32();
    size_t stop = boost::numeric_cast<size_t>((1000)*(2 +  boost::numeric_cast<size_t>(std::ceil(2.0/6.0 *
          std::exp((random % 100)/17.0)))));
    size_t start = boost::numeric_cast<size_t>((1000)*(stop + 10 + static_cast<boost::uint64_t>(random % 20)));
    nodes_[index]->time_table.push_back(
      std::shared_ptr<StartStop>(new StartStop(stop, start)));
  }
  for (int index = 0; index < sample_nodes_.size(); ++index) {
    timers[index]->expires_from_now(boost::posix_time::millisec(
        nodes_[index]->time_table.front()->stop));
    timers[index]->async_wait(strands[index]->wrap(
      std::bind(&FunctionalKNodeTest::HandleStop, this, index)));    
  }
  total_restart_count_ = 1;
  {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
}

}
}
}
