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
#include "boost/numeric/conversion/cast.hpp"

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

const dht::transport::Port kStartingPort = 8000;
const std::string kLocalIp = "127.0.0.1";
const unsigned int kMaxRestartCycles = 5;

struct SampleNodesStats {
  explicit SampleNodesStats(int index)
      : index(index),
        restart_cycles(RandomUint32() % kMaxRestartCycles + 1) {}
  size_t index;
  size_t restart_cycles;
};

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
        alternative_store(),
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

    // create actual node
    node.reset(new dht::kademlia::Node(asio_service, transport, message_handler,
                                       securifier, alternative_store,
                                       client_only_node, k, alpha, beta,
                                       mean_refresh_interval));
  }
  dht::kademlia::AsioService asio_service;
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread_group> thread_group;
  std::shared_ptr<dht::Securifier> securifier;
  std::shared_ptr<dht::transport::Transport> transport;
  std::shared_ptr<dht::kademlia::MessageHandler> message_handler;
  dht::kademlia::AlternativeStorePtr alternative_store;
  std::shared_ptr<dht::kademlia::Node> node;
};

struct TimerContainer {
  TimerContainer()
      : asio_service(),
        work(),
        thread_group(),
        timer() {
    work.reset(
        new boost::asio::io_service::work(asio_service));
    thread_group.reset(new boost::thread_group());
    thread_group->create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service));
    timer.reset(new boost::asio::deadline_timer(asio_service));
  }
  dht::kademlia::AsioService asio_service;
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread_group> thread_group;
  std::shared_ptr<boost::asio::deadline_timer> timer;
};

class FunctionalNodeTest : public testing::Test {
 public:
  void JoinCallback(size_t index,
                    int result,
                    boost::mutex *mutex,
                    boost::condition_variable *cond_var,
                    size_t *joined_nodes,
                    size_t *failed_nodes) {
    boost::mutex::scoped_lock lock(*mutex);
    if (result >= 0) {
      if (index > 0 && index < network_size_) {
        if ((std::find(bootstrap_contacts_.begin(), bootstrap_contacts_.end(),
            nodes_[index]->node->contact())) == bootstrap_contacts_.end())
          bootstrap_contacts_.push_back(nodes_[index]->node->contact());
      }
      DLOG(INFO) << "Node " << (index + 1) << " joined.";
      ++(*joined_nodes);
    } else {
      DLOG(ERROR) << "Node " << (index + 1) << " failed to join.";
      ++(*failed_nodes);
    }
    cond_var->notify_one();
  }

  void HandleStart(const int index, size_t count) {
    {
      boost::mutex::scoped_lock lock(mutex_start_);
      size_t joined_nodes(0), failed_nodes(0);
      dht::kademlia::JoinFunctor join_callback(std::bind(
          &FunctionalNodeTest::JoinCallback, this, index, arg::_1, &mutex_,
          &cond_var_, &joined_nodes, &failed_nodes));
      EXPECT_FALSE(nodes_[index]->node->joined());
      nodes_[index]->node->Join(
         nodes_[index]->node->contact().node_id(),
          bootstrap_contacts_, join_callback);
      {
        boost::mutex::scoped_lock lock(mutex_);
        cond_var_.wait(lock);
      }
      EXPECT_TRUE(nodes_[index]->node->joined());
      if (++total_finished_ == total_restart_) {  // all restarts are done
        cond_var2_.notify_one();
        return;
      }
      if (--count == 0)  // this node restart cycles is over
        return;
    }
    timers_[index]->timer->expires_from_now(
        boost::posix_time::millisec(Stop()));
    timers_[index]->timer->async_wait(std::bind(&FunctionalNodeTest::HandleStop,
                                               this, index, count));
  }

  void HandleStop(const int index, size_t count) {
    {
      boost::mutex::scoped_lock lock(mutex_stop_);
      EXPECT_TRUE(nodes_[index]->node->joined());
      nodes_[index]->node->Leave(NULL);
      EXPECT_FALSE(nodes_[index]->node->joined());
    }
    timers_[index]->timer->expires_from_now(
        boost::posix_time::millisec(Start()));
    timers_[index]->timer->async_wait(
        std::bind(&FunctionalNodeTest::HandleStart, this, index, count));
  }

 protected:
  FunctionalNodeTest()
      : nodes_(),
        mutex_(),
        cond_var_(),
        mutex2_(),
        cond_var2_(),
        mutex_start_(),
        mutex_stop_(),
        kAlpha_(3),
        kBeta_(2),
        kReplicationFactor_(4),
        kMeanRefreshInterval_(boost::posix_time::hours(1)),
        bootstrap_contacts_(),
        timers_(),
        sample_nodes_(),
        network_size_(20),
        total_finished_(0),
        total_restart_(0) {
     for (size_t index = 0; index < network_size_; ++index)
       timers_.push_back(std::shared_ptr<TimerContainer>(new TimerContainer));
  }

  virtual void SetUp() {
    size_t joined_nodes(0), failed_nodes(0);
    crypto::RsaKeyPair key_pair;
    key_pair.GenerateKeys(4096);
    dht::kademlia::NodeId node_id(dht::kademlia::NodeId::kRandomId);
    nodes_.push_back(std::shared_ptr<NodeContainer>(new NodeContainer(
        node_id.String(), key_pair.public_key(), key_pair.private_key(), false,
        kReplicationFactor_, kAlpha_, kBeta_, kMeanRefreshInterval_)));
    dht::kademlia::JoinFunctor join_callback(std::bind(
        &FunctionalNodeTest::JoinCallback, this, 0, arg::_1, &mutex_,
        &cond_var_, &joined_nodes, &failed_nodes));
    dht::transport::Endpoint endpoint(kLocalIp, kStartingPort);
    std::vector<dht::transport::Endpoint> local_endpoints;
    local_endpoints.push_back(endpoint);
    dht::kademlia::Contact contact(node_id, endpoint,
                                   local_endpoints, endpoint, false, false,
                                   node_id.String(), key_pair.public_key(), "");
    bootstrap_contacts_.push_back(contact);
    ASSERT_EQ(dht::transport::kSuccess,
              nodes_[0]->transport->StartListening(endpoint));
    nodes_[0]->node->Join(node_id, bootstrap_contacts_, join_callback);
    for (size_t index = 1; index < network_size_; ++index) {
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
      while (joined_nodes + failed_nodes < network_size_)
        cond_var_.wait(lock);
    }
    EXPECT_EQ(0, failed_nodes);
    // populate sample_nodes_
    std::set<size_t> sample_set;
    while (sample_set.size() < network_size_ / 2)
      sample_set.insert(RandomUint32() % network_size_ + 1);
    for (auto it(sample_set.begin()); it != sample_set.end(); ++it)
      sample_nodes_.push_back(
          std::shared_ptr<SampleNodesStats>(new SampleNodesStats((*it))));
    for (auto it(sample_nodes_.begin()); it != sample_nodes_.end(); ++it)
      total_restart_ += (*it)->restart_cycles;
  }

  virtual void TearDown() {
    for (auto itr(nodes_.begin()); itr != nodes_.end(); ++itr) {
      if ((*itr)->node->joined()) {
        (*itr)->node->Leave(NULL);
        (*itr)->work.reset();
        (*itr)->asio_service.stop();
        (*itr)->thread_group->join_all();
        (*itr)->thread_group.reset();
      }
    }
    for (auto itr(timers_.begin()); itr != timers_.end(); ++itr) {
      (*itr)->work.reset();
      (*itr)->asio_service.stop();
      (*itr)->thread_group->join_all();
    }
  }

/** Approximate the uptime distribution given in "A Measurement Study of
 * Peer-to-Peer File Sharing Systems" by Saroiu et al, fig. 6.
 * The median of 60 minutes is converted to roughly 10 seconds and
 * another two seconds are added; the total range is [3,113] seconds.*/
  size_t Stop() {
    return boost::numeric_cast<size_t>((1000)*(2 +
        (std::ceil(2.0/6.0 * std::exp((RandomUint32() % 100)/17.0)))));
  }

/** The node re-joins after 10 to 29 seconds. */
  size_t Start() {
    return boost::numeric_cast<size_t>((1000)*(10 + (RandomUint32() % 20)));
  }

  std::vector<std::shared_ptr<NodeContainer> > nodes_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  boost::mutex mutex2_;
  boost::condition_variable cond_var2_;
  boost::mutex mutex_start_;
  boost::mutex mutex_stop_;
  const uint16_t kAlpha_;
  const uint16_t kBeta_;
  const uint16_t kReplicationFactor_;
  const boost::posix_time::time_duration kMeanRefreshInterval_;
  std::vector<dht::kademlia::Contact> bootstrap_contacts_;
  std::vector<std::shared_ptr<TimerContainer> > timers_;
  std::vector<std::shared_ptr<SampleNodesStats> > sample_nodes_;
  size_t network_size_;
  size_t total_finished_;
  size_t total_restart_;
};


TEST_F(FunctionalNodeTest, FUNC_RandomStartStopNodes) {
  for (auto it(sample_nodes_.begin()); it != sample_nodes_.end(); ++it) {
    timers_[(*it)->index]->timer->expires_from_now(
        boost::posix_time::millisec(Stop()));
    timers_[(*it)->index]->timer->async_wait(
        std::bind(&FunctionalNodeTest::HandleStop, this, (*it)->index,
                                          (*it)->restart_cycles));
  }
  {
    boost::mutex::scoped_lock lock(mutex2_);
    cond_var2_.wait(lock);
  }
}

}  // namespace test_node

}  // namespace kademlia

}  // namespace maidsafe

