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
#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_impl.h"
#include "maidsafe/dht/transport/tcp_transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/tests/test_utils.h"
#include "maidsafe/dht/kademlia/node_container.h"
#include "maidsafe/dht/kademlia/tests/functional/test_node_environment.h"

namespace fs = boost::filesystem;
namespace arg = std::placeholders;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {


                                                                              //struct SampleNodeStats {
                                                                              //  explicit SampleNodeStats(size_t index_in)
                                                                              //      : index(index_in),
                                                                              //        restart_cycles(RandomUint32() % kMaxRestartCycles + 1) {}
                                                                              //  size_t index;
                                                                              //  size_t restart_cycles;
                                                                              //};
                                                                              //
struct TimerContainer {
  TimerContainer()
      : asio_service(),
        work(new boost::asio::io_service::work(asio_service)),
        timer_thread(new boost::thread(
            std::bind(static_cast<size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service))),
        timer(new boost::asio::deadline_timer(asio_service)) {}
  AsioService asio_service;
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread> timer_thread;
  std::shared_ptr<boost::asio::deadline_timer> timer;
};

class NodeChurnTest : public testing::Test {
 public:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<NodeImpl>>
      NodeContainerPtr;
  typedef std::shared_ptr<TimerContainer> TimerContainerPtr;
  void HandleStart(NodeContainerPtr node_container,
                   TimerContainerPtr timer_container,
                   size_t count);
  void HandleStop(NodeContainerPtr node_container,
                  TimerContainerPtr timer_container,
                  size_t count);

 protected:
  NodeChurnTest()
      : env_(NodesEnvironment<Node>::g_environment()),
        kTimeout_(bptime::seconds(10)),
        timers_(env_->node_containers_.size(),
                std::shared_ptr<TimerContainer>(new TimerContainer)),
//                                                                        sample_nodes_(),
        total_finished_(0),
        total_restart_(0),
        kMaxRestartCycles_(5) {}


//  virtual void SetUp() {
//    // Replace node containers' default join callbacks with one for this test.
//    for (size_t i(0); i != env_->node_containers_.size(); ++i) {
//      env_->node_containers_[i]->set_join_functor(
//          std::bind(&NodeChurnTest::JoinCallback, this, i, arg::_1));
//    }
//  }

  NodesEnvironment<Node>* env_;
  const bptime::time_duration kTimeout_;

//  NodeChurnTest()
//      : nodes_(),
//        mutex_(),
//        cond_var_(),
//        mutex2_(),
//        cond_var2_(),
//        mutex_start_(),
//        mutex_stop_(),
//        kAlpha_(3),
//        kBeta_(2),
//        kReplicationFactor_(4),
//        kMeanRefreshInterval_(boost::posix_time::hours(1)),
//        bootstrap_contacts_(),
//        timers_(),
//        sample_nodes_(),
//        network_size_(20),
//        total_finished_(0),
//        total_restart_(0) {
//     for (size_t index = 0; index < network_size_; ++index)
//       timers_.push_back(std::shared_ptr<TimerContainer>(new TimerContainer));
//  }

  virtual void SetUp() {
                                                                            //    // populate sample_nodes_
                                                                            //    std::set<size_t> sample_set;
                                                                            //    while (sample_set.size() < env_->node_containers_.size() / 2)
                                                                            //      sample_set.insert(RandomUint32() % env_->node_containers_.size());
                                                                            //    for (auto it(sample_set.begin()); it != sample_set.end(); ++it) {
                                                                            //      sample_nodes_.push_back(std::shared_ptr<SampleNodeStats>(
                                                                            //          new SampleNodeStats(*it)));
                                                                            //    }
                                                                            //    for (auto it(sample_nodes_.begin()); it != sample_nodes_.end(); ++it)
                                                                            //      total_restart_ += (*it)->restart_cycles;
  }

  virtual void TearDown() {
    for (auto itr(timers_.begin()); itr != timers_.end(); ++itr) {
      (*itr)->work.reset();
      (*itr)->asio_service.stop();
      (*itr)->timer_thread->join();
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

  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  std::vector<std::shared_ptr<TimerContainer>> timers_;
                        //  std::vector<std::shared_ptr<SampleNodeStats>> sample_nodes_;
  const size_t kMaxRestartCycles_;
  size_t total_finished_;
  size_t total_restart_;
};

void NodeChurnTest::HandleStart(NodeContainerPtr node_container,
                                TimerContainerPtr timer_container,
                                size_t count) {
  EXPECT_FALSE(node_container->node()->joined());
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    node_container->Join(node_container->node()->contact().node_id(),
                         node_container->bootstrap_contacts());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                node_container->wait_for_join_functor()));
    node_container->GetAndResetStoreResult(&result);
    EXPECT_EQ(kSuccess, result);
    EXPECT_TRUE(node_container->node()->joined());

    if (++total_finished_ == total_restart_) {  // all restarts are done
      cond_var_.notify_one();
      return;
    }
    if (--count == 0)  // this node restart cycles is over
      return;
  }
  timer_container->timer->expires_from_now(
      boost::posix_time::milliseconds(Stop()));
  timer_container->timer->async_wait(std::bind(&NodeChurnTest::HandleStop,
                                                this, node_container,
                                                timer_container, count));
}

void NodeChurnTest::HandleStop(NodeContainerPtr node_container,
                               TimerContainerPtr timer_container,
                               size_t count) {
  EXPECT_TRUE(node_container->node()->joined());
  node_container->node()->Leave(NULL);
  EXPECT_FALSE(node_container->node()->joined());

  timer_container->timer->expires_from_now(
      boost::posix_time::milliseconds(Start()));
  timer_container->timer->async_wait(std::bind(&NodeChurnTest::HandleStart,
                                               this, node_container,
                                               timer_container, count));
}



TEST_F(NodeChurnTest, FUNC_RandomStartStopNodes) {
  ASSERT_EQ(env_->node_containers_.size(), timers_.size());
  auto node_itr(env_->node_containers_.begin()),
       node_itr_end(env_->node_containers_.end());
  auto timer_itr(timers_.begin());

  for (; node_itr != node_itr_end; ++node_itr, ++timer_itr) {
    size_t restarts(RandomUint32() % kMaxRestartCycles_ + 1);
    (*timer_itr)->timer->expires_from_now(boost::posix_time::millisec(Stop()));
    (*timer_itr)->timer->async_wait(std::bind(&NodeChurnTest::HandleStop, this,
        (*node_itr), (*timer_itr), restarts));
  }
  {
    boost::mutex::scoped_lock lock(mutex_);
    cond_var_.wait(lock);
  }
}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe

