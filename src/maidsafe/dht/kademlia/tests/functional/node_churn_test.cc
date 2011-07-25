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
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/numeric/conversion/cast.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127)
#endif
#include "boost/date_time/posix_time/posix_time.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/common/test.h"

#include "maidsafe/dht/kademlia/node-api.h"
#include "maidsafe/dht/kademlia/node_container.h"
#include "maidsafe/dht/kademlia/tests/functional/test_node_environment.h"

namespace bptime = boost::posix_time;

namespace maidsafe {
namespace dht {
namespace kademlia {
namespace test {

class NodeChurnTest : public testing::Test {
 public:
  typedef std::shared_ptr<maidsafe::dht::kademlia::NodeContainer<Node>>
      NodeContainerPtr;
  typedef std::shared_ptr<boost::asio::deadline_timer> TimerPtr;
  void HandleStart(NodeContainerPtr node_container,
                   TimerPtr timer_container,
                   size_t count);
  void HandleStop(NodeContainerPtr node_container,
                  TimerPtr timer_container,
                  size_t count);

 protected:
  NodeChurnTest()
      : env_(NodesEnvironment<Node>::g_environment()),
        kTimeout_(bptime::minutes(1)),
        mutex_(),
        cond_var_(),
        total_finished_(0),
        total_restarts_(0),
        kMaxRestartCycles_(5) {}

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

  NodesEnvironment<Node>* env_;
  const bptime::time_duration kTimeout_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  size_t total_finished_;
  size_t total_restarts_;
  const size_t kMaxRestartCycles_;

 private:
  NodeChurnTest(const NodeChurnTest&);
  NodeChurnTest& operator=(const NodeChurnTest&);
};

void NodeChurnTest::HandleStart(NodeContainerPtr node_container,
                                TimerPtr timer,
                                size_t count) {
  EXPECT_FALSE(node_container->node()->joined());
  int result(kPendingResult);
  {
    boost::mutex::scoped_lock lock(env_->mutex_);
    node_container->Join(node_container->node()->contact().node_id(),
                         node_container->bootstrap_contacts());
    EXPECT_TRUE(env_->cond_var_.timed_wait(lock, kTimeout_,
                node_container->wait_for_join_functor()));
    node_container->GetAndResetJoinResult(&result);
    EXPECT_EQ(kSuccess, result);
    EXPECT_TRUE(node_container->node()->joined());

    if (++total_finished_ == total_restarts_) {  // all restarts are done
      cond_var_.notify_one();
      return;
    }
    if (--count == 0)  // this node restart cycles are over
      return;
  }
  timer->expires_from_now(bptime::milliseconds(Stop()));
  timer->async_wait(std::bind(&NodeChurnTest::HandleStop, this, node_container,
                              timer, count));
}

void NodeChurnTest::HandleStop(NodeContainerPtr node_container,
                               TimerPtr timer,
                               size_t count) {
  EXPECT_TRUE(node_container->node()->joined());
  node_container->node()->Leave(NULL);
  EXPECT_FALSE(node_container->node()->joined());

  timer->expires_from_now(bptime::milliseconds(Start()));
  timer->async_wait(std::bind(&NodeChurnTest::HandleStart, this, node_container,
                              timer, count));
}


TEST_F(NodeChurnTest, FUNC_RandomStartStopNodes) {
  auto node_itr(env_->node_containers_.begin()),
       node_itr_end(env_->node_containers_.end());
  for (; node_itr != node_itr_end; ++node_itr) {
    size_t restarts(RandomUint32() % kMaxRestartCycles_ + 2);
    TimerPtr timer(
        new boost::asio::deadline_timer((*node_itr)->asio_service()));
    timer->expires_from_now(bptime::milliseconds(Stop()));
    timer->async_wait(std::bind(&NodeChurnTest::HandleStop, this,
                                *node_itr, timer, restarts));
    total_restarts_ += restarts;
  }
  boost::mutex::scoped_lock lock(mutex_);
  cond_var_.wait(lock);
}

}  // namespace test
}  // namespace kademlia
}  // namespace dht
}  // namespace maidsafe

