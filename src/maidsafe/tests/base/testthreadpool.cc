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

#include <boost/lexical_cast.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest.h>

#include "maidsafe/base/threadpool.h"
#include "maidsafe/base/utils.h"

namespace base {

namespace test {

class Work {
 public:
  Work(const boost::uint8_t &min_task_sleep,
       const boost::uint8_t &max_task_sleep)
      : min_task_sleep_(min_task_sleep),
        max_task_sleep_(max_task_sleep),
        task_sleep_difference_(max_task_sleep - min_task_sleep + 1),
        completed_tasks_(),
        completed_tasks_mutex_(),
        done_min_sleep_(false),
        done_max_sleep_(false) {
    if (min_task_sleep_ > max_task_sleep_) {
      min_task_sleep_ = 10;
      max_task_sleep_ = 90;
      task_sleep_difference_ = 81;
    }
  }
  ~Work() {}
  void DoTask(const int &task_id) {
    boost::posix_time::milliseconds sleeptime(min_task_sleep_);
    {
      boost::mutex::scoped_lock lock(completed_tasks_mutex_);
      if (!done_min_sleep_) {
        done_min_sleep_ = true;
      } else if (!done_max_sleep_) {
        sleeptime = boost::posix_time::milliseconds(min_task_sleep_);
        done_max_sleep_ = true;
      } else if (task_sleep_difference_ != 1) {
        sleeptime += boost::posix_time::milliseconds(base::RandomUint32() %
                                                     task_sleep_difference_);
      }
    }
    boost::this_thread::sleep(sleeptime);
    boost::mutex::scoped_lock lock(completed_tasks_mutex_);
    completed_tasks_.push_back(task_id);
  }
  std::vector<int> completed_tasks() {
    boost::mutex::scoped_lock lock(completed_tasks_mutex_);
    return completed_tasks_;
  }
 private:
  Work(const Work&);
  Work& operator=(const Work&);
  boost::uint8_t min_task_sleep_, max_task_sleep_, task_sleep_difference_;
  std::vector<int> completed_tasks_;
  boost::mutex completed_tasks_mutex_;
  bool done_min_sleep_, done_max_sleep_;
};

class ThreadpoolTest : public testing::Test {
 protected:
  ThreadpoolTest() : kTimeout_(10000),
                     kMinTaskDuration_(10),
                     kMaxTaskDuration_(110),
                     work_(kMinTaskDuration_, kMaxTaskDuration_ - 10) {}
  virtual ~ThreadpoolTest() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
  void Sleep(const boost::uint32_t &duration) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(duration));
  }
  const boost::posix_time::milliseconds kTimeout_;
  const boost::uint8_t kMinTaskDuration_, kMaxTaskDuration_;
  Work work_;
 private:
  ThreadpoolTest(const ThreadpoolTest&);
  ThreadpoolTest& operator=(const ThreadpoolTest&);
};

TEST_F(ThreadpoolTest, BEH_BASE_SingleTask) {
  boost::function<void()> functor(boost::bind(&Work::DoTask, &work_, 999));
  // Run a threadpool with 0 threads
  Threadpool threadpool1(0);
  EXPECT_TRUE(threadpool1.EnqueueTask(functor));
  Sleep(kMaxTaskDuration_ + 10);
  EXPECT_TRUE(work_.completed_tasks().empty());

  // Run a threadpool with 1 thread
  Threadpool threadpool2(1);
  EXPECT_TRUE(threadpool2.EnqueueTask(functor));
  EXPECT_TRUE(work_.completed_tasks().empty());
  Sleep(kMaxTaskDuration_ + 10);
  EXPECT_EQ(1U, work_.completed_tasks().size());

  // Run a threadpool with 10 threads
  Threadpool threadpool3(10);
  EXPECT_TRUE(threadpool3.EnqueueTask(functor));
  EXPECT_EQ(1U, work_.completed_tasks().size());
  Sleep(kMaxTaskDuration_ + 10);
  EXPECT_EQ(2U, work_.completed_tasks().size());

  // Destroy a running threadpool with 10 threads
  {
    Threadpool threadpool4(10);
    EXPECT_TRUE(threadpool4.EnqueueTask(functor));
    EXPECT_EQ(2U, work_.completed_tasks().size());
  }
  EXPECT_EQ(3U, work_.completed_tasks().size());
}

TEST_F(ThreadpoolTest, BEH_BASE_MultipleTasks) {
  const size_t kThreadCount(10);
  const size_t kTaskCount(1000);
  std::vector<int> enqueued_tasks;
  enqueued_tasks.reserve(kTaskCount);
  {
    Threadpool threadpool(kThreadCount);
    ASSERT_TRUE(work_.completed_tasks().empty());
    for (size_t i = 0; i < kTaskCount; ++i) {
      threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work_, i));
      enqueued_tasks.push_back(i);
    }
    size_t timeout_count(0);
    while (work_.completed_tasks().size() < kTaskCount &&
           timeout_count < (2 * kMaxTaskDuration_ * kTaskCount)) {
      Sleep(20);
      timeout_count += 20;
    }
    ASSERT_EQ(kTaskCount, work_.completed_tasks().size());
  }
  ASSERT_EQ(kTaskCount, work_.completed_tasks().size());
  std::vector<int> completed_tasks(work_.completed_tasks());
  EXPECT_FALSE(std::equal(enqueued_tasks.begin(), enqueued_tasks.end(),
                          completed_tasks.begin()));
  std::sort(completed_tasks.begin(), completed_tasks.end());
  EXPECT_TRUE(std::equal(enqueued_tasks.begin(), enqueued_tasks.end(),
                         completed_tasks.begin()));
}

}  // namespace test

}  // namespace base
