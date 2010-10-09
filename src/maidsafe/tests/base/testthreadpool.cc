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
  Threadpool threadpool(0);
  ASSERT_FALSE(threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work_, 999)));
  ASSERT_TRUE(threadpool.TimedWait(kTimeout_,
              boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
  ASSERT_TRUE(threadpool.functors_.empty());
  ASSERT_TRUE(work_.completed_tasks().empty());
  const size_t kThreadCount(10);
  ASSERT_TRUE(threadpool.Resize(kThreadCount));
  ASSERT_TRUE(threadpool.TimedWait(kTimeout_,
              boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
  ASSERT_TRUE(threadpool.functors_.empty());
  ASSERT_TRUE(work_.completed_tasks().empty());
  ASSERT_TRUE(threadpool.functors_.empty());
  ASSERT_TRUE(work_.completed_tasks().empty());
  threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work_, 999));
  EXPECT_TRUE(threadpool.WaitForTasksToFinish(kTimeout_));
  ASSERT_EQ(size_t(1), work_.completed_tasks().size());
  ASSERT_EQ(kThreadCount, threadpool.running_thread_count_);
}

TEST_F(ThreadpoolTest, BEH_BASE_MultipleTasks) {
  const size_t kThreadCount(10);
  const size_t kTaskCount(1000);
  std::vector<int> enqueued_tasks;
  enqueued_tasks.reserve(kTaskCount);
  {
    Threadpool threadpool(kThreadCount);
    ASSERT_TRUE(threadpool.functors_.empty());
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
    ASSERT_EQ(kThreadCount, threadpool.running_thread_count_);
  }
  ASSERT_EQ(kTaskCount, work_.completed_tasks().size());
  std::vector<int> completed_tasks(work_.completed_tasks());
  ASSERT_FALSE(std::equal(enqueued_tasks.begin(), enqueued_tasks.end(),
                          completed_tasks.begin()));
  std::sort(completed_tasks.begin(), completed_tasks.end());
  ASSERT_TRUE(std::equal(enqueued_tasks.begin(), enqueued_tasks.end(),
                         completed_tasks.begin()));
}

TEST_F(ThreadpoolTest, BEH_BASE_Resize) {
  const size_t kMaxTestThreadCount(20);
  size_t thread_count((base::RandomUint32() % kMaxTestThreadCount) + 1);
  Threadpool threadpool(thread_count);
  ASSERT_EQ(thread_count, threadpool.requested_thread_count_);
  ASSERT_TRUE(threadpool.TimedWait(kTimeout_,
              boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
  ASSERT_EQ(thread_count, threadpool.running_thread_count_);

  // Enqueue many lengthy tasks
  boost::uint8_t task_duration(255);
  Work work(task_duration, task_duration);
  const size_t kTaskCount(10000);
  for (size_t i = 0; i < kTaskCount; ++i)
    threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work, i));

  // Repeatedly resize to size - 1 until 0 threads.
  while (true) {
    --thread_count;
    SCOPED_TRACE("Resizing to " +
                 boost::lexical_cast<std::string>(thread_count));
    ASSERT_TRUE(threadpool.Resize(thread_count));
    ASSERT_EQ(thread_count, threadpool.requested_thread_count_);
    ASSERT_TRUE(threadpool.TimedWait(kTimeout_,
                boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
    ASSERT_EQ(thread_count, threadpool.running_thread_count_);
    if (thread_count == 0)
      break;
  }

  // Check that not all tasks have been completed
  size_t tasks_completed = work.completed_tasks().size();
  ASSERT_LT(tasks_completed, kTaskCount);
  Sleep(task_duration * 2);
  // Check that no more tasks have been completed
  ASSERT_EQ(tasks_completed, work.completed_tasks().size());

  // Resize to max for test
  ASSERT_TRUE(threadpool.Resize(kMaxTestThreadCount));
  ASSERT_EQ(kMaxTestThreadCount, threadpool.requested_thread_count_);
  ASSERT_TRUE(threadpool.TimedWait(kTimeout_,
              boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
  ASSERT_EQ(kMaxTestThreadCount, threadpool.running_thread_count_);

  // Check that some more tasks have been completed
  Sleep(task_duration * 2);
  ASSERT_LT(tasks_completed, work.completed_tasks().size());

  bool thread_resources_ok(true);
  boost::uint64_t exceed_system_resource_count(kMaxTestThreadCount);
  while (thread_resources_ok)
    thread_resources_ok = threadpool.Resize(++exceed_system_resource_count);
}

TEST_F(ThreadpoolTest, BEH_BASE_TimedWait) {
  const size_t kThreadCount(10);
  const size_t kTaskCount(10);
  std::vector<int> enqueued_tasks;
  enqueued_tasks.reserve(kTaskCount);
  boost::posix_time::milliseconds timeout(2 * kMaxTaskDuration_ * kTaskCount);
  {
    Threadpool threadpool(kThreadCount);
    ASSERT_TRUE(threadpool.functors_.empty());
    ASSERT_TRUE(work_.completed_tasks().empty());
    for (size_t i = 0; i < kTaskCount; ++i) {
      threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work_, i));
      enqueued_tasks.push_back(i);
    }
    EXPECT_TRUE(threadpool.WaitForTasksToFinish(timeout));
    ASSERT_EQ(kTaskCount, work_.completed_tasks().size());
    ASSERT_EQ(kThreadCount, threadpool.running_thread_count_);
  }
  ASSERT_EQ(kTaskCount, work_.completed_tasks().size());
  timeout = boost::posix_time::milliseconds(kMinTaskDuration_);
  {
    Threadpool threadpool(kThreadCount);
    ASSERT_TRUE(threadpool.functors_.empty());
    for (size_t i = 0; i < kTaskCount; ++i) {
      threadpool.EnqueueTask(boost::bind(&Work::DoTask, &work_, i));
      enqueued_tasks.push_back(i);
    }
    threadpool.Resize(0);
    EXPECT_FALSE(threadpool.WaitForTasksToFinish(timeout));
    ASSERT_LE(kTaskCount, work_.completed_tasks().size());
    ASSERT_GT(2 * kTaskCount, work_.completed_tasks().size());
    timeout = boost::posix_time::milliseconds(10000);
    ASSERT_TRUE(threadpool.TimedWait(timeout,
                boost::bind(&Threadpool::ThreadCountCorrect, &threadpool)));
    ASSERT_EQ(0U, threadpool.running_thread_count_);
  }
}

}  // namespace test

}  // namespace base
