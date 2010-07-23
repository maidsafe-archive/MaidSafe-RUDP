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

#include <boost/thread/mutex.hpp>
#include <gtest/gtest.h>

#include "maidsafe/base/threadpool.h"
#include "maidsafe/base/utils.h"

namespace base {

namespace test {

class Work {
 public:
  Work() {}
  ~Work() {}
  void DoJob(const int &job_id) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(
        base::RandomUint32() % 100));
    boost::mutex::scoped_lock lock(completed_jobs_mutex_);
    completed_jobs_.push_back(job_id);
  }
  std::vector<int> completed_jobs() const { return completed_jobs_; }
 private:
  Work(const Work&);
  Work& operator=(const Work&);
  std::vector<int> completed_jobs_;
  boost::mutex completed_jobs_mutex_;
};

class ThreadpoolTest : public testing::Test {
 protected:
  ThreadpoolTest() : work_() {}
  virtual ~ThreadpoolTest() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
  Work work_;
 private:
  ThreadpoolTest(const ThreadpoolTest&);
  ThreadpoolTest& operator=(const ThreadpoolTest&);
};

TEST_F(ThreadpoolTest, BEH_BASE_AddSingleTask) {
  const size_t kThreadCount(10);
  {
    ThreadedCallContainer threadpool(kThreadCount);
    ASSERT_EQ(kThreadCount, threadpool.threads_.size());
    ASSERT_TRUE(threadpool.functors_.empty());
    ASSERT_TRUE(work_.completed_jobs().empty());
    threadpool.Enqueue(boost::bind(&Work::DoJob, &work_, 999));
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  ASSERT_EQ(1U, work_.completed_jobs().size());
}

}  // namespace test

}  // namespace base
