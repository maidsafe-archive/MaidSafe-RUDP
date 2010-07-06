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

#include <gtest/gtest.h>
#include <boost/scoped_ptr.hpp>
#include <boost/thread/thread.hpp>
#include "maidsafe/base/log.h"

#include "maidsafe/base/calllatertimer.h"

namespace base {

class Lynyrd {
 public:
  Lynyrd()
      : count_(0),
        mutex_(new boost::mutex),
        cond_var_(new boost::condition_variable) {}
  Lynyrd(boost::shared_ptr<boost::mutex> mutex,
         boost::shared_ptr<boost::condition_variable> cond_var)
      : count_(0),
        mutex_(mutex),
        cond_var_(cond_var) {}
  ~Lynyrd() {}
  void Skynyrd() {
    boost::mutex::scoped_lock guard(*mutex_);
    ++count_;
    cond_var_->notify_all();
  }
  void Alabama() {
    Skynyrd();
  }
  int count() {
    boost::mutex::scoped_lock guard(*mutex_);
    return count_;
  }
  void reset() {
    boost::mutex::scoped_lock guard(*mutex_);
    count_ = 0;
  }

 private:
  Lynyrd(const Lynyrd&);
  Lynyrd& operator=(const Lynyrd&);
  int count_;
  boost::shared_ptr<boost::mutex> mutex_;
  boost::shared_ptr<boost::condition_variable> cond_var_;
};

class CallLaterTest : public testing::Test {
 protected:
  CallLaterTest() : clt_() {}
  virtual ~CallLaterTest() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
  CallLaterTimer clt_;

 private:
  CallLaterTest(const CallLaterTest&);
  CallLaterTest& operator=(const CallLaterTest&);
};

TEST_F(CallLaterTest, BEH_BASE_AddSingleCallLater) {
  // Most basic test - create object on stack and call a method later.
  ASSERT_TRUE(clt_.IsStarted());
  clt_.CancelAll();
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  Lynyrd sweethome;
  ASSERT_EQ(0, sweethome.count());
  clt_.AddCallLater(50, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  while (sweethome.count() < 1)
    boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  ASSERT_EQ(1, sweethome.count());
  ASSERT_EQ(0, clt_.CancelAll()) <<
      "Some calls were cancelled, list not empty";
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
}

TEST_F(CallLaterTest, BEH_BASE_AddManyCallLaters) {
  // Set up 100 calls fairly closely spaced
  ASSERT_TRUE(clt_.IsStarted());
  clt_.CancelAll();
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  Lynyrd sweethome;
  for (int i = 0; i < 100; ++i)
    clt_.AddCallLater(50 + (20*i), boost::bind(&Lynyrd::Skynyrd, &sweethome));
  while (sweethome.count() < 100)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(100, sweethome.count()) << "Count in variable != 100";
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  LOG(INFO) << "First 100 call laters executed." << std::endl;
  // Set up 100 calls very closely spaced
  for (int j = 0; j < 100; ++j)
    clt_.AddCallLater(50, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  while (sweethome.count() < 200)
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  ASSERT_EQ(200, sweethome.count()) << "Count in variable != 200";
  LOG(INFO) << "Second 100 call laters executed." << std::endl;
  ASSERT_EQ(0, clt_.CancelAll()) <<
      "Some calls were cancelled, list not empty";
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
}

TEST_F(CallLaterTest, BEH_BASE_AddCallLatersDestroyService) {
  Lynyrd sweethome;
  {
    CallLaterTimer clt;
    for (int i = 5000; i < 5100; ++i)
      clt.AddCallLater(i, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  }
  ASSERT_EQ(0, sweethome.count()) << "Count in variable != 0";
  {
    CallLaterTimer clt;
    for (int i = 10; i < 1010; ++i)
      clt.AddCallLater(i, boost::bind(&Lynyrd::Skynyrd, &sweethome));
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  ASSERT_LT(0, sweethome.count());
  ASSERT_GT(1000, sweethome.count());
}

TEST_F(CallLaterTest, BEH_BASE_AddRemoveCallLaters) {
  // Set up 100 calls and remove 50 of them before they start
  boost::shared_ptr<boost::mutex> mutex(new boost::mutex);
  boost::shared_ptr<boost::condition_variable>
      cond_var(new boost::condition_variable);
  Lynyrd sweethome(mutex, cond_var);
  std::vector<int> call_ids;
  for (int i = 0; i < 100; ++i) {
    call_ids.push_back(clt_.AddCallLater(1000 + (20 * i),
        boost::bind(&Lynyrd::Skynyrd, &sweethome)));
  }
  LOG(INFO) << "Scheduled 1st run, before cancelling " << clt_.TimersMapSize()
       << std::endl;
  for (int j = 0; j < 50; ++j)
    EXPECT_TRUE(clt_.CancelOne(call_ids[j]));
  {
    size_t sweethome_count = sweethome.count();
    boost::mutex::scoped_lock lock(*mutex);
    while (sweethome_count < 50) {
      EXPECT_TRUE(cond_var->timed_wait(lock, boost::posix_time::seconds(5)));
      lock.unlock();
      sweethome_count = sweethome.count();
      lock.lock();
    }
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  sweethome.reset();
  ASSERT_EQ(0, sweethome.count());

  // Set up 100 calls again, then remove them all before they start
  LOG(INFO) << "Finished 1st run, before scheduling 2nd." << std::endl;
  for (int k = 0; k < 100; ++k) {
    clt_.AddCallLater(2000 + (100 * k),
                      boost::bind(&Lynyrd::Skynyrd, &sweethome));
  }
  int n = clt_.CancelAll();
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  {
    boost::mutex::scoped_lock lock(*mutex);
    while (clt_.TimersMapSize())
      EXPECT_TRUE(cond_var->timed_wait(lock, boost::posix_time::seconds(5)));
  }
  ASSERT_EQ(100 - n, sweethome.count()) << "Count in variable incorrect";
  sweethome.reset();
  ASSERT_EQ(0, sweethome.count());

  // Set up 100 calls again, then remove them all while they're being run.
  LOG(INFO) << "Finished 2nd run, before scheduling 3rd." << std::endl;
  for (int l = 0; l < 100; ++l) {
    clt_.AddCallLater(100 + (100 * l),
                      boost::bind(&Lynyrd::Skynyrd, &sweethome));
  }
  {
    boost::mutex::scoped_lock lock(*mutex);
    while (clt_.TimersMapSize() > 95)
      EXPECT_TRUE(cond_var->timed_wait(lock, boost::posix_time::seconds(5)));
    n = clt_.CancelAll();
  }
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
  while (sweethome.count() < 100 - n) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
  ASSERT_EQ(100 - n, sweethome.count()) << "Count in variable incorrect";
}

TEST_F(CallLaterTest, BEH_BASE_AddPtrCallLater) {
  // Basic call later, but this time to method of object created on heap.
  boost::scoped_ptr<Lynyrd> sweethome(new Lynyrd());
  ASSERT_EQ(0, sweethome->count());
  clt_.AddCallLater(20, boost::bind(&Lynyrd::Skynyrd, sweethome.get()));
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  ASSERT_EQ(0, clt_.CancelAll()) <<
      "Some calls were cancelled, list not empty";
  ASSERT_EQ(0, clt_.TimersMapSize()) << "List not empty";
}

}  // namespace base
