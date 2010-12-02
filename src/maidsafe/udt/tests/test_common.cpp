/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Tests for methods and classes in udt/common.h
* Version:      1.0
* Created:      30/11/2010 13:14:00
* Author:       Team www.maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <gtest/gtest.h>
#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread.hpp>

#include "maidsafe/udt/common.h"

namespace bptime = boost::posix_time;

namespace test_udt {

class UdtCTimerTest : public testing::Test {
 public:
  UdtCTimerTest() : ctimer_() {}
  ~UdtCTimerTest() {}
 protected:
  void SetUp() {}
  void TearDown() {}
  CTimer ctimer_;
};

template <typename T>
testing::AssertionResult BetweenLimits(const T &data,
                                       const T &target,
                                       const float &error_margin) {
  T lower_limit(static_cast<T>(target * (1 - error_margin)));
  T upper_limit(static_cast<T>(target * (1 + error_margin)));
  if (lower_limit > data)
    return testing::AssertionFailure() << "lower limit (" << lower_limit <<
        ") > data (" << data << ")";
  if (upper_limit < data)
    return testing::AssertionFailure() << "upper limit (" << upper_limit <<
        ") < data (" << data << ")";
  return testing::AssertionSuccess();
}

TEST_F(UdtCTimerTest, BEH_UDT_sleepto) {
  // TODO(Fraser#5#): 2010-12-02 - Use smaller margin of error.
  const float kErrorMargin(0.2f);
  const boost::uint64_t kExpectedSleepDuration(1000000);  // 1 second
  uint64_t single_second_interval(ctimer_.getCPUFrequency() * 1000000);

  bptime::ptime clock_start(bptime::microsec_clock::universal_time());
  uint64_t start_time(ctimer_.getTime()), start_clock_cycle(0);
  ctimer_.rdtsc(start_clock_cycle);

  ctimer_.sleepto(start_clock_cycle + single_second_interval);

  bptime::ptime clock_end(bptime::microsec_clock::universal_time());
  uint64_t end_time(ctimer_.getTime()), end_clock_cycle(0);
  ctimer_.rdtsc(end_clock_cycle);

  boost::uint64_t clock_elapsed(static_cast<boost::uint64_t>(
      (clock_end - clock_start).total_microseconds()));
  EXPECT_TRUE(BetweenLimits(clock_elapsed, kExpectedSleepDuration,
                            kErrorMargin));
}

TEST_F(UdtCTimerTest, BEH_UDT_sleep) {
  // TODO(Fraser#5#): 2010-12-02 - Use smaller margin of error.
  const float kErrorMargin(0.2f);
  const boost::uint64_t kExpectedSleepDuration(1000000);  // 1 second
  uint64_t single_second_interval(ctimer_.getCPUFrequency() * 1000000);
  bptime::ptime clock_start(bptime::microsec_clock::universal_time());

  ctimer_.sleep(single_second_interval);

  bptime::ptime clock_end(bptime::microsec_clock::universal_time());

  boost::uint64_t clock_elapsed(static_cast<boost::uint64_t>(
      (clock_end - clock_start).total_microseconds()));
  EXPECT_TRUE(BetweenLimits(clock_elapsed, kExpectedSleepDuration,
                            kErrorMargin));
}

TEST_F(UdtCTimerTest, BEH_UDT_fixed_sleep) {
  // TODO(Fraser#5#): 2010-12-02 - Use smaller margin of error.
  const float kErrorMargin(0.2f);
#ifndef WIN32
  const boost::uint64_t kMinExpectedSleepDuration(10);  // 10 microseconds
#else
  const boost::uint64_t kMinExpectedSleepDuration(1000);  // 1 millisecond
#endif

  bptime::ptime clock_start(bptime::microsec_clock::universal_time());

  ctimer_.sleep();

  bptime::ptime clock_end(bptime::microsec_clock::universal_time());

  boost::uint64_t clock_elapsed(static_cast<boost::uint64_t>(
      (clock_end - clock_start).total_microseconds()));
  EXPECT_LE(kMinExpectedSleepDuration * (1 - kErrorMargin), clock_elapsed);
}

void TimerInterrupt(CTimer *ctimer, const bptime::microseconds &wait_duration) {
  boost::this_thread::sleep(wait_duration);
  ctimer->tick();
  ctimer->interrupt();
}

TEST_F(UdtCTimerTest, BEH_UDT_interrupt) {
  // TODO(Fraser#5#): 2010-12-02 - Use smaller margin of error.
  const float kErrorMargin(0.2f);
  const boost::uint64_t kExpectedSleepDuration(1000000);  // 1 second
  uint64_t ten_second_interval(ctimer_.getCPUFrequency() * 10000000);
  bptime::ptime clock_start(bptime::microsec_clock::universal_time());

  boost::thread interrupter(&TimerInterrupt, &ctimer_,
                            bptime::microseconds(kExpectedSleepDuration));
  ctimer_.sleep(ten_second_interval);

  bptime::ptime clock_end(bptime::microsec_clock::universal_time());

  boost::uint64_t clock_elapsed(static_cast<boost::uint64_t>(
      (clock_end - clock_start).total_microseconds()));
  EXPECT_TRUE(BetweenLimits(clock_elapsed, kExpectedSleepDuration,
                            kErrorMargin));
  interrupter.join();
}

void TimerTriggerEvent(CTimer *ctimer,
                       const bptime::microseconds &wait_duration) {
  boost::this_thread::sleep(wait_duration);
  ctimer->triggerEvent();
}

TEST_F(UdtCTimerTest, BEH_UDT_Event) {
  // TODO(Fraser#5#): 2010-12-02 - Use smaller margin of error.
  const float kErrorMargin(1.0f);
#ifndef WIN32
  boost::uint64_t expected_wait_duration(10000);  // 10 milliseconds
#else
  boost::uint64_t expected_wait_duration(1000);  // 1 millisecond
#endif

  // No triggering of event
  bptime::ptime clock_start(bptime::microsec_clock::universal_time());
  ctimer_.waitForEvent();
  bptime::ptime clock_end(bptime::microsec_clock::universal_time());

  boost::uint64_t clock_elapsed(static_cast<boost::uint64_t>(
      (clock_end - clock_start).total_microseconds()));
  EXPECT_TRUE(BetweenLimits(clock_elapsed, expected_wait_duration,
                            kErrorMargin));

  // Triggering of event after short sleep
  expected_wait_duration = 500;  // 500 microseconds
  clock_start = bptime::microsec_clock::universal_time();
  boost::thread trigger(&TimerTriggerEvent, &ctimer_,
                        bptime::microseconds(expected_wait_duration));
  ctimer_.waitForEvent();
  clock_end = bptime::microsec_clock::universal_time();

  clock_elapsed = static_cast<boost::uint64_t>(
                  (clock_end - clock_start).total_microseconds());
  EXPECT_GE(expected_wait_duration * (1 + kErrorMargin), clock_elapsed);
  trigger.join();
}


class UdtCGuardTest : public testing::Test {
 public:
  UdtCGuardTest() : mutex_(),
                    cguard_(mutex_),
                    shared_resource_(0),
                    kThreadCount_(20),
                    kRepeatCount_(100000),
                    workers_() {
#ifndef WIN32
    pthread_mutex_init(&mutex_, NULL);
#else
    mutex_ = CreateMutex(NULL, false, NULL);
#endif
  }
  ~UdtCGuardTest() {}
  void UnprotectedIncrememt(const int &repeat_count) {
    for (int i = 0; i < repeat_count; ++i)
      ++shared_resource_;
  }
  void ProtectedIncrememt(const int &repeat_count, pthread_mutex_t *mutex) {
    for (int i = 0; i < repeat_count; ++i) {
      cguard_.enterCS(*mutex);
      ++shared_resource_;
      cguard_.leaveCS(*mutex);
    }
  }
 protected:
  void SetUp() {}
  void TearDown() {}
  pthread_mutex_t mutex_;
  CGuard cguard_;
  int shared_resource_;
  const int kThreadCount_, kRepeatCount_;
  boost::thread_group workers_;
};

TEST_F(UdtCGuardTest, BEH_UDT_CriticalSection) {
  // Check unprotected increment fails
  for (int i = 0; i < kThreadCount_; ++i)
    workers_.create_thread(boost::bind(&UdtCGuardTest::UnprotectedIncrememt,
                                       this, kRepeatCount_));
  workers_.join_all();
  EXPECT_GT(kThreadCount_ * kRepeatCount_, shared_resource_);

  // Check protected increment succeeds
  shared_resource_ = 0;
  for (int i = 0; i < kThreadCount_; ++i)
    workers_.create_thread(boost::bind(&UdtCGuardTest::ProtectedIncrememt, this,
                                       kRepeatCount_, &mutex_));
  workers_.join_all();
  EXPECT_EQ(kThreadCount_ * kRepeatCount_, shared_resource_);
}

TEST_F(UdtCGuardTest, BEH_UDT_Mutex) {
  // Check uninitialised mutex fails to protect shared data
  pthread_mutex_t local_mutex;
  for (int i = 0; i < kThreadCount_; ++i)
    workers_.create_thread(boost::bind(&UdtCGuardTest::ProtectedIncrememt, this,
                                       kRepeatCount_, &local_mutex));
  workers_.join_all();
  EXPECT_GT(kThreadCount_ * kRepeatCount_, shared_resource_);

  // Check initialised mutex protects shared data
  shared_resource_ = 0;
  cguard_.createMutex(local_mutex);
  for (int i = 0; i < kThreadCount_; ++i)
    workers_.create_thread(boost::bind(&UdtCGuardTest::ProtectedIncrememt, this,
                                       kRepeatCount_, &local_mutex));
  workers_.join_all();
  EXPECT_EQ(kThreadCount_ * kRepeatCount_, shared_resource_);

  // Check unlocked mutex fails to protect shared data
  // TODO(Fraser#5#): 2010-12-02 - Uncomment below.
//  shared_resource_ = 0;
//  cguard_.releaseMutex(local_mutex);
//  for (int i = 0; i < kThreadCount_; ++i)
//    workers_.create_thread(boost::bind(&UdtCGuardTest::ProtectedIncrememt, this,
//                                       kRepeatCount_, &local_mutex));
//  workers_.join_all();
//  EXPECT_GT(kThreadCount_ * kRepeatCount_, shared_resource_);
}

}  // namespace test_udt
