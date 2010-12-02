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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_BASE_THREADPOOL_H_
#define MAIDSAFE_BASE_THREADPOOL_H_

#include <boost/thread.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/function.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest_prod.h>
#include <queue>
#include <vector>

namespace base {

namespace test {
class ThreadpoolTest_BEH_BASE_SingleTask_Test;
class ThreadpoolTest_BEH_BASE_MultipleTasks_Test;
class ThreadpoolTest_BEH_BASE_Resize_Test;
class ThreadpoolTest_BEH_BASE_TimedWait_Test;
}  // namespace test

class Threadpool {
 public:
  typedef boost::function<void()> VoidFunctor;
  explicit Threadpool(const boost::uint16_t &thread_count);
  // Resizes to 0 (doesn't complete tasks not already started)
  ~Threadpool();
  // Returns false if a thread resource error is thrown
  bool Resize(const boost::uint16_t &thread_count);
  bool EnqueueTask(const VoidFunctor &functor);
  bool WaitForTasksToFinish(const boost::posix_time::milliseconds &duration);
  friend class test::ThreadpoolTest_BEH_BASE_SingleTask_Test;
  friend class test::ThreadpoolTest_BEH_BASE_MultipleTasks_Test;
  friend class test::ThreadpoolTest_BEH_BASE_Resize_Test;
  friend class test::ThreadpoolTest_BEH_BASE_TimedWait_Test;
 private:
  Threadpool(const Threadpool&);
  Threadpool &operator=(const Threadpool&);
  void Run();
  bool Continue();
  bool TimedWait(const boost::posix_time::milliseconds &duration,
                 boost::function<bool()> predicate);
  bool ThreadCountCorrect() {
    return requested_thread_count_ == running_thread_count_;
  }
  bool AllTasksDone() { return remaining_tasks_ == 0U; }
  boost::uint16_t requested_thread_count_, running_thread_count_;
  boost::posix_time::milliseconds default_wait_timeout_;
  size_t remaining_tasks_;
  boost::mutex mutex_;
  boost::condition_variable condition_;
  std::queue<VoidFunctor> functors_;
};

}  // namespace base

#endif  // MAIDSAFE_BASE_THREADPOOL_H_
