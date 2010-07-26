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

#include "maidsafe/base/threadpool.h"
#include "maidsafe/base/log.h"

namespace base {

Threadpool::Threadpool(const boost::uint16_t &thread_count)
    : requested_thread_count_(thread_count),
      running_thread_count_(0),
      mutex_(),
      condition_(),
      functors_() {
  Resize(requested_thread_count_);
}

Threadpool::~Threadpool() {
  Resize(0);
  boost::mutex::scoped_lock lock(mutex_);
  while (requested_thread_count_ != running_thread_count_)
    condition_.wait(lock);
}

bool Threadpool::Resize(const boost::uint16_t &thread_count) {
  boost::mutex::scoped_lock lock(mutex_);
  requested_thread_count_ = thread_count;
  boost::int32_t difference = requested_thread_count_ - running_thread_count_;
  if (difference > 0) {
    for (int i = 0; i < difference; ++i) {
      try {
        boost::thread(&Threadpool::Run, this);
      }
      catch(const std::exception &e) {
        DLOG(ERROR) << "Exception resizing threadpool to " <<
            requested_thread_count_ << " threads: " << e.what() << std::endl;
        return false;
      }
    }
  } else if (difference < 0) {
    condition_.notify_all();
  }
  return true;
}

void Threadpool::EnqueueTask(const VoidFunctor &functor) {
  boost::mutex::scoped_lock lock(mutex_);
  functors_.push(functor);
  condition_.notify_all();
}

bool Threadpool::ThreadCountCorrect() {
  return requested_thread_count_ == running_thread_count_;
}

bool Threadpool::Continue() {
  return (requested_thread_count_ < running_thread_count_) ||
         !functors_.empty();
}

void Threadpool::Run() {
  {
    boost::mutex::scoped_lock lock(mutex_);
    ++running_thread_count_;
  }
  while (true) {
    boost::mutex::scoped_lock lock(mutex_);
    condition_.wait(lock, boost::bind(&Threadpool::Continue, this));
    if (requested_thread_count_ < running_thread_count_) {
      --running_thread_count_;
      // Notify to destructor
      if (running_thread_count_ == 0) {
        condition_.notify_one();
      }
      return;
    } else {
      // grab the first functor from the queue, but allow other threads to
      // operate while executing it
      VoidFunctor functor = functors_.front();
      functors_.pop();
      lock.unlock();
      functor();
      lock.lock();
    }
  }
}

}  // namespace base
