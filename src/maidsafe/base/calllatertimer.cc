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

#include <limits>
#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/base/log.h"
namespace base {

void dummy_timeout_func() {}

CallLaterTimer::CallLaterTimer()
    : timers_mutex_(),
      is_started_(true),
      timers_(),
      io_service_(),
      strand_(io_service_),
      work_(new boost::asio::io_service::work(io_service_)),
      worker_thread_(),
      call_later_id_(0) {
  worker_thread_.reset(new boost::thread(&CallLaterTimer::Run, this));
}

CallLaterTimer::~CallLaterTimer() {
  CancelAll();
  {
    boost::mutex::scoped_lock guard(timers_mutex_);
    is_started_ = false;
  }
  // Allow io_service_.run() to exit.
  work_.reset();
  worker_thread_->join();
}

void CallLaterTimer::Run() {
  while (true) {
    try {
      io_service_.run();
      break;
    } catch(const std::exception &e) {
      DLOG(ERROR) << e.what() << std::endl;
    }
  }
}

void CallLaterTimer::ExecuteFunctor(
    const VoidFunctorEmpty &callback,
    const boost::uint32_t &call_later_id,
    const boost::system::error_code &error_code) {
  if (error_code) {
    if (error_code != boost::asio::error::operation_aborted) {
      DLOG(ERROR) << error_code.message() << std::endl;
      boost::mutex::scoped_lock guard(timers_mutex_);
      timers_.erase(call_later_id);
    }
  } else {
    strand_.dispatch(callback);
    boost::mutex::scoped_lock guard(timers_mutex_);
    timers_.erase(call_later_id);
  }
}

boost::uint32_t CallLaterTimer::AddCallLater(const boost::uint64_t &msecs,
                                             VoidFunctorEmpty callback) {
  boost::mutex::scoped_lock guard(timers_mutex_);
  if ((msecs == 0) || (!is_started_))
    return std::numeric_limits<boost::uint32_t>::max();
  call_later_id_ = (call_later_id_ + 1) % 32768;
  boost::shared_ptr<boost::asio::deadline_timer> timer(
      new boost::asio::deadline_timer(io_service_,
      boost::posix_time::milliseconds(msecs)));
  std::pair<TimersMap::iterator, bool> p =
      timers_.insert(TimersMap::value_type(call_later_id_, timer));
  if (p.second) {
    timer->async_wait(boost::bind(&CallLaterTimer::ExecuteFunctor, this,
                                  callback, call_later_id_, _1));
    return call_later_id_;
  }
  return std::numeric_limits<boost::uint32_t>::max();
}

bool CallLaterTimer::CancelOne(const boost::uint32_t &call_later_id) {
  boost::mutex::scoped_lock guard(timers_mutex_);
  TimersMap::iterator it = timers_.find(call_later_id);
  if (it == timers_.end())
    return false;
  it->second->cancel();
  timers_.erase(call_later_id);
  return true;
}

int CallLaterTimer::CancelAll() {
  boost::mutex::scoped_lock guard(timers_mutex_);
  int n = timers_.size();
  for (TimersMap::iterator it = timers_.begin(); it != timers_.end(); ++it) {
    it->second->cancel();
  }
  timers_.clear();
  return n;
}

size_t CallLaterTimer::TimersMapSize() {
  boost::mutex::scoped_lock guard(timers_mutex_);
  return timers_.size();
}
}  // namespace base
