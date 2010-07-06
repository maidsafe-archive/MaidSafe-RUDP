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

#ifndef MAIDSAFE_BASE_CALLLATERTIMER_H_
#define MAIDSAFE_BASE_CALLLATERTIMER_H_
#include <boost/thread.hpp>
#include <boost/cstdint.hpp>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <map>

namespace base {

typedef boost::function<void()> VoidFunctorEmpty;

struct CallLaterMap {
  CallLaterMap() : time_to_execute(0), callback(), call_later_id(0) {}
  boost::uint64_t time_to_execute;
  VoidFunctorEmpty callback;
  boost::uint32_t call_later_id;
};

class CallLaterTimer {
 public:
  typedef std::map<boost::uint32_t,
                   boost::shared_ptr<boost::asio::deadline_timer> > TimersMap;
  CallLaterTimer();
  ~CallLaterTimer();
  inline bool IsStarted() { return is_started_; }
  int CancelAll();
  bool CancelOne(const boost::uint32_t &call_later_id);
  size_t TimersMapSize();
  // Delay msecs milliseconds to call the function specified by callback
  boost::uint32_t AddCallLater(const boost::uint64_t &msecs,
                               VoidFunctorEmpty callback);
 private:
  void Run();
  void ExecuteFunctor(const VoidFunctorEmpty &callback,
                      const boost::uint32_t &call_later_id,
                      const boost::system::error_code &ec);
  CallLaterTimer(const CallLaterTimer&);
  CallLaterTimer& operator=(const CallLaterTimer&);
  boost::mutex timers_mutex_;
  bool is_started_;
  TimersMap timers_;
  boost::asio::io_service io_service_;
  boost::asio::strand strand_;
  boost::shared_ptr<boost::asio::io_service::work> work_;
  boost::shared_ptr<boost::thread> worker_thread_;
  boost::uint32_t call_later_id_;
};

}  // namespace base
#endif  // MAIDSAFE_BASE_CALLLATERTIMER_H_
