/* Copyright (c) 2011 maidsafe.net limited
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

#ifndef MAIDSAFE_DHT_TIMED_TASK_H_
#define MAIDSAFE_DHT_TIMED_TASK_H_

#include "boost/asio.hpp"

namespace maidsafe {

namespace dht {

namespace kademlia {

struct TimerContainer {
  TimerContainer()
      : asio_service(),
        timer(new boost::asio::deadline_timer(asio_service)),
        work(),
        thread_group() {
    work.reset(
        new boost::asio::io_service::work(asio_service));
    thread_group.reset(new boost::thread_group());
    thread_group->create_thread(
        std::bind(static_cast<size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), &asio_service));
  }
  ~TimerContainer() {
    work.reset();
    asio_service.stop();
    thread_group->join_all();
  }
  AsioService asio_service;
  std::shared_ptr<boost::asio::io_service::work> work;
  std::shared_ptr<boost::thread_group> thread_group;
  std::shared_ptr<boost::asio::deadline_timer> timer;
};

template <typename F>
struct TimedTaskContainer {
  TimedTaskContainer(F f, size_t deadline)
      : timer(new TimerContainer()),
        function(f),
        repeat_time(deadline),
        stop(false) {
    timer->timer->async_wait(std::bind(&TimedTaskContainer::Handle, this));
  }

  void Handle() {
    if (!stop) {
      function();
      timer->timer->expires_from_now(boost::posix_time::millisec(repeat_time));
      timer->timer->async_wait(std::bind(&TimedTaskContainer::Handle, this));
    }
  }

  void Stop() {
    if (!stop) {
      stop = true;
      timer->timer->cancel();
    }
  }

  void Start() {
    if (stop) {
      stop = false;      
      timer->timer->async_wait(std::bind(&TimedTaskContainer::HandleWrap, this));
    }
  }
 private:
  std::shared_ptr<TimerContainer> timer;
  F function;
  size_t repeat_time;
  bool stop;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TIMED_TASK_H_
