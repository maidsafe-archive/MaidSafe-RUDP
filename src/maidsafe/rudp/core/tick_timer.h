/* Copyright (c) 2010 maidsafe.net limited
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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_RUDP_TICK_TIMER_H_
#define MAIDSAFE_TRANSPORT_RUDP_TICK_TIMER_H_

#include "boost/asio/deadline_timer.hpp"

namespace maidsafe {

namespace transport {

// Lightweight wrapper around a deadline_timer that avoids modifying the expiry
// time if it would move it further away.
class RudpTickTimer {
 public:
  explicit RudpTickTimer(boost::asio::io_service &asio_service)  // NOLINT (Fraser)
    : timer_(asio_service) {
    Reset();
  }

  static boost::posix_time::ptime Now() {
    return boost::asio::deadline_timer::traits_type::now();
  }

  void Cancel() {
    timer_.cancel();
  }

  void Reset() {
    timer_.expires_at(boost::posix_time::pos_infin);
  }

  bool Expired() const {
    // Infinate time out will be counted as expired
    if (timer_.expires_at() == boost::posix_time::pos_infin)
      return true;
    return Now() >= timer_.expires_at();
  }

  void TickAt(const boost::posix_time::ptime &time) {
    if (time < timer_.expires_at())
      timer_.expires_at(time);
  }

  void TickAfter(const boost::posix_time::time_duration &duration) {
    TickAt(Now() + duration);
  }

  template <typename WaitHandler>
  void AsyncWait(WaitHandler handler) {
    timer_.async_wait(handler);
  }

 private:
  boost::asio::deadline_timer timer_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_TICK_TIMER_H_
