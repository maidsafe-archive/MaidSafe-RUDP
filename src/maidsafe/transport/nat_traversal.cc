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

#include "maidsafe/transport/nat_traversal.h"

#include "maidsafe/transport/contact.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/message_handler.h"
#include "maidsafe/transport/nat_detection_rpcs.h"

namespace maidsafe {

namespace transport {

NatTraversal::NatTraversal(boost::asio::io_service &asio_service, // NOLINT
                           const Timeout &interval,
                           const Timeout &timeout,
                           TransportPtr transport,
                           MessageHandlerPtr message_handler)
    : rpcs_(new NatDetectionRpcs()),
      asio_service_(asio_service),
      timeout_(timeout),
      interval_(interval),
      timer_(asio_service, interval),
      transport_(transport),
      message_handler_(message_handler),
      callback_(),
      endpoint_() {}

void NatTraversal::KeepAlive(const Endpoint &endpoint,
                             KeepAliveFunctor callback) {
  boost::system::error_code ec;
  if (IsValid(endpoint) && callback) {
    endpoint_ = endpoint;
    callback_ = callback;
    rpcs_->KeepAlive(endpoint_, timeout_, transport_, message_handler_,
                     std::bind(&NatTraversal::KeepAliveCallback, this,
                               args::_1, ec));
    timer_.async_wait(boost::bind(&NatTraversal::DoKeepAlive, this));
  }
}


void NatTraversal::DoKeepAlive() {
  boost::system::error_code ec;
  rpcs_->KeepAlive(endpoint_, timeout_, transport_, message_handler_,
                   std::bind(&NatTraversal::KeepAliveCallback, this, args::_1,
                     ec));
  timer_.expires_from_now(interval_);
  timer_.async_wait(boost::bind(&NatTraversal::DoKeepAlive, this));
}

void NatTraversal::KeepAliveCallback(const TransportCondition &condition,
                                     const boost::system::error_code& ec) {
  if (ec) {
    timer_.cancel();
    callback_(condition);
  }
}

}  // namespace transport

}  // namespace maidsafe
