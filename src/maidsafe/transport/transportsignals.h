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

/*******************************************************************************
 * NOTE: This header should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_

#include <boost/signals2/signal.hpp>
#include <maidsafe/transport/transportconditions.h>
#include <string>


namespace bs2 = boost::signals2;

namespace transport {

// place-holder; need a way to respond on the same socket
typedef boost::uint64_t MessageId;

// to handle the event of receiving a message
typedef bs2::signal<void(const MessageId&,
                         const std::string&,
                         const float&)> OnMessageReceived;

// to handle the event of any kind of failure, at any stage
typedef bs2::signal<void(const MessageId&,
                         const TransportCondition&)> OnError;

class Signals {
 public:
  Signals() : on_message_received_(),
              on_error_() {}
  ~Signals() {}

  // OnMessageReceived =========================================================
  bs2::connection ConnectOnMessageReceived(
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(slot);
  }

  bs2::connection GroupConnectOnMessageReceived(
      const int &group,
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(group, slot);
  }

  // OnError ===================================================================
  bs2::connection ConnectOnError(const OnError::slot_type &slot) {
    return on_error_.connect(slot);
  }

  bs2::connection GroupConnectOnStats(const int &group,
                                      const OnError::slot_type &slot) {
    return on_error_.connect(group, slot);
  }

 private:
  OnMessageReceived on_message_received_;
  OnError on_error_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_

