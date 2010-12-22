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

#ifndef MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_
#define MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_

#include <boost/thread/mutex.hpp>
#include <string>
#include <utility>
#include <vector>
#include "maidsafe/transport/transport.h"

namespace transport {

namespace test {

typedef std::vector< std::pair<std::string, Info> > IncomingMessages;
typedef std::vector<std::string> OutgoingResponses;
typedef std::vector<TransportCondition> Errors;

class MessageHandler {
 public:
  explicit MessageHandler(const std::string &id)
    : this_id_(id),
      requests_received_(),
      responses_received_(),
      responses_sent_(),
      errors_(),
      mutex_() {}
  void DoOnRequestReceived(const std::string &request,
                           const Info &info,
                           std::string *response,
                           Timeout *timeout);
  void DoOnResponseReceived(const std::string &request,
                            const Info &info,
                            std::string *response,
                            Timeout *timeout);
  void DoOnError(const TransportCondition &tc);
  void ClearContainers();
  IncomingMessages requests_received();
  IncomingMessages responses_received();
  OutgoingResponses responses_sent();
  Errors errors();
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  std::string this_id_;
  IncomingMessages requests_received_, responses_received_;
  OutgoingResponses responses_sent_;
  Errors errors_;
  boost::mutex mutex_;
};

}  // namespace test

}  // namespace transport

#endif  // MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_

