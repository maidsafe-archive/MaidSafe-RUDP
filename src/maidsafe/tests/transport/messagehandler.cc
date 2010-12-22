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

#include <boost/lexical_cast.hpp>
#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/base/log.h"

namespace transport {

namespace test {

void MessageHandler::DoOnRequestReceived(const std::string &request,
                                         const Info &info,
                                         std::string *response,
                                         Timeout *timeout) {
  boost::mutex::scoped_lock lock(mutex_);
  requests_received_.push_back(std::make_pair(request, info));
  responses_sent_.push_back(*response);
  *response = "Replied to " + request + " (Id = " +
              boost::lexical_cast<std::string>(requests_received_.size()) + ")";
  *timeout = kImmediateTimeout;
  DLOG(INFO) << this_id_ << " - Received request: \"" << request
              << "\".  Responding with \"" << *response << "\"" << std::endl;
}

void MessageHandler::DoOnResponseReceived(const std::string &request,
                                          const Info &info,
                                          std::string *response,
                                          Timeout *timeout) {
  response->clear();
  *timeout = kImmediateTimeout;
  boost::mutex::scoped_lock lock(mutex_);
  responses_received_.push_back(std::make_pair(request, info));
  DLOG(INFO) << this_id_ << " - Received response: \"" << request << "\""
             << std::endl;
}

void MessageHandler::DoOnError(const TransportCondition &tc) {
  boost::mutex::scoped_lock lock(mutex_);
  errors_.push_back(tc);
  DLOG(INFO) << this_id_ << " - Error: " << tc << std::endl;
}

void MessageHandler::ClearContainers() {
  boost::mutex::scoped_lock lock(mutex_);
  requests_received_.clear();
  responses_received_.clear();
  responses_sent_.clear();
  errors_.clear();
}

IncomingMessages MessageHandler::requests_received() {
  boost::mutex::scoped_lock lock(mutex_);
  return requests_received_;
}

IncomingMessages MessageHandler::responses_received() {
  boost::mutex::scoped_lock lock(mutex_);
  return responses_received_;
}

OutgoingResponses MessageHandler::responses_sent() {
  boost::mutex::scoped_lock lock(mutex_);
  return responses_sent_;
}

Errors MessageHandler::errors() {
  boost::mutex::scoped_lock lock(mutex_);
  return errors_;
}

}  // namespace test

}  // namespace transport
