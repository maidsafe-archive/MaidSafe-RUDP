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

#include "maidsafe/transport/message_handler.h"
#include "boost/lexical_cast.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/transport/log.h"

namespace maidsafe {

namespace transport {

void MessageHandler::OnMessageReceived(const std::string &request,
                                       const Info &info,
                                       std::string *response,
                                       Timeout *timeout) {
  if (request.empty())
    return;
  SecurityType security_type = request.at(0);
  std::string serialised_message(request.substr(1));
  protobuf::WrapperMessage wrapper;
  if (wrapper.ParseFromString(serialised_message) && wrapper.IsInitialized()) {
    ProcessSerialisedMessage(wrapper.msg_type(), wrapper.payload(),
                             security_type, wrapper.message_signature(),
                             info, response, timeout);
  }
}

bool MessageHandler::UnwrapWrapperMessage(const std::string& serialised_message,
                                          int* msg_type,
                                          std::string* payload,
                                          std::string* message_signature) {
  protobuf::WrapperMessage wrapper;
  if (wrapper.ParseFromString(serialised_message) && wrapper.IsInitialized()) {
    *msg_type = wrapper.msg_type();
    *payload = wrapper.payload();
    *message_signature = wrapper.message_signature();
    return true;
  } else {
    return false;
  }
}

std::string MessageHandler::WrapWrapperMessage(const int& msg_type,
    const std::string& payload, const std::string& message_signature) {
  protobuf::WrapperMessage wrapper;
  wrapper.set_msg_type(msg_type);
  wrapper.set_payload(payload);
  if (!message_signature.empty())
    wrapper.set_message_signature(message_signature);
  return wrapper.SerializeAsString();
}

void MessageHandler::OnError(const TransportCondition &transport_condition,
                             const Endpoint &remote_endpoint) {
  (*on_error_)(transport_condition, remote_endpoint);
}

void MessageHandler::ProcessSerialisedMessage(
    const int &/*message_type*/,
    const std::string &/*payload*/,
    const SecurityType &/*security_type*/,
    const std::string &/*message_signature*/,
    const Info & /*info*/,
    std::string* /*message_response*/,
    Timeout* /*timeout*/) {}

std::string MessageHandler::MakeSerialisedWrapperMessage(
    const int &message_type,
    const std::string &payload,
    SecurityType /*security_type*/,
    const std::string &/*recipient_public_key*/) {
  std::string final_message(1, kNone);
  final_message += WrapWrapperMessage(message_type, payload, "");
  return final_message;
}

}  // namespace transport

}  // namespace maidsafe
