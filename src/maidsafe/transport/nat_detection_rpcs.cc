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

#include <vector>
#include <string>

#include "maidsafe/transport/nat_detection_rpcs.h"
#include "maidsafe/transport/contact.h"
#include "maidsafe/transport/message_handler.h"


namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

void NatDetectionRpcs::NatDetection(const std::vector<Contact>& /*candidates*/,
                                    const bool& /*full*/,
                                    NatResultFunctor /*nat_result_functor*/) {
}

void NatDetectionRpcs::NatDetection(const std::vector<Contact> &candidates,
                                    TransportPtr transport,
                                    MessageHandlerPtr message_handler,
                                    const bool &full,
                                    NatResultFunctor callback) {
  protobuf::NatDetectionRequest request;
  TransportDetails transport_details(transport->transport_details());
  for (auto itr(transport_details.local_endpoints.begin());
      itr != transport_details.local_endpoints.end(); ++itr)
    request.add_local_ips((*itr).ip.to_string());
  request.set_local_port(transport_details.local_endpoints.begin()->port);
  request.set_full_detection(full);
  std::string message(message_handler->WrapMessage(request));
  DoNatDetection(candidates, transport, message_handler, message, full,
                 callback, 0);
}

void NatDetectionRpcs::DoNatDetection(const std::vector<Contact> &candidates,
                                      TransportPtr transport,
                                      MessageHandlerPtr message_handler,
                                      const std::string &request,
                                      const bool &full,
                                      NatResultFunctor callback,
                                      const size_t &index) {
  message_handler->on_nat_detection_response()->connect(
      std::bind(&NatDetectionRpcs::NatDetectionCallback, this,
                transport::kSuccess, args::_1, candidates, callback, transport,
                message_handler, request, full, index));
  message_handler->on_error()->connect(
      std::bind(&NatDetectionRpcs::NatDetectionCallback, this, args::_1,
                protobuf::NatDetectionResponse(), candidates, callback,
                transport, message_handler, request, full, index));
  transport->Send(request, candidates[index].endpoint(),
                   transport::kDefaultInitialTimeout);
}

void NatDetectionRpcs::KeepAlive(const Endpoint endpoint,
                                 const Timeout &/*timeout*/,
                                 TransportPtr transport,
                                 MessageHandlerPtr message_handler,
                                 KeepAliveFunctor callback) {
  message_handler->on_error()->connect(
      std::bind(&NatDetectionRpcs::KeepAliveCallback, this, args::_1,
      callback));
  // TODO(Prakash): adjust timeout parameter of RUDP if needed
  transport->Send("Alive", endpoint, kImmediateTimeout);
}

void NatDetectionRpcs::NatDetectionCallback(const TransportCondition &result,
                                const protobuf::NatDetectionResponse &response,
                                const std::vector<Contact> &candidates,
                                NatResultFunctor callback,
                                TransportPtr transport,
                                MessageHandlerPtr message_handler,
                                const std::string &request,
                                const bool &full,
                                const size_t &index) {
  TransportDetails transport_details;
  if (result == kSuccess) {
    transport_details.endpoint.ip.from_string(response.endpoint().ip().data());
    transport_details.endpoint.port =
        static_cast<Port>(response.endpoint().port());
    transport_details.rendezvous_endpoint = candidates[index].endpoint();
    callback(response.nat_type(), transport_details);
  }
  if (result != kSuccess) {
    if (index + 1 < candidates.size()) {
      DoNatDetection(candidates, transport, message_handler, request, full,
                     callback, index + 1);
    } else {
      callback(kError, transport_details);
    }
  }
}

void NatDetectionRpcs::KeepAliveCallback(const TransportCondition &result,
                                         KeepAliveFunctor callback) {
  callback(result);
}

}  // namespace transport

}  // namespace maidsafe
