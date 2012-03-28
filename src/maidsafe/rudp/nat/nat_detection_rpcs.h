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

#ifndef MAIDSAFE_TRANSPORT_NAT_DETECTION_RPCS_H_
#define MAIDSAFE_TRANSPORT_NAT_DETECTION_RPCS_H_

#include <vector>
#include <string>

#include "boost/function.hpp"

#include "maidsafe/transport/transport_pb.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class Transport;
struct Endpoint;
struct TransportDetails;
class Contact;

class NatDetectionRpcs {
  typedef std::function<void(const int&, const TransportDetails&)>
      NatResultFunctor;
  typedef std::function<void(const TransportCondition&)> KeepAliveFunctor;
  typedef std::shared_ptr<RudpMessageHandler> MessageHandlerPtr;

 public:
  void NatDetection(const std::vector<Contact> &candidates,
                    const bool &full,
                    NatResultFunctor nrf);
  void NatDetection(const std::vector<Contact> &candidates,
                    TransportPtr transport,
                    MessageHandlerPtr message_handler,
                    const bool &full,
                    NatResultFunctor callback);
  void KeepAlive(const Endpoint endpoint, const Timeout &timeout,
                 TransportPtr transport, MessageHandlerPtr message_handler,
                 KeepAliveFunctor callback);

 private:
  void DoNatDetection(const std::vector<Contact> &candidates,
                      TransportPtr transport,
                      MessageHandlerPtr message_handler,
                      const std::string &request,
                      const bool &full,
                      NatResultFunctor callback,
                      const size_t &index);
  void NatDetectionCallback(const TransportCondition &result,
                            const protobuf::NatDetectionResponse &response,
                            const std::vector<Contact> &candidates,
                            NatResultFunctor callback,
                            TransportPtr transport,
                            MessageHandlerPtr message_handler,
                            const std::string &request,
                            const bool &full,
                            const size_t &index);
  void KeepAliveCallback(const TransportCondition &result,
                         KeepAliveFunctor callback);
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_NAT_DETECTION_RPCS_H_
