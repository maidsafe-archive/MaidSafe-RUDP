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

#ifndef MAIDSAFE_TRANSPORT_NAT_DETECTION_H_
#define MAIDSAFE_TRANSPORT_NAT_DETECTION_H_

#include <vector>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/transport/contact.h"

#if MAIDSAFE_TRANSPORT_VERSION != 104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif

namespace maidsafe {

namespace transport {

class NatDetectionRpcs;
class RudpMessageHandler;

class NatDetection {
  typedef std::shared_ptr<RudpMessageHandler> MessageHandlerPtr;
 public:
  NatDetection();
  void Detect(const std::vector<Contact>& contacts,
              const bool &full,
              std::shared_ptr<Transport> transport,
              MessageHandlerPtr message_handler,
              NatType* nat_type,
              Endpoint *rendezvous_endpoint);
 protected:
  std::shared_ptr<NatDetectionRpcs> rpcs_;

 private:
  void DetectCallback(const int &nat_type, const TransportDetails &details,
                      NatType *out_nat_type, TransportPtr,
                      Endpoint *rendezvous_endpoint,
                      boost::condition_variable *cond_var);
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_NAT_DETECTION_H_
