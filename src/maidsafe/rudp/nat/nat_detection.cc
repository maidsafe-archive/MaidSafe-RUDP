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

#include "maidsafe/transport/nat_detection.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/message_handler.h"
#include "maidsafe/transport/nat_detection_rpcs.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

NatDetection::NatDetection() : rpcs_(new NatDetectionRpcs()) {}

void NatDetection::Detect(
    const std::vector<maidsafe::transport::Contact>& contacts,
    const bool& full,
    TransportPtr transport,
    MessageHandlerPtr message_handler,
    NatType* nat_type,
    Endpoint *rendezvous_endpoint) {
  boost::mutex mutex;
  boost::condition_variable cond_var;
  std::vector<maidsafe::transport::Contact> directly_connected_contacts;
  for (auto itr = contacts.begin(); itr != contacts.end(); ++itr)
    if ((*itr).IsDirectlyConnected())
      directly_connected_contacts.push_back(*itr);
  boost::mutex::scoped_lock lock(mutex);
  rpcs_->NatDetection(directly_connected_contacts, transport, message_handler,
                      full, std::bind(&NatDetection::DetectCallback, this,
                                      args::_1, args::_2, nat_type, transport,
                                      rendezvous_endpoint, &cond_var));
  cond_var.timed_wait(lock, kDefaultInitialTimeout);
}

void NatDetection::DetectCallback(const int &nat_type,
                                  const TransportDetails &details,
                                  NatType *out_nat_type,
                                  TransportPtr transport,
                                  Endpoint *rendezvous_endpoint,
                                  boost::condition_variable *cond_var) {
  if (nat_type >= 0) {
    *out_nat_type = static_cast<NatType>(nat_type);
    transport->transport_details_.endpoint = details.endpoint;
    *rendezvous_endpoint = details.rendezvous_endpoint;
    if (nat_type == transport::kPortRestricted)
      transport->transport_details_.rendezvous_endpoint =
          details.rendezvous_endpoint;
    cond_var->notify_one();
  }
}

}  // namespace transport

}  // namespace maidsafe
