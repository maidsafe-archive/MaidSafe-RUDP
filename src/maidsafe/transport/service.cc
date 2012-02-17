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

#include "maidsafe/transport/service.h"

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transport_pb.h"

namespace maidsafe {

namespace transport {

void Service::ManagedEndpoint(const protobuf::ManagedEndpointMessage&,
                              protobuf::ManagedEndpointMessage*,
                              transport::Timeout*) {}

void Service::NatDetection(const protobuf::NatDetectionRequest &request,
                           const Info &info,
                           protobuf::NatDetectionResponse *response,
                           transport::Timeout*) {
  if (!request.full_detection()) {
    protobuf::Endpoint *ep = response->mutable_endpoint();
    ep->set_ip(info.endpoint.ip.to_string());
    ep->set_port(info.endpoint.port);
    response->set_nat_type(5);
    for (int n = 0; n < request.local_ips_size(); ++n) {
      if (ep->ip() == request.local_ips(n)) {
        response->set_nat_type(0);
        n = request.local_ips_size();
      }
    }
  } else {
    // TODO(Team): Implement full nat detection.
  }
}

void Service::ProxyConnect(const protobuf::ProxyConnectRequest&,
                           protobuf::ProxyConnectResponse*,
                           transport::Timeout*) {}

void Service::ForwardRendezvous(
    const protobuf::ForwardRendezvousRequest&,
    protobuf::ForwardRendezvousResponse*,
    transport::Timeout*) {}

void Service::Rendezvous(const protobuf::RendezvousRequest &) {}

}  // namespace transport

}  // namespace maidsafe
