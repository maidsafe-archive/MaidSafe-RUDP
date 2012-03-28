/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

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
