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

#ifndef MAIDSAFE_RUDP_SERVICE_H_
#define MAIDSAFE_RUDP_SERVICE_H_

#include "boost/date_time/posix_time/posix_time_duration.hpp"

#include "maidsafe/transport/transport_pb.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

typedef bptime::time_duration Timeout;
struct Info;

class Service {
 public:
  void ManagedEndpoint(const protobuf::ManagedEndpointMessage &request,
                       protobuf::ManagedEndpointMessage *response,
                       transport::Timeout *timeout);
  void NatDetection(const protobuf::NatDetectionRequest &request,
                    const Info &info,
                    protobuf::NatDetectionResponse *response,
                    transport::Timeout *timeout);
  void ProxyConnect(const protobuf::ProxyConnectRequest &request,
                    protobuf::ProxyConnectResponse *response,
                    transport::Timeout *timeout);
  void ForwardRendezvous(const protobuf::ForwardRendezvousRequest &request,
                         protobuf::ForwardRendezvousResponse *response,
                         transport::Timeout *timeout);
  void Rendezvous(const protobuf::RendezvousRequest &request);

 private:
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_SERVICE_H_
