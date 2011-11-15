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

#ifndef MAIDSAFE_TRANSPORT_NAT_DETECTION_SERVICE_H_
#define MAIDSAFE_TRANSPORT_NAT_DETECTION_SERVICE_H_

#include <memory>
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/condition_variable.hpp"
#include "maidsafe/transport/transport.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

typedef boost::asio::io_service AsioService;
typedef std::shared_ptr<MessageHandler> MessageHandlerPtr;
typedef std::shared_ptr<transport::Transport> TransportPtr;


typedef bptime::time_duration Timeout;
struct Info;

class NatDetectionService : public std::enable_shared_from_this<NatDetectionService> { // NOLINT
 public:
  NatDetectionService(AsioService &asio_service, // NOLINT
                      MessageHandlerPtr message_handler);
  void ConnectToSignals();
  // At rendezvous
  void NatDetection(const Info &info,
                    const protobuf::NatDetectionRequest &request,
                    protobuf::NatDetectionResponse *nat_detection_response,
                    transport::Timeout *timeout);

  void ForwardRendezvous(const Info & info,
                         const protobuf::ForwardRendezvousRequest &request,
                         protobuf::ForwardRendezvousResponse *response);

  void ProxyConnectResponse(
      const transport::TransportCondition &transport_condition,
      const Endpoint &remote_endpoint,
      const protobuf::ProxyConnectResponse &response,
      const Endpoint &peer,
      boost::condition_variable *condition_variable,
      transport::TransportCondition *tc,
      bool *result);
  // At proxy
  void ProxyConnect(const Info &info,
                    const protobuf::ProxyConnectRequest &request,
                    protobuf::ProxyConnectResponse *response,
                    transport::Timeout *timeout);
  // At originator
  void Rendezvous(const Info & info, const protobuf::RendezvousRequest& request,
                  protobuf::RendezvousAcknowledgement*);

  void ConnectResponse(const bool rendezvous,
                       const transport::TransportCondition &transport_condition,
                       const Endpoint &remote_endpoint,
                       const protobuf::ConnectResponse &response,
                       const Endpoint &peer,
                       boost::condition_variable *condition_variable,
                       transport::TransportCondition *tc,
                       bool* result);
 private:
  /** Copy Constructor.
   *  @param NatDetectionService The object to be copied. */
  NatDetectionService(const NatDetectionService&);
  /** Assignment overload */
  NatDetectionService& operator = (const Service&);

  void SetNatDetectionResponse(
      protobuf::NatDetectionResponse *nat_detection_response,
     const Endpoint &endpoint, const NatType &nat_type);

  void SetRendezvousRequest(protobuf::RendezvousRequest *rendezvous_request,
                            const Endpoint &proxy);

  bool DirectlyConnected(const protobuf::NatDetectionRequest &request,
                         const Endpoint &endpoint);
  // Proxy to Rendezvous
  void SendForwardRendezvousRequest(const Endpoint &rendezvous,
                                    const Endpoint &originator,
                                    TransportPtr transport);
  // Proxy to originator
  void SendNatDetectionResponse(const Endpoint &originator,
                                TransportPtr transport);
  // Rendezvous to proxy
  void SendProxyConnectRequest(const Endpoint &originator,
                               const Endpoint &proxy,
                               const bool &rendezvous,
                               TransportPtr transport);
  // Proxy to originator
  void SendConnectRequest(const Endpoint &endpoint, const bool &rendezvous,
                          TransportPtr transport);

  AsioService &asio_service_;
  MessageHandlerPtr message_handler_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_NAT_DETECTION_SERVICE_H_
