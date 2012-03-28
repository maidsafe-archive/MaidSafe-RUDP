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

#include "boost/asio/io_service.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/condition_variable.hpp"

#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/transport_pb.h"
#include "maidsafe/transport/rudp_message_handler.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

class RudpMessageHandler;
typedef std::function<Endpoint()> GetEndpointFunctor;
typedef std::shared_ptr<Transport> TransportPtr;

typedef bptime::time_duration Timeout;
struct Info;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class NatDetectionService : public std::enable_shared_from_this<NatDetectionService> { // NOLINT
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

 public:
  NatDetectionService(boost::asio::io_service &asio_service, // NOLINT
                      RudpMessageHandlerPtr message_handler,
                      RudpTransportPtr listening_transport,
                      GetEndpointFunctor get_endpoint_functor);
  virtual ~NatDetectionService();
  void ConnectToSignals();
  // At rendezvous
  virtual void NatDetection(const Info &info,
                    const protobuf::NatDetectionRequest &request,
                    protobuf::NatDetectionResponse *nat_detection_response,
                    Timeout *timeout);

  void ForwardRendezvous(const Info & info,
                         const protobuf::ForwardRendezvousRequest &request,
                         protobuf::ForwardRendezvousResponse *response);

  void ProxyConnectResponse(
      const TransportCondition &transport_condition,
      const Endpoint &remote_endpoint,
      const protobuf::ProxyConnectResponse &response,
      const Endpoint &peer,
      boost::condition_variable *condition_variable,
      TransportCondition *tc,
      bool *result);
  // At proxy
  void ProxyConnect(const Info &info,
                    const protobuf::ProxyConnectRequest &request,
                    protobuf::ProxyConnectResponse *response,
                    Timeout *timeout);
  // At originator
  void Rendezvous(const Info & /*info*/,
                  const protobuf::RendezvousRequest &request,
                  protobuf::RendezvousAcknowledgement*);

  virtual void ConnectResult(const int &in_result,
                             int *out_result,
                             boost::mutex *mutex,
                             boost::condition_variable *condition);

  void OriginConnectResult(const TransportCondition &result,
                           const Endpoint &endpoint);

 protected:
  /** Copy Constructor.
   *  @param NatDetectionService The object to be copied. */
  NatDetectionService(const NatDetectionService&);
  /** Assignment overload */
  NatDetectionService& operator = (const Service&);

  void SetNatDetectionResponse(
      protobuf::NatDetectionResponse *nat_detection_response,
     const Endpoint &endpoint,
     const NatType &nat_type);

  void SetRendezvousRequest(protobuf::RendezvousRequest *rendezvous_request,
                            const Endpoint &proxy);

  virtual bool DirectlyConnected(const protobuf::NatDetectionRequest &request,
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

  Endpoint GetDirectlyConnectedEndpoint();

  bool StartListening(RudpTransportPtr transport, Endpoint* endpoint);

  boost::asio::io_service &asio_service_;
  std::shared_ptr<RudpMessageHandler> message_handler_;
  RudpTransportPtr listening_transport_;
  GetEndpointFunctor get_directly_connected_endpoint_;
};

typedef std::shared_ptr<NatDetectionService> NatDetectionServicePtr;

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_NAT_DETECTION_SERVICE_H_
