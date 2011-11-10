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

#include "maidsafe/transport/nat_detection_service.h"

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/message_handler.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

NatDetectionService::NatDetectionService(AsioService &asio_service, // NOLINT
                                         MessageHandlerPtr message_handler)
    : asio_service_(asio_service),
      message_handler_(message_handler) {
}

void NatDetectionService::ConnectToSignals() {
    message_handler_->on_nat_detection_request()->connect(
        MessageHandler::NatDetectionReqSigPtr::element_type::slot_type(
            &NatDetectionService::NatDetection, this, _1, _2, _3, _4, _5).
                track_foreign(shared_from_this()));

    message_handler_->on_proxy_connect_request()->connect(
        MessageHandler::ProxyConnectReqSigPtr::element_type::slot_type(
            &NatDetectionService::ProxyConnect, this, _1, _2, _3, _4).
                track_foreign(shared_from_this()));
}

// At rendezvous
void NatDetectionService::NatDetection(
    const Info &info,
    const protobuf::NatDetectionRequest &request,
    protobuf::NatDetectionResponse *nat_detection_response,
    protobuf::RendezvousRequest *rendezvous_request,
    transport::Timeout*) {
  if (!request.full_detection()) {  // Partial NAT detection
    if (DirectlyConnected(request, info.endpoint))
      SetNatDetectionResponse(nat_detection_response, info.endpoint,
                              kDirectConnected);
    else
      SetNatDetectionResponse(nat_detection_response, info.endpoint,
                              kNotConnected);
    return;
  } else {  // Full nat detection
    // Directly Connected check
    if (DirectlyConnected(request, info.endpoint)) {
      SetNatDetectionResponse(nat_detection_response, info.endpoint,
                              kDirectConnected);
      return;
    }
    // Full cone NAT type check
    Endpoint proxy /*= get_live_proxy()*/;
    // Waiting for ProxyConnect Callback to return
    boost::condition_variable condition_variable;
    boost::mutex mutex;
    TransportPtr transport(new transport::RudpTransport(asio_service_));
    bool result(false);
    transport::TransportCondition tc;
    message_handler_->on_proxy_connect_response()->connect(
        std::bind(&NatDetectionService::ProxyConnectResponse, this, kSuccess,
                  proxy, arg::_1, proxy, &condition_variable, &tc, &result));
    message_handler_->on_error()->connect(
        std::bind(&NatDetectionService::ProxyConnectResponse, this, arg::_1,
                  arg::_2, protobuf::ProxyConnectResponse(), proxy,
                  &condition_variable, &tc, &result));
    SendProxyConnectRequest(info.endpoint, proxy, false, transport);
    {
      boost::mutex::scoped_lock lock(mutex);
      condition_variable.wait(lock);  // timed wait?
    }
    if (tc != kSuccess) {
      return;  // retry or return?
    }
    if (result) {
      SetNatDetectionResponse(nat_detection_response, info.endpoint,
                              kFullCone);
      return;
    }
    // message_handler_->on_proxy_connect_response()->disconnect();
    // Port restricted check
    proxy /* = get_live_proxy()*/;  // New contact
    SetRendezvousRequest(info.endpoint, proxy, rendezvous_request);
    SendProxyConnectRequest(info.endpoint, proxy, true, transport);
  }
}

bool NatDetectionService::DirectlyConnected(
    const protobuf::NatDetectionRequest &request,
    const Endpoint &endpoint) {
  for (int i = 0; i < request.local_ips_size(); ++i)
    if (endpoint.ip.to_string() == request.local_ips(i))
      return true;
  return false;
}

void NatDetectionService::SetNatDetectionResponse(
    protobuf::NatDetectionResponse *nat_detection_response,
    const Endpoint &endpoint, const NatType &nat_type) {
  nat_detection_response->mutable_endpoint()->set_ip(endpoint.ip.to_string());
  nat_detection_response->mutable_endpoint()->set_port(endpoint.port);
  nat_detection_response->set_nat_type(nat_type);
}

// Rendezvous to proxy
void NatDetectionService::SendProxyConnectRequest(const Endpoint &originator,
                                                  const Endpoint &proxy,
                                                  const bool &rendezvous,
                                                  TransportPtr transport) {
  protobuf::ProxyConnectRequest request;
  request.set_rendezvous_connect(rendezvous);
  request.mutable_endpoint()->set_ip(originator.ip.to_string());
  request.mutable_endpoint()->set_port(originator.port);
  std::string message = message_handler_->WrapMessage(request);
  transport->Send(message, proxy, transport::kDefaultInitialTimeout);
}

void NatDetectionService::ProxyConnectResponse(
    const transport::TransportCondition &transport_condition,
    const Endpoint &remote_endpoint,
    const protobuf::ProxyConnectResponse &response,
    const Endpoint &peer,
    boost::condition_variable *condition_variable,
    transport::TransportCondition *tc,
    bool *result) {
  if (remote_endpoint.ip == peer.ip) {  // port?
    *result = response.result();
    *tc = transport_condition;
    condition_variable->notify_one();
  }
}

// At proxy
void NatDetectionService::ProxyConnect(
    const Info &/*info*/,
    const protobuf::ProxyConnectRequest &request,
    protobuf::ProxyConnectResponse *response,
    transport::Timeout*) {
  // validate info ?
  transport::TransportCondition tc;
  Endpoint endpoint(request.endpoint().ip(),
                    static_cast<uint16_t> (request.endpoint().port()));
  response->set_result(false);
  TransportPtr transport(new transport::RudpTransport(asio_service_));
  bool rendezvous(false), result(false);
  boost::condition_variable condition_variable;
  boost::mutex mutex;
  if (!request.rendezvous_connect()) {  // FullConNatDetection
    message_handler_->on_connect_response()->connect(
        std::bind(&NatDetectionService::ConnectResponse, this, rendezvous,
                  kSuccess, endpoint, arg::_1, endpoint, &condition_variable,
                  &tc, &result));
    message_handler_->on_error()->connect(
        std::bind(&NatDetectionService::ConnectResponse, this, rendezvous,
                  arg::_1, arg::_2, protobuf::ConnectResponse(), endpoint,
                  &condition_variable, &tc, &result));
    SendConnectRequest(endpoint, rendezvous, transport);
    {
      boost::mutex::scoped_lock lock(mutex);
      condition_variable.wait(lock);
    }
    if (tc == kSuccess && result) {
      response->set_result(true);
    } else {
      response->set_result(false);
    }
    return;
  } else {  // PortRestrictedNatDetection
    rendezvous = false;
    SendConnectRequest(endpoint, rendezvous, transport);
    // retry?
  }
}

// TODO(Prakash) : finalise
// Proxy to originator
void NatDetectionService::SendConnectRequest(const Endpoint &endpoint,
                                             const bool &rendezvous,
                                             TransportPtr transport) {
  protobuf::ConnectRequest request;
  request.set_rendezvous(rendezvous);
  std::string message(message_handler_->WrapMessage(request));
  transport->Send(message, endpoint, transport::kDefaultInitialTimeout);
}

void NatDetectionService::ConnectResponse(
    const bool rendezvous,
    const transport::TransportCondition &transport_condition,
    const Endpoint &remote_endpoint,
    const protobuf::ConnectResponse &response,
    const Endpoint &peer,
    boost::condition_variable *condition_variable,
    transport::TransportCondition *tc,
    bool* result) {
  if (remote_endpoint.ip == peer.ip) {
    if (response.IsInitialized() && response.rendezvous() == rendezvous) {
      *result = response.rendezvous();
      *tc = transport_condition;
      if (response.rendezvous() == false)  // notify only on non-rendezvous
        condition_variable->notify_one();
    }
  }
}

void NatDetectionService::SetRendezvousRequest(
    const Endpoint &originator,
    const Endpoint &proxy,
    protobuf::RendezvousRequest *rendezvous_request) {
  rendezvous_request->mutable_originator_endpoint()->set_ip(
      originator.ip.to_string());
  rendezvous_request->mutable_originator_endpoint()->set_port(originator.port);
  rendezvous_request->mutable_proxy_endpoint()->set_ip(proxy.ip.to_string());
  rendezvous_request->mutable_proxy_endpoint()->set_port(proxy.port);
}

void NatDetectionService::ForwardRendezvous(
    const protobuf::ForwardRendezvousRequest&,
    protobuf::ForwardRendezvousResponse*,
    transport::Timeout*) {}

}  // namespace transport

}  // namespace maidsafe
