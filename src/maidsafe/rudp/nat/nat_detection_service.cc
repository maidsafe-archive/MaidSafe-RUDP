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

#include <string>

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/transport/transport_pb.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

NatDetectionService::NatDetectionService(
    boost::asio::io_service &asio_service, // NOLINT
    RudpMessageHandlerPtr message_handler,
    RudpTransportPtr listening_transport,
    GetEndpointFunctor get_endpoint_functor)
    : asio_service_(asio_service),
      message_handler_(message_handler),
      listening_transport_(listening_transport),
      get_directly_connected_endpoint_(get_endpoint_functor) {}

NatDetectionService::~NatDetectionService() {}

void NatDetectionService::ConnectToSignals() {
    message_handler_->on_nat_detection_request()->connect(
        RudpMessageHandler::NatDetectionReqSigPtr::element_type::slot_type(
            &NatDetectionService::NatDetection, this, _1, _2, _3, _4).
                track_foreign(shared_from_this()));

    message_handler_->on_proxy_connect_request()->connect(
        RudpMessageHandler::ProxyConnectReqSigPtr::element_type::slot_type(
            &NatDetectionService::ProxyConnect, this, _1, _2, _3, _4).
                track_foreign(shared_from_this()));

    message_handler_->on_rendezvous_request()->connect(
        RudpMessageHandler::RendezvousReqSigPtr::element_type::slot_type(
            &NatDetectionService::Rendezvous, this, _1, _2, _3).
                track_foreign(shared_from_this()));

    message_handler_->on_forward_rendezvous_request()->connect(
        RudpMessageHandler::ForwardRendezvousReqSigPtr::element_type::slot_type(
            &NatDetectionService::ForwardRendezvous, this, _1, _2, _3).
                track_foreign(shared_from_this()));
}

// At rendezvous
void NatDetectionService::NatDetection(
    const Info &info,
    const protobuf::NatDetectionRequest &request,
    protobuf::NatDetectionResponse *nat_detection_response,
    Timeout* timeout) {
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
    Endpoint proxy = GetDirectlyConnectedEndpoint();
    std::string ipstr(proxy.ip.to_string());
    // Waiting for ProxyConnect Callback to return
    boost::condition_variable condition_variable;
    boost::mutex mutex;
    TransportPtr transport(std::make_shared<RudpTransport>(asio_service_));
    bool result(false);
    TransportCondition condition;
    boost::signals2::connection proxy_connect =
        message_handler_->on_proxy_connect_response()->connect(
            std::bind(&NatDetectionService::ProxyConnectResponse, this,
                      kSuccess, proxy, args::_1, proxy, &condition_variable,
                      &condition, &result));
    boost::signals2::connection error =
        message_handler_->on_error()->connect(
            std::bind(&NatDetectionService::ProxyConnectResponse, this,
                      args::_1, args::_2, protobuf::ProxyConnectResponse(),
                      proxy, &condition_variable, &condition, &result));
    transport->on_message_received()->connect(
          OnMessageReceived::element_type::slot_type(
              &RudpMessageHandler::OnMessageReceived, message_handler_.get(),
              _1, _2, _3, _4).track_foreign(message_handler_));
    transport->on_error()->connect(
        OnError::element_type::slot_type(
            &RudpMessageHandler::OnError,
            message_handler_.get(), _1, _2).track_foreign(message_handler_));
    SendProxyConnectRequest(info.endpoint, proxy, false, transport);
    {
      boost::mutex::scoped_lock lock(mutex);
      condition_variable.wait(lock);  // timed wait?
    }
    if (condition != kSuccess) {
      return;  // retry or return?
    }
    if (result) {
      SetNatDetectionResponse(nat_detection_response, info.endpoint,
                              kFullCone);
      *timeout = kDefaultInitialTimeout;
      return;
    }
    // message_handler_->on_proxy_connect_response()->disconnect();
    // Port restricted check
    proxy_connect.disconnect();
    error.disconnect();
    proxy = GetDirectlyConnectedEndpoint();  // new contact
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
  request.mutable_rendezvous()->set_ip(
      listening_transport_->transport_details().endpoint.ip.to_string());
  request.mutable_rendezvous()->set_port(
      listening_transport_->transport_details().endpoint.port);
  std::string message = message_handler_->WrapMessage(request);
  transport->Send(message, proxy, kDefaultInitialTimeout);
}

void NatDetectionService::ProxyConnectResponse(
    const TransportCondition &transport_condition,
    const Endpoint &remote_endpoint,
    const protobuf::ProxyConnectResponse &response,
    const Endpoint &peer,
    boost::condition_variable *condition_variable,
    TransportCondition *condition,
    bool *result) {
  if (remote_endpoint.ip == peer.ip) {  // port?
    *result = response.result();
    *condition = transport_condition;
    condition_variable->notify_one();
  }
}

// At proxy
void NatDetectionService::ProxyConnect(
    const Info& /*info*/,
    const protobuf::ProxyConnectRequest &request,
    protobuf::ProxyConnectResponse *response,
    Timeout*) {
  // validate info ?
  Endpoint endpoint(request.endpoint().ip(),
                    static_cast<uint16_t> (request.endpoint().port()));
  response->set_result(false);
  std::shared_ptr<RudpTransport> transport(
      std::make_shared<RudpTransport>(asio_service_));
  // TODO(Mahmoud): The IP address should be changed.
  Endpoint listening_endpoint(IP::from_string("127.0.0.1"), 0);
  if (!StartListening(transport, &listening_endpoint)) {
    (*listening_transport_->on_error_)(kListenError, listening_endpoint);
    return;
  }
  if (!request.rendezvous_connect()) {  // FullConNatDetection
    int connect_result(kPendingResult);
    boost::condition_variable condition_variable;
    boost::mutex mutex;
    ConnectFunctor callback =
        std::bind(&NatDetectionService::ConnectResult, this, args::_1,
                  &connect_result, &mutex, &condition_variable);
    // message_handler_->on_error()->connect(
    //    std::bind(&NatDetectionService::ConnectResponse, this, rendezvous,
    //              args::_1, args::_2, protobuf::ConnectResponse(), endpoint,
    //              &condition_variable, tc, &result));

    // TODO(Mahmoud): The wait to be removed, if possible
    transport->Connect(endpoint, transport::kDefaultInitialTimeout, callback);
    bool result(true);
    {
      boost::mutex::scoped_lock lock(mutex);
      result = condition_variable.timed_wait(lock, kDefaultInitialTimeout,
          [&connect_result]() { return connect_result != kPendingResult; });  // NOLINT (Fraser)
    }
    response->set_result(result && (connect_result == kSuccess));
    return;
  } else {  // PortRestrictedNatDetection
    Endpoint rendezvous(request.rendezvous().ip(),
        static_cast<uint16_t> (request.rendezvous().port()));
    SendForwardRendezvousRequest(rendezvous, endpoint, transport);
    //  Delay ?
    SendNatDetectionResponse(endpoint, transport);

    // TODO(Mahmoud): transport should be stored to allow incoming connections.
  }
}

bool NatDetectionService::StartListening(RudpTransportPtr transport,
    Endpoint* endpoint) {
  TransportCondition condition(kError);
  size_t max_try(10), attempt(0);
  while (attempt++ < max_try && (condition != kSuccess)) {
    endpoint->port = RandomUint32() % (64000 - 1025) + 1025;
    condition = transport->StartListening(*endpoint);
  }
  return (condition == kSuccess);
}

Endpoint NatDetectionService::GetDirectlyConnectedEndpoint() {
  if (get_directly_connected_endpoint_)
    return get_directly_connected_endpoint_();
  else
    return Endpoint();
}


void NatDetectionService::ConnectResult(const int &in_result,
                                        int *out_result,
                                        boost::mutex *mutex,
                                        boost::condition_variable *condition) {
  boost::mutex::scoped_lock lock(*mutex);
  *out_result = in_result;
  condition->notify_one();
}

// Proxy to Rendezvous
void NatDetectionService::SendForwardRendezvousRequest(
    const Endpoint &rendezvous,
    const Endpoint &originator,
    TransportPtr transport) {
  protobuf::ForwardRendezvousRequest request;
  request.mutable_receiver_endpoint()->set_ip(originator.ip.to_string());
  request.mutable_receiver_endpoint()->set_port(originator.port);
  std::string message(message_handler_->WrapMessage(request));
  transport->Send(message, rendezvous, kDefaultInitialTimeout);
}

// Proxy to originator
void NatDetectionService::SendNatDetectionResponse(const Endpoint &originator,
                                                   TransportPtr transport) {
  protobuf::NatDetectionResponse response;
  SetNatDetectionResponse(&response, originator, kPortRestricted);
  std::string message(message_handler_->WrapMessage(response));
  transport->Send(message, originator, kDefaultInitialTimeout);
}

void NatDetectionService::SetRendezvousRequest(
    protobuf::RendezvousRequest *rendezvous_request,
    const Endpoint &proxy) {
  rendezvous_request->mutable_proxy_endpoint()->set_ip(proxy.ip.to_string());
  rendezvous_request->mutable_proxy_endpoint()->set_port(proxy.port);
}

// At Rendezvous
void NatDetectionService::ForwardRendezvous(
    const Info &info,
    const protobuf::ForwardRendezvousRequest& request,
    protobuf::ForwardRendezvousResponse*) {
  protobuf::RendezvousRequest rendezvous_request;
  SetRendezvousRequest(&rendezvous_request, info.endpoint);

  Endpoint originator(request.receiver_endpoint().ip(),
      static_cast<uint16_t> (request.receiver_endpoint().port()));
  // Need to send from listening transport
  std::string message(message_handler_->WrapMessage(rendezvous_request));
  listening_transport_->Send(message, originator,
                             kDefaultInitialTimeout);
}

//  At originator
void NatDetectionService::Rendezvous(const Info & /*info*/,
                                     const protobuf::RendezvousRequest& request,
                                     protobuf::RendezvousAcknowledgement*) {
  // TODO(Prakash): validate info if request is sent from rendezvous node
  Endpoint proxy(request.proxy_endpoint().ip(),
      static_cast<uint16_t> (request.proxy_endpoint().port()));
  ConnectFunctor callback =
        std::bind(&NatDetectionService::OriginConnectResult, this, args::_1,
                  proxy);
  listening_transport_->Connect(proxy, transport::kDefaultInitialTimeout,
                                callback);
}

//  At originator
void NatDetectionService::OriginConnectResult(const TransportCondition &result,
                                         const Endpoint &endpoint) {
  if (result != kSuccess) {
    (*listening_transport_->on_error_)(result, endpoint);
  }
}

}  // namespace transport

}  // namespace maidsafe
