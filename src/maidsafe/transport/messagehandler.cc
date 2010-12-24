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

#include "maidsafe/transport/messagehandler.h"
#include "maidsafe/transport/transport.pb.h"

namespace transport {

enum MessageType {
  kManagedEndpointMessage = 1,
  kNatDetectionRequest,
  kNatDetectionResponse,
  kProxyConnectRequest,
  kProxyConnectResponse,
  kForwardRendezvousRequest,
  kForwardRendezvousResponse,
  kRendezvousRequest,
  kRendezvousAcknowledgement
};

void MessageHandler::OnMessageReceived(const std::string &request,
                                       const Info &info,
                                       std::string *response,
                                       Timeout *timeout) {
  protobuf::WrapperMessage wrapper;
  if (!wrapper.ParseFromString(request))
    return;
  if (!wrapper.IsInitialized())
    return;

  (*on_info_)(wrapper.msg_type(), info);
  ProcessSerialisedMessage(wrapper.msg_type(), wrapper.payload(), info,
                           response, timeout);
}

std::string MessageHandler::WrapMessage(
    const protobuf::ManagedEndpointMessage &msg) {
  return MakeSerialisedWrapperMessage(kManagedEndpointMessage,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::NatDetectionRequest &msg) {
  return MakeSerialisedWrapperMessage(kNatDetectionRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::NatDetectionResponse &msg) {
  return MakeSerialisedWrapperMessage(kNatDetectionResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ProxyConnectRequest &msg) {
  return MakeSerialisedWrapperMessage(kProxyConnectRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ProxyConnectResponse &msg) {
  return MakeSerialisedWrapperMessage(kProxyConnectResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ForwardRendezvousRequest &msg) {
  return MakeSerialisedWrapperMessage(kForwardRendezvousRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::ForwardRendezvousResponse &msg) {
  return MakeSerialisedWrapperMessage(kForwardRendezvousResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::RendezvousRequest &msg) {
  return MakeSerialisedWrapperMessage(kRendezvousRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::RendezvousAcknowledgement &msg) {
  return MakeSerialisedWrapperMessage(kRendezvousAcknowledgement,
                                      msg.SerializeAsString());
}

void MessageHandler::ProcessSerialisedMessage(const int &message_type,
                                              const std::string &payload,
                                              const Info&,
                                              std::string *response,
                                              Timeout *timeout) {
  response->clear();
  *timeout = kImmediateTimeout;

  switch (message_type) {
    case kManagedEndpointMessage: {
      protobuf::ManagedEndpointMessage req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::ManagedEndpointMessage rsp;
        (*on_managed_endpoint_message_)(req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = kDefaultInitialTimeout;
      }
      break;
    }
    case kNatDetectionRequest: {
      protobuf::NatDetectionRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
//         NatDetectionReqSigPtr::element_type::result_type
//             (NatDetectionReqSigPtr::element_type::*sig)
//             (NatDetectionReqSigPtr::element_type::arg<0>::type,
//              NatDetectionReqSigPtr::element_type::arg<1>::type) =
//             &NatDetectionReqSigPtr::element_type::operator();
//         asio_service_->post(boost::bind(sig, on_nat_detection_, req,
//                                         conversation_id));
        protobuf::NatDetectionResponse rsp;
        (*on_nat_detection_request_)(req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = kDefaultInitialTimeout;
      }
      break;
    }
    case kNatDetectionResponse: {
      protobuf::NatDetectionResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_nat_detection_response_)(req);
      break;
    }
    case kProxyConnectRequest: {
      protobuf::ProxyConnectRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::ProxyConnectResponse rsp;
        (*on_proxy_connect_request_)(req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = kDefaultInitialTimeout;
      }
      break;
    }
    case kProxyConnectResponse: {
      protobuf::ProxyConnectResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_proxy_connect_response_)(req);
      break;
    }
    case kForwardRendezvousRequest: {
      protobuf::ForwardRendezvousRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::ForwardRendezvousResponse rsp;
        (*on_forward_rendezvous_request_)(req, &rsp);
        if (!(*response = WrapMessage(rsp)).empty())
          *timeout = kDefaultInitialTimeout;
      }
      break;
    }
    case kForwardRendezvousResponse: {
      protobuf::ForwardRendezvousResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_forward_rendezvous_response_)(req);
      break;
    }
    case kRendezvousRequest: {
      protobuf::RendezvousRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_rendezvous_request_)(req);
      break;
    }
    case kRendezvousAcknowledgement: {
      protobuf::RendezvousAcknowledgement req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_rendezvous_acknowledgement_)(req);
      break;
    }
  }
}

std::string MessageHandler::MakeSerialisedWrapperMessage(
    const int& message_type,
    const std::string& payload) {
  protobuf::WrapperMessage msg;
  msg.set_msg_type(message_type);
  msg.set_payload(payload);
  return msg.SerializeAsString();
}

}  // namespace transport
