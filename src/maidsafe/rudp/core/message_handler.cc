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

#include "maidsafe/transport/rudp_message_handler.h"
#include "boost/lexical_cast.hpp"

#include "maidsafe/transport/transport_pb.h"
#include "maidsafe/transport/log.h"


namespace maidsafe {

namespace transport {

//  void RudpMessageHandler::OnMessageReceived(const std::string &request,
//                                         const Info &info,
//                                         std::string *response,
//                                         Timeout *timeout) {
//    if (request.empty())
//      return;
//    SecurityType security_type = request.at(0);
//    std::string serialised_message(request.substr(1));
//    protobuf::WrapperMessage wrapper;
//    if (wrapper.ParseFromString(serialised_message) &&
//        wrapper.IsInitialized()) {
//      ProcessSerialisedMessage(wrapper.msg_type(), wrapper.payload(),
//                               security_type, wrapper.message_signature(),
//                               info, response, timeout);
//    }
//  }

std::string RudpMessageHandler::WrapMessage(
    const protobuf::ManagedEndpointMessage &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kManagedEndpointMessage,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::NatDetectionRequest &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kNatDetectionRequest,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::NatDetectionResponse &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kNatDetectionResponse,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::ProxyConnectRequest &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kProxyConnectRequest,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::ProxyConnectResponse &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kProxyConnectResponse,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::ForwardRendezvousRequest &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kForwardRendezvousRequest,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::ForwardRendezvousResponse &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kForwardRendezvousResponse,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::RendezvousRequest &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kRendezvousRequest,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::WrapMessage(
    const protobuf::RendezvousAcknowledgement &msg) {
  if (!msg.IsInitialized())
    return "";
  return MakeSerialisedWrapperMessage(kRendezvousAcknowledgement,
                                      msg.SerializeAsString(), kNone,
                                      asymm::PublicKey());
}

std::string RudpMessageHandler::CreateForwardRendezvousRequest(
    const Endpoint &endpoint) {
  protobuf::ForwardRendezvousRequest request;
  request.mutable_receiver_endpoint()->set_ip(endpoint.ip.to_string());
  request.mutable_receiver_endpoint()->set_port(endpoint.port);
  return WrapMessage(request);
}

void RudpMessageHandler::ProcessSerialisedMessage(
    const int &message_type,
    const std::string &payload,
    const SecurityType &security_type,
    const std::string &message_signature,
    const Info & info,
    std::string *message_response,
    Timeout *timeout) {
  message_response->clear();
  *timeout = kImmediateTimeout;

  switch (message_type) {
    case kManagedEndpointMessage: {
      protobuf::ManagedEndpointMessage request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::ManagedEndpointMessage response;
        (*on_managed_endpoint_message_)(request, &response, timeout);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kNatDetectionRequest: {
      protobuf::NatDetectionRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::NatDetectionResponse response;
        (*on_nat_detection_request_)(info, request, &response, timeout);
        if (response.IsInitialized()) {
          *message_response = WrapMessage(response);
        }
      }
      break;
    }
    case kNatDetectionResponse: {
      protobuf::NatDetectionResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_nat_detection_response_)(response);
      break;
    }
    case kProxyConnectRequest: {
      protobuf::ProxyConnectRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::ProxyConnectResponse response;
        (*on_proxy_connect_request_)(info, request, &response, timeout);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kProxyConnectResponse: {
      protobuf::ProxyConnectResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_proxy_connect_response_)(response);
      break;
    }
    case kForwardRendezvousRequest: {
      protobuf::ForwardRendezvousRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::ForwardRendezvousResponse response;
        (*on_forward_rendezvous_request_)(info, request, &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kForwardRendezvousResponse: {
      protobuf::ForwardRendezvousResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_forward_rendezvous_response_)(response);
      break;
    }
    case kRendezvousRequest: {
      protobuf::RendezvousRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::RendezvousAcknowledgement response;
        (*on_rendezvous_request_)(info, request, &response);
      }
      break;
    }
    case kRendezvousAcknowledgement: {
      protobuf::RendezvousAcknowledgement acknowledgement;
      if (acknowledgement.ParseFromString(payload) &&
          acknowledgement.IsInitialized())
        (*on_rendezvous_acknowledgement_)(acknowledgement);
      break;
    }
    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type,
                                                          payload,
                                                          security_type,
                                                          message_signature,
                                                          info,
                                                          message_response,
                                                          timeout);
  }
}

}  // namespace transport

}  // namespace maidsafe
