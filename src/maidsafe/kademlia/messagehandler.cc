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

#include "maidsafe/kademlia/messagehandler.h"
#include <boost/lexical_cast.hpp>
#include "maidsafe/kademlia/rpcs.pb.h"

namespace maidsafe {

namespace kademlia {

enum MessageType {
  kPingRequest = transport::kMaxMessageType + 1,
  kPingResponse,
  kFindValueRequest,
  kFindValueResponse,
  kFindNodesRequest,
  kFindNodesResponse,
  kStoreRequest,
  kStoreResponse,
  kDeleteRequest,
  kDeleteResponse,
  kUpdateRequest,
  kUpdateResponse,
  kDownlistNotification
};

std::string MessageHandler::WrapMessage(const protobuf::PingRequest &msg) {
  return MakeSerialisedWrapperMessage(kPingRequest, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::PingResponse &msg) {
  return MakeSerialisedWrapperMessage(kPingResponse, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::FindValueRequest &msg) {
  return MakeSerialisedWrapperMessage(kFindValueRequest,
                                      msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(
    const protobuf::FindValueResponse &msg) {
  return MakeSerialisedWrapperMessage(kFindValueResponse,
                                      msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::FindNodesRequest &msg) {
  return MakeSerialisedWrapperMessage(kFindNodesRequest,
                                      msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(
    const protobuf::FindNodesResponse &msg) {
  return MakeSerialisedWrapperMessage(kFindNodesResponse,
                                      msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::StoreRequest &msg) {
  return MakeSerialisedWrapperMessage(kStoreRequest, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::StoreResponse &msg) {
  return MakeSerialisedWrapperMessage(kStoreResponse, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::DeleteRequest &msg) {
  return MakeSerialisedWrapperMessage(kDeleteRequest, msg.SerializeAsString(),
                                      kSign | kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::DeleteResponse &msg) {
  return MakeSerialisedWrapperMessage(kDeleteResponse, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::UpdateRequest &msg) {
  return MakeSerialisedWrapperMessage(kUpdateRequest, msg.SerializeAsString(),
                                      kSign | kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(const protobuf::UpdateResponse &msg) {
  return MakeSerialisedWrapperMessage(kUpdateResponse, msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

std::string MessageHandler::WrapMessage(
    const protobuf::DownlistNotification &msg) {
  return MakeSerialisedWrapperMessage(kDownlistNotification,
                                      msg.SerializeAsString(),
                                      kAsymmetricEncrypt);
}

void MessageHandler::ProcessSerialisedMessage(
    const int &message_type,
    const std::string &payload,
    const std::string &message_signature,
    const transport::Info &info,
    bool asymmetrical_encrypted,
    std::string *message_response,
    transport::Timeout* timeout) {
  message_response->clear();
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
    case kPingRequest: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::PingRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::PingResponse response;
        (*on_ping_request_)(info, request, &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kPingResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::PingResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_ping_response_)(info, response);
      break;
    }
    case kFindValueRequest: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::FindValueRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::FindValueResponse response;
        (*on_find_value_request_)(info, request, &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kFindValueResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::FindValueResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_find_value_response_)(info, response);
      break;
    }
    case kFindNodesRequest: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::FindNodesRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::FindNodesResponse response;
        (*on_find_nodes_request_)(info, request, &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kFindNodesResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::FindNodesResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_find_nodes_response_)(info, response);
      break;
    }
    case kStoreRequest: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::StoreRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        protobuf::StoreResponse response;
        (*on_store_request_)(info, request, &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kStoreResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::StoreResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_store_response_)(info, response);
      break;
    }
    case kDeleteRequest: {
      if (!asymmetrical_encrypted || message_signature.empty())
        return;
      protobuf::DeleteRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        std::string message =
           boost::lexical_cast<std::string>(message_type) + payload;
        protobuf::DeleteResponse response;
        (*on_delete_request_)(info, request, message, message_signature,
                              &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kDeleteResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::DeleteResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_delete_response_)(info, response);
      break;
    }
    case kUpdateRequest: {
      if (!asymmetrical_encrypted || message_signature.empty())
        return;
      protobuf::UpdateRequest request;
      if (request.ParseFromString(payload) && request.IsInitialized()) {
        std::string message =
           boost::lexical_cast<std::string>(message_type) + payload;
        protobuf::UpdateResponse response;
        (*on_update_request_)(info, request, message, message_signature,
                              &response);
        *message_response = WrapMessage(response);
      }
      break;
    }
    case kUpdateResponse: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::UpdateResponse response;
      if (response.ParseFromString(payload) && response.IsInitialized())
        (*on_update_response_)(info, response);
      break;
    }
    case kDownlistNotification: {
      if (!asymmetrical_encrypted)
        return;
      protobuf::DownlistNotification request;
      if (request.ParseFromString(payload) && request.IsInitialized())
        (*on_downlist_notification_)(info, request);
      break;
    }
    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type,
          payload, message_signature, info, asymmetrical_encrypted,
          message_response, timeout);
  }
}

}  // namespace kademlia

}  // namespace maidsafe
