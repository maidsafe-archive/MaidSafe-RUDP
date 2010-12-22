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

namespace kademlia {

enum MessageType {
  kPingRequest = transport::MessageType::kMaxValue + 1,
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
  kDownlistRequest,
  kDownlistResponse,
  kMaxValue = transport::MessageType::kMaxValue + 1000
};

std::string MessageHandler::WrapMessage(const protobuf::PingRequest &msg) {
  return MakeSerialisedWrapperMessage(kPingRequest, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::PingResponse &msg) {
  return MakeSerialisedWrapperMessage(kPingResponse, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::FindValueRequest &msg) {
  return MakeSerialisedWrapperMessage(kFindValueRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::FindValueResponse &msg) {
  return MakeSerialisedWrapperMessage(kFindValueResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::FindNodesRequest &msg) {
  return MakeSerialisedWrapperMessage(kFindNodesRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(
    const protobuf::FindNodesResponse &msg) {
  return MakeSerialisedWrapperMessage(kFindNodesResponse,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::StoreRequest &msg) {
  return MakeSerialisedWrapperMessage(kStoreRequest, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::StoreResponse &msg) {
  return MakeSerialisedWrapperMessage(kStoreResponse, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::DeleteRequest &msg) {
  return MakeSerialisedWrapperMessage(kDeleteRequest, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::DeleteResponse &msg) {
  return MakeSerialisedWrapperMessage(kDeleteResponse, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::UpdateRequest &msg) {
  return MakeSerialisedWrapperMessage(kUpdateRequest, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::UpdateResponse &msg) {
  return MakeSerialisedWrapperMessage(kUpdateResponse, msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::DownlistRequest &msg) {
  return MakeSerialisedWrapperMessage(kDownlistRequest,
                                      msg.SerializeAsString());
}

std::string MessageHandler::WrapMessage(const protobuf::DownlistResponse &msg) {
  return MakeSerialisedWrapperMessage(kDownlistResponse,
                                      msg.SerializeAsString());
}

void MessageHandler::ProcessSerialisedMessage(const int& message_type,
                                              const std::string& payload,
                                              std::string* response,
                                              transport::Timeout* timeout) {
  *response = "";
  *timeout = transport::kImmediateTimeout;

  switch (message_type) {
    case kPingRequest: {
      protobuf::PingRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::PingResponse rsp;
        (*on_ping_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kPingResponse: {
      protobuf::PingResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_ping_response_)(req);
      break;
    }
    case kFindValueRequest: {
      protobuf::FindValueRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::FindValueResponse rsp;
        (*on_find_value_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kFindValueResponse: {
      protobuf::FindValueResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_find_value_response_)(req);
      break;
    }
    case kFindNodesRequest: {
      protobuf::FindNodesRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::FindNodesResponse rsp;
        (*on_find_nodes_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kFindNodesResponse: {
      protobuf::FindNodesResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_find_nodes_response_)(req);
      break;
    }
    case kStoreRequest: {
      protobuf::StoreRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::StoreResponse rsp;
        (*on_store_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kStoreResponse: {
      protobuf::StoreResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_store_response_)(req);
      break;
    }
    case kDeleteRequest: {
      protobuf::DeleteRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::DeleteResponse rsp;
        (*on_delete_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kDeleteResponse: {
      protobuf::DeleteResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_delete_response_)(req);
      break;
    }
    case kUpdateRequest: {
      protobuf::UpdateRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::UpdateResponse rsp;
        (*on_update_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kUpdateResponse: {
      protobuf::UpdateResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_update_response_)(req);
      break;
    }
    case kDownlistRequest: {
      protobuf::DownlistRequest req;
      if (req.ParseFromString(payload) && req.IsInitialized()) {
        protobuf::DownlistResponse rsp;
        (*on_downlist_request_)(req, &rsp);
        if ((*response = WrapMessage(rsp)) != "")
          *timeout = transport::kDefaultInitialTimeout;
      }
      break;
    }
    case kDownlistResponse: {
      protobuf::DownlistResponse req;
      if (req.ParseFromString(payload) && req.IsInitialized())
        (*on_downlist_response_)(req);
      break;
    }
    default:
      transport::MessageHandler::ProcessSerialisedMessage(message_type, payload,
                                                          response, timeout);
  }
}


}  // namespace kademlia
