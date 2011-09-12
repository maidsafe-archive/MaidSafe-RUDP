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

#ifndef MAIDSAFE_DHT_KADEMLIA_MESSAGE_HANDLER_H_
#define MAIDSAFE_DHT_KADEMLIA_MESSAGE_HANDLER_H_

#include <memory>
#include <string>
#include "boost/concept_check.hpp"
#include "boost/signals2/signal.hpp"
#include "maidsafe/dht/transport/message_handler.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace bs2 = boost::signals2;

namespace maidsafe {

namespace dht {

class Securifier;

namespace kademlia {

namespace protobuf {
class PingRequest;
class PingResponse;
class FindValueRequest;
class FindValueResponse;
class FindNodesRequest;
class FindNodesResponse;
class StoreRequest;
class StoreResponse;
class StoreRefreshRequest;
class StoreRefreshResponse;
class DeleteRequest;
class DeleteResponse;
class DeleteRefreshRequest;
class DeleteRefreshResponse;
class UpdateRequest;
class UpdateResponse;
class DownlistNotification;
}  // namespace protobuf

namespace test {
class KademliaMessageHandlerTest_BEH_WrapMessagePingResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageFindValueResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageFindNodesResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageStoreResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageStoreRefreshResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageDeleteResponse_Test;
class KademliaMessageHandlerTest_BEH_WrapMessageDeleteRefreshResponse_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRefRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRefRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRefRqst_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRefRsp_Test;
class KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDownlist_Test;
class KademliaMessageHandlerTest;
}  // namespace test

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(transport::kMaxMessageType + 1000);

enum MessageType {
  kPingRequest = transport::kMaxMessageType + 1,
  kPingResponse,
  kFindValueRequest,
  kFindValueResponse,
  kFindNodesRequest,
  kFindNodesResponse,
  kStoreRequest,
  kStoreResponse,
  kStoreRefreshRequest,
  kStoreRefreshResponse,
  kDeleteRequest,
  kDeleteResponse,
  kDeleteRefreshRequest,
  kDeleteRefreshResponse,
  kDownlistNotification
};

class MessageHandler : public transport::MessageHandler {
 public:
  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::PingRequest&,
           protobuf::PingResponse*,
           transport::Timeout*)>> PingReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::PingResponse&)>> PingRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindValueRequest&,
           protobuf::FindValueResponse*,
           transport::Timeout*)>> FindValueReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindValueResponse&)>> FindValueRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindNodesRequest&,
           protobuf::FindNodesResponse*,
           transport::Timeout*)>> FindNodesReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::FindNodesResponse&)>> FindNodesRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::StoreRequest&,
           const std::string&,
           const std::string&,
           protobuf::StoreResponse*,
           transport::Timeout*)>> StoreReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::StoreResponse&)>> StoreRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::StoreRefreshRequest&,
           protobuf::StoreRefreshResponse*,
           transport::Timeout*)>> StoreRefreshReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::StoreRefreshResponse&)>> StoreRefreshRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::DeleteRequest&,
           const std::string&,
           const std::string&,
           protobuf::DeleteResponse*,
           transport::Timeout*)>> DeleteReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::DeleteResponse&)>> DeleteRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::DeleteRefreshRequest&,
           protobuf::DeleteRefreshResponse*,
           transport::Timeout*)>> DeleteRefreshReqSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::DeleteRefreshResponse&)>> DeleteRefreshRspSigPtr;

  typedef std::shared_ptr<bs2::signal<  // NOLINT
      void(const transport::Info&,
           const protobuf::DownlistNotification&,
           transport::Timeout*)>> DownlistNtfSigPtr;

  explicit MessageHandler(std::shared_ptr<Securifier> securifier)
    : transport::MessageHandler(securifier),
      on_ping_request_(new PingReqSigPtr::element_type),
      on_ping_response_(new PingRspSigPtr::element_type),
      on_find_value_request_(new FindValueReqSigPtr::element_type),
      on_find_value_response_(new FindValueRspSigPtr::element_type),
      on_find_nodes_request_(new FindNodesReqSigPtr::element_type),
      on_find_nodes_response_(new FindNodesRspSigPtr::element_type),
      on_store_request_(new StoreReqSigPtr::element_type),
      on_store_response_(new StoreRspSigPtr::element_type),
      on_store_refresh_request_(new StoreRefreshReqSigPtr::element_type),
      on_store_refresh_response_(new StoreRefreshRspSigPtr::element_type),
      on_delete_request_(new DeleteReqSigPtr::element_type),
      on_delete_response_(new DeleteRspSigPtr::element_type),
      on_delete_refresh_request_(new DeleteRefreshReqSigPtr::element_type),
      on_delete_refresh_response_(new DeleteRefreshRspSigPtr::element_type),
      on_downlist_notification_(new DownlistNtfSigPtr::element_type) {}
  virtual ~MessageHandler() {}

  std::string WrapMessage(const protobuf::PingRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::FindValueRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::FindNodesRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::StoreRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::StoreRefreshRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::DeleteRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::DeleteRefreshRequest &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::DownlistNotification &msg,
                          const std::string &recipient_public_key);

  PingReqSigPtr on_ping_request() { return on_ping_request_; }
  PingRspSigPtr on_ping_response() { return on_ping_response_; }
  FindValueReqSigPtr on_find_value_request() { return on_find_value_request_; }
  FindValueRspSigPtr on_find_value_response() {
    return on_find_value_response_;
  }
  FindNodesReqSigPtr on_find_nodes_request() { return on_find_nodes_request_; }
  FindNodesRspSigPtr on_find_nodes_response() {
    return on_find_nodes_response_;
  }
  StoreReqSigPtr on_store_request() { return on_store_request_; }
  StoreRspSigPtr on_store_response() { return on_store_response_; }
  StoreRefreshReqSigPtr on_store_refresh_request() {
    return on_store_refresh_request_;
  }
  StoreRefreshRspSigPtr on_store_refresh_response() {
    return on_store_refresh_response_;
  }
  DeleteReqSigPtr on_delete_request() { return on_delete_request_; }
  DeleteRspSigPtr on_delete_response() { return on_delete_response_; }
  DeleteRefreshReqSigPtr on_delete_refresh_request() {
    return on_delete_refresh_request_;
  }
  DeleteRefreshRspSigPtr on_delete_refresh_response() {
    return on_delete_refresh_response_;
  }
  DownlistNtfSigPtr on_downlist_notification() {
    return on_downlist_notification_;
  }

 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const SecurityType &security_type,
                                        const std::string &message_signature,
                                        const transport::Info &info,
                                        std::string *message_response,
                                        transport::Timeout *timeout);

 private:
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessagePingResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageFindValueResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageFindNodesResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageStoreResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageStoreRefreshResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageDeleteResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_WrapMessageDeleteRefreshResponse_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessagePingRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFValRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageFNodeRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRefRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageStoreRefRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRefRqst_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDeleteRefRsp_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest_BEH_ProcessSerialisedMessageDownlist_Test;  // NOLINT
  friend class test::KademliaMessageHandlerTest;

  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  std::string WrapMessage(const protobuf::PingResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::FindValueResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::FindNodesResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::StoreResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::StoreRefreshResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::DeleteResponse &msg,
                          const std::string &recipient_public_key);
  std::string WrapMessage(const protobuf::DeleteRefreshResponse &msg,
                          const std::string &recipient_public_key);

  PingReqSigPtr on_ping_request_;
  PingRspSigPtr on_ping_response_;
  FindValueReqSigPtr on_find_value_request_;
  FindValueRspSigPtr on_find_value_response_;
  FindNodesReqSigPtr on_find_nodes_request_;
  FindNodesRspSigPtr on_find_nodes_response_;
  StoreReqSigPtr on_store_request_;
  StoreRspSigPtr on_store_response_;
  StoreRefreshReqSigPtr on_store_refresh_request_;
  StoreRefreshRspSigPtr on_store_refresh_response_;
  DeleteReqSigPtr on_delete_request_;
  DeleteRspSigPtr on_delete_response_;
  DeleteRefreshReqSigPtr on_delete_refresh_request_;
  DeleteRefreshRspSigPtr on_delete_refresh_response_;
  DownlistNtfSigPtr on_downlist_notification_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_MESSAGE_HANDLER_H_
