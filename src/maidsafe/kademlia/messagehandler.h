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

#ifndef MAIDSAFE_KADEMLIA_MESSAGEHANDLER_H_
#define MAIDSAFE_KADEMLIA_MESSAGEHANDLER_H_

#include <boost/shared_ptr.hpp>
#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>

#include "maidsafe/transport/messagehandler.h"
#include "maidsafe/kademlia/rpcs.pb.h"

namespace bs2 = boost::signals2;

namespace kademlia {

typedef transport::MessageHandlerCondition MessageHandlerCondition;

class MessageHandler : public transport::MessageHandler {
 public:
  const int kMessageTypeExt = transport::MessageHandler::kMessageTypeExt + 14;
  typedef boost::function<void(protobuf::PingResponse)> PingRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::PingRequest,
      transport::ConversationId)> > PingReqSigPtr;
  typedef boost::function<void(protobuf::FindValueResponse)> FindValueRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::FindValueRequest,
      transport::ConversationId)> > FindValueReqSigPtr;
  typedef boost::function<void(protobuf::FindNodesResponse)> FindNodesRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::FindNodesRequest,
      transport::ConversationId)> > FindNodesReqSigPtr;
  typedef boost::function<void(protobuf::StoreResponse)> StoreRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::StoreRequest,
      transport::ConversationId)> > StoreReqSigPtr;
  typedef boost::function<void(protobuf::DeleteResponse)> DeleteRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::DeleteRequest,
      transport::ConversationId)> > DeleteReqSigPtr;
  typedef boost::function<void(protobuf::UpdateResponse)> UpdateRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::UpdateRequest,
      transport::ConversationId)> > UpdateReqSigPtr;
  typedef boost::function<void(protobuf::DownlistResponse)> DownlistRspFunc;
  typedef boost::shared_ptr<bs2::signal<void(protobuf::DownlistRequest,
      transport::ConversationId)> > DownlistReqSigPtr;
   
  MessageHandler()
    : on_ping_(),
      on_find_value_(),
      on_find_nodes_(),
      on_store_(),
      on_delete_(),
      on_update_(),
      on_downlist_() {}
  virtual ~MessageHandler() {}

  MessageHandlerCondition RequestPing(
      const protobuf::PingRequest &request,
      const transport::Endpoint &recipient,
      PingRspFunc response_cb);
  MessageHandlerCondition RespondToPing(
      const protobuf::PingResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestFindValue(
      const protobuf::FindValueRequest &request,
      const transport::Endpoint &recipient,
      FindValueRspFunc response_cb);
  MessageHandlerCondition RespondToFindValue(
      const protobuf::FindValueResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestFindNodes(
      const protobuf::FindNodesRequest &request,
      const transport::Endpoint &recipient,
      FindNodesRspFunc response_cb);
  MessageHandlerCondition RespondToFindNodes(
      const protobuf::FindNodesResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestStore(
      const protobuf::StoreRequest &request,
      const transport::Endpoint &recipient,
      StoreRspFunc response_cb);
  MessageHandlerCondition RespondToStore(
      const protobuf::StoreResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestDelete(
      const protobuf::DeleteRequest &request,
      const transport::Endpoint &recipient,
      DeleteRspFunc response_cb);
  MessageHandlerCondition RespondToDelete(
      const protobuf::DeleteResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestUpdate(
      const protobuf::UpdateRequest &request,
      const transport::Endpoint &recipient,
      UpdateRspFunc response_cb);
  MessageHandlerCondition RespondToUpdate(
      const protobuf::UpdateResponse &response,
      const transport::ConversationId &conversation_id);

  MessageHandlerCondition RequestDownlist(
      const protobuf::DownlistRequest &request,
      const transport::Endpoint &recipient,
      DownlistRspFunc response_cb);
  MessageHandlerCondition RespondToDownlist(
      const protobuf::DownlistResponse &response,
      const transport::ConversationId &conversation_id);
  
  PingReqSigPtr on_ping() { return on_ping_; }
  FindValueReqSigPtr on_find_value() { return on_find_value_; }
  FindNodesReqSigPtr on_find_nodes() { return on_find_nodes_; }
  StoreReqSigPtr on_store() { return on_store_; }
  DeleteReqSigPtr on_delete() { return on_delete_; }
  UpdateReqSigPtr on_update() { return on_update_; }
  DownlistReqSigPtr on_downlist() { return on_downlist_; }
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  PingReqSigPtr on_ping_;
  FindValueReqSigPtr on_find_value_;
  FindNodesReqSigPtr on_find_nodes_;
  StoreReqSigPtr on_store_;
  DeleteReqSigPtr on_delete_;
  UpdateReqSigPtr on_update_;
  DownlistReqSigPtr on_downlist_;
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_MESSAGEHANDLER_H_
