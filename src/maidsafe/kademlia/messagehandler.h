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

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>

#include "maidsafe/transport/messagehandler.h"
#include "maidsafe/kademlia/rpcs.pb.h"

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace bs2 = boost::signals2;

namespace kademlia {

typedef transport::MessageHandlerCondition MessageHandlerCondition;

enum MessageType {
  kPingRequest = transport::kMessageTypeExt,
  kPingResponse = transport::kMessageTypeExt + 1,
  kFindValueRequest = transport::kMessageTypeExt + 2,
  kFindValueResponse = transport::kMessageTypeExt + 3,
  kFindNodesRequest = transport::kMessageTypeExt + 4,
  kFindNodesResponse = transport::kMessageTypeExt + 5,
  kStoreRequest = transport::kMessageTypeExt + 6,
  kStoreResponse = transport::kMessageTypeExt + 7,
  kDeleteRequest = transport::kMessageTypeExt + 8,
  kDeleteResponse = transport::kMessageTypeExt + 9,
  kUpdateRequest = transport::kMessageTypeExt + 10,
  kUpdateResponse = transport::kMessageTypeExt + 11,
  kDownlistRequest = transport::kMessageTypeExt + 12,
  kDownlistResponse = transport::kMessageTypeExt + 13
};
const int kMessageTypeExt = transport::kMessageTypeExt + 14;  // offset for exts

typedef boost::function<void(protobuf::PingResponse,
                             transport::ConversationId)> PingRspFunc;
typedef bs2::signal<void(protobuf::PingRequest,
                         transport::ConversationId)> PingReqSig;

typedef boost::function<void(protobuf::FindValueResponse,
                             transport::ConversationId)> FindValueRspFunc;
typedef bs2::signal<void(protobuf::FindValueRequest,
                         transport::ConversationId)> FindValueReqSig;

typedef boost::function<void(protobuf::FindNodesResponse,
                             transport::ConversationId)> FindNodesRspFunc;
typedef bs2::signal<void(protobuf::FindNodesRequest,
                         transport::ConversationId)> FindNodesReqSig;

typedef boost::function<void(protobuf::StoreResponse,
                             transport::ConversationId)> StoreRspFunc;
typedef bs2::signal<void(protobuf::StoreRequest,
                         transport::ConversationId)> StoreReqSig;

typedef boost::function<void(protobuf::DeleteResponse,
                             transport::ConversationId)> DeleteRspFunc;
typedef bs2::signal<void(protobuf::DeleteRequest,
                         transport::ConversationId)> DeleteReqSig;

typedef boost::function<void(protobuf::UpdateResponse,
                             transport::ConversationId)> UpdateRspFunc;
typedef bs2::signal<void(protobuf::UpdateRequest,
                         transport::ConversationId)> UpdateReqSig;

typedef boost::function<void(protobuf::DownlistResponse,
                             transport::ConversationId)> DownlistRspFunc;
typedef bs2::signal<void(protobuf::DownlistRequest,
                         transport::ConversationId)> DownlistReqSig;

class MessageHandler : public transport::MessageHandler {
 public:
  MessageHandler()
    : on_ping_(),
      on_find_value_(),
      on_find_nodes_(),
      on_store_(),
      on_delete_(),
      on_update_(),
      on_downlist_() {}
  virtual ~MessageHandler() {}
  MessageHandlerCondition Ping(const protobuf::PingRequest &request,
                               PingRspFunc response_cb);
  MessageHandlerCondition FindValue(const protobuf::FindValueRequest &request,
                                    FindValueRspFunc response_cb);
  MessageHandlerCondition FindNodes(const protobuf::FindNodesRequest &request,
                                    FindNodesRspFunc response_cb);
  MessageHandlerCondition Store(const protobuf::StoreRequest &request,
                                StoreRspFunc response_cb);
  MessageHandlerCondition Delete(const protobuf::DeleteRequest &request,
                                 DeleteRspFunc response_cb);
  MessageHandlerCondition Update(const protobuf::UpdateRequest &request,
                                 UpdateRspFunc response_cb);
  MessageHandlerCondition Downlist(const protobuf::DownlistRequest &request,
                                   DownlistRspFunc response_cb);
  PingReqSig on_ping() { return on_ping_; }
  FindValueReqSig on_find_value() { return on_find_value_; }
  FindNodesReqSig on_find_nodes() { return on_find_nodes_; }
  StoreReqSig on_store() { return on_store_; }
  DeleteReqSig on_delete() { return on_delete_; }
  UpdateReqSig on_update() { return on_update_; }
  DownlistReqSig on_downlist() { return on_downlist_; }
 protected:
  PingReqSig on_ping_;
  FindValueReqSig on_find_value_;
  FindNodesReqSig on_find_nodes_;
  StoreReqSig on_store_;
  DeleteReqSig on_delete_;
  UpdateReqSig on_update_;
  DownlistReqSig on_downlist_;
 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_MESSAGEHANDLER_H_
