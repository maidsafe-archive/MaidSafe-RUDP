/* Copyright (c) 2009 maidsafe.net limited
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

#include "maidsafe/kademlia/rpcs.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/kademlia/messagehandler.h"
// #include "maidsafe/transport/udttransport.h"

namespace kademlia {
// TODO(dirvine) Dec 12 2010 - template this to take mutiple
// transports to support tcp as well as reliable udp

Rpcs::Rpcs() {}

void Rpcs::FindNodes(const NodeId &key,
                     const Endpoint &ep,
                     FindNodesFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::FindNodesRequest args;
  args.set_key(key.String());
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestFindNodes(args, ep, boost::bind(&FindNodesCallback,
                                    this, _1, callback, message_handler));
}

void Rpcs::FindValue(const NodeId &key,
                     const Endpoint &ep,
                     FindValueFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::FindValueRequest args;
  args.set_key(key.String());
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestFindValue(args, ep, boost::bind(&FindValueCallback,
                                    this, _1, callback, message_handler));
}

void Rpcs::Ping(const Endpoint &ep,
                PingFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::PingRequest args;
  args.set_ping("ping");
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestPing(args, ep, boost::bind(&PingCallback,
                               this, _1, callback, message_handler));
}

void Rpcs::Store(const NodeId &key,
                 const protobuf::SignedValue &value,
                 const protobuf::SignedRequest &sig_req,
                 const Endpoint &ep,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 StoreSigFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::StoreRequest args;
  args.set_key(key.String());
  protobuf::SignedValue *svalue = args.mutable_sig_value();
  *svalue = value;
  args.set_ttl(ttl);
  args.set_publish(publish);
  protobuf::SignedRequest *sreq = args.mutable_signed_request();
  *sreq = sig_req;
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestStore(args, ep, boost::bind(&StoreSigCallback,
                                this, _1, callback, message_handler));
}

void Rpcs::Store(const NodeId &key,
                 const std::string &value,
                 const Endpoint &ep,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 StoreFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::StoreRequest args;
  args.set_key(key.String());
  args.set_value(value);
  args.set_ttl(ttl);
  args.set_publish(publish);
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestStore(args, ep, boost::bind(&StoreCallback,
                                this, _1, callback, message_handler));
}

void Rpcs::Downlist(const std::vector<std::string> downlist,
                    const Endpoint &ep,
                    DownlistFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::DownlistRequest args;
  for (unsigned int i = 0; i < downlist.size(); ++i)
    args.add_downlist(downlist[i]);
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestDownlist(args, ep, boost::bind(&DownlistCallback,
                                   this, _1, callback, message_handler));
}

void Rpcs::Bootstrap(const NodeId &local_id,
                     const Endpoint &ep,
                     const NodeType &type,
                     BootStrapFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::BootstrapRequest args;
  args.set_newcomer_id(local_id.String());
  args.set_newcomer_local_ip(ep.ip);
  args.set_newcomer_local_port(ep.port);
  args.set_node_type(type);
  message_handler->RequestBootstrap(args, ep, boost::bind(&BootStrapCallback,
                                    this, _1, callback, message_handler));
}

void Rpcs::Delete(const NodeId &key,
                  const protobuf::SignedValue &value,
                  const protobuf::SignedRequest &sig_req,
                  const Endpoint &ep,
                  DeleteFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::DeleteRequest args;
  args.set_key(key.String());
  protobuf::SignedValue *svalue = args.mutable_value();
  *svalue = value;
  protobuf::SignedRequest *sreq = args.mutable_signed_request();
  *sreq = sig_req;
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestDelete(args, ep, boost::bind(&DeleteCallback,
                                 this, _1, callback, message_handler));
}

void Rpcs::Update(const NodeId &key,
                  const protobuf::SignedValue &old_value,
                  const protobuf::SignedValue &new_value,
                  const boost::int32_t &ttl,
                  const protobuf::SignedRequest &sig_req,
                  const Endpoint &ep,
                  UpdateFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  protobuf::UpdateRequest args;
  args.set_key(key.String());
  protobuf::SignedValue *newvalue = args.mutable_new_value();
  *newvalue = new_value;
  protobuf::SignedValue *oldvalue = args.mutable_old_value();
  *oldvalue = old_value;
  args.set_ttl(ttl);
  protobuf::SignedRequest *sreq = args.mutable_request();
  *sreq = sig_req;
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  message_handler->RequestUpdate(args, ep, boost::bind(&UpdateCallback,
                                 this, _1, callback, message_handler));
}
void FindNodesCallback(const protobuf::FindNodesResponse &response,
                       FindNodesFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
// need to change type of contact 
callback(response.result, response.contact);
}
void FindValueCallback(const protobuf::FindValueResponse &response,
                       FindValueFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void PingCallback(const protobuf::PingResponse &response,
                       PingFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void StoreSigCallback(const protobuf::StoreResponse &response,
                       StoreSigFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void StoreCallback(const protobuf::StoreResponse &response,
                       StoreFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void DownlistCallback(const protobuf::DownlistResponse &response,
                       DownlistFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void BootStrapCallback(const protobuf::BootStrapResponse &response,
                       BootStrapFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void DeleteCallback(const protobuf::DeleteResponse &response,
                       DeleteFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}
void UpdateCallback(const protobuf::UpdateResponse &response,
                       UpdateFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
 // code for callback calling
}

}  // namespace kademlia
