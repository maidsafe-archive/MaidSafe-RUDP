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

#include "maidsafe/kademlia/rpcs.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/kademlia/messagehandler.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/transport/transport.h"

namespace transport {

template <class TransportType>
Rpcs::Rpcs()
      {}
template <class TransportType>
void Rpcs::FindNodes(const NodeId &key,
                     const Endpoint &ep,
                     FindNodesFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::FindNodesRequest args;
  args.set_key(key.String());
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_find_nodes_response()->connect(boost::bind(
                                                     &Rpc::FindNodesCallback,
                                                     this, _1, callback,
                                                     message_handler, transport));
  transport->Send(msg, ep, timeout);
}
template <class TransportType>
void Rpcs::FindValue(const NodeId &key,
                     const Endpoint &ep,
                     FindValueFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::FindValueRequest args;
  args.set_key(key.String());
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_find_value_response()->connect(boost::bind(
                                                     &Rpc::FindValueCallback,
                                                     this, _1, callback,
                                                     message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Ping(const Endpoint &ep,
                PingFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::PingRequest args;
  args.set_ping("ping");
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_ping_response()->connect(boost::bind(&Rpc::PingCallback,
                                               this, _1, callback,
                                               message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Store(const NodeId &key,
                 const protobuf::SignedValue &value,
                 const protobuf::SignedRequest &sig_req,
                 const Endpoint &ep,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 StoreSigFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
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
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_store_response()->connect(boost::bind(
                                               &Rpc::StoreCallback,
                                               this, _1, callback,
                                               message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Store(const NodeId &key,
                 const std::string &value,
                 const Endpoint &ep,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 StoreFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::StoreRequest args;
  args.set_key(key.String());
  args.set_value(value);
  args.set_ttl(ttl);
  args.set_publish(publish);
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_store_response()->connect(boost::bind(
                                                &Rpc::StoreCallback,
                                                this, _1, callback,
                                                message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Downlist(const std::vector<std::string> downlist,
                    const Endpoint &ep,
                    DownlistFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::DownlistRequest args;
  for (unsigned int i = 0; i < downlist.size(); ++i)
    args.add_downlist(downlist[i]);
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_downlist_response()->connect(boost::bind(
                                                   &Rpc::DownlistCallback,
                                                   this, _1, callback,
                                                   message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Delete(const NodeId &key,
                  const protobuf::SignedValue &value,
                  const protobuf::SignedRequest &sig_req,
                  const Endpoint &ep,
                  DeleteFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
  protobuf::DeleteRequest args;
  args.set_key(key.String());
  protobuf::SignedValue *svalue = args.mutable_value();
  *svalue = value;
  protobuf::SignedRequest *sreq = args.mutable_signed_request();
  *sreq = sig_req;
  protobuf::Contact *sender_info = args.mutable_sender();
  *sender_info = info_;
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_delete_response()->connect(boost::bind(
                                                 &Rpc::DeleteCallback,
                                                 this, _1, callback,
                                                 message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::Update(const NodeId &key,
                  const protobuf::SignedValue &old_value,
                  const protobuf::SignedValue &new_value,
                  const boost::int32_t &ttl,
                  const protobuf::SignedRequest &sig_req,
                  const Endpoint &ep,
                  UpdateFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<transport::Transport> transport(new TransportType);
  transport::Timeout timeout(transport::kDefaultInitialTimeout);
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
  std::string msg = message_handler->WrapMessage(args);
  message_handler->on_update_response()->connect(boost::bind(
                                                 &Rpc::UpdateCallback,
                                                 this, _1, callback,
                                                 message_handler, transport));
  transport->Send(msg, ep, timeout);
}

template <class TransportType>
void Rpcs::FindNodesCallback(const protobuf::FindNodesResponse &response,
                       FindNodesFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport) {
  std::vector<Contact> contacts; 
  for (int i =0; i < response.closest_nodes_size(); ++i) {
    Contact contact(response.closest_nodes(i));
    contacts[i] = contact;
  }
  callback(response.result(), contacts);
}

template <class TransportType>
void Rpcs::FindValueCallback(const protobuf::FindValueResponse &response,
                       FindValueFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport) {
  std::vector<Contact> contacts; 
  for (int i =0; i < response.closest_nodes_size(); ++i) {
    Contact contact(response.closest_nodes(i));
    contacts[i] = contact;
  }
  callback(response.result(), contacts);
}

template <class TransportType>
void Rpcs::PingCallback(const protobuf::PingResponse &response,
                       PingFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport> transport) {
  callback(response.result(), response.echo());
}

template <class TransportType>
void Rpcs::StoreSigCallback(const protobuf::StoreResponse &response,
                       StoreSigFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler,
                       boost::shared_ptr<transport::Transport>transport) {
  callback(response.result(), response.signed_request());
}

template <class TransportType>
void Rpcs::StoreCallback(const protobuf::StoreResponse &response,
                       StoreFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::DownlistCallback(const protobuf::DownlistResponse &response,
                       DownlistFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::DeleteCallback(const protobuf::DeleteResponse &response,
                       DeleteFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::UpdateCallback(const protobuf::UpdateResponse &response,
                       UpdateFunctor callback,
                       boost::shared_ptr<MessageHandler> message_handler) {
  callback(response.result());
}

}  // namespace transport
