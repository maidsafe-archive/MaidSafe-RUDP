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
#include "maidsafe/kademlia/messagehandler.h"
#include "maidsafe/kademlia/rpcs.pb.h"
#include "maidsafe/transport/transport.h"

namespace kademlia {

template <class TransportType>
void Rpcs::Ping(const transport::Endpoint &endpoint,
                PingFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::PingRequest req;
  req.set_ping("ping");
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_ping_response()->connect(boost::bind(
      &Rpcs::PingCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::FindValue(const NodeId &key,
                     const transport::Endpoint &endpoint,
                     FindValueFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::FindValueRequest req;
  req.set_key(key.String());
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_find_value_response()->connect(boost::bind(
      &Rpcs::FindValueCallback, this, _1, callback, message_handler,
      transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::FindNodes(const NodeId &key,
                     const transport::Endpoint &endpoint,
                     FindNodesFunctor callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::FindNodesRequest req;
  req.set_key(key.String());
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_find_nodes_response()->connect(boost::bind(
      &Rpcs::FindNodesCallback, this, _1, callback, message_handler,
      transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::Store(const NodeId &key,
                 const SignedValue &signed_value,
                 const Signature &signature,
                 const transport::Endpoint &endpoint,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 VoidFunctorOneBool callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::StoreRequest req;
  req.set_key(key.String());
  req.mutable_signed_value()->set_value(signed_value.value);
  req.mutable_signed_value()->set_signature(signed_value.signature);
  req.set_ttl(ttl);
  req.set_publish(publish);
  req.mutable_signature()->set_signer_id(signature.signer_id);
  req.mutable_signature()->set_public_key(signature.public_key);
  req.mutable_signature()->set_signed_public_key(signature.signed_public_key);
  req.mutable_signature()->set_signature(signature.signature);
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_store_response()->connect(boost::bind(
      &Rpcs::StoreCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::Store(const NodeId &key,
                 const std::string &value,
                 const transport::Endpoint &endpoint,
                 const boost::int32_t &ttl,
                 const bool &publish,
                 VoidFunctorOneBool callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::StoreRequest req;
  req.set_key(key.String());
  req.set_value(value);
  req.set_ttl(ttl);
  req.set_publish(publish);
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_store_response()->connect(boost::bind(
      &Rpcs::StoreCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::Delete(const NodeId &key,
                  const SignedValue &signed_value,
                  const Signature &signature,
                  const transport::Endpoint &endpoint,
                  VoidFunctorOneBool callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::DeleteRequest req;
  req.set_key(key.String());
  req.mutable_signed_value()->set_value(signed_value.value);
  req.mutable_signed_value()->set_signature(signed_value.signature);
  req.mutable_signature()->set_signer_id(signature.signer_id);
  req.mutable_signature()->set_public_key(signature.public_key);
  req.mutable_signature()->set_signed_public_key(signature.signed_public_key);
  req.mutable_signature()->set_signature(signature.signature);
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_delete_response()->connect(boost::bind(
      &Rpcs::DeleteCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::Update(const NodeId &key,
                  const SignedValue &old_signed_value,
                  const SignedValue &new_signed_value,
                  const boost::int32_t &ttl,
                  const Signature &signature,
                  const transport::Endpoint &endpoint,
                  VoidFunctorOneBool callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::UpdateRequest req;
  req.set_key(key.String());
  req.mutable_new_signed_value()->set_value(new_signed_value.value);
  req.mutable_new_signed_value()->set_signature(new_signed_value.signature);
  req.mutable_old_signed_value()->set_value(old_signed_value.value);
  req.mutable_old_signed_value()->set_signature(old_signed_value.signature);
  req.set_ttl(ttl);
  req.mutable_signature()->set_signer_id(signature.signer_id);
  req.mutable_signature()->set_public_key(signature.public_key);
  req.mutable_signature()->set_signed_public_key(signature.signed_public_key);
  req.mutable_signature()->set_signature(signature.signature);
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_update_response()->connect(boost::bind(
      &Rpcs::UpdateCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::Downlist(const std::vector<std::string> &downlist,
                    const transport::Endpoint &endpoint,
                    VoidFunctorOneBool callback) {
  boost::shared_ptr<MessageHandler> message_handler;
  boost::shared_ptr<TransportType> transport(new TransportType);
  protobuf::DownlistRequest req;
  for (size_t i = 0; i < downlist.size(); ++i)
    req.add_downlist(downlist[i]);
  (*req.mutable_sender()) = node_contact_.ToProtobuf();
  std::string msg = message_handler->WrapMessage(req);
  message_handler->on_downlist_response()->connect(boost::bind(
      &Rpcs::DownlistCallback, this, _1, callback, message_handler, transport));
  transport->Send(msg, endpoint, transport::kDefaultInitialTimeout);
}

template <class TransportType>
void Rpcs::PingCallback(const protobuf::PingResponse &response,
                        PingFunctor callback,
                        boost::shared_ptr<MessageHandler>,
                        boost::shared_ptr<TransportType>) {
  callback(response.result(), response.echo());
}

template <class TransportType>
void Rpcs::FindValueCallback(const protobuf::FindValueResponse &response,
                             FindValueFunctor callback,
                             boost::shared_ptr<MessageHandler>,
                             boost::shared_ptr<TransportType>) {
  std::vector<Contact> contacts; 
  for (int i = 0; i < response.closest_nodes_size(); ++i) {
    Contact contact(response.closest_nodes(i));
    contacts.push_back(contact);
  }

  std::vector<std::string> values;
  for (int i = 0; i < response.values_size(); ++i)
    values.push_back(response.values(i);
  
  std::vector<SignedValue> signed_values;
  for (int i = 0; i < response.signed_values_size(); ++i) {
    SignedValue signed_value(response.signed_values(i).value(),
                             response.signed_values(i).signature());
    signed_values.push_back(signed_value);
  }
  
  Contact alternative_value_holder;
  if (response.has_alternative_value_holder())
    alternative_value_holder.FromProtobuf(response.alternative_value_holder());
  
  bool needs_cache_copy(false);
  if (response.has_needs_cache_copy())
    needs_cache_copy = response.needs_cache_copy();
  
  callback(response.result(), contacts, values, signed_values,
           alternative_value_holder, needs_cache_copy);
}

template <class TransportType>
void Rpcs::FindNodesCallback(const protobuf::FindNodesResponse &response,
                             FindNodesFunctor callback,
                             boost::shared_ptr<MessageHandler>,
                             boost::shared_ptr<TransportType>) {
  std::vector<Contact> contacts; 
  for (int i = 0; i < response.closest_nodes_size(); ++i) {
    Contact contact(response.closest_nodes(i));
    contacts.push_back(contact);
  }
  
  callback(response.result(), contacts);
}

template <class TransportType>
void Rpcs::StoreCallback(const protobuf::StoreResponse &response,
                         VoidFunctorOneBool callback,
                         boost::shared_ptr<MessageHandler>,
                         boost::shared_ptr<TransportType>) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::DeleteCallback(const protobuf::DeleteResponse &response,
                          VoidFunctorOneBool callback,
                          boost::shared_ptr<MessageHandler>,
                          boost::shared_ptr<TransportType>) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::UpdateCallback(const protobuf::UpdateResponse &response,
                          VoidFunctorOneBool callback,
                          boost::shared_ptr<MessageHandler>,
                          boost::shared_ptr<TransportType>) {
  callback(response.result());
}

template <class TransportType>
void Rpcs::DownlistCallback(const protobuf::DownlistResponse &response,
                            VoidFunctorOneBool callback,
                            boost::shared_ptr<MessageHandler>,
                            boost::shared_ptr<TransportType>) {
  callback(response.result());
}

}  // namespace kademlia
