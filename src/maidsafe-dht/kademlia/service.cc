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

// TODO(Fraser#5#): 27/01/11 - output warnings consistently.

#include <utility>
#include <set>

// #include "boost/compressed_pair.hpp"

#include "maidsafe-dht/kademlia/service.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/datastore.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/kademlia/message_handler.h"

#include "maidsafe-dht/common/alternative_store.h"
#include "maidsafe-dht/common/securifier.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/crypto.h"

namespace maidsafe {

namespace kademlia {

Service::Service(std::shared_ptr<RoutingTable> routing_table,
                 std::shared_ptr<DataStore> datastore,
                 AlternativeStorePtr alternative_store,
                 SecurifierPtr securifier,
                 const boost::uint16_t &k )
    : routing_table_(routing_table),
      datastore_(datastore),
      alternative_store_(alternative_store),
      securifier_(securifier),
      node_joined_(false),
      node_contact_(),
      k_(k) {}

Service::Service(std::shared_ptr<RoutingTable> routing_table,
                 std::shared_ptr<DataStore> datastore,
                 AlternativeStorePtr alternative_store,
                 SecurifierPtr securifier)
    : routing_table_(routing_table),
      datastore_(datastore),
      alternative_store_(alternative_store),
      securifier_(securifier),
      node_joined_(false),
      node_contact_(),
      k_(size_t(16)) {}

void Service::ConnectToSignals(TransportPtr transport,
                               MessageHandlerPtr message_handler) {
  // Connect message handler to transport for incoming raw messages.  Don't need
  // to connect to on_error() as service doesn't care if reply succeeds or not.
  transport->on_message_received()->connect(
      transport::OnMessageReceived::element_type::slot_type(
          &MessageHandler::OnMessageReceived, message_handler.get(),
          _1, _2, _3, _4).track_foreign(message_handler));
  // Connect service to message handler for incoming parsed requests
  message_handler->on_ping_request()->connect(
      MessageHandler::PingReqSigPtr::element_type::slot_type(
          &Service::Ping, this, _1, _2, _3).track(shared_from_this()));
  message_handler->on_find_value_request()->connect(
      MessageHandler::FindValueReqSigPtr::element_type::slot_type(
          &Service::FindValue, this, _1, _2, _3).track(shared_from_this()));
  message_handler->on_find_nodes_request()->connect(
      MessageHandler::FindNodesReqSigPtr::element_type::slot_type(
          &Service::FindNodes, this, _1, _2, _3).track(shared_from_this()));
  message_handler->on_store_request()->connect(
      MessageHandler::StoreReqSigPtr::element_type::slot_type(
          &Service::Store, this, _1, _2, _3, _4, _5).track(shared_from_this()));
  message_handler->on_delete_request()->connect(
      MessageHandler::DeleteReqSigPtr::element_type::slot_type(
          &Service::Delete, this, _1, _2, _3, _4, _5).track(
              shared_from_this()));
  message_handler->on_downlist_notification()->connect(
      MessageHandler::DownlistNtfSigPtr::element_type::slot_type(
          &Service::Downlist, this, _1, _2).track(shared_from_this()));
}

void Service::Ping(const transport::Info &info,
                   const protobuf::PingRequest &request,
                   protobuf::PingResponse *response) {
  response->set_echo(request.ping());
  routing_table_->AddContact(FromProtobuf(request.sender()),
                             RankInfoPtr(new transport::Info(info)));
}

void Service::FindValue(const transport::Info &info,
                        const protobuf::FindValueRequest &request,
                        protobuf::FindValueResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;
  Contact sender(FromProtobuf(request.sender()));

  // Are we the alternative value holder?
  std::string key(request.key());
  std::vector<std::pair<std::string, std::string>> values_str;
  if (alternative_store_ != NULL && alternative_store_->Has(key)) {
    *(response->mutable_alternative_value_holder()) = ToProtobuf(node_contact_);
    response->set_result(true);
    routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
    return;
  }

  // Do we have the values?
  if (datastore_->GetValues(key, &values_str)) {
    // signature is mandatory in new implementation
    //  if (using_signatures_) {
    for (unsigned int i = 0; i < values_str.size(); i++) {
      protobuf::SignedValue *signed_value = response->add_signed_values();
      signed_value->set_value(values_str[i].first);
      signed_value->set_signature(values_str[i].second);
    }
//     } else {
//       for (unsigned int i = 0; i < values_str.size(); i++)
//         response->add_values(values_str[i].first);
//     }
    response->set_result(true);
    routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
    return;
  }

  protobuf::FindNodesRequest find_nodes_req;
  find_nodes_req.set_key(key);
  find_nodes_req.mutable_sender()->CopyFrom(request.sender());
  protobuf::FindNodesResponse find_nodes_rsp;
  FindNodes(info, find_nodes_req, &find_nodes_rsp);
  response->mutable_closest_nodes()->MergeFrom(find_nodes_rsp.closest_nodes());
  response->set_result(find_nodes_rsp.result());
}

void Service::FindNodes(const transport::Info &info,
                        const protobuf::FindNodesRequest &request,
                        protobuf::FindNodesResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;
  NodeId key(request.key());
  if (!key.IsValid())
    return;  
  Contact sender(FromProtobuf(request.sender()));
  std::vector<Contact> closest_contacts, exclude_contacts;
  exclude_contacts.push_back(sender);
  routing_table_->GetCloseContactsForTargetId(key,
      k_, exclude_contacts, &closest_contacts);
      
//  bool found_node(false);
  for (size_t i = 0; i < closest_contacts.size(); ++i) {
    (*response->add_closest_nodes()) = ToProtobuf(closest_contacts[i]);
//     if (key == closest_contacts[i].node_id())
//       found_node = true;
  }

//   if (!found_node) {
//     Contact key_node;
//     routing_table_->GetContact(key, &key_node);
//     if ( key_node != Contact() )
//       (*response->add_closest_nodes()) = ToProtobuf(key_node);
//   }
  response->set_result(true);
  routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
}

// void Service::Store(const transport::Info &info,
//                     const protobuf::StoreRequest &request,
//                     const std::string &message,
//                     const std::string &message_signature,
//                     protobuf::StoreResponse *response) {
//   response->set_result(false);
//   bool result(false);
//   if (!node_joined_)
//     return;
//   //const google::protobuf::Message signature(request.request_signature());
//   std::string serialised_deletion_signature;
//   if (message_signature.empty() ||
//       message.empty() ||
//       securifier_ == NULL ||
//       // Vakudate(value, sender_id, value_signature, public_key
//       //          pulbic_key_validation, kademlia_key)
//       !securifier_->Validate(
//           message, request.sender().node_id(), message_signature,
//           request.public_key(), "", request.key() )) {
//     DLOG(WARNING) << "Failed to validate Store request for kademlia value"
//                   << std::endl;
//     return;
//   }
//   result = StoreValueLocal(request.key(), request.signed_value(),
//                             request.ttl(), request.has_public_key(), // request.publish
//                             &serialised_deletion_signature);
// 
//   if (result) {
//     response->set_result(true);
//     routing_table_->AddContact(FromProtobuf(request.sender()),
//                                RankInfoPtr(new transport::Info(info)));
//   } else if (!serialised_deletion_signature.empty()) {
//     //(*response->mutable_deletion_signature()).ParseFromString(
//     (*request->mutable_serialised_store_request_signature()).ParseFromString(
//         serialised_deletion_signature);
//   } else {
//     DLOG(WARNING) << "Failed to store kademlia value" << std::endl;
//   }
// }
/*
void Service::Delete(const transport::Info &info,
                     const protobuf::DeleteRequest &request,
                     const std::string &message,
                     const std::string &message_signature,
                     protobuf::DeleteResponse *response) {
  response->set_result(false);
  if (!node_joined_ || !using_signatures_ || signature_validator_ == NULL)
    return;

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasKey(request.key()))
    return;

  const protobuf::MessageSignature &signature(request.request_signature());
  if (!signature_validator_->ValidateSignerId(signature.signer_id(),
                                              signature.public_key(),
                                              signature.public_key_validation()) ||
      !signature_validator_->ValidateRequest(signature.request_signature(),
                                             signature.public_key(),
                                             signature.public_key_validation(),
                                             request.key()))
    return;

  // Only the signer of the value can delete it.
  crypto::Crypto cobj;
  if (!cobj.AsymCheckSig(request.signed_value().value(),
                         request.signed_value().signature(),
                         request.request_signature().public_key(),
                         crypto::STRING_STRING))
    return;
  KeyValueSignatureTuple keyvaluesignature(request.key(),
                                           request.signed_value().value(),
                                           request.signed_value().signature());
  if (datastore_->MarkForDeletion(keyvaluesignature,
                                  signature.SerializeAsString())) {
    response->set_result(true);
    routing_table_->AddContact(FromProtobuf(request.sender()), info);
  }
}

void Service::Update(const transport::Info &info,
                     const protobuf::UpdateRequest &request,
                     const std::string &message,
                     const std::string &message_signature,
                     protobuf::UpdateResponse *response) {
  response->set_result(false);
  if (!node_joined_ || !using_signatures_ || signature_validator_ == NULL)
    return;

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasKey(request.key()))
    return;

  const protobuf::MessageSignature &signature(request.request_signature());
  if (!signature_validator_->ValidateSignerId(signature.signer_id(),
                                              signature.public_key(),
                                              signature.public_key_validation()) ||
      !signature_validator_->ValidateRequest(signature.request_signature(),
                                             signature.public_key(),
                                             signature.public_key_validation(),
                                             request.key()))
    return;

  crypto::Crypto cobj;
  if (!cobj.AsymCheckSig(request.new_signed_value().value(),
                         request.new_signed_value().signature(),
                         signature.public_key(),
                         crypto::STRING_STRING)) {
    DLOG(WARNING) << "Service::Update - New value doesn't validate" <<
                     std::endl;
    return;
  }
  if (!cobj.AsymCheckSig(request.old_signed_value().value(),
                         request.old_signed_value().signature(),
                         signature.public_key(),
                         crypto::STRING_STRING)) {
    DLOG(WARNING) << "Service::Update - Old value doesn't validate" <<
                     std::endl;
    return;
  }
  */
/*******************************************************************************
This code would check if the current value is hashable, and accept only
hashable replacement values.

//  bool current_hashable(request->key() ==
//                        cobj.Hash(sv.value() + sv.value_signature(), "",
//                                  crypto::STRING_STRING, false));
//  bool new_hashable(request->key() ==
//                    cobj.Hash(request->new_value().value() +
//                                  request->new_value().value_signature(),
//                              "", crypto::STRING_STRING, false));
//  if (current_hashable && !new_hashable && values_str.size() == size_t(1)) {
//    done->Run();
//    DLOG(WARNING) << "Service::Update - Hashable tags don't match" <<
//                     std::endl;
//    return;
//  }
*******************************************************************************/
/*
  bool new_hashable(SignedValueHashable(request.key(),
                                        request.new_signed_value()));
  KeyValueSignatureTuple old_keyvaluesignature(
      request.key(), request.old_signed_value().value(),
      request.old_signed_value().signature());
  KeyValueSignatureTuple new_keyvaluesignature(
      request.key(), request.new_signed_value().value(),
      request.new_signed_value().signature());

  if (!datastore_->UpdateValue(old_keyvaluesignature, new_keyvaluesignature,
                               request.ttl(), new_hashable)) {
    DLOG(WARNING) << "Service::Update - Failed UpdateItem" << std::endl;
    return;
  }

  response->set_result(true);
  routing_table_->AddContact(FromProtobuf(request.sender()), info);
}

void Service::Downlist(const transport::Info &info,
                       const protobuf::DownlistNotification &request) {
  if (!node_joined_)
    return;

  // A sophisticated attacker possibly sent a random downlist. We only verify
  // the offline status of the nodes in our routing table.
  std::set<Contact> contacts;
  for (int i = 0; i < request.node_ids_size(); ++i) {
    NodeId id(request.node_ids(i));
    if (id.IsValid()) {
      Contact contact;
      if (routing_table_->GetContact(id, &contact))
        contacts.insert(contact);
    }
  }

  // TODO async ping all contacts in set and remove from RT if no answer
}
*/
// bool Service::StoreValueLocal(const std::string &key,
//                               const std::string &value,
//                               const boost::int32_t &ttl,
//                               bool publish,
//                               std::string *serialised_deletion_signature) {
//   KeyValueSignatureTuple keyvaluesignature(key, value, "");
//   if (publish)
//     return datastore_->StoreValue(keyvaluesignature, ttl, false);
// 
//   if (datastore_->RefreshKeyValue(keyvaluesignature,
//                                   serialised_deletion_signature))
//     return true;
// 
//   if (serialised_deletion_signature->empty())
//     return datastore_->StoreValue(keyvaluesignature, ttl, false);
// 
//   return false;
// }
// 
// bool Service::StoreValueLocal(const std::string &key,
//                               const protobuf::SignedValue &signed_value,
//                               const boost::int32_t &ttl,
//                               bool publish,
//                               std::string *serialised_deletion_signature) {
//   bool hashable;
//   std::string ser_signed_value(signed_value.SerializeAsString());
//   KeyValueSignatureTuple keyvaluesignature(key, signed_value.value(),
//                                            signed_value.signature());
// 
//   if (publish)
//     return CanStoreSignedValueHashable(key, signed_value, &hashable) &&
//         datastore_->StoreValue(keyvaluesignature, ttl, hashable);
// 
//   if (datastore_->RefreshKeyValue(keyvaluesignature,
//                                   serialised_deletion_signature))
//     return true;
// 
//   if (CanStoreSignedValueHashable(key, signed_value, &hashable) &&
//       serialised_deletion_signature->empty())
//     return datastore_->StoreValue(keyvaluesignature, ttl, hashable);
// 
//   return false;
// }
/*
bool Service::SignedValueHashable(const std::string &key,
                                  const protobuf::SignedValue &signed_value) {
  crypto::Crypto cobj;
  cobj.set_hash_algorithm(crypto::SHA_512);
  return key == cobj.Hash(signed_value.value() + signed_value.signature(), "",
                          crypto::STRING_STRING, false);
}

bool Service::CanStoreSignedValueHashable(
    const std::string &key,
    const protobuf::SignedValue &signed_value,
    bool *hashable) {
  std::vector< std::pair<std::string, bool> > attr;
  attr = datastore_->LoadKeyAppendableAttr(key);
  *hashable = false;
  if (attr.empty()) {
    *hashable = SignedValueHashable(key, signed_value);
  } else if (attr.size() == 1) {
    *hashable = attr[0].second;
    if (*hashable &&
        signed_value.value() + signed_value.signature() != attr[0].first)
      return false;
  }
  return true;
}*/

}  // namespace kademlia

}  // namespace maidsafe
