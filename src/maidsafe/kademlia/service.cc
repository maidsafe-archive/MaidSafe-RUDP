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

// TODO output warnings consistently

#include "maidsafe/kademlia/service.h"

// #include <boost/compressed_pair.hpp>
#include <utility>
#include <set>

#include "maidsafe/kademlia/routingtable.h"
#include "maidsafe/kademlia/datastore.h"
#include "maidsafe/kademlia/rpcs.pb.h"
#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/base/log.h"

// #include "maidsafe/kademlia/rpcs.h"
// #include "maidsafe/kademlia/nodeimpl.h"
#include "maidsafe/base/crypto.h"
// #include "maidsafe/base/utils.h"
// #include "maidsafe/kademlia/node-api.h"
// #include "maidsafe/protobuf/signed_kadvalue.pb.h"
// #include "maidsafe/kademlia/nodeid.h"

namespace kademlia {

Service::Service(boost::shared_ptr<RoutingTable> routing_table,
                 boost::shared_ptr<DataStore> datastore,
                 bool using_signatures)
    : routing_table_(routing_table),
      datastore_(datastore),
      node_joined_(false),
      using_signatures_(using_signatures),
      node_contact_(),
      alternative_store_(),
      signature_validator_() {
  // Connect message handler to transport for incoming raw messages
/*  transport_->on_message_received()->connect(boost::bind(
      &MessageHandler::OnMessageReceived, message_handler_, _1, _2, _3, _4));
  // Connect service to message handler for incoming parsed requests
  message_handler_->on_ping_request()->connect(boost::bind(
      &Service::Ping, this, _1, _2));
  message_handler_->on_find_value_request()->connect(boost::bind(
      &Service::FindValue, this, _1, _2));
  message_handler_->on_find_nodes_request()->connect(boost::bind(
      &Service::FindNodes, this, _1, _2));
  message_handler_->on_store_request()->connect(boost::bind(
      &Service::Store, this, _1, _2));
  message_handler_->on_delete_request()->connect(boost::bind(
      &Service::Delete, this, _1, _2));
  message_handler_->on_update_request()->connect(boost::bind(
      &Service::Update, this, _1, _2));
  message_handler_->on_downlist_request()->connect(boost::bind(
      &Service::Downlist, this, _1, _2)); */
}

void Service::Ping(const transport::Info &info,
                   const protobuf::PingRequest &request,
                   protobuf::PingResponse *response) {
  response->set_echo("pong");
  response->set_result(true);
  routing_table_->AddContact(Contact(request.sender()));  // TODO pass info
}

void Service::FindValue(const transport::Info &info,
                        const protobuf::FindValueRequest &request,
                        protobuf::FindValueResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;
  Contact sender(request.sender());

  // Are we the alternative value holder?
  std::string key(request.key());
  std::vector<std::string> values_str;
  if (alternative_store_ != NULL && alternative_store_->Has(key)) {
    *(response->mutable_alternative_value_holder()) =
        node_contact_.ToProtobuf();
    response->set_result(true);
    routing_table_->AddContact(sender);  // TODO pass info
    return;
  }

  // Do we have the values?
  if (datastore_->LoadItem(key, &values_str)) {
    if (using_signatures_) {
      for (unsigned int i = 0; i < values_str.size(); i++) {
        protobuf::SignedValue *signed_value = response->add_signed_values();
        signed_value->ParseFromString(values_str[i]);
      }
    } else {
      for (unsigned int i = 0; i < values_str.size(); i++)
        response->add_values(values_str[i]);
    }
    response->set_result(true);
    routing_table_->AddContact(sender);  // TODO pass info
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
  Contact sender(request.sender());
  std::vector<Contact> closest_contacts, exclude_contacts;
  NodeId key(request.key());

  if (!key.IsValid())
    return;

  exclude_contacts.push_back(sender);
  // TODO change to an overloaded method with implicit K
  routing_table_->FindCloseNodes(key, -1, exclude_contacts, &closest_contacts);
  bool found_node(false);
  for (size_t i = 0; i < closest_contacts.size(); ++i) {
    (*response->add_closest_nodes()) = closest_contacts[i].ToProtobuf();
    if (key == closest_contacts[i].node_id())
      found_node = true;
  }

  if (!found_node) {
    Contact key_node;
    if (routing_table_->GetContact(key, &key_node))
      (*response->add_closest_nodes()) = key_node.ToProtobuf();
  }

  response->set_result(true);
  routing_table_->AddContact(sender);  // TODO pass info
}

void Service::Store(const transport::Info &info,
                    const protobuf::StoreRequest &request,
                    protobuf::StoreResponse *response) {
  response->set_result(false);
  bool result(false);
  if (!node_joined_)
    return;
  const protobuf::Signature &signature(request.request_signature());
  std::string serialised_deletion_signature;

  if (using_signatures_) {
    if (!request.has_request_signature() ||
        !request.has_signed_value() ||
        signature_validator_ == NULL ||
        !signature_validator_->ValidateSignerId(
            signature.signer_id(), signature.public_key(),
            signature.signed_public_key()) ||
        !signature_validator_->ValidateRequest(
            signature.payload_signature(), signature.public_key(),
            signature.signed_public_key(), request.key())) {
      DLOG(WARNING) << "Failed to validate Store request for kademlia value"
                    << std::endl;
      return;
    }
    result = StoreValueLocal(request.key(), request.signed_value(),
                             request.ttl(), request.publish(),
                             &serialised_deletion_signature);
  } else if (request.has_value()) {
    result = StoreValueLocal(request.key(), request.value(), request.ttl(),
                             request.publish(), &serialised_deletion_signature);
  }

  if (result) {
    response->set_result(true);
    routing_table_->AddContact(Contact(request.sender()));  // TODO pass info
  } else if (!serialised_deletion_signature.empty()) {
    (*response->mutable_deletion_signature()).ParseFromString(
        serialised_deletion_signature);
  } else {
    DLOG(WARNING) << "Failed to store kademlia value" << std::endl;
  }
}

void Service::Delete(const transport::Info &info,
                     const protobuf::DeleteRequest &request,
                     protobuf::DeleteResponse *response) {
  response->set_result(false);
  if (!node_joined_ || !using_signatures_ || signature_validator_ == NULL)
    return;

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasItem(request.key()))
    return;

  const protobuf::Signature &signature(request.request_signature());
  if (!signature_validator_->ValidateSignerId(signature.signer_id(),
                                              signature.public_key(),
                                              signature.signed_public_key()) ||
      !signature_validator_->ValidateRequest(signature.payload_signature(),
                                             signature.public_key(),
                                             signature.signed_public_key(),
                                             request.key()))
    return;

  // Only the signer of the value can delete it.
  crypto::Crypto cobj;
  if (!cobj.AsymCheckSig(request.signed_value().value(),
                         request.signed_value().signature(),
                         request.request_signature().public_key(),
                         crypto::STRING_STRING))
    return;

  if (datastore_->MarkForDeletion(request.key(),
                                  request.signed_value().SerializeAsString(),
                                  signature.SerializeAsString())) {
    response->set_result(true);
    routing_table_->AddContact(Contact(request.sender()));  // TODO pass info
  }
}

void Service::Update(const transport::Info &info,
                     const protobuf::UpdateRequest &request,
                     protobuf::UpdateResponse *response) {
  response->set_result(false);
  if (!node_joined_ || !using_signatures_ || signature_validator_ == NULL)
    return;

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasItem(request.key()))
    return;

  const protobuf::Signature &signature(request.request_signature());
  if (!signature_validator_->ValidateSignerId(signature.signer_id(),
                                              signature.public_key(),
                                              signature.signed_public_key()) ||
      !signature_validator_->ValidateRequest(signature.payload_signature(),
                                             signature.public_key(),
                                             signature.signed_public_key(),
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

  bool new_hashable(SignedValueHashable(request.key(),
                                        request.new_signed_value()));

  if (!datastore_->UpdateItem(request.key(),
                              request.old_signed_value().SerializeAsString(),
                              request.new_signed_value().SerializeAsString(),
                              request.ttl(), new_hashable)) {
    DLOG(WARNING) << "Service::Update - Failed UpdateItem" << std::endl;
    return;
  }

  response->set_result(true);
  routing_table_->AddContact(Contact(request.sender()));  // TODO pass info
}

void Service::Downlist(const transport::Info &info,
                       const protobuf::DownlistRequest &request,
                       protobuf::DownlistResponse *response) {
  if (!node_joined_) {
    response->set_result(false);
    return;
  }
  response->set_result(true);  // TODO needed?

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

  routing_table_->AddContact(Contact(request.sender()));  // TODO pass info
}

bool Service::StoreValueLocal(const std::string &key,
                              const std::string &value,
                              const boost::int32_t &ttl,
                              bool publish,
                              std::string *serialised_deletion_signature) {
  if (publish)
    return datastore_->StoreItem(key, value, ttl, false);

  if (datastore_->RefreshItem(key, value, serialised_deletion_signature))
    return true;

  if (serialised_deletion_signature->empty())
    return datastore_->StoreItem(key, value, ttl, false);

  return false;
}

bool Service::StoreValueLocal(const std::string &key,
                              const protobuf::SignedValue &signed_value,
                              const boost::int32_t &ttl,
                              bool publish,
                              std::string *serialised_deletion_signature) {
  bool hashable;
  std::string ser_signed_value(signed_value.SerializeAsString());

  if (publish)
    return CanStoreSignedValueHashable(key, signed_value, &hashable) &&
           datastore_->StoreItem(key, ser_signed_value, ttl, hashable);

  if (datastore_->RefreshItem(key, ser_signed_value,
                              serialised_deletion_signature))
    return true;

  if (CanStoreSignedValueHashable(key, signed_value, &hashable) &&
      serialised_deletion_signature->empty())
    return datastore_->StoreItem(key, ser_signed_value, ttl, hashable);

  return false;
}

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
}

}  // namespace kademlia
