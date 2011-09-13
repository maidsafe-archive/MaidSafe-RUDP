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

#include <utility>
#include <set>

#include "maidsafe/dht/kademlia/service.h"
#include "maidsafe/common/alternative_store.h"
#include "maidsafe/common/crypto.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/routing_table.h"
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/log.h"


namespace arg = std::placeholders;

namespace maidsafe {

namespace dht {

namespace kademlia {

Service::Service(std::shared_ptr<RoutingTable> routing_table,
                 std::shared_ptr<DataStore> data_store,
                 AlternativeStorePtr alternative_store,
                 SecurifierPtr securifier,
                 const uint16_t &k)
    : routing_table_(routing_table),
      datastore_(data_store),
      alternative_store_(alternative_store),
      securifier_(securifier),
      node_joined_(false),
      node_contact_(),
      k_(k),
      sender_task_(new SenderTask),
      client_node_id_(NodeId().String()) {}

Service::~Service() {}

void Service::ConnectToSignals(MessageHandlerPtr message_handler) {
  // Connect service to message handler for incoming parsed requests
  message_handler->on_ping_request()->connect(
      MessageHandler::PingReqSigPtr::element_type::slot_type(
          &Service::Ping, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_find_value_request()->connect(
      MessageHandler::FindValueReqSigPtr::element_type::slot_type(
          &Service::FindValue, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_find_nodes_request()->connect(
      MessageHandler::FindNodesReqSigPtr::element_type::slot_type(
          &Service::FindNodes, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_store_request()->connect(
      MessageHandler::StoreReqSigPtr::element_type::slot_type(
          &Service::Store, this, _1, _2, _3, _4, _5, _6).track_foreign(
              shared_from_this()));
  message_handler->on_store_refresh_request()->connect(
      MessageHandler::StoreRefreshReqSigPtr::element_type::slot_type(
          &Service::StoreRefresh, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_delete_request()->connect(
      MessageHandler::DeleteReqSigPtr::element_type::slot_type(
          &Service::Delete, this, _1, _2, _3, _4, _5, _6).track_foreign(
              shared_from_this()));
  message_handler->on_delete_refresh_request()->connect(
      MessageHandler::DeleteRefreshReqSigPtr::element_type::slot_type(
          &Service::DeleteRefresh, this, _1, _2, _3, _4).track_foreign(
              shared_from_this()));
  message_handler->on_downlist_notification()->connect(
      MessageHandler::DownlistNtfSigPtr::element_type::slot_type(
          &Service::Downlist, this, _1, _2, _3).track_foreign(
              shared_from_this()));
}

bool Service::CheckParameters(const std::string &method_name,
                              const Key *key,
                              const std::string *message,
                              const std::string *message_signature) const {
  std::string debug_msg(DebugId(node_contact_) + " - in " + method_name + ": ");
  if (!node_joined_) {
    DLOG(WARNING) << debug_msg << ": Not joined.";
    return false;
  }
  if (!securifier_) {
    DLOG(WARNING) << debug_msg << ": NULL securifier.";
    return false;
  }
  if (key && !key->IsValid()) {
    DLOG(WARNING) << debug_msg << ": invalid Kad key.";
    return false;
  }
  if (message && message->empty()) {
    DLOG(WARNING) << debug_msg << ": empty message.";
    return false;
  }
  if (message_signature && message_signature->empty()) {
    DLOG(WARNING) << debug_msg << ": signature empty.";
    return false;
  }
  return true;
}

void Service::Ping(const transport::Info &info,
                   const protobuf::PingRequest &request,
                   protobuf::PingResponse *response,
                   transport::Timeout*) {
  response->set_echo("");
  if (!CheckParameters("Ping", NULL, &request.ping()))
    return;
  response->set_echo(request.ping());
  AddContactToRoutingTable(FromProtobuf(request.sender()), info);
}

void Service::FindValue(const transport::Info &info,
                        const protobuf::FindValueRequest &request,
                        protobuf::FindValueResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("FindValue", &key))
    return;

  Contact sender(FromProtobuf(request.sender()));

  // Are we the alternative value holder?
  if (alternative_store_ && (alternative_store_->Has(key.String()))) {
    *(response->mutable_alternative_value_holder()) = ToProtobuf(node_contact_);
    response->set_result(true);
    AddContactToRoutingTable(sender, info);
    return;
  }

  // Do we have the values?
  std::vector<ValueAndSignature> values_and_signatures;
  if (datastore_->GetValues(key.String(), &values_and_signatures)) {
    for (unsigned int i = 0; i < values_and_signatures.size(); i++) {
      protobuf::SignedValue *signed_value = response->add_signed_values();
      signed_value->set_value(values_and_signatures[i].first);
      signed_value->set_signature(values_and_signatures[i].second);
    }
    response->set_result(true);
    AddContactToRoutingTable(sender, info);
    return;
  }

  size_t num_nodes_requested(k_);
  if (request.has_num_nodes_requested() && request.num_nodes_requested() > k_)
    num_nodes_requested = request.num_nodes_requested();

  std::vector<Contact> closest_contacts, exclude_contacts;
  routing_table_->GetCloseContacts(key, num_nodes_requested,
                                   exclude_contacts, &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i)
    (*response->add_closest_nodes()) = ToProtobuf(closest_contacts[i]);

  response->set_result(true);
  AddContactToRoutingTable(sender, info);
}

void Service::FindNodes(const transport::Info &info,
                        const protobuf::FindNodesRequest &request,
                        protobuf::FindNodesResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("FindNodes", &key))
    return;

  size_t num_nodes_requested(k_);
  if (request.has_num_nodes_requested() && request.num_nodes_requested() > k_)
    num_nodes_requested = request.num_nodes_requested();

  std::vector<Contact> closest_contacts, exclude_contacts;
  routing_table_->GetCloseContacts(key, num_nodes_requested, exclude_contacts,
                                   &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i)
    *response->add_closest_nodes() = ToProtobuf(closest_contacts[i]);
  response->set_result(true);

  Contact sender(FromProtobuf(request.sender()));
  if (sender.node_id().String() != client_node_id_) {
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  }
}

void Service::Store(const transport::Info &info,
                    const protobuf::StoreRequest &request,
                    const std::string &message,
                    const std::string &message_signature,
                    protobuf::StoreResponse *response,
                    transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("Store", &key, &message, &message_signature))
    return;

  // Check if same private key signs other values under same key in datastore
  KeyValueSignature key_value_signature(key.String(),
                                        request.signed_value().value(),
                                        request.signed_value().signature());
  if (datastore_->DifferentSigner(key_value_signature,
                                  request.sender().public_key(),
                                  securifier_)) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Can't store - different "
                  << "signing key used to store under Kad key.";
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
    return;
  }

  RequestAndSignature request_signature(message, message_signature);
  TaskCallback store_cb = std::bind(&Service::StoreCallback, this, arg::_1,
                              request, arg::_2, arg::_3, arg::_4, arg::_5);
  bool is_new_id = true;
  if (sender_task_->AddTask(key_value_signature, info, request_signature,
                            request.sender().public_key_id(), store_cb,
                            &is_new_id)) {
    if (is_new_id) {  // If public_key_id is new
      GetPublicKeyAndValidationCallback cb =
          std::bind(&SenderTask::SenderTaskCallback, sender_task_,
                    request.sender().public_key_id(), arg::_1, arg::_2);
      securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(),
                                             cb);
    }
    response->set_result(true);
  } else {
    DLOG(ERROR) << DebugId(node_contact_) << ": failed to add the store task.";
  }
}

void Service::StoreRefresh(const transport::Info &info,
                           const protobuf::StoreRefreshRequest &request,
                           protobuf::StoreRefreshResponse *response,
                           transport::Timeout*) {
  response->set_result(false);
  if (!CheckParameters("StoreRefresh", NULL,
                       &request.serialised_store_request(),
                       &request.serialised_store_request_signature()))
    return;

  protobuf::StoreRequest ori_store_request;
  if (!ori_store_request.ParseFromString(request.serialised_store_request())) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Invalid serialised store "
                  << "request.";
    return;
  }

  if (!Key(ori_store_request.key()).IsValid()) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Invalid key.";
    return;
  }

  // Check if same private key signs other values under same key in datastore
  KeyValueSignature key_value_signature(
      ori_store_request.key(), ori_store_request.signed_value().value(),
      ori_store_request.signed_value().signature());
  if (datastore_->DifferentSigner(key_value_signature,
                                  ori_store_request.sender().public_key(),
                                  securifier_)) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Can't refresh store - "
                  << "different signing key used to store under Kad key.";
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
    return;
  }

  RequestAndSignature request_signature(request.serialised_store_request(),
                          request.serialised_store_request_signature());
  TaskCallback store_refresh_cb = std::bind(&Service::StoreRefreshCallback,
                                            this, arg::_1, request, arg::_2,
                                            arg::_3, arg::_4, arg::_5);
  bool is_new_id = true;
  if (sender_task_->AddTask(key_value_signature, info, request_signature,
                            ori_store_request.sender().public_key_id(),
                            store_refresh_cb, &is_new_id)) {
    if (is_new_id) {
      GetPublicKeyAndValidationCallback cb =
          std::bind(&SenderTask::SenderTaskCallback, sender_task_,
                    ori_store_request.sender().public_key_id(), arg::_1,
                    arg::_2);
      securifier_->GetPublicKeyAndValidation(
          ori_store_request.sender().public_key_id(), cb);
    }
    response->set_result(true);
  } else {
    DLOG(ERROR) << DebugId(node_contact_) << ": failed to add the store "
                << "refresh task.";
  }
}

void Service::StoreCallback(KeyValueSignature key_value_signature,
                            protobuf::StoreRequest request,
                            transport::Info info,
                            RequestAndSignature request_signature,
                            std::string public_key,
                            std::string public_key_validation) {
  if (ValidateAndStore(key_value_signature, request, info, request_signature,
                       public_key, public_key_validation, false))
    if (request.sender().node_id() != client_node_id_)
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
}

void Service::StoreRefreshCallback(KeyValueSignature key_value_signature,
                                   protobuf::StoreRefreshRequest request,
                                   transport::Info info,
                                   RequestAndSignature request_signature,
                                   std::string public_key,
                                   std::string public_key_validation) {
  protobuf::StoreRequest ori_store_request;
  ori_store_request.ParseFromString(request.serialised_store_request());
  if (ValidateAndStore(key_value_signature, ori_store_request, info,
      request_signature, public_key, public_key_validation, true))
    if (request.sender().node_id() != client_node_id_)
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
}

bool Service::ValidateAndStore(const KeyValueSignature &key_value_signature,
                               const protobuf::StoreRequest &request,
                               const transport::Info &/*info*/,
                               const RequestAndSignature &request_signature,
                               const std::string &public_key,
                               const std::string &public_key_validation,
                               const bool is_refresh) {
  if (!securifier_->Validate(key_value_signature.value,
                             key_value_signature.signature,
                             request.sender().public_key_id(),
                             public_key,
                             public_key_validation,
                             request.key())) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Failed to validate Store "
                  << "request for kademlia value (is_refresh = "
                  << std::boolalpha << is_refresh << ")";
    return false;
  }
  if (datastore_->StoreValue(key_value_signature,
      boost::posix_time::seconds(request.ttl()), request_signature,
      is_refresh) == kSuccess) {
    return true;
  } else {
    DLOG(WARNING) << DebugId(node_contact_) << ": Failed to store Kad value.";
    return false;
  }
}

void Service::Delete(const transport::Info &info,
                     const protobuf::DeleteRequest &request,
                     const std::string &message,
                     const std::string &message_signature,
                     protobuf::DeleteResponse *response,
                     transport::Timeout*) {
  response->set_result(false);
  Key key(request.key());
  if (!CheckParameters("Delete", &key, &message, &message_signature))
    return;

  if (!datastore_->HasKey(key.String())) {
    response->set_result(true);
    return;
  }

  // Check if same private key signs other values under same key in datastore
  KeyValueSignature key_value_signature(key.String(),
                                        request.signed_value().value(),
                                        request.signed_value().signature());
  if (datastore_->DifferentSigner(key_value_signature,
                                  request.sender().public_key(),
                                  securifier_)) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Can't delete - different "
                  << "signing key used to store key,value.";
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
    return;
  }

  RequestAndSignature request_signature(message, message_signature);
  TaskCallback delete_cb = std::bind(&Service::DeleteCallback, this, arg::_1,
                                     request, arg::_2, arg::_3, arg::_4,
                                     arg::_5);
  bool is_new_id = true;
  if (sender_task_->AddTask(key_value_signature, info, request_signature,
                            request.sender().public_key_id(), delete_cb,
                            &is_new_id)) {
    if (is_new_id) {
      GetPublicKeyAndValidationCallback cb =
          std::bind(&SenderTask::SenderTaskCallback, sender_task_,
                    request.sender().public_key_id(), arg::_1, arg::_2);
      securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(),
                                             cb);
    }
    response->set_result(true);
  } else {
    DLOG(ERROR) << DebugId(node_contact_) << ": failed to add the delete task.";
  }
}

void Service::DeleteRefresh(const transport::Info &info,
                            const protobuf::DeleteRefreshRequest &request,
                            protobuf::DeleteRefreshResponse *response,
                            transport::Timeout*) {
  response->set_result(false);
  if (!CheckParameters("DeleteRefresh", NULL,
                       &request.serialised_delete_request(),
                       &request.serialised_delete_request_signature()))
    return;

  protobuf::DeleteRequest ori_delete_request;
  if (!ori_delete_request.ParseFromString(
      request.serialised_delete_request())) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Invalid serialised delete "
                  << "request.";
    return;
  }

  if (!Key(ori_delete_request.key()).IsValid()) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Invalid key.";
    return;
  }

  // Check if same private key signs other values under same key in datastore
  KeyValueSignature key_value_signature(
      ori_delete_request.key(),
      ori_delete_request.signed_value().value(),
      ori_delete_request.signed_value().signature());
  if (datastore_->DifferentSigner(key_value_signature,
                                  ori_delete_request.sender().public_key(),
                                  securifier_)) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Can't refresh delete - "
                  << "different signing key used to store key,value.";
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
    return;
  }

  RequestAndSignature request_signature(request.serialised_delete_request(),
                          request.serialised_delete_request_signature());
  TaskCallback delete_refresh_cb = std::bind(&Service::DeleteRefreshCallback,
                                             this, arg::_1, request, arg::_2,
                                             arg::_3, arg::_4, arg::_5);
  bool is_new_id = true;
  if (sender_task_->AddTask(key_value_signature, info, request_signature,
                            ori_delete_request.sender().public_key_id(),
                            delete_refresh_cb, &is_new_id)) {
    if (is_new_id) {
      GetPublicKeyAndValidationCallback cb =
          std::bind(&SenderTask::SenderTaskCallback, sender_task_,
                    ori_delete_request.sender().public_key_id(), arg::_1,
                    arg::_2);
      securifier_->GetPublicKeyAndValidation(
          ori_delete_request.sender().public_key_id(), cb);
    }
    response->set_result(true);
  } else {
    DLOG(ERROR) << DebugId(node_contact_) << ": failed to add the delete "
                << "refresh task.";
  }
}

void Service::DeleteCallback(KeyValueSignature key_value_signature,
                             protobuf::DeleteRequest request,
                             transport::Info info,
                             RequestAndSignature request_signature,
                             std::string public_key,
                             std::string public_key_validation) {
  if (ValidateAndDelete(key_value_signature, request, info, request_signature,
                        public_key, public_key_validation, false))
    if (request.sender().node_id() != client_node_id_)
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
}

void Service::DeleteRefreshCallback(KeyValueSignature key_value_signature,
                                    protobuf::DeleteRefreshRequest request,
                                    transport::Info info,
                                    RequestAndSignature request_signature,
                                    std::string public_key,
                                    std::string public_key_validation) {
  protobuf::DeleteRequest ori_delete_request;
  ori_delete_request.ParseFromString(request.serialised_delete_request());
  if (ValidateAndDelete(key_value_signature, ori_delete_request, info,
                        request_signature, public_key, public_key_validation,
                        true)) {
    if (request.sender().node_id() != client_node_id_)
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
  }
}

bool Service::ValidateAndDelete(const KeyValueSignature &key_value_signature,
                                const protobuf::DeleteRequest &request,
                                const transport::Info &/*info*/,
                                const RequestAndSignature &request_signature,
                                const std::string &public_key,
                                const std::string &public_key_validation,
                                const bool is_refresh) {
  if (!securifier_->Validate(key_value_signature.value,
                             key_value_signature.signature,
                             request.sender().public_key_id(),
                             public_key,
                             public_key_validation,
                             request.key())) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Failed to validate Delete "
                  << "request for kademlia value (is_refresh = "
                  << std::boolalpha << is_refresh << ")";
    return false;
  }

  if (datastore_->DeleteValue(key_value_signature, request_signature,
                              is_refresh)) {
    return true;
  } else {
    DLOG(WARNING) << DebugId(node_contact_) << ": Failed to delete Kad value.";
    return false;
  }
}

void Service::Downlist(const transport::Info &/*info*/,
                       const protobuf::DownlistNotification &request,
                       transport::Timeout*) {
  if (!node_joined_) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Not joined.";
    return;
  }

  // A sophisticated attacker possibly sent a random downlist.  We only verify
  // the offline status of the nodes in our routing table, and then only if the
  // downlist is <= 2k Contacts (more than this is probably unreasonable).
  if (request.node_ids_size() > 2 * k_) {
    DLOG(WARNING) << DebugId(node_contact_) << ": Downlist size ("
                  << request.node_ids_size() << ") > 2*k (" << 2 * k_ << ")";
    return;
  }

  for (int i = 0; i < request.node_ids_size(); ++i) {
    NodeId id(request.node_ids(i));
    if (id.IsValid())
      routing_table_->Downlist(id);
  }
}

void Service::AddContactToRoutingTable(const Contact &contact,
                                       const transport::Info &info) {
  if (contact.node_id().String() != client_node_id_) {
#ifdef DEBUG
    int result(routing_table_->AddContact(contact,
               RankInfoPtr(new transport::Info(info))));
    if (result != kSuccess)
      DLOG(ERROR) << DebugId(node_contact_) << ": Failed to add contact "
                  << DebugId(contact) << " (result " << result << ")";
#else
    routing_table_->AddContact(contact, RankInfoPtr(new transport::Info(info)));
#endif
  }
}


}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
