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
      ping_down_list_contacts_(new PingDownListContactsPtr::element_type),
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

void Service::Ping(const transport::Info &info,
                   const protobuf::PingRequest &request,
                   protobuf::PingResponse *response,
                   transport::Timeout*) {
  if (request.ping() != "ping")
    return;
  response->set_echo("pong");
  if (request.sender().node_id() != client_node_id_) {
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  }
}

void Service::FindValue(const transport::Info &info,
                        const protobuf::FindValueRequest &request,
                        protobuf::FindValueResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  if (!node_joined_)
    return;
  Contact sender(FromProtobuf(request.sender()));

  // Are we the alternative value holder?
  std::string key(request.key());
  std::vector<std::pair<std::string, std::string>> values_str;
  if (alternative_store_ && (alternative_store_->Has(key))) {
    *(response->mutable_alternative_value_holder()) = ToProtobuf(node_contact_);
    response->set_result(true);
    routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
    return;
  }
  // Do we have the values?
  if (datastore_->GetValues(key, &values_str)) {
    for (unsigned int i = 0; i < values_str.size(); i++) {
      protobuf::SignedValue *signed_value = response->add_signed_values();
      signed_value->set_value(values_str[i].first);
      signed_value->set_signature(values_str[i].second);
    }
    response->set_result(true);
    routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
    return;
  }

  std::vector<Contact> closest_contacts, exclude_contacts(1, sender);
  routing_table_->GetCloseContacts(NodeId(key), k_, exclude_contacts,
                                   &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i) {
    (*response->add_closest_nodes()) = ToProtobuf(closest_contacts[i]);
  }
  response->set_result(true);
  if (sender.node_id().String() != client_node_id_)
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
}

void Service::FindNodes(const transport::Info &info,
                        const protobuf::FindNodesRequest &request,
                        protobuf::FindNodesResponse *response,
                        transport::Timeout*) {
  response->set_result(false);
  if (!node_joined_)
    return;
  NodeId key(request.key());
  if (!key.IsValid())
    return;
  Contact sender(FromProtobuf(request.sender()));
  std::vector<Contact> closest_contacts, exclude_contacts;
  exclude_contacts.push_back(sender);
  // the repsonse will always be the k-closest contacts
  // if the target is contained in the routing table, then it shall be one of
  // the k-closest. Then the send will interate the result, if find the target
  // then stop the search.
  routing_table_->GetCloseContacts(key, k_, exclude_contacts,
                                   &closest_contacts);
  for (size_t i = 0; i < closest_contacts.size(); ++i) {
    (*response->add_closest_nodes()) = ToProtobuf(closest_contacts[i]);
  }
  response->set_result(true);
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
  if (!node_joined_) {
    return;
  }

  if (!securifier_ || message.empty() ||
      (message_signature.empty() && !securifier_->kSigningKeyId().empty())) {
    return;
  }
  // Check if same private key signs other values under same key in datastore
  std::vector<std::pair<std::string, std::string>> values;
  if (datastore_->GetValues(request.key(), &values)) {
    if (!crypto::AsymCheckSig(values[0].first, values[0].second,
                              request.sender().public_key())) {
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
      return;
    }
  }

  KeyValueSignature key_value_signature(request.key(),
                                        request.signed_value().value(),
                                        request.signed_value().signature());

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
  }
}

void Service::StoreRefresh(const transport::Info &info,
                           const protobuf::StoreRefreshRequest &request,
                           protobuf::StoreRefreshResponse *response,
                           transport::Timeout*) {
  response->set_result(false);
  if (!node_joined_)
    return;
  if (request.serialised_store_request().empty() ||
      request.serialised_store_request_signature().empty() || !securifier_) {
    DLOG(WARNING) << "StoreRefresh Input Error";
    return;
  }

  protobuf::StoreRequest ori_store_request;
  ori_store_request.ParseFromString(request.serialised_store_request());

  // Check if same private key signs other values under same key in datastore
  std::vector<std::pair<std::string, std::string>> values;
  if (datastore_->GetValues(ori_store_request.key(), &values)) {
    if (!crypto::AsymCheckSig(values[0].first, values[0].second,
                              ori_store_request.sender().public_key())) {
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
      return;
    }
  }

  KeyValueSignature key_value_signature(ori_store_request.key(),
                        ori_store_request.signed_value().value(),
                        ori_store_request.signed_value().signature());
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
  }
}

void Service::StoreCallback(KeyValueSignature key_value_signature,
                            protobuf::StoreRequest request,
                            transport::Info info,
                            RequestAndSignature request_signature,
                            std::string public_key,
                            std::string public_key_validation) {
  // no matter the store succeed or not, once validated, the sender shall
  // always be add into the routing table
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
  if (!crypto::AsymCheckSig(request_signature.first, request_signature.second,
                            public_key)) {
    DLOG(WARNING) << "Failed to validate request_signature";
    return;
  }
  // no matter the store succeed or not, once validated, the sender shall
  // always be add into the routing table
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
                             request.key() ) ) {
    DLOG(WARNING) << "Failed to validate Store request for kademlia value"
                  << " (is_refresh = " << is_refresh << " )";
    return false;
  }
  return datastore_->StoreValue(key_value_signature,
      boost::posix_time::seconds(request.ttl()), request_signature, public_key,
      is_refresh) == kSuccess;
}

void Service::Delete(const transport::Info &info,
                     const protobuf::DeleteRequest &request,
                     const std::string &message,
                     const std::string &message_signature,
                     protobuf::DeleteResponse *response,
                     transport::Timeout*) {
  response->set_result(false);
  if (!node_joined_ || !securifier_)
    return;
  if (!securifier_ || message.empty() ||
      (message_signature.empty() && !securifier_->kSigningKeyId().empty())) {
    DLOG(WARNING) << "Delete Input Error";
    return;
  }

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasKey(request.key()))
    return;
  // Check if same private key signs other values under same key in datastore
  std::vector<std::pair<std::string, std::string>> values;
  if (datastore_->GetValues(request.key(), &values)) {
    if (!crypto::AsymCheckSig(values[0].first, values[0].second,
                              request.sender().public_key())) {
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
      return;
    }
  }
    // Only the signer of the value can delete it.
    // this will be done in message_handler, no need to do it here
//   if (!crypto::AsymCheckSig(message, message_signature,
//                             request.sender().public_key()))
//     return;
  KeyValueSignature key_value_signature(request.key(),
      request.signed_value().value(), request.signed_value().signature());
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
  }
}

void Service::DeleteRefresh(const transport::Info &info,
                            const protobuf::DeleteRefreshRequest &request,
                            protobuf::DeleteRefreshResponse *response,
                            transport::Timeout*) {
  response->set_result(false);
  if (!node_joined_ || !securifier_)
    return;
  if (request.serialised_delete_request().empty() ||
      request.serialised_delete_request_signature().empty()) {
    DLOG(WARNING) << "DeleteFresh Input Error";
    return;
  }
  protobuf::DeleteRequest ori_delete_request;
  ori_delete_request.ParseFromString(request.serialised_delete_request());

  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasKey(ori_delete_request.key()))
    return;
  // Check if same private key signs other values under same key in datastore
  std::vector<std::pair<std::string, std::string>> values;
  if (datastore_->GetValues(ori_delete_request.key(), &values)) {
    if (!crypto::AsymCheckSig(values[0].first, values[0].second,
                              ori_delete_request.sender().public_key())) {
      routing_table_->AddContact(FromProtobuf(request.sender()),
                                 RankInfoPtr(new transport::Info(info)));
      return;
    }
  }

  KeyValueSignature key_value_signature(ori_delete_request.key(),
                        ori_delete_request.signed_value().value(),
                            ori_delete_request.signed_value().signature());
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
  }
}

void Service::DeleteCallback(KeyValueSignature key_value_signature,
                             protobuf::DeleteRequest request,
                             transport::Info info,
                             RequestAndSignature request_signature,
                             std::string public_key,
                             std::string public_key_validation) {
  // no matter the store succeed or not, once validated, the sender shall
  // always be add into the routing table
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
  if (!crypto::AsymCheckSig(request_signature.first, request_signature.second,
                            public_key)) {
    DLOG(WARNING) << "Failed to validate request_signature";
    return;
  }
  // no matter the store succeed or not, once validated, the sender shall
  // always be add into the routing table
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
                             request.key() ) ) {
    DLOG(WARNING) << "Failed to validate Delete request for kademlia value"
                  << " (is_refresh = " << is_refresh << " )";
                 
    return false;
  }

  if (!datastore_->DeleteValue(key_value_signature,
                               request_signature, is_refresh))
    DLOG(WARNING) << "Failed to delete kademlia value";
  return true;
}

void Service::Downlist(const transport::Info &/*info*/,
                       const protobuf::DownlistNotification &request,
                       transport::Timeout*) {
  if (!node_joined_)
    return;
  // A sophisticated attacker possibly sent a random downlist. We only verify
  // the offline status of the nodes in our routing table.
  for (int i = 0; i < request.node_ids_size(); ++i) {
    NodeId id(request.node_ids(i));
    if (id.IsValid()) {
      Contact contact;
      routing_table_->GetContact(id, &contact);
  // We can have a vector of contacts in the signal's signature and only fire
  // it once, (and hence the node_impl has to iterate and ping each).
  // Or we just fire the signal once per ID.
  // As the normal case will be only one node per Downlist RPC, so option 2 is
  // adapted by far.
      if (contact != Contact())
        (*ping_down_list_contacts_)(contact);
    }
  }
}

PingDownListContactsPtr Service::GetPingDownListSignalHandler() {
  return this->ping_down_list_contacts_;
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
