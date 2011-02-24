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
                 std::shared_ptr<DataStore> data_store,
                 AlternativeStorePtr alternative_store,
                 SecurifierPtr securifier,
                 const boost::uint16_t &k)
    : routing_table_(routing_table),
      datastore_(data_store),
      alternative_store_(alternative_store),
      securifier_(securifier),
      node_joined_(false),
      node_contact_(),
      k_(k),
      ping_down_list_contacts_(new PingDownListContactsPtr::element_type) {}

Service::Service(std::shared_ptr<RoutingTable> routing_table,
                 std::shared_ptr<DataStore> data_store,
                 AlternativeStorePtr alternative_store,
                 SecurifierPtr securifier)
    : routing_table_(routing_table),
      datastore_(data_store),
      alternative_store_(alternative_store),
      securifier_(securifier),
      node_joined_(false),
      node_contact_(),
      k_(16U),
      ping_down_list_contacts_(new PingDownListContactsPtr::element_type) {}

Service::~Service() {
}

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
  message_handler->on_store_refresh_request()->connect(
      MessageHandler::StoreRefreshReqSigPtr::element_type::slot_type(
          &Service::StoreRefresh, this, _1, _2, _3).track(shared_from_this()));
  message_handler->on_delete_request()->connect(
      MessageHandler::DeleteReqSigPtr::element_type::slot_type(
          &Service::Delete, this, _1, _2, _3, _4, _5).track(
              shared_from_this()));
  message_handler->on_delete_refresh_request()->connect(
      MessageHandler::DeleteRefreshReqSigPtr::element_type::slot_type(
          &Service::DeleteRefresh, this, _1, _2, _3).track(
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
  if ((alternative_store_ != NULL) && (alternative_store_->Has(key))) {
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
  routing_table_->AddContact(sender, RankInfoPtr(new transport::Info(info)));
}

void Service::Store(const transport::Info &info,
                    const protobuf::StoreRequest &request,
                    const std::string &message,
                    const std::string &message_signature,
                    protobuf::StoreResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;

  if (message_signature.empty() || message.empty() || !securifier_) {
    DLOG(WARNING) << "Input Error" << std::endl;
    return;
  }
  KeyValueSignature key_value_signature(request.key(), message,
                                        message_signature);
  GetPublicKeyAndValidationCallback cb = boost::bind(
      &Service::StoreCallback, this, key_value_signature, request, info,
      response, _1, _2);
  securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(), cb);
}

void Service::StoreRefresh(const transport::Info &info,
                           const protobuf::StoreRefreshRequest &request,
                           protobuf::StoreRefreshResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;
  KeyValueSignature key_value_signature(
      request.sender().node_id(),
      request.serialised_store_request(),
      request.serialised_store_request_signature());
  GetPublicKeyAndValidationCallback cb = boost::bind(
      &Service::StoreRefreshCallback, this, key_value_signature, request, info,
      response, _1, _2);
  securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(), cb);
}

void Service::StoreCallback (const KeyValueSignature key_value_signature,
                             const protobuf::StoreRequest request,
                             const transport::Info info,
                             protobuf::StoreResponse *response,
                             const std::string public_key,
                             const std::string public_key_validation) {
  if (!securifier_->Validate(
          key_value_signature.value,
          key_value_signature.signature, request.sender().public_key_id(),
          public_key, public_key_validation, request.key() ) ) {
    DLOG(WARNING) << "Failed to validate Store request for kademlia value"
                  << std::endl;
    return;
  }
  RequestAndSignature request_signature(request.signed_value().value(),
                                        request.signed_value().signature());  
  bool result(false);
  bool is_refresh(false);
  result = datastore_->StoreValue(key_value_signature,
                                  boost::posix_time::seconds(request.ttl()),
                                  request_signature,
                                  public_key,
                                  is_refresh);
  if (result) {
    response->set_result(true);
  } else {
    DLOG(WARNING) << "Failed to store kademlia value" << std::endl;
  }
  // no matter the store succeed or not, the send shall always be add into
  // the routing table
  routing_table_->AddContact(FromProtobuf(request.sender()),
                             RankInfoPtr(new transport::Info(info)));
}

void Service::StoreRefreshCallback (const KeyValueSignature key_value_signature,
                                    const protobuf::StoreRefreshRequest request,
                                    const transport::Info info,
                                    protobuf::StoreRefreshResponse *response,
                                    const std::string public_key,
                                    const std::string public_key_validation) {
  protobuf::StoreRequest ori_store_request;
  ori_store_request.ParseFromString(request.serialised_store_request());
  if (!securifier_->Validate(
          key_value_signature.value, key_value_signature.signature,
          request.sender().public_key_id(), public_key,
          public_key_validation, ori_store_request.key() ) ) {
    DLOG(WARNING)
        << "Failed to validate Refresh(store) request for kademlia value"
        << std::endl;
    return;
  }
  RequestAndSignature request_signature(
      ori_store_request.signed_value().value(),
      ori_store_request.signed_value().signature());
  bool result(false);
  bool is_refresh(true);
  result = datastore_->StoreValue(key_value_signature,
      boost::posix_time::seconds(ori_store_request.ttl()),
      request_signature, public_key, is_refresh);
  if (result) {
    response->set_result(true);
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  } else {
    DLOG(WARNING) << "Failed to refresh(Store) kademlia value" << std::endl;
  }
}

void Service::Delete(const transport::Info &info,
                     const protobuf::DeleteRequest &request,
                     const std::string &message,
                     const std::string &message_signature,
                     protobuf::DeleteResponse *response) {
  response->set_result(false);
  if (!node_joined_ || securifier_ == NULL)
    return;
  // Avoid CPU-heavy validation work if key doesn't exist.
  if (!datastore_->HasKey(request.key()))
    return;
  KeyValueSignature key_value_signature(request.key(), message,
                                        message_signature);
  GetPublicKeyAndValidationCallback cb = boost::bind(
      &Service::DeleteCallback, this, key_value_signature, request, info,
      response, _1, _2);
  securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(), cb);
}

void Service::DeleteRefresh(const transport::Info &info,
                            const protobuf::DeleteRefreshRequest &request,
                            protobuf::DeleteRefreshResponse *response) {
  response->set_result(false);
  if (!node_joined_)
    return;
  KeyValueSignature key_value_signature(
      request.sender().node_id(),
      request.serialised_delete_request(),
      request.serialised_delete_request_signature());
  GetPublicKeyAndValidationCallback cb = boost::bind(
      &Service::DeleteRefreshCallback, this, key_value_signature, request, info,
      response, _1, _2);
  securifier_->GetPublicKeyAndValidation(request.sender().public_key_id(), cb);  
}

void Service::DeleteCallback (const KeyValueSignature key_value_signature,
                              const protobuf::DeleteRequest request,
                              const transport::Info info,
                              protobuf::DeleteResponse *response,
                              const std::string public_key,
                              const std::string public_key_validation) {
  if  ( !securifier_->Validate(
          key_value_signature.value,
          key_value_signature.signature, request.sender().public_key_id(),
          public_key, public_key_validation, request.key() ) ) {
    DLOG(WARNING) << "Failed to validate Delete request for kademlia value"
                  << std::endl;
    return;
  }
  // Only the signer of the value can delete it.
  // this shall be validated by the secuifier->validate
//   if (!crypto::AsymCheckSig(message, message_signature, request.public_key()))
//     return;
  
  RequestAndSignature request_signature(request.signed_value().value(),
                                        request.signed_value().signature());
  bool result(false);
  bool is_refresh(false);
  result = datastore_->DeleteValue(key_value_signature,
                              request_signature, is_refresh);
  if (result) {
    response->set_result(true);
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  } else {
    DLOG(WARNING) << "Failed to delete kademlia value" << std::endl;
  }
}

void Service::DeleteRefreshCallback (
    const KeyValueSignature key_value_signature,
    const protobuf::DeleteRefreshRequest request,
    const transport::Info info,
    protobuf::DeleteRefreshResponse *response,
    const std::string public_key,
    const std::string public_key_validation) {
  protobuf::DeleteRequest ori_delete_request;
  ori_delete_request.ParseFromString(request.serialised_delete_request());
  if  ( !securifier_->Validate(
          key_value_signature.value, key_value_signature.signature,
          request.sender().public_key_id(), public_key,
          public_key_validation, ori_delete_request.key() ) ) {
    DLOG(WARNING)
        << "Failed to validate Refresh(Delete) request for kademlia value"
        << std::endl;
    return;
  }
  // Only the signer of the value can delete it.
  // this shall be validated by the secuifier->validate
//   if (!crypto::AsymCheckSig(message, message_signature, request.public_key()))
//     return;

  RequestAndSignature request_signature(
      ori_delete_request.signed_value().value(),
      ori_delete_request.signed_value().signature());
  bool result(false);
  bool is_refresh(true);
  result = datastore_->DeleteValue(key_value_signature,
                                   request_signature, is_refresh);
  if (result) {
    response->set_result(true);
    routing_table_->AddContact(FromProtobuf(request.sender()),
                               RankInfoPtr(new transport::Info(info)));
  } else {
    DLOG(WARNING) << "Failed to delete kademlia value" << std::endl;
  }
}

void Service::Downlist(const transport::Info &info,
                       const protobuf::DownlistNotification &request) {
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
      if (contact != Contact() )
        (*ping_down_list_contacts_)(contact);
    }
  }
}

PingDownListContactsPtr  Service::GetPingOldestContactSingalHandler() {
  return this->ping_down_list_contacts_;
}

}  // namespace kademlia

}  // namespace maidsafe
