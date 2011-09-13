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

#ifndef MAIDSAFE_DHT_KADEMLIA_RPCS_H_
#define MAIDSAFE_DHT_KADEMLIA_RPCS_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/tuple/tuple.hpp"
#include "maidsafe/common/utils.h"

#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/dht/kademlia/rpcs.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "maidsafe/dht/kademlia/securifier.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/rpcs_objects.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/log.h"

namespace arg = std::placeholders;


namespace maidsafe {

namespace dht {

namespace kademlia {

class MessageHandler;
class NodeId;

namespace protobuf {
class PingResponse;
class FindValueResponse;
class FindNodesResponse;
class StoreResponse;
class StoreRefreshResponse;
class DeleteResponse;
class DeleteRefreshResponse;
class UpdateResponse;
}  // namespace protobuf

typedef std::function<void(RankInfoPtr, const int&)> RpcPingFunctor,
                                                     RpcStoreFunctor,
                                                     RpcStoreRefreshFunctor,
                                                     RpcDeleteFunctor,
                                                     RpcDeleteRefreshFunctor;
typedef std::function<void(RankInfoPtr,
                           const int&,
                           const std::vector<ValueAndSignature>&,
                           const std::vector<Contact>&,
                           const Contact&)> RpcFindValueFunctor;
typedef std::function<void(RankInfoPtr,
                           const int&,
                           const std::vector<Contact>&)> RpcFindNodesFunctor;

struct RpcsFailurePeer {
 public:
  RpcsFailurePeer() : peer(), rpcs_failure(1) {}
  Contact peer;
  uint16_t rpcs_failure;
};

template <typename TransportType>
class Rpcs {
 public:
  Rpcs(AsioService &asio_service, SecurifierPtr default_securifier)  // NOLINT (Fraser)
      : asio_service_(asio_service),
        kFailureTolerance_(2),
        contact_(),
        default_securifier_(default_securifier),
        connected_objects_() {}
  virtual ~Rpcs() {}
  virtual void Ping(SecurifierPtr securifier,
                    const Contact &peer,
                    RpcPingFunctor callback);
  virtual void FindValue(const Key &key,
                         const uint16_t &nodes_requested,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         RpcFindValueFunctor callback);
  virtual void FindNodes(const Key &key,
                         const uint16_t &nodes_requested,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         RpcFindNodesFunctor callback);
  virtual void Store(const Key &key,
                     const std::string &value,
                     const std::string &signature,
                     const boost::posix_time::seconds &ttl,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     RpcStoreFunctor callback);
  virtual void StoreRefresh(
      const std::string &serialised_store_request,
      const std::string &serialised_store_request_signature,
      SecurifierPtr securifier,
      const Contact &peer,
      RpcStoreRefreshFunctor callback);
  virtual void Delete(const Key &key,
                      const std::string &value,
                      const std::string &signature,
                      SecurifierPtr securifier,
                      const Contact &peer,
                      RpcDeleteFunctor callback);
  virtual void DeleteRefresh(
      const std::string &serialised_delete_request,
      const std::string &serialised_delete_request_signature,
      SecurifierPtr securifier,
      const Contact &peer,
      RpcDeleteRefreshFunctor callback);
  virtual void Downlist(const std::vector<NodeId> &node_ids,
                        SecurifierPtr securifier,
                        const Contact &peer);
  void set_contact(const Contact &contact) { contact_ = contact; }

  virtual void Prepare(SecurifierPtr securifier,
                       TransportPtr &transport,
                       MessageHandlerPtr &message_handler);

  std::pair<std::string, std::string> MakeStoreRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    const boost::posix_time::seconds &ttl,
    SecurifierPtr securifier);

  std::pair<std::string, std::string> MakeDeleteRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    SecurifierPtr securifier);

 protected:
  AsioService &asio_service_;
  const uint16_t kFailureTolerance_;

 private:
  Rpcs(const Rpcs&);
  Rpcs& operator=(const Rpcs&);
  void PingCallback(const std::string &random_data,
                    const transport::TransportCondition &transport_condition,
                    const transport::Info &info,
                    const protobuf::PingResponse &response,
                    const uint32_t &index,
                    RpcPingFunctor callback,
                    const std::string &message,
                    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindValueCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindValueResponse &response,
      const uint32_t &index,
      RpcFindValueFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void FindNodesCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::FindNodesResponse &response,
      const uint32_t &index,
      RpcFindNodesFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void StoreCallback(const transport::TransportCondition &transport_condition,
                     const transport::Info &info,
                     const protobuf::StoreResponse &response,
                     const uint32_t &index,
                     RpcStoreFunctor callback,
                     const std::string &message,
                     std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void StoreRefreshCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::StoreRefreshResponse &response,
      const uint32_t &index,
      RpcStoreRefreshFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void DeleteCallback(const transport::TransportCondition &transport_condition,
                      const transport::Info &info,
                      const protobuf::DeleteResponse &response,
                      const uint32_t &index,
                      RpcDeleteFunctor callback,
                      const std::string &message,
                      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  void DeleteRefreshCallback(
      const transport::TransportCondition &transport_condition,
      const transport::Info &info,
      const protobuf::DeleteRefreshResponse &response,
      const uint32_t &index,
      RpcDeleteRefreshFunctor callback,
      const std::string &message,
      std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer);

  Contact contact_;
  SecurifierPtr default_securifier_;
  ConnectedObjectsList connected_objects_;
};



template <typename TransportType>
void Rpcs<TransportType>::Ping(SecurifierPtr securifier,
                               const Contact &peer,
                               RpcPingFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::PingRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  std::string random_data(RandomString(50 + (RandomUint32() % 50)));
  request.set_ping(random_data);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;
  std::string message(message_handler->WrapMessage(request, peer.public_key()));

  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_ping_response()->connect(
      std::bind(&Rpcs::PingCallback, this, random_data, transport::kSuccess,
                arg::_1, arg::_2, object_indx, callback, message,
                rpcs_failure_peer));
  message_handler->on_error()->connect(
      std::bind(&Rpcs::PingCallback, this, random_data, arg::_1,
                transport::Info(), protobuf::PingResponse(), object_indx,
                callback, message, rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " PING to " << DebugId(peer);
  transport->Send(message,
                  peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::FindValue(const Key &key,
                                    const uint16_t &nodes_requested,
                                    SecurifierPtr securifier,
                                    const Contact &peer,
                                    RpcFindValueFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindValueRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  request.set_num_nodes_requested(nodes_requested);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_find_value_response()->connect(std::bind(
      &Rpcs::FindValueCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::FindValueCallback, this, arg::_1, transport::Info(),
      protobuf::FindValueResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " FIND_VALUE to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::FindNodes(const Key &key,
                                    const uint16_t &nodes_requested,
                                    SecurifierPtr securifier,
                                    const Contact &peer,
                                    RpcFindNodesFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindNodesRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  request.set_num_nodes_requested(nodes_requested);
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_find_nodes_response()->connect(std::bind(
      &Rpcs::FindNodesCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::FindNodesCallback, this, arg::_1, transport::Info(),
      protobuf::FindNodesResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " FIND_NODES to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::Store(const Key &key,
                                const std::string &value,
                                const std::string &signature,
                                const boost::posix_time::seconds &ttl,
                                SecurifierPtr securifier,
                                const Contact &peer,
                                RpcStoreFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::StoreRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature);
  request.set_ttl(ttl.is_pos_infinity() ? -1 : ttl.total_seconds());
  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_store_response()->connect(std::bind(
      &Rpcs::StoreCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::StoreCallback, this, arg::_1, transport::Info(),
      protobuf::StoreResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " STORE to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::StoreRefresh(
    const std::string &serialised_store_request,
    const std::string &serialised_store_request_signature,
    SecurifierPtr securifier,
    const Contact &peer,
    RpcStoreRefreshFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::StoreRefreshRequest request;
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_serialised_store_request(serialised_store_request);
  request.set_serialised_store_request_signature(
      serialised_store_request_signature);
  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_store_refresh_response()->connect(std::bind(
      &Rpcs::StoreRefreshCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::StoreRefreshCallback, this, arg::_1, transport::Info(),
      protobuf::StoreRefreshResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " STORE_REFRESH to "
             << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::Delete(const Key &key,
                                 const std::string &value,
                                 const std::string &signature,
                                 SecurifierPtr securifier,
                                 const Contact &peer,
                                 RpcDeleteFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::DeleteRequest request;
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature);
  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_delete_response()->connect(std::bind(
      &Rpcs::DeleteCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::DeleteCallback, this, arg::_1, transport::Info(),
      protobuf::DeleteResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " DELETE to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::DeleteRefresh(
    const std::string &serialised_delete_request,
    const std::string &serialised_delete_request_signature,
    SecurifierPtr securifier,
    const Contact &peer,
    RpcDeleteRefreshFunctor callback) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);
  uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::DeleteRefreshRequest request;
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_serialised_delete_request(serialised_delete_request);
  request.set_serialised_delete_request_signature(
      serialised_delete_request_signature);
  std::string message =
      message_handler->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  message_handler->on_delete_refresh_response()->connect(std::bind(
      &Rpcs::DeleteRefreshCallback, this, transport::kSuccess, arg::_1, arg::_2,
      object_indx, callback, message, rpcs_failure_peer));
  message_handler->on_error()->connect(std::bind(
      &Rpcs::DeleteRefreshCallback, this, arg::_1, transport::Info(),
      protobuf::DeleteRefreshResponse(), object_indx, callback, message,
      rpcs_failure_peer));
  DLOG(INFO) << "\t" << DebugId(contact_) << " DELETE_REFRESH to "
             << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::Downlist(const std::vector<NodeId> &node_ids,
                                   SecurifierPtr securifier,
                                   const Contact &peer) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(securifier, transport, message_handler);

  protobuf::DownlistNotification notification;
  *notification.mutable_sender() = ToProtobuf(contact_);
  for (size_t i = 0; i < node_ids.size(); ++i)
    notification.add_node_ids(node_ids[i].String());
  std::string message =
      message_handler->WrapMessage(notification, peer.public_key());
  DLOG(INFO) << "\t" << DebugId(contact_) << " DOWNLIST to " << DebugId(peer);
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

template <typename TransportType>
void Rpcs<TransportType>::PingCallback(
    const std::string &random_data,
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::PingResponse &response,
    const uint32_t &index,
    RpcPingFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(message,
                    rpcs_failure_peer->peer.PreferredEndpoint(),
                    transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.echo() == random_data) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    } else {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
    }
  }
}

template <typename TransportType>
void Rpcs<TransportType>::FindValueCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindValueResponse &response,
    const uint32_t &index,
    RpcFindValueFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
    (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);

    std::vector<ValueAndSignature> values_and_signatures;
    std::vector<Contact> contacts;
    Contact alternative_value_holder;

    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition,
               values_and_signatures, contacts, alternative_value_holder);
      return;
    }
    if (!response.IsInitialized() || !response.result()) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError,
               values_and_signatures, contacts, alternative_value_holder);
      return;
    }

    if (response.has_alternative_value_holder()) {
      alternative_value_holder =
          FromProtobuf(response.alternative_value_holder());
      callback(RankInfoPtr(new transport::Info(info)),
               kFoundAlternativeStoreHolder, values_and_signatures, contacts,
               alternative_value_holder);
      return;
    }

    if (response.signed_values_size() != 0) {
      for (int i = 0; i < response.signed_values_size(); ++i) {
        values_and_signatures.push_back(
            std::make_pair(response.signed_values(i).value(),
                           response.signed_values(i).signature()));
      }
      callback(RankInfoPtr(new transport::Info(info)), kSuccess,
               values_and_signatures, contacts, alternative_value_holder);
      return;
    }

    if (response.closest_nodes_size() != 0) {
      for (int i = 0; i < response.closest_nodes_size(); ++i)
        contacts.push_back(FromProtobuf(response.closest_nodes(i)));
      callback(RankInfoPtr(new transport::Info(info)), kFailedToFindValue,
               values_and_signatures, contacts, alternative_value_holder);
      return;
    }
    callback(RankInfoPtr(new transport::Info(info)), kIterativeLookupFailed,
             values_and_signatures, contacts, alternative_value_holder);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::FindNodesCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindNodesResponse &response,
    const uint32_t &index,
    RpcFindNodesFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    std::vector<Contact> contacts;
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition,
               contacts);
      return;
    }
    if (!response.IsInitialized() || !response.result()) {
      callback(RankInfoPtr(new transport::Info(info)), transport::kError,
               contacts);
      return;
    }

    if (response.closest_nodes_size() != 0) {
      for (int i = 0; i < response.closest_nodes_size(); ++i)
        contacts.push_back(FromProtobuf(response.closest_nodes(i)));
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess,
               contacts);
      return;
    }
    callback(RankInfoPtr(new transport::Info(info)), kIterativeLookupFailed,
             contacts);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::StoreCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreResponse &response,
    const uint32_t &index,
    RpcStoreFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.result())
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    else
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::StoreRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreRefreshResponse &response,
    const uint32_t &index,
    RpcStoreRefreshFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.result())
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    else
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::DeleteCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteResponse &response,
    const uint32_t &index,
    RpcDeleteFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.result())
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    else
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::DeleteRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteRefreshResponse &response,
    const uint32_t &index,
    RpcDeleteRefreshFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance_)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);
    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition);
      return;
    }
    if (response.IsInitialized() && response.result())
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    else
      callback(RankInfoPtr(new transport::Info(info)), transport::kError);
  }
}

template <typename TransportType>
void Rpcs<TransportType>::Prepare(SecurifierPtr securifier,
                                  TransportPtr &transport,
                                  MessageHandlerPtr &message_handler) {
  transport.reset(new TransportType(asio_service_));
  message_handler.reset(new MessageHandler(securifier ? securifier :
                                                        default_securifier_));
  // Connect message handler to transport for incoming raw messages
  transport->on_message_received()->connect(
      transport::OnMessageReceived::element_type::slot_type(
          &MessageHandler::OnMessageReceived, message_handler.get(),
          _1, _2, _3, _4).track_foreign(message_handler));
  transport->on_error()->connect(
      transport::OnError::element_type::slot_type(
          &MessageHandler::OnError, message_handler.get(),
          _1, _2).track_foreign(message_handler));
}

template <typename T>
std::pair<std::string, std::string> Rpcs<T>::MakeStoreRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    const boost::posix_time::seconds &ttl,
    SecurifierPtr securifier) {
  MessageHandlerPtr message_handler(new MessageHandler(securifier));

  protobuf::StoreRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());

  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature);
  request.set_ttl(ttl.is_pos_infinity() ? -1 : ttl.total_seconds());
  std::string message(request.SerializeAsString());
  std::string message_signature(securifier->Sign(
        boost::lexical_cast<std::string>(kStoreRequest) + message));
  return std::make_pair(message, message_signature);
}

template <typename T>
std::pair<std::string, std::string> Rpcs<T>::MakeDeleteRequestAndSignature(
    const Key &key,
    const std::string &value,
    const std::string &signature,
    SecurifierPtr securifier) {
  MessageHandlerPtr message_handler(new MessageHandler(securifier));

  protobuf::DeleteRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());

  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature);

  std::string message(request.SerializeAsString());
  std::string message_signature(securifier->Sign(
        boost::lexical_cast<std::string>(kDeleteRequest) + message));
  return std::make_pair(message, message_signature);
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_RPCS_H_
