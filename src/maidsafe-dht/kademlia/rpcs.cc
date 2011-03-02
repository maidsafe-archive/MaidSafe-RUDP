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

#include "maidsafe-dht/kademlia/rpcs.h"
#include "maidsafe-dht/common/securifier.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/message_handler.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/transport/tcp_transport.h"

// TODO(Fraser#5#): 2011-01-30 - Handle sending to port-restricted peers.
namespace maidsafe {

namespace kademlia {

void Rpcs::Ping(SecurifierPtr securifier,
                const Contact &peer,
                PingFunctor callback,
                TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::PingRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  std::string random_data(RandomString(50 + (RandomUint32() % 50)));
  request.set_ping(random_data);
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_ping_response()->connect(boost::bind(
      &Rpcs::PingCallback, this, random_data, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::PingCallback, this, "", _1, transport::Info(),
      protobuf::PingResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::FindValue(const Key &key,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     FindValueFunctor callback,
                     TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::FindValueRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_find_value_response()->connect(boost::bind(
      &Rpcs::FindValueCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::FindValueCallback, this, _1, transport::Info(),
      protobuf::FindValueResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::FindNodes(const Key &key,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     FindNodesFunctor callback,
                     TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::FindNodesRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_find_nodes_response()->connect(boost::bind(
      &Rpcs::FindNodesCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::FindNodesCallback, this, _1, transport::Info(),
      protobuf::FindNodesResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::Store(const Key &key,
                 const std::string &value,
                 const std::string &signature,
                 const boost::posix_time::seconds &ttl,
                 SecurifierPtr securifier,
                 const Contact &peer,
                 StoreFunctor callback,
                 TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::StoreRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature.empty() ? securifier->Sign(value) :
                              signature);
  request.set_ttl(ttl.is_pos_infinity() ? -1 : ttl.total_seconds());
  request.set_signing_public_key_id(securifier->kSigningKeyId());
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_store_response()->connect(boost::bind(
      &Rpcs::StoreCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::StoreCallback, this, _1, transport::Info(),
      protobuf::StoreResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::StoreRefresh(const std::string &serialised_store_request,
                        const std::string &serialised_store_request_signature,
                        SecurifierPtr securifier,
                        const Contact &peer,
                        StoreRefreshFunctor callback,
                        TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::StoreRefreshRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_serialised_store_request(serialised_store_request);
  request.set_serialised_store_request_signature(
      serialised_store_request_signature);
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_store_refresh_response()->connect(boost::bind(
      &Rpcs::StoreRefreshCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::StoreRefreshCallback, this, _1, transport::Info(),
      protobuf::StoreRefreshResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::Delete(const Key &key,
                  const std::string &value,
                  const std::string &signature,
                  SecurifierPtr securifier,
                  const Contact &peer,
                  DeleteFunctor callback,
                  TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::DeleteRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature.empty() ? securifier->Sign(value) :
                              signature);
  request.set_signing_public_key_id(securifier->kSigningKeyId());
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_delete_response()->connect(boost::bind(
      &Rpcs::DeleteCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::DeleteCallback, this, _1, transport::Info(),
      protobuf::DeleteResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::DeleteRefresh(const std::string &serialised_delete_request,
                         const std::string &serialised_delete_request_signature,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         DeleteRefreshFunctor callback,
                         TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::DeleteRefreshRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_serialised_delete_request(serialised_delete_request);
  request.set_serialised_delete_request_signature(
      serialised_delete_request_signature);
  std::string message =
      connected_objects.get<1>()->WrapMessage(request, peer.public_key());
  // Connect callback to message handler for incoming parsed response or error
  connected_objects.get<1>()->on_delete_refresh_response()->connect(boost::bind(
      &Rpcs::DeleteRefreshCallback, this, transport::kSuccess, _1, _2,
      connected_objects, callback));
  connected_objects.get<1>()->on_error()->connect(boost::bind(
      &Rpcs::DeleteRefreshCallback, this, _1, transport::Info(),
      protobuf::DeleteRefreshResponse(), connected_objects, callback));
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::Downlist(const std::vector<NodeId> &node_ids,
                    SecurifierPtr securifier,
                    const Contact &peer,
                    TransportType type) {
  Rpcs::ConnectedObjects connected_objects(Prepare(type, securifier));
  protobuf::DownlistNotification notification;
  *notification.mutable_sender() = ToProtobuf(contact_);
  for (size_t i = 0; i < node_ids.size(); ++i)
    notification.add_node_ids(node_ids[i].String());
  std::string message =
      connected_objects.get<1>()->WrapMessage(notification, peer.public_key());
  connected_objects.get<0>()->Send(message, peer.PreferredEndpoint(),
                                   transport::kDefaultInitialTimeout);
}

void Rpcs::PingCallback(
    const std::string &random_data,
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::PingResponse &response,
    ConnectedObjects /*connected_objects*/,
    PingFunctor callback) {
  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)),
                    transport_condition);
  if (response.IsInitialized() && response.echo() == random_data)
    callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
  else
    callback(RankInfoPtr(new transport::Info(info)), -1);
}

void Rpcs::FindValueCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindValueResponse &response,
    ConnectedObjects /*connected_objects*/,
    FindValueFunctor callback) {
  std::vector<std::string> values;
  std::vector<Contact> contacts;
  Contact alternative_value_holder;

  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)), transport_condition,
                    values, contacts, alternative_value_holder);

  if (!response.IsInitialized() || !response.result())
    return callback(RankInfoPtr(new transport::Info(info)), -1, values,
                    contacts, alternative_value_holder);

  for (int i = 0; i < response.signed_values_size(); ++i)
    values.push_back(response.signed_values(i).value());

  for (int i = 0; i < response.closest_nodes_size(); ++i)
    contacts.push_back(FromProtobuf(response.closest_nodes(i)));

  if (response.has_alternative_value_holder()) {
    alternative_value_holder =
        FromProtobuf(response.alternative_value_holder());
  }

  callback(RankInfoPtr(new transport::Info(info)), transport_condition, values,
           contacts, alternative_value_holder);
}

void Rpcs::FindNodesCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindNodesResponse &response,
    ConnectedObjects /*connected_objects*/,
    FindNodesFunctor callback) {
  std::vector<Contact> contacts;

  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)), transport_condition,
                    contacts);

  if (!response.IsInitialized() || !response.result())
    return callback(RankInfoPtr(new transport::Info(info)), -1, contacts);

  for (int i = 0; i < response.closest_nodes_size(); ++i)
    contacts.push_back(FromProtobuf(response.closest_nodes(i)));

  callback(RankInfoPtr(new transport::Info(info)), transport_condition,
                       contacts);
}

void Rpcs::StoreCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreResponse &response,
    ConnectedObjects /*connected_objects*/,
    StoreFunctor callback) {
  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)),
                    transport_condition);
  if (response.IsInitialized() && response.result())
    callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
  else
    callback(RankInfoPtr(new transport::Info(info)), -1);
}

void Rpcs::StoreRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreRefreshResponse &response,
    ConnectedObjects /*connected_objects*/,
    StoreRefreshFunctor callback) {
  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)),
                    transport_condition);
  if (response.IsInitialized() && response.result())
    callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
  else
    callback(RankInfoPtr(new transport::Info(info)), -1);
}

void Rpcs::DeleteCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteResponse &response,
    ConnectedObjects /*connected_objects*/,
    DeleteFunctor callback) {
  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)),
                    transport_condition);
  if (response.IsInitialized() && response.result())
    callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
  else
    callback(RankInfoPtr(new transport::Info(info)), -1);
}

void Rpcs::DeleteRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteRefreshResponse &response,
    ConnectedObjects /*connected_objects*/,
    DeleteRefreshFunctor callback) {
  if (transport_condition != transport::kSuccess)
    return callback(RankInfoPtr(new transport::Info(info)),
                    transport_condition);
  if (response.IsInitialized() && response.result())
    callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
  else
    callback(RankInfoPtr(new transport::Info(info)), -1);
}

Rpcs::ConnectedObjects Rpcs::Prepare(TransportType type,
                                     SecurifierPtr securifier) {
  TransportPtr transport;
  switch (type) {
    case kTcp:
      transport.reset(new transport::TcpTransport(asio_service_));
      break;
//    case kOther:
//      transport.reset(new transport::UdtTransport(asio_service_));
//      break;
    default:
      break;
  }
  MessageHandlerPtr message_handler(new MessageHandler(securifier ? securifier :
                                                       default_securifier_));
  // Connect message handler to transport for incoming raw messages
  bs2::connection on_recv_con = transport->on_message_received()->connect(
      boost::bind(&MessageHandler::OnMessageReceived, message_handler.get(),
                  _1, _2, _3, _4));
  bs2::connection on_err_con = transport->on_error()->connect(
      boost::bind(&MessageHandler::OnError, message_handler.get(), _1));
  return boost::make_tuple(transport, message_handler, on_recv_con, on_err_con);
}

}  // namespace kademlia

}  // namespace maidsafe
