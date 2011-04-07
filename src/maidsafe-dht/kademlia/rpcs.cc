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
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/message_handler.h"
#include "maidsafe-dht/kademlia/rpcs.pb.h"
#include "maidsafe-dht/kademlia/securifier.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/transport/tcp_transport.h"
#include "maidsafe-dht/transport/udp_transport.h"

namespace arg = std::placeholders;
// TODO(Fraser#5#): 2011-01-30 - Handle sending to port-restricted peers.
namespace maidsafe {

namespace kademlia {

const boost::uint16_t kFailureTolerance = 2;

void Rpcs::Ping(SecurifierPtr securifier,
                const Contact &peer,
                PingFunctor callback,
                TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::PingRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
//  std::string random_data(RandomString(50 + (RandomUint32() % 50)));
  std::string random_data("ping");
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
  transport->Send(message,
                  peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::FindValue(const Key &key,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     FindValueFunctor callback,
                     TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindValueRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
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
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::FindNodes(const Key &key,
                     SecurifierPtr securifier,
                     const Contact &peer,
                     FindNodesFunctor callback,
                     TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::FindNodesRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
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
  transport->Send(message, peer.PreferredEndpoint(),
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
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::StoreRequest request;
  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature.empty() ? securifier->Sign(value) :
                              signature);
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
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::StoreRefresh(const std::string &serialised_store_request,
                        const std::string &serialised_store_request_signature,
                        SecurifierPtr securifier,
                        const Contact &peer,
                        StoreRefreshFunctor callback,
                        TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
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
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::Delete(const Key &key,
                  const std::string &value,
                  const std::string &signature,
                  SecurifierPtr securifier,
                  const Contact &peer,
                  DeleteFunctor callback,
                  TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
      connected_objects_.AddObject(transport, message_handler);

  protobuf::DeleteRequest request;
  std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer(new RpcsFailurePeer);
  rpcs_failure_peer->peer = peer;

  *request.mutable_sender() = ToProtobuf(contact_);
  request.set_key(key.String());
  protobuf::SignedValue *signed_value(request.mutable_signed_value());
  signed_value->set_value(value);
  signed_value->set_signature(signature.empty() ? securifier->Sign(value) :
                              signature);
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
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::DeleteRefresh(const std::string &serialised_delete_request,
                         const std::string &serialised_delete_request_signature,
                         SecurifierPtr securifier,
                         const Contact &peer,
                         DeleteRefreshFunctor callback,
                         TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);
  boost::uint32_t object_indx =
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
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::Downlist(const std::vector<NodeId> &node_ids,
                    SecurifierPtr securifier,
                    const Contact &peer,
                    TransportType type) {
  TransportPtr transport;
  MessageHandlerPtr message_handler;
  Prepare(type, securifier, transport, message_handler);

  protobuf::DownlistNotification notification;
  *notification.mutable_sender() = ToProtobuf(contact_);
  for (size_t i = 0; i < node_ids.size(); ++i)
    notification.add_node_ids(node_ids[i].String());
  std::string message =
      message_handler->WrapMessage(notification, peer.public_key());
  transport->Send(message, peer.PreferredEndpoint(),
                  transport::kDefaultInitialTimeout);
}

void Rpcs::PingCallback(
    const std::string &random_data,
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::PingResponse &response,
    const boost::uint32_t &index,
    PingFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
    if (response.IsInitialized() && response.echo() == "pong") {
      callback(RankInfoPtr(new transport::Info(info)), transport::kSuccess);
    } else {
      callback(RankInfoPtr(new transport::Info(info)), -1);
    }
  }
}

void Rpcs::FindValueCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindValueResponse &response,
    const boost::uint32_t &index,
    FindValueFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
    (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
    ++(rpcs_failure_peer->rpcs_failure);
    TransportPtr transport = connected_objects_.GetTransport(index);
    transport->Send(
        message, rpcs_failure_peer->peer.PreferredEndpoint(),
        transport::kDefaultInitialTimeout);
  } else {
    connected_objects_.RemoveObject(index);

    std::vector<std::string> values;
    std::vector<Contact> contacts;
    Contact alternative_value_holder;

    if (transport_condition != transport::kSuccess) {
      callback(RankInfoPtr(new transport::Info(info)), transport_condition,
               values, contacts, alternative_value_holder);
      return;
    }
    if (!response.IsInitialized() || !response.result()) {
      callback(RankInfoPtr(new transport::Info(info)), -1, values,
                      contacts, alternative_value_holder);
      return;
    }
    for (int i = 0; i < response.signed_values_size(); ++i)
      values.push_back(response.signed_values(i).value());

    for (int i = 0; i < response.closest_nodes_size(); ++i)
      contacts.push_back(FromProtobuf(response.closest_nodes(i)));
    if (response.has_alternative_value_holder()) {
      alternative_value_holder =
          FromProtobuf(response.alternative_value_holder());
    }

    callback(RankInfoPtr(new transport::Info(info)), transport_condition,
             values, contacts, alternative_value_holder);
  }
}

void Rpcs::FindNodesCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::FindNodesResponse &response,
    const boost::uint32_t &index,
    FindNodesFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
      callback(RankInfoPtr(new transport::Info(info)), -1, contacts);
      return;
    }

    for (int i = 0; i < response.closest_nodes_size(); ++i)
      contacts.push_back(FromProtobuf(response.closest_nodes(i)));

    callback(RankInfoPtr(new transport::Info(info)), transport_condition,
                         contacts);
  }
}

void Rpcs::StoreCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreResponse &response,
    const boost::uint32_t &index,
    StoreFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
      callback(RankInfoPtr(new transport::Info(info)), -1);
  }
}

void Rpcs::StoreRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::StoreRefreshResponse &response,
    const boost::uint32_t &index,
    StoreRefreshFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
      callback(RankInfoPtr(new transport::Info(info)), -1);
  }
}

void Rpcs::DeleteCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteResponse &response,
    const boost::uint32_t &index,
    DeleteFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
      callback(RankInfoPtr(new transport::Info(info)), -1);
  }
}

void Rpcs::DeleteRefreshCallback(
    const transport::TransportCondition &transport_condition,
    const transport::Info &info,
    const protobuf::DeleteRefreshResponse &response,
    const boost::uint32_t &index,
    DeleteRefreshFunctor callback,
    const std::string &message,
    std::shared_ptr<RpcsFailurePeer> rpcs_failure_peer) {
  if ((transport_condition != transport::kSuccess) &&
      (rpcs_failure_peer->rpcs_failure < kFailureTolerance)) {
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
      callback(RankInfoPtr(new transport::Info(info)), -1);
  }
}

void Rpcs::Prepare(TransportType type,
                   SecurifierPtr securifier,
                   TransportPtr &transport,
                   MessageHandlerPtr &message_handler) {
  switch (type) {
    case kTcp:
      transport.reset(new transport::TcpTransport(*asio_service_));
      break;
    case kUdp:
      transport.reset(new transport::UdpTransport(*asio_service_));
      break;
    default:
      break;
  }
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

}  // namespace kademlia

}  // namespace maidsafe
