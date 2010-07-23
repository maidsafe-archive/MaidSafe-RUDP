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

/*
#include <boost/tokenizer.hpp>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <typeinfo>
#include "maidsafe/base/log.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/rpcprotocol/channelimpl.h"
#include "maidsafe/rpcprotocol/channelmanagerimpl.h"
#include "maidsafe/transport/transport.h"
*/
#include <boost/tokenizer.hpp>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/message.h>
#include <typeinfo>
#include "maidsafe/base/log.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/rpcprotocol/channelimpl.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/rpcprotocol/channelmanagerimpl.h"
#include "maidsafe/transport/transport.h"

namespace rpcprotocol {

void ControllerImpl::Reset() {
  timeout_ = kRpcTimeout;
  time_sent_ = 0;
  time_received_ = 0;
  rtt_ = 0.0;
  failure_.clear();
  rpc_id_ = 0;
}

ChannelImpl::ChannelImpl(ChannelManager *channel_manager,
                         transport::Transport *transport)
    : channel_manager_(channel_manager),
      transport_(transport),
      service_(0),
      remote_ip_(),
      local_ip_(),
      rendezvous_ip_(),
      remote_port_(0),
      local_port_(0),
      rendezvous_port_(0),
      id_(0) {
  channel_manager_->AddChannelId(&id_);
}

ChannelImpl::ChannelImpl(ChannelManager *channel_manager,
                         transport::Transport *transport,
                         const IP &remote_ip,
                         const Port &remote_port,
                         const IP &local_ip,
                         const Port &local_port,
                         const IP &rendezvous_ip,
                         const Port &rendezvous_port)
    : channel_manager_(channel_manager),
      transport_(transport),
      service_(0),
      remote_ip_(),
      local_ip_(),
      rendezvous_ip_(),
      remote_port_(remote_port),
      local_port_(local_port),
      rendezvous_port_(rendezvous_port),
      id_(0) {
  // To send we need ip in decimal dotted format
  if (remote_ip.size() == 4)
    remote_ip_ = base::IpBytesToAscii(remote_ip);
  else
    remote_ip_ = remote_ip;
  if (local_ip.size() == 4)
    local_ip_ = base::IpBytesToAscii(local_ip);
  else
    local_ip_ = local_ip;
  if (rendezvous_ip.size() == 4)
    rendezvous_ip_ = base::IpBytesToAscii(rendezvous_ip);
  else
    rendezvous_ip_ = rendezvous_ip;
  channel_manager_->AddChannelId(&id_);
}

ChannelImpl::~ChannelImpl() {
  channel_manager_->RemoveChannelId(id_);
}

void ChannelImpl::CallMethod(const google::protobuf::MethodDescriptor *method,
                             google::protobuf::RpcController *rpc_controller,
                             const google::protobuf::Message *request,
                             google::protobuf::Message *response,
                             google::protobuf::Closure *done) {
  if ((remote_ip_.empty()) || (remote_port_ == 0)) {
    DLOG(ERROR) << "ChannelImpl::CallMethod. No remote_ip or remote_port\n";
    done->Run();
    return;
  }

  // Wrap request in TransportMessage
  transport::TransportMessage transport_message;
  transport_message.set_type(transport::TransportMessage::kRequest);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(channel_manager_->CreateNewId());
  rpc_message->set_method(method->name());
  // Get field descriptor for RPC payload
  const google::protobuf::FieldDescriptor *field_descriptor =
      rpc_message->detail().GetReflection()->FindKnownExtensionByName(
          request->GetTypeName());
  // Get mutable payload field
  rpcprotocol::RpcMessage::Detail *rpc_message_detail =
      rpc_message->mutable_detail();
  // Copy payload into RpcMessage
  google::protobuf::Message *mutable_message =
      rpc_message_detail->GetReflection()->MutableMessage(
          rpc_message_detail, field_descriptor);
  mutable_message->CopyFrom(*request);

  PendingRequest pending_request;
  pending_request.args = response;
  pending_request.callback = done;
//  ConnectionId connection_id = 0;
  ConnectionId connection_id = base::RandomUint32();
  Controller *controller = static_cast<Controller*>(rpc_controller);
  controller->set_rpc_id(rpc_message->rpc_id());
  controller->set_method(method->name());
  controller->StartRpcTimer();
//  if (true/*0 == transport_->ConnectToSend(remote_ip_, remote_port_,
//      local_ip_, local_port_, rendezvous_ip_, rendezvous_port_, true, &connection_id)*/) {
//    pending_request.connection_id = connection_id;
//    // Set the RPC request timeout
//    if (controller->timeout() != 0) {
//      pending_request.timeout = controller->timeout();
//    } else {
//      pending_request.timeout = kRpcTimeout;
//    }
//    pending_request.controller = controller;
//    if (!channel_manager_->AddPendingRequest(rpc_message->rpc_id(),
//                                             pending_request)) {
//      done->Run();
//      return;
//    }
//    channel_manager_->AddTimeOutRequest(connection_id, rpc_message->rpc_id(),
//                                 pending_request.timeout);
/******************************************************************************/
//    if (0 != transport_->Send(transport_message, remote_ip_, remote_port_,
//                              controller->timeout())) {
//      DLOG(WARNING) << transport_->listening_port() <<
//        " --- Failed to send request with id " << rpc_message->rpc_id()
//          << std::endl;
//    }
/******************************************************************************/
//  } else {
/******************************************************************************/
//    DLOG(WARNING) << transport_->listening_port() <<
//        " --- Failed to connect to send rpc " << rpc_message->method() <<
//        " to " << remote_ip_ << ":" << remote_port_ << " with id " <<
//        rpc_message->rpc_id() << std::endl;
/******************************************************************************/
//    controller->set_timeout(1);
//    pending_request.timeout = controller->timeout();
//    pending_request.controller = controller;
//    if (!channel_manager_->AddPendingRequest(rpc_message->rpc_id(),
//                                             pending_request)) {
//      done->Run();
//      return;
//    }
//    channel_manager_->AddRequestToTimer(rpc_message->rpc_id(),
//                                        pending_request.timeout);
//    return;
//  }
/******************************************************************************/
//  DLOG(INFO) << transport_->listening_port() <<
//      " --- Sending rpc " << rpc_message->method() << " to " << remote_ip_ <<
//      ":" << remote_port_ << " connection_id = " << connection_id <<
//      " -- rpc_id = " << rpc_message->rpc_id() << std::endl;
/******************************************************************************/
}

std::string ChannelImpl::GetServiceName(const std::string &full_name) {
  std::string service_name;
  try {
    boost::char_separator<char> sep(".");
    boost::tokenizer< boost::char_separator<char> > tok(full_name, sep);
    boost::tokenizer< boost::char_separator<char> >::iterator beg = tok.begin();
    int no_tokens = -1;
    while (beg != tok.end()) {
      ++beg;
      ++no_tokens;
    }
    beg = tok.begin();
    advance(beg, no_tokens - 1);
    service_name = *beg;
  } catch(const std::exception &e) {
    LOG(ERROR) << "ChannelImpl::GetServiceName. " <<
        "Error with full method name format: " << e.what() << std::endl;
  }
  return service_name;
}

void ChannelImpl::HandleRequest(const rpcprotocol::RpcMessage &rpc_message,
                                const ConnectionId &connection_id,
                                const float &rtt) {
  if (!service_) {
    LOG(ERROR) << "ChannelImpl::HandleRequest - no service." << std::endl;
//    transport_->CloseConnection(connection_id);
    return;
  }
  if (!rpc_message.IsInitialized()) {
    LOG(ERROR) << "ChannelImpl::HandleRequest - uninitialised." << std::endl;
//    transport_->CloseConnection(connection_id);
    return;
  }
  if (!rpc_message.has_method()) {
    LOG(ERROR) << "ChannelImpl::HandleRequest - no method." << std::endl;
//    transport_->CloseConnection(connection_id);
    return;
  }

  const google::protobuf::MethodDescriptor* method =
      service_->GetDescriptor()->FindMethodByName(rpc_message.method());
  google::protobuf::Message* response  =
      service_->GetResponsePrototype(method).New();

  // Extract the optional field which is the actual RPC payload.  The field must
  // be a proto message itself and is an extension.
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  rpc_message.detail().GetReflection()->ListFields(rpc_message.detail(),
                                                   &field_descriptors);
  // Check only one field exists
  if (field_descriptors.size() != 1U) {
    LOG(ERROR) << "ChannelImpl::HandleRequest - invalid request." << std::endl;
//    transport_->CloseConnection(connection_id);
    return;
  }
  // Get the payload message's descriptor
  const google::protobuf::FieldDescriptor *field_descriptor =
      rpc_message.detail().GetReflection()->FindKnownExtensionByName(
          field_descriptors.at(0)->full_name());
  // Check it's a message type
  if (field_descriptor->type() !=
      google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
    LOG(ERROR) << "ChannelImpl::HandleRequest - invalid request." << std::endl;
//    transport_->CloseConnection(connection_id);
    return;
  }
  // Copy the payload to a new message (DescriptorProto inherits from Message)
  google::protobuf::DescriptorProto proto_request;
  field_descriptor->message_type()->CopyTo(&proto_request);

  boost::shared_ptr<Controller> controller(new Controller);
  controller->set_rtt(rtt);
  controller->set_rpc_id(rpc_message.rpc_id());
  controller->set_socket_id(connection_id);
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<ChannelImpl,
                                    const google::protobuf::Message*,
                                    boost::shared_ptr<Controller> >
      (this, &ChannelImpl::SendResponse, response, controller);
  service_->CallMethod(method, controller.get(), &proto_request, response,
                       done);
}

void ChannelImpl::SendResponse(const google::protobuf::Message *response,
                               boost::shared_ptr<Controller> controller) {
  // Wrap request in TransportMessage
  transport::TransportMessage transport_message;
  transport_message.set_type(transport::TransportMessage::kResponse);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(controller->rpc_id());
  rpc_message->set_method(controller->method());
  // Get field descriptor for RPC payload
  const google::protobuf::FieldDescriptor *field_descriptor =
      rpc_message->detail().GetReflection()->FindKnownExtensionByName(
          response->GetTypeName());
  // Get mutable payload field
  rpcprotocol::RpcMessage::Detail *rpc_message_detail =
      rpc_message->mutable_detail();
  // Copy payload into RpcMessage
  google::protobuf::Message *mutable_message =
      rpc_message_detail->GetReflection()->MutableMessage(
          rpc_message_detail, field_descriptor);
  mutable_message->CopyFrom(*response);

/******************************************************************************/
//  if (0 != transport_->Send(transport_message, controller->socket_id())) {
//    DLOG(WARNING) << transport_->listening_port() <<
//        " Failed to send response to connection " << controller->socket_id()
//         << std::endl;
//  }
//  DLOG(INFO) << transport_->listening_port() <<
//    " --- Response to req " << controller->rpc_id() << std::endl;
/******************************************************************************/
  delete response;
}

}  // namespace rpcprotocol
