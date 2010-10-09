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

#include "maidsafe/rpcprotocol/channelmanagerimpl.h"
#include <google/protobuf/descriptor.h>

#include <list>
#include <vector>

#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/network_interface.h"
#include "maidsafe/protobuf/rpcmessage.pb.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/rpcprotocol/rpcstructs.h"
#include "maidsafe/transport/udttransport.h"


namespace rpcprotocol {

ChannelManagerImpl::ChannelManagerImpl()
    : udt_transport_(), is_started_(false), message_mutex_(),
      channels_mutex_(), id_mutex_(), channels_ids_mutex_(), timings_mutex_(),
      current_rpc_id_(0), current_channel_id_(0), channels_(),
      pending_messages_(), channels_ids_(), rpc_timings_(),
      delete_channels_cond_(), online_status_id_(0), rpc_request_(),
      rpc_reponse_(), data_sent_(), timeout_() {}

ChannelManagerImpl::ChannelManagerImpl(
    boost::shared_ptr<transport::UdtTransport> udt_transport)
    : udt_transport_(udt_transport), is_started_(false), message_mutex_(),
      channels_mutex_(), id_mutex_(), channels_ids_mutex_(), timings_mutex_(),
      current_rpc_id_(0), current_channel_id_(0), channels_(),
      pending_messages_(), channels_ids_(), rpc_timings_(),
      delete_channels_cond_(), online_status_id_(0), rpc_request_(),
      rpc_reponse_(), data_sent_(), timeout_() {
  rpc_request_ = udt_transport_->signals()->ConnectOnRpcRequestReceived(
                     boost::bind(&ChannelManagerImpl::RequestArrive,
                                 this, _1, _2, _3));
  rpc_reponse_ = udt_transport_->signals()->ConnectOnRpcResponseReceived(
                     boost::bind(&ChannelManagerImpl::ResponseArrive,
                                 this, _1, _2, _3));
  data_sent_ = udt_transport_->signals()->ConnectOnSend(
                   boost::bind(&ChannelManagerImpl::RpcMessageSent,
                               this, _1, _2));
  timeout_ = udt_transport_->signals()->ConnectOnReceive(
                 boost::bind(&ChannelManagerImpl::RpcStatus, this, _1, _2));
}

ChannelManagerImpl::~ChannelManagerImpl() {
  Stop();
}

int ChannelManagerImpl::Start() {
  if (is_started_) {
    return 0;
  }
  current_rpc_id_ = base::GenerateNextTransactionId(current_rpc_id_);
  is_started_ = true;
  return 0;
}

int ChannelManagerImpl::Stop() {
  if (!is_started_) {
    return 0;
  }
  is_started_ = false;
  ClearCallLaters();
  {
    boost::mutex::scoped_lock lock(channels_ids_mutex_);
    while (!channels_ids_.empty()) {
      bool wait_result = delete_channels_cond_.timed_wait(lock,
          boost::posix_time::seconds(10));
      if (!wait_result)
        channels_ids_.clear();
    }
  }
  ClearChannels();
  rpc_request_.disconnect();
  rpc_reponse_.disconnect();
  data_sent_.disconnect();
  timeout_.disconnect();
  return 1;
}

void ChannelManagerImpl::RegisterChannel(const std::string &service_name,
                                         Channel* channel) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_[service_name] = channel;
}

void ChannelManagerImpl::UnRegisterChannel(const std::string &service_name) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_.erase(service_name);
}

void ChannelManagerImpl::ClearChannels() {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_.clear();
}

void ChannelManagerImpl::ClearCallLaters() {
  boost::mutex::scoped_lock loch_more(message_mutex_);
  std::map<SocketId, PendingMessage>::iterator it;
  for (it = pending_messages_.begin(); it != pending_messages_.end(); ++it)
    delete it->second.callback;
  pending_messages_.clear();
}

void ChannelManagerImpl::AddChannelId(boost::uint32_t *id) {
  boost::mutex::scoped_lock guard(channels_ids_mutex_);
  current_channel_id_ = base::GenerateNextTransactionId(current_channel_id_);
  channels_ids_.insert(current_channel_id_);
  *id = current_channel_id_;
}

void ChannelManagerImpl::RemoveChannelId(const boost::uint32_t &id) {
  boost::mutex::scoped_lock guard(channels_ids_mutex_);
  channels_ids_.erase(id);
  delete_channels_cond_.notify_all();
}

bool ChannelManagerImpl::AddPendingRequest(const SocketId &socket_id,
                                           PendingMessage pending_request) {
  if (!is_started_) {
    return false;
  }
  pending_request.controller->set_socket_id(socket_id);
  if (pending_request.local_transport) {
    pending_request.rpc_reponse =
        pending_request.controller->udt_connection()->signals()->
            ConnectOnRpcResponseReceived(
                boost::bind(&ChannelManagerImpl::ResponseArrive,
                            this, _1, _2, _3));
    pending_request.data_sent =
        pending_request.controller->udt_connection()->signals()->ConnectOnSend(
            boost::bind(&ChannelManagerImpl::RpcMessageSent, this, _1, _2));
    pending_request.timeout =
        pending_request.controller->udt_connection()->signals()->
            ConnectOnReceive(boost::bind(&ChannelManagerImpl::RpcStatus, this,
                                         _1, _2));
  }
  std::pair<std::map<SocketId, PendingMessage>::iterator, bool> p;
  {
    boost::mutex::scoped_lock loch_nan_clar(message_mutex_);
    p = pending_messages_.insert(std::pair<SocketId,  PendingMessage>(
                                           socket_id, pending_request));
  }
  return p.second;
}

bool ChannelManagerImpl::TriggerPendingRequest(const SocketId &socket_id) {
  if (!is_started_) {
    return false;
  }
  std::map<SocketId, PendingMessage>::iterator it;
  message_mutex_.lock();
  it = pending_messages_.find(socket_id);
  if (it == pending_messages_.end()) {
    message_mutex_.unlock();
    return false;
  }
  it->second.controller->SetFailed(kCancelled);
  google::protobuf::Closure *callback = it->second.callback;
  pending_messages_.erase(it);
  message_mutex_.unlock();
  callback->Run();
  return true;
}

bool ChannelManagerImpl::DeletePendingRequest(const SocketId &socket_id) {
  if (!is_started_) {
    return false;
  }
  std::map<SocketId, PendingMessage>::iterator it;
  message_mutex_.lock();
  it = pending_messages_.find(socket_id);
  if (it == pending_messages_.end()) {
    message_mutex_.unlock();
    return false;
  }
  delete it->second.callback;
  pending_messages_.erase(it);
  message_mutex_.unlock();
  return true;
}

void ChannelManagerImpl::RequestArrive(const rpcprotocol::RpcMessage &msg,
                                       const SocketId &socket_id,
                                       const float &rtt) {
  rpcprotocol::RpcMessage decoded_msg = msg;
  std::map<std::string, Channel*>::iterator it;
  channels_mutex_.lock();
  it = channels_.find(decoded_msg.service());
  if (it != channels_.end()) {
    std::pair<std::map<SocketId, PendingMessage>::iterator, bool> p;
    {
      boost::mutex::scoped_lock loch_loanan(message_mutex_);
      PendingMessage pm;
      pm.status = kAwaitingResponseSend;
      p = pending_messages_.insert(std::pair<SocketId,  PendingMessage>(
                                             socket_id, pm));
      if (!p.second) {
        channels_mutex_.unlock();
        DLOG(ERROR) << "CMImpl::RequestArrive - Failed to add to pending msgs"
                    << " - " << socket_id << std::endl;
      }
    }
    it->second->HandleRequest(decoded_msg, socket_id, rtt);
    channels_mutex_.unlock();
  } else {
    DLOG(ERROR) << "Message arrived for unregistered service" << std::endl;
    channels_mutex_.unlock();
  }
}

void ChannelManagerImpl::ResponseArrive(const rpcprotocol::RpcMessage &msg,
                                        const SocketId &socket_id,
                                        const float&) {
  rpcprotocol::RpcMessage decoded_msg = msg;
  if (!decoded_msg.has_method()) {
    DLOG(ERROR) << "CMImpl::ResponseArrive - " << socket_id
                << " - response arrived cannot parse message" << std::endl;
    return;
  }
  std::map<SocketId, PendingMessage>::iterator it;
  {
    boost::mutex::scoped_lock loch_coire(message_mutex_);
    it = pending_messages_.find(socket_id);
    if (it == pending_messages_.end()) {
      DLOG(ERROR) << "CMImpl::ResponseArrive - " << socket_id
                  << " - response not expected" << std::endl;
      return;
    }
  }
  if ((*it).second.status != kRequestSent) {
    DLOG(ERROR) << "CMImpl::ResponseArrive - " << socket_id
                << " - response weird req status: "
                << (*it).second.status << std::endl;
    return;
  }

  if (!(*it).second.callback) {
    DLOG(ERROR) << "CMImpl::ResponseArrive - " << socket_id
                << " - callback null" << std::endl;
    return;
  }
  // Extract the optional field which is the actual RPC payload.
  // The field must be a proto message itself and is an extension.
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  decoded_msg.detail().GetReflection()->ListFields(decoded_msg.detail(),
                                                   &field_descriptors);

  // Check only one field exists
  if (field_descriptors.size() != size_t(1) || !field_descriptors.at(0) ||
      field_descriptors.at(0)->type() !=
          google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
    DLOG(ERROR) << "ChannelImpl::HandleRequest - invalid request."
                << std::endl;
    return;
  }

  const google::protobuf::Message &args =
      decoded_msg.detail().GetReflection()->GetMessage(
          decoded_msg.detail(), field_descriptors.at(0));

  google::protobuf::Closure *done;
  {
    boost::mutex::scoped_lock loch_coire(message_mutex_);
    (*it).second.args->MergeFrom(args);
    (*it).second.rpc_reponse.disconnect();
    (*it).second.data_sent.disconnect();
    (*it).second.timeout.disconnect();
    (*it).second.controller->udt_connection().reset();
    done = (*it).second.callback;
    pending_messages_.erase(it);
  }
  done->Run();
}

void ChannelManagerImpl::RpcMessageSent(
    const SocketId &socket_id, const transport::TransportCondition &success) {
  std::map<SocketId, PendingMessage>::iterator it;
  boost::mutex::scoped_lock loch_hope(message_mutex_);
  it = pending_messages_.find(socket_id);
  if (it == pending_messages_.end())
    return;
  if (success != transport::kSuccess) {
    DLOG(INFO) << "CMImpl::RpcMessageSent - id = " << socket_id
               << " failed to send. " << std::endl;
    if ((*it).second.status == kRequestSent ||
        (*it).second.status == kAwaitingRequestSend) {
      (*it).second.callback->Run();
      (*it).second.rpc_reponse.disconnect();
      (*it).second.data_sent.disconnect();
      (*it).second.timeout.disconnect();
    }
    pending_messages_.erase(it);
    return;
  }

  switch ((*it).second.status) {
    case kAwaitingRequestSend: (*it).second.status = kRequestSent;
                               break;
    case kAwaitingResponseSend: delete (*it).second.callback;
    case kPending: pending_messages_.erase(it);
                   break;
    default:break;
  }
}

void ChannelManagerImpl::RpcStatus(const SocketId &socket_id,
                                   const transport::TransportCondition &tc) {
  if (tc != transport::kSuccess) {
    boost::mutex::scoped_lock loch_urigill(message_mutex_);
    std::map<SocketId, PendingMessage>::iterator it;
    it = pending_messages_.find(socket_id);
    if (it != pending_messages_.end()) {
      if ((*it).second.status == kRequestSent) {
        DLOG(ERROR) << "CMImpl::RpcStatus - " << socket_id
                    << " - request timeout" << std::endl;
        if ((*it).second.callback)
          (*it).second.callback->Run();
        (*it).second.rpc_reponse.disconnect();
        (*it).second.data_sent.disconnect();
        (*it).second.timeout.disconnect();
        pending_messages_.erase(it);
      }
    }
  }
}

RpcStatsMap ChannelManagerImpl::RpcTimings() {
  boost::mutex::scoped_lock lock(timings_mutex_);
  return rpc_timings_;
}

void ChannelManagerImpl::ClearRpcTimings() {
  boost::mutex::scoped_lock lock(timings_mutex_);
  rpc_timings_.clear();
}

}  // namespace rpcprotocol
