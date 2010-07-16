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
#include <list>
#include "maidsafe/base/log.h"
#include "maidsafe/base/online.h"
#include "maidsafe/base/network_interface.h"
#include "maidsafe/protobuf/general_messages.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/protobuf/transport_message.pb.h"

namespace rpcprotocol {

ChannelManagerImpl::ChannelManagerImpl(transport::Transport *transport)
    : is_started_(false),
      call_later_timer_(new base::CallLaterTimer),
      req_mutex_(),
      channels_mutex_(),
      id_mutex_(),
      pend_timeout_mutex_(),
      channels_ids_mutex_(),
      timings_mutex_(),
      current_rpc_id_(0),
      current_channel_id_(0),
      channels_(),
      pending_requests_(),
      pending_timeouts_(),
      channels_ids_(),
      rpc_timings_(),
      delete_channels_cond_(),
      online_status_id_(0) {
  rpc_request_ = transport_->ConnectRpcRequestReceived(
      boost::bind(&ChannelManagerImpl::RequestArrive, this, _1, _2, _3));
  rpc_reponse_ = transport_->ConnectRpcResponseReceived(
      boost::bind(&ChannelManagerImpl::ResponseArrive, this, _1, _2, _3));
  data_sent_connection_ = transport_->ConnectSent((boost::bind(
      &ChannelManagerImpl::RequestSent, this, _1, _2)));
}

ChannelManagerImpl::~ChannelManagerImpl() {
  Stop();
}

int ChannelManagerImpl::Start() {
  if (is_started_) {
    return 0;
  }
  current_rpc_id_ =
      base::GenerateNextTransactionId(current_rpc_id_) +
      (transport_->listening_port() * 100);
  is_started_ = true;
  online_status_id_ = base::OnlineController::Instance()->RegisterObserver(
      transport_->listening_port(),
      boost::bind(&ChannelManagerImpl::OnlineStatusChanged, this, _1));
  return 0;
}

int ChannelManagerImpl::Stop() {
  if (!is_started_) {
    return 0;
  }
  is_started_ = false;
  base::OnlineController::Instance()->UnregisterObserver(online_status_id_);
  {
    boost::mutex::scoped_lock guard(pend_timeout_mutex_);
    pending_timeouts_.clear();
  }
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
  return 1;
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

bool ChannelManagerImpl::AddPendingRequest(const RpcId &rpc_id,
                                           PendingRequest pending_request) {
  if (!is_started_) {
    return false;
  }
  boost::mutex::scoped_lock guard(req_mutex_);
  pending_requests_[rpc_id] = pending_request;
  return true;
}

bool ChannelManagerImpl::DeletePendingRequest(const RpcId &rpc_id) {
  if (!is_started_) {
    return false;
  }
  std::map<RpcId, PendingRequest>::iterator it;
  req_mutex_.lock();
  it = pending_requests_.find(rpc_id);
  if (it == pending_requests_.end()) {
    req_mutex_.unlock();
    return false;
  }
  ConnectionId connection_id = it->second.connection_id;
  it->second.controller->SetFailed(kCancelled);
  google::protobuf::Closure *callback = it->second.callback;
  pending_requests_.erase(it);
  req_mutex_.unlock();
  if (connection_id != 0)
    transport_->CloseConnection(connection_id);
  callback->Run();
  return true;
}

bool ChannelManagerImpl::CancelPendingRequest(const RpcId &rpc_id) {
  if (!is_started_) {
    return false;
  }
  std::map<RpcId, PendingRequest>::iterator it;
  req_mutex_.lock();
  it = pending_requests_.find(rpc_id);
  if (it == pending_requests_.end()) {
    req_mutex_.unlock();
    return false;
  }
  ConnectionId connection_id = it->second.connection_id;
  delete it->second.callback;
  pending_requests_.erase(it);
  req_mutex_.unlock();
  if (connection_id != 0)
    transport_->CloseConnection(connection_id);
  return true;
}

void ChannelManagerImpl::AddReqToTimer(const RpcId &rpc_id,
                                       const boost::uint64_t &timeout) {
  if (!is_started_) {
    return;
  }
  call_later_timer_->AddCallLater(timeout,
      boost::bind(&ChannelManagerImpl::TimerHandler, this, rpc_id));
}

RpcId ChannelManagerImpl::CreateNewId() {
  boost::mutex::scoped_lock guard(id_mutex_);
  current_rpc_id_ = base::GenerateNextTransactionId(current_rpc_id_);
  return current_rpc_id_;
}

void ChannelManagerImpl::RegisterChannel(const std::string &service_name,
                                         Channel* channel) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_[service_name] = channel;
}

void ChannelManagerImpl::RequestArrive(const transport::RpcMessage &msg,
                                       const ConnectionId &connection_id,
                                       const float &rtt) {
  transport::RpcMessage decoded_msg = msg;
  std::map<RpcId, PendingRequest>::iterator it;
  req_mutex_.lock();
  it = pending_requests_.find(decoded_msg.rpc_id());
  //if (it != pending_requests_.end()) {
  //  if (it->second.args->CopyFrom(decoded_msg.args())) {
  //    boost::uint64_t duration(0);
  //    std::string method;
  //    if (it->second.controller != NULL) {
  //      it->second.controller->StopRpcTimer();
  //      it->second.controller->set_rtt(rtt);
  //      method = it->second.controller->method();
  //      duration = it->second.controller->Duration();
  //      {
  //        boost::mutex::scoped_lock lock(timings_mutex_);
  //        rpc_timings_[method].Add(duration);
  //      }
  //    }
  //    google::protobuf::Closure* done = (*it).second.callback;
  //    pending_requests_.erase(decoded_msg.rpc_id());
  //    req_mutex_.unlock();
  //    DLOG(INFO) << transport_->listening_port() <<
  //        " --- Request arrived for " << method << " -- " <<
  //        decoded_msg.rpc_id() << " -- RTT: " << rtt << " ms, duration: " <<
  //        duration << " ms" << std::endl;
  //    done->Run();
  //    // TODO(dirvine) FIXREFRESH Check this is not connected to a node in
  //    // our first kbucketkbucket
  //    //transport_->CloseConnection(connection_id);
  //  } else {
  //    req_mutex_.unlock();
  //    DLOG(INFO) << transport_->listening_port() <<
  //        " --- ChannelManager no callback for id " <<
  //        decoded_msg.rpc_id() << std::endl;
  //  }
  //} else {
  //  req_mutex_.unlock();
  //  DLOG(INFO) << transport_->listening_port() <<
  //      " --- ChannelManager no request for id " <<
  //      decoded_msg.rpc_id() << std::endl;
  //}
}

void ChannelManagerImpl::ResponseArrive(const transport::RpcMessage &msg,
                                        const ConnectionId &connection_id,
                                        const float &rtt) {
  transport::RpcMessage decoded_msg = msg;
  // TODO FIXME (dirvine)
  if (/*!decoded_msg.has_service() ||*/ !decoded_msg.has_method()) {
    DLOG(ERROR) << transport_->listening_port() <<
        " --- request arrived cannot parse message\n";
    return;
  }
  // If this is a special find node for boostrapping,
  // inject incoming address
  //if (decoded_msg.method() == "Bootstrap") {
  //  kad::BootstrapRequest decoded_bootstrap;
  //  if (!decoded_bootstrap.ParseFromString(decoded_msg.args())) {
  //    return;
  //  }
  //  struct sockaddr peer_addr;
  //  if (!transport_->GetPeerAddr(connection_id, &peer_addr))
  //    return;
  //  IP peer_ip =
  //      base::NetworkInterface::SockaddrToAddress(&peer_addr).to_string();
  //  Port peer_port = ntohs(reinterpret_cast<struct sockaddr_in*>(
  //                                    &peer_addr)->sin_port);
  //  decoded_bootstrap.set_newcomer_ext_ip(peer_ip);
  //  decoded_bootstrap.set_newcomer_ext_port(peer_port);
  //  std::string encoded_bootstrap;
  //  if (!decoded_bootstrap.SerializeToString(&encoded_bootstrap)) {
  //    return;
  //  }
  //  decoded_msg.set_args(encoded_bootstrap);
  //}
  //// Find Channel that has registered the service
  //std::map<std::string, Channel*>::iterator it;
  //channels_mutex_.lock();
  //it = channels_.find(decoded_msg.service());
  //if (it != channels_.end()) {
  //  it->second->HandleRequest(decoded_msg, connection_id, rtt);
  //  channels_mutex_.unlock();
  //} else {
  //  LOG(ERROR) << "Message arrived for unregistered service\n";
  //  channels_mutex_.unlock();
  //}
}

void ChannelManagerImpl::TimerHandler(const RpcId &rpc_id) {
  if (!is_started_) {
    return;
  }
  std::map<RpcId, PendingRequest>::iterator it;
  req_mutex_.lock();
  it = pending_requests_.find(rpc_id);
  if (it != pending_requests_.end()) {
    transport::DataSize size_received = it->second.size_received;
    ConnectionId connection_id = it->second.connection_id;
    boost::uint64_t timeout = it->second.timeout;
    if (transport_->HasReceivedData(connection_id, &size_received)) {
      it->second.size_received = size_received;
      req_mutex_.unlock();
      DLOG(INFO) << transport_->listening_port() <<
          " -- Reseting timeout for RPC ID: " << rpc_id <<
          ". Connection ID: " << connection_id << ". Recvd: " << size_received;
      AddReqToTimer(rpc_id, timeout);
    } else {
      DLOG(INFO) << transport_->listening_port() <<
          "Request " << rpc_id << " times out.  Connection ID: " <<
          connection_id << std::endl;
      // call back without modifying the response
      google::protobuf::Closure* done = (*it).second.callback;
      (*it).second.controller->SetFailed(kTimeOut);
      pending_requests_.erase(it);
      req_mutex_.unlock();
      done->Run();
      if (connection_id != 0)
        transport_->CloseConnection(connection_id);
    }
  } else {
    req_mutex_.unlock();
  }
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
  {
    boost::mutex::scoped_lock guard(req_mutex_);
    std::map<RpcId, PendingRequest>::iterator it;
    for (it = pending_requests_.begin(); it != pending_requests_.end(); ++it)
      delete it->second.callback;
    pending_requests_.clear();
  }
  call_later_timer_->CancelAll();
}

void ChannelManagerImpl::RequestSent(const ConnectionId &connection_id,
    const bool &success) {
  std::map<ConnectionId, PendingTimeOut>::iterator it;
  boost::mutex::scoped_lock guard(pend_timeout_mutex_);
  it = pending_timeouts_.find(connection_id);
  if (it != pending_timeouts_.end()) {
    if (success) {
      AddReqToTimer(it->second.rpc_id, it->second.timeout);
    } else {
      AddReqToTimer(it->second.rpc_id, 1000);
    }
  }
}

void ChannelManagerImpl::AddTimeOutRequest(const ConnectionId &connection_id,
    const RpcId &rpc_id, const int &timeout) {
  struct PendingTimeOut timestruct;
  timestruct.rpc_id = rpc_id;
  timestruct.timeout = timeout;
  boost::mutex::scoped_lock guard(pend_timeout_mutex_);
  pending_timeouts_[connection_id] = timestruct;
}

void ChannelManagerImpl::OnlineStatusChanged(const bool&) {
  // TODO(anyone) handle connection loss
}

// bool ChannelManagerImpl::RegisterNotifiersToTransport() {
//   if (is_started_) {
//     return true;  // Everything has already been registered
//   }
//    if (transport_->RegisterOnRPCMessage(
//      boost::bind(&ChannelManagerImpl::MessageArrive, this, _1, _2, _3, _4))) {
//   return transport_->RegisterOnSend(boost::bind(
//         &ChannelManagerImpl::RequestSent, this, _1, _2));
//    }
//   return false;
// }

RpcStatsMap ChannelManagerImpl::RpcTimings() {
  boost::mutex::scoped_lock lock(timings_mutex_);
  return rpc_timings_;
}

void ChannelManagerImpl::ClearRpcTimings() {
  boost::mutex::scoped_lock lock(timings_mutex_);
  rpc_timings_.clear();
}

}  // namespace rpcprotocol
