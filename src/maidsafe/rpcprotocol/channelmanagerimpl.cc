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
#include "maidsafe/transport/transport-api.h"

namespace rpcprotocol {

ChannelManagerImpl::ChannelManagerImpl(
    transport::TransportHandler *transport_handler)
        : is_started_(false),
          ptimer_(new base::CallLaterTimer),
          req_mutex_(),
          channels_mutex_(),
          id_mutex_(),
          pend_timeout_mutex_(),
          channels_ids_mutex_(),
          timings_mutex_(),
          current_request_id_(0),
          current_channel_id_(0),
          channels_(),
          pending_req_(),
          pending_timeout_(),
          channels_ids_(),
          rpc_timings_(),
          delete_channels_cond_(),
          online_status_id_(0) {
//   rpc_request_ = transport_handler_->connect_rpc_request_recieved(
//     boost::bind(&ChannelManagerImpl::RequestArrive, this, _1, _2, _3, _4));
//   rpc_reponse_ = transport_handler_->connect_rpc_response_recieved(
//     boost::bind(&ChannelManagerImpl::ResponseArrive, this, _1, _2, _3, _4));
  data_sent_connection_ = transport_handler_->connect_sent((boost::bind(
        &ChannelManagerImpl::RequestSent, this, _1, _2)));
  }

ChannelManagerImpl::~ChannelManagerImpl() {
  Stop();
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

bool ChannelManagerImpl::AddPendingRequest(const boost::uint32_t &request_id,
      PendingReq req) {
  if (!is_started_) {
    return false;
  }
  boost::mutex::scoped_lock guard(req_mutex_);
  pending_req_[request_id] = req;
  return true;
}

bool ChannelManagerImpl::DeletePendingRequest(
    const boost::uint32_t &request_id) {
  if (!is_started_) {
    return false;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  req_mutex_.lock();
  it = pending_req_.find(request_id);
  if (it == pending_req_.end()) {
    req_mutex_.unlock();
    return false;
  }
  boost::uint32_t connection_id = it->second.connection_id;
  boost::int16_t transport_id = it->second.transport_id;
  it->second.ctrl->SetFailed(kCancelled);
  google::protobuf::Closure *callback = it->second.callback;
  pending_req_.erase(it);
  req_mutex_.unlock();
  if (connection_id != 0)
    transport_handler_->CloseConnection(connection_id, transport_id);
  callback->Run();
  return true;
}

bool ChannelManagerImpl::CancelPendingRequest(
    const boost::uint32_t &request_id) {
  if (!is_started_) {
    return false;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  req_mutex_.lock();
  it = pending_req_.find(request_id);
  if (it == pending_req_.end()) {
    req_mutex_.unlock();
    return false;
  }
  boost::uint32_t connection_id = it->second.connection_id;
  boost::int16_t transport_id = it->second.transport_id;
  delete it->second.callback;
  pending_req_.erase(it);
  req_mutex_.unlock();
  if (connection_id != 0)
    transport_handler_->CloseConnection(connection_id, transport_id);
  return true;
}

void ChannelManagerImpl::AddReqToTimer(const boost::uint32_t &request_id,
    const boost::uint64_t &timeout) {
  if (!is_started_) {
    return;
  }
  ptimer_->AddCallLater(timeout,
      boost::bind(&ChannelManagerImpl::TimerHandler, this, request_id));
}

boost::uint32_t ChannelManagerImpl::CreateNewId() {
  boost::mutex::scoped_lock guard(id_mutex_);
  current_request_id_ = base::GenerateNextTransactionId(current_request_id_);
  return current_request_id_;
}

void ChannelManagerImpl::RegisterChannel(const std::string &service_name,
      Channel* channel) {
  boost::mutex::scoped_lock guard(channels_mutex_);
  channels_[service_name] = channel;
}

int ChannelManagerImpl::Start() {
  if (is_started_) {
    return 0;
  }
  if (transport_handler_->AllAreStopped()) {
    DLOG(ERROR) << "No transports are running\n";
    return 1;
  }
  std::list<boost::int16_t> udt_transports =
      transport_handler_->GetTransportIDByType(transport::kUdt);

  if (udt_transports.empty())
    return 1;

  boost::int16_t udtID = udt_transports.front();

  current_request_id_ =
    base::GenerateNextTransactionId(current_request_id_) +
    (transport_handler_->listening_port(udtID)*100);
  is_started_ = true;
  online_status_id_ = base::OnlineController::Instance()->RegisterObserver(
    transport_handler_->listening_port(udtID),
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
    pending_timeout_.clear();
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

void ChannelManagerImpl::ResponseArrive(const transport::RpcMessage &msg,
                                       const boost::uint32_t &connection_id,
                                       const boost::int16_t transport_id,
                                       const float &rtt) {
    transport::RpcMessage decoded_msg = msg;
    if (!decoded_msg.has_service() || !decoded_msg.has_method()) {
    DLOG(ERROR) << transport_handler_->listening_port(transport_id) <<
        " --- request arrived cannot parse message\n";
    return;
  }
  // If this is a special find node for boostrapping,
  // inject incoming address
  if (decoded_msg.method() == "Bootstrap") {
    kad::BootstrapRequest decoded_bootstrap;
    if (!decoded_bootstrap.ParseFromString(decoded_msg.args())) {
      return;
    }
    struct sockaddr peer_addr;
    if (!transport_handler_->GetPeerAddr(connection_id, transport_id,
        &peer_addr))
      return;
    std::string peer_ip = base::NetworkInterface::SockaddrToAddress(
                          &peer_addr).to_string();
    boost::uint16_t peer_port = ntohs(reinterpret_cast<struct sockaddr_in*>(
                                      &peer_addr)->sin_port);
    decoded_bootstrap.set_newcomer_ext_ip(peer_ip);
    decoded_bootstrap.set_newcomer_ext_port(peer_port);
    std::string encoded_bootstrap;
    if (!decoded_bootstrap.SerializeToString(&encoded_bootstrap)) {
      return;
    }
    decoded_msg.set_args(encoded_bootstrap);
  }
  // Find Channel that has registered the service
  std::map<std::string, Channel*>::iterator it;
  channels_mutex_.lock();
  it = channels_.find(decoded_msg.service());
  if (it != channels_.end()) {
    it->second->HandleRequest(decoded_msg, connection_id, transport_id, rtt);
    channels_mutex_.unlock();
  } else {
    LOG(ERROR) << "Message arrived for unregistered service\n";
    channels_mutex_.unlock();
  }
}
void ChannelManagerImpl::RequestArrive(const transport::RpcMessage &msg,
                                       const boost::uint32_t &connection_id,
                                       const boost::int16_t transport_id,
                                       const float &rtt) {
  transport::RpcMessage decoded_msg = msg;
  std::map<boost::uint32_t, PendingReq>::iterator it;
  req_mutex_.lock();
  it = pending_req_.find(decoded_msg.message_id());
  if (it != pending_req_.end()) {
    if (it->second.args->ParseFromString(decoded_msg.args())) {
      boost::uint64_t duration(0);
      std::string service, method;
      if (it->second.ctrl != NULL) {
        it->second.ctrl->StopRpcTimer();
        it->second.ctrl->set_rtt(rtt);
        it->second.ctrl->message_info(&service, &method);
        duration = it->second.ctrl->Duration();
        {
          boost::mutex::scoped_lock lock(timings_mutex_);
          rpc_timings_[service + "::" + method].Add(duration);
        }
      }
      google::protobuf::Closure* done = (*it).second.callback;
      pending_req_.erase(decoded_msg.message_id());
      req_mutex_.unlock();
      DLOG(INFO) << transport_handler_->listening_port(transport_id) <<
      " --- Response arrived for " << service << "::" << method << " -- " <<
      decoded_msg.message_id() << " -- RTT: " << rtt << " ms, duration: " <<
          duration << " ms" << std::endl;
      done->Run();
      // TODO(dirvine) FIXREFRESH Check this is not connected to a node in
      // our first kbucketkbucket
      transport_handler_->CloseConnection(connection_id, transport_id);
    } else {
      req_mutex_.unlock();
      DLOG(INFO) << transport_handler_->listening_port(transport_id) <<
          " --- ChannelManager no callback for id " <<
          decoded_msg.message_id() << std::endl;
    }
  } else {
    req_mutex_.unlock();
    DLOG(INFO) << transport_handler_->listening_port(transport_id) <<
        " --- ChannelManager no request for id " <<
        decoded_msg.message_id() << std::endl;
  }
}

void ChannelManagerImpl::TimerHandler(const boost::uint32_t &request_id) {
  if (!is_started_) {
    return;
  }
  std::map<boost::uint32_t, PendingReq>::iterator it;
  req_mutex_.lock();
  it = pending_req_.find(request_id);
  if (it != pending_req_.end()) {
    boost::int64_t size_rec = it->second.size_rec;
    boost::uint32_t connection_id = it->second.connection_id;
    boost::int16_t transport_id = it->second.transport_id;
    boost::uint64_t timeout = it->second.timeout;
    if (transport_handler_->HasReceivedData(connection_id, transport_id,
        &size_rec)) {
      it->second.size_rec = size_rec;
      req_mutex_.unlock();
      DLOG(INFO) << transport_handler_->listening_port(transport_id) <<
          " -- Reseting timeout for RPC ID: " << request_id <<
          ". Connection ID: " << connection_id << ". Received: " << size_rec;
      AddReqToTimer(request_id, timeout);
    } else {
      DLOG(INFO) << transport_handler_->listening_port(transport_id) <<
          "Request " << request_id << " times out.  Connection ID: " <<
          connection_id << std::endl;
      // call back without modifying the response
      google::protobuf::Closure* done = (*it).second.callback;
      (*it).second.ctrl->SetFailed(kTimeOut);
      pending_req_.erase(it);
      req_mutex_.unlock();
      done->Run();
      if (connection_id != 0)
        transport_handler_->CloseConnection(connection_id, transport_id);
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
    std::map<boost::uint32_t, PendingReq>::iterator it;
    for (it = pending_req_.begin(); it != pending_req_.end(); ++it)
      delete it->second.callback;
    pending_req_.clear();
  }
  ptimer_->CancelAll();
}

void ChannelManagerImpl::RequestSent(const boost::uint32_t &connection_id,
    const bool &success) {
  std::map<boost::uint32_t, PendingTimeOut>::iterator it;
  boost::mutex::scoped_lock guard(pend_timeout_mutex_);
  it = pending_timeout_.find(connection_id);
  if (it != pending_timeout_.end()) {
    if (success) {
      AddReqToTimer(it->second.request_id, it->second.timeout);
    } else {
      AddReqToTimer(it->second.request_id, 1000);
    }
  }
}

void ChannelManagerImpl::AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &request_id, const int &timeout) {
  struct PendingTimeOut timestruct;
  timestruct.request_id = request_id;
  timestruct.timeout = timeout;
  boost::mutex::scoped_lock guard(pend_timeout_mutex_);
  pending_timeout_[connection_id] = timestruct;
}

void ChannelManagerImpl::OnlineStatusChanged(const bool&) {
  // TODO(anyone) handle connection loss
}

// bool ChannelManagerImpl::RegisterNotifiersToTransport() {
//   if (is_started_) {
//     return true;  // Everything has already been registered
//   }
//    if (transport_handler_->RegisterOnRPCMessage(
//      boost::bind(&ChannelManagerImpl::MessageArrive, this, _1, _2, _3, _4))) {
//   return transport_handler_->RegisterOnSend(boost::bind(
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
