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

#ifndef MAIDSAFE_RPCPROTOCOL_CHANNELIMPL_H_
#define MAIDSAFE_RPCPROTOCOL_CHANNELIMPL_H_

#include <boost/asio.hpp>
#include <google/protobuf/service.h>
#include <memory>
#include <string>
#include "maidsafe/base/utils.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/transport/transporthandler-api.h"

namespace rpcprotocol {

class Controller;
class ChannelManager;

class ControllerImpl {
 public:
  ControllerImpl()
      : timeout_(kRpcTimeout),
        time_sent_(0),
        time_received_(0),
        rtt_(0.0),
        failure_(),
        request_id_(0),
        transport_id_(0),
        service_(),
        method_() {}
  void SetFailed(const std::string &failure) { failure_ = failure; }
  void Reset();
  bool Failed() const { return !failure_.empty(); }
  std::string ErrorText() const { return failure_; }
  void StartCancel() {}
  bool IsCanceled() const { return false; }
  void NotifyOnCancel(google::protobuf::Closure*) {}
  // input is in seconds
  void set_timeout(const boost::uint32_t &seconds) {
    timeout_ = static_cast<boost::uint64_t>(seconds)*1000;
  }
  // returns timeout in milliseconds
  boost::uint64_t timeout() const { return timeout_; }
  // returns time between sending and receiving the RPC in milliseconds
  boost::uint64_t Duration() const {
    return time_sent_ < time_received_ ? time_received_ - time_sent_ : 0;
  }
  // set sending time
  void StartRpcTimer() { time_sent_ = base::GetEpochMilliseconds(); }
  // set receiving time
  void StopRpcTimer() { time_received_ = base::GetEpochMilliseconds(); }
  // rtt in milliseconds
  void set_rtt(const float &rtt) { rtt_ = rtt; }
  float rtt() const { return rtt_; }
  void set_transport_id(const boost::int16_t &transport_id) {
    transport_id_ = transport_id;
  }
  boost::int16_t transport_id() const { return transport_id_; }
  void set_request_id(const boost::uint32_t &id) { request_id_ = id; }
  boost::uint32_t request_id() const { return request_id_; }
  // Set additional information for the processed message.
  void set_message_info(const std::string &service, const std::string &method) {
    service_ = service;
    method_ = method;
  }
  // Get information for the processed message, if stored.
  void message_info(std::string *service, std::string *method) const {
    *service = service_;
    *method = method_;
  }
 private:
  boost::uint64_t timeout_;
  boost::uint64_t time_sent_, time_received_;
  float rtt_;
  std::string failure_;
  boost::uint32_t request_id_;
  boost::int16_t transport_id_;
  std::string service_, method_;
};

struct RpcInfo {
  RpcInfo() : ctrl(NULL), rpc_id(0), connection_id(0), transport_id(0) {}
  Controller *ctrl;
  boost::uint32_t rpc_id, connection_id;
  boost::int16_t transport_id;
};

class ChannelImpl {
 public:
  ChannelImpl(ChannelManager *channelmanager,
              transport::TransportHandler *transport_handler);
  ChannelImpl(ChannelManager *channelmanager,
              transport::TransportHandler *transport_handler,
              const boost::int16_t &transport_id, const std::string &remote_ip,
              const boost::uint16_t &remote_port, const std::string &local_ip,
              const boost::uint16_t &local_port,
              const std::string &rendezvous_ip,
              const boost::uint16_t &rendezvous_port);
  ~ChannelImpl();
  void CallMethod(const google::protobuf::MethodDescriptor *method,
                  google::protobuf::RpcController *controller,
                  const google::protobuf::Message *request,
                  google::protobuf::Message *response,
                  google::protobuf::Closure *done);
  void SetService(google::protobuf::Service *service);
  void HandleRequest(const RpcMessage &request,
                     const boost::uint32_t &connection_id,
                     const boost::int16_t &transport_id,
                     const float &rtt);
 private:
  void SendResponse(const google::protobuf::Message *response, RpcInfo info);
  std::string GetServiceName(const std::string &full_name);
  transport::TransportHandler *transport_handler_;
  boost::int16_t transport_id_;
  ChannelManager *pmanager_;
  google::protobuf::Service *pservice_;
  std::string remote_ip_, local_ip_, rv_ip_;
  boost::uint16_t remote_port_, local_port_, rv_port_;
  ChannelImpl(const ChannelImpl&);
  ChannelImpl& operator=(const ChannelImpl&);
  boost::uint32_t id_;
};
}  // namespace
#endif  // MAIDSAFE_RPCPROTOCOL_CHANNELIMPL_H_
