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

#ifndef MAIDSAFE_RPCPROTOCOL_CHANNELMANAGERIMPL_H_
#define MAIDSAFE_RPCPROTOCOL_CHANNELMANAGERIMPL_H_

#include <map>
#include <set>
#include <string>
#include <memory>
#include "boost/shared_ptr.hpp"
#include "google/protobuf/service.h"
#include "google/protobuf/message.h"
#include "maidsafe/base/calllatertimer.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/rpcprotocol/channelimpl.h"
#include "maidsafe/transport/transport-api.h"

namespace rpcprotocol {

typedef std::map<std::string, base::Stats<boost::uint64_t> > RpcStatsMap;

struct PendingReq {
  PendingReq() : args(NULL), callback(NULL), ctrl(NULL), connection_id(0),
    transport_id(0), timeout(0), size_rec(0) {}
  google::protobuf::Message* args;
  google::protobuf::Closure* callback;
  Controller *ctrl;
  boost::uint32_t connection_id;
  boost::int16_t transport_id;
  boost::uint64_t timeout;
  boost::int64_t size_rec;
};

struct PendingTimeOut {
  PendingTimeOut() : request_id(0), timeout(0) {}
  boost::uint32_t request_id;
  boost::uint64_t timeout;
};

class ChannelManagerImpl {
 public:
  explicit ChannelManagerImpl(transport::TransportHandler *transport_handler);
  ~ChannelManagerImpl();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void AddChannelId(boost::uint32_t *id);
  void RemoveChannelId(const boost::uint32_t &id);
  void ClearChannels();
  void ClearCallLaters();
  int Start();
  int Stop();
  boost::uint32_t CreateNewId();
  bool AddPendingRequest(const boost::uint32_t &request_id, PendingReq req);
  bool DeletePendingRequest(const boost::uint32_t &request_id);
  bool CancelPendingRequest(const boost::uint32_t &request_id);
  void AddReqToTimer(const boost::uint32_t &request_id,
    const boost::uint64_t &timeout);
  void AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &request_id, const int &timeout);
  bool RegisterNotifiersToTransport();
  RpcStatsMap RpcTimings();
  void ClearRpcTimings();
 private:
  void TimerHandler(const boost::uint32_t &request_id);
  void RequestSent(const boost::uint32_t &connection_id, const bool &success);
  void OnlineStatusChanged(const bool &online);
  void ResponseArrive(const transport::RpcMessage &msg,
                     const boost::uint32_t &connection_id,
                     const boost::int16_t transport_id,
                     const float &rtt);
  void RequestArrive(const transport::RpcMessage &msg,
                     const boost::uint32_t &connection_id,
                     const boost::int16_t transport_id,
                     const float &rtt);
  transport::TransportHandler *transport_handler_;
  bool is_started_;
  boost::shared_ptr<base::CallLaterTimer> ptimer_;
  boost::mutex req_mutex_, channels_mutex_, id_mutex_, pend_timeout_mutex_,
      channels_ids_mutex_, timings_mutex_;
  boost::uint32_t current_request_id_, current_channel_id_;
  std::map<std::string, Channel*> channels_;
  std::map<boost::uint32_t, PendingReq> pending_req_;
  ChannelManagerImpl(const ChannelManagerImpl&);
  ChannelManagerImpl& operator=(const ChannelManagerImpl&);
  std::map<boost::uint32_t, PendingTimeOut> pending_timeout_;
  std::set<boost::uint32_t> channels_ids_;
  RpcStatsMap rpc_timings_;
  boost::condition_variable delete_channels_cond_;
  boost::uint16_t online_status_id_;
  bs2::connection rpc_reponse_, rpc_request_;
  bs2::connection data_sent_connection_;
};
}  // namespace rpcprotocol
#endif  // MAIDSAFE_RPCPROTOCOL_CHANNELMANAGERIMPL_H_
