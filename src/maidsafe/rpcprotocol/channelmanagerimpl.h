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
#include "maidsafe/rpcprotocol/channelimpl.h"
#include "maidsafe/rpcprotocol/rpcstructs.h"
#include "maidsafe/transport/transport.h"

namespace transport {
class Transport;
}  // namespace transport

namespace rpcprotocol {

class Channel;

typedef std::map<std::string, base::Stats<boost::uint64_t> > RpcStatsMap;

class ChannelManagerImpl {
 public:
  explicit ChannelManagerImpl(transport::Transport *transport);
  ~ChannelManagerImpl();
  void RegisterChannel(const std::string &service_name, Channel* channel);
  void UnRegisterChannel(const std::string &service_name);
  void AddChannelId(boost::uint32_t *id);
  void RemoveChannelId(const boost::uint32_t &id);
  void ClearChannels();
  void ClearCallLaters();
  int Start();
  int Stop();
  RpcId CreateNewId();
  bool AddPendingRequest(const SocketId &socket_id,
                         PendingRequest pending_request);
  bool DeletePendingRequest(const SocketId &socket_id);
  bool CancelPendingRequest(const SocketId &socket_id);
  void AddReqToTimer(const SocketId &socket_id, const boost::uint64_t &timeout);
//  void AddTimeOutRequest(const ConnectionId &connection_id,
//                         const SocketId &socket_id,
//                         const int &timeout);
  bool RegisterNotifiersToTransport();
  RpcStatsMap RpcTimings();
  void ClearRpcTimings();
 private:
  void TimerHandler(const SocketId &socket_id);
  void RequestSent(const ConnectionId &connection_id, const bool &success);
  void OnlineStatusChanged(const bool &online);
  void RequestArrive(const rpcprotocol::RpcMessage &msg,
                     const SocketId &socket_id,
                     const float &rtt);
  void ResponseArrive(const rpcprotocol::RpcMessage &msg,
                      const SocketId &socket_id,
                      const float &rtt);
  transport::Transport *transport_;
  bool is_started_;
  boost::shared_ptr<base::CallLaterTimer> call_later_timer_;
  boost::mutex req_mutex_, channels_mutex_, id_mutex_, pend_timeout_mutex_,
      channels_ids_mutex_, timings_mutex_;
  RpcId current_rpc_id_;
  boost::uint32_t current_channel_id_;
  std::map<std::string, Channel*> channels_;
  std::map<SocketId, PendingRequest> pending_requests_;
  ChannelManagerImpl(const ChannelManagerImpl&);
  ChannelManagerImpl& operator=(const ChannelManagerImpl&);
  std::map<SocketId, PendingTimeOut> pending_timeouts_;
  std::set<boost::uint32_t> channels_ids_;
  RpcStatsMap rpc_timings_;
  boost::condition_variable delete_channels_cond_;
  boost::uint16_t online_status_id_;
  bs2::connection rpc_request_, rpc_reponse_, data_sent_connection_;
  boost::uint16_t listening_port_;
};

}  // namespace rpcprotocol

#endif  // MAIDSAFE_RPCPROTOCOL_CHANNELMANAGERIMPL_H_
