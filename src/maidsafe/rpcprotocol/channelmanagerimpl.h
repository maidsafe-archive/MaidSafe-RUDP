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

#include <boost/shared_ptr.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>

#include <map>
#include <set>
#include <string>
#include <memory>

#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/transport/transportconditions.h"

namespace base {
template <typename T>
class Stats;
}  // namespace base

namespace transport {
class TransportUDT;
}  // namespace transport

namespace rpcprotocol {

class Channel;
class RpcMessage;
struct PendingMessage;

typedef std::map<std::string, base::Stats<boost::uint64_t> > RpcStatsMap;

class ChannelManagerImpl {
 public:
  ChannelManagerImpl();
  explicit ChannelManagerImpl(
      boost::shared_ptr<transport::TransportUDT> udt_transport);
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
                         PendingMessage pending_request);
  bool DeletePendingRequest(const SocketId &socket_id);
  bool CancelPendingRequest(const SocketId &socket_id);
  RpcStatsMap RpcTimings();
  void ClearRpcTimings();
 private:
  ChannelManagerImpl(const ChannelManagerImpl&);
  ChannelManagerImpl& operator=(const ChannelManagerImpl&);
  void RpcMessageSent(const SocketId &socket_id, const bool &success);
  void RequestArrive(const rpcprotocol::RpcMessage &msg,
                     const SocketId &socket_id,
                     const float &rtt);
  void ResponseArrive(const rpcprotocol::RpcMessage &msg,
                      const SocketId &socket_id,
                      const float &rtt);
  void RpcStatus(const SocketId &socket_id,
                 const transport::TransportCondition &tc);
  boost::shared_ptr<transport::TransportUDT> udt_transport_;
  bool is_started_;
  boost::mutex message_mutex_, channels_mutex_, id_mutex_, channels_ids_mutex_,
               timings_mutex_;
  RpcId current_rpc_id_;
  boost::uint32_t current_channel_id_;
  std::map<std::string, Channel*> channels_;
  std::map<SocketId, PendingMessage> pending_messages_;
  std::set<boost::uint32_t> channels_ids_;
  RpcStatsMap rpc_timings_;
  boost::condition_variable delete_channels_cond_;
  boost::uint16_t online_status_id_;
  boost::signals2::connection rpc_request_, rpc_reponse_, data_sent_, timeout_;
};

}  // namespace rpcprotocol

#endif  // MAIDSAFE_RPCPROTOCOL_CHANNELMANAGERIMPL_H_
