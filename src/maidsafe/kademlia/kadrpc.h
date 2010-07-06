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

#ifndef MAIDSAFE_KADEMLIA_KADRPC_H_
#define MAIDSAFE_KADEMLIA_KADRPC_H_

#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/protobuf/kademlia_service.pb.h"
#include "maidsafe/transport/transporthandler-api.h"
#include "maidsafe/maidsafe-dht_config.h"

namespace rpcprotocol {
class Controller;
}  // namespace rpcprotocol

namespace kad {
// different RPCs have different timeouts, normally it is 5 seconds
const boost::uint32_t kRpcPingTimeout = 3;  // 3 secs
const boost::uint32_t kRpcBootstrapTimeout = 7;  // 7secs

class KadId;

class KadRpcs {
 public:
  KadRpcs(rpcprotocol::ChannelManager *channel_manager,
      transport::TransportHandler *transport_handler);
  void FindNode(const KadId &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
  void FindValue(const KadId &key, const std::string &ip,
      const boost::uint16_t &port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, FindResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
  void Ping(const std::string &ip, const boost::uint16_t &port,
      const std::string &rendezvous_ip, const boost::uint16_t &rendezvous_port,
      PingResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *callback);
  void Store(const KadId &key, const SignedValue &value,
      const SignedRequest &sig_req, const std::string &ip,
      const boost::uint16_t &port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, StoreResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback,
      const boost::int32_t &ttl, const bool &publish);
  void Store(const KadId &key, const std::string &value,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rendezvous_ip, const boost::uint16_t &rendezvous_port,
      StoreResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *callback, const boost::int32_t &ttl,
      const bool &publish);
  void Downlist(const std::vector<std::string> downlist,
      const std::string &ip, const boost::uint16_t &port,
      const std::string &rendezvous_ip, const boost::uint16_t &rendezvous_port,
      DownlistResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *callback);
  void Bootstrap(const KadId &local_id, const std::string &local_ip,
      const boost::uint16_t &local_port, const std::string &remote_ip,
      const boost::uint16_t &remote_port, const NodeType &type,
      BootstrapResponse *resp, rpcprotocol::Controller *ctler,
      google::protobuf::Closure *callback);
  void Delete(const KadId &key, const SignedValue &value,
      const SignedRequest &sig_req, const std::string &ip,
      const boost::uint16_t &port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, DeleteResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
  void Update(const KadId &key, const SignedValue &new_value,
      const SignedValue &old_value, const boost::int32_t &ttl,
      const SignedRequest &sig_req, const std::string &ip,
      const boost::uint16_t &port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, UpdateResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
  void set_info(const ContactInfo &info);
 private:
  KadRpcs(const KadRpcs&);
  KadRpcs& operator=(const KadRpcs&);
  ContactInfo info_;
  rpcprotocol::ChannelManager *pchannel_manager_;
  transport::TransportHandler *transport_handler_;
};
}  // namespace kad

#endif  // MAIDSAFE_KADEMLIA_KADRPC_H_
