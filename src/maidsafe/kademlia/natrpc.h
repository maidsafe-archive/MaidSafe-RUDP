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

#ifndef MAIDSAFE_KADEMLIA_NATRPC_H_
#define MAIDSAFE_KADEMLIA_NATRPC_H_

#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <string>
#include "maidsafe/protobuf/kademlia_service.pb.h"
#include "maidsafe/rpcprotocol/channelmanager-api.h"
#include "maidsafe/transport/transporthandler-api.h"

namespace rpcprotocol {
class Controller;
}  // namespace rpcprotocol

namespace kad {
const boost::uint32_t kRpcNatPingTimeout = 3;
class NatRpcs {
 public:
  NatRpcs(rpcprotocol::ChannelManager *ch_manager, transport::TransportHandler
    *transport_handler);
  void NatDetection(const std::string &newcomer,
      const std::string &bootstrap_node, const boost::uint32_t type,
      const std::string &sender_id, const std::string &remote_ip,
      const boost::uint16_t &remote_port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, NatDetectionResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
  void NatDetectionPing(const std::string &remote_ip,
      const boost::uint16_t &remote_port, const std::string &rendezvous_ip,
      const boost::uint16_t &rendezvous_port, NatDetectionPingResponse *resp,
      rpcprotocol::Controller *ctler, google::protobuf::Closure *callback);
 private:
  rpcprotocol::ChannelManager *pchannel_manager_;
  transport::TransportHandler *transport_handler_;
};
}  // namespace kad
#endif  // MAIDSAFE_KADEMLIA_NATRPC_H_
