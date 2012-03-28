/* Copyright (c) 2010 maidsafe.net limited
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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_RUDP_PEER_H_
#define MAIDSAFE_TRANSPORT_RUDP_PEER_H_

#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "maidsafe/transport/rudp_multiplexer.h"

namespace maidsafe {

namespace transport {

class RudpPeer {
 public:
  explicit RudpPeer(RudpMultiplexer &multiplexer)  // NOLINT (Fraser)
    : multiplexer_(multiplexer), endpoint_(), id_(0) {}

  const boost::asio::ip::udp::endpoint &Endpoint() const { return endpoint_; }
  void SetEndpoint(const boost::asio::ip::udp::endpoint &ep) { endpoint_ = ep; }

  boost::uint32_t Id() const { return id_; }
  void SetId(boost::uint32_t id) { id_ = id; }

  template <typename Packet>
  TransportCondition Send(const Packet &packet) {
    return multiplexer_.SendTo(packet, endpoint_);
  }

 private:
  // Disallow copying and assignment.
  RudpPeer(const RudpPeer&);
  RudpPeer &operator=(const RudpPeer&);

  // The multiplexer used to send and receive UDP packets.
  RudpMultiplexer &multiplexer_;

  // The remote socket's endpoint and identifier.
  boost::asio::ip::udp::endpoint endpoint_;
  boost::uint32_t id_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_PEER_H_
