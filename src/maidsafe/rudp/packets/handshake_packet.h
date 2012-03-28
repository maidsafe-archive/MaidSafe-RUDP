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

#ifndef MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_

#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/cstdint.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_control_packet.h"

namespace maidsafe {

namespace transport {

class RudpHandshakePacket : public RudpControlPacket {
 public:
  enum { kPacketSize = RudpControlPacket::kHeaderSize + 48 };
  enum { kPacketType = 0 };

  RudpHandshakePacket();
  virtual ~RudpHandshakePacket() {}

  boost::uint32_t RudpVersion() const;
  void SetRudpVersion(boost::uint32_t n);

  static const boost::uint32_t kStreamSocketType = 0;
  static const boost::uint32_t kDatagramSocketType = 1;
  boost::uint32_t SocketType() const;
  void SetSocketType(boost::uint32_t n);

  boost::uint32_t InitialPacketSequenceNumber() const;
  void SetInitialPacketSequenceNumber(boost::uint32_t n);

  boost::uint32_t MaximumPacketSize() const;
  void SetMaximumPacketSize(boost::uint32_t n);

  boost::uint32_t MaximumFlowWindowSize() const;
  void SetMaximumFlowWindowSize(boost::uint32_t n);

  boost::uint32_t ConnectionType() const;
  void SetConnectionType(boost::uint32_t n);

  boost::uint32_t SocketId() const;
  void SetSocketId(boost::uint32_t n);

  boost::uint32_t SynCookie() const;
  void SetSynCookie(boost::uint32_t n);

  boost::asio::ip::address IpAddress() const;
  void SetIpAddress(const boost::asio::ip::address &address);

  static bool IsValid(const boost::asio::const_buffer &buffer);
  bool Decode(const boost::asio::const_buffer &buffer);
  size_t Encode(const boost::asio::mutable_buffer &buffer) const;

 private:
  boost::uint32_t rudp_version_;
  boost::uint32_t socket_type_;
  boost::uint32_t initial_packet_sequence_number_;
  boost::uint32_t maximum_packet_size_;
  boost::uint32_t maximum_flow_window_size_;
  boost::uint32_t connection_type_;
  boost::uint32_t socket_id_;
  boost::uint32_t syn_cookie_;
  boost::asio::ip::address_v6 ip_address_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_HANDSHAKE_PACKET_H_
