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

#include "maidsafe/transport/rudp_handshake_packet.h"

#include <cassert>
#include <cstring>

namespace asio = boost::asio;

namespace maidsafe {

namespace transport {

RudpHandshakePacket::RudpHandshakePacket()
  : rudp_version_(0),
    socket_type_(0),
    initial_packet_sequence_number_(0),
    maximum_packet_size_(0),
    maximum_flow_window_size_(0),
    connection_type_(0),
    socket_id_(0),
    syn_cookie_(0),
    ip_address_() {
  SetType(kPacketType);
}

boost::uint32_t RudpHandshakePacket::RudpVersion() const {
  return rudp_version_;
}

void RudpHandshakePacket::SetRudpVersion(boost::uint32_t n) {
  rudp_version_ = n;
}

boost::uint32_t RudpHandshakePacket::SocketType() const {
  return socket_type_;
}

void RudpHandshakePacket::SetSocketType(boost::uint32_t n) {
  socket_type_ = n;
}

boost::uint32_t RudpHandshakePacket::InitialPacketSequenceNumber() const {
  return initial_packet_sequence_number_;
}

void RudpHandshakePacket::SetInitialPacketSequenceNumber(boost::uint32_t n) {
  initial_packet_sequence_number_ = n;
}

boost::uint32_t RudpHandshakePacket::MaximumPacketSize() const {
  return maximum_packet_size_;
}

void RudpHandshakePacket::SetMaximumPacketSize(boost::uint32_t n) {
  maximum_packet_size_ = n;
}

boost::uint32_t RudpHandshakePacket::MaximumFlowWindowSize() const {
  return maximum_flow_window_size_;
}

void RudpHandshakePacket::SetMaximumFlowWindowSize(boost::uint32_t n) {
  maximum_flow_window_size_ = n;
}

boost::uint32_t RudpHandshakePacket::ConnectionType() const {
  return connection_type_;
}

void RudpHandshakePacket::SetConnectionType(boost::uint32_t n) {
  connection_type_ = n;
}

boost::uint32_t RudpHandshakePacket::SocketId() const {
  return socket_id_;
}

void RudpHandshakePacket::SetSocketId(boost::uint32_t n) {
  socket_id_ = n;
}

boost::uint32_t RudpHandshakePacket::SynCookie() const {
  return syn_cookie_;
}

void RudpHandshakePacket::SetSynCookie(boost::uint32_t n) {
  syn_cookie_ = n;
}

asio::ip::address RudpHandshakePacket::IpAddress() const {
  if (ip_address_.is_v4_compatible())
    return ip_address_.to_v4();
  return ip_address_;
}

void RudpHandshakePacket::SetIpAddress(const asio::ip::address &address) {
  if (address.is_v4())
    ip_address_ = asio::ip::address_v6::v4_compatible(address.to_v4());
  else
    ip_address_ = address.to_v6();
}

bool RudpHandshakePacket::IsValid(const asio::const_buffer &buffer) {
  return (IsValidBase(buffer, kPacketType) &&
          (asio::buffer_size(buffer) == kPacketSize));
}

bool RudpHandshakePacket::Decode(const asio::const_buffer &buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char *p = asio::buffer_cast<const unsigned char *>(buffer);
//  size_t length = asio::buffer_size(buffer) - kHeaderSize;
  p += kHeaderSize;

  DecodeUint32(&rudp_version_, p + 0);
  DecodeUint32(&socket_type_, p + 4);
  DecodeUint32(&initial_packet_sequence_number_, p + 8);
  DecodeUint32(&maximum_packet_size_, p + 12);
  DecodeUint32(&maximum_flow_window_size_, p + 16);
  DecodeUint32(&connection_type_, p + 20);
  DecodeUint32(&socket_id_, p + 24);
  DecodeUint32(&syn_cookie_, p + 28);

  asio::ip::address_v6::bytes_type bytes;
  std::memcpy(&bytes[0], p + 32, 16);
  ip_address_ = asio::ip::address_v6(bytes);

  return true;
}

size_t RudpHandshakePacket::Encode(const asio::mutable_buffer &buffer) const {
  // Refuse to encode if the output buffer is not big enough.
  if (asio::buffer_size(buffer) < kPacketSize)
    return 0;

  // Encode the common parts of the control packet.
  if (EncodeBase(buffer) == 0)
    return 0;

  unsigned char *p = asio::buffer_cast<unsigned char *>(buffer);
  p += kHeaderSize;

  EncodeUint32(rudp_version_, p + 0);
  EncodeUint32(socket_type_, p + 4);
  EncodeUint32(initial_packet_sequence_number_, p + 8);
  EncodeUint32(maximum_packet_size_, p + 12);
  EncodeUint32(maximum_flow_window_size_, p + 16);
  EncodeUint32(connection_type_, p + 20);
  EncodeUint32(socket_id_, p + 24);
  EncodeUint32(syn_cookie_, p + 28);

  asio::ip::address_v6::bytes_type bytes = ip_address_.to_bytes();
  std::memcpy(p + 32, &bytes[0], 16);

  return kPacketSize;
}

}  // namespace transport

}  // namespace maidsafe

