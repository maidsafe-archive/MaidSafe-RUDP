/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/
// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/rudp/packets/handshake_packet.h"

#include <cassert>
#include <cstring>

namespace asio = boost::asio;

namespace maidsafe {

namespace rudp {

namespace detail {

HandshakePacket::HandshakePacket()
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

uint32_t HandshakePacket::RudpVersion() const {
  return rudp_version_;
}

void HandshakePacket::SetRudpVersion(uint32_t n) {
  rudp_version_ = n;
}

uint32_t HandshakePacket::SocketType() const {
  return socket_type_;
}

void HandshakePacket::SetSocketType(uint32_t n) {
  socket_type_ = n;
}

uint32_t HandshakePacket::InitialPacketSequenceNumber() const {
  return initial_packet_sequence_number_;
}

void HandshakePacket::SetInitialPacketSequenceNumber(uint32_t n) {
  initial_packet_sequence_number_ = n;
}

uint32_t HandshakePacket::MaximumPacketSize() const {
  return maximum_packet_size_;
}

void HandshakePacket::SetMaximumPacketSize(uint32_t n) {
  maximum_packet_size_ = n;
}

uint32_t HandshakePacket::MaximumFlowWindowSize() const {
  return maximum_flow_window_size_;
}

void HandshakePacket::SetMaximumFlowWindowSize(uint32_t n) {
  maximum_flow_window_size_ = n;
}

uint32_t HandshakePacket::ConnectionType() const {
  return connection_type_;
}

void HandshakePacket::SetConnectionType(uint32_t n) {
  connection_type_ = n;
}

uint32_t HandshakePacket::SocketId() const {
  return socket_id_;
}

void HandshakePacket::SetSocketId(uint32_t n) {
  socket_id_ = n;
}

uint32_t HandshakePacket::SynCookie() const {
  return syn_cookie_;
}

void HandshakePacket::SetSynCookie(uint32_t n) {
  syn_cookie_ = n;
}

asio::ip::address HandshakePacket::IpAddress() const {
  if (ip_address_.is_v4_compatible())
    return ip_address_.to_v4();
  return ip_address_;
}

void HandshakePacket::SetIpAddress(const asio::ip::address &address) {
  if (address.is_v4())
    ip_address_ = asio::ip::address_v6::v4_compatible(address.to_v4());
  else
    ip_address_ = address.to_v6();
}

bool HandshakePacket::IsValid(const asio::const_buffer &buffer) {
  return (IsValidBase(buffer, kPacketType) &&
          (asio::buffer_size(buffer) == kPacketSize));
}

bool HandshakePacket::Decode(const asio::const_buffer &buffer) {
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

size_t HandshakePacket::Encode(const asio::mutable_buffer &buffer) const {
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

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
