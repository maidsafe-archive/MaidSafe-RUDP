/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/rudp/packets/handshake_packet.h"

#include <cassert>
#include <cstring>
#include <vector>

#include "maidsafe/common/log.h"

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
      connection_reason_(0),
      socket_id_(0),
      node_id_(),
      syn_cookie_(0),
      request_nat_detection_port_(false),
      nat_detection_port_(0),
      peer_endpoint_(),
      public_key_() {
  SetType(kPacketType);
}

uint32_t HandshakePacket::RudpVersion() const { return rudp_version_; }

void HandshakePacket::SetRudpVersion(uint32_t n) { rudp_version_ = n; }

uint32_t HandshakePacket::SocketType() const { return socket_type_; }

void HandshakePacket::SetSocketType(uint32_t n) { socket_type_ = n; }

uint32_t HandshakePacket::InitialPacketSequenceNumber() const {
  return initial_packet_sequence_number_;
}

void HandshakePacket::SetInitialPacketSequenceNumber(uint32_t n) {
  initial_packet_sequence_number_ = n;
}

uint32_t HandshakePacket::MaximumPacketSize() const { return maximum_packet_size_; }

void HandshakePacket::SetMaximumPacketSize(uint32_t n) { maximum_packet_size_ = n; }

uint32_t HandshakePacket::MaximumFlowWindowSize() const { return maximum_flow_window_size_; }

void HandshakePacket::SetMaximumFlowWindowSize(uint32_t n) { maximum_flow_window_size_ = n; }

uint32_t HandshakePacket::ConnectionType() const { return connection_type_; }

void HandshakePacket::SetConnectionType(uint32_t n) { connection_type_ = n; }

uint32_t HandshakePacket::ConnectionReason() const { return connection_reason_; }

void HandshakePacket::SetConnectionReason(uint32_t n) { connection_reason_ = n; }

uint32_t HandshakePacket::SocketId() const { return socket_id_; }

void HandshakePacket::SetSocketId(uint32_t n) { socket_id_ = n; }

NodeId HandshakePacket::node_id() const { return node_id_; }

void HandshakePacket::set_node_id(NodeId node_id) { node_id_ = node_id; }

uint32_t HandshakePacket::SynCookie() const { return syn_cookie_; }

void HandshakePacket::SetSynCookie(uint32_t n) { syn_cookie_ = n; }

//  boost::asio::ip::address HandshakePacket::IpAddress() const {
//    if (ip_address_.is_v4_compatible())
//      return ip_address_.to_v4();
//    return ip_address_;
//  }

//  void HandshakePacket::SetIpAddress(const boost::asio::ip::address& address) {
//    if (address.is_v4())
//      ip_address_ = boost::asio::ip::address_v6::v4_compatible(address.to_v4());
//    else
//      ip_address_ = address.to_v6();
//  }

bool HandshakePacket::RequestNatDetectionPort() const { return request_nat_detection_port_; }

void HandshakePacket::SetRequestNatDetectionPort(bool b) { request_nat_detection_port_ = b; }

uint16_t HandshakePacket::NatDetectionPort() const { return nat_detection_port_; }

void HandshakePacket::SetNatDetectionPort(uint16_t port) { nat_detection_port_ = port; }

boost::asio::ip::udp::endpoint HandshakePacket::PeerEndpoint() const { return peer_endpoint_; }

void HandshakePacket::SetPeerEndpoint(const boost::asio::ip::udp::endpoint& endpoint) {
  peer_endpoint_ = endpoint;
}

std::shared_ptr<asymm::PublicKey> HandshakePacket::PublicKey() const { return public_key_; }

void HandshakePacket::SetPublicKey(std::shared_ptr<asymm::PublicKey> public_key) {
  public_key_ = public_key;
}

bool HandshakePacket::IsValid(const boost::asio::const_buffer& buffer) {
  // TODO(Fraser#5#): 2012-07-11 - If encoded public key size can be determined, change buffer size
  // check to:  == kMinPacketSize || == kMinPacketSize + key size.
  return (IsValidBase(buffer, kPacketType) && (boost::asio::buffer_size(buffer) >= kMinPacketSize));
}

bool HandshakePacket::Decode(const boost::asio::const_buffer& buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char* p = boost::asio::buffer_cast<const unsigned char*>(buffer);
  size_t length = boost::asio::buffer_size(buffer) - kHeaderSize;

  p += kHeaderSize;

  DecodeUint32(&rudp_version_, p + 0);
  DecodeUint32(&socket_type_, p + 4);
  DecodeUint32(&initial_packet_sequence_number_, p + 8);
  DecodeUint32(&maximum_packet_size_, p + 12);
  DecodeUint32(&maximum_flow_window_size_, p + 16);
  DecodeUint32(&connection_type_, p + 20);
  DecodeUint32(&connection_reason_, p + 24);
  DecodeUint32(&socket_id_, p + 28);
  node_id_ = NodeId(std::string(p + 32, p + 96));
  DecodeUint32(&syn_cookie_, p + 96);

  request_nat_detection_port_ = ((p[100] & 0x80) != 0);
  nat_detection_port_ = p[101];
  nat_detection_port_ = ((nat_detection_port_ << 8) | p[102]);

  boost::asio::ip::address_v6::bytes_type bytes;
  std::memcpy(&bytes[0], p + 103, 16);
  boost::asio::ip::address_v6 ip_v6_address(bytes);

  boost::asio::ip::address ip_address;
  if (ip_v6_address.is_v4_compatible())
    ip_address = ip_v6_address.to_v4();
  else
    ip_address = ip_v6_address;

  unsigned short port = p[119];
  port = ((port << 8) | p[120]);

  peer_endpoint_ = boost::asio::ip::udp::endpoint(ip_address, port);

  if (boost::asio::buffer_size(buffer) != kMinPacketSize) {
    asymm::EncodedPublicKey encoded_public_key(std::string(p + 121, p + length));
    try {
      public_key_ = std::make_shared<asymm::PublicKey>(asymm::DecodeKey(encoded_public_key));
      if (!asymm::ValidateKey(*public_key_)) {
        LOG(kError) << "Failed to validate peer's public key.";
        return false;
      }
    }
    catch (const std::exception& e) {
      LOG(kError) << "Failed to parse peer's public key: " << e.what();
      return false;
    }
  }

  return true;
}

size_t HandshakePacket::Encode(std::vector<boost::asio::mutable_buffer>& buffers) const {
  std::string encoded_public_key;
  if (public_key_) {
    assert(asymm::ValidateKey(*public_key_));
    encoded_public_key = asymm::EncodeKey(*public_key_).string();
    // Refuse to encode if the output buffer is not big enough.
    if (boost::asio::buffer_size(buffers[0])
        < kMinPacketSize + encoded_public_key.size()) {
      LOG(kError) << "Not enough space in buffer to encode public key.";
      return 0;
    }
  } else {
    // Refuse to encode if the output buffer is not big enough.
    if (boost::asio::buffer_size(buffers[0]) < kMinPacketSize)
      return 0;
  }

  // Encode the common parts of the control packet.
  if (EncodeBase(buffers) == 0)
    return 0;

  unsigned char* p = boost::asio::buffer_cast<unsigned char*>(buffers[0]);
  p += kHeaderSize;

  EncodeUint32(rudp_version_, p + 0);
  EncodeUint32(socket_type_, p + 4);
  EncodeUint32(initial_packet_sequence_number_, p + 8);
  EncodeUint32(maximum_packet_size_, p + 12);
  EncodeUint32(maximum_flow_window_size_, p + 16);
  EncodeUint32(connection_type_, p + 20);
  EncodeUint32(connection_reason_, p + 24);
  EncodeUint32(socket_id_, p + 28);
  std::memcpy(p + 32, node_id_.string().data(), 64);
  EncodeUint32(syn_cookie_, p + 96);

  p[100] = (request_nat_detection_port_ ? 0x80 : 0);
  p[101] = ((nat_detection_port_ >> 8) & 0xff);
  p[102] = (nat_detection_port_ & 0xff);

  boost::asio::ip::address_v6 ip_address;
  if (peer_endpoint_.address().is_v4()) {
    ip_address = boost::asio::ip::address_v6::v4_compatible(peer_endpoint_.address().to_v4());
  } else {
    ip_address = peer_endpoint_.address().to_v6();
  }
  boost::asio::ip::address_v6::bytes_type bytes = ip_address.to_bytes();
  std::memcpy(p + 103, &bytes[0], 16);

  p[119] = ((peer_endpoint_.port() >> 8) & 0xff);
  p[120] = (peer_endpoint_.port() & 0xff);

  // As much as we'd like to do a gather write, lifetime is a problem here
  std::memcpy(p + 121, encoded_public_key.data(), encoded_public_key.size());

  // LOG(kVerbose) << "Sending HandshakePacket to " << DestinationSocketId()
  //               << " type " << connection_type_ << " reason " << connection_reason_;

  return kMinPacketSize + encoded_public_key.size();
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
