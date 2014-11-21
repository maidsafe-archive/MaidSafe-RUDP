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

#ifndef MAIDSAFE_RUDP_PACKETS_HANDSHAKE_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_HANDSHAKE_PACKET_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/types.h"
#include "maidsafe/rudp/packets/control_packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class HandshakePacket : public ControlPacket {
 public:
  enum {
    kMinPacketSize = ControlPacket::kHeaderSize + 121
  };
  enum {
    kPacketType = 0
  };

  HandshakePacket();
  virtual ~HandshakePacket() {}

  uint32_t RudpVersion() const;
  void SetRudpVersion(uint32_t n);

  static const uint32_t kStreamSocketType = 0;
  static const uint32_t kDatagramSocketType = 1;
  uint32_t SocketType() const;
  void SetSocketType(uint32_t n);

  uint32_t InitialPacketSequenceNumber() const;
  void SetInitialPacketSequenceNumber(uint32_t n);

  uint32_t MaximumPacketSize() const;
  void SetMaximumPacketSize(uint32_t n);

  uint32_t MaximumFlowWindowSize() const;
  void SetMaximumFlowWindowSize(uint32_t n);

  uint32_t ConnectionType() const;
  void SetConnectionType(uint32_t n);

  uint32_t ConnectionReason() const;
  void SetConnectionReason(uint32_t n);

  uint32_t SocketId() const;
  void SetSocketId(uint32_t n);

  node_id get_node_id() const;
  void set_node_id(node_id node_id);

  uint32_t SynCookie() const;
  void SetSynCookie(uint32_t n);

  bool RequestNatDetectionPort() const;
  void SetRequestNatDetectionPort(bool b);

  uint16_t NatDetectionPort() const;
  void SetNatDetectionPort(uint16_t port);

  boost::asio::ip::udp::endpoint PeerEndpoint() const;
  void SetPeerEndpoint(const boost::asio::ip::udp::endpoint& endpoint);

  asymm::PublicKey PublicKey() const;
  void SetPublicKey(const asymm::PublicKey& public_key);

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(std::vector<boost::asio::mutable_buffer>& buffers) const;

 private:
  uint32_t rudp_version_;
  uint32_t socket_type_;
  uint32_t initial_packet_sequence_number_;
  uint32_t maximum_packet_size_;
  uint32_t maximum_flow_window_size_;
  uint32_t connection_type_;
  uint32_t connection_reason_;
  uint32_t socket_id_;
  node_id node_id_;
  uint32_t syn_cookie_;
  bool request_nat_detection_port_;
  uint16_t nat_detection_port_;
  boost::asio::ip::udp::endpoint peer_endpoint_;
  asymm::PublicKey public_key_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_HANDSHAKE_PACKET_H_
