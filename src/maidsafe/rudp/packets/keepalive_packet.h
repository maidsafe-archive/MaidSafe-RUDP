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

#ifndef MAIDSAFE_RUDP_PACKETS_KEEPALIVE_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_KEEPALIVE_PACKET_H_

#include "boost/asio/buffer.hpp"
#include "maidsafe/rudp/packets/control_packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class KeepalivePacket : public ControlPacket {
 public:
  enum { kPacketSize = ControlPacket::kHeaderSize };
  enum { kPacketType = 1 };

  KeepalivePacket();
  virtual ~KeepalivePacket() {}

  void SetSequenceNumber(uint32_t n);
  uint32_t SequenceNumber() const;
  // Request will have odd sequence number
  bool IsRequest() const;
  // Response will have even sequence number
  bool IsResponse() const;
  // Checks if this is a response to provided request sequence number (odd).
  bool IsResponseOf(const uint32_t& sequence_number) const;

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(const boost::asio::mutable_buffer& buffer) const;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_KEEPALIVE_PACKET_H_
