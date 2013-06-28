/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_PACKETS_CONTROL_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_CONTROL_PACKET_H_

#include <cstdint>

#include "boost/asio/buffer.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/rudp/packets/packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test { class ControlPacketTest; }

class ControlPacket : public Packet {
 public:
  enum { kHeaderSize = 16 };

  ControlPacket();

  uint16_t Type() const;

  uint32_t TimeStamp() const;
  void SetTimeStamp(uint32_t n);

  uint32_t DestinationSocketId() const;
  void SetDestinationSocketId(uint32_t n);

  friend class test::ControlPacketTest;

 protected:
  void SetType(uint16_t n);

  uint32_t AdditionalInfo() const;
  void SetAdditionalInfo(uint32_t n);

  static bool IsValidBase(const boost::asio::const_buffer& buffer, uint16_t expected_packet_type);
  bool DecodeBase(const boost::asio::const_buffer& buffer, uint16_t expected_packet_type);
  size_t EncodeBase(const boost::asio::mutable_buffer& buffer) const;

  // Prevent deletion through this type.
  virtual ~ControlPacket();

 private:
  uint16_t type_;
  uint32_t additional_info_;
  uint32_t time_stamp_;
  uint32_t destination_socket_id_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_CONTROL_PACKET_H_
