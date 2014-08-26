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

#ifndef MAIDSAFE_RUDP_PACKETS_CONTROL_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_CONTROL_PACKET_H_

#include <cstdint>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/rudp/packets/packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {
class ControlPacketTest;
}

class ControlPacket : public Packet {
 public:
  enum {
    kHeaderSize = 16
  };

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
  size_t EncodeBase(std::vector<boost::asio::mutable_buffer>& buffers) const;

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
