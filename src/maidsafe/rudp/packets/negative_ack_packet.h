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

#ifndef MAIDSAFE_RUDP_PACKETS_NEGATIVE_ACK_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_NEGATIVE_ACK_PACKET_H_

#include <vector>

#include "boost/asio/buffer.hpp"
#include "maidsafe/rudp/packets/control_packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class NegativeAckPacket : public ControlPacket {
 public:
  enum { kPacketType = 3 };

  NegativeAckPacket();
  virtual ~NegativeAckPacket() {}

  void AddSequenceNumber(uint32_t n);
  void AddSequenceNumbers(uint32_t first, uint32_t last);
  bool ContainsSequenceNumber(uint32_t n) const;
  bool HasSequenceNumbers() const;

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(const boost::asio::mutable_buffer& buffer) const;

 private:
  std::vector<uint32_t> sequence_numbers_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_NEGATIVE_ACK_PACKET_H_
