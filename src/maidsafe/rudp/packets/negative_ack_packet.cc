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

#include "maidsafe/rudp/packets/negative_ack_packet.h"

#include <cassert>

namespace maidsafe {

namespace rudp {

namespace detail {

NegativeAckPacket::NegativeAckPacket() : sequence_numbers_() { SetType(kPacketType); }

void NegativeAckPacket::AddSequenceNumber(uint32_t n) {
  assert(n <= 0x7fffffff);
  sequence_numbers_.push_back(n);
}

void NegativeAckPacket::AddSequenceNumbers(uint32_t first, uint32_t last) {
  assert(first <= 0x7fffffff);
  assert(last <= 0x7fffffff);
  sequence_numbers_.push_back(first | 0x80000000);
  sequence_numbers_.push_back(last);
}

bool NegativeAckPacket::IsValid(const boost::asio::const_buffer& buffer) {
  return (IsValidBase(buffer, kPacketType) && (boost::asio::buffer_size(buffer) > kHeaderSize) &&
          ((boost::asio::buffer_size(buffer) - kHeaderSize) % 4 == 0));
}

bool NegativeAckPacket::ContainsSequenceNumber(uint32_t n) const {
  assert(n <= 0x7fffffff);
  for (size_t i = 0; i < sequence_numbers_.size(); ++i) {
    if (((sequence_numbers_[i] & 0x80000000) != 0) && (i + 1 < sequence_numbers_.size())) {
      // This is a range.
      uint32_t first = (sequence_numbers_[i] & 0x7fffffff);
      uint32_t last = (sequence_numbers_[i + 1] & 0x7fffffff);
      if (first <= last) {
        if ((first <= n) && (n <= last))
          return true;
      } else {
        // The range wraps around past the maximum sequence number.
        if (((first <= n) && (n <= 0x7fffffff)) || (n <= last))
          return true;
      }
    } else {
      // This is a single sequence number.
      if ((sequence_numbers_[i] & 0x7fffffff) == n)
        return true;
    }
  }
  return false;
}

bool NegativeAckPacket::HasSequenceNumbers() const { return !sequence_numbers_.empty(); }

bool NegativeAckPacket::Decode(const boost::asio::const_buffer& buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char* p = boost::asio::buffer_cast<const unsigned char*>(buffer);
  size_t length = boost::asio::buffer_size(buffer) - kHeaderSize;
  p += kHeaderSize;

  sequence_numbers_.clear();
  for (size_t i = 0; i < length; i += 4) {
    uint32_t value = 0;
    DecodeUint32(&value, p + i);
    sequence_numbers_.push_back(value);
  }

  return true;
}

size_t NegativeAckPacket::Encode(std::vector<boost::asio::mutable_buffer>& buffers) const {
  // Refuse to encode if the output buffer is not big enough.
  if (boost::asio::buffer_size(buffers[0]) < kHeaderSize + sequence_numbers_.size() * 4)
    return 0;

  // Encode the common parts of the control packet.
  if (EncodeBase(buffers) == 0)
    return 0;

  unsigned char* p = boost::asio::buffer_cast<unsigned char*>(buffers[0]);
  p += kHeaderSize;

  for (size_t i = 0; i < sequence_numbers_.size(); ++i)
    EncodeUint32(sequence_numbers_[i], p + i * 4);

  return kHeaderSize + sequence_numbers_.size() * 4;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
