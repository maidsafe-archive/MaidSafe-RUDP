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

#include "maidsafe/transport/rudp_negative_ack_packet.h"

namespace asio = boost::asio;

namespace maidsafe {

namespace transport {

RudpNegativeAckPacket::RudpNegativeAckPacket()
    : sequence_numbers_() {
  SetType(kPacketType);
}

void RudpNegativeAckPacket::AddSequenceNumber(boost::uint32_t n) {
  assert(n <= 0x7fffffff);
  sequence_numbers_.push_back(n);
}

void RudpNegativeAckPacket::AddSequenceNumbers(boost::uint32_t first,
                                               boost::uint32_t last) {
  assert(first <= 0x7fffffff);
  assert(last <= 0x7fffffff);
  sequence_numbers_.push_back(first | 0x80000000);
  sequence_numbers_.push_back(last);
}

bool RudpNegativeAckPacket::IsValid(const asio::const_buffer &buffer) {
  return (IsValidBase(buffer, kPacketType) &&
          (asio::buffer_size(buffer) > kHeaderSize) &&
          ((asio::buffer_size(buffer) - kHeaderSize) % 4 == 0));
}

bool RudpNegativeAckPacket::ContainsSequenceNumber(boost::uint32_t n) const {
  assert(n <= 0x7fffffff);
  for (size_t i = 0; i < sequence_numbers_.size(); ++i) {
    if (((sequence_numbers_[i] & 0x80000000) != 0) &&
        (i + 1 < sequence_numbers_.size())) {
      // This is a range.
      boost::uint32_t first = (sequence_numbers_[i] & 0x7fffffff);
      boost::uint32_t last = (sequence_numbers_[i + 1] & 0x7fffffff);
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

bool RudpNegativeAckPacket::HasSequenceNumbers() const {
  return !sequence_numbers_.empty();
}

bool RudpNegativeAckPacket::Decode(const asio::const_buffer &buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char *p = asio::buffer_cast<const unsigned char *>(buffer);
  size_t length = asio::buffer_size(buffer) - kHeaderSize;
  p += kHeaderSize;

  sequence_numbers_.clear();
  for (size_t i = 0; i < length; i += 4) {
    boost::uint32_t value = 0;
    DecodeUint32(&value, p + i);
    sequence_numbers_.push_back(value);
  }

  return true;
}

size_t RudpNegativeAckPacket::Encode(const asio::mutable_buffer &buffer) const {
  // Refuse to encode if the output buffer is not big enough.
  if (asio::buffer_size(buffer) < kHeaderSize + sequence_numbers_.size() * 4)
    return 0;

  // Encode the common parts of the control packet.
  if (EncodeBase(buffer) == 0)
    return 0;

  unsigned char *p = asio::buffer_cast<unsigned char *>(buffer);
  p += kHeaderSize;

  for (size_t i = 0; i < sequence_numbers_.size(); ++i)
    EncodeUint32(sequence_numbers_[i], p + i * 4);

  return kHeaderSize + sequence_numbers_.size() * 4;
}

}  // namespace transport

}  // namespace maidsafe

