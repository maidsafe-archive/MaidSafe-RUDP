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

#include "maidsafe/rudp/packets/ack_packet.h"

#include <cassert>
#include <cstring>

namespace maidsafe {

namespace rudp {

namespace detail {

AckPacket::AckPacket()
    : has_optional_fields_(false),
      round_trip_time_(0),
      round_trip_time_variance_(0),
      available_buffer_size_(0),
      packets_receiving_rate_(0),
      estimated_link_capacity_(0) {
  SetType(kPacketType);
}

uint32_t AckPacket::AckSequenceNumber() const { return AdditionalInfo(); }

void AckPacket::SetAckSequenceNumber(uint32_t n) { SetAdditionalInfo(n); }

bool AckPacket::HasOptionalFields() const { return has_optional_fields_; }

void AckPacket::SetHasOptionalFields(bool b) { has_optional_fields_ = b; }

uint32_t AckPacket::RoundTripTime() const { return round_trip_time_; }

void AckPacket::SetRoundTripTime(uint32_t n) { round_trip_time_ = n; }

uint32_t AckPacket::RoundTripTimeVariance() const { return round_trip_time_variance_; }

void AckPacket::SetRoundTripTimeVariance(uint32_t n) { round_trip_time_variance_ = n; }

uint32_t AckPacket::AvailableBufferSize() const { return available_buffer_size_; }

void AckPacket::SetAvailableBufferSize(uint32_t n) { available_buffer_size_ = n; }

uint32_t AckPacket::PacketsReceivingRate() const { return packets_receiving_rate_; }

void AckPacket::SetPacketsReceivingRate(uint32_t n) { packets_receiving_rate_ = n; }

uint32_t AckPacket::EstimatedLinkCapacity() const { return estimated_link_capacity_; }

void AckPacket::SetEstimatedLinkCapacity(uint32_t n) { estimated_link_capacity_ = n; }

bool AckPacket::IsValid(const boost::asio::const_buffer& buffer) {
  auto buffer_size = boost::asio::buffer_size(buffer);
  if (!IsValidBase(buffer, kPacketType) || buffer_size < kPacketSize)
    return false;

  // get the number of sequence parameters
  auto p = boost::asio::buffer_cast<const unsigned char*>(buffer) + kHeaderSize;
  uint32_t sequence_count = 0;
  DecodeUint32(&sequence_count, p);

  return buffer_size == kPacketSize + (sequence_count * 4) ||
         buffer_size == kPacketSize + (sequence_count * 4) + kOptionalPacketSize;
}

void AckPacket::ClearSequenceNumbers() {
  sequence_numbers_.clear();
}

void AckPacket::AddSequenceNumber(uint32_t n) {
  AddSequenceNumbers(n, n);
}

void AckPacket::AddSequenceNumbers(uint32_t first, uint32_t last) {
  assert(first <= kMaxSequenceNumber);
  assert(last <= kMaxSequenceNumber);
  if (last >= first) {
    sequence_numbers_.push_back(std::make_pair(first, last));
  } else {
    // Sequence numbers have wrapped. Break into two segments.
    sequence_numbers_.push_back(std::make_pair(first, kMaxSequenceNumber));
    sequence_numbers_.push_back(std::make_pair(0, last));
  }
}

bool AckPacket::ContainsSequenceNumber(uint32_t n) const {
  for (auto seq_range : sequence_numbers_) {
    if (seq_range.first <= n && n <= seq_range.second)
      return true;
  }
  return false;
}

bool AckPacket::HasSequenceNumbers() const {
  return !sequence_numbers_.empty();
}

std::vector<std::pair<uint32_t, uint32_t>> AckPacket::GetSequenceRanges() const {
  return sequence_numbers_;
}

bool AckPacket::Decode(const boost::asio::const_buffer& buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char* p = boost::asio::buffer_cast<const unsigned char *>(buffer);
  const unsigned char* buffer_end = p + boost::asio::buffer_size(buffer);
  p += kHeaderSize;

  // get the number of sequence parameters
  uint32_t sequence_count = 0;
  DecodeUint32(&sequence_count, p);
  p += 4;
  sequence_numbers_.clear();
  sequence_numbers_.reserve(sequence_count);
  for (size_t i = 0; i < sequence_count; ++i) {
    uint32_t first = 0;
    DecodeUint32(&first, p + i*4);
    uint32_t second = first;
    if (first & 0x80000000) {
      if (++i >= sequence_count)
        return false;
      first = first & 0x7fffffff;
      DecodeUint32(&second, p + i*4);
    }
    sequence_numbers_.push_back(std::make_pair(first, second));
  }

  p += sequence_count * 4;

  if ((buffer_end - p) ==  kOptionalPacketSize) {
    has_optional_fields_ = true;
    DecodeUint32(&round_trip_time_, p);
    DecodeUint32(&round_trip_time_variance_, p + 4);
    DecodeUint32(&available_buffer_size_, p + 8);
    DecodeUint32(&packets_receiving_rate_, p + 12);
    DecodeUint32(&estimated_link_capacity_, p + 16);
  }

  return true;
}

size_t AckPacket::Encode(std::vector<boost::asio::mutable_buffer>& buffers) const {
  size_t required_bytes = kPacketSize +
                          (has_optional_fields_ ? kOptionalPacketSize : 0) +
                          sequence_numbers_.size()*2*4;

  // Refuse to encode if the output buffer is not big enough.
  if (boost::asio::buffer_size(buffers[0]) < required_bytes)
    return 0;

  // Encode the common parts of the control packet.
  if (EncodeBase(buffers) == 0)
    return 0;

  unsigned char* p = boost::asio::buffer_cast<unsigned char*>(buffers[0]);
  p += kHeaderSize;


  // get the pointer to the count so we can update it when we know the number
  // of items stored
  unsigned char* pcount = p;
  p += 4;
  for (auto seq_range : sequence_numbers_) {
    // if (seq_range.first == seq_range.second) {
    //   EncodeUint32(seq_range.first, p);
    //   p += 4;
    // } else {
      EncodeUint32(seq_range.first | 0x80000000, p);
      p += 4;
      EncodeUint32(seq_range.second, p);
      p += 4;
    // }
  }
  // store the number of items in the list
  EncodeUint32(static_cast<uint32_t>(p-pcount-4)/4, pcount);

  if (has_optional_fields_) {
    EncodeUint32(round_trip_time_, p + 0);
    EncodeUint32(round_trip_time_variance_, p + 4);
    EncodeUint32(available_buffer_size_, p + 8);
    EncodeUint32(packets_receiving_rate_, p + 12);
    EncodeUint32(estimated_link_capacity_, p + 16);
  }

  return required_bytes;
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
