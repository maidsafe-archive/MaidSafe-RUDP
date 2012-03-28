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

#include "maidsafe/transport/rudp_ack_packet.h"

#include <cassert>
#include <cstring>

namespace asio = boost::asio;

namespace maidsafe {

namespace transport {

RudpAckPacket::RudpAckPacket()
  : packet_sequence_number_(0),
    has_optional_fields_(false),
    round_trip_time_(0),
    round_trip_time_variance_(0),
    available_buffer_size_(0),
    packets_receiving_rate_(0),
    estimated_link_capacity_(0) {
  SetType(kPacketType);
}

boost::uint32_t RudpAckPacket::AckSequenceNumber() const {
  return AdditionalInfo();
}

void RudpAckPacket::SetAckSequenceNumber(boost::uint32_t n) {
  SetAdditionalInfo(n);
}

boost::uint32_t RudpAckPacket::PacketSequenceNumber() const {
  return packet_sequence_number_;
}

void RudpAckPacket::SetPacketSequenceNumber(boost::uint32_t n) {
  packet_sequence_number_ = n;
}

bool RudpAckPacket::HasOptionalFields() const {
  return has_optional_fields_;
}

void RudpAckPacket::SetHasOptionalFields(bool b) {
  has_optional_fields_ = b;
}

boost::uint32_t RudpAckPacket::RoundTripTime() const {
  return round_trip_time_;
}

void RudpAckPacket::SetRoundTripTime(boost::uint32_t n) {
  round_trip_time_ = n;
}

boost::uint32_t RudpAckPacket::RoundTripTimeVariance() const {
  return round_trip_time_variance_;
}

void RudpAckPacket::SetRoundTripTimeVariance(boost::uint32_t n) {
  round_trip_time_variance_ = n;
}

boost::uint32_t RudpAckPacket::AvailableBufferSize() const {
  return available_buffer_size_;
}

void RudpAckPacket::SetAvailableBufferSize(boost::uint32_t n) {
  available_buffer_size_ = n;
}

boost::uint32_t RudpAckPacket::PacketsReceivingRate() const {
  return packets_receiving_rate_;
}

void RudpAckPacket::SetPacketsReceivingRate(boost::uint32_t n) {
  packets_receiving_rate_ = n;
}

boost::uint32_t RudpAckPacket::EstimatedLinkCapacity() const {
  return estimated_link_capacity_;
}

void RudpAckPacket::SetEstimatedLinkCapacity(boost::uint32_t n) {
  estimated_link_capacity_ = n;
}

bool RudpAckPacket::IsValid(const asio::const_buffer &buffer) {
  return (IsValidBase(buffer, kPacketType) &&
          ((asio::buffer_size(buffer) == kPacketSize) ||
           (asio::buffer_size(buffer) == kOptionalPacketSize)));
}

bool RudpAckPacket::Decode(const asio::const_buffer &buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  // Decode the common parts of the control packet.
  if (!DecodeBase(buffer, kPacketType))
    return false;

  const unsigned char *p = asio::buffer_cast<const unsigned char *>(buffer);
//   size_t length = asio::buffer_size(buffer) - kHeaderSize;
  p += kHeaderSize;

  DecodeUint32(&packet_sequence_number_, p + 0);
  if (asio::buffer_size(buffer) == kOptionalPacketSize) {
    has_optional_fields_ = true;
    DecodeUint32(&round_trip_time_, p + 4);
    DecodeUint32(&round_trip_time_variance_, p + 8);
    DecodeUint32(&available_buffer_size_, p + 12);
    DecodeUint32(&packets_receiving_rate_, p + 16);
    DecodeUint32(&estimated_link_capacity_, p + 20);
  }

  return true;
}

size_t RudpAckPacket::Encode(const asio::mutable_buffer &buffer) const {
  // Refuse to encode if the output buffer is not big enough.
  if (asio::buffer_size(buffer) < kPacketSize)
    return 0;

  // Encode the common parts of the control packet.
  if (EncodeBase(buffer) == 0)
    return 0;

  unsigned char *p = asio::buffer_cast<unsigned char *>(buffer);
  p += kHeaderSize;

  EncodeUint32(packet_sequence_number_, p + 0);
  if (has_optional_fields_) {
    EncodeUint32(round_trip_time_, p + 4);
    EncodeUint32(round_trip_time_variance_, p + 8);
    EncodeUint32(available_buffer_size_, p + 12);
    EncodeUint32(packets_receiving_rate_, p + 16);
    EncodeUint32(estimated_link_capacity_, p + 20);
  }

  return has_optional_fields_ ? static_cast<size_t>(kOptionalPacketSize)
      : static_cast<size_t>(kPacketSize);
}

}  // namespace transport

}  // namespace maidsafe

