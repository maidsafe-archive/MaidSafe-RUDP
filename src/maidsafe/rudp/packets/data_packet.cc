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

#include "maidsafe/transport/rudp_data_packet.h"

#include <cassert>
#include <cstring>

namespace asio = boost::asio;

namespace maidsafe {

namespace transport {

RudpDataPacket::RudpDataPacket()
  : packet_sequence_number_(0),
    first_packet_in_message_(false),
    last_packet_in_message_(false),
    in_order_(false),
    message_number_(0),
    time_stamp_(0),
    destination_socket_id_(0),
    data_() {}

boost::uint32_t RudpDataPacket::PacketSequenceNumber() const {
  return packet_sequence_number_;
}

void RudpDataPacket::SetPacketSequenceNumber(boost::uint32_t n) {
  assert(n <= 0x7fffffff);
  packet_sequence_number_ = n;
}

bool RudpDataPacket::FirstPacketInMessage() const {
  return first_packet_in_message_;
}

void RudpDataPacket::SetFirstPacketInMessage(bool b) {
  first_packet_in_message_ = b;
}

bool RudpDataPacket::LastPacketInMessage() const {
  return last_packet_in_message_;
}

void RudpDataPacket::SetLastPacketInMessage(bool b) {
  last_packet_in_message_ = b;
}

bool RudpDataPacket::InOrder() const {
  return in_order_;
}

void RudpDataPacket::SetInOrder(bool b) {
  in_order_ = b;
}

boost::uint32_t RudpDataPacket::MessageNumber() const {
  return message_number_;
}

void RudpDataPacket::SetMessageNumber(boost::uint32_t n) {
  assert(n <= 0x1fffffff);
  message_number_ = n;
}

boost::uint32_t RudpDataPacket::TimeStamp() const {
  return time_stamp_;
}

void RudpDataPacket::SetTimeStamp(boost::uint32_t n) {
  time_stamp_ = n;
}

boost::uint32_t RudpDataPacket::DestinationSocketId() const {
  return destination_socket_id_;
}

void RudpDataPacket::SetDestinationSocketId(boost::uint32_t n) {
  destination_socket_id_ = n;
}

const std::string &RudpDataPacket::Data() const {
  return data_;
}

void RudpDataPacket::SetData(const std::string &data) {
  data_ = data;
}

bool RudpDataPacket::IsValid(const asio::const_buffer &buffer) {
  return ((asio::buffer_size(buffer) >= 16) &&
          ((asio::buffer_cast<const unsigned char *>(buffer)[0] & 0x80) == 0));
}

bool RudpDataPacket::Decode(const asio::const_buffer &buffer) {
  // Refuse to decode if the input buffer is not valid.
  if (!IsValid(buffer))
    return false;

  const unsigned char *p = asio::buffer_cast<const unsigned char *>(buffer);
  size_t length = asio::buffer_size(buffer);

  packet_sequence_number_ = (p[0] & 0x7f);
  packet_sequence_number_ = ((packet_sequence_number_ << 8) | p[1]);
  packet_sequence_number_ = ((packet_sequence_number_ << 8) | p[2]);
  packet_sequence_number_ = ((packet_sequence_number_ << 8) | p[3]);
  first_packet_in_message_ = ((p[4] & 0x80) != 0);
  last_packet_in_message_ = ((p[4] & 0x40) != 0);
  in_order_ = ((p[4] & 0x20) != 0);
  message_number_ = (p[4] & 0x1f);
  message_number_ = ((message_number_ << 8) | p[5]);
  message_number_ = ((message_number_ << 8) | p[6]);
  message_number_ = ((message_number_ << 8) | p[7]);
  DecodeUint32(&time_stamp_, p + 8);
  DecodeUint32(&destination_socket_id_, p + 12);
  data_.assign(p + 16, p + length);

  return true;
}

size_t RudpDataPacket::Encode(const asio::mutable_buffer &buffer) const {
  // Refuse to encode if the output buffer is not big enough.
  if (asio::buffer_size(buffer) < kHeaderSize + data_.size())
    return 0;

  unsigned char *p = asio::buffer_cast<unsigned char *>(buffer);

  p[0] = ((packet_sequence_number_ >> 24) & 0x7f);
  p[1] = ((packet_sequence_number_ >> 16) & 0xff);
  p[2] = ((packet_sequence_number_ >> 8) & 0xff);
  p[3] = (packet_sequence_number_ & 0xff);
  p[4] = ((message_number_ >> 24) & 0x1f);
  p[4] |= (first_packet_in_message_ ? 0x80 : 0);
  p[4] |= (last_packet_in_message_ ? 0x40 : 0);
  p[4] |= (in_order_ ? 0x20 : 0);
  p[5] = ((message_number_ >> 16) & 0xff);
  p[6] = ((message_number_ >> 8) & 0xff);
  p[7] = (message_number_ & 0xff);
  EncodeUint32(time_stamp_, p + 8);
  EncodeUint32(destination_socket_id_, p + 12);
  std::memcpy(p + kHeaderSize, data_.data(), data_.size());

  return kHeaderSize + data_.size();
}

}  // namespace transport

}  // namespace maidsafe
