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

#ifndef MAIDSAFE_TRANSPORT_RUDP_ACK_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_ACK_PACKET_H_

#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/cstdint.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_control_packet.h"

namespace maidsafe {

namespace transport {

class RudpAckPacket : public RudpControlPacket {
 public:
  enum { kPacketSize = RudpControlPacket::kHeaderSize + 4 };
  enum { kOptionalPacketSize = RudpControlPacket::kHeaderSize + 24 };
  enum { kPacketType = 2 };

  RudpAckPacket();
  virtual ~RudpAckPacket() {}

  boost::uint32_t AckSequenceNumber() const;
  void SetAckSequenceNumber(boost::uint32_t n);

  boost::uint32_t PacketSequenceNumber() const;
  void SetPacketSequenceNumber(boost::uint32_t n);

  bool HasOptionalFields() const;
  void SetHasOptionalFields(bool b);

  // The following fields are optional in the encoded packet.

  boost::uint32_t RoundTripTime() const;
  void SetRoundTripTime(boost::uint32_t n);

  boost::uint32_t RoundTripTimeVariance() const;
  void SetRoundTripTimeVariance(boost::uint32_t n);

  boost::uint32_t AvailableBufferSize() const;
  void SetAvailableBufferSize(boost::uint32_t n);

  boost::uint32_t PacketsReceivingRate() const;
  void SetPacketsReceivingRate(boost::uint32_t n);

  boost::uint32_t EstimatedLinkCapacity() const;
  void SetEstimatedLinkCapacity(boost::uint32_t n);

  // End of optional fields.

  static bool IsValid(const boost::asio::const_buffer &buffer);
  bool Decode(const boost::asio::const_buffer &buffer);
  size_t Encode(const boost::asio::mutable_buffer &buffer) const;

 private:
  boost::uint32_t packet_sequence_number_;
  bool has_optional_fields_;
  boost::uint32_t round_trip_time_;
  boost::uint32_t round_trip_time_variance_;
  boost::uint32_t available_buffer_size_;
  boost::uint32_t packets_receiving_rate_;
  boost::uint32_t estimated_link_capacity_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_ACK_PACKET_H_
