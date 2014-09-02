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

#ifndef MAIDSAFE_RUDP_PACKETS_ACK_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_ACK_PACKET_H_

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/address.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/rudp/packets/control_packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class AckPacket : public ControlPacket {
 public:
  enum {
    kPacketSize = ControlPacket::kHeaderSize + 4
  };
  enum {
    kOptionalPacketSize = 20
  };
  enum {
    kPacketType = 2
  };
  enum {
    kMaxSequenceNumber = 0x7fffffff
  };

  AckPacket();
  virtual ~AckPacket() {}

  // the sequence number of the ack packet
  uint32_t AckSequenceNumber() const;
  void SetAckSequenceNumber(uint32_t n);

  void ClearSequenceNumbers();
  void AddSequenceNumber(uint32_t n);
  void AddSequenceNumbers(uint32_t first, uint32_t last);
  std::vector<std::pair<uint32_t, uint32_t>> GetSequenceRanges() const;

  bool ContainsSequenceNumber(uint32_t n) const;
  bool HasSequenceNumbers() const;

  bool HasOptionalFields() const;
  void SetHasOptionalFields(bool b);

  // The following fields are optional in the encoded packet.

  uint32_t RoundTripTime() const;
  void SetRoundTripTime(uint32_t n);

  uint32_t RoundTripTimeVariance() const;
  void SetRoundTripTimeVariance(uint32_t n);

  uint32_t AvailableBufferSize() const;
  void SetAvailableBufferSize(uint32_t n);

  uint32_t PacketsReceivingRate() const;
  void SetPacketsReceivingRate(uint32_t n);

  uint32_t EstimatedLinkCapacity() const;
  void SetEstimatedLinkCapacity(uint32_t n);

  // End of optional fields.

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(std::vector<boost::asio::mutable_buffer>& buffers) const;

 private:
  std::vector<std::pair<uint32_t, uint32_t>> sequence_numbers_;
  bool has_optional_fields_;
  uint32_t round_trip_time_;
  uint32_t round_trip_time_variance_;
  uint32_t available_buffer_size_;
  uint32_t packets_receiving_rate_;
  uint32_t estimated_link_capacity_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_ACK_PACKET_H_
