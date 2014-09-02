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

#ifndef MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_

#include <cstdint>
#include <string>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/rudp/packets/packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class DataPacket : public Packet {
 public:
  enum {
    kHeaderSize = 16
  };

  DataPacket();

  uint32_t PacketSequenceNumber() const;
  void SetPacketSequenceNumber(uint32_t n);

  bool FirstPacketInMessage() const;
  void SetFirstPacketInMessage(bool b);

  bool LastPacketInMessage() const;
  void SetLastPacketInMessage(bool b);

  bool InOrder() const;
  void SetInOrder(bool b);

  uint32_t MessageNumber() const;
  void SetMessageNumber(uint32_t n);

  uint32_t TimeStamp() const;
  void SetTimeStamp(uint32_t n);

  uint32_t DestinationSocketId() const;
  void SetDestinationSocketId(uint32_t n);

  const std::string& Data() const;
  void SetData(const std::string& data);

  template <typename Iterator>
  void SetData(Iterator begin, Iterator end) {
    data_.assign(begin, end);
  }

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(std::vector<boost::asio::mutable_buffer>& buffer) const;

 private:
  uint32_t packet_sequence_number_;
  bool first_packet_in_message_;
  bool last_packet_in_message_;
  bool in_order_;
  uint32_t message_number_;
  uint32_t time_stamp_;
  uint32_t destination_socket_id_;
  std::string data_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_
