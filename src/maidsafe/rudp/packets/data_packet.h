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

#ifndef MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_

#include <cstdint>
#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/rudp/packets/packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class DataPacket : public Packet {
 public:
  enum { kHeaderSize = 16 };

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
  void SetData(Iterator begin, Iterator end) { data_.assign(begin, end); }

  static bool IsValid(const boost::asio::const_buffer& buffer);
  bool Decode(const boost::asio::const_buffer& buffer);
  size_t Encode(const boost::asio::mutable_buffer& buffer) const;

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
