/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/
// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_

#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/cstdint.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_packet.h"

namespace maidsafe {

namespace transport {

class RudpDataPacket : public RudpPacket {
 public:
  enum { kHeaderSize = 16 };

  RudpDataPacket();

  boost::uint32_t PacketSequenceNumber() const;
  void SetPacketSequenceNumber(boost::uint32_t n);

  bool FirstPacketInMessage() const;
  void SetFirstPacketInMessage(bool b);

  bool LastPacketInMessage() const;
  void SetLastPacketInMessage(bool b);

  bool InOrder() const;
  void SetInOrder(bool b);

  boost::uint32_t MessageNumber() const;
  void SetMessageNumber(boost::uint32_t n);

  boost::uint32_t TimeStamp() const;
  void SetTimeStamp(boost::uint32_t n);

  boost::uint32_t DestinationSocketId() const;
  void SetDestinationSocketId(boost::uint32_t n);

  const std::string &Data() const;
  void SetData(const std::string &data);

  template <typename Iterator>
  void SetData(Iterator begin, Iterator end) {
    data_.assign(begin, end);
  }

  static bool IsValid(const boost::asio::const_buffer &buffer);
  bool Decode(const boost::asio::const_buffer &buffer);
  size_t Encode(const boost::asio::mutable_buffer &buffer) const;

 private:
  boost::uint32_t packet_sequence_number_;
  bool first_packet_in_message_;
  bool last_packet_in_message_;
  bool in_order_;
  boost::uint32_t message_number_;
  boost::uint32_t time_stamp_;
  boost::uint32_t destination_socket_id_;
  std::string data_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_DATA_PACKET_H_
