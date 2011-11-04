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

#ifndef MAIDSAFE_TRANSPORT_RUDP_DATA_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_DATA_PACKET_H_

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

#endif  // MAIDSAFE_TRANSPORT_RUDP_DATA_PACKET_H_
