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

#ifndef MAIDSAFE_TRANSPORT_RUDP_CONTROL_PACKET_H_
#define MAIDSAFE_TRANSPORT_RUDP_CONTROL_PACKET_H_

#include "boost/asio/buffer.hpp"
#include "boost/cstdint.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_packet.h"

namespace maidsafe {

namespace transport {

namespace test {
class RudpControlPacketTest;
}  // namespace test

class RudpControlPacket : public RudpPacket {
 public:
  enum { kHeaderSize = 16 };

  RudpControlPacket();

  boost::uint16_t Type() const;

  boost::uint32_t TimeStamp() const;
  void SetTimeStamp(boost::uint32_t n);

  boost::uint32_t DestinationSocketId() const;
  void SetDestinationSocketId(boost::uint32_t n);

  friend class test::RudpControlPacketTest;
 protected:
  void SetType(boost::uint16_t n);

  boost::uint32_t AdditionalInfo() const;
  void SetAdditionalInfo(boost::uint32_t n);

  static bool IsValidBase(const boost::asio::const_buffer &buffer,
                          boost::uint16_t expected_packet_type);
  bool DecodeBase(const boost::asio::const_buffer &buffer,
                  boost::uint16_t expected_packet_type);
  size_t EncodeBase(const boost::asio::mutable_buffer &buffer) const;

  // Prevent deletion through this type.
  virtual ~RudpControlPacket();

 private:
  boost::uint16_t type_;
  boost::uint32_t additional_info_;
  boost::uint32_t time_stamp_;
  boost::uint32_t destination_socket_id_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_CONTROL_PACKET_H_
