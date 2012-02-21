/* Copyright (c) 2011 maidsafe.net limited
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

#include "maidsafe/common/test.h"

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/rudp_packet.h"
#include "maidsafe/transport/rudp_data_packet.h"
#include "maidsafe/transport/rudp_control_packet.h"
#include "maidsafe/transport/rudp_ack_packet.h"
#include "maidsafe/transport/rudp_handshake_packet.h"
#include "maidsafe/transport/rudp_keepalive_packet.h"
#include "maidsafe/transport/rudp_shutdown_packet.h"
#include "maidsafe/transport/rudp_ack_of_ack_packet.h"
#include "maidsafe/transport/rudp_negative_ack_packet.h"
#include "maidsafe/transport/rudp_parameters.h"

namespace maidsafe {

namespace transport {

namespace test {

TEST(RudpPacketTest, FUNC_DecodeDestinationSocketId) {
  {
    // Try to decode with an invalid buffer
    boost::uint32_t id;
    char d[15];
    EXPECT_FALSE(RudpPacket::DecodeDestinationSocketId(&id,
                                                       boost::asio::buffer(d)));
  }
  {
    // Decode with a valid buffer
    char d[16];
    d[12] = 0x44;
    d[13] = 0x22;
    d[14] = 0x11;
    d[15] = 0x00;
    boost::uint32_t id;
    EXPECT_TRUE(RudpPacket::DecodeDestinationSocketId(&id,
                                                      boost::asio::buffer(d)));
    EXPECT_EQ(0x44221100, id);
  }
}

class RudpDataPacketTest : public testing::Test {
 public:
  RudpDataPacketTest() : data_packet_() {}

  void RestoreDefault() {
    data_packet_.SetFirstPacketInMessage(false);
    data_packet_.SetLastPacketInMessage(false);
    data_packet_.SetInOrder(false);
    data_packet_.SetPacketSequenceNumber(0);
    data_packet_.SetMessageNumber(0);
    data_packet_.SetTimeStamp(0);
    data_packet_.SetDestinationSocketId(0);
    data_packet_.SetData("");
  }

  void TestEncodeDecode() {
    std::string data;
    for (uint32_t i = 0; i < RudpParameters::max_size; ++i)
      data += "a";
    boost::uint32_t packet_sequence_number = 0x7fffffff;
    boost::uint32_t message_number = 0x1fffffff;
    boost::uint32_t time_stamp = 0xffffffff;
    boost::uint32_t destination_socket_id = 0xffffffff;

    data_packet_.SetData(data);
    data_packet_.SetPacketSequenceNumber(packet_sequence_number);
    data_packet_.SetMessageNumber(message_number);
    data_packet_.SetTimeStamp(time_stamp);
    data_packet_.SetDestinationSocketId(destination_socket_id);

    char char_array[RudpParameters::kUDPPayload];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(&char_array[0],
        RudpDataPacket::kHeaderSize + RudpParameters::max_size));
    EXPECT_EQ(RudpDataPacket::kHeaderSize + data.size(),
              data_packet_.Encode(dbuffer));
    RestoreDefault();
    EXPECT_TRUE(data_packet_.Decode(dbuffer));

    std::string full_data = data_packet_.Data();
    std::string trimmed_data;
    trimmed_data.assign(full_data, 0, data.size());
    EXPECT_EQ(data, trimmed_data);
    EXPECT_EQ(packet_sequence_number, data_packet_.PacketSequenceNumber());
    EXPECT_EQ(message_number, data_packet_.MessageNumber());
    EXPECT_EQ(time_stamp, data_packet_.TimeStamp());
    EXPECT_EQ(destination_socket_id, data_packet_.DestinationSocketId());
  }

 protected:
  RudpDataPacket data_packet_;
};

TEST_F(RudpDataPacketTest, FUNC_SequenceNumber) {
  EXPECT_EQ(0U, data_packet_.PacketSequenceNumber());
//   data_packet_.SetPacketSequenceNumber(0x80000000);
//   EXPECT_EQ(0U, data_packet_.PacketSequenceNumber());
  data_packet_.SetPacketSequenceNumber(0x7fffffff);
  EXPECT_EQ(0x7fffffff, data_packet_.PacketSequenceNumber());
}

TEST_F(RudpDataPacketTest, FUNC_FirstPacketInMessage) {
  EXPECT_FALSE(data_packet_.FirstPacketInMessage());
  data_packet_.SetFirstPacketInMessage(true);
  EXPECT_TRUE(data_packet_.FirstPacketInMessage());
}

TEST_F(RudpDataPacketTest, FUNC_LastPacketInMessage) {
  EXPECT_FALSE(data_packet_.LastPacketInMessage());
  data_packet_.SetLastPacketInMessage(true);
  EXPECT_TRUE(data_packet_.LastPacketInMessage());
}

TEST_F(RudpDataPacketTest, FUNC_InOrder) {
  EXPECT_FALSE(data_packet_.InOrder());
  data_packet_.SetInOrder(true);
  EXPECT_TRUE(data_packet_.InOrder());
}

TEST_F(RudpDataPacketTest, FUNC_MessageNumber) {
  EXPECT_EQ(0U, data_packet_.MessageNumber());
//   data_packet_.SetPacketMessageNumber(0x20000000);
//   EXPECT_EQ(0U, data_packet_.MessageNumber());
  data_packet_.SetMessageNumber(0x1fffffff);
  EXPECT_EQ(0x1fffffff, data_packet_.MessageNumber());
}

TEST_F(RudpDataPacketTest, FUNC_TimeStamp) {
  EXPECT_EQ(0U, data_packet_.TimeStamp());
  data_packet_.SetTimeStamp(0xffffffff);
  EXPECT_EQ(0xffffffff, data_packet_.TimeStamp());
}

TEST_F(RudpDataPacketTest, FUNC_DestinationSocketId) {
  EXPECT_EQ(0U, data_packet_.DestinationSocketId());
  data_packet_.SetDestinationSocketId(0xffffffff);
  EXPECT_EQ(0xffffffff, data_packet_.DestinationSocketId());
}

TEST_F(RudpDataPacketTest, FUNC_Data) {
  EXPECT_EQ("", data_packet_.Data());
  data_packet_.SetData("Data Test");
  EXPECT_EQ("Data Test", data_packet_.Data());
}

TEST_F(RudpDataPacketTest, FUNC_IsValid) {
  char d1[15];
  EXPECT_FALSE(data_packet_.IsValid(boost::asio::buffer(d1)));
  char d2[16];
  d2[0] = 0x00;
  EXPECT_TRUE(data_packet_.IsValid(boost::asio::buffer(d2)));
  d2[0] = static_cast<unsigned char>(0x80);
  EXPECT_FALSE(data_packet_.IsValid(boost::asio::buffer(d2)));
}

TEST_F(RudpDataPacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    std::string data("Encode Decode Test");
    data_packet_.SetData(data);
    char dbuffer[32];
    EXPECT_EQ(0U, data_packet_.Encode(boost::asio::buffer(dbuffer)));
  }
  RestoreDefault();
  {
    // Send a packet as the First packet in message
    data_packet_.SetFirstPacketInMessage(true);
    TestEncodeDecode();
    EXPECT_TRUE(data_packet_.FirstPacketInMessage());
    EXPECT_FALSE(data_packet_.InOrder());
    EXPECT_FALSE(data_packet_.LastPacketInMessage());
  }
  RestoreDefault();
  {
    // Send a packet as the InOrder packet in message
    data_packet_.SetInOrder(true);
    TestEncodeDecode();
    EXPECT_TRUE(data_packet_.InOrder());
    EXPECT_FALSE(data_packet_.FirstPacketInMessage());
    EXPECT_FALSE(data_packet_.LastPacketInMessage());
  }
  RestoreDefault();
  {
    // Send a packet as the Last packet in message
    data_packet_.SetLastPacketInMessage(true);
    TestEncodeDecode();
    EXPECT_TRUE(data_packet_.LastPacketInMessage());
    EXPECT_FALSE(data_packet_.FirstPacketInMessage());
    EXPECT_FALSE(data_packet_.InOrder());
  }
}

class RudpControlPacketTest : public testing::Test {
 public:
  RudpControlPacketTest() : control_packet_() {}

 protected:
  void TestAdditionalInfo() {
    EXPECT_EQ(0U, control_packet_.AdditionalInfo());
    control_packet_.SetAdditionalInfo(0xffffffff);
    EXPECT_EQ(0xffffffff, control_packet_.AdditionalInfo());
  }

  void SetType(boost::uint16_t n) {
    control_packet_.SetType(n);
  }

  bool IsValidBase(const boost::asio::const_buffer &buffer,
                   boost::uint16_t expected_packet_type) {
    return control_packet_.IsValidBase(buffer, expected_packet_type);
  }

  void TestEncodeDecode() {
    {
      // Pass in a buffer having the length less than required
      char d[15];
      EXPECT_EQ(0U, control_packet_.EncodeBase(boost::asio::buffer(d)));
    }
    {
      control_packet_.SetType(0x7fff);
      control_packet_.SetAdditionalInfo(0xffffffff);
      control_packet_.SetTimeStamp(0xffffffff);
      control_packet_.SetDestinationSocketId(0xffffffff);

      char char_array[RudpControlPacket::kHeaderSize];
      boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
      EXPECT_EQ(RudpControlPacket::kHeaderSize,
                control_packet_.EncodeBase(dbuffer));

      control_packet_.SetType(0);
      control_packet_.SetAdditionalInfo(0);
      control_packet_.SetTimeStamp(0);
      control_packet_.SetDestinationSocketId(0);
      EXPECT_TRUE(control_packet_.DecodeBase(dbuffer, 0x7fff));

      EXPECT_EQ(0x7fff, control_packet_.Type());
      EXPECT_EQ(0xffffffff, control_packet_.AdditionalInfo());
      EXPECT_EQ(0xffffffff, control_packet_.TimeStamp());
      EXPECT_EQ(0xffffffff, control_packet_.DestinationSocketId());
    }
  }

  RudpControlPacket control_packet_;
};

TEST_F(RudpControlPacketTest, FUNC_Type) {
  EXPECT_EQ(0U, control_packet_.Type());
//   control_packet_.SetType(0x8000);
//   EXPECT_EQ(0U, control_packet_.Type());
  SetType(0x7fff);
  EXPECT_EQ(0x7fff, control_packet_.Type());
}

TEST_F(RudpControlPacketTest, FUNC_AdditionalInfo) {
  TestAdditionalInfo();
}

TEST_F(RudpControlPacketTest, FUNC_TimeStamp) {
  EXPECT_EQ(0U, control_packet_.TimeStamp());
  control_packet_.SetTimeStamp(0xffffffff);
  EXPECT_EQ(0xffffffff, control_packet_.TimeStamp());
}

TEST_F(RudpControlPacketTest, FUNC_DestinationSocketId) {
  EXPECT_EQ(0U, control_packet_.DestinationSocketId());
  control_packet_.SetDestinationSocketId(0xffffffff);
  EXPECT_EQ(0xffffffff, control_packet_.DestinationSocketId());
}

TEST_F(RudpControlPacketTest, FUNC_IsValidBase) {
  {
    // Buffer length too short
    char d[15];
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(d), 0x7444));
  }
  char d[16];
  {
    // Packet type is not a control_packet
    d[0] = 0x00;
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(d), 0x7444));
  }
  {
    // Input control packet is not in an expected packet type
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(d), 0x7444));
  }
  {
    // Everything is fine
    d[0] = static_cast<unsigned char>(0xf4);
    d[1] = 0x44;
    EXPECT_TRUE(IsValidBase(boost::asio::buffer(d), 0x7444));
  }
}

TEST_F(RudpControlPacketTest, BEH_EncodeDecode) {
  TestEncodeDecode();
}

class RudpAckPacketTest : public testing::Test {
 public:
  RudpAckPacketTest() : ack_packet_() {}

 protected:
  void RestoreDefault() {
    ack_packet_.SetAckSequenceNumber(0);
    ack_packet_.SetPacketSequenceNumber(0);
    ack_packet_.SetRoundTripTime(0);
    ack_packet_.SetRoundTripTimeVariance(0);
    ack_packet_.SetAvailableBufferSize(0);
    ack_packet_.SetPacketsReceivingRate(0);
    ack_packet_.SetEstimatedLinkCapacity(0);
  }

  void TestEncodeDecode() {
    ack_packet_.SetAckSequenceNumber(0xffffffff);
    ack_packet_.SetPacketSequenceNumber(0xffffffff);

    char char_array_optional[RudpAckPacket::kOptionalPacketSize];
    char char_array[RudpAckPacket::kPacketSize];
    boost::asio::mutable_buffer dbuffer;
    if (ack_packet_.HasOptionalFields()) {
      dbuffer = boost::asio::buffer(char_array_optional);
      EXPECT_EQ(RudpAckPacket::kOptionalPacketSize,
                ack_packet_.Encode(dbuffer));
    } else {
      dbuffer = boost::asio::buffer(char_array);
      EXPECT_EQ(RudpAckPacket::kPacketSize, ack_packet_.Encode(dbuffer));
    }
    RestoreDefault();
    EXPECT_TRUE(ack_packet_.Decode(dbuffer));

    EXPECT_EQ(0xffffffff, ack_packet_.AckSequenceNumber());
    EXPECT_EQ(0xffffffff, ack_packet_.PacketSequenceNumber());
  }

  RudpAckPacket ack_packet_;
};

TEST_F(RudpAckPacketTest, FUNC_IsValid) {
  {
    // Buffer length wrong
    char d[RudpControlPacket::kHeaderSize + 10];
    EXPECT_FALSE(ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  char d[RudpControlPacket::kHeaderSize + 4];
  {
    // Packet type wrong
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  {
    // Everything is fine
    d[0] = static_cast<unsigned char>(0x80);
    d[1] = RudpAckPacket::kPacketType;
    EXPECT_TRUE(ack_packet_.IsValid(boost::asio::buffer(d)));
  }
}

TEST_F(RudpAckPacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    char dbuffer[RudpAckPacket::kPacketSize - 1];
    EXPECT_EQ(0U, ack_packet_.Encode(boost::asio::buffer(dbuffer)));
  }
  {
    // TODO(Team) There will be an error if passed in buffer has a size less
    //            than kOptionalPacketSize, but the has_optional_fields_ has
    //            been set
  }
  RestoreDefault();
  {
    // Send an ack_packet without optional fields
    ack_packet_.SetHasOptionalFields(false);
    TestEncodeDecode();
    EXPECT_EQ(0U, ack_packet_.RoundTripTime());
    EXPECT_EQ(0U, ack_packet_.RoundTripTimeVariance());
    EXPECT_EQ(0U, ack_packet_.AvailableBufferSize());
    EXPECT_EQ(0U, ack_packet_.PacketsReceivingRate());
    EXPECT_EQ(0U, ack_packet_.EstimatedLinkCapacity());
  }
  RestoreDefault();
  {
    // Send an ack_packet without optional fields
    ack_packet_.SetHasOptionalFields(true);
    ack_packet_.SetRoundTripTime(0x11111111);
    ack_packet_.SetRoundTripTimeVariance(0x22222222);
    ack_packet_.SetAvailableBufferSize(0x44444444);
    ack_packet_.SetPacketsReceivingRate(0x88888888);
    ack_packet_.SetEstimatedLinkCapacity(0xffffffff);
    TestEncodeDecode();
    EXPECT_EQ(0x11111111, ack_packet_.RoundTripTime());
    EXPECT_EQ(0x22222222, ack_packet_.RoundTripTimeVariance());
    EXPECT_EQ(0x44444444, ack_packet_.AvailableBufferSize());
    EXPECT_EQ(0x88888888, ack_packet_.PacketsReceivingRate());
    EXPECT_EQ(0xffffffff, ack_packet_.EstimatedLinkCapacity());
  }
}

class RudpHandshakePacketTest : public testing::Test {
 public:
  RudpHandshakePacketTest() : handshake_packet_() {}

 protected:
  RudpHandshakePacket handshake_packet_;
};

TEST_F(RudpHandshakePacketTest, FUNC_IsValid) {
  {
    // Buffer length wrong
    char d[RudpHandshakePacket::kPacketSize + 10];
    EXPECT_FALSE(handshake_packet_.IsValid(boost::asio::buffer(d)));
  }
  char d[RudpHandshakePacket::kPacketSize];
  {
    // Packet type wrong
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(handshake_packet_.IsValid(boost::asio::buffer(d)));
  }
  {
    // Everything is fine
    d[0] = static_cast<unsigned char>(0x80);
    d[1] = RudpHandshakePacket::kPacketType;
    EXPECT_TRUE(handshake_packet_.IsValid(boost::asio::buffer(d)));
  }
}

TEST_F(RudpHandshakePacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    char dbuffer[RudpHandshakePacket::kPacketSize - 1];
    EXPECT_EQ(0U, handshake_packet_.Encode(boost::asio::buffer(dbuffer)));
  }
  {
    // Encode and Decode a Handshake Packet
    handshake_packet_.SetRudpVersion(0x11111111);
    handshake_packet_.SetSocketType(0x22222222);
    handshake_packet_.SetInitialPacketSequenceNumber(0x44444444);
    handshake_packet_.SetMaximumPacketSize(0x88888888);
    handshake_packet_.SetMaximumFlowWindowSize(0xffffffff);
    handshake_packet_.SetConnectionType(0xdddddddd);
    handshake_packet_.SetSocketId(0xbbbbbbbb);
    handshake_packet_.SetSynCookie(0xaaaaaaaa);
    handshake_packet_.SetIpAddress(
        boost::asio::ip::address::from_string(
            "2001:db8:85a3:8d3:1319:8a2e:370:7348"));

    char char_array[RudpHandshakePacket::kPacketSize];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
    handshake_packet_.Encode(boost::asio::buffer(dbuffer));

    handshake_packet_.SetRudpVersion(0);
    handshake_packet_.SetSocketType(0);
    handshake_packet_.SetInitialPacketSequenceNumber(0);
    handshake_packet_.SetMaximumPacketSize(0);
    handshake_packet_.SetMaximumFlowWindowSize(0);
    handshake_packet_.SetConnectionType(0);
    handshake_packet_.SetSocketId(0);
    handshake_packet_.SetSynCookie(0);
    handshake_packet_.SetIpAddress(
        boost::asio::ip::address::from_string("123.234.231.134"));

    handshake_packet_.Decode(dbuffer);

    EXPECT_EQ(0x11111111, handshake_packet_.RudpVersion());
    EXPECT_EQ(0x22222222, handshake_packet_.SocketType());
    EXPECT_EQ(0x44444444, handshake_packet_.InitialPacketSequenceNumber());
    EXPECT_EQ(0x88888888, handshake_packet_.MaximumPacketSize());
    EXPECT_EQ(0xffffffff, handshake_packet_.MaximumFlowWindowSize());
    EXPECT_EQ(0xdddddddd, handshake_packet_.ConnectionType());
    EXPECT_EQ(0xbbbbbbbb, handshake_packet_.SocketId());
    EXPECT_EQ(0xaaaaaaaa, handshake_packet_.SynCookie());
    EXPECT_EQ(boost::asio::ip::address::from_string(
                  "2001:db8:85a3:8d3:1319:8a2e:370:7348"),
              handshake_packet_.IpAddress());
  }
}

TEST(RudpKeepalivePacketTest, FUNC_ALL) {
  // Generally, KeepalivePacket use Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branch
  RudpKeepalivePacket keepalive_packet;
  {
    // Decode with a wrong length Buffer
    char d[RudpKeepalivePacket::kPacketSize + 10];
    EXPECT_FALSE(keepalive_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Decode with a type wrong Packet
    char d[RudpKeepalivePacket::kPacketSize];
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(keepalive_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Encode then Decode
    char char_array[RudpKeepalivePacket::kPacketSize];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
    EXPECT_EQ(RudpKeepalivePacket::kPacketSize,
              keepalive_packet.Encode(dbuffer));
    EXPECT_TRUE(keepalive_packet.Decode(dbuffer));
  }
}

TEST(RudpShutdownPacketTest, FUNC_ALL) {
  // Generally, RudpShutdownPacket use Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branch
  RudpShutdownPacket shutdown_packet;
  {
    // Decode with a wrong length Buffer
    char d[RudpShutdownPacket::kPacketSize + 10];
    EXPECT_FALSE(shutdown_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Decode with a type wrong Packet
    char d[RudpShutdownPacket::kPacketSize];
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(shutdown_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Encode then Decode
    char char_array[RudpShutdownPacket::kPacketSize];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
    EXPECT_EQ(RudpShutdownPacket::kPacketSize,
              shutdown_packet.Encode(dbuffer));
    EXPECT_TRUE(shutdown_packet.Decode(dbuffer));
  }
}

TEST(RudpAckOfAckPacketTest, FUNC_ALL) {
  // Generally, RudpAckOfAckPacket use Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branch
  RudpAckOfAckPacket ackofack_packet;
  {
    // Decode with a wrong length Buffer
    char d[RudpAckOfAckPacket::kPacketSize + 10];
    EXPECT_FALSE(ackofack_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Decode with a type wrong Packet
    char d[RudpAckOfAckPacket::kPacketSize];
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(ackofack_packet.Decode(boost::asio::buffer(d)));
  }
  {
    // Encode then Decode
    ackofack_packet.SetAckSequenceNumber(0xffffffff);
    char char_array[RudpAckOfAckPacket::kPacketSize];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
    EXPECT_EQ(RudpAckOfAckPacket::kPacketSize,
              ackofack_packet.Encode(dbuffer));
    ackofack_packet.SetAckSequenceNumber(0);
    EXPECT_TRUE(ackofack_packet.Decode(dbuffer));
    EXPECT_EQ(0xffffffff, ackofack_packet.AckSequenceNumber());
  }
}

class RudpNegativeAckPacketTest : public testing::Test {
 public:
  RudpNegativeAckPacketTest() : negative_ack_packet_() {}

 protected:
  RudpNegativeAckPacket negative_ack_packet_;
};

TEST_F(RudpNegativeAckPacketTest, FUNC_IsValid) {
  {
    // Buffer length less
    char d[RudpControlPacket::kHeaderSize];
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  {
    // Buffer length wrong
    char d[RudpControlPacket::kHeaderSize + 13];
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  char d[RudpControlPacket::kHeaderSize + 12];
  {
    // Packet type wrong
    d[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  {
    // Everything is fine
    d[0] = static_cast<unsigned char>(0x80);
    d[1] = RudpNegativeAckPacket::kPacketType;
    EXPECT_TRUE(negative_ack_packet_.IsValid(boost::asio::buffer(d)));
  }
}

TEST_F(RudpNegativeAckPacketTest, FUNC_ContainsSequenceNumber) {
  EXPECT_FALSE(negative_ack_packet_.HasSequenceNumbers());
  {
    // Search in Empty
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0));
  }
  {
    // Search a single
    negative_ack_packet_.AddSequenceNumber(0x8);
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x8));
  }
  {
    // Search in an one-value-range
    negative_ack_packet_.AddSequenceNumbers(0x9, 0x9);
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x10));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x9));
  }
  {
    // Search in a range
    negative_ack_packet_.AddSequenceNumbers(0x11, 0x17);
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x10));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x11));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x17));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x16));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x12));
  }
  {
    // Search in a wrapped around range
    negative_ack_packet_.AddSequenceNumbers(0x7fffffff, 0x0);
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x10));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x11));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x17));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x16));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x12));
  }
  {
    // Search in an overlapped range
    negative_ack_packet_.AddSequenceNumbers(0x7ffffff0, 0xf);
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x8));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x9));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x10));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x11));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x17));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x16));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x12));
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffef));
  }
  EXPECT_TRUE(negative_ack_packet_.HasSequenceNumbers());
}

TEST_F(RudpNegativeAckPacketTest, BEH_EncodeDecode) {
  negative_ack_packet_.AddSequenceNumber(0x8);
  {
    // Pass in a buffer having less space to encode
    char d[RudpControlPacket::kHeaderSize + 1 * 4 - 1];
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(d)));
  }
  {
    // Encode and Decode a NegativeAck Packet
    negative_ack_packet_.AddSequenceNumbers(0x7fffffff, 0x5);

    char char_array[RudpControlPacket::kHeaderSize + 3 * 4];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
    negative_ack_packet_.Encode(boost::asio::buffer(dbuffer));

    negative_ack_packet_.AddSequenceNumber(0x7);

    negative_ack_packet_.Decode(dbuffer);

    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x8));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x0));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x5));
//     EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x80000000));
  }
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
