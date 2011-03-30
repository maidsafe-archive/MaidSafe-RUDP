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

#include "gtest/gtest.h"
#include "maidsafe/common/log.h"
#include "maidsafe-dht/transport/rudp_data_packet.h"
#include "maidsafe-dht/transport/rudp_sender.h"

namespace maidsafe {

namespace transport {

namespace test {

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
    for (int i = 0; i < RudpPacket::kMaxSize; ++i)
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

//    char char_array[RudpDataPacket::kHeaderSize + RudpSender::kMaxDataSize];
    char char_array[RudpDataPacket::kHeaderSize + RudpPacket::kMaxSize];
    boost::asio::mutable_buffer dbuffer(boost::asio::buffer(char_array));
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
  d2[0] = 0x80;
  EXPECT_FALSE(data_packet_.IsValid(boost::asio::buffer(d2)));
}

TEST_F(RudpDataPacketTest, BEH_EncodeDecode) {
  std::string data("Encode Decode Test");
  {
    // Pass in a buffer having the length less than required
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

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
