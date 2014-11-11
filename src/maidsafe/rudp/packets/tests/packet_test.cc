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

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/packets/control_packet.h"
#include "maidsafe/rudp/packets/ack_packet.h"
#include "maidsafe/rudp/packets/handshake_packet.h"
#include "maidsafe/rudp/packets/keepalive_packet.h"
#include "maidsafe/rudp/packets/shutdown_packet.h"
#include "maidsafe/rudp/packets/ack_of_ack_packet.h"
#include "maidsafe/rudp/packets/negative_ack_packet.h"
#include "maidsafe/rudp/parameters.h"

namespace maidsafe {

namespace rudp {

namespace detail {

namespace test {

TEST(PacketTest, BEH_DecodeDestinationSocketId) {
  {
    // Try to decode with an invalid buffer
    uint32_t id;
    char char_array[15] = {0};
    EXPECT_FALSE(Packet::DecodeDestinationSocketId(&id, boost::asio::buffer(char_array)));
  }
  {
    // Decode with a valid buffer
    char char_array[16] = {0};
    char_array[12] = 0x44;
    char_array[13] = 0x22;
    char_array[14] = 0x11;
    char_array[15] = 0x00;
    uint32_t id;
    EXPECT_TRUE(Packet::DecodeDestinationSocketId(&id, boost::asio::buffer(char_array)));
    EXPECT_EQ(0x44221100, id);
  }
}

class DataPacketTest : public testing::Test {
 public:
  DataPacketTest() : data_packet_() {}

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
    for (uint32_t i = 0; i < Parameters::max_size; ++i)
      data += "a";
    uint32_t packet_sequence_number = 0x7fffffff;
    uint32_t message_number = 0x1fffffff;
    uint32_t time_stamp = 0xffffffff;
    uint32_t destination_socket_id = 0xffffffff;

    data_packet_.SetData(data);
    data_packet_.SetPacketSequenceNumber(packet_sequence_number);
    data_packet_.SetMessageNumber(message_number);
    data_packet_.SetTimeStamp(time_stamp);
    data_packet_.SetDestinationSocketId(destination_socket_id);

    char char_array[Parameters::kUDPPayload] = {0};
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::mutable_buffer(boost::asio::buffer(&char_array[0],
                                        DataPacket::kHeaderSize + Parameters::max_size)));
    EXPECT_EQ(DataPacket::kHeaderSize + data.size(), data_packet_.Encode(dbuffers));
    if (dbuffers.size() > 1) {
      memcpy(boost::asio::buffer_cast<char *>(dbuffers[0]) +
             boost::asio::buffer_size(dbuffers[0]),
             boost::asio::buffer_cast<char *>(dbuffers[1]),
             boost::asio::buffer_size(dbuffers[1]));
      dbuffers.clear();
      dbuffers.push_back(boost::asio::buffer(char_array,
                                             DataPacket::kHeaderSize + data.size()));
    }
    RestoreDefault();
    EXPECT_TRUE(data_packet_.Decode(dbuffers[0]));

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
  DataPacket data_packet_;
};

TEST_F(DataPacketTest, BEH_SequenceNumber) {
  EXPECT_EQ(0U, data_packet_.PacketSequenceNumber());
  data_packet_.SetPacketSequenceNumber(0x7fffffff);
  EXPECT_EQ(0x7fffffff, data_packet_.PacketSequenceNumber());
}

TEST_F(DataPacketTest, BEH_FirstPacketInMessage) {
  EXPECT_FALSE(data_packet_.FirstPacketInMessage());
  data_packet_.SetFirstPacketInMessage(true);
  EXPECT_TRUE(data_packet_.FirstPacketInMessage());
}

TEST_F(DataPacketTest, BEH_LastPacketInMessage) {
  EXPECT_FALSE(data_packet_.LastPacketInMessage());
  data_packet_.SetLastPacketInMessage(true);
  EXPECT_TRUE(data_packet_.LastPacketInMessage());
}

TEST_F(DataPacketTest, BEH_InOrder) {
  EXPECT_FALSE(data_packet_.InOrder());
  data_packet_.SetInOrder(true);
  EXPECT_TRUE(data_packet_.InOrder());
}

TEST_F(DataPacketTest, BEH_MessageNumber) {
  EXPECT_EQ(0U, data_packet_.MessageNumber());
  data_packet_.SetMessageNumber(0x1fffffff);
  EXPECT_EQ(0x1fffffff, data_packet_.MessageNumber());
}

TEST_F(DataPacketTest, BEH_TimeStamp) {
  EXPECT_EQ(0U, data_packet_.TimeStamp());
  data_packet_.SetTimeStamp(0xffffffff);
  EXPECT_EQ(0xffffffff, data_packet_.TimeStamp());
}

TEST_F(DataPacketTest, BEH_DestinationSocketId) {
  EXPECT_EQ(0U, data_packet_.DestinationSocketId());
  data_packet_.SetDestinationSocketId(0xffffffff);
  EXPECT_EQ(0xffffffff, data_packet_.DestinationSocketId());
}

TEST_F(DataPacketTest, BEH_Data) {
  EXPECT_EQ("", data_packet_.Data());
  data_packet_.SetData("Data Test");
  EXPECT_EQ("Data Test", data_packet_.Data());
}

TEST_F(DataPacketTest, BEH_IsValid) {
  {
    // Buffer length wrong
    char char_array[DataPacket::kHeaderSize - 1] = {0};
    char_array[0] = 0x00;
    EXPECT_FALSE(data_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  char char_array[DataPacket::kHeaderSize] = {0};
  {
    // Packet type wrong
    char_array[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(data_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  {
    // Everything is fine
    char_array[0] = 0x00;
    EXPECT_TRUE(data_packet_.IsValid(boost::asio::buffer(char_array)));
  }
}

TEST_F(DataPacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    std::string data("Encode Decode Test");
    data_packet_.SetData(data);
    char char_array[32] = {0};
    std::vector<boost::asio::mutable_buffer> buffers;
    buffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(0U, data_packet_.Encode(buffers));
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

class ControlPacketTest : public testing::Test {
 public:
  ControlPacketTest() : control_packet_() {}

 protected:
  void TestAdditionalInfo() {
    EXPECT_EQ(0U, control_packet_.AdditionalInfo());
    control_packet_.SetAdditionalInfo(0xffffffff);
    EXPECT_EQ(0xffffffff, control_packet_.AdditionalInfo());
  }

  void SetType(uint16_t n) { control_packet_.SetType(n); }

  bool IsValidBase(const boost::asio::const_buffer& buffer, uint16_t expected_packet_type) {
    return control_packet_.IsValidBase(buffer, expected_packet_type);
  }

  void TestEncodeDecode() {
    {
      // Pass in a buffer having the length less than required
      char char_array[15] = {0};
      std::vector<boost::asio::mutable_buffer> buffers;
      buffers.push_back(boost::asio::buffer(char_array));
      EXPECT_EQ(0U, control_packet_.EncodeBase(buffers));
    }
    {
      control_packet_.SetType(0x7fff);
      control_packet_.SetAdditionalInfo(0xffffffff);
      control_packet_.SetTimeStamp(0xffffffff);
      control_packet_.SetDestinationSocketId(0xffffffff);

      char char_array[ControlPacket::kHeaderSize] = {0};
      std::vector<boost::asio::mutable_buffer> dbuffers;
      dbuffers.push_back(boost::asio::buffer(char_array));
      EXPECT_EQ(ControlPacket::kHeaderSize, control_packet_.EncodeBase(dbuffers));

      control_packet_.SetType(0);
      control_packet_.SetAdditionalInfo(0);
      control_packet_.SetTimeStamp(0);
      control_packet_.SetDestinationSocketId(0);
      EXPECT_TRUE(control_packet_.DecodeBase(dbuffers[0], 0x7fff));

      EXPECT_EQ(0x7fff, control_packet_.Type());
      EXPECT_EQ(0xffffffff, control_packet_.AdditionalInfo());
      EXPECT_EQ(0xffffffff, control_packet_.TimeStamp());
      EXPECT_EQ(0xffffffff, control_packet_.DestinationSocketId());
    }
  }

  ControlPacket control_packet_;
};

TEST_F(ControlPacketTest, BEH_Type) {
  EXPECT_EQ(0U, control_packet_.Type());
  SetType(0x7fff);
  EXPECT_EQ(0x7fff, control_packet_.Type());
}

TEST_F(ControlPacketTest, BEH_AdditionalInfo) { TestAdditionalInfo(); }

TEST_F(ControlPacketTest, BEH_TimeStamp) {
  EXPECT_EQ(0U, control_packet_.TimeStamp());
  control_packet_.SetTimeStamp(0xffffffff);
  EXPECT_EQ(0xffffffff, control_packet_.TimeStamp());
}

TEST_F(ControlPacketTest, BEH_DestinationSocketId) {
  EXPECT_EQ(0U, control_packet_.DestinationSocketId());
  control_packet_.SetDestinationSocketId(0xffffffff);
  EXPECT_EQ(0xffffffff, control_packet_.DestinationSocketId());
}

TEST_F(ControlPacketTest, BEH_IsValidBase) {
  {
    // Buffer length wrong
    char char_array[ControlPacket::kHeaderSize - 1] = {0};
    char_array[0] = static_cast<unsigned char>(0xf4);
    char_array[1] = 0x44;
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(char_array), 0x7444));
  }
  char char_array[HandshakePacket::kMinPacketSize] = {0};
  {
    // Packet type wrong
    char_array[0] = 0x00;
    char_array[1] = 0x44;
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(char_array), 0x7444));
  }
  {
    // Input control packet is not in an expected packet type
    char_array[0] = static_cast<unsigned char>(0x80);
    EXPECT_FALSE(IsValidBase(boost::asio::buffer(char_array), 0x7444));
  }
  {
    // Everything is fine
    char_array[0] = static_cast<unsigned char>(0xf4);
    EXPECT_TRUE(IsValidBase(boost::asio::buffer(char_array), 0x7444));
  }
}

TEST_F(ControlPacketTest, BEH_EncodeDecode) { TestEncodeDecode(); }

class AckPacketTest : public testing::Test {
 public:
  AckPacketTest() : ack_packet_() {}

 protected:
  void RestoreDefault() {
    ack_packet_.SetAckSequenceNumber(0);
    ack_packet_.ClearSequenceNumbers();
    ack_packet_.SetRoundTripTime(0);
    ack_packet_.SetRoundTripTimeVariance(0);
    ack_packet_.SetAvailableBufferSize(0);
    ack_packet_.SetPacketsReceivingRate(0);
    ack_packet_.SetEstimatedLinkCapacity(0);
  }

  void TestEncodeDecode() {
    ack_packet_.SetAckSequenceNumber(0xbabeface);
    ack_packet_.AddSequenceNumber(0xface);
    ack_packet_.AddSequenceNumbers(0xaceface, 0xace);

    // About the magic numbers: 3 entries because of sequence wrap, 2 for start/end, 4-bytes each
    const uint32_t optional_packet_size = AckPacket::kPacketSize +
                                          AckPacket::kOptionalPacketSize +
                                          3*2*4;

    const uint32_t packet_size = AckPacket::kPacketSize +
                                 3*2*4;

    char char_array_optional[optional_packet_size] = {0};
    char char_array[packet_size] = {0};
    std::vector<boost::asio::mutable_buffer> dbuffers;
    if (ack_packet_.HasOptionalFields()) {
      dbuffers.push_back(boost::asio::buffer(char_array_optional));
      EXPECT_EQ(optional_packet_size, ack_packet_.Encode(dbuffers));
    } else {
      dbuffers.push_back(boost::asio::buffer(char_array));
      EXPECT_EQ(packet_size, ack_packet_.Encode(dbuffers));
    }
    RestoreDefault();
    EXPECT_TRUE(AckPacket::IsValid(dbuffers[0]));
    EXPECT_TRUE(ack_packet_.Decode(dbuffers[0]));

    EXPECT_EQ(0xbabeface, ack_packet_.AckSequenceNumber());
    EXPECT_TRUE(ack_packet_.ContainsSequenceNumber(0xface));
    EXPECT_FALSE(ack_packet_.ContainsSequenceNumber(0xfacf));
    EXPECT_TRUE(ack_packet_.ContainsSequenceNumber(0xaceface));
    EXPECT_TRUE(ack_packet_.ContainsSequenceNumber(0xace));
    EXPECT_TRUE(ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_TRUE(ack_packet_.ContainsSequenceNumber(0x01));
    EXPECT_FALSE(ack_packet_.ContainsSequenceNumber(0xacf));
    EXPECT_FALSE(ack_packet_.ContainsSequenceNumber(0xacefacd));
  }

  AckPacket ack_packet_;
};

TEST_F(AckPacketTest, BEH_IsValid) {
  {
    // Buffer length wrong
    char char_array[AckPacket::kPacketSize + 10] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  char char_array[AckPacket::kPacketSize] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = HandshakePacket::kPacketType;
    EXPECT_FALSE(ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  {
    // Everything is fine
    char_array[1] = AckPacket::kPacketType;
    EXPECT_TRUE(ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
}

TEST_F(AckPacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    char char_array[AckPacket::kPacketSize - 1] = {0};
    std::vector<boost::asio::mutable_buffer> buffers;
    buffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(0U, ack_packet_.Encode(buffers));
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

class HandshakePacketTest : public testing::Test {
 public:
  HandshakePacketTest() : handshake_packet_() {}

 protected:
  HandshakePacket handshake_packet_;
};

TEST_F(HandshakePacketTest, BEH_IsValid) {
  {
    // Buffer length wrong
    char char_array[HandshakePacket::kMinPacketSize - 1] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = HandshakePacket::kPacketType;
    EXPECT_FALSE(handshake_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  char char_array[HandshakePacket::kMinPacketSize] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(handshake_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  {
    // Everything is fine
    char_array[1] = HandshakePacket::kPacketType;
    EXPECT_TRUE(handshake_packet_.IsValid(boost::asio::buffer(char_array)));
  }
}

TEST_F(HandshakePacketTest, BEH_EncodeDecode) {
  {
    // Pass in a buffer having the length less than required
    char char_array[HandshakePacket::kMinPacketSize - 1] = {0};
    std::vector<boost::asio::mutable_buffer> buffers;
    buffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(0U, handshake_packet_.Encode(buffers));
  }
  {
    NodeId node_id(RandomString(NodeId::kSize));
    // Encode and Decode a Handshake Packet
    handshake_packet_.SetRudpVersion(0x11111111);
    handshake_packet_.SetSocketType(0x22222222);
    handshake_packet_.SetInitialPacketSequenceNumber(0x44444444);
    handshake_packet_.SetMaximumPacketSize(0x88888888);
    handshake_packet_.SetMaximumFlowWindowSize(0xffffffff);
    handshake_packet_.SetConnectionType(0xdddddddd);
    handshake_packet_.SetConnectionReason(0x33333333);
    handshake_packet_.SetSocketId(0xbbbbbbbb);
    handshake_packet_.set_node_id(node_id);
    handshake_packet_.SetSynCookie(0xaaaaaaaa);
    handshake_packet_.SetRequestNatDetectionPort(true);
    handshake_packet_.SetNatDetectionPort(9999);
    boost::asio::ip::udp::endpoint endpoint(
        boost::asio::ip::address::from_string("2001:db8:85a3:8d3:1319:8a2e:370:7348"), 12345);
    handshake_packet_.SetPeerEndpoint(endpoint);

    char char_array1[HandshakePacket::kMinPacketSize] = {0};
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::buffer(char_array1));
    ASSERT_EQ(HandshakePacket::kMinPacketSize,
              handshake_packet_.Encode(dbuffers));

    handshake_packet_.SetRudpVersion(0);
    handshake_packet_.SetSocketType(0);
    handshake_packet_.SetInitialPacketSequenceNumber(0);
    handshake_packet_.SetMaximumPacketSize(0);
    handshake_packet_.SetMaximumFlowWindowSize(0);
    handshake_packet_.SetConnectionType(0);
    handshake_packet_.SetConnectionReason(0);
    handshake_packet_.SetSocketId(0);
    handshake_packet_.set_node_id(NodeId());
    handshake_packet_.SetSynCookie(0);
    handshake_packet_.SetRequestNatDetectionPort(false);
    handshake_packet_.SetNatDetectionPort(0);
    handshake_packet_.SetPeerEndpoint(boost::asio::ip::udp::endpoint());
    EXPECT_FALSE(handshake_packet_.PublicKey());

    handshake_packet_.Decode(dbuffers[0]);

    EXPECT_EQ(0x11111111, handshake_packet_.RudpVersion());
    EXPECT_EQ(0x22222222, handshake_packet_.SocketType());
    EXPECT_EQ(0x44444444, handshake_packet_.InitialPacketSequenceNumber());
    EXPECT_EQ(0x88888888, handshake_packet_.MaximumPacketSize());
    EXPECT_EQ(0xffffffff, handshake_packet_.MaximumFlowWindowSize());
    EXPECT_EQ(0xdddddddd, handshake_packet_.ConnectionType());
    EXPECT_EQ(0x33333333, handshake_packet_.ConnectionReason());
    EXPECT_EQ(0xbbbbbbbb, handshake_packet_.SocketId());
    EXPECT_EQ(node_id, handshake_packet_.node_id());
    EXPECT_EQ(0xaaaaaaaa, handshake_packet_.SynCookie());
    EXPECT_TRUE(handshake_packet_.RequestNatDetectionPort());
    EXPECT_EQ(9999, handshake_packet_.NatDetectionPort());
    EXPECT_EQ(endpoint, handshake_packet_.PeerEndpoint());
    EXPECT_FALSE(handshake_packet_.PublicKey());

    // Encode and decode with a valid public key
    asymm::Keys keys(asymm::GenerateKeyPair());
    std::string encoded_key(asymm::EncodeKey(keys.public_key).string());
    handshake_packet_.SetPublicKey(
        std::shared_ptr<asymm::PublicKey>(new asymm::PublicKey(keys.public_key)));
    char char_array2[10000] = {0};
    dbuffers.clear();
    dbuffers.push_back(boost::asio::buffer(char_array2));

    ASSERT_EQ(HandshakePacket::kMinPacketSize + encoded_key.size(),
              handshake_packet_.Encode(dbuffers));

    handshake_packet_.SetRudpVersion(0);
    handshake_packet_.SetSocketType(0);
    handshake_packet_.SetInitialPacketSequenceNumber(0);
    handshake_packet_.SetMaximumPacketSize(0);
    handshake_packet_.SetMaximumFlowWindowSize(0);
    handshake_packet_.SetConnectionType(0);
    handshake_packet_.SetConnectionReason(0);
    handshake_packet_.SetSocketId(0);
    handshake_packet_.set_node_id(NodeId());
    handshake_packet_.SetSynCookie(0);
    handshake_packet_.SetRequestNatDetectionPort(false);
    handshake_packet_.SetNatDetectionPort(0);
    handshake_packet_.SetPeerEndpoint(boost::asio::ip::udp::endpoint());
    handshake_packet_.SetPublicKey(std::shared_ptr<asymm::PublicKey>());

    handshake_packet_.Decode(dbuffers[0]);

    EXPECT_EQ(0x11111111, handshake_packet_.RudpVersion());
    EXPECT_EQ(0x22222222, handshake_packet_.SocketType());
    EXPECT_EQ(0x44444444, handshake_packet_.InitialPacketSequenceNumber());
    EXPECT_EQ(0x88888888, handshake_packet_.MaximumPacketSize());
    EXPECT_EQ(0xffffffff, handshake_packet_.MaximumFlowWindowSize());
    EXPECT_EQ(0xdddddddd, handshake_packet_.ConnectionType());
    EXPECT_EQ(0x33333333, handshake_packet_.ConnectionReason());
    EXPECT_EQ(0xbbbbbbbb, handshake_packet_.SocketId());
    EXPECT_EQ(node_id, handshake_packet_.node_id());
    EXPECT_EQ(0xaaaaaaaa, handshake_packet_.SynCookie());
    EXPECT_TRUE(handshake_packet_.RequestNatDetectionPort());
    EXPECT_EQ(9999, handshake_packet_.NatDetectionPort());
    EXPECT_EQ(endpoint, handshake_packet_.PeerEndpoint());
    bool public_key_not_null(handshake_packet_.PublicKey());
    ASSERT_TRUE(public_key_not_null);
    EXPECT_TRUE(asymm::MatchingKeys(keys.public_key, *handshake_packet_.PublicKey()));
  }
}

TEST(KeepalivePacketTest, BEH_All) {
  // Generally, KeepalivePacket uses Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branches
  KeepalivePacket keepalive_packet;
  {
    // Buffer length wrong
    char char_array[KeepalivePacket::kPacketSize + 10] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = KeepalivePacket::kPacketType;
    EXPECT_FALSE(keepalive_packet.Decode(boost::asio::buffer(char_array)));
  }
  char char_array[KeepalivePacket::kPacketSize] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(keepalive_packet.Decode(boost::asio::buffer(char_array)));
  }
  {
    // Encode then Decode
    char_array[1] = KeepalivePacket::kPacketType;
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(KeepalivePacket::kPacketSize, keepalive_packet.Encode(dbuffers));
    EXPECT_TRUE(keepalive_packet.Decode(dbuffers[0]));
  }
}

TEST(ShutdownPacketTest, BEH_All) {
  // Generally, ShutdownPacket uses Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branches
  ShutdownPacket shutdown_packet;
  {
    // Buffer length wrong
    char char_array[ShutdownPacket::kPacketSize + 10] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = ShutdownPacket::kPacketType;
    EXPECT_FALSE(shutdown_packet.Decode(boost::asio::buffer(char_array)));
  }
  char char_array[ShutdownPacket::kPacketSize] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(shutdown_packet.Decode(boost::asio::buffer(char_array)));
  }
  {
    // Encode then Decode
    char_array[1] = ShutdownPacket::kPacketType;
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(ShutdownPacket::kPacketSize, shutdown_packet.Encode(dbuffers));
    EXPECT_TRUE(shutdown_packet.Decode(dbuffers[0]));
  }
}

TEST(AckOfAckPacketTest, BEH_All) {
  // Generally, AckOfAckPacket uses Base(ControlPacket)'s IsValid and
  // Encode/Decode directly. So here we only test those error condition branches
  AckOfAckPacket ack_of_ack_packet;
  {
    // Buffer length wrong
    char char_array[AckOfAckPacket::kPacketSize - 1] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = AckOfAckPacket::kPacketType;
    EXPECT_FALSE(ack_of_ack_packet.Decode(boost::asio::buffer(char_array)));
  }
  char char_array[AckOfAckPacket::kPacketSize] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(ack_of_ack_packet.Decode(boost::asio::buffer(char_array)));
  }
  {
    // Encode then Decode
    ack_of_ack_packet.SetAckSequenceNumber(0xffffffff);
    char_array[1] = AckOfAckPacket::kPacketType;
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::buffer(char_array));
    EXPECT_EQ(AckOfAckPacket::kPacketSize, ack_of_ack_packet.Encode(dbuffers));
    ack_of_ack_packet.SetAckSequenceNumber(0);
    EXPECT_TRUE(ack_of_ack_packet.Decode(dbuffers[0]));
    EXPECT_EQ(0xffffffff, ack_of_ack_packet.AckSequenceNumber());
  }
}

class NegativeAckPacketTest : public testing::Test {
 public:
  NegativeAckPacketTest() : negative_ack_packet_() {}

 protected:
  NegativeAckPacket negative_ack_packet_;
};

TEST_F(NegativeAckPacketTest, BEH_IsValid) {
  {
    // Buffer length wrong
    char char_array[ControlPacket::kHeaderSize + 10] = {0};
    char_array[0] = static_cast<unsigned char>(0x80);
    char_array[1] = NegativeAckPacket::kPacketType;
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  char char_array[ControlPacket::kHeaderSize + 12] = {0};
  char_array[0] = static_cast<unsigned char>(0x80);
  {
    // Packet type wrong
    char_array[1] = AckPacket::kPacketType;
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  {
    // Everything is fine
    char_array[1] = NegativeAckPacket::kPacketType;
    EXPECT_TRUE(negative_ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
}

TEST_F(NegativeAckPacketTest, BEH_ContainsSequenceNumber) {
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

TEST_F(NegativeAckPacketTest, BEH_EncodeDecode) {
  negative_ack_packet_.AddSequenceNumber(0x8);
  {
    // Pass in a buffer having less space to encode
    char char_array[ControlPacket::kHeaderSize + 1 * 4 - 1] = {0};
    EXPECT_FALSE(negative_ack_packet_.IsValid(boost::asio::buffer(char_array)));
  }
  {
    // Encode and Decode a NegativeAck Packet
    negative_ack_packet_.AddSequenceNumbers(0x7fffffff, 0x5);

    char char_array[ControlPacket::kHeaderSize + 3 * 4] = {0};
    std::vector<boost::asio::mutable_buffer> dbuffers;
    dbuffers.push_back(boost::asio::buffer(char_array));
    negative_ack_packet_.Encode(dbuffers);

    negative_ack_packet_.AddSequenceNumber(0x7);

    negative_ack_packet_.Decode(dbuffers[0]);

    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x7));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x8));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x7fffffff));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x0));
    EXPECT_TRUE(negative_ack_packet_.ContainsSequenceNumber(0x5));
#ifdef NDEBUG
    EXPECT_FALSE(negative_ack_packet_.ContainsSequenceNumber(0x80000000));
#endif
  }
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
