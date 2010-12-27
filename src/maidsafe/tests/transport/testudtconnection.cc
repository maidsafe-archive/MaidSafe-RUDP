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
/*
#include <boost/lexical_cast.hpp>
#include <boost/scoped_array.hpp>
#include <google/protobuf/descriptor.h>
#include <gtest/gtest.h>
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/tests/transport/udttestshelpers.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/transport/udtconnection.h"


namespace transport {

namespace test {

testing::AssertionResult SingleSignalFired(
    const TransportMessage &transport_message,
    boost::shared_ptr<MessageHandler> message_handler,
    bool connection_has_valid_pointer_to_transport_object) {
  if (!transport_message.IsInitialized())
    return testing::AssertionFailure() << "message uninitialised";
  bool is_request(transport_message.type() == TransportMessage::kKeepAlive);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      transport_message.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(transport_message.data(), &field_descriptors);
  if (field_descriptors.size() != 1U)
    return testing::AssertionFailure() << "message has more than one field.";
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      if (message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "missing raw_message";
      if (!message_handler->rpc_requests().empty())
        return testing::AssertionFailure() << "unexpected rpc_request";
      if (!message_handler->rpc_responses().empty())
        return testing::AssertionFailure() << "unexpected rpc_response";
      if (!message_handler->sent_results().empty())
        return testing::AssertionFailure() << "unexpected message_sent";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (!message_handler->managed_endpoint_messages().empty())
        return testing::AssertionFailure() <<
            "unexpected managed_endpoint_message";
      if (!message_handler->managed_endpoint_ids().empty())
        return testing::AssertionFailure() << "unexpected managed_endpoint_id";
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (!message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "unexpected raw_message";
      if (is_request) {
        if (message_handler->rpc_requests().empty())
          return testing::AssertionFailure() << "missing rpc_request";
        if (!message_handler->rpc_responses().empty())
          return testing::AssertionFailure() << "unexpected rpc_response";
      } else {
        if (!message_handler->rpc_requests().empty())
          return testing::AssertionFailure() << "unexpected rpc_request";
        if (message_handler->rpc_responses().empty())
          return testing::AssertionFailure() << "missing rpc_response";
      }
      if (!message_handler->sent_results().empty())
        return testing::AssertionFailure() << "unexpected message_sent";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (!message_handler->managed_endpoint_messages().empty())
        return testing::AssertionFailure() <<
            "unexpected managed_endpoint_message";
      if (!message_handler->managed_endpoint_ids().empty())
        return testing::AssertionFailure() << "unexpected managed_endpoint_id";
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
      if (!message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "unexpected raw_message";
      if (!message_handler->rpc_requests().empty())
        return testing::AssertionFailure() << "unexpected rpc_request";
      if (!message_handler->rpc_responses().empty())
        return testing::AssertionFailure() << "unexpected rpc_response";
      if (!message_handler->sent_results().empty())
        return testing::AssertionFailure() << "unexpected message_sent";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (!message_handler->managed_endpoint_messages().empty())
        return testing::AssertionFailure() <<
            "unexpected managed_endpoint_message";
      if (!message_handler->managed_endpoint_ids().empty())
        return testing::AssertionFailure() << "unexpected managed_endpoint_id";
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    case TransportMessage::Data::kPingFieldNumber:
      if (!message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "unexpected raw_message";
      if (!message_handler->rpc_requests().empty())
        return testing::AssertionFailure() << "unexpected rpc_request";
      if (!message_handler->rpc_responses().empty())
        return testing::AssertionFailure() << "unexpected rpc_response";
      if (!message_handler->sent_results().empty())
        return testing::AssertionFailure() << "unexpected message_sent";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (!message_handler->managed_endpoint_messages().empty())
        return testing::AssertionFailure() <<
            "unexpected managed_endpoint_message";
      if (!message_handler->managed_endpoint_ids().empty())
        return testing::AssertionFailure() << "unexpected managed_endpoint_id";
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    case TransportMessage::Data::kProxyPingFieldNumber:
      if (!message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "unexpected raw_message";
      if (!message_handler->rpc_requests().empty())
        return testing::AssertionFailure() << "unexpected rpc_request";
      if (!message_handler->rpc_responses().empty())
        return testing::AssertionFailure() << "unexpected rpc_response";
      if (!message_handler->sent_results().empty())
        return testing::AssertionFailure() << "unexpected message_sent";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (!message_handler->managed_endpoint_messages().empty())
        return testing::AssertionFailure() <<
            "unexpected managed_endpoint_message";
      if (!message_handler->managed_endpoint_ids().empty())
        return testing::AssertionFailure() << "unexpected managed_endpoint_id";
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    case TransportMessage::Data::kManagedEndpointMessageFieldNumber:
      if (!message_handler->raw_messages().empty())
        return testing::AssertionFailure() << "unexpected raw_message";
      if (!message_handler->rpc_requests().empty())
        return testing::AssertionFailure() << "unexpected rpc_request";
      if (!message_handler->rpc_responses().empty())
        return testing::AssertionFailure() << "unexpected rpc_response";
      if (!message_handler->received_results().empty())
        return testing::AssertionFailure() << "unexpected message_received";
      if (is_request && connection_has_valid_pointer_to_transport_object) {
        if (message_handler->sent_results().empty())
          return testing::AssertionFailure() << "missing message_sent";
        if (message_handler->managed_endpoint_messages().empty())
          return testing::AssertionFailure() <<
              "missing managed_endpoint_message";
        if (message_handler->managed_endpoint_ids().empty())
          return testing::AssertionFailure() << "missing managed_endpoint_id";
      } else {
        if (!message_handler->sent_results().empty())
          return testing::AssertionFailure() << "unexpected message_sent";
        if (!message_handler->managed_endpoint_messages().empty())
          return testing::AssertionFailure() <<
              "unexpected managed_endpoint_message";
        if (!message_handler->managed_endpoint_ids().empty())
          return testing::AssertionFailure() <<
              "unexpected managed_endpoint_id";
      }
      if (!message_handler->lost_managed_endpoint_ids().empty())
        return testing::AssertionFailure() <<
            "unexpected lost_managed_endpoint_id";
      break;
    default:
      return testing::AssertionFailure() << "Unrecognised data type";
  }
  return testing::AssertionSuccess();
}

testing::AssertionResult WaitForRawMessage(
    const int &timeout,
    const std::string &sent_raw_message,
    const size_t &expected_count,
    MessageHandler *listening_message_handler,
    SocketId *receiving_socket_id) {
  *receiving_socket_id = UDT::INVALID_SOCK;
  if (expected_count < 1)
    return testing::AssertionFailure() << "expected_count (" << expected_count
        << ") must be >= 1";
  int count(0);
  while (count < timeout &&
         listening_message_handler->raw_messages().size() < expected_count) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  size_t received_count = listening_message_handler->raw_messages().size();
  if (received_count != expected_count)
    return testing::AssertionFailure() << "received " << received_count <<
        ", expected " << expected_count;
  boost::tuple<std::string, SocketId, float> signalled_received_message =
      listening_message_handler->raw_messages().back();
  if (sent_raw_message != signalled_received_message.get<0>())
    return testing::AssertionFailure() << "sent: " << sent_raw_message <<
    "          received: " << signalled_received_message.get<0>();
  *receiving_socket_id = signalled_received_message.get<1>();
  return testing::AssertionSuccess();
}

class UdtConnectionTest: public testing::Test {
 protected:
  UdtConnectionTest() : listening_node_(),
                        listening_message_handler_(listening_node_.signals(),
                                                   "Listening", false),
                        listening_port_(0),
                        loopback_ip_("127.0.0.1") {}
  void SetUp() {
    listening_port_ = listening_node_.StartListening("", 0, NULL);
    ASSERT_TRUE(ValidPort(listening_port_));
    boost::this_thread::sleep(boost::posix_time::milliseconds(1));
  }
  UdtTransport listening_node_;
  MessageHandler listening_message_handler_;
  Port listening_port_;
  IP loopback_ip_;
};

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnInit) {
  // Bad remote IP
  UdtConnection udt_connection1("Rubbish", 5001, loopback_ip_, 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection1.socket_id());
  // Bad remote Port
  UdtConnection udt_connection2(loopback_ip_, 5000, loopback_ip_, 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection2.socket_id());
  // Bad rendezvous IP
  UdtConnection udt_connection3(loopback_ip_, 5001, "Rubbish", 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection3.socket_id());
  // Bad rendezvous Port
  UdtConnection udt_connection4(loopback_ip_, 5001, loopback_ip_, 5000);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection4.socket_id());

  // All good - no rendezvous
  UdtConnection udt_connection5(loopback_ip_, -1, "", 0);
  EXPECT_NE(UDT::INVALID_SOCK, udt_connection5.socket_id());
  EXPECT_GT(udt_connection5.socket_id(), 0);
  // All good - no rendezvous
  UdtConnection udt_connection6(loopback_ip_, -1, "", 1);
  EXPECT_NE(UDT::INVALID_SOCK, udt_connection6.socket_id());
  EXPECT_GT(udt_connection6.socket_id(), 0);
}

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnSendRecvDataSize) {
  // Get a new socket for listening
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  ASSERT_EQ(kSuccess, udtutils::GetNewSocket("", 0, true, &listening_socket_id,
                                             &address_info));
  ASSERT_NE(UDT::ERROR, UDT::bind(listening_socket_id, address_info->ai_addr,
                                  address_info->ai_addrlen));
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(listening_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port listening_port = ntohs(name.sin_port);
  ASSERT_NE(UDT::ERROR, UDT::listen(listening_socket_id, 1));

  // Try with message before connected
  UdtConnection sending_udt_connection1(loopback_ip_, listening_port, "", 0);
  ASSERT_NE(UDT::INVALID_SOCK, sending_udt_connection1.socket_id_);
  *(sending_udt_connection1.transport_message_.mutable_data()->
      mutable_raw_message()) = "Test";
  sending_udt_connection1.transport_message_.set_type(
      TransportMessage::kClose);
  DataSize sending_data_size =
      sending_udt_connection1.transport_message_.ByteSize();
  EXPECT_EQ(kSendFailure, sending_udt_connection1.SendDataSize());

  // Connect to listening socket, then send and receive data size
  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection1.socket_id_,
                                        sending_udt_connection1.peer_));
  EXPECT_EQ(kSuccess, sending_udt_connection1.SendDataSize());
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  SocketId receiving_socket_id1 = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id1);
  UdtConnection receiving_udt_connection1(&listening_node_,
                                          receiving_socket_id1);
  DataSize received_data_size = receiving_udt_connection1.ReceiveDataSize(1000);
  EXPECT_EQ(sending_data_size, received_data_size);

  // Send too many chars - should only retrieve correct number on receiving
  // side, but remainder will stay enqueued (and will subsequently corrupt
  // incoming data content)
  boost::uint8_t extra_char_count = 1;
  boost::uint8_t big_data_buffer_size = sizeof(DataSize) + extra_char_count;
  boost::scoped_array<char> big_data_size(new char[big_data_buffer_size]);
  big_data_size[0] = 10;
  for (int i = 1; i < big_data_buffer_size; ++i)
    big_data_size[i] = 0;
  int sent_count = UDT::send(sending_udt_connection1.socket_id_,
      big_data_size.get(), big_data_buffer_size, 0);
  EXPECT_EQ(big_data_buffer_size, sent_count);
  received_data_size = receiving_udt_connection1.ReceiveDataSize(1000);
  EXPECT_EQ(10, received_data_size);
  // remove extra chars from receive buffer to allow test to continue
  boost::scoped_array<char> temp(new char[256]);
  int received_size = UDT::recv(receiving_socket_id1, temp.get(), 256, 0);
  EXPECT_EQ(extra_char_count, received_size);

  // Send too few chars - should fail and close sockets
  boost::uint8_t missing_char_count = 1;
  ASSERT_LE(missing_char_count, sizeof(DataSize));
  boost::uint8_t wee_data_buffer_size = sizeof(DataSize) - missing_char_count;
  boost::scoped_array<char> wee_data_size(new char[wee_data_buffer_size]);
  wee_data_size[0] = 10;
  for (int i = 1; i < wee_data_buffer_size; ++i)
    wee_data_size[i] = 0;
  sent_count = UDT::send(sending_udt_connection1.socket_id_,
      wee_data_size.get(), wee_data_buffer_size, 0);
  EXPECT_EQ(wee_data_buffer_size, sent_count);
  EXPECT_TRUE(listening_message_handler_.received_results().empty());
  EXPECT_TRUE(SocketAlive(receiving_socket_id1));
  received_data_size = receiving_udt_connection1.ReceiveDataSize(1000);
  EXPECT_EQ(0, received_data_size);
  EXPECT_FALSE(SocketAlive(receiving_socket_id1));
  ASSERT_EQ(1U, listening_message_handler_.received_results().size());
  boost::tuple<SocketId, TransportCondition> message_result =
     listening_message_handler_.received_results().back();
  EXPECT_EQ(message_result.get<0>(), receiving_socket_id1);
  EXPECT_EQ(message_result.get<1>(), kReceiveTimeout);

  // Get new sockets
  UdtConnection sending_udt_connection2(loopback_ip_, listening_port, "", 0);
  sending_udt_connection2.transport_message_ =
     sending_udt_connection1.transport_message_;
  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection2.socket_id_,
                                        sending_udt_connection2.peer_));
  EXPECT_EQ(kSuccess, sending_udt_connection2.SendDataSize());
  SocketId receiving_socket_id2 = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id2);
  UdtConnection receiving_udt_connection2(&listening_node_,
                                          receiving_socket_id2);
  received_data_size = receiving_udt_connection2.ReceiveDataSize(1000);
  EXPECT_EQ(sending_data_size, received_data_size);

  // Send negative data size - should fail and close sockets
  boost::uint8_t data_buffer_size = sizeof(DataSize);
  sending_data_size = -1;
  sent_count = UDT::send(sending_udt_connection2.socket_id_,
     reinterpret_cast<char*>(&sending_data_size), data_buffer_size, 0);
  EXPECT_EQ(data_buffer_size, sent_count);
  EXPECT_TRUE(SocketAlive(receiving_socket_id2));
  received_data_size = receiving_udt_connection2.ReceiveDataSize(1000);
  EXPECT_EQ(0, received_data_size);
  EXPECT_FALSE(SocketAlive(receiving_socket_id2));
  ASSERT_EQ(2U, listening_message_handler_.received_results().size());
  message_result = listening_message_handler_.received_results().back();
  EXPECT_EQ(message_result.get<0>(), receiving_socket_id2);
  EXPECT_EQ(message_result.get<1>(), kReceiveSizeFailure);

  // Get new sockets
  UdtConnection sending_udt_connection3(loopback_ip_, listening_port, "", 0);
  sending_udt_connection3.transport_message_ =
     sending_udt_connection1.transport_message_;
  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection3.socket_id_,
                                        sending_udt_connection3.peer_));
  EXPECT_EQ(kSuccess, sending_udt_connection3.SendDataSize());
  SocketId receiving_socket_id3 = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id3);
  UdtConnection receiving_udt_connection3(&listening_node_,
                                          receiving_socket_id3);
  received_data_size = receiving_udt_connection3.ReceiveDataSize(1000);
  sending_data_size = sending_udt_connection3.transport_message_.ByteSize();
  EXPECT_EQ(sending_data_size, received_data_size);

  // Try with excessively large message - should fail and close sockets
  sending_data_size = kMaxTransportMessageSize + 1;
  sent_count = UDT::send(sending_udt_connection3.socket_id_,
     reinterpret_cast<char*>(&sending_data_size), data_buffer_size, 0);
  EXPECT_EQ(data_buffer_size, sent_count);
  EXPECT_TRUE(SocketAlive(receiving_socket_id3));
  received_data_size = receiving_udt_connection3.ReceiveDataSize(1000);
  EXPECT_EQ(0, received_data_size);
  EXPECT_FALSE(SocketAlive(receiving_socket_id3));
  ASSERT_EQ(3U, listening_message_handler_.received_results().size());
  message_result = listening_message_handler_.received_results().back();
  EXPECT_EQ(message_result.get<0>(), receiving_socket_id3);
  EXPECT_EQ(message_result.get<1>(), kMessageSizeTooLarge);

  TransportMessage big_message;
  std::string *big_raw_message =
      big_message.mutable_data()->mutable_raw_message();
  try {
    big_raw_message->assign(kMaxTransportMessageSize, 'A');
  }
  catch(const std::exception &e) {
    FAIL() << e.what() << std::endl;
  }
}

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnSendRecvDataContent) {
  // Get a new socket for listening
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  ASSERT_EQ(kSuccess, udtutils::GetNewSocket("", 0, true, &listening_socket_id,
                                             &address_info));
  ASSERT_NE(UDT::ERROR, UDT::bind(listening_socket_id, address_info->ai_addr,
                                  address_info->ai_addrlen));
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(listening_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port listening_port = ntohs(name.sin_port);
  ASSERT_NE(UDT::ERROR, UDT::listen(listening_socket_id, 1));

  // Try with message before connected
  UdtConnection sending_udt_connection1(loopback_ip_, listening_port, "", 0);
  ASSERT_NE(UDT::INVALID_SOCK, sending_udt_connection1.socket_id_);
  *(sending_udt_connection1.transport_message_.mutable_data()->
      mutable_raw_message()) = "Test";
  sending_udt_connection1.transport_message_.set_type(
      TransportMessage::kClose);
  EXPECT_EQ(kSendFailure, sending_udt_connection1.SendDataContent());

  // Connect to listening socket, then try with invalid message
  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection1.socket_id_,
                                        sending_udt_connection1.peer_));
  sending_udt_connection1.transport_message_.clear_type();
  EXPECT_EQ(kInvalidData, sending_udt_connection1.SendDataContent());
  sending_udt_connection1.transport_message_.set_type(
      TransportMessage::kClose);

  // Send and receive data content
  const DataSize kProperDataSize =
      sending_udt_connection1.transport_message_.ByteSize();
  EXPECT_EQ(kSuccess, sending_udt_connection1.SendDataContent());
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  SocketId receiving_socket_id1 = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id1);
  EXPECT_EQ(kSuccess, udtutils::SetSyncMode(receiving_socket_id1, true));
  UdtConnection receiving_udt_connection1(&listening_node_,
                                          receiving_socket_id1);
  EXPECT_TRUE(receiving_udt_connection1.ReceiveDataContent(kProperDataSize,
                                                           kDynamicTimeout));
  EXPECT_TRUE(MessagesMatch(sending_udt_connection1.transport_message_,
                            receiving_udt_connection1.transport_message_));

  // Send too many chars - should only retrieve correct number on receiving
  // side.
  boost::uint8_t extra_char_count = 1;
  DataSize big_data_buffer_size = kProperDataSize + extra_char_count;
  boost::scoped_array<char> big_data_content(new char[big_data_buffer_size]);
  sending_udt_connection1.transport_message_.SerializeToArray(
     big_data_content.get(), kProperDataSize);
  big_data_content[kProperDataSize] = 'A';
  int sent_count = UDT::send(sending_udt_connection1.socket_id_,
      big_data_content.get(), big_data_buffer_size, 0);
  EXPECT_EQ(big_data_buffer_size, sent_count);
  EXPECT_TRUE(receiving_udt_connection1.ReceiveDataContent(kProperDataSize,
                                                           kDynamicTimeout));
  EXPECT_TRUE(MessagesMatch(sending_udt_connection1.transport_message_,
                            receiving_udt_connection1.transport_message_));
  // remove extra chars from receive buffer to allow test to continue
  boost::scoped_array<char> temp(new char[256]);
  int received_size = UDT::recv(receiving_socket_id1, temp.get(), 256, 0);
  EXPECT_EQ(extra_char_count, received_size);

  // Send too few chars - should timeout and close sockets
  int receive_timeout = 100;  // milliseconds
  ASSERT_EQ(kSuccess, UDT::setsockopt(receiving_udt_connection1.socket_id_,
            0, UDT_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)));
  boost::uint8_t missing_char_count = 1;
  ASSERT_LE(missing_char_count, kProperDataSize);
  DataSize wee_data_buffer_size = kProperDataSize - missing_char_count;
  boost::scoped_array<char> wee_data_content(new char[wee_data_buffer_size]);
  for (DataSize i = 0; i < wee_data_buffer_size; ++i)
    wee_data_content[i] = big_data_content[i];
  sent_count = UDT::send(sending_udt_connection1.socket_id_,
      wee_data_content.get(), wee_data_buffer_size, 0);
  EXPECT_EQ(wee_data_buffer_size, sent_count);
  EXPECT_TRUE(SocketAlive(receiving_socket_id1));
  EXPECT_FALSE(receiving_udt_connection1.ReceiveDataContent(kProperDataSize,
                                                            kDynamicTimeout));
  EXPECT_FALSE(MessagesMatch(sending_udt_connection1.transport_message_,
                             receiving_udt_connection1.transport_message_));
  EXPECT_FALSE(SocketAlive(receiving_socket_id1));
  ASSERT_EQ(1U, listening_message_handler_.received_results().size());
  boost::tuple<SocketId, TransportCondition> message_result =
     listening_message_handler_.received_results().back();
  EXPECT_EQ(message_result.get<0>(), receiving_socket_id1);
  EXPECT_EQ(message_result.get<1>(), kReceiveTimeout);

  // Get new sockets
  UdtConnection sending_udt_connection2(loopback_ip_, listening_port, "", 0);
  sending_udt_connection2.transport_message_ =
     sending_udt_connection1.transport_message_;
  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection2.socket_id_,
                                        sending_udt_connection2.peer_));
  EXPECT_EQ(kSuccess, sending_udt_connection2.SendDataContent());
  SocketId receiving_socket_id2 = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id2);
  UdtConnection receiving_udt_connection2(&listening_node_,
                                          receiving_socket_id2);
  EXPECT_TRUE(receiving_udt_connection2.ReceiveDataContent(kProperDataSize,
                                                           kDynamicTimeout));
  EXPECT_TRUE(MessagesMatch(sending_udt_connection2.transport_message_,
                            receiving_udt_connection2.transport_message_));

  // Send content which is unparseable - should fail and close sockets
  sent_count = UDT::send(sending_udt_connection2.socket_id_,
      wee_data_content.get(), wee_data_buffer_size, 0);
  EXPECT_EQ(wee_data_buffer_size, sent_count);
  EXPECT_TRUE(SocketAlive(receiving_socket_id2));
  EXPECT_FALSE(receiving_udt_connection2.ReceiveDataContent(
               wee_data_buffer_size, kDynamicTimeout));
  EXPECT_FALSE(MessagesMatch(sending_udt_connection2.transport_message_,
                             receiving_udt_connection2.transport_message_));
  EXPECT_FALSE(SocketAlive(receiving_socket_id2));
  ASSERT_EQ(2U, listening_message_handler_.received_results().size());
  message_result = listening_message_handler_.received_results().back();
  EXPECT_EQ(message_result.get<0>(), receiving_socket_id2);
  EXPECT_EQ(message_result.get<1>(), kReceiveFailure);
}

TEST_F(UdtConnectionTest, BEH_TRANS_UdtMoveDataTimeout) {
  // Get a new socket for listening
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  ASSERT_EQ(kSuccess, udtutils::GetNewSocket("", 0, true, &listening_socket_id,
                                             &address_info));
  ASSERT_NE(UDT::ERROR, UDT::bind(listening_socket_id, address_info->ai_addr,
                                  address_info->ai_addrlen));
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(listening_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port listening_port = ntohs(name.sin_port);
  ASSERT_NE(UDT::ERROR, UDT::listen(listening_socket_id, 1));

  // Get a new socket for sending
  UdtConnection sending_udt_connection(loopback_ip_, listening_port, "", 0);
  ASSERT_NE(UDT::INVALID_SOCK, sending_udt_connection.socket_id_);
  *(sending_udt_connection.transport_message_.mutable_data()->
      mutable_raw_message()) = "Test";
  sending_udt_connection.transport_message_.set_type(
      TransportMessage::kClose);
  DataSize sending_data_size =
      sending_udt_connection.transport_message_.ByteSize();

  ASSERT_EQ(kSuccess, udtutils::Connect(sending_udt_connection.socket_id_,
                                        sending_udt_connection.peer_));
  EXPECT_EQ(kSuccess, sending_udt_connection.SendDataSize());
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  SocketId receiving_socket_id = UDT::accept(listening_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen);
  EXPECT_NE(UDT::INVALID_SOCK, receiving_socket_id);
  UdtConnection receiving_udt_connection(&listening_node_, receiving_socket_id);
  DataSize received_data_size = receiving_udt_connection.ReceiveDataSize(1000);
  sending_data_size = sending_udt_connection.transport_message_.ByteSize();
  EXPECT_EQ(sending_data_size, received_data_size);

  // Send large data with tiny timeout to trigger timeout
  (sending_udt_connection.transport_message_.mutable_data()->
      mutable_raw_message())->assign(10000000, 'A');
  sending_data_size = sending_udt_connection.transport_message_.ByteSize();
  boost::scoped_array<char> serialised_message(new char[sending_data_size]);
  ASSERT_TRUE(sending_udt_connection.transport_message_.
      SerializeToArray(serialised_message.get(), sending_data_size));
  sending_udt_connection.send_timeout_ = 1;
  int result = kSuccess;
  int count(0);
  while (result == kSuccess && count < 1000) {
    ++count;
    result = sending_udt_connection.MoveData(true, sending_data_size,
                                             serialised_message.get());
  }
  EXPECT_EQ(kSendTimeout, result);

  // Send large data with large timeout to trigger stall
  sending_udt_connection.send_timeout_ = -1;
  result = kSuccess;
  count = 0;
  while (result == kSuccess && count < 1000) {
    ++count;
    result = sending_udt_connection.MoveData(true, sending_data_size,
                                             serialised_message.get());
  }
  EXPECT_EQ(kSendStalled, result);
}

TEST_F(UdtConnectionTest, FUNC_TRANS_UdtConnHandleTransportMessage) {
  // Get a new socket for listening
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  ASSERT_EQ(kSuccess, udtutils::GetNewSocket("", 0, true, &listening_socket_id,
                                             &address_info));
  ASSERT_NE(UDT::ERROR, UDT::bind(listening_socket_id, address_info->ai_addr,
                                  address_info->ai_addrlen));
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(listening_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port listening_port = ntohs(name.sin_port);
  ASSERT_NE(UDT::ERROR, UDT::listen(listening_socket_id, 1));

  // Set up new connections and message handlers
  std::vector<UdtConnection> udt_connections;
  std::vector< boost::shared_ptr<MessageHandler> > message_handlers;
  sockaddr_storage clientaddr_storage;
  int addrlen = sizeof(clientaddr_storage);
  sockaddr clientaddr;
  for (int i = 0; i < 14; ++i) {
    UdtConnection udt_connection(loopback_ip_, listening_port, "", 0);
    ASSERT_GT(udt_connection.socket_id_, 0);
    ASSERT_EQ(kSuccess, udtutils::Connect(udt_connection.socket_id_,
                                          udt_connection.peer_));
    UDT::accept(listening_socket_id, &clientaddr, &addrlen);
    ASSERT_TRUE(SocketAlive(udt_connection.socket_id_));
    udt_connections.push_back(udt_connection);
    boost::shared_ptr<MessageHandler> message_handler(new MessageHandler(
        udt_connection.signals_, boost::lexical_cast<std::string>(i), false));
    message_handlers.push_back(message_handler);
  }

  // Set > 1 optional field as data (request)
  udt_connections.at(0).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  TransportMessage::Data *message_data =
      udt_connections.at(0).transport_message_.mutable_data();
  *(message_data->mutable_raw_message()) = "Test";
  *(message_data->mutable_ping());
  float rtt = 1.0;
  EXPECT_FALSE(udt_connections.at(0).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(0).socket_id_));
  EXPECT_TRUE(message_handlers.at(0)->received_results().empty());

  // Set > 1 optional field as data (response)
  udt_connections.at(1).transport_message_ =
      udt_connections.at(0).transport_message_;
  udt_connections.at(1).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 1.1;
  EXPECT_FALSE(udt_connections.at(1).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(1).socket_id_));
  ASSERT_EQ(1U, message_handlers.at(1)->received_results().size());
  boost::tuple<SocketId, TransportCondition> message_result =
     message_handlers.at(1)->received_results().back();
  EXPECT_EQ(message_result.get<0>(), udt_connections.at(1).socket_id_);
  EXPECT_EQ(message_result.get<1>(), kReceiveParseFailure);


  // data is raw_message request
  const std::string kSentRawMessage(base::RandomString(100));
  *(udt_connections.at(2).transport_message_.mutable_data()->
      mutable_raw_message()) = kSentRawMessage;
  udt_connections.at(2).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 1.2;
  EXPECT_TRUE(udt_connections.at(2).HandleTransportMessage(rtt));
  EXPECT_TRUE(SocketAlive(udt_connections.at(2).socket_id_));
  ASSERT_TRUE(SingleSignalFired(udt_connections.at(2).transport_message_,
                                message_handlers.at(2), false));
  boost::tuple<std::string, SocketId, float> signalled_raw_message =
      message_handlers.at(2)->raw_messages().back();
  EXPECT_EQ(kSentRawMessage, signalled_raw_message.get<0>());
  EXPECT_EQ(udt_connections.at(2).socket_id_,
            signalled_raw_message.get<1>());
  EXPECT_EQ(rtt, signalled_raw_message.get<2>());

  // data is raw_message response
  udt_connections.at(3).transport_message_ =
      udt_connections.at(2).transport_message_;
  udt_connections.at(3).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 1.3;
  EXPECT_TRUE(udt_connections.at(3).HandleTransportMessage(rtt));
  EXPECT_TRUE(SocketAlive(udt_connections.at(3).socket_id_));
  ASSERT_TRUE(SingleSignalFired(udt_connections.at(3).transport_message_,
                                message_handlers.at(3), false));
  signalled_raw_message = message_handlers.at(3)->raw_messages().back();
  EXPECT_EQ(kSentRawMessage, signalled_raw_message.get<0>());
  EXPECT_EQ(udt_connections.at(3).socket_id_,
            signalled_raw_message.get<1>());
  EXPECT_EQ(rtt, signalled_raw_message.get<2>());


  // data is rpc_message request
  rpcprotocol::RpcMessage *sent_rpc_message = udt_connections.at(4).
      transport_message_.mutable_data()->mutable_rpc_message();
  const boost::uint32_t kSentRpcId(base::RandomUint32());
  const std::string kSentRpcMethod(base::RandomString(100));
  kademlia::NatDetectionPingRequest kad_request;
  kad_request.set_ping(base::RandomString(100));
  const kademlia::NatDetectionPingRequest kSentRpcDetail(kad_request);
  const std::string kSentRpcService(base::RandomString(100));
  sent_rpc_message->set_rpc_id(kSentRpcId);
  sent_rpc_message->set_method(kSentRpcMethod);
  google::protobuf::Message *mutable_message =
      sent_rpc_message->mutable_detail()->GetReflection()->
          MutableMessage(sent_rpc_message->mutable_detail(),
                         kad_request.GetDescriptor()->extension(0));
  mutable_message->CopyFrom(kSentRpcDetail);
  sent_rpc_message->set_service(kSentRpcService);
  udt_connections.at(4).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 1.4;
  EXPECT_TRUE(udt_connections.at(4).HandleTransportMessage(rtt));
  EXPECT_TRUE(SocketAlive(udt_connections.at(4).socket_id_));
  ASSERT_TRUE(SingleSignalFired(udt_connections.at(4).transport_message_,
                                message_handlers.at(4), false));
  boost::tuple<rpcprotocol::RpcMessage, SocketId, float> signalled_rpc_message =
      message_handlers.at(4)->rpc_requests().back();
  EXPECT_EQ(sent_rpc_message->SerializeAsString(),
            signalled_rpc_message.get<0>().SerializeAsString());
  EXPECT_EQ(udt_connections.at(4).socket_id_,
            signalled_rpc_message.get<1>());
  EXPECT_EQ(rtt, signalled_rpc_message.get<2>());

  // data is rpc_message response
  udt_connections.at(5).transport_message_ =
      udt_connections.at(4).transport_message_;
  udt_connections.at(5).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 1.5;
  EXPECT_TRUE(udt_connections.at(5).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(5).socket_id_));
  ASSERT_TRUE(SingleSignalFired(udt_connections.at(5).transport_message_,
                                message_handlers.at(5), false));
  signalled_rpc_message = message_handlers.at(5)->rpc_responses().back();
  EXPECT_EQ(sent_rpc_message->SerializeAsString(),
            signalled_rpc_message.get<0>().SerializeAsString());
  EXPECT_EQ(udt_connections.at(5).socket_id_,
            signalled_rpc_message.get<1>());
  EXPECT_EQ(rtt, signalled_rpc_message.get<2>());


  // data is hole_punching_message request
  HolePunchingMessage *sent_hole_punch_message = udt_connections.at(6).
      transport_message_.mutable_data()->mutable_hole_punching_message();
  sent_hole_punch_message->set_ip(base::RandomString(100));
  sent_hole_punch_message->set_port(base::RandomInt32());
  sent_hole_punch_message->set_type(HolePunchingMessage::FORWARD_REQ);
  udt_connections.at(6).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 1.6;
  EXPECT_TRUE(udt_connections.at(6).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(6).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - Uncomment lines below
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(6).transport_message_,
//                                message_handlers.at(6), false));
//  boost::tuple<HolePunchingMessage, SocketId, float>
//      signalled_hole_punch_message =
//      message_handlers.at(6)->hole_punch_requests().back();
//  EXPECT_EQ(sent_hole_punch_message->SerializeAsString(),
//            signalled_hole_punch_message.get<0>().SerializeAsString());
//  EXPECT_EQ(udt_connections.at(6).socket_id_,
//            signalled_hole_punch_message.get<1>());
//  EXPECT_EQ(rtt, signalled_hole_punch_message.get<2>());

  // data is hole_punching_message response
  udt_connections.at(7).transport_message_ =
      udt_connections.at(6).transport_message_;
  udt_connections.at(7).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 1.7;
  EXPECT_TRUE(udt_connections.at(7).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(7).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - Uncomment lines below
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(7).transport_message_,
//                                message_handlers.at(7), false));
//  boost::tuple<HolePunchingMessage, SocketId, float>
//      signalled_hole_punch_message =
//      message_handlers.at(7)->hole_punch_responses().back();
//  EXPECT_EQ(sent_hole_punch_message->SerializeAsString(),
//            signalled_hole_punch_message.get<0>().SerializeAsString());
//  EXPECT_EQ(udt_connections.at(7).socket_id_,
//            signalled_hole_punch_message.get<1>());
//  EXPECT_EQ(rtt, signalled_hole_punch_message.get<2>());


  // data is ping request
  Ping *sent_ping_message =
      udt_connections.at(8).transport_message_.mutable_data()->mutable_ping();
  Address *address = sent_ping_message->mutable_from_address();
  address->set_ip(base::RandomString(100));
  address->set_port(base::RandomInt32());
  udt_connections.at(8).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 1.8;
  EXPECT_TRUE(udt_connections.at(8).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(8).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - complete test
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(8).transport_message_,
//                                message_handlers.at(8), false));

  // data is ping response
  udt_connections.at(9).transport_message_ =
      udt_connections.at(8).transport_message_;
  udt_connections.at(9).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 1.9;
  EXPECT_TRUE(udt_connections.at(9).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(9).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - complete test
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(9).transport_message_,
//                                message_handlers.at(9), false));


  // data is proxy_ping request
  ProxyPing *sent_proxy_ping_message = udt_connections.at(10).
      transport_message_.mutable_data()->mutable_proxy_ping();
  sent_proxy_ping_message->set_result(ProxyPing::kNACK);
  address = sent_proxy_ping_message->mutable_address();
  address->set_ip(base::RandomString(100));
  address->set_port(base::RandomInt32());
  udt_connections.at(10).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 2.0;
  EXPECT_TRUE(udt_connections.at(10).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(10).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - complete test
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(10).transport_message_,
//                                message_handlers.at(10), false));

  // data is proxy_ping response
  udt_connections.at(11).transport_message_ =
      udt_connections.at(10).transport_message_;
  udt_connections.at(11).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 2.1;
  EXPECT_TRUE(udt_connections.at(11).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(11).socket_id_));
  // TODO(Fraser#5#): 2010-08-10 - complete test
//  ASSERT_TRUE(SingleSignalFired(udt_connections.at(11).transport_message_,
//                                message_handlers.at(11), false));


  // data is managed_endpoint_message request (no transport)
  ManagedEndpointMessage *sent_managed_endpoint_message =
      udt_connections.at(12).transport_message_.mutable_data()->
          mutable_managed_endpoint_message();
  address = sent_managed_endpoint_message->mutable_address();
  address->set_ip(base::RandomString(100));
  address->set_port(base::RandomInt32());
  sent_managed_endpoint_message->set_result(true);
  sent_managed_endpoint_message->set_message_id(base::RandomInt32());
  sent_managed_endpoint_message->set_identifier(base::RandomString(100));
  sent_managed_endpoint_message->set_frequency(base::RandomInt32());
  sent_managed_endpoint_message->set_retry_count(base::RandomInt32());
  sent_managed_endpoint_message->set_retry_frequency(base::RandomInt32());
  udt_connections.at(12).transport_message_.set_type(
      TransportMessage::kKeepAlive);
  rtt = 2.2;
  EXPECT_TRUE(udt_connections.at(12).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(12).socket_id_));
  EXPECT_TRUE(SingleSignalFired(udt_connections.at(12).transport_message_,
                                message_handlers.at(12), false));

  // data is managed_endpoint_message response (no transport)
  udt_connections.at(13).transport_message_ =
      udt_connections.at(12).transport_message_;
  udt_connections.at(13).transport_message_.set_type(
      TransportMessage::kClose);
  rtt = 2.3;
  EXPECT_TRUE(udt_connections.at(13).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections.at(13).socket_id_));
  EXPECT_TRUE(SingleSignalFired(udt_connections.at(13).transport_message_,
                                message_handlers.at(13), false));
  // Set up connections with valid pointers to transport objects
  std::vector< boost::shared_ptr<UdtTransport> > udt_transports;
  std::vector<UdtConnection> udt_connections2;
  std::vector< boost::shared_ptr<MessageHandler> > message_handlers2;
  for (int i = 100; i < 102; ++i) {
    boost::shared_ptr<UdtTransport> udt_transport(new UdtTransport);
    udt_transports.push_back(udt_transport);
    UdtConnection udt_connection(udt_transport.get(), loopback_ip_,
                                 listening_port_, "", 0);
    ASSERT_GT(udt_connection.socket_id_, 0);
    ASSERT_EQ(kSuccess, udtutils::Connect(udt_connection.socket_id_,
                                          udt_connection.peer_));
    ASSERT_TRUE(SocketAlive(udt_connection.socket_id_));
    udt_connections2.push_back(udt_connection);
    boost::shared_ptr<MessageHandler> message_handler(new MessageHandler(
        udt_connection.signals_, boost::lexical_cast<std::string>(i), false));
    message_handlers2.push_back(message_handler);
  }

  // data is managed_endpoint_message request (with transport)
  udt_connections2.at(0).transport_message_ =
      udt_connections.at(12).transport_message_;
  EXPECT_TRUE(udt_connections2.at(0).HandleTransportMessage(rtt));
  ASSERT_TRUE(SingleSignalFired(udt_connections2.at(0).transport_message_,
                                message_handlers2.at(0), true));
  boost::tuple<ManagedEndpointId, ManagedEndpointMessage>
      signalled_managed_endpoint_message =
          message_handlers2.at(0)->managed_endpoint_messages().back();
  EXPECT_FALSE(SocketAlive(udt_connections2.at(0).socket_id_));
  int count(0), timeout(1000);
  while (count < timeout &&
         SocketAlive(signalled_managed_endpoint_message.get<0>())) {
    ++count;
    boost::this_thread::sleep(boost::posix_time::milliseconds(1));
  }
  EXPECT_FALSE(SocketAlive(signalled_managed_endpoint_message.get<0>()));
  EXPECT_EQ(sent_managed_endpoint_message->SerializeAsString(),
            signalled_managed_endpoint_message.get<1>().SerializeAsString());

  // data is managed_endpoint_message response (with transport)
  udt_connections2.at(1).transport_message_ =
      udt_connections.at(13).transport_message_;
  EXPECT_TRUE(udt_connections2.at(1).HandleTransportMessage(rtt));
  EXPECT_FALSE(SocketAlive(udt_connections2.at(1).socket_id_));
  EXPECT_TRUE(SingleSignalFired(udt_connections2.at(1).transport_message_,
                                message_handlers2.at(1), true));
}

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnSendRecvDataFull) {
  std::vector<UdtConnection> send_connections;
  std::vector< boost::shared_ptr<MessageHandler> > send_message_handlers;
  for (int i = 0; i < 3; ++i) {
    UdtConnection udt_connection(loopback_ip_, listening_port_, "", 0);
    ASSERT_GT(udt_connection.socket_id_, 0);
    send_connections.push_back(udt_connection);
    boost::shared_ptr<MessageHandler> message_handler(new MessageHandler(
        udt_connection.signals_, boost::lexical_cast<std::string>(i), false));
    send_message_handlers.push_back(message_handler);
  }
  TransportMessage sent_message;
  std::string *sent_raw_message =
      sent_message.mutable_data()->mutable_raw_message();
  *sent_raw_message = base::RandomString(100);
  sent_message.set_type(TransportMessage::kClose);
  SocketId receiving_socket_id;

  // Send response (no response expected)
  size_t test_count(0);
  EXPECT_TRUE(send_connections.at(test_count).worker_.get() == NULL);
  // Explicitly connect as responses are usually sent on pre-connected sockets
  ASSERT_EQ(kSuccess,
            udtutils::Connect(send_connections.at(test_count).socket_id_,
                              send_connections.at(test_count).peer_));
  const int kTimeout(5000);
  const boost::uint32_t kTestRpcTimeout(kTimeout - 1000);
  send_connections.at(test_count).Send(sent_message, kTestRpcTimeout);
  EXPECT_TRUE(WaitForRawMessage(kTimeout, *sent_raw_message, test_count + 1,
              &listening_message_handler_, &receiving_socket_id));
  ASSERT_EQ(1U, send_message_handlers.at(test_count)->sent_results().size());
  boost::tuple<SocketId, TransportCondition> signalled_message_result =
      send_message_handlers.at(test_count)->sent_results().back();
  EXPECT_EQ(send_connections.at(test_count).socket_id_,
            signalled_message_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_message_result.get<1>());
  EXPECT_FALSE(send_connections.at(test_count).worker_.get() == NULL);
  EXPECT_FALSE(SocketAlive(send_connections.at(test_count).socket_id_));
  EXPECT_FALSE(SocketAlive(receiving_socket_id));

  // Send request (response expected) and don't send response
  ++test_count;  // 1
  *sent_raw_message = base::RandomString(100);
  sent_message.set_type(TransportMessage::kKeepAlive);
  EXPECT_TRUE(send_connections.at(test_count).worker_.get() == NULL);
  send_connections.at(test_count).Send(sent_message, kTestRpcTimeout);
  EXPECT_TRUE(WaitForRawMessage(kTimeout, *sent_raw_message, test_count + 1,
              &listening_message_handler_, &receiving_socket_id));
  ASSERT_EQ(1U, send_message_handlers.at(test_count)->sent_results().size());
  signalled_message_result =
      send_message_handlers.at(test_count)->sent_results().back();
  EXPECT_EQ(send_connections.at(test_count).socket_id_,
            signalled_message_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_message_result.get<1>());
  int count(0);
  while (count < kTimeout &&
         send_message_handlers.at(test_count)->received_results().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  ASSERT_EQ(1U,
            send_message_handlers.at(test_count)->received_results().size());
  signalled_message_result =
      send_message_handlers.at(test_count)->received_results().back();
  EXPECT_EQ(send_connections.at(test_count).socket_id_,
            signalled_message_result.get<0>());
  EXPECT_EQ(kReceiveTimeout, signalled_message_result.get<1>());
  EXPECT_FALSE(send_connections.at(test_count).worker_.get() == NULL);
  EXPECT_FALSE(SocketAlive(send_connections.at(test_count).socket_id_));
  EXPECT_FALSE(SocketAlive(receiving_socket_id));

  // Send request and send response
  ++test_count;  // 2
  *sent_raw_message = base::RandomString(100);
  EXPECT_TRUE(send_connections.at(test_count).worker_.get() == NULL);
  send_connections.at(test_count).Send(sent_message, kTestRpcTimeout);
  EXPECT_TRUE(WaitForRawMessage(kTimeout, *sent_raw_message, test_count + 1,
              &listening_message_handler_, &receiving_socket_id));
  ASSERT_EQ(1U, send_message_handlers.at(test_count)->sent_results().size());
  signalled_message_result =
      send_message_handlers.at(test_count)->sent_results().back();
  EXPECT_EQ(send_connections.at(test_count).socket_id_,
            signalled_message_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_message_result.get<1>());
  UdtConnection reply_connection(&listening_node_, receiving_socket_id);
  TransportMessage reply_message;
  std::string *reply_raw_message =
      reply_message.mutable_data()->mutable_raw_message();
  *reply_raw_message = base::RandomString(100);
  reply_message.set_type(TransportMessage::kClose);
  reply_connection.Send(reply_message, 0);
  count = 0;
  while (count < kTimeout &&
         send_message_handlers.at(test_count)->raw_messages().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  ASSERT_EQ(1U, send_message_handlers.at(test_count)->raw_messages().size());
  EXPECT_TRUE(send_message_handlers.at(test_count)->received_results().empty());
  boost::tuple<std::string, SocketId, float> signalled_received_reply =
      send_message_handlers.at(test_count)->raw_messages().back();
  EXPECT_EQ(*reply_raw_message, signalled_received_reply.get<0>());
  EXPECT_EQ(send_connections.at(test_count).socket_id_,
            signalled_received_reply.get<1>());
  EXPECT_FALSE(send_connections.at(test_count).worker_.get() == NULL);
  EXPECT_FALSE(SocketAlive(send_connections.at(test_count).socket_id_));
  EXPECT_FALSE(SocketAlive(receiving_socket_id));
}

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnBigMessage) {
  TransportMessage sent_message;
  std::string *sent_raw_message =
      sent_message.mutable_data()->mutable_raw_message();
  try {
    sent_raw_message->assign(base::RandomString(kMaxTransportMessageSize - 12));
  }
  catch(const std::exception &e) {
    FAIL() << e.what() << std::endl;
  }
  sent_message.set_type(TransportMessage::kClose);
  UdtConnection udt_connection(loopback_ip_, listening_port_, "", 0);
  SocketId sending_socket_id = udt_connection.socket_id();
  ASSERT_GT(sending_socket_id, 0);
  MessageHandler message_handler(udt_connection.signals(), "BigSend", false);
  // Explicitly connect as responses are usually sent on pre-connected sockets
  ASSERT_EQ(kSuccess, udtutils::Connect(udt_connection.socket_id_,
                                        udt_connection.peer_));
  const int kTimeout(10000);
  const boost::uint32_t kTestRpcTimeout(kTimeout - 1000);
  udt_connection.Send(sent_message, kTestRpcTimeout);
  SocketId receiving_socket_id;

  EXPECT_TRUE(WaitForRawMessage(kTimeout, *sent_raw_message, 1,
              &listening_message_handler_, &receiving_socket_id));
  ASSERT_EQ(1U, message_handler.sent_results().size());
  boost::tuple<SocketId, TransportCondition> signalled_message_result =
      message_handler.sent_results().back();
  EXPECT_EQ(sending_socket_id, signalled_message_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_message_result.get<1>());
  EXPECT_FALSE(SocketAlive(sending_socket_id));
  EXPECT_FALSE(SocketAlive(receiving_socket_id));
}

}  // namespace test

}  // namespace transport
*/
