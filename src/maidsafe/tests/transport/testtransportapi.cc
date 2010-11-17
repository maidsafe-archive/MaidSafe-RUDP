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

#include <boost/asio/ip/address.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <gtest/gtest.h>
#include <list>
#include <set>
#include <string>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/tests/transport/udttestshelpers.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/transportsignals.h"
#include "maidsafe/transport/udtconnection.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/transport/tcptransport.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/udt/api.h"


namespace transport {

namespace test {

  // NOTE: Put any new transport objects in here.
  typedef testing::Types<UdtTransport, TcpTransport > Implementations;
//  typedef testing::Types<TcpTransport > Implementations;

TransportMessage MakeTransportMessage(bool is_request,
                                           const size_t &message_size) {
  TransportMessage transport_message;
  if (is_request)
    transport_message.set_type(TransportMessage::kRequest);
  else
    transport_message.set_type(TransportMessage::kResponse);
  rpcprotocol::RpcMessage *rpc_message =
      transport_message.mutable_data()->mutable_rpc_message();
  rpc_message->set_rpc_id(base::RandomUint32());
  rpc_message->set_method("Method");
  rpcprotocol::RpcMessage::Detail *payload = rpc_message->mutable_detail();
  kad::NatDetectionPingRequest *request = payload->MutableExtension(
      kad::NatDetectionPingRequest::nat_detection_ping_request);
  request->set_ping(base::RandomString(message_size));
  rpc_message->set_service("Service");
  return transport_message;
}

// All transport objects constructed in same manner
// No need for factory methods 
template <class T>
Transport * CreateTransport() {
  return new T; }



template <class T>
class TransportAPITest: public testing::Test {
 protected:
  TransportAPITest() : trans1_(CreateTransport<T>()),
                       trans2_(CreateTransport<T>()),
                       listening_message_handler_(this->trans1_->signals(),
                                                 "Listening", false),
                       listening_port_(0),
                       loopback_ip_("127.0.0.1"),
                       sockets_for_closing_() {}
    virtual ~TransportAPITest() { delete trans1_; delete trans2_; }
    
  void SetUp() {
    listening_port_ = this->trans1_->StartListening("", 0, NULL);
    //ASSERT_TRUE(ValidPort(listening_port_));
    ASSERT_GT(listening_port_, 0);
  }
  void TearDown() {
    std::for_each(sockets_for_closing_.begin(), sockets_for_closing_.end(),
                  boost::bind(&UDT::close, _1));
  }
  //Transport listening_node_;
  Transport * const trans1_;
  Transport * const trans2_;
  MessageHandler listening_message_handler_;
  Port listening_port_;
  IP loopback_ip_;
  std::vector<UdtSocketId> sockets_for_closing_;
  
};



TYPED_TEST_CASE(TransportAPITest, Implementations);

TYPED_TEST(TransportAPITest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  // Set up sending node and message
  Transport * const sending_node = this->trans2_;
  MessageHandler sending_message_handler(sending_node->signals(),
           "Send", false);
  TransportMessage request = MakeTransportMessage(true, 256 * 1024);
  const std::string kSentRpcRequest =
      request.data().rpc_message().SerializeAsString();

  // Send message
  SocketId sending_socket_id =
      this->trans2_->PrepareToSend(this->loopback_ip_,
                                 this->listening_port_, "", 0);
  ASSERT_GT(sending_socket_id, 0);
  const int kTimeout(rpcprotocol::kRpcTimeout + 1000);
  sending_node->Send(request, sending_socket_id, rpcprotocol::kRpcTimeout);
  int count(0);
  while (count < kTimeout &&
         this->listening_message_handler_.rpc_requests().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results and get receiving socket's ID
  ASSERT_EQ(1U, sending_message_handler.sent_results().size());
  boost::tuple<SocketId, TransportCondition> signalled_sent_result =
      sending_message_handler.sent_results().back();
  EXPECT_EQ(sending_socket_id, signalled_sent_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_sent_result.get<1>());
  ASSERT_EQ(1U, this->listening_message_handler_.rpc_requests().size());
  boost::tuple<rpcprotocol::RpcMessage, SocketId, float> signalled_rpc_message =
      this->listening_message_handler_.rpc_requests().back();
  EXPECT_EQ(kSentRpcRequest,
            signalled_rpc_message.get<0>().SerializeAsString());
  UdtSocketId receiving_socket_id = signalled_rpc_message.get<1>();

  // Send reply
  TransportMessage response = MakeTransportMessage(false, 256 * 1024);
  const std::string kSentRpcResponse =
      response.data().rpc_message().SerializeAsString();
  this->trans1_->Send(response, receiving_socket_id, 0);
  count = 0;
  while (count < kTimeout &&
         sending_message_handler.rpc_responses().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results
  ASSERT_EQ(1U, this->listening_message_handler_.sent_results().size());
  signalled_sent_result = this->listening_message_handler_.sent_results().back();
  EXPECT_EQ(receiving_socket_id, signalled_sent_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_sent_result.get<1>());
  ASSERT_EQ(1U, sending_message_handler.rpc_responses().size());
  signalled_rpc_message = sending_message_handler.rpc_responses().back();
  EXPECT_EQ(kSentRpcResponse,
            signalled_rpc_message.get<0>().SerializeAsString());
  EXPECT_EQ(sending_socket_id, signalled_rpc_message.get<1>());
  EXPECT_FALSE(SocketAlive(sending_socket_id));
  EXPECT_FALSE(SocketAlive(receiving_socket_id));
}


TYPED_TEST(TransportAPITest, BEH_TRANS_MultipleListeningPorts) {
  // Start listening ports
  Transport * const listening_node = this->trans2_;
  const boost::uint16_t kNumberOfListeningPorts = 12;
  std::vector<Port> listening_ports;
  listening_ports.push_back(this->listening_port_);
  for (int i = 0; i < kNumberOfListeningPorts - 1 ; ++i) {
    Port listening_port = this->trans1_->StartListening("", 0, NULL);
    // We need to tell tranports what is valid not measure it
    // only TODO:(dirvine)
    // EXPECT_TRUE(ValidPort(listening_port));
    ASSERT_GT(this->listening_port_, 0);
    listening_ports.push_back(listening_port);
  }
  EXPECT_EQ(kNumberOfListeningPorts, this->trans1_->listening_ports().size());

  // Send a message to each
  TransportMessage message = MakeTransportMessage(true, 256 * 1024);
  for (int i = 0; i < kNumberOfListeningPorts ; ++i) {
    this->sockets_for_closing_.push_back(this->trans1_->PrepareToSend(this->loopback_ip_,
                                   listening_ports.at(i), "", 0));
    listening_node->Send(message, this->sockets_for_closing_.at(i), 0);
  }
  const int kTimeout(rpcprotocol::kRpcTimeout + 1000);
  int count(0);
  while (count < kTimeout &&
         this->listening_message_handler_.rpc_requests().size() !=
         kNumberOfListeningPorts) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(30));
    count += 30;
  }

  EXPECT_EQ(this->listening_message_handler_.rpc_requests().size(),
            this->listening_message_handler_.sent_results().size());
  EXPECT_TRUE(listening_node->StopAllListening());
}

 // This is where is all changes
/*
class UdtTransportVPTest: public testing::TestWithParam<size_t> {
 protected:
  UdtTransportVPTest() : listening_node_(),
                         listening_message_handler_(listening_node_.signals(),
                                                    "Listening", false),
                         listening_port_(0),
                         loopback_ip_("127.0.0.1"),
                         sockets_for_closing_() {}
  void SetUp() {
    listening_port_ = listening_node_.StartListening("", 0, NULL);
    ASSERT_TRUE(ValidPort(listening_port_));
  }
  void TearDown() {
    std::for_each(sockets_for_closing_.begin(), sockets_for_closing_.end(),
                  boost::bind(&UDT::close, _1));
  }
  UdtTransport listening_node_;
  MessageHandler listening_message_handler_;
  Port listening_port_;
  IP loopback_ip_;
  std::vector<UdtSocketId> sockets_for_closing_;
};

TEST_P(UdtTransportVPTest, FUNC_TRANS_UdtSendMessagesFromManyToOne) {
  // Set up sending connections and message
  const size_t kTestMessageSize(GetParam());
  const boost::uint16_t kRepeats(kTestMessageSize > 256 * 1024 ? 5 : 50);
  std::vector<UdtConnection> send_connections;
  std::vector< boost::shared_ptr<MessageHandler> > send_message_handlers;
  for (boost::uint16_t i = 0; i < kRepeats; ++i) {
    UdtConnection udt_connection(loopback_ip_, listening_port_, "", 0);
    ASSERT_GT(udt_connection.udt_socket_id(), 0);
    sockets_for_closing_.push_back(udt_connection.udt_socket_id());
    send_connections.push_back(udt_connection);
    boost::shared_ptr<MessageHandler> message_handler(new MessageHandler(
        udt_connection.signals(), boost::lexical_cast<std::string>(i), false));
    send_message_handlers.push_back(message_handler);
  }
  TransportMessage request(MakeDummyTransportMessage(true, kTestMessageSize));
  const std::string kSentRpcRequest =
      request.data().rpc_message().SerializeAsString();

  // Send messages
  const int kTimeout(kTestMessageSize > 256 * 1024 ?
                     rpcprotocol::kRpcTimeout * 10 : rpcprotocol::kRpcTimeout);
  for (boost::uint16_t i = 0; i < kRepeats; ++i)
    send_connections.at(i).Send(request, kTimeout);
  int count(0);
  while (count < kTimeout * 2 &&
         listening_message_handler_.rpc_requests().size() < kRepeats) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results and get receiving sockets' IDs
  boost::tuple<SocketId, TransportCondition> signalled_sent_result;
  size_t send_success_count(0);
  for (boost::uint16_t i = 0; i < kRepeats; ++i) {
    ASSERT_EQ(1U, send_message_handlers.at(i)->sent_results().size());
    signalled_sent_result = send_message_handlers.at(i)->sent_results().back();
    EXPECT_EQ(sockets_for_closing_.at(i), signalled_sent_result.get<0>());
    if (signalled_sent_result.get<1>() == kSuccess)
      ++send_success_count;
  }
  if (kTestMessageSize > 256 * 1024)
    ASSERT_LT(0, send_success_count);
  else
    ASSERT_EQ(kRepeats, send_success_count);
  ASSERT_EQ(send_success_count,
            listening_message_handler_.rpc_requests().size());
  std::vector<UdtSocketId> receiving_socket_ids;
  boost::tuple<rpcprotocol::RpcMessage, SocketId, float> signalled_rpc_message;
  MessageHandler::RpcMessageList copy_of_signalled_messages =
      listening_message_handler_.rpc_requests();
  for (boost::uint16_t i = 0; i < send_success_count; ++i) {
    signalled_rpc_message = copy_of_signalled_messages.front();
    copy_of_signalled_messages.pop_front();
    EXPECT_EQ(kSentRpcRequest,
              signalled_rpc_message.get<0>().SerializeAsString());
    receiving_socket_ids.push_back(signalled_rpc_message.get<1>());
  }

  // Send reply
  request.Clear();
  TransportMessage response(MakeDummyTransportMessage(false, kTestMessageSize));
  const std::string kSentRpcResponse =
      response.data().rpc_message().SerializeAsString();
  std::for_each(receiving_socket_ids.begin(), receiving_socket_ids.end(),
      boost::bind(&UdtTransport::Send, &listening_node_, response, _1, 0));
  count = 0;
  while (count < kTimeout * 5 &&
         listening_message_handler_.sent_results().size() < kRepeats) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }

  // Assess results
  ASSERT_EQ(send_success_count,
            listening_message_handler_.sent_results().size());
  MessageHandler::MessageResultList copy_of_signalled_results =
      listening_message_handler_.sent_results();
  size_t reply_success_count = 0;
  for (boost::uint16_t i = 0; i < send_success_count; ++i) {
    signalled_sent_result = copy_of_signalled_results.front();
    copy_of_signalled_results.pop_front();
    if (signalled_sent_result.get<1>() == kSuccess)
      ++reply_success_count;
    count = 0;
    while (count < kTimeout &&
           send_message_handlers.at(i)->rpc_responses().empty()) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      count += 10;
    }
    if (!send_message_handlers.at(i)->rpc_responses().empty()) {
      ASSERT_EQ(1U, send_message_handlers.at(i)->rpc_responses().size());
      signalled_rpc_message =
          send_message_handlers.at(i)->rpc_responses().back();
      EXPECT_EQ(kSentRpcResponse,
                signalled_rpc_message.get<0>().SerializeAsString());
    }
  }
  if (kTestMessageSize > 256 * 1024)
    ASSERT_LT(0, reply_success_count);
  else
    ASSERT_EQ(kRepeats, reply_success_count);
}

INSTANTIATE_TEST_CASE_P(VPTest, UdtTransportVPTest,
                        testing::Values(100, 1024 * 256,
                                        kMaxTransportMessageSize / 2));*/


}  // namespace test

}  // namespace transport
