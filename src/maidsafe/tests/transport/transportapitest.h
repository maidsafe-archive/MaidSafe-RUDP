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

#ifndef MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_
#define MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_

#include <gtest/gtest.h>
#include <list>
#include <set>
#include <string>

#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"

namespace transport {

namespace test {

const IP kIP("127.0.0.1");

template <class T>
class TransportAPITest: public testing::Test {
 protected:
  boost::shared_ptr<Transport> CreateTransport() {
    return boost::shared_ptr<Transport>(new T);
  };
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
};

TYPED_TEST_CASE_P(TransportAPITest);

// Function Testing Start 

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StartListening) {
  std::vector<Port> listening_port_;
  Port port[] = {0, 100, 100, 200, 300, 300, 5000, 10000, 25555, 65343}; 
  boost::uint16_t lport;
  boost::uint16_t num_lport = 0;
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  TransportCondition transport_condition;
  boost::uint16_t i = 0;
  for (; i < 10; ++i) {
    lport = sender->StartListening(kIP, port[i], NULL);
    listening_port_ = sender->listening_ports();
    if (num_lport < listening_port_.size()) {
      if ( port[i] == 0)
        ASSERT_EQ(*(find(listening_port_.begin(), listening_port_.end(), lport)), lport);
      else
        ASSERT_EQ(lport, port[i]);
      ++num_lport;
    }
  }
  for (; i < 10; ++i) {
    lport = sender->StartListening(kIP, port[i], &transport_condition);
    listening_port_ = sender->listening_ports();
    if (num_lport < listening_port_.size()) {
      if ( port[i] == 0)
        ASSERT_EQ(*(find(listening_port_.begin(), listening_port_.end(), lport)), lport);
      else
        ASSERT_EQ(lport, port[i]);
      ASSERT_EQ(kSuccess, transport_condition);
      ++num_lport;
    }
    else
      ASSERT_EQ(kListenError, transport_condition);
  }
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_PrepareToSend) {
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  boost::shared_ptr<Transport> receiver(this->CreateTransport());
  ASSERT_LT(0, receiver->StartListening(kIP, 5500, NULL));
  ASSERT_GT(0, sender->PrepareToSend(kIP, 5000, "", 0));
  ASSERT_LT(0, sender->PrepareToSend(kIP, 5500, "", 0));
  ASSERT_LT(0, sender->PrepareToSend(kIP,5500, "", 0));
  ASSERT_LT(0, sender->PrepareToSend(kIP, 5500, kIP, 5500));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StopListening) {
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  ASSERT_LT(0, sender->StartListening(kIP, 0, NULL));
  ASSERT_LT(0, sender->StartListening(kIP, 3000, NULL));
  ASSERT_EQ(size_t(2), sender->listening_ports().size());
  ASSERT_TRUE(sender->StopListening(3000));
  ASSERT_EQ(size_t(1), sender->listening_ports().size());
  ASSERT_TRUE(sender->StopListening(sender->listening_ports().front()));
  ASSERT_EQ(size_t(0), sender->listening_ports().size());
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StopAllListening) {
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  ASSERT_LT(0, sender->StartListening(kIP, 0, NULL));
  ASSERT_LT(0, sender->StartListening(kIP, 3000, NULL));
  ASSERT_EQ(size_t(2), sender->listening_ports().size());
  ASSERT_TRUE(sender->StopAllListening());
  ASSERT_EQ(size_t(0), sender->listening_ports().size());
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Send) {
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  boost::shared_ptr<Transport> receiver(this->CreateTransport());
  MessageHandler sender_msgh(sender->signals(), "Send", false);
  const int kTimeout(rpcprotocol::kRpcTimeout + 1000);
  TransportMessage request = this->MakeTransportMessage(true, 256 * 1024);
  sender->Send(request, 1, kTimeout);
  ASSERT_EQ(size_t(1), sender_msgh.sent_results().size());
  boost::tuple<SocketId, TransportCondition> signalled_sent_result =
      sender_msgh.sent_results().back();
  ASSERT_EQ(kSendFailure, signalled_sent_result.get<1>());

  TransportMessage request_1;
  ASSERT_LT(0, receiver->StartListening(kIP, 3000, NULL));
  SocketId socket_id = sender->PrepareToSend(kIP, 3000, "", 0);
  sender->Send(request_1, socket_id, kTimeout);
  ASSERT_EQ(size_t(1), sender_msgh.sent_results().size());
  signalled_sent_result = sender_msgh.sent_results().back();
  ASSERT_EQ(kInvalidData, signalled_sent_result.get<1>());
  
}

// Function Testing End

// NOTE: register new test patterns using macro at bottom

TYPED_TEST_P(TransportAPITest, BEH_TRANS_SendOneMessageFromOneToAnother) {
  // Set up nodes and message handlers
  boost::shared_ptr<Transport> sender(this->CreateTransport());
  MessageHandler sender_msgh(sender->signals(), "Send", false);
  boost::shared_ptr<Transport> receiver(this->CreateTransport());
  MessageHandler receiver_msgh(receiver->signals(), "Receive", false);
  Port listening_port = receiver->StartListening("", 0, NULL);
  ASSERT_LT(Port(0), listening_port);

  // Send message
  TransportMessage request = this->MakeTransportMessage(true, 256 * 1024);
  const std::string kSentRpcRequest =
      request.data().rpc_message().SerializeAsString();
  SocketId sender_socket = sender->PrepareToSend(kIP, listening_port, "", 0);
  ASSERT_LT(0, sender_socket);
  const int kTimeout(rpcprotocol::kRpcTimeout + 1000);
  sender->Send(request, sender_socket, rpcprotocol::kRpcTimeout);
  int count(0);
  while (count < kTimeout && receiver_msgh.rpc_requests().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(size_t(0), sender_msgh.rpc_requests().size());
  EXPECT_EQ(size_t(0), sender_msgh.rpc_responses().size());
  ASSERT_EQ(size_t(1), sender_msgh.sent_results().size());
  EXPECT_EQ(size_t(0), sender_msgh.received_results().size());
  ASSERT_EQ(size_t(1), receiver_msgh.rpc_requests().size());
  EXPECT_EQ(size_t(0), receiver_msgh.rpc_responses().size());
  EXPECT_EQ(size_t(0), receiver_msgh.sent_results().size());
  EXPECT_EQ(size_t(0), receiver_msgh.received_results().size());

  // Assess results and get receiving socket's ID
  boost::tuple<SocketId, TransportCondition> signalled_sent_result =
      sender_msgh.sent_results().back();
  EXPECT_EQ(sender_socket, signalled_sent_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_sent_result.get<1>());
  boost::tuple<rpcprotocol::RpcMessage, SocketId, float> signalled_rpc_message =
      receiver_msgh.rpc_requests().back();
  EXPECT_EQ(kSentRpcRequest,
            signalled_rpc_message.get<0>().SerializeAsString());
  SocketId receiver_socket = signalled_rpc_message.get<1>();

  // Send reply
  TransportMessage response = this->MakeTransportMessage(false, 256 * 1024);
  const std::string kSentRpcResponse =
      response.data().rpc_message().SerializeAsString();
  receiver->Send(response, receiver_socket, 0);
  count = 0;
  while (count < kTimeout && receiver_msgh.rpc_responses().empty()) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    count += 10;
  }
  EXPECT_EQ(size_t(0), sender_msgh.rpc_requests().size());
  ASSERT_EQ(size_t(1), sender_msgh.rpc_responses().size());
  EXPECT_EQ(size_t(1), sender_msgh.sent_results().size());
  EXPECT_EQ(size_t(0), sender_msgh.received_results().size());
  EXPECT_EQ(size_t(1), receiver_msgh.rpc_requests().size());
  EXPECT_EQ(size_t(0), receiver_msgh.rpc_responses().size());
  ASSERT_EQ(size_t(1), receiver_msgh.sent_results().size());
  EXPECT_EQ(size_t(0), receiver_msgh.received_results().size());

  // Assess results
  signalled_sent_result = receiver_msgh.sent_results().back();
  EXPECT_EQ(receiver_socket, signalled_sent_result.get<0>());
  EXPECT_EQ(kSuccess, signalled_sent_result.get<1>());
  signalled_rpc_message = sender_msgh.rpc_responses().back();
  EXPECT_EQ(kSentRpcResponse,
            signalled_rpc_message.get<0>().SerializeAsString());
  EXPECT_EQ(sender_socket, signalled_rpc_message.get<1>());
}




REGISTER_TYPED_TEST_CASE_P(TransportAPITest,
                           BEH_TRANS_StartListening,
                           BEH_TRANS_PrepareToSend,
                           BEH_TRANS_StopListening,
                           BEH_TRANS_StopAllListening,
                           BEH_TRANS_Send,
                           BEH_TRANS_SendOneMessageFromOneToAnother);

}  // namespace test

}  // namespace transport

#endif  // MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_