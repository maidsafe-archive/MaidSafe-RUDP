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

#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/protobuf/transport.pb.h"
#include "maidsafe/protobuf/kademlia.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"

#include <list>
#include <set>
#include <string>
#include <vector>

namespace transport {

namespace test {

// default local IP address
const IP kIP(boost::asio::ip::address::from_string("127.0.0.1"));

// type-parametrised test case for the transport API
template <class T>
class TransportAPITest: public testing::Test {
 protected:
  // creates a transport listening on the given or random port (if zero)
  boost::shared_ptr<Transport> SetupTransport(bool listen, Port lport) {
    boost::shared_ptr<boost::asio::io_service> asio_service;
    boost::shared_ptr<Transport> transport(new T(asio_service));
    if (listen) {
      if (lport != Port(0))
        EXPECT_EQ(kSuccess, transport->StartListening(EndPoint(kIP, lport)));
      else while (kSuccess != transport->StartListening(EndPoint(kIP,
          (base::RandomUint32() % 1000) + 5000)));
      // TODO some handling for asio_service
    }
    return transport;
  };
  // test a conversation between the given transports
  void RunTransportTest(
      const std::vector< boost::shared_ptr<Transport> > &transports,
      const int &num_messages) {
    std::vector<MessageHandler> msgh;
    std::string msg;
    Endpoint endpoint;
    endpoint.ip = kIP;
    std::vector<Transport>::iterator it = transports.begin();
    boost::uint16_t num_transport = transports.size();
    while (it != transports.end()) {
      if ((*it)->listening_port() == 0) {
        MessageHandler msg_h((*it)->signals(), "Sender" , false);
        (*it)->on_message_received()->connect(boost::bind(
            &MessageHandler::DoOnResponseReceived, &msg_h, _1, _2, _3, _4));
        (*it)->on_error()->connect(boost::bind(&MessageHandler::DoOnError,
                                              &msg_h, _1));
        msgh.push_back(msg_h);
      }
      else {
        MessageHandler msg_h(*(it)->signals(), "Receiver", false);
        (*it)->on_message_received()->connect(boost::bind(
            &MessageHandler::DoOnRequestReceived, &msg_h, _1, _2, _3, _4));
        (*it)->on_message_received()->connect(boost::bind(
            &MessageHandler::DoResponseReceived, &msg_h, _1, _2, _3, _4));
        (*it)->on_error()->connect(boost::bind(&MessageHandler::DoOnError,
                                              &msg_h, _1));
        msgh.push_back(msg_h);
      }
      ++it;
    }
    it = transports.begin();
    msg_it = msgh.begin();

    /*
    In this block of code sender(listening_port = 0) can only send msg to receiver with listening_port. 
    then sender and receiver will check their corresponding request_received ,response_received, error_ queues.
              req
    Sender1 -----------------> receiver1      compare queues  (request_received ,response_received, error_) and messages
              response
            <--------------

                   req
    Receiver1 ----------------> Receiver2   compare queues  (request_received ,response_received, error_) and messages
                  response
              <---------------
                 
                   req
    Receiver2 -----------------> Receiver1  compare queues  (request_received ,response_received, error_) and messages
                   response
              <-----------------
    */
    for (int i = 0; i < num_transport ; ++i) {
      for (int j = 0 ; j < num_transport ; ++j) {
        if ( ( i == j ) && ( *(it+j)->listening_port() == 0 ) )
          continue;
        endpoint.port = *(it+j)->listening_port();
        for (int num = 1; num <= num_messages ; ++num) {
          std::string request = base::RandomString(25);
          int num_of_req_received = (*(msg_it+j))->request_received().size();
          int num_of_errors = (*(msg_it+i))->errors().size();
          int num_of_res_received = (*(msg_it+i))->response_received().size();
          (*(it+i))->Send(request, endpoint);
          ASSERT_EQ((num_of_received_msgs+1), (*(msg_it+j)->request_received().size()));
          ASSERT_EQ(num_of_errors, (*(msg_it+i))->errors().size());
          std::string response = base::RandomString(25);
          endpoint.port = (*(it+i))->listening_port();
          (*(it+j))->send(response, endpoint);
          ASSERT_STREQ(response, /* (*(msg_it+i))->response_received().string */);
        }
      }
    }

    /**
     * TODO
     * - create message handler for transports and connect to signals
     * - create message per listening transport
     * - from each transport, send message to each (other) listening transport
     * - check all received messages for original content
     * - check message handlers' statuses
     * - (allow for conversations with multiple replies)
     * - (allow for a separate thread per transport and asynchronous sending)
     */
    FAIL() << "RunTransportTest() not implemented.";
  }
};

TYPED_TEST_CASE_P(TransportAPITest);

// NOTE: register new test patterns using macro at bottom

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StartStopListening) {
  boost::shared_ptr<boost::asio::io_service> asio_service;
  boost::shared_ptr<Transport> transport(new TypeParam(asio_service));
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kInvalidEndpoint, transport->StartListening(Endpoint(kIP, 0));
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 77));
  EXPECT_EQ(Port(77), transport->listening_port());
  EXPECT_EQ(kAlreadyStarted, transport->StartListening(Endpoint(kIP, 77));
  EXPECT_EQ(Port(77), transport->listening_port());
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 55123));
  EXPECT_EQ(Port(55123), transport->listening_port());
  transport->StopListening();
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 55123));
  EXPECT_EQ(Port(55123), transport->listening_port());
  transport->StopListening();
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Send) {
  FAIL() << "Not implemented.";
  /*
  boost::shared_ptr<Transport> sender(new TypeParam), receiver(new TypeParam);
  // MessageHandler sender_msgh(sender->signals(), "Send", false);
  const int kTimeout(rpcprotocol::kRpcTimeout + 1000);
  TransportMessage request = this->MakeTransportMessage(
      TransportMessage::kKeepAlive, 256 * 1024);
  sender->Send(request, 1, kTimeout);
  ASSERT_EQ(size_t(1), sender_msgh.sent_results().size());
  boost::tuple<SocketId, TransportCondition> signalled_sent_result =
      sender_msgh.sent_results().back();
  EXPECT_EQ(kSendFailure, signalled_sent_result.get<1>());

  TransportMessage request_1;
  Port lport(receiver->StartListening(kIP, 3000, NULL));
  EXPECT_NE(Port(0), lport);
  SocketId socket_id(sender->PrepareToSend(kIP, lport, "", 0));
  sender->Send(request_1, socket_id, kTimeout);
  ASSERT_EQ(size_t(1), sender_msgh.sent_results().size());
  signalled_sent_result = sender_msgh.sent_results().back();
  EXPECT_EQ(kInvalidData, signalled_sent_result.get<1>());
  */
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneSingleMessage) {
  std::vector< boost::shared_ptr<Transport> > transports;
  transports.push_back(this->SetupTransport(false, 0));  // sender
  transports.push_back(this->SetupTransport(true, 0));  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(transports, 1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneReply) {
  std::vector< boost::shared_ptr<Transport> > transports;
  transports.push_back(this->SetupTransport(false, 0));  // sender
  transports.push_back(this->SetupTransport(true, 0));  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(transports, 2));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneMultiMessage) {
  std::vector< boost::shared_ptr<Transport> > transports;
  transports.push_back(this->SetupTransport(false, 0));  // sender
  transports.push_back(this->SetupTransport(true, 0));  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(transports, 123));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_ManyNodesSingleMessage) {
  std::vector< boost::shared_ptr<Transport> > transports;
  for (int i = 0; i < 20; ++i)
    transports.push_back(this->SetupTransport(true, 0));  // sender & receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(transports, 1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Random) {
  std::vector< boost::shared_ptr<Transport> > transports;
  int num_transports(static_cast<int>(base::RandomUint32() % 10 + 5));  // 5-14
  int num_messages(static_cast<int>(base::RandomUint32() % 100 + 1));  // 1-100
  for (int i = 0; i < num_transports; ++i)
    transports.push_back(this->SetupTransport(true, 0));
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(transports, num_messages));
}

REGISTER_TYPED_TEST_CASE_P(TransportAPITest,
                           BEH_TRANS_StartStopListening,
                           BEH_TRANS_Send,
                           BEH_TRANS_OneToOneSingleMessage,
                           BEH_TRANS_OneToOneMultiMessage,
                           BEH_TRANS_ManyNodesSingleMessage,
                           BEH_TRANS_Random);

}  // namespace test

}  // namespace transport

#endif  // MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_
