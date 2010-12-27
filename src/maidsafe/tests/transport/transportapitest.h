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
#include <cstdlib>
#include <list>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/transport/transport.h"
//  #include "maidsafe/base/utils.h"
#include "maidsafe/transport/transport.pb.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"

namespace transport {

namespace test {

// default local IP address
const IP kIP(boost::asio::ip::address::from_string("127.0.0.1"));

typedef boost::shared_ptr<boost::asio::io_service> IoServicePtr;
typedef boost::shared_ptr<boost::asio::io_service::work> WorkPtr;
typedef boost::shared_ptr<Transport> TransportPtr;
typedef boost::shared_ptr<MessageHandler> MessageHandlerPtr;

template <class T>
struct TransportGroup {
  TransportGroup()
    : asio_service(new boost::asio::io_service),
      work(new boost::asio::io_service::work(*asio_service)),
      thread(new boost::thread(boost::bind(&boost::asio::io_service::run,
                                           asio_service))),
      transport(new T(asio_service)) {}
  ~TransportGroup() {
    work.reset();
    thread->join();
  }
  IoServicePtr asio_service;
  WorkPtr work;
  boost::shared_ptr<boost::thread> thread;
  TransportPtr transport;
};

// type-parameterised test case for the transport API
template <class T>
class TransportAPITest: public testing::Test {
 public:
  TransportAPITest()
      : listening_transports_(),
        listening_message_handlers_(),
        sending_transports_(),
        sending_message_handlers_(),
        asio_service_(new boost::asio::io_service),
        work_(new boost::asio::io_service::work(*asio_service_)),
        thread_group_() {
    for (int i = 0; i < 3; ++i)
      thread_group_.create_thread(boost::bind(&boost::asio::io_service::run,
                                              asio_service_));
  }
  ~TransportAPITest() {
    work_.reset();
    thread_group_.join_all();
  }
 protected:
  // Creates a transport and an io_service listening on the given or random port
  // (if zero) if listen == true.  If not, only a transport is created, and the
  // test member asio_service_ is used.
  void SetupTransport(bool listen, Port lport) {
    if (listen) {
      TransportGroup<T> transport_group;
      if (lport != Port(0)) {
        EXPECT_EQ(kSuccess,
            transport_group.transport->StartListening(Endpoint(kIP, lport)));
      } else {
        while (kSuccess != transport_group.transport->StartListening(Endpoint(
  // TODO(Fraser#5#): 2010-12-27 - Uncomment once maidsafe_dht_static can be
  //                               compiled.
//            kIP, (base::RandomUint32() % 60536) + 5000)));
            kIP, (rand() % 60536) + 5000)));
      }
      listening_transports_.push_back(transport_group);
    } else {
      TransportPtr transport(new T(asio_service_));
      sending_transports_.push_back(transport);
    }
  };
  // test a conversation between the given transports
  void RunTransportTest(const int &num_messages) {
    Endpoint endpoint;
    endpoint.ip = kIP;
    std::vector<TransportPtr>::iterator sending_transports_itr(
        sending_transports_.begin());
    while (sending_transports_itr != sending_transports_.end()) {
      MessageHandlerPtr msg_h(new MessageHandler("Sender"));
      (*sending_transports_itr)->on_message_received()->connect(boost::bind(
          &MessageHandler::DoOnResponseReceived, msg_h, _1, _2, _3, _4));
      (*sending_transports_itr)->on_error()->connect(
          boost::bind(&MessageHandler::DoOnError, msg_h, _1));
      sending_message_handlers_.push_back(msg_h);
      ++sending_transports_itr;
    }
    std::vector< TransportGroup<T> >::iterator listening_transports_itr(
        listening_transports_.begin());
    while(listening_transports_itr != listening_transports_.end()) {
      MessageHandlerPtr msg_h(new MessageHandler("Receiver"));
      (*listening_transports_itr).transport->on_message_received()->connect(
          boost::bind(&MessageHandler::DoOnRequestReceived, msg_h, _1, _2, _3,
                      _4));
      (*listening_transports_itr).transport->on_message_received()->connect(
          boost::bind(&MessageHandler::DoOnResponseReceived, msg_h, _1, _2, _3,
                      _4));
      (*listening_transports_itr).transport->on_error()->connect(boost::bind(
          &MessageHandler::DoOnError, msg_h, _1));
      listening_message_handlers_.push_back(msg_h);
      ++listening_transports_itr;
    }

    /* Example (sender1, receiver1, receiver2)
    In this block of code sender(listening_port = 0) can only send msg to receiver with listening_port. 
    then sender and receiver will check their corresponding request_received ,response_received, error_ queues.
              req
    Sender1 -----------------> Receiver1      compare queues  (request_received ,response_received, error_) and messages
              response
            <--------------

              req
    Sender1 -----------------> Receiver2      compare queues  (request_received ,response_received, error_) and messages
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
//    it = transports.begin();
//    msg_it = msgh.begin();
//    boost::uint16_t num_transport = transports.size();
//    for (int i = 0; i < num_transport ; ++i) {
//      for (int j = 0 ; j < num_transport ; ++j) {
//        if ( ( i == j ) && ( *(it+j)->listening_port() == 0 ) )
//          continue;
//        endpoint.port = *(it+j)->listening_port();
//        for (int num = 1; num <= num_messages ; ++num) {
//          std::string request = base::RandomString(25);
//          int num_of_req_received = (*(msg_it+j))->request_received().size();
//          int num_of_errors = (*(msg_it+i))->errors().size();
//          int num_of_res_received = (*(msg_it+i))->response_received().size();
//          (*(it+i))->Send(request, endpoint);
//          ASSERT_EQ((num_of_received_msgs+1), (*(msg_it+j)->request_received().size()));
//          ASSERT_STREQ(request, /* (*(msg_it+j))->request_received().string */);
//          ASSERT_EQ(num_of_errors, (*(msg_it+i))->errors().size());
//          std::string response = base::RandomString(25);
//          endpoint.port = (*(it+i))->listening_port();
//          (*(it+j))->send(response, endpoint);
//          ASSERT_EQ((num_of_res_received+1), (*(msg_it+j)->request_received().size()));
//          ASSERT_STREQ(response, /* (*(msg_it+i))->response_received().string */);
//        }
//      }
//    }

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
  std::vector< TransportGroup<T> > listening_transports_;
  std::vector<MessageHandlerPtr> listening_message_handlers_;
  std::vector<TransportPtr> sending_transports_;
  std::vector<MessageHandlerPtr> sending_message_handlers_;
  IoServicePtr asio_service_;
  WorkPtr work_;
  boost::thread_group thread_group_;
};

TYPED_TEST_CASE_P(TransportAPITest);

// NOTE: register new test patterns using macro at bottom

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StartStopListening) {
  TransportPtr transport(new TypeParam(asio_service_));
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kInvalidAddress, transport->StartListening(Endpoint(kIP, 0)));
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 77)));
  EXPECT_EQ(Port(77), transport->listening_port());
  EXPECT_EQ(kAlreadyStarted, transport->StartListening(Endpoint(kIP, 77)));
  EXPECT_EQ(kAlreadyStarted, transport->StartListening(Endpoint(kIP, 55123)));
  EXPECT_EQ(Port(77), transport->listening_port());
  transport->StopListening();
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 55123)));
  EXPECT_EQ(Port(55123), transport->listening_port());
  transport->StopListening();
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Send) {
  FAIL() << "Not implemented.";
  /*
  TransportPtr sender(new TypeParam), receiver(new TypeParam);
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
  SetupTransport(false, 0);  // sender
  SetupTransport(true, 0);  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneReply) {
  this->SetupTransport(false, 0);  // sender
  this->SetupTransport(true, 0);  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(2));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneMultiMessage) {
  this->SetupTransport(false, 0);  // sender
  this->SetupTransport(true, 0);  // receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(123));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_ManyNodesSingleMessage) {
  for (int i = 0; i < 20; ++i)
    SetupTransport(true, 0);  // sender & receiver
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Random) {
  boost::uint8_t num_transports(static_cast<boost::uint8_t>(rand() % 10 + 5));
  boost::uint8_t num_messages(static_cast<boost::uint8_t>(rand() % 100 + 1));
  // TODO(Fraser#5#): 2010-12-27 - Uncomment once maidsafe_dht_static can be
  //                               compiled.
//  boost::uint8_t num_transports(
//      static_cast<boost::uint8_t>(boost::RandomUint32() % 10 + 5));
//  boost::uint8_t num_messages(
//      static_cast<boost::uint8_t>(boost::RandomUint32() % 100 + 1));
  for (boost::uint8_t i = 0; i < num_transports; ++i)
    SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(num_messages));
}

REGISTER_TYPED_TEST_CASE_P(TransportAPITest,
                           BEH_TRANS_StartStopListening,
                           BEH_TRANS_Send,
                           BEH_TRANS_OneToOneSingleMessage,
                           BEH_TRANS_OneToOneReply,
                           BEH_TRANS_OneToOneMultiMessage,
                           BEH_TRANS_ManyNodesSingleMessage,
                           BEH_TRANS_Random);

}  // namespace test

}  // namespace transport

#endif  // MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_
