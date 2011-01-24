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
#include <boost/thread.hpp>
#include <cstdlib>
#include <list>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/transport/transport.h"
//  #include "maidsafe/common/utils.h"
#include "maidsafe/transport/transport.pb.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/tests/transport/messagehandler.h"

namespace maidsafe {

namespace transport {

namespace test {

// default local IP address
const IP kIP(boost::asio::ip::address::from_string("127.0.0.1"));
typedef boost::shared_ptr<boost::asio::io_service> IoServicePtr;
typedef boost::shared_ptr<boost::asio::io_service::work> WorkPtr;
typedef boost::shared_ptr<Transport> TransportPtr;
typedef boost::shared_ptr<MessageHandler> MessageHandlerPtr;
typedef std::vector<std::string> Messages;

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
    for (int i = 0; i < 2; ++i)
      thread_group_.create_thread(boost::bind(&boost::asio::io_service::run,
                                              asio_service_));
  }
  ~TransportAPITest() {
    work_.reset();
    thread_group_.join_all();
  }
 protected:
  // Create a transport and an io_service listening on the given or random port
  // (if zero) if listen == true.  If not, only a transport is created, and the
  // test member asio_service_ is used.
  void SetupTransport(bool listen, Port lport) {
    if (listen) {
      TransportPtr transport(new T(asio_service_));
      if (lport != Port(0)) {
        EXPECT_EQ(kSuccess,
                  transport->StartListening(Endpoint(kIP, lport)));
      } else {
        while (kSuccess != transport->StartListening(Endpoint(
            kIP, (rand() % 60536) + 5000)));
          // TODO(Fraser#5#): 2010-12-27 - Uncomment once maidsafe_dht_static
          //      can be compiled.
          //            kIP, (base::RandomUint32() % 60536) + 5000)));
          //  kIP, (rand() % 60536) + 5000)));
      } // do check for fail listening port
      listening_transports_.push_back(transport);
    } else {
      TransportPtr transport(new T(asio_service_));
      sending_transports_.push_back(transport);
    }
  }
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
    std::vector< TransportPtr >::iterator listening_transports_itr(
        listening_transports_.begin());
    while(listening_transports_itr != listening_transports_.end()) {
      MessageHandlerPtr msg_h(new MessageHandler("Receiver"));
      (*listening_transports_itr)->on_message_received()->connect(
          boost::bind(&MessageHandler::DoOnRequestReceived, msg_h, _1, _2, _3,
                      _4));
      (*listening_transports_itr)->on_error()->connect(boost::bind(
          &MessageHandler::DoOnError, msg_h, _1));
      listening_message_handlers_.push_back(msg_h);
      ++listening_transports_itr;
    }
    sending_transports_itr = sending_transports_.begin();
    while (sending_transports_itr != sending_transports_.end()) {
      listening_transports_itr = listening_transports_.begin();
      while (listening_transports_itr != listening_transports_.end()) {
        for (int i = 0 ; i < num_messages; ++i) {
          asio_service_->post(boost::bind(
              &transport::test::TransportAPITest<T>::SendMessage, this,
              *sending_transports_itr, *listening_transports_itr));
        }
        ++listening_transports_itr;
      }
      ++sending_transports_itr;
    }
    CheckMessages();
    std::vector<MessageHandlerPtr>::iterator sending_msg_handlers_itr(
        sending_message_handlers_.begin());
    while (sending_msg_handlers_itr != sending_message_handlers_.end()) {
      ASSERT_EQ((*sending_msg_handlers_itr)->responses_received().size(),
                 num_messages);
      ++sending_msg_handlers_itr;
    }
    FAIL() << "RunTransportTest() not implemented.";
  }
  // To send request to listener
  void SendMessage(TransportPtr sender_pt, TransportPtr listener_pt) {
    // std::string request = base::RandomString(10); need to change
    std::string request("Request");
    sender_pt->Send(request, Endpoint(kIP, listener_pt->listening_port()),
                    Timeout(1000));
    (request_messages_).push_back(request);
    // std::string response = base::RandomString(10); need to change
    std::string response("Response");
    listener_pt->Send(response, Endpoint(kIP, sender_pt->listening_port()),
                      Timeout(1000));
  }

  void CheckMessages() {
    bool found(false);
    // Compare request
    std::vector<MessageHandlerPtr>::iterator listening_msg_handlers_itr(
        listening_message_handlers_.begin());
    while (listening_msg_handlers_itr != listening_message_handlers_.end()) {
      IncomingMessages listening_request_received =
          (*listening_msg_handlers_itr)->requests_received();
      IncomingMessages::iterator listening_request_received_itr =
          listening_request_received.begin();
      while (listening_request_received_itr !=
          listening_request_received.end()) {
        found = false;
        std::vector<std::string>::iterator request_messages_itr;
        request_messages_itr = std::find(
            request_messages_.begin(), request_messages_.end(),
            (*listening_request_received_itr).first);
        if (request_messages_itr != request_messages_.end())
          found = true;
        ++listening_request_received_itr;
      }
      if (!found)
        break;
      ++listening_msg_handlers_itr;
    }
    ASSERT_EQ(listening_msg_handlers_itr,
              listening_message_handlers_.end());

    // compare response
    std::vector<MessageHandlerPtr>::iterator sending_msg_handlers_itr(
        sending_message_handlers_.begin());
    listening_msg_handlers_itr = listening_message_handlers_.begin();
    while (sending_msg_handlers_itr != sending_message_handlers_.end()) {
      IncomingMessages sending_response_received =
          (*sending_msg_handlers_itr)->responses_received();
      IncomingMessages::iterator sending_response_received_itr =
          sending_response_received.begin();
      for (; sending_response_received_itr != sending_response_received.end();
          ++sending_response_received_itr) {
        found = false;
        listening_msg_handlers_itr = listening_message_handlers_.begin();
        while (listening_msg_handlers_itr !=
            listening_message_handlers_.end()) {
          OutgoingResponses listening_response_sent =
              (*listening_msg_handlers_itr)->responses_sent();
          OutgoingResponses::iterator listening_response_sent_itr;
          listening_response_sent_itr = std::find(
              listening_response_sent.begin(), listening_response_sent.end(),
              (*sending_response_received_itr).first);
          if (listening_response_sent_itr != listening_response_sent.end()) {
            found = true;
            break;
          }
          ++listening_msg_handlers_itr;
        }
        if (!found)
         break;
      }
      ASSERT_EQ(sending_response_received_itr,
                sending_response_received.end());
      ++sending_msg_handlers_itr;
    }
 }

  std::vector< TransportPtr> listening_transports_;
  std::vector<MessageHandlerPtr> listening_message_handlers_;
  std::vector<TransportPtr> sending_transports_;
  std::vector<MessageHandlerPtr> sending_message_handlers_;
  IoServicePtr asio_service_;
  WorkPtr work_;
  boost::thread_group thread_group_;
  std::vector<std::string> request_messages_;
};

TYPED_TEST_CASE_P(TransportAPITest);

// NOTE: register new test patterns using macro at bottom

TYPED_TEST_P(TransportAPITest, BEH_TRANS_StartStopListening) {
  TransportPtr transport(new TypeParam(this->asio_service_));
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kInvalidPort, transport->StartListening(Endpoint(kIP, 0)));
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
  TransportPtr sender(new TypeParam(this->asio_service_));
  TransportPtr listener(new TypeParam(this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2000)));
  MessageHandlerPtr msgh_sender(new MessageHandler("Sender"));
  MessageHandlerPtr msgh_listener(new MessageHandler("listener"));
  sender->on_message_received()->connect(
      boost::bind(&MessageHandler::DoOnResponseReceived, msgh_sender, _1, _2,
      _3, _4));
  sender->on_error()->connect(boost::bind(&MessageHandler::DoOnError,
                                          msgh_sender, _1));
  listener->on_message_received()->connect(
      boost::bind(&MessageHandler::DoOnRequestReceived, msgh_listener, _1, _2,
      _3, _4));
  listener->on_error()->connect(boost::bind(&MessageHandler::DoOnError,
                                            msgh_listener, _1));
  std::string request("FirstRequest");
  std::string response("FirstResponse");
  sender->Send(request, Endpoint(kIP, listener->listening_port()),
               Timeout(1000));

  ASSERT_EQ(size_t(0), msgh_sender->errors().size());
  ASSERT_EQ(size_t(1), msgh_listener->requests_received().size());
  ASSERT_EQ(request, msgh_listener->requests_received().at(0).first);
  listener->Send(response, Endpoint(kIP, sender->listening_port()),
                 Timeout(1000));
  ASSERT_EQ(size_t(1), msgh_listener->responses_sent().size());
  ASSERT_EQ(size_t(1), msgh_sender->responses_received().size());
  ASSERT_EQ(msgh_listener->responses_sent().at(0),
            msgh_sender->responses_received().at(0).first);

  request = "SecondRequest";
  response = "SecondResponse";
  sender->Send(request, Endpoint(kIP, listener->listening_port()),
               Timeout(1000));
  ASSERT_EQ(size_t(0), msgh_sender->errors().size());
  ASSERT_EQ(size_t(2), msgh_listener->requests_received().size());
  ASSERT_EQ(request, msgh_listener->requests_received().at(1).first);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
  listener->Send(response, Endpoint(kIP, sender->listening_port()),
                 Timeout(1000));
  ASSERT_EQ(size_t(2), msgh_listener->responses_sent().size());
  ASSERT_EQ(size_t(1), msgh_sender->responses_received().size());

  sender->Send(request, Endpoint(kIP, 10000), Timeout(1000));
  ASSERT_EQ(size_t(1), msgh_sender->errors().size());
  ASSERT_EQ(kRemoteUnreachable, msgh_sender->errors().at(0));
  ASSERT_EQ(size_t(2), msgh_listener->requests_received().size());
}


TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneSingleMessage) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneMultiMessage) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(123));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToManySingleMessage) {
  this->SetupTransport(false, 0);
  for (int i = 0; i < 20; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToManyMultiMessage) {
  this->SetupTransport(false, 0);
  for (int i = 0; i < 20; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(2033));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_ManyToManyMultiMessage) {
  for (int i = 0; i < 15; ++i)
    this->SetupTransport(false, 0);
  for (int i = 0; i < 20; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(2033));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Random) {
  boost::uint8_t num_sender_transports(
      static_cast<boost::uint8_t>(rand() % 10 + 5));
  boost::uint8_t num_listener_transports(
      static_cast<boost::uint8_t>(rand() % 10 + 5));
  boost::uint8_t num_messages(static_cast<boost::uint8_t>(rand() % 100 + 1));
  // TODO(Fraser#5#): 2010-12-27 - Uncomment once maidsafe_dht_static can be
  //                               compiled.
//  boost::uint8_t num_transports(
//      static_cast<boost::uint8_t>(boost::RandomUint32() % 10 + 5));
//  boost::uint8_t num_messages(
//      static_cast<boost::uint8_t>(boost::RandomUint32() % 100 + 1));
  for (boost::uint8_t i = 0; i < num_sender_transports; ++i)
    this->SetupTransport(false, 0);
  for (boost::uint8_t i = 0; i < num_listener_transports; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(num_messages));
}

REGISTER_TYPED_TEST_CASE_P(TransportAPITest,
                           BEH_TRANS_StartStopListening,
                           BEH_TRANS_Send,
                           BEH_TRANS_OneToOneSingleMessage,
                           BEH_TRANS_OneToOneMultiMessage,
                           BEH_TRANS_OneToManySingleMessage,
                           BEH_TRANS_OneToManyMultiMessage,
                           BEH_TRANS_ManyToManyMultiMessage,
                           BEH_TRANS_Random);

}  // namespace test

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TESTS_TRANSPORT_TRANSPORTAPITEST_H_

