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

#include "maidsafe-dht/tests/transport/test_transport_api.h"
#include <functional>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport {

boost::uint32_t RudpParameters::kDefaultWindowSize = 16;
boost::uint32_t RudpParameters::kMaximumWindowSize = 512;
boost::uint32_t RudpParameters::kDefaultSize = 1480;
boost::uint32_t RudpParameters::kMaxSize = 25980;
boost::uint32_t RudpParameters::kDefaultDataSize = 1450;
boost::uint32_t RudpParameters::kMaxDataSize = 25950;
bptime::time_duration RudpParameters::kDefaultSendTimeOut =
                                                    bptime::milliseconds(1000);
bptime::time_duration RudpParameters::kDefaultReceiveTimeOut =
                                                    bptime::milliseconds(200);
bptime::time_duration RudpParameters::kDefaultAckTimeOut =
                                                    bptime::milliseconds(1000);
bptime::time_duration RudpParameters::kDefaultSendDelay =
                                                    bptime::microseconds(1000);
bptime::time_duration RudpParameters::kDefaultReceiveDelay =
                                                    bptime::milliseconds(100);
bptime::time_duration RudpParameters::kAckInterval =
                                                    bptime::milliseconds(100);
RudpParameters::ConnectionType RudpParameters::kConnectionType =
                                 RudpParameters::ConnectionType::kWireless;
bptime::time_duration RudpParameters::kSpeedCalculateInverval =
                                                    bptime::milliseconds(1000);
boost::uint32_t RudpParameters::SlowSpeedThreshold = 1024;  // b/s

namespace test {

TestMessageHandler::TestMessageHandler(const std::string &id)
    : finished_(false),
      this_id_(id),
      requests_received_(),
      responses_received_(),
      responses_sent_(),
      results_(),
      mutex_() {}

void TestMessageHandler::DoOnRequestReceived(const std::string &request,
                                             const Info &info,
                                             std::string *response,
                                             Timeout *timeout) {
  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  boost::mutex::scoped_lock lock(mutex_);
  requests_received_.push_back(std::make_pair(request, info));
  *response = "Replied to " + request + " (Id = " + boost::lexical_cast<
              std::string>(requests_received_.size()) + ")";
  responses_sent_.push_back(*response);
  *timeout = kStallTimeout;
  DLOG(INFO) << this_id_ << " - Received request: \"" << request
              << "\".  Responding with \"" << *response << "\"" << std::endl;
}

void TestMessageHandler::DoTimeOutOnRequestReceived(const std::string &request,
                                                    const Info &info,
                                                    std::string *response,
                                                    Timeout *timeout) {
  DLOG(INFO) << "Mocking a timedout response" << std::endl;
  boost::mutex::scoped_lock lock(mutex_);
  requests_received_.push_back(std::make_pair(request, info));
  *response = "Timed out reply to " + request + " (Id = " + boost::lexical_cast<
              std::string>(requests_received_.size()) + ")";
  responses_sent_.push_back(*response);
  lock.unlock();
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  *timeout = kImmediateTimeout;
}

void TestMessageHandler::DoOnResponseReceived(const std::string &request,
                                              const Info &info,
                                              std::string *response,
                                              Timeout *timeout) {
  response->clear();
  *timeout = kImmediateTimeout;
  boost::mutex::scoped_lock lock(mutex_);
  responses_received_.push_back(std::make_pair(request, info));
  DLOG(INFO) << this_id_ << " - Received response: \"" << request << "\""
              << std::endl;
  finished_ = true;
}

void TestMessageHandler::DoOnError(const TransportCondition &tc) {
  boost::mutex::scoped_lock lock(mutex_);
  results_.push_back(tc);
  DLOG(ERROR) << this_id_ << " - Error: " << tc << std::endl;
  finished_ = true;
}

void TestMessageHandler::ClearContainers() {
  boost::mutex::scoped_lock lock(mutex_);
  requests_received_.clear();
  responses_received_.clear();
  responses_sent_.clear();
  results_.clear();
}

IncomingMessages TestMessageHandler::requests_received() {
  boost::mutex::scoped_lock lock(mutex_);
  return requests_received_;
}

IncomingMessages TestMessageHandler::responses_received() {
  boost::mutex::scoped_lock lock(mutex_);
  return responses_received_;
}

OutgoingResponses TestMessageHandler::responses_sent() {
  boost::mutex::scoped_lock lock(mutex_);
  return responses_sent_;
}

Results TestMessageHandler::results() {
  boost::mutex::scoped_lock lock(mutex_);
  return results_;
}


template <typename T>
TransportAPI<T>::TransportAPI()
    : asio_service_(new boost::asio::io_service),
      asio_service_1_(new boost::asio::io_service),
      asio_service_2_(new boost::asio::io_service),
      asio_service_3_(new boost::asio::io_service),
      work_(new boost::asio::io_service::work(*asio_service_)),
      work_1_(new boost::asio::io_service::work(*asio_service_1_)),
      work_2_(new boost::asio::io_service::work(*asio_service_2_)),
      work_3_(new boost::asio::io_service::work(*asio_service_3_)),
      listening_transports_(),
      listening_message_handlers_(),
      sending_transports_(),
      sending_message_handlers_(),
      thread_group_(),
      thread_group_1_(),
      thread_group_2_(),
      thread_group_3_(),
      mutex_(),
      request_messages_(),
      count_(0) {
  for (int i = 0; i < kThreadGroupSize; ++i)
    thread_group_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), asio_service_));
  for (int i = 0; i < kThreadGroupSize; ++i)
    thread_group_1_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), asio_service_1_));
  for (int i = 0; i < kThreadGroupSize; ++i)
    thread_group_2_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), asio_service_2_));
  for (int i = 0; i < kThreadGroupSize; ++i)
    thread_group_3_.create_thread(std::bind(static_cast<
        std::size_t(boost::asio::io_service::*)()>
            (&boost::asio::io_service::run), asio_service_3_));
  // count_ = 0;
}

template <typename T>
TransportAPI<T>::~TransportAPI() {
  work_.reset();
  work_1_.reset();
  work_2_.reset();
  work_3_.reset();
  asio_service_->stop();
  asio_service_1_->stop();
  asio_service_2_->stop();
  asio_service_3_->stop();
  thread_group_.join_all();
  thread_group_1_.join_all();
  thread_group_2_.join_all();
  thread_group_3_.join_all();
}

template <typename T>
void TransportAPI<T>::SetupTransport(bool listen, Port lport) {
  if (listen) {
    TransportPtr transport1;
    if (count_ < 8)
      transport1 = TransportPtr(new T(*asio_service_));
    else
      transport1 = TransportPtr(new T(*asio_service_3_));

    if (lport != Port(0)) {
      EXPECT_EQ(kSuccess,
                transport1->StartListening(Endpoint(kIP, lport)));
    } else {
      while (kSuccess != transport1->StartListening(Endpoint(kIP,
                          (RandomUint32() % 60536) + 5000)));
    }  // do check for fail listening port
    listening_transports_.push_back(transport1);
  } else {
    TransportPtr transport1;
    if (count_ < 8)
      transport1 = TransportPtr(new T(*asio_service_1_));
    else
      transport1 = TransportPtr(new T(*asio_service_2_));
    sending_transports_.push_back(transport1);
  }
  ++count_;
}

template <typename T>
void TransportAPI<T>::RunTransportTest(const int &num_messages,
    const int &messages_length) {
  Endpoint endpoint;
  endpoint.ip = kIP;
  std::vector<TestMessageHandlerPtr> msg_handlers;
  std::vector<TransportPtr>::iterator sending_transports_itr(
      sending_transports_.begin());
  while (sending_transports_itr != sending_transports_.end()) {
    TestMessageHandlerPtr msg_h(new TestMessageHandler("Sender"));
    msg_handlers.push_back(msg_h);
    (*sending_transports_itr)->on_message_received()->connect(boost::bind(
        &TestMessageHandler::DoOnResponseReceived, msg_h, _1, _2, _3, _4));
    (*sending_transports_itr)->on_error()->connect(
        boost::bind(&TestMessageHandler::DoOnError, msg_h, _1));
    sending_message_handlers_.push_back(msg_h);
    ++sending_transports_itr;
  }
  std::vector< TransportPtr >::iterator listening_transports_itr(
      listening_transports_.begin());
  while (listening_transports_itr != listening_transports_.end()) {
    TestMessageHandlerPtr msg_h(new TestMessageHandler("Receiver"));
//     msg_handlers.push_back(msg_h);
    (*listening_transports_itr)->on_message_received()->connect(
        boost::bind(&TestMessageHandler::DoOnRequestReceived, msg_h, _1, _2,
                    _3, _4));
    (*listening_transports_itr)->on_error()->connect(boost::bind(
        &TestMessageHandler::DoOnError, msg_h, _1));
    listening_message_handlers_.push_back(msg_h);
    ++listening_transports_itr;
  }
  boost::uint16_t thread_size(0);
  sending_transports_itr = sending_transports_.begin();
  while (sending_transports_itr != sending_transports_.end()) {
    listening_transports_itr = listening_transports_.begin();
    while (listening_transports_itr != listening_transports_.end()) {
      for (int i = 0 ; i < num_messages; ++i) {
        if (thread_size > kThreadGroupSize) {
          // std::cout<<"\nthread_size::"<<thread_size<<std::endl;
          asio_service_2_->post(boost::bind(
            &transport::test::TransportAPITest<T>::SendRPC, this,
            *sending_transports_itr, *listening_transports_itr,
            messages_length));
        } else {
          asio_service_1_->post(boost::bind(
            &transport::test::TransportAPITest<T>::SendRPC, this,
            *sending_transports_itr, *listening_transports_itr,
            messages_length));
        }
        thread_size++;
      }
      ++listening_transports_itr;
    }
    ++sending_transports_itr;
  }
  bool waiting(true);
  int i(0);
  do {
    waiting = false;
    boost::this_thread::sleep(boost::posix_time::seconds(1));
    ++i;
    for (auto it = msg_handlers.begin(); it != msg_handlers.end(); ++it){
      if ((!(*it)->finished_) ||
          ((*it)->responses_received().size() < num_messages))
        waiting = true;
    }
  } while (waiting && (i < 10 * (num_messages + 1) * messages_length));
  // without this sleep, test of RUDP/ManyToManyMultiMessage will fail,
  // reporting received responses not match with the expected
  // Note: only RUDP has this problem. TCP and UDP will not fail even without
  //       this sleep
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  work_.reset();
  work_1_.reset();
  work_2_.reset();
  work_3_.reset();
  asio_service_->stop();
  asio_service_1_->stop();
  asio_service_2_->stop();
  asio_service_3_->stop();
  thread_group_.join_all();
  thread_group_1_.join_all();
  thread_group_2_.join_all();
  thread_group_3_.join_all();
  CheckMessages();
  std::vector<TestMessageHandlerPtr>::iterator sending_msg_handlers_itr(
      sending_message_handlers_.begin());
  while (sending_msg_handlers_itr != sending_message_handlers_.end()) {
    ASSERT_EQ((*sending_msg_handlers_itr)->responses_received().size(),
      listening_message_handlers_.size() * num_messages);
    ++sending_msg_handlers_itr;
  }
}

template <typename T>
void TransportAPI<T>::SendRPC(TransportPtr sender_pt,
    TransportPtr listener_pt, int &messages_length) {
  std::string request(RandomString(1));
  // Cap the length of the msg to 64MB - 100,
  // As during the test, the response will be the send append with a head
  if (messages_length > 26)
    messages_length = 26;
  for (int i = 0; i < messages_length; ++i)
    request = request + request;
  if (messages_length == 26)
    request = request.substr(0, request.size() - 100);
  sender_pt->Send(request, Endpoint(kIP, listener_pt->listening_port()),
                  bptime::seconds(messages_length));
  boost::mutex::scoped_lock lock(mutex_);
  (request_messages_).push_back(request);
}

template <typename T>
void TransportAPI<T>::CheckMessages() {
  bool found(false);
  // Compare Request
  std::vector<TestMessageHandlerPtr>::iterator listening_msg_handlers_itr(
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

  // Compare Response
  std::vector<TestMessageHandlerPtr>::iterator sending_msg_handlers_itr(
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


TYPED_TEST_P(TransportAPITest, BEH_TRANS_StartStopListening) {
  TransportPtr transport(new TypeParam(*this->asio_service_));
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kInvalidPort, transport->StartListening(Endpoint(kIP, 0)));
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 2277)));
  EXPECT_EQ(Port(2277), transport->listening_port());
  EXPECT_EQ(kAlreadyStarted, transport->StartListening(Endpoint(kIP, 2277)));
  EXPECT_EQ(kAlreadyStarted, transport->StartListening(Endpoint(kIP, 55123)));
  EXPECT_EQ(Port(2277), transport->listening_port());
  transport->StopListening();
  EXPECT_EQ(Port(0), transport->listening_port());
  EXPECT_EQ(kSuccess, transport->StartListening(Endpoint(kIP, 55123)));
  EXPECT_EQ(Port(55123), transport->listening_port());
  transport->StopListening();
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Send) {
  TransportPtr sender(new TypeParam(*this->asio_service_));
  TransportPtr listener(new TypeParam(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2000)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_message_received()->connect(
      boost::bind(&TestMessageHandler::DoOnResponseReceived, msgh_sender, _1,
      _2, _3, _4));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  auto it_connection = listener->on_message_received()->connect(
      boost::bind(&TestMessageHandler::DoOnRequestReceived, msgh_listener, _1,
      _2, _3, _4));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));

  std::string request(RandomString(23));
  sender->Send(request, Endpoint(kIP, listener->listening_port()),
               bptime::seconds(1));
  boost::uint16_t timeout = 100;
  while (msgh_sender->responses_received().size() == 0 && timeout < 1100) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    timeout +=100;
  }
  EXPECT_GE(boost::uint16_t(1000), timeout);
  ASSERT_EQ(size_t(0), msgh_sender->results().size());
  ASSERT_EQ(size_t(1), msgh_listener->requests_received().size());
  ASSERT_EQ(request, msgh_listener->requests_received().at(0).first);
  ASSERT_EQ(size_t(1), msgh_listener->responses_sent().size());
  ASSERT_EQ(size_t(1), msgh_sender->responses_received().size());
  ASSERT_EQ(msgh_listener->responses_sent().at(0),
            msgh_sender->responses_received().at(0).first);

  // Timeout scenario
  it_connection.disconnect();
  listener->on_message_received()->connect(
      boost::bind(&TestMessageHandler::DoTimeOutOnRequestReceived,
                  msgh_listener, _1, _2, _3, _4));
  request = RandomString(29);
  sender->Send(request, Endpoint(kIP, listener->listening_port()),
               bptime::milliseconds(2));
  timeout = 100;
  while ((msgh_sender->results().size() == 0) && timeout < 5000) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    timeout +=100;
  }
  ASSERT_EQ(size_t(1), msgh_sender->results().size());
  ASSERT_EQ(size_t(2), msgh_listener->requests_received().size());
  ASSERT_EQ(request, msgh_listener->requests_received().at(1).first);
  ASSERT_EQ(size_t(2), msgh_listener->responses_sent().size());
  ASSERT_EQ(size_t(1), msgh_sender->responses_received().size());
  listener->StopListening();
}


TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneSingleMessage) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToOneMultiMessage) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(20));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToManySingleMessage) {
  this->SetupTransport(false, 0);
  for (int i = 0; i < 16; ++i) {
    this->SetupTransport(true, 0);
  }
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_OneToManyMultiMessage) {
  this->SetupTransport(false, 0);
  for (int i = 0; i < 10; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(20));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_ManyToManyMultiMessage) {
  for (int i = 0; i < 5; ++i)
    this->SetupTransport(false, 0);
  for (int i = 0; i < 10; ++i)
    this->SetupTransport(true, 0);
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(10));
}

TYPED_TEST_P(TransportAPITest, BEH_TRANS_Random) {
  boost::uint8_t num_sender_transports(
      static_cast<boost::uint8_t>(RandomUint32() % 5 + 3));
  boost::uint8_t num_listener_transports(
      static_cast<boost::uint8_t>(RandomUint32() % 5 + 3));
  boost::uint8_t num_messages(
      static_cast<boost::uint8_t>(RandomUint32() % 10 + 1));
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

INSTANTIATE_TYPED_TEST_CASE_P(TCP, TransportAPITest, TcpTransport);
INSTANTIATE_TYPED_TEST_CASE_P(RUDP, TransportAPITest, RudpTransport);
INSTANTIATE_TYPED_TEST_CASE_P(UDP, TransportAPITest, UdpTransport);

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_OneToOneSingleLargeMessage) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  // Send out a message with upto 64MB = 2^26
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1, 26));
}

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_OneToOneSeqMultipleLargeMessage) {
  TransportPtr sender(new RudpTransport(*this->asio_service_));
  TransportPtr listener(new RudpTransport(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2001)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_message_received()->connect(
      boost::bind(&TestMessageHandler::DoOnResponseReceived, msgh_sender, _1,
      _2, _3, _4));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  listener->on_message_received()->connect(
      boost::bind(&TestMessageHandler::DoOnRequestReceived, msgh_listener, _1,
      _2, _3, _4));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));
  std::string request(RandomString(1));
  for (int i = 0; i < 24; ++i)
    request = request + request;

  for (int j = 0; j < 5; ++j) {
    sender->Send(request, Endpoint(kIP, listener->listening_port()),
                 bptime::seconds(24));
    while (!msgh_sender->finished_) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    }
    msgh_sender->finished_ = false;
  }

  ASSERT_EQ(size_t(0), msgh_sender->results().size());
  ASSERT_EQ(size_t(5), msgh_listener->requests_received().size());
  ASSERT_EQ(size_t(5), msgh_listener->responses_sent().size());
  ASSERT_EQ(size_t(5), msgh_sender->responses_received().size());
  ASSERT_EQ(msgh_listener->responses_sent().at(0),
            msgh_sender->responses_received().at(0).first);
}

// TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_OneToOneSimMultipleLargeMessage) {
//   this->SetupTransport(false, 0);
//   this->SetupTransport(true, 0);
//   // Send out a bunch of messages simultaneously, each one is 16MB = 2^24
//   ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(5, 24));
// }

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_DetectDroppedReceiver) {
  // Prevent the low speed detection will terminate the test earlier
  RudpParameters::kSpeedCalculateInverval = bptime::seconds(100);

  TransportPtr sender(new RudpTransport(*this->asio_service_));
  TransportPtr listener(new RudpTransport(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2000)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));

  std::string request(RandomString(1));
  for (int i = 0; i < 26; ++i)
    request = request + request;
  {
    // Detect a dropped connection while sending (receiver dropped)
    sender->Send(request, Endpoint(kIP, listener->listening_port()),
                 bptime::seconds(26));
    int waited_seconds(0);
    while ((msgh_sender->results().size() == 0) && (waited_seconds < 10)) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
      ++ waited_seconds;
      if (waited_seconds == 1)
          listener->StopListening();
    }
    EXPECT_GT(10, waited_seconds);
  }
}

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_DetectDroppedSender) {
  // Prevent the low speed detection will terminate the test earlier
  RudpParameters::kSpeedCalculateInverval = bptime::seconds(100);

  TransportPtr sender(new RudpTransport(*this->asio_service_));
  TransportPtr listener(new RudpTransport(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2000)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));

  std::string request(RandomString(1));
  for (int i = 0; i < 26; ++i)
    request = request + request;
  {
    // Detect a dropped connection while receiving (sender dropped)
    sender->Send(request, Endpoint(kIP, listener->listening_port()),
                 bptime::seconds(26));
    int waited_seconds(0);
    while ((msgh_listener->results().size() == 0) && (waited_seconds < 10)) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
      ++ waited_seconds;
      if (waited_seconds == 1)
          sender->StopListening();
    }
    EXPECT_GT(10, waited_seconds);
  }
}

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_SlowSendSpeed) {
  // Global Static Parameter set in the previous test will still valid
  // need to reset here
  RudpParameters::kSpeedCalculateInverval = bptime::seconds(1);

  TransportPtr sender(new RudpTransport(*this->asio_service_));
  TransportPtr listener(new RudpTransport(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2010)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));
  // slow send speed
  RudpParameters::kDefaultSendDelay = bptime::milliseconds(1000);
  RudpParameters::kAckInterval = bptime::milliseconds(500);
  RudpParameters::kDefaultReceiveDelay = bptime::milliseconds(100);
  RudpParameters::kDefaultWindowSize = 16;
  RudpParameters::kMaximumWindowSize = 16;
  RudpParameters::kDefaultSize = 1480;
  RudpParameters::kMaxSize = 1480;
  RudpParameters::kDefaultDataSize = 1450;
  RudpParameters::kMaxDataSize = 1450;

  // max speed limit will be 16 * 1450 * 8 / 1 = 185600 b/s
  // observed speed: first second 197200 b/s (counted one more packet),
  //                 then 69600 b/s
  RudpParameters::SlowSpeedThreshold = 200000;

  std::string request(RandomString(1));
  for (int i = 0; i < 26; ++i)
    request = request + request;
  {
    // Detect a dropped connection while sending (receiver dropped)
    sender->Send(request, Endpoint(kIP, listener->listening_port()),
                 bptime::seconds(26));
    int waited_seconds(0);
    while ((msgh_sender->results().size() == 0) && (waited_seconds < 10)) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
      ++ waited_seconds;
    }
    EXPECT_GT(3, waited_seconds);
  }
}

TEST_F(RUDPSingleTransportAPITest, BEH_TRANS_SlowReceiveSpeed) {
  // Global Static Parameter set in the previous test will still valid
  // need to reset here
  RudpParameters::kSpeedCalculateInverval = bptime::seconds(1);

  TransportPtr sender(new RudpTransport(*this->asio_service_));
  TransportPtr listener(new RudpTransport(*this->asio_service_));
  EXPECT_EQ(kSuccess, listener->StartListening(Endpoint(kIP, 2100)));
  TestMessageHandlerPtr msgh_sender(new TestMessageHandler("Sender"));
  TestMessageHandlerPtr msgh_listener(new TestMessageHandler("listener"));
  sender->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_sender, _1));
  listener->on_error()->connect(
      boost::bind(&TestMessageHandler::DoOnError, msgh_listener, _1));
  RudpParameters::kDefaultSendDelay = bptime::milliseconds(100);
  // slow receive speed
  RudpParameters::kAckInterval = bptime::milliseconds(500);
  RudpParameters::kDefaultReceiveDelay = bptime::milliseconds(100);
  RudpParameters::kDefaultWindowSize = 16;
  RudpParameters::kMaximumWindowSize = 16;
  RudpParameters::kDefaultSize = 1480;
  RudpParameters::kMaxSize = 1480;
  RudpParameters::kDefaultDataSize = 1450;
  RudpParameters::kMaxDataSize = 1450;

  // max speed limit will be 16 * 1450 * 8 / 0.5 = 371200 b/s
  // observed speed around 359600 b/s
  RudpParameters::SlowSpeedThreshold = 371200;

  std::string request(RandomString(1));
  for (int i = 0; i < 26; ++i)
    request = request + request;
  {
    // Detect a dropped connection while sending (receiver dropped)
    sender->Send(request, Endpoint(kIP, listener->listening_port()),
                 bptime::seconds(26));
    int waited_seconds(0);
    while ((msgh_listener->results().size() == 0) && (waited_seconds < 10)) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
      ++ waited_seconds;
    }
    EXPECT_GT(3, waited_seconds);
  }
}

INSTANTIATE_TEST_CASE_P(ConfigurableTraffic, RUDPConfigurableTransportAPITest,
                        testing::Range(0, 3));

TEST_P(RUDPConfigurableTransportAPITest, BEH_TRANS_ConfigurableTraffic) {
  this->SetupTransport(false, 0);
  this->SetupTransport(true, 0);
  // To save the test time, send out a message with 4MB = 2^22
  ASSERT_NO_FATAL_FAILURE(this->RunTransportTest(1, 22));
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
