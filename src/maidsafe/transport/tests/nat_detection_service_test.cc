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

#include "boost/thread.hpp"
#include "boost/thread/detail/thread_group.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/transport/nat_detection_service.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/common/log.h"
#include "maidsafe/transport/transport_pb.h"
#include "maidsafe/transport/nat_detection.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace transport {
namespace test {

typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
class MockNatDetectionServiceTest;

struct Node {
  Node() : asio_service(),
           work(new boost::asio::io_service::work(asio_service)),
           endpoint(IP::from_string("127.0.0.1"), 0),
           transport(new transport::RudpTransport(asio_service)),
           message_handler(new RudpMessageHandler(nullptr)) {
    for (size_t k = 0; k < 5; ++k) {
      thread_group.create_thread(
          std::bind(static_cast<size_t(boost::asio::io_service::*)()>(
              &boost::asio::io_service::run), std::ref(asio_service)));
    }
  }

  ~Node() {
    transport->StopListening();
    work.reset();
    asio_service.stop();
    thread_group.join_all();
  }

  AsioService asio_service;
  WorkPtr work;
  Endpoint endpoint;
  Endpoint live_contact;
  std::shared_ptr<RudpTransport> transport;
  MessageHandlerPtr message_handler;
  boost::thread_group thread_group;
  //   std::shared_ptr<MockNatDetectionService> service;
  bool StartListening() {
    TransportCondition condition(kError);
    size_t max(5), attempt(0);
    while (attempt++ < max && (condition != kSuccess)) {
      endpoint.port = RandomUint32() % 50000 + 1025;
      condition = transport->StartListening(endpoint);
    }
    return (condition == kSuccess);
  }

  Endpoint GetEndpoint() const {
    return endpoint;
  }

  void SetLiveContact(const Endpoint &endpoint) {
    live_contact = endpoint;
  }

  Endpoint GetLiveContact() const {
    return live_contact;
  }
};

typedef std::shared_ptr<Node> NodePtr;

class MockNatDetectionService : public NatDetectionService {
 public:
  MockNatDetectionService(AsioService &asio_service, // NOLINT
                           MessageHandlerPtr message_handler,
                           TransportPtr listening_transport,
                           GetEndpointFunctor get_endpoint_functor)
      : NatDetectionService(asio_service, message_handler,
                            listening_transport, get_endpoint_functor) {}
  MOCK_METHOD2(DirectlyConnected, bool(
      const protobuf::NatDetectionRequest &request, const Endpoint &endpoint));
  MOCK_METHOD4(ConnectResult, void(const int &in_result,
      int *out_result, const bool &notify_result,
      boost::condition_variable* condition));

  bool NotDirectlyConnected() {
    return false;
  }

  void ConnectResultFail(int *out_result,
                         const bool &notify_result,
                         boost::condition_variable* condition) {
    *out_result = kError;
    if (notify_result)
      condition->notify_one();
  }
};

class MockNatDetectionServiceTest : public testing::Test {
 public:
  MockNatDetectionServiceTest()
      :  origin_(new Node()),
         proxy_(new Node()),
         rendezvous_(new Node()) {}
  void ConnectToSignals(TransportPtr transport,
                        MessageHandlerPtr message_handler) {
    transport->on_message_received()->connect(
          transport::OnMessageReceived::element_type::slot_type(
              &RudpMessageHandler::OnMessageReceived, message_handler.get(),
              _1, _2, _3, _4).track_foreign(message_handler));
    transport->on_error()->connect(
        transport::OnError::element_type::slot_type(
            &RudpMessageHandler::OnError,
            message_handler.get(), _1, _2).track_foreign(message_handler));
  }
  ~MockNatDetectionServiceTest() {
    proxy_.reset();
    rendezvous_.reset();
    origin_.reset();
  }

 protected:
  NodePtr origin_;
  NodePtr proxy_;
  NodePtr rendezvous_;
};

TEST_F(MockNatDetectionServiceTest, BEH_FullConeDetection) {
  NatDetection nat_detection;
  std::shared_ptr<MockNatDetectionService> origin_service, rendezvous_service,
       proxy_service;
  std::vector<Contact> contacts;
  std::vector<Endpoint> endpoints;
  bool listens = origin_->StartListening();
  EXPECT_TRUE(listens);
  origin_->transport->transport_details_.local_endpoints.push_back(
      origin_->endpoint);
  ConnectToSignals(origin_->transport, origin_->message_handler);
  listens = rendezvous_->StartListening();
  EXPECT_TRUE(listens);
  origin_->SetLiveContact(rendezvous_->GetEndpoint());
  ConnectToSignals(rendezvous_->transport, rendezvous_->message_handler);
  listens =  proxy_->StartListening();
  EXPECT_TRUE(listens);
  rendezvous_->SetLiveContact(proxy_->GetEndpoint());
  ConnectToSignals(proxy_->transport, proxy_->message_handler);
  origin_service.reset(new MockNatDetectionService(origin_->asio_service,
      origin_->message_handler, origin_->transport,
      std::bind(&Node::GetLiveContact, origin_)));
  origin_service->ConnectToSignals();
  rendezvous_service.reset(
      new MockNatDetectionService(rendezvous_->asio_service,
          rendezvous_->message_handler, rendezvous_->transport,
          std::bind(&Node::GetLiveContact, rendezvous_)));
  rendezvous_service->ConnectToSignals();
  EXPECT_CALL(*rendezvous_service, DirectlyConnected(testing::_, testing::_))
      .WillOnce((testing::Invoke(
          std::bind(&MockNatDetectionService::NotDirectlyConnected,
          rendezvous_service.get()))));
  proxy_service.reset(new MockNatDetectionService(proxy_->asio_service,
    proxy_->message_handler, proxy_->transport,
    std::bind(&Node::GetLiveContact, proxy_)));
  proxy_service->ConnectToSignals();
  NatType nattype;
  Endpoint rendezvous_endpoint;
  endpoints.push_back(rendezvous_->endpoint);
  Contact rendezvous_contact(rendezvous_->endpoint, endpoints,
                             Endpoint(), true, true);
  contacts.push_back(rendezvous_contact);
  nat_detection.Detect(contacts, true, origin_->transport,
    origin_->message_handler, &nattype, &rendezvous_endpoint);
  EXPECT_EQ(nattype, kFullCone);
}

TEST_F(MockNatDetectionServiceTest, BEH_PortRestrictedDetection) {
  NatDetection nat_detection;
  std::shared_ptr<MockNatDetectionService> origin_service, rendezvous_service,
       proxy_service;
  std::vector<Contact> contacts;
  std::vector<Endpoint> endpoints;
  bool listens = origin_->StartListening();
  EXPECT_TRUE(listens);
  origin_->transport->transport_details_.local_endpoints.push_back(
      origin_->endpoint);
  ConnectToSignals(origin_->transport, origin_->message_handler);
  listens = rendezvous_->StartListening();
  EXPECT_TRUE(listens);
  origin_->SetLiveContact(rendezvous_->GetEndpoint());
  ConnectToSignals(rendezvous_->transport, rendezvous_->message_handler);
  listens =  proxy_->StartListening();
  EXPECT_TRUE(listens);
  rendezvous_->SetLiveContact(proxy_->GetEndpoint());
  ConnectToSignals(proxy_->transport, proxy_->message_handler);
  origin_service.reset(new MockNatDetectionService(origin_->asio_service,
      origin_->message_handler, origin_->transport,
      std::bind(&Node::GetLiveContact, origin_)));
  origin_service->ConnectToSignals();
  rendezvous_service.reset(
      new MockNatDetectionService(rendezvous_->asio_service,
          rendezvous_->message_handler, rendezvous_->transport,
          std::bind(&Node::GetLiveContact, rendezvous_)));
  rendezvous_service->ConnectToSignals();
  EXPECT_CALL(*rendezvous_service, DirectlyConnected(testing::_, testing::_))
      .WillOnce((testing::Invoke(
          std::bind(&MockNatDetectionService::NotDirectlyConnected,
          rendezvous_service.get()))));
  proxy_service.reset(new MockNatDetectionService(proxy_->asio_service,
    proxy_->message_handler, proxy_->transport,
    std::bind(&Node::GetLiveContact, proxy_)));
  proxy_service->ConnectToSignals();
  EXPECT_CALL(*proxy_service, ConnectResult(testing::_, testing::_,
                                            testing::_, testing::_))
       .WillOnce(testing::WithArgs<1, 2, 3>(testing::Invoke(
           std::bind(&MockNatDetectionService::ConnectResultFail,
           proxy_service.get(), args::_1, args::_2, args::_3))));
  NatType nattype;
  Endpoint rendezvous_endpoint;
  endpoints.push_back(rendezvous_->endpoint);
  Contact rendezvous_contact(rendezvous_->endpoint, endpoints,
                             Endpoint(), true, true);
  contacts.push_back(rendezvous_contact);
  nat_detection.Detect(contacts, true, origin_->transport,
    origin_->message_handler, &nattype, &rendezvous_endpoint);
  EXPECT_EQ(nattype, kPortRestricted);
}

class NatDetectionServicesTest : public testing::Test {
 public:
  NatDetectionServicesTest()
      : asio_service_(),
        work_(),
        message_handler_(),
        service_(),
        listening_transport_() {
  }

  virtual void SetUp() {
    work_.reset(new boost::asio::io_service::work(asio_service_));
    message_handler_.reset(new RudpMessageHandler(nullptr));
    listening_transport_.reset(new transport::RudpTransport(asio_service_));
    Endpoint endpoint(IP::from_string("127.0.0.1"), 9999);
    listening_transport_->StartListening(endpoint);
    GetEndpointFunctor get_directly_connected_endpoint =
      std::bind(&NatDetectionServicesTest::GetDirectlyConnectedEndpoint, this);
    service_.reset(new NatDetectionService(asio_service_, message_handler_,
                   listening_transport_, get_directly_connected_endpoint));
  }

  virtual void TearDown() {}

  ~NatDetectionServicesTest() {
    work_.reset();
    asio_service_.stop();
  }

  Endpoint GetDirectlyConnectedEndpoint() {
    return Endpoint("151.151.151.151", 40000);
    /*AsioService asio_service;
    TransportPtr t(new transport::RudpTransport(asio_service));
    transport = t;
    transport->StartListening(*endpoint);*/
  }

 protected:
  AsioService asio_service_;
  WorkPtr work_;
  MessageHandlerPtr message_handler_;
  std::shared_ptr<NatDetectionService> service_;
  TransportPtr listening_transport_;
};

TEST_F(NatDetectionServicesTest, BEH_NatDetection) {
  listening_transport_.reset(new transport::RudpTransport(asio_service_));
  listening_transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler_.get(),
            _1, _2, _3, _4).track_foreign(message_handler_));
  listening_transport_->on_error()->connect(
  transport::OnError::element_type::slot_type(&MessageHandler::OnError,
      message_handler_.get(), _1, _2).track_foreign(message_handler_));
  service_->ConnectToSignals();
  Info info;
  Endpoint endpoint("192.168.0.1", 1000);
  info.endpoint = endpoint;
  protobuf::NatDetectionRequest request;
  request.add_local_ips(std::string("192.168.0.1"));
  request.set_local_port(1000);
  request.set_full_detection(true);
  protobuf::NatDetectionResponse
      *nat_detection_response(new protobuf::NatDetectionResponse);
  transport::Timeout* timeout = new Timeout;
  *timeout = kDefaultInitialTimeout;
  service_->NatDetection(info, request, nat_detection_response, timeout);
  EXPECT_EQ(kDirectConnected, nat_detection_response->nat_type());
  endpoint = Endpoint("150.150.150.150", 30000);
  info.endpoint = endpoint;
  delete nat_detection_response;
  nat_detection_response = new protobuf::NatDetectionResponse;
//  service_->NatDetection(info, request, nat_detection_response, timeout);
//  EXPECT_EQ(kFullCone, nat_detection_response->nat_type());
//  delete nat_detection_response;
//  delete timeout;
//  delete rendezvous_request;
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
