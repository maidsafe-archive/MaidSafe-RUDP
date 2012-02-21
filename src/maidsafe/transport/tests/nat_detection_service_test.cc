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
#include "maidsafe/common/asio_service.h"

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/nat_detection_service.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/transport/transport_pb.h"
#include "maidsafe/transport/nat_detection.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace transport {
namespace test {

class MockNatDetectionServiceTest;

class Node {
 public:
  Node() : asio_service_(),
           endpoint_(IP::from_string("127.0.0.1"), 0),
           live_contact_(IP::from_string("127.0.0.1"), 0),
           transport_(new transport::RudpTransport(asio_service_.service())),
           message_handler_(new RudpMessageHandler(nullptr)) {
    asio_service_.Start(5);
  }

  ~Node() {
    transport_->StopListening();
    transport_.reset();
    asio_service_.Stop();
  }

  bool StartListening() {
    TransportCondition condition(kError);
    size_t max(5), attempt(0);
    while (attempt++ < max && (condition != kSuccess)) {
      endpoint_.port = RandomUint32() % 50000 + 1025;
      condition = transport_->StartListening(endpoint_);
    }
    return (condition == kSuccess);
  }

  Endpoint endpoint() const { return endpoint_; }
  Endpoint live_contact() const { return live_contact_; }
  std::shared_ptr<RudpTransport> transport() const { return transport_; }
  MessageHandlerPtr message_handler() const { return message_handler_; }
  boost::asio::io_service& io_service() { return asio_service_.service(); }

  void set_live_contact(Endpoint live_contact) { live_contact_ = live_contact; }

 private:
  AsioService asio_service_;
  Endpoint endpoint_, live_contact_;
  std::shared_ptr<RudpTransport> transport_;
  MessageHandlerPtr message_handler_;
};

typedef std::shared_ptr<Node> NodePtr;

class MockNatDetectionService : public NatDetectionService {
 public:
  MockNatDetectionService(boost::asio::io_service &io_service,  // NOLINT
                          RudpMessageHandlerPtr message_handler,
                          RudpTransportPtr listening_transport,
                          GetEndpointFunctor get_endpoint_functor)
      : NatDetectionService(io_service, message_handler,
                            listening_transport, get_endpoint_functor) {}
  MOCK_METHOD2(DirectlyConnected,
               bool(const protobuf::NatDetectionRequest &request,  // NOLINT (Fraser)
                    const Endpoint &endpoint));
  MOCK_METHOD4(ConnectResult, void(const int &in_result,
                                   int *out_result,
                                   boost::mutex *mutex,
                                   boost::condition_variable* condition));

  bool NotDirectlyConnected() {
    return false;
  }

  void ConnectResultFail(int *out_result,
                         boost::mutex *mutex,
                         boost::condition_variable* condition) {
    boost::mutex::scoped_lock lock(*mutex);
    *out_result = kError;
    condition->notify_one();
  }
};

class MockNatDetectionServiceTest : public testing::Test {
 public:
  MockNatDetectionServiceTest()
      :  origin_(new Node),
         proxy_(new Node),
         rendezvous_(new Node) {}
  void ConnectToSignals(TransportPtr transport,
                        RudpMessageHandlerPtr message_handler) {
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
  NodePtr origin_, proxy_, rendezvous_;
};

TEST_F(MockNatDetectionServiceTest, BEH_FullConeDetection) {
  NatDetection nat_detection;
  std::shared_ptr<MockNatDetectionService> origin_service, rendezvous_service,
       proxy_service;
  std::vector<Contact> contacts;
  std::vector<Endpoint> endpoints;
  bool listens = origin_->StartListening();
  EXPECT_TRUE(listens);
  origin_->transport()->transport_details_.local_endpoints.push_back(
      origin_->endpoint());
  ConnectToSignals(origin_->transport(), origin_->message_handler());
  listens = rendezvous_->StartListening();
  EXPECT_TRUE(listens);
  origin_->set_live_contact(rendezvous_->endpoint());
  ConnectToSignals(rendezvous_->transport(), rendezvous_->message_handler());
  listens =  proxy_->StartListening();
  EXPECT_TRUE(listens);
  rendezvous_->set_live_contact(proxy_->endpoint());
  ConnectToSignals(proxy_->transport(), proxy_->message_handler());
  origin_service.reset(
      new MockNatDetectionService(origin_->io_service(),
                                  origin_->message_handler(),
                                  origin_->transport(),
                                  std::bind(&Node::live_contact, origin_)));
  origin_service->ConnectToSignals();
  rendezvous_service.reset(
      new MockNatDetectionService(rendezvous_->io_service(),
                                  rendezvous_->message_handler(),
                                  rendezvous_->transport(),
                                  std::bind(&Node::live_contact, rendezvous_)));
  rendezvous_service->ConnectToSignals();
  EXPECT_CALL(*rendezvous_service, DirectlyConnected(testing::_, testing::_))
      .WillOnce((testing::Invoke(
          std::bind(&MockNatDetectionService::NotDirectlyConnected,
          rendezvous_service.get()))));
  proxy_service.reset(
      new MockNatDetectionService(proxy_->io_service(),
                                  proxy_->message_handler(),
                                  proxy_->transport(),
                                  std::bind(&Node::live_contact, proxy_)));
  proxy_service->ConnectToSignals();
  NatType nattype;
  Endpoint rendezvous_endpoint;
  endpoints.push_back(rendezvous_->endpoint());
  Contact rendezvous_contact(rendezvous_->endpoint(), endpoints,
                             Endpoint(), true, true);
  contacts.push_back(rendezvous_contact);
  nat_detection.Detect(contacts, true, origin_->transport(),
                       origin_->message_handler(), &nattype,
                       &rendezvous_endpoint);
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
  origin_->transport()->transport_details_.local_endpoints.push_back(
      origin_->endpoint());
  ConnectToSignals(origin_->transport(), origin_->message_handler());
  listens = rendezvous_->StartListening();
  EXPECT_TRUE(listens);
  origin_->set_live_contact(rendezvous_->endpoint());
  ConnectToSignals(rendezvous_->transport(), rendezvous_->message_handler());
  listens =  proxy_->StartListening();
  EXPECT_TRUE(listens);
  rendezvous_->set_live_contact(proxy_->endpoint());
  ConnectToSignals(proxy_->transport(), proxy_->message_handler());
  origin_service.reset(
      new MockNatDetectionService(origin_->io_service(),
                                  origin_->message_handler(),
                                  origin_->transport(),
                                  std::bind(&Node::live_contact, origin_)));
  origin_service->ConnectToSignals();
  rendezvous_service.reset(
      new MockNatDetectionService(rendezvous_->io_service(),
                                  rendezvous_->message_handler(),
                                  rendezvous_->transport(),
                                  std::bind(&Node::live_contact, rendezvous_)));
  rendezvous_service->ConnectToSignals();
  EXPECT_CALL(*rendezvous_service, DirectlyConnected(testing::_, testing::_))
      .WillOnce((testing::Invoke(
          std::bind(&MockNatDetectionService::NotDirectlyConnected,
          rendezvous_service.get()))));
  proxy_service.reset(
      new MockNatDetectionService(proxy_->io_service(),
                                  proxy_->message_handler(),
                                  proxy_->transport(),
                                  std::bind(&Node::live_contact, proxy_)));
  proxy_service->ConnectToSignals();
  EXPECT_CALL(*proxy_service, ConnectResult(testing::_, testing::_,
                                            testing::_, testing::_))
       .WillOnce(testing::WithArgs<1, 2, 3>(testing::Invoke(
           std::bind(&MockNatDetectionService::ConnectResultFail,
           proxy_service.get(), args::_1, args::_2, args::_3))));
  NatType nattype;
  Endpoint rendezvous_endpoint;
  endpoints.push_back(rendezvous_->endpoint());
  Contact rendezvous_contact(rendezvous_->endpoint(), endpoints,
                             Endpoint(), true, true);
  contacts.push_back(rendezvous_contact);
  nat_detection.Detect(contacts, true, origin_->transport(),
                       origin_->message_handler(), &nattype,
                       &rendezvous_endpoint);
  EXPECT_EQ(nattype, kPortRestricted);
}

class NatDetectionServicesTest : public testing::Test {
 public:
  NatDetectionServicesTest()
      : asio_service_(),
        message_handler_(),
        service_(),
        listening_transport_() {}

  virtual void SetUp() {
    asio_service_.Start(5);
    message_handler_.reset(new RudpMessageHandler(nullptr));
    listening_transport_.reset(
        new transport::RudpTransport(asio_service_.service()));
    Endpoint endpoint(IP::from_string("127.0.0.1"), 9999);
    listening_transport_->StartListening(endpoint);
    GetEndpointFunctor get_directly_connected_endpoint =
      std::bind(&NatDetectionServicesTest::GetDirectlyConnectedEndpoint, this);
    service_.reset(new NatDetectionService(asio_service_.service(),
                   message_handler_, listening_transport_,
                   get_directly_connected_endpoint));
  }

  virtual void TearDown() {}

  ~NatDetectionServicesTest() {
    asio_service_.Stop();
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
  RudpMessageHandlerPtr message_handler_;
  std::shared_ptr<NatDetectionService> service_;
  RudpTransportPtr listening_transport_;
};

TEST_F(NatDetectionServicesTest, BEH_NatDetection) {
  listening_transport_.reset(
      new transport::RudpTransport(asio_service_.service()));
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
