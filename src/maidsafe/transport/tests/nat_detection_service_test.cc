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

#include "maidsafe/transport/nat_detection_service.h"

#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/rudp_message_handler.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#include <maidsafe/transport/nat_detection.h>
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {
namespace test {

namespace {
class MockNatDetectionServices : public NatDetectionService {
 public:
  MockNatDetectionServices(AsioService &asio_service, // NOLINT
                           MessageHandlerPtr message_handler,
                           TransportPtr listening_transport,
                           GetEndpointFunctor get_endpoint_functor);
 // At rendezvous
  virtual void NatDetection(const Info &info,
                    const protobuf::NatDetectionRequest &request,
                    protobuf::NatDetectionResponse *nat_detection_response,
                    transport::Timeout *timeout);  
};

} // unnamed namespace

class MockNatDetectionServicesTest : public testing::Test {

 protected:
  AsioService asio_service_;  
};

TEST_F(MockNatDetectionServicesTest, BEH_FullConeDetection) {
  NatDetection nat_detection;
  std::shared_ptr<RudpTransport> origin_transport, rendezvous_transport,
      proxy_transport;
  MessageHandlerPtr origin_msg_handler, rendezvous_msg_handler,
      proxy_msg_handler;
  std::shared_ptr<MockNatDetectionServices> origin_service, rendezvous_service,
      proxy_service;
  std::vector<Contact> contacts;
  Endpoint origin_endpoint(IP::from_string("127.0.0.1"), 20005),
           rendezvous_endpoint(IP::from_string("127.0.0.1"), 20006),
           proxy_endpoint(IP::from_string("127.0.0.1"), 20007);
  std::vector<Endpoint> endpoints;
  Endpoint endpoint;
  Contact origin_contact(origin_endpoint, endpoints, endpoint, false, false);
  origin_transport.reset(new transport::RudpTransport(asio_service_));
  origin_transport->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, origin_msg_handler.get(),
            _1, _2, _3, _4).track_foreign(origin_msg_handler));
  origin_transport->on_error()->connect(
  transport::OnError::element_type::slot_type(&MessageHandler::OnError,
      origin_msg_handler.get(), _1, _2).track_foreign(origin_msg_handler));
  rendezvous_transport.reset(new transport::RudpTransport(asio_service_));
  rendezvous_transport->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, rendezvous_msg_handler.get(),
            _1, _2, _3, _4).track_foreign(rendezvous_msg_handler));
  rendezvous_transport->on_error()->connect(
  transport::OnError::element_type::slot_type(&MessageHandler::OnError,
      rendezvous_msg_handler.get(), _1, _2).track_foreign(rendezvous_msg_handler));
  proxy_transport.reset(new transport::RudpTransport(asio_service_));
  proxy_transport->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, proxy_msg_handler.get(),
            _1, _2, _3, _4).track_foreign(proxy_msg_handler));
  proxy_transport->on_error()->connect(
  transport::OnError::element_type::slot_type(&MessageHandler::OnError,
      proxy_msg_handler.get(), _1, _2).track_foreign(proxy_msg_handler));
//   origin_service.reset(new MockNatDetectionServices(asio_service_,
//       origin_msg_handler, origin_transport));
//   rendezvous_service.reset(new MockNatDetectionServices(asio_service_,
//       rendezvous_msg_handler, rendezvous_transport));
//   proxy_service.reset(new MockNatDetectionServices(asio_service_, 
//     proxy_msg_handler, proxy_transport));
//   nat_detection.Detect();
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
    message_handler_.reset(new RudpMessageHandler());
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
  typedef std::shared_ptr<boost::asio::io_service::work> WorkPtr;
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
