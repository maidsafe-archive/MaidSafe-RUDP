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
#include "maidsafe/transport/message_handler.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

typedef boost::asio::io_service AsioService;
typedef std::shared_ptr<MessageHandler> MessageHandlerPtr;

namespace test {

class NatDetectionServicesTest : public testing::Test {
 public:
  NatDetectionServicesTest()
      : asio_service_(), 
        message_handler_(new MessageHandler()),
        service_(asio_service_, message_handler_),
        listening_transport_(new transport::RudpTransport(asio_service_)) {
  }
 protected:
  AsioService asio_service_;
  MessageHandlerPtr message_handler_;
  NatDetectionService service_;
  TransportPtr listening_transport_;
   
   
  virtual void SetUp() {}

  virtual void TearDown() {}
};



TEST_F(NatDetectionServicesTest, BEH_NatDetection) {
  listening_transport_.reset(new transport::RudpTransport(asio_service_));
  listening_transport_->on_message_received()->connect(
        transport::OnMessageReceived::element_type::slot_type(
            &MessageHandler::OnMessageReceived, message_handler_.get(),
            _1, _2, _3, _4).track_foreign(message_handler_));
   listening_transport_->on_error()->connect(
   transport::OnError::element_type::slot_type(
             &MessageHandler::OnError, message_handler_.get(),
             _1, _2).track_foreign(message_handler_));
  service_.ConnectToSignals();
  Info info;
  Endpoint endpoint("192.168.0.1", 1000);
  info.endpoint = endpoint;
  protobuf::NatDetectionRequest request;
  request.add_local_ips(std::string("192.168.0.1"));
  request.set_local_port(1000);
  request.set_full_detection(true);
  protobuf::NatDetectionResponse
      *nat_detection_response(new protobuf::NatDetectionResponse);
  protobuf::RendezvousRequest
      *rendezvous_request(new protobuf::RendezvousRequest);
  transport::Timeout* timeout = new Timeout;
  *timeout = kDefaultInitialTimeout;
  service_.NatDetection(info, request, nat_detection_response, timeout);
  EXPECT_EQ(NatType::kDirectConnected, nat_detection_response->nat_type());
  endpoint = Endpoint("150.150.150.150", 30000);
  info.endpoint = endpoint;
  delete nat_detection_response;
  nat_detection_response = new protobuf::NatDetectionResponse;
  service_.NatDetection(info, request, nat_detection_response, timeout);
  EXPECT_EQ(NatType::kFullCone, nat_detection_response->nat_type());
  delete nat_detection_response;
  delete timeout;
  delete rendezvous_request;
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe