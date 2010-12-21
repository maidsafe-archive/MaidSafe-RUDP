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
/*
#include <gtest/gtest.h>
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/transport/udtconnection.h"


namespace transport {

namespace test {

class TestMessageHandler {
 public:
  explicit TestMessageHandler(int i) : this_id_(i) {}
  void DoOnError(const TransportCondition &tc) {
    printf("%i - Error: %i\n", this_id_, tc);
  }
  void DoOnRequestReceived(const std::string &request,
                           const Info &info,
                           std::string *response,
                           Timeout *timeout) {
    *response = "Replied to " + request;
    *timeout = Timeout(10000);
    printf("%i - Received request: %s.  Responding with \"%s\"\n", this_id_,
           request.c_str(), response->c_str());
  }
  void DoOnResponseReceived(const std::string &request,
                            const Info &info,
                            std::string *response,
                            Timeout *timeout) {
    response->clear();
    *timeout = kImmediateTimeout;
    printf("%i - Received response: %s.\n", this_id_, request.c_str());
  }
 private:
  int this_id_;
};

class UdtConnectionTest: public testing::Test {
 protected:
  UdtConnectionTest() : asio_service_(new boost::asio::io_service),
                        listening_node_(asio_service_),
                        listening_endpoint_(),
                        message_handler_(1) {}
  void SetUp() {
    listening_endpoint_.ip.from_string("127.0.0.1");
    listening_endpoint_.port = 9000;
    ASSERT_EQ(kSuccess, listening_node_.StartListening(listening_endpoint_));
  }
  boost::shared_ptr<boost::asio::io_service> asio_service_;
  UdtTransport listening_node_;
  Endpoint listening_endpoint_;
  TestMessageHandler message_handler_;
};

TEST_F(UdtConnectionTest, BEH_TRANS_UdtConnConstructors) {
  // Bad remote IP
  UdtConnection udt_connection1("Rubbish", 5001, "127.0.0.1", 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection1.udt_socket_id());
  // Bad remote Port
  UdtConnection udt_connection2("127.0.0.1", 5000, "127.0.0.1", 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection2.udt_socket_id());
  // Bad rendezvous IP
  UdtConnection udt_connection3("127.0.0.1", 5001, "Rubbish", 5001);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection3.udt_socket_id());
  // Bad rendezvous Port
  UdtConnection udt_connection4("127.0.0.1", 5001, "127.0.0.1", 5000);
  EXPECT_EQ(UDT::INVALID_SOCK, udt_connection4.udt_socket_id());

  // All good - no rendezvous
  UdtConnection udt_connection5("127.0.0.1", -1, "", 0);
  EXPECT_NE(UDT::INVALID_SOCK, udt_connection5.udt_socket_id());
  EXPECT_GT(udt_connection5.udt_socket_id(), 0);
  // All good - no rendezvous
  UdtConnection udt_connection6("127.0.0.1", -1, "", 1);
  EXPECT_NE(UDT::INVALID_SOCK, udt_connection6.udt_socket_id());
  EXPECT_GT(udt_connection6.udt_socket_id(), 0);

}

}  // namespace test

}  // namespace transport
*/
