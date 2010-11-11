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
#include "maidsafe/tests/transport/messagehandler.h"
#include "maidsafe/transport/udttransport.h"
#include "maidsafe/transport/udtconnection.h"


namespace transport {

namespace test {

class UdtConnectionTest: public testing::Test {
 protected:
  UdtConnectionTest() : listening_node_(),
                        message_handler_(listening_node_.signals(), "A", false),
                        listening_port_(0) {}
  void SetUp() {
    listening_port_ = listening_node_.StartListening("", 0, NULL);
    ASSERT_TRUE(ValidPort(listening_port_));
  }
  UdtTransport listening_node_;
  MessageHandler message_handler_;
  Port listening_port_;
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
