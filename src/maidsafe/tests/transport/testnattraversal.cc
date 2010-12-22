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

Sequence for directly-connected joining node
============================================
 Node A                Node B
(Joining)            (Bootstrap)
   |
   |--- NatDetection --->|
   |      Request        |
   |                     |
   |<-- NatDetection ----|
   |      Response
   |


Sequence for joining node behind full cone router
=================================================
 Node A                Node B                Node C
(Joining)            (Bootstrap)       (Directly-connected
   |                                       rendezvous)
   |--- NatDetection --->|
   |      Request        |
   |                     |
   |                     |---- ProxyConnect --->|
   |                     |        Request       |
   |                     |                      |
   |                     |                Try to connect
   |<------------------------------------- (no message)
   |                     |                   Succeeds
   |                     |                      |
   |                     |<--- ProxyConnect ----|
   |                     |       Response
   |<-- NatDetection ----|
   |      Response
   |


Sequence for joining node behind port restricted router
=======================================================
 Node A                Node B                Node C                Node D
(Joining)            (Bootstrap)       (Directly-connected   (Directly-connected
   |                                       rendezvous)           rendezvous)
   |--- NatDetection --->|
   |      Request        |
   |                     |     Non-RV type
   |                     |---- ProxyConnect --->|
   |                     |       Request        |
   |                     |                      |
   |                     |                Try to connect
   |<------------------------------------- (no message)
   |                     |                    Fails
   |                     |                      |
   |                     |<--- ProxyConnect ----|
   |                     |       Response
   |<--- Rendezvous -----|
   |      Request        |
   |                     |
   |---- Rendezvous ---->|(on port to be used for RV connect; not listning port)
   |  Response (on diff- |
   |  erent connection)  |------- RV type ProxyConnectRequest ------->|
   |                                                                  |
Try to RV connect                                              Try to RV connect
(no message) ------------------------> <------------------------ (no message)
Succeeds                                                           Succeeds
   |                                                                  |
   |<---------------------- NatDetectionResponse ---------------------|
   |
   |

*/

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "maidsafe/transport/udttransport.h"

namespace transport {
namespace test {

class TestNatTraversal : public testing::Test {
 public:
  TestNatTraversal()
      : joining_transport_(),
        bootstrap_transport_(),
        rendezvous_transport1_(),
        rendezvous_transport2_() {}
 protected:
  void SetUp() {
    // Start rendezvous nodes
    TransportCondition result(kError);
    Port rv_port1 = rendezvous_transport1_.StartListening("127.0.0.1", 0,
                                                          &result);
    ASSERT_EQ(kSuccess, result);
    result = kError;
    Port rv_port2 = rendezvous_transport2_.StartListening("127.0.0.1", 0,
                                                          &result);
    ASSERT_EQ(kSuccess, result);
    // Start bootstrap node and add rendezvous nodes as contacts
    result = kError;
    Port bootstrap_port = bootstrap_transport_.StartListening("127.0.0.1", 0,
                                                              &result);
    ASSERT_EQ(kSuccess, result);
    (*base::PublicRoutingTable::GetInstance())
        [boost::lexical_cast<std::string>(bootstrap_port)]->AddContact(
            Contact());

    // Pass boostrapping node's details into joining node
    joining_transport_.nat_detection_nodes_.assign(1,
        NatDetectionNode("127.0.0.1", bootstrap_port));
  }
  UdtTransport joining_transport_, bootstrap_transport_;
  UdtTransport rendezvous_transport1_, rendezvous_transport2_;
};

TEST_F(TestNatTraversal, BEH_UDT_DirectlyConnected) {
  UdtTransport udt_transport;
  udt_transport.DoNatDetection();
  EXPECT_EQ(kNotConnected, udt_transport.nat_details_.nat_type);
  TransportCondition result(kError);
  Port joining_port = joining_transport_.StartListening("", 0, &result);
  ASSERT_EQ(kSuccess, result);
}

}  // namespace test
}  // namespace transport
