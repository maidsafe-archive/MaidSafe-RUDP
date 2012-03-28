/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/
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
   |                     |
   |<--- Rendezvous -----|
   |      Request        |------- RV type ProxyConnectRequest ------->|
   |                                                                  |
Try to RV connect                                              Try to RV connect
(no message) ------------------------> <------------------------ (no message)
Succeeds                                                           Succeeds
   |                                                                  |
   |<---------------------- NatDetectionResponse ---------------------|
   |
   |

*/
/*
#include "maidsafe/common/test.h"
#include "maidsafe/transport/udt_transport.h"

namespace maidsafe {

namespace transport {

namespace test {

class NatTraversalTest : public testing::Test {
 public:
  NatTraversalTest()
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
    (*PublicRoutingTable::GetInstance())
        [boost::lexical_cast<std::string>(bootstrap_port)]->AddContact(
            Contact());

    // Pass boostrapping node's details into joining node
    joining_transport_.nat_detection_nodes_.assign(1,
        NatDetectionNode("127.0.0.1", bootstrap_port));
  }
  UdtTransport joining_transport_, bootstrap_transport_;
  UdtTransport rendezvous_transport1_, rendezvous_transport2_;
};

NatTraversalTest, BEH_UDT_DirectlyConnected) {
  UdtTransport udt_transport;
  udt_transport.DoNatDetection();
  EXPECT_EQ(kNotConnected, udt_transport.nat_details_.nat_type);
  TransportCondition result(kError);
  Port joining_port = joining_transport_.StartListening("", 0, &result);
  ASSERT_EQ(kSuccess, result);
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
*/
