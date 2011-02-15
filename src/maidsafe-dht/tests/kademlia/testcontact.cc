/* Copyright (c) 2009 maidsafe.net limited
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

#include "gtest/gtest.h"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/kademlia.pb.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/transport/utils.h"

namespace maidsafe {

namespace kademlia {

namespace test {

class TestContact : public testing::Test {
 public:
  TestContact()
      : kNodeId_(NodeId::kRandomId),
        kIp_(IP::from_string("192.168.1.55")),
        kRvIp_(IP::from_string("192.168.1.56")),
        kLocalIp1_(IP::from_string("192.168.1.57")),
        kLocalIp2_(IP::from_string("192.168.1.58")),
        kPort_(1111),
        kRvPort_(2222),
        kLocalPort_(3333),
        kEndpoint_(kIp_, kPort_),
        kRvEndpoint_(kRvIp_, kRvPort_),
        locals_(),
        direct_connected_locals_(),
        contact_(),
        rv_contact_(),
        direct_connected_contact_() {
    locals_.push_back(transport::Endpoint(kLocalIp1_, kLocalPort_));
    locals_.push_back(transport::Endpoint(kLocalIp2_, kLocalPort_));
    direct_connected_locals_.push_back(
        transport::Endpoint(kLocalIp1_, kLocalPort_));
    direct_connected_locals_.push_back(transport::Endpoint(kIp_, kLocalPort_));
    contact_ = Contact(kNodeId_, kEndpoint_, locals_, transport::Endpoint(),
                       false, false);
    rv_contact_ = Contact(kNodeId_, kEndpoint_, locals_, kRvEndpoint_, false,
                          false);
    direct_connected_contact_ = Contact(kNodeId_, kEndpoint_,
        direct_connected_locals_, transport::Endpoint(), false, true);
  }
  ~TestContact() {}
 protected:
  const NodeId kNodeId_;
  const IP kIp_, kRvIp_, kLocalIp1_, kLocalIp2_;
  const Port kPort_, kRvPort_, kLocalPort_;
  const transport::Endpoint kEndpoint_, kRvEndpoint_;
  std::vector<transport::Endpoint> locals_, direct_connected_locals_;
  Contact contact_, rv_contact_, direct_connected_contact_;
};

testing::AssertionResult ContactDetails(const Contact &contact,
                                        const NodeId &node_id,
                                        const IP &ip,
                                        const Port &port,
                                        const IP &local_ip1,
                                        const Port &local_port1,
                                        const IP &local_ip2,
                                        const Port &local_port2,
                                        const IP &rendezvous_ip,
                                        const Port &rendezvous_port,
                                        const IP &tcp443_ip,
                                        const Port &tcp443_port,
                                        const IP &tcp80_ip,
                                        const Port &tcp80_port) {
  if (contact.local_endpoints().size() > 2)
    return testing::AssertionFailure() << "Local endpoint count error.";

  if (node_id != contact.node_id())
    return testing::AssertionFailure() << "Node ID mismatch.";
  if (ip != contact.endpoint().ip)
    return testing::AssertionFailure() << "IP mismatch.";
  if (port != contact.endpoint().port)
    return testing::AssertionFailure() << "Port mismatch.";
  if (contact.local_endpoints().size() > 0) {
    if (local_ip1 != contact.local_endpoints().at(0).ip)
      return testing::AssertionFailure() << "Local IP 1 mismatch 1.";
    if (local_port1 != contact.local_endpoints().at(0).port)
      return testing::AssertionFailure() << "Local Port 1 mismatch 1.";
  } else {
    if (local_ip1 != IP())
      return testing::AssertionFailure() << "Local IP 1 mismatch 2.";
    if (local_port1 != 0)
      return testing::AssertionFailure() << "Local Port 1 mismatch 2.";
  }
  if (contact.local_endpoints().size() > 1) {
    if (local_ip2 != contact.local_endpoints().at(1).ip)
      return testing::AssertionFailure() << "Local IP 2 mismatch 1.";
    if (local_port2 != contact.local_endpoints().at(1).port)
      return testing::AssertionFailure() << "Local Port 2 mismatch 1.";
  } else {
    if (local_ip2 != IP())
      return testing::AssertionFailure() << "Local IP 2 mismatch 2.";
    if (local_port2 != 0)
      return testing::AssertionFailure() << "Local Port 2 mismatch 2.";
  }
  if (rendezvous_ip != contact.rendezvous_endpoint().ip)
    return testing::AssertionFailure() << "Rendezvous IP mismatch.";
  if (rendezvous_port != contact.rendezvous_endpoint().port)
    return testing::AssertionFailure() << "Rendezvous Port mismatch.";
  if (tcp443_ip != contact.tcp443endpoint().ip)
    return testing::AssertionFailure() << "TCP 443 IP mismatch.";
  if (tcp443_port != contact.tcp443endpoint().port)
    return testing::AssertionFailure() << "TCP 443 Port mismatch.";
  if (tcp80_ip != contact.tcp80endpoint().ip)
    return testing::AssertionFailure() << "TCP 80 IP mismatch.";
  if (tcp80_port != contact.tcp80endpoint().port)
    return testing::AssertionFailure() << "TCP 80 Port mismatch.";
  return testing::AssertionSuccess();
}

TEST_F(TestContact, BEH_KAD_GetIpPortNodeId) {
  const Port kLocalPort2(4444);
  std::vector<transport::Endpoint> bad_locals;
  bad_locals.push_back(transport::Endpoint(kLocalIp1_, kLocalPort_));
  bad_locals.push_back(transport::Endpoint(kLocalIp2_, kLocalPort2));

  Contact default_contact;
  Contact bad_locals_contact(kNodeId_, kEndpoint_, bad_locals, kRvEndpoint_,
                             false, false);
  Contact invalid_contact1(kNodeId_, kEndpoint_, locals_, kRvEndpoint_, false,
                           true);
  Contact invalid_contact2(kNodeId_, kEndpoint_, locals_, kRvEndpoint_, true,
                           false);
  Contact invalid_contact3(kNodeId_, kEndpoint_, locals_, kRvEndpoint_, true,
                           true);

  EXPECT_TRUE(ContactDetails(default_contact, NodeId(), IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(contact_, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  EXPECT_TRUE(ContactDetails(rv_contact_, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(direct_connected_contact_, kNodeId_, kIp_, kPort_,
      kIp_, kLocalPort_, kLocalIp1_, kLocalPort_, IP(), 0, IP(), 0, kIp_, 80));
  EXPECT_TRUE(ContactDetails(bad_locals_contact, NodeId(), IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(invalid_contact1, NodeId(), IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(invalid_contact2, NodeId(), IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(invalid_contact3, NodeId(), IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0, IP(), 0));

  EXPECT_FALSE(default_contact.IsDirectlyConnected());
  EXPECT_FALSE(contact_.IsDirectlyConnected());
  EXPECT_FALSE(rv_contact_.IsDirectlyConnected());
  EXPECT_TRUE(direct_connected_contact_.IsDirectlyConnected());
  EXPECT_FALSE(bad_locals_contact.IsDirectlyConnected());
}

TEST_F(TestContact, BEH_KAD_OverloadedOperators) {
  std::vector<transport::Endpoint> locals1(1,
      transport::Endpoint("192.168.1.56", 8889));
  std::vector<transport::Endpoint> locals2(1,
      transport::Endpoint("192.168.1.57", 8890));
  transport::Endpoint rv_endpoint1("192.168.1.58", 8891);
  transport::Endpoint rv_endpoint2("192.168.1.59", 8892);
  Contact contact1(kNodeId_, kEndpoint_, locals1, transport::Endpoint(), false,
                   false);
  Contact contact2(kNodeId_, kEndpoint_, locals2, rv_endpoint2, false, false);
  EXPECT_EQ(contact1, contact2);

  Contact contact3(kNodeId_, transport::Endpoint("192.168.1.55", 8889), locals2,
                   rv_endpoint2, false, false);
  EXPECT_EQ(contact1, contact3);

  std::vector<transport::Endpoint> locals(10,
      transport::Endpoint("192.168.1.1", 10000));
  Contact contact4(kNodeId_, transport::Endpoint("192.168.2.155", 8888), locals,
                   transport::Endpoint("192.168.2.155", 8888), false, false);
  EXPECT_EQ(contact1, contact4);

  Contact contact5(NodeId(crypto::Hash<crypto::SHA512>("5612348")), kEndpoint_,
                   std::vector<transport::Endpoint>(1, kEndpoint_),
                   transport::Endpoint(), true, true);
  EXPECT_NE(contact1, contact5);

  Contact contact6(NodeId(crypto::Hash<crypto::SHA512>("5612348")),
                   transport::Endpoint("192.168.1.55", 8889), locals1,
                   transport::Endpoint(), true, true);
  EXPECT_NE(contact1, contact6);

  Contact contact7(kNodeId_, transport::Endpoint("192.168.2.54", 8889), locals1,
                   transport::Endpoint(), false, false);
  EXPECT_EQ(contact1, contact7);

  contact6 = contact1;
  EXPECT_EQ(contact1, contact6);

  Contact contact8(contact1);
  EXPECT_EQ(contact1, contact8);

  Contact contact9(NodeId(kZeroId), transport::Endpoint("127.0.0.1", 1234),
                   locals1, transport::Endpoint(), false, false);
  Contact contact10(NodeId(kZeroId), transport::Endpoint("127.0.0.2", 1234),
                    locals1, transport::Endpoint(), false, false);
  EXPECT_NE(contact9, contact10);

  Contact contact11(contact9);
  EXPECT_EQ(contact9, contact11);

  EXPECT_LT(contact9, contact1);
  EXPECT_GT(contact1, contact9);
  EXPECT_LE(contact9, contact1);
  EXPECT_LE(contact1, contact1);
  EXPECT_GE(contact1, contact9);
  EXPECT_GE(contact9, contact9);
}

TEST_F(TestContact, BEH_KAD_SetPreferredEndpoint) {
  // Before being set
  Contact contact(contact_), rv_contact(rv_contact_);
  transport::Endpoint preferred_endpoint(contact.PreferredEndpoint());
  EXPECT_EQ(kIp_, preferred_endpoint.ip);
  EXPECT_EQ(kPort_, preferred_endpoint.port);
  preferred_endpoint = rv_contact.PreferredEndpoint();
  EXPECT_EQ(kRvIp_, preferred_endpoint.ip);
  EXPECT_EQ(kRvPort_, preferred_endpoint.port);

  // Set to endpoint_
  contact = contact_;
  EXPECT_TRUE(contact.SetPreferredEndpoint(kIp_));
  EXPECT_TRUE(ContactDetails(contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  preferred_endpoint = contact.PreferredEndpoint();
  EXPECT_EQ(kIp_, preferred_endpoint.ip);
  EXPECT_EQ(kPort_, preferred_endpoint.port);

  rv_contact = rv_contact_;
  EXPECT_FALSE(rv_contact.SetPreferredEndpoint(kIp_));
  EXPECT_TRUE(ContactDetails(rv_contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  preferred_endpoint = rv_contact.PreferredEndpoint();
  EXPECT_EQ(kRvIp_, preferred_endpoint.ip);
  EXPECT_EQ(kRvPort_, preferred_endpoint.port);

  // Set to a local endpoint
  contact = contact_;
  EXPECT_TRUE(contact.SetPreferredEndpoint(kLocalIp2_));
  EXPECT_TRUE(ContactDetails(contact, kNodeId_, kIp_, kPort_,
      kLocalIp2_, kLocalPort_, kLocalIp1_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  preferred_endpoint = contact.PreferredEndpoint();
  EXPECT_EQ(kLocalIp2_, preferred_endpoint.ip);
  EXPECT_EQ(kLocalPort_, preferred_endpoint.port);

  rv_contact = rv_contact_;
  EXPECT_FALSE(rv_contact.SetPreferredEndpoint(kLocalIp2_));
  EXPECT_TRUE(ContactDetails(rv_contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  preferred_endpoint = rv_contact.PreferredEndpoint();
  EXPECT_EQ(kRvIp_, preferred_endpoint.ip);
  EXPECT_EQ(kRvPort_, preferred_endpoint.port);

  // Set to rendezvous
  contact = contact_;
  EXPECT_FALSE(contact.SetPreferredEndpoint(kRvIp_));
  EXPECT_TRUE(ContactDetails(contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  preferred_endpoint = contact.PreferredEndpoint();
  EXPECT_EQ(kIp_, preferred_endpoint.ip);
  EXPECT_EQ(kPort_, preferred_endpoint.port);

  rv_contact = rv_contact_;
  EXPECT_TRUE(rv_contact.SetPreferredEndpoint(kRvIp_));
  EXPECT_TRUE(ContactDetails(rv_contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  preferred_endpoint = rv_contact.PreferredEndpoint();
  EXPECT_EQ(kRvIp_, preferred_endpoint.ip);
  EXPECT_EQ(kRvPort_, preferred_endpoint.port);

  // Set to IP not in contact
  contact = contact_;
  EXPECT_FALSE(contact.SetPreferredEndpoint(IP::from_string("192.167.1.1")));
  EXPECT_TRUE(ContactDetails(contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  preferred_endpoint = contact.PreferredEndpoint();
  EXPECT_EQ(kIp_, preferred_endpoint.ip);
  EXPECT_EQ(kPort_, preferred_endpoint.port);

  rv_contact = rv_contact_;
  EXPECT_FALSE(rv_contact.SetPreferredEndpoint(IP::from_string("192.167.1.1")));
  EXPECT_TRUE(ContactDetails(rv_contact, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  preferred_endpoint = rv_contact.PreferredEndpoint();
  EXPECT_EQ(kRvIp_, preferred_endpoint.ip);
  EXPECT_EQ(kRvPort_, preferred_endpoint.port);
}

TEST_F(TestContact, BEH_KAD_ToFromProtobuf) {
  protobuf::Contact proto_contact(ToProtobuf(contact_));
  EXPECT_TRUE(proto_contact.IsInitialized());
  protobuf::Contact rv_proto_contact(ToProtobuf(rv_contact_));
  EXPECT_TRUE(rv_proto_contact.IsInitialized());
  protobuf::Contact direct_connected_proto_contact(ToProtobuf(
      direct_connected_contact_));
  EXPECT_TRUE(direct_connected_proto_contact.IsInitialized());

  std::string ser_contact, rv_ser_contact, direct_connected_ser_contact;
  EXPECT_TRUE(proto_contact.SerializeToString(&ser_contact));
  EXPECT_TRUE(rv_proto_contact.SerializeToString(&rv_ser_contact));
  EXPECT_TRUE(direct_connected_proto_contact.SerializeToString(
      &direct_connected_ser_contact));
  protobuf::Contact proto_contact_restored, rv_proto_contact_restored;
  protobuf::Contact direct_connected_proto_contact_restored;
  EXPECT_TRUE(proto_contact_restored.ParseFromString(ser_contact));
  EXPECT_TRUE(rv_proto_contact_restored.ParseFromString(rv_ser_contact));
  EXPECT_TRUE(direct_connected_proto_contact_restored.ParseFromString(
      direct_connected_ser_contact));

  Contact contact_restored(FromProtobuf(proto_contact_restored));
  Contact rv_contact_restored(FromProtobuf(rv_proto_contact_restored));
  Contact direct_connected_contact_restored(FromProtobuf(
      direct_connected_proto_contact_restored));
  EXPECT_TRUE(ContactDetails(contact_restored, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, IP(), 0, IP(), 0,
      IP(), 0));
  EXPECT_TRUE(ContactDetails(rv_contact_restored, kNodeId_, kIp_, kPort_,
      kLocalIp1_, kLocalPort_, kLocalIp2_, kLocalPort_, kRvIp_, kRvPort_,
      IP(), 0, IP(), 0));
  EXPECT_TRUE(ContactDetails(direct_connected_contact_restored, kNodeId_, kIp_,
      kPort_, kIp_, kLocalPort_, kLocalIp1_, kLocalPort_, IP(), 0, IP(), 0,
      kIp_, 80));

  Contact bad_contact(FromProtobuf(protobuf::Contact()));
  EXPECT_TRUE(ContactDetails(bad_contact, NodeId(), IP(), 0, IP(), 0, IP(), 0,
      IP(), 0, IP(), 0, IP(), 0));
}

TEST_F(TestContact, BEH_KAD_ContactWithinClosest) {
  std::vector<Contact> contacts;
  std::vector<transport::Endpoint> locals(1, kEndpoint_);
  contacts.push_back(Contact(NodeId(
      DecodeFromHex(std::string(2 * kKeySizeBytes, '1'))), kEndpoint_, locals,
      transport::Endpoint(), false, false));
  contacts.push_back(Contact(NodeId(
      DecodeFromHex(std::string(2 * kKeySizeBytes, '7'))), kEndpoint_, locals,
      transport::Endpoint(), false, false));

  Contact close(NodeId(DecodeFromHex(std::string(2 * kKeySizeBytes, '3'))),
                kEndpoint_, locals, transport::Endpoint(), false, false);
  Contact not_close(NodeId(DecodeFromHex(std::string(2 * kKeySizeBytes, 'f'))),
                    kEndpoint_, locals, transport::Endpoint(), false, false);

  EXPECT_TRUE(ContactWithinClosest(close, contacts, NodeId(kZeroId)));
  EXPECT_FALSE(ContactWithinClosest(not_close, contacts, NodeId(kZeroId)));
}

TEST_F(TestContact, BEH_KAD_RemoveContact) {
  std::vector<Contact> contacts;
  std::vector<transport::Endpoint> locals(1, kEndpoint_);
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("aaa")),
      kEndpoint_, locals, transport::Endpoint(), false, false));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("bbb")),
      kEndpoint_, locals, transport::Endpoint(), false, false));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("ccc")),
      kEndpoint_, locals, transport::Endpoint(), false, false));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("bbb")),
      kEndpoint_, locals, transport::Endpoint(), false, false));

  EXPECT_EQ(4U, contacts.size());
  EXPECT_FALSE(RemoveContact(NodeId(crypto::Hash<crypto::SHA512>("ddd")),
                             &contacts));
  EXPECT_EQ(4U, contacts.size());
  EXPECT_TRUE(RemoveContact(NodeId(crypto::Hash<crypto::SHA512>("bbb")),
                            &contacts));
  EXPECT_EQ(2U, contacts.size());
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
