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

namespace test_contact {

TEST(TestContact, BEH_KAD_GetIpPortNodeId) {
  std::string ip("192.168.1.55");
  std::string local_ip(ip);
  boost::uint16_t port(8888), local_port(port);
  NodeId node_id(crypto::Hash<crypto::SHA512>("1238425"));
  transport::Endpoint ep(ip, port);
  Contact contact(node_id, ep);
  EXPECT_EQ(ip, contact.GetPreferredEndpoint().ip.to_string());
//  EXPECT_EQ(ip, transport::IpBytesToAscii(contact.ip()));
  EXPECT_EQ(node_id, contact.node_id());
  EXPECT_EQ(port, contact.GetPreferredEndpoint().port);
//  EXPECT_EQ(transport::IpAsciiToBytes(local_ip), contact.local_ip());
//  EXPECT_EQ(local_ip, transport::IpBytesToAscii(contact.local_ip()));
//  EXPECT_EQ(local_port, contact.local_port());
}

TEST(TestContact, BEH_KAD_OverloadedOperators) {
  NodeId node_id(crypto::Hash<crypto::SHA512>("1238425"));
  transport::Endpoint endpoint("192.168.1.55", 8888);
  Contact contact1(node_id, endpoint);
  Contact contact2(node_id, endpoint);
  EXPECT_EQ(contact1, contact2);

  Contact contact3(node_id, transport::Endpoint("192.168.1.55", 8889));
  EXPECT_EQ(contact1, contact3);

  std::vector<transport::Endpoint> locals(10,
      transport::Endpoint("192.168.1.1", 10000));
  Contact contact4(node_id, transport::Endpoint("192.168.2.155", 8888),
                   transport::Endpoint("192.168.2.155", 8888), locals);
  EXPECT_EQ(contact1, contact4);

  Contact contact5(NodeId(crypto::Hash<crypto::SHA512>("5612348")), endpoint);
  EXPECT_NE(contact1, contact5);

  Contact contact6(NodeId(crypto::Hash<crypto::SHA512>("5612348")),
                   transport::Endpoint("192.168.1.55", 8889));
  EXPECT_NE(contact1, contact6);

  Contact contact7(node_id, transport::Endpoint("192.168.2.54", 8889));
  EXPECT_EQ(contact1, contact7);

  contact6 = contact1;
  EXPECT_EQ(contact1, contact6);

  Contact contact8(contact1);
  EXPECT_EQ(contact1, contact8);

  Contact contact9(NodeId(kZeroId), transport::Endpoint("127.0.0.1", 1234));
  Contact contact10(NodeId(kZeroId), transport::Endpoint("127.0.0.2", 1234));
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

TEST(TestContact, BEH_KAD_SetPreferredEndpoint) {
  FAIL() << "Test needs implementing";
}

TEST(TestContact, BEH_KAD_ToFromProtobuf) {
  transport::Endpoint endpoint("192.168.1.55", 8888);
  transport::Endpoint rv_endpoint("192.168.2.56", 9999);
  std::vector<transport::Endpoint> local_endpoints;
  for (int i = 0; i < 10; ++i) {
    local_endpoints.push_back(transport::Endpoint("192.168.1." + IntToString(i),
                                                  10000));
  }
  NodeId node_id(crypto::Hash<crypto::SHA512>("1238425"));
  Contact contact(node_id, endpoint, rv_endpoint, local_endpoints);

  protobuf::Contact proto_contact(ToProtobuf(contact));
  EXPECT_TRUE(proto_contact.IsInitialized());

  std::string ser_contact;
  EXPECT_TRUE(proto_contact.SerializeToString(&ser_contact));
  protobuf::Contact proto_contact1;
  EXPECT_TRUE(proto_contact1.ParseFromString(ser_contact));

  Contact contact1(FromProtobuf(proto_contact1));
  EXPECT_EQ(contact.node_id(), contact1.node_id());
  EXPECT_EQ(contact.endpoint().ip, contact1.endpoint().ip);
  EXPECT_EQ(contact.endpoint().port, contact1.endpoint().port);
  EXPECT_EQ(contact.rendezvous_endpoint().ip,
            contact1.rendezvous_endpoint().ip);
  EXPECT_EQ(contact.rendezvous_endpoint().port,
            contact1.rendezvous_endpoint().port);
  for (int i = 0; i < 10; ++i) {
    std::vector<transport::Endpoint> &locals(contact.local_endpoints());
    std::vector<transport::Endpoint> &locals1(contact1.local_endpoints());
    EXPECT_EQ(locals.at(i).ip, locals1.at(i).ip);
    EXPECT_EQ(locals.at(i).port, locals1.at(i).port);
  }
}

TEST(TestContact, BEH_KAD_ContactWithinClosest) {
  std::vector<Contact> contacts;
  transport::Endpoint endpoint;
  contacts.push_back(Contact(NodeId(
      DecodeFromHex(std::string(2 * kKeySizeBytes, '1'))), endpoint));
  contacts.push_back(Contact(NodeId(
      DecodeFromHex(std::string(2 * kKeySizeBytes, '7'))), endpoint));

  Contact close(NodeId(DecodeFromHex(std::string(2 * kKeySizeBytes, '3'))),
                endpoint);
  Contact not_close(NodeId(DecodeFromHex(std::string(2 * kKeySizeBytes, 'f'))),
                    endpoint);

  EXPECT_TRUE(ContactWithinClosest(close, contacts, NodeId(kZeroId)));
  EXPECT_FALSE(ContactWithinClosest(not_close, contacts, NodeId(kZeroId)));
}

TEST(TestContact, BEH_KAD_RemoveContact) {
  std::vector<Contact> contacts;
  transport::Endpoint ep;
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("aaa")), ep));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("bbb")), ep));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("ccc")), ep));
  contacts.push_back(Contact(NodeId(crypto::Hash<crypto::SHA512>("bbb")), ep));

  EXPECT_EQ(4U, contacts.size());
  EXPECT_FALSE(RemoveContact(NodeId(crypto::Hash<crypto::SHA512>("ddd")),
                             &contacts));
  EXPECT_EQ(4U, contacts.size());
  EXPECT_TRUE(RemoveContact(NodeId(crypto::Hash<crypto::SHA512>("bbb")),
                            &contacts));
  EXPECT_EQ(2U, contacts.size());
}


}  // namespace test_contact

}  // namespace kademlia

}  // namespace maidsafe
