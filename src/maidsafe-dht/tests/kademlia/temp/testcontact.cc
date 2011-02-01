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
#include "maidsafe-dht/kademlia/node_id.h"
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
  ASSERT_EQ(ip, contact.GetPreferredEndpoint().ip.to_string());
//  ASSERT_EQ(ip, transport::IpBytesToAscii(contact.ip()));
  ASSERT_EQ(node_id, contact.node_id());
  ASSERT_EQ(port, contact.GetPreferredEndpoint().port);
//  ASSERT_EQ(transport::IpAsciiToBytes(local_ip), contact.local_ip());
//  ASSERT_EQ(local_ip, transport::IpBytesToAscii(contact.local_ip()));
//  ASSERT_EQ(local_port, contact.local_port());
}
/*
TEST(TestContact, BEH_KAD_OverloadedOperators) {
  std::string ip("192.168.1.55");
  std::string local_ip(ip);
  boost::uint16_t port(8888);
  boost::uint16_t local_port(port);
  std::string node_id(cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false));
  Contact contact1(node_id, ip, port, local_ip, local_port);
  Contact contact2(node_id, ip, port, local_ip, local_port);
  ASSERT_TRUE(contact1.Equals(contact2));
  Contact contact3(node_id, ip, 8889);
  ASSERT_TRUE(contact1.Equals(contact3));
  Contact contact4(node_id, "192.168.2.54", port, "192.168.2.54", port);
  ASSERT_TRUE(contact1.Equals(contact4));
  Contact contact5(cry_obj.Hash("5612348", "", crypto::STRING_STRING,
      false), ip, port, ip, port);
  ASSERT_FALSE(contact1.Equals(contact5));
  Contact contact6(cry_obj.Hash("5612348", "", crypto::STRING_STRING,
      false), ip, 8889, ip, 8889);
  ASSERT_FALSE(contact1.Equals(contact6));
  Contact contact7(node_id, "192.168.2.54", 8889, "192.168.2.54", 8889);
  ASSERT_TRUE(contact1.Equals(contact7));
  contact6 = contact1;
  ASSERT_TRUE(contact1.Equals(contact6));
  Contact contact8(contact1);
  ASSERT_TRUE(contact1.Equals(contact8));
  Contact contact9(kClientId, "127.0.0.1", 1234);
  Contact contact10(kClientId, "127.0.0.2", 1234);
  ASSERT_FALSE(contact9.Equals(contact10));
  Contact contact11(contact9);
  ASSERT_TRUE(contact9.Equals(contact11));
}

TEST(TestContact, BEH_KAD_IncreaseGetFailedRPC) {
  std::string ip("192.168.1.55");
  std::string local_ip(ip);
  boost::uint16_t port(8888);
  boost::uint16_t local_port(port);
  std::string node_id(cry_obj.Hash("1238425", "", crypto::STRING_STRING,
    false));
  Contact contact(node_id, ip, port, local_ip, local_port);
  ASSERT_EQ(0, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(1, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(2, static_cast<int>(contact.failed_rpc()));
  contact.IncreaseFailed_RPC();
  ASSERT_EQ(3, static_cast<int>(contact.failed_rpc()));
}

TEST(TestContact, BEH_KAD_ContactPointer) {
  std::string ip("192.168.1.55");
  std::string local_ip(ip);
  boost::uint16_t port(8888);
  boost::uint16_t local_port(port);
  std::string node_id(cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false));
  Contact *contact = new Contact(node_id, ip, port, local_ip,
    local_port);
  ASSERT_EQ(IpAsciiToBytes(ip), contact->ip());
  ASSERT_EQ(ip, IpBytesToAscii(contact->ip()));
  ASSERT_EQ(node_id, contact->node_id().String());
  ASSERT_EQ(port, contact->port());
  ASSERT_EQ(IpAsciiToBytes(local_ip), contact->local_ip());
  ASSERT_EQ(local_ip, IpBytesToAscii(contact->local_ip()));
  ASSERT_EQ(local_port, contact->local_port());
  ASSERT_EQ(0, contact->failed_rpc());
  contact->IncreaseFailed_RPC();
  ASSERT_EQ(1, contact->failed_rpc());
  delete contact;
}

TEST(TestContact, BEH_KAD_SerialiseToString) {
  std::string ip("192.168.1.55");
  std::string local_ip(ip);
  boost::uint16_t port(8888);
  boost::uint16_t local_port(port);
  std::string node_id(cry_obj.Hash("1238425", "", crypto::STRING_STRING,
      false));
  Contact contact(node_id, ip, port, local_ip, local_port);
  std::string ser_contact;
  ASSERT_TRUE(contact.SerialiseToString(&ser_contact));
  Contact contact1;
  std::string ser_contact1;
  ASSERT_FALSE(contact1.SerialiseToString(&ser_contact1));
  ASSERT_TRUE(contact1.ParseFromString(ser_contact));
  ASSERT_FALSE(contact1.ParseFromString("invaliddata"));
  ASSERT_EQ(ip, IpBytesToAscii(contact1.ip()));
  ASSERT_EQ(port, contact1.port());
  ASSERT_EQ(node_id, contact1.node_id().String());
  ASSERT_EQ(local_ip, IpBytesToAscii(contact1.local_ip()));
  ASSERT_EQ(local_port, contact1.port());
}

TEST(TestContact, BEH_KAD_Constructors) {
  // empty contact
  Contact ctc1;
  NodeId id1;
  ASSERT_EQ(id1.String(), ctc1.node_id().String());
  ASSERT_EQ("", ctc1.ip());
  ASSERT_EQ("", ctc1.local_ip());
  ASSERT_EQ("", ctc1.rendezvous_ip());
  ASSERT_EQ(0, ctc1.port());
  ASSERT_EQ(0, ctc1.local_port());
  ASSERT_EQ(0, ctc1.rendezvous_port());
  ASSERT_EQ("Empty contact.\n", ctc1.DebugString());

  std::string ip(IpAsciiToBytes("192.168.1.55"));
  boost::uint16_t port(8888);
  std::string node_id(cry_obj.Hash("1238425", "", crypto::STRING_STRING,
    false));
  Contact ctc2(node_id, ip, port);
  NodeId id2(node_id);
  ASSERT_EQ(id2.String(), ctc2.node_id().String());
  ASSERT_EQ(ip, ctc2.ip());
  ASSERT_EQ("", ctc2.local_ip());
  ASSERT_EQ("", ctc2.rendezvous_ip());
  ASSERT_EQ(port, ctc2.port());
  ASSERT_EQ(0, ctc2.local_port());
  ASSERT_EQ(0, ctc2.rendezvous_port());

  Contact ctc3(node_id, ip, port, ip, port);
  ASSERT_EQ(id2.String(), ctc3.node_id().String());
  ASSERT_EQ(ip, ctc3.ip());
  ASSERT_EQ(ip, ctc3.local_ip());
  ASSERT_EQ("", ctc3.rendezvous_ip());
  ASSERT_EQ(port, ctc3.port());
  ASSERT_EQ(port, ctc3.local_port());
  ASSERT_EQ(0, ctc3.rendezvous_port());

  Contact ctc4(node_id, ip, port, ip, port, ip, port);
  ASSERT_EQ(id2.String(), ctc4.node_id().String());
  ASSERT_EQ(ip, ctc4.ip());
  ASSERT_EQ(ip, ctc4.local_ip());
  ASSERT_EQ(ip, ctc4.rendezvous_ip());
  ASSERT_EQ(port, ctc4.port());
  ASSERT_EQ(port, ctc4.local_port());
  ASSERT_EQ(port, ctc4.rendezvous_port());
}
*/
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
