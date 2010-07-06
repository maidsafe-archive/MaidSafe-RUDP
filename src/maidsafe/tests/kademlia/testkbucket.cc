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

#include <gtest/gtest.h>
#include <boost/lexical_cast.hpp>
#include "maidsafe/kademlia/kbucket.h"
#include "maidsafe/kademlia/kadid.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/maidsafe-dht.h"

namespace test_kbucket {
  static const boost::uint16_t K = 16;
}  // namespace test_kbucket

namespace kad {

class TestKbucket : public testing::Test {
 public:
  TestKbucket() : cry_obj() {}
 protected:
  void SetUp() {
    cry_obj.set_symm_algorithm(crypto::AES_256);
    cry_obj.set_hash_algorithm(crypto::SHA_512);
  }
  crypto::Crypto cry_obj;
};

TEST_F(TestKbucket, BEH_KAD_IsInRange) {
  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket1(min_value, max_value, test_kbucket::K);
  KadId id(cry_obj.Hash("15641654616", "", crypto::STRING_STRING, false));
  ASSERT_TRUE(kbucket1.KeyInRange(id));
  hex_max_val = "";
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "a";
  KadId max_value1(hex_max_val, kad::KadId::kHex);
  KBucket kbucket2(min_value, max_value1, test_kbucket::K);
  std::string enc_id;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    enc_id += "b";
  ASSERT_FALSE(kbucket2.KeyInRange(KadId(enc_id, kad::KadId::kHex)));
}

TEST_F(TestKbucket, BEH_KAD_AddAndGetContact) {
  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  KadId id[test_kbucket::K];
  std::string ip("127.0.0.1");
  boost::int16_t port = 8880;
  for (boost::int16_t i = 0; i < test_kbucket::K; ++i) {
    ASSERT_EQ(i, kbucket.Size());
    id[i] = KadId(cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
                  crypto::STRING_STRING, false));
    ++port;
    Contact contact(id[i], ip, port, ip, port);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
  }
  ++port;
  KadId id1(cry_obj.Hash("125486", "", crypto::STRING_STRING, false));
  ASSERT_EQ(test_kbucket::K, kbucket.Size());
  Contact contact1(id1, ip, port, ip, port);
  ASSERT_EQ(FULL, kbucket.AddContact(contact1));
  ASSERT_EQ(test_kbucket::K, kbucket.Size());
  port = 8880;
  for (boost::int16_t i = 0; i < test_kbucket::K; ++i) {
    ++port;
    Contact contact(id[i], ip, port, ip, port);
    Contact contact_rec;
    ASSERT_TRUE(kbucket.GetContact(id[i], &contact_rec));
    ASSERT_TRUE(contact.node_id() == contact_rec.node_id());
    ASSERT_EQ(contact.host_ip(), contact_rec.host_ip());
    ASSERT_EQ(contact.host_port(), contact_rec.host_port());
    ASSERT_EQ(contact.local_ip(), contact_rec.local_ip());
    ASSERT_EQ(contact.local_port(), contact_rec.local_port());
  }
  Contact contact_rec;
  ASSERT_FALSE(kbucket.GetContact(KadId(), &contact_rec));
}

TEST_F(TestKbucket, BEH_KAD_GetContacts) {
  if (test_kbucket::K <= 2) {
    SUCCEED();
    return;
  }

  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  KadId id[test_kbucket::K - 1];
  std::string ip("127.0.0.1");
  boost::int16_t port[test_kbucket::K - 1];
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    id[i] = KadId(cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
  }
  ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
  std::vector<Contact> contacts, ex_contacts;
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    kbucket.GetContacts(i + 1, ex_contacts, &contacts);
    ASSERT_EQ(i + 1, static_cast<int>(contacts.size()));
    for (boost::int16_t j = 0; j <= i; ++j) {
      Contact contact;
      ASSERT_TRUE(kbucket.GetContact(id[test_kbucket::K - 2 - j], &contact));
      ASSERT_TRUE(contact.Equals(contacts[j]));
    }
    contacts.clear();
  }
  Contact ex_contact1, ex_contact2;
  ASSERT_TRUE(kbucket.GetContact(id[1], &ex_contact1));
  ASSERT_TRUE(kbucket.GetContact(id[2], &ex_contact2));
  ex_contacts.push_back(ex_contact1);
  ex_contacts.push_back(ex_contact2);
  kbucket.GetContacts(test_kbucket::K - 1, ex_contacts, &contacts);
  ASSERT_EQ(test_kbucket::K - 3, static_cast<int>(contacts.size()));
  for (boost::int16_t i = 0; i < test_kbucket::K - 3; ++i) {
    EXPECT_FALSE(contacts[i].Equals(ex_contacts[0]));
    EXPECT_FALSE(contacts[i].Equals(ex_contacts[1]));
  }
  contacts.clear();
  ex_contacts.clear();
  kbucket.GetContacts(test_kbucket::K, ex_contacts, &contacts);
  ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
  contacts.clear();
  Contact contact1(id[2], ip, 8882, ip, 8882);
  kbucket.AddContact(contact1);
  kbucket.GetContacts(1, ex_contacts, &contacts);
  Contact contact2;
  ASSERT_TRUE(kbucket.GetContact(id[2], &contact2));
  ASSERT_TRUE(contact2.Equals(contacts[0])) <<
      "the contact readded was not placed at the begging of the list";
}

TEST_F(TestKbucket, BEH_KAD_DeleteContact) {
  if (test_kbucket::K <= 3) {
    SUCCEED();
    return;
  }

  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  KadId id[test_kbucket::K - 1];
  std::string ip("127.0.0.1");
  boost::int16_t port = 8880;
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    id[i] = KadId(cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    ++port;
    Contact contact(id[i], ip, port, ip, port);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
  }
  for (boost::int16_t i = 0; i < kFailedRpc; ++i) {
    ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
    kbucket.RemoveContact(id[2], false);
    Contact contact;
    ASSERT_TRUE(kbucket.GetContact(id[2], &contact));
    ASSERT_EQ(i + 1, contact.failed_rpc());
  }
  ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
  kbucket.RemoveContact(id[2], false);
  ASSERT_EQ(test_kbucket::K - 2, kbucket.Size()) <<
      "Size of kbucket same as before deleting the contact";
  Contact contact;
  ASSERT_FALSE(kbucket.GetContact(id[2], &contact));
  kbucket.RemoveContact(id[1], true);
  ASSERT_EQ(test_kbucket::K - 3, kbucket.Size()) <<
      "Size of kbucket same as before deleting the contact";
  ASSERT_FALSE(kbucket.GetContact(id[1], &contact));
}

TEST_F(TestKbucket, BEH_KAD_SetLastAccessed) {
  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  boost::uint32_t time_accessed = base::GetEpochTime();
  kbucket.set_last_accessed(time_accessed);
  ASSERT_EQ(time_accessed, kbucket.last_accessed());
}

TEST_F(TestKbucket, BEH_KAD_FillKbucketUpdateContent) {
  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  KadId id[test_kbucket::K];
  std::string ip = "127.0.0.1";
  boost::int16_t port[test_kbucket::K];
  for (boost::int16_t i = 0; i < test_kbucket::K; ++i) {
    id[i] = KadId(cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
  }
  ASSERT_EQ(test_kbucket::K, kbucket.Size());
  std::vector<Contact> contacts, ex_contacts;
  Contact contact1(id[test_kbucket::K - 1], ip, port[test_kbucket::K - 1], ip,
                   port[test_kbucket::K - 1]);
  ASSERT_EQ(SUCCEED, kbucket.AddContact(contact1));
  for (boost::int16_t i = 0; i < test_kbucket::K; ++i) {
    std::cout << "contacts retrieved = " << i + 1 << std::endl;
    kbucket.GetContacts(i + 1, ex_contacts, &contacts);
    ASSERT_EQ(i + 1, static_cast<int>(contacts.size()));
    Contact contact;
    ASSERT_TRUE(kbucket.GetContact(id[test_kbucket::K - 1], &contact));
    ASSERT_TRUE(contact.Equals(contacts[0]));
    contacts.clear();
  }
}

TEST_F(TestKbucket, BEH_KAD_AddSameContact) {
  if (test_kbucket::K <= 3) {
    SUCCEED();
    return;
  }

  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  KadId id[test_kbucket::K - 1];
  std::string ip("127.0.0.1");
  boost::int16_t port[test_kbucket::K - 1];
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    id[i] = KadId(cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false));
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
  }
  ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
  std::vector<Contact> contacts, ex_contacts;
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    std::cout << "contacts retrieved = " << i + 1 << std::endl;
    kbucket.GetContacts(i + 1, ex_contacts, &contacts);
    ASSERT_EQ(i + 1, static_cast<int>(contacts.size()));
    for (boost::int16_t j = 0; j <= i; ++j) {
      Contact contact;
      ASSERT_TRUE(kbucket.GetContact(id[test_kbucket::K - 2-j], &contact));
      ASSERT_TRUE(contact.Equals(contacts[j]));
    }
    contacts.clear();
  }
  Contact ex_contact1, ex_contact2;
  ASSERT_TRUE(kbucket.GetContact(id[1], &ex_contact1));
  ASSERT_TRUE(kbucket.GetContact(id[2], &ex_contact2));
  ex_contacts.push_back(ex_contact1);
  ex_contacts.push_back(ex_contact2);
  kbucket.GetContacts(test_kbucket::K - 1, ex_contacts, &contacts);
  ASSERT_EQ(test_kbucket::K - 3, contacts.size());
  for (boost::int16_t i = 0; i < test_kbucket::K - 3; ++i) {
    EXPECT_FALSE(contacts[i].Equals(ex_contacts[0]));
    EXPECT_FALSE(contacts[i].Equals(ex_contacts[1]));
  }
  contacts.clear();
  ex_contacts.clear();
  kbucket.GetContacts(test_kbucket::K, ex_contacts, &contacts);
  ASSERT_EQ(test_kbucket::K - 1, kbucket.Size());
  contacts.clear();
  Contact contact1(id[2], "192.168.1.70", 8890, "192.168.1.70", 8890);
  ASSERT_EQ(SUCCEED, kbucket.AddContact(contact1));
  kbucket.GetContacts(1, ex_contacts, &contacts);
  Contact contact2;
  ASSERT_TRUE(kbucket.GetContact(id[2], &contact2));
  ASSERT_TRUE(contact2.Equals(contacts[0])) <<
      "the contact readded was not placed at the begging of the list";
  ex_contacts.clear();
  contacts.clear();

  size_t currsize = kbucket.Size();
  Contact contact3(cry_obj.Hash("newid", "", crypto::STRING_STRING, false),
    ip, 8880, ip, 8880);
  ASSERT_EQ(SUCCEED, kbucket.AddContact(contact3));
  ASSERT_EQ(currsize, kbucket.Size());
  Contact contact4;
  kbucket.GetContacts(1, ex_contacts, &contacts);
  ASSERT_TRUE(kbucket.GetContact(KadId(cry_obj.Hash("newid",
      "", crypto::STRING_STRING, false)), &contact4));
  ASSERT_TRUE(contact4.Equals(contacts[0])) <<
      "the contact readded was not placed at the begging of the list";
}

TEST_F(TestKbucket, BEH_KAD_GetOldestContact) {
  KadId min_value;
  std::string hex_max_val;
  for (boost::int16_t i = 0; i < kKeySizeBytes * 2; ++i)
    hex_max_val += "f";
  KadId max_value(hex_max_val, kad::KadId::kHex);
  KBucket kbucket(min_value, max_value, test_kbucket::K);
  std::string id[test_kbucket::K - 1], ip("127.0.0.1");
  boost::int16_t port[test_kbucket::K - 1];
  Contact empty;
  Contact rec;
  rec = kbucket.LastSeenContact();
  ASSERT_TRUE(empty.Equals(rec));
  for (boost::int16_t i = 0; i < test_kbucket::K - 1; ++i) {
    id[i] = cry_obj.Hash(boost::lexical_cast<std::string>(i), "",
        crypto::STRING_STRING, false);
    port[i] = 8880 + i;
    Contact contact(id[i], ip, port[i], ip, port[i]);
    Contact firstinput(id[0], ip, port[0], ip, port[0]);
    ASSERT_EQ(SUCCEED, kbucket.AddContact(contact));
    Contact last_seen = kbucket.LastSeenContact();
    ASSERT_TRUE(firstinput.Equals(last_seen));
  }
}

}  // namespace kad
