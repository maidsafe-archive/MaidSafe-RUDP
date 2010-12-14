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
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/kademlia/nodeimpl.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"

namespace kademlia {

namespace test_kadid {

void InsertKadContact(const NodeId &key, const kademlia::Contact &new_contact,
                      std::vector<kademlia::Contact> *contacts) {
  std::list<kademlia::Contact> contact_list(contacts->begin(), contacts->end());
  contact_list.push_back(new_contact);
  kademlia::SortContactList(key, &contact_list);
  contacts->clear();
  for (std::list<kademlia::Contact>::iterator it = contact_list.begin();
       it != contact_list.end(); ++it) {
    contacts->push_back(*it);
  }
}

NodeId IncreaseId(const NodeId &kad_id) {
  std::string raw(kad_id.String());
  std::string::reverse_iterator rit = raw.rbegin();
  while (rit != raw.rend()) {
    if (++(*rit) == 0)
      ++rit;
    else
      break;
  }
  return NodeId(raw);
}

const std::string ToBinary(const std::string &raw_id)  {
  std::string hex_encoded(base::EncodeToHex(raw_id));
  std::string result;
  for (size_t i = 0; i < hex_encoded.size(); ++i) {
    std::string temp;
    switch (hex_encoded[i]) {
      case '0': temp = "0000"; break;
      case '1': temp = "0001"; break;
      case '2': temp = "0010"; break;
      case '3': temp = "0011"; break;
      case '4': temp = "0100"; break;
      case '5': temp = "0101"; break;
      case '6': temp = "0110"; break;
      case '7': temp = "0111"; break;
      case '8': temp = "1000"; break;
      case '9': temp = "1001"; break;
      case 'a': temp = "1010"; break;
      case 'b': temp = "1011"; break;
      case 'c': temp = "1100"; break;
      case 'd': temp = "1101"; break;
      case 'e': temp = "1110"; break;
      case 'f': temp = "1111"; break;
    }
    result += temp;
  }
  return result;
}

TEST(TestKadId, BEH_KAD_BitToByteCount) {
  for (size_t i = 0; i < kKeySizeBytes; ++i) {
    ASSERT_EQ(i, BitToByteCount(8 * i));
    for (size_t j = 1; j < 8; ++j) {
      ASSERT_EQ(i + 1, BitToByteCount((8 * i) + j));
    }
  }
}

TEST(TestKadId, BEH_KAD_DefaultCtr) {
  NodeId node_id;
  ASSERT_EQ(kKeySizeBytes, node_id.String().size());
  for (size_t i = 0; i < node_id.String().size(); ++i)
    ASSERT_EQ('\0', node_id.String()[i]);
  std::string hex_id(kKeySizeBytes * 2, '0');
  ASSERT_EQ(hex_id, node_id.ToStringEncoded(NodeId::kHex));
  std::string bin_id(kKeySizeBits, '0');
  ASSERT_EQ(bin_id, node_id.ToStringEncoded(NodeId::kBinary));
}

TEST(TestKadId, BEH_KAD_CopyCtr) {
  NodeId kadid1(NodeId::kRandomId);
  NodeId kadid2(kadid1);
  ASSERT_TRUE(kadid1 == kadid2);
  for (size_t i = 0; i < kadid1.String().size(); ++i)
    ASSERT_EQ(kadid1.String()[i], kadid2.String()[i]);
  ASSERT_EQ(kadid1.ToStringEncoded(NodeId::kBinary),
            kadid2.ToStringEncoded(NodeId::kBinary));
  ASSERT_EQ(kadid1.ToStringEncoded(NodeId::kHex),
            kadid2.ToStringEncoded(NodeId::kHex));
  ASSERT_EQ(kadid1.String(), kadid2.String());
}

TEST(TestKadId, BEH_KAD_KadIdTypeCtr) {
  std::string min_id = kClientId;
  ASSERT_EQ(kKeySizeBytes, min_id.size());
  for (int i = 0; i < kKeySizeBytes; ++i)
    ASSERT_EQ(min_id[i], '\0');
  NodeId max_id(NodeId::kMaxId);
  ASSERT_EQ(kKeySizeBytes, max_id.String().size());
  for (int i = 0; i < kKeySizeBytes; ++i)
    ASSERT_TRUE((max_id.String()[i] == static_cast<char>(255)) ||
                (max_id.String()[i] == -1));
  NodeId rand_id(NodeId::kRandomId);
  ASSERT_EQ(kKeySizeBytes, rand_id.String().size());
  // TODO(Fraser#5#): 2010-06-06 - Test for randomness properly
  ASSERT_NE(rand_id.String(), NodeId(NodeId::kRandomId).String());
}

TEST(TestKadId, BEH_KAD_StringCtr) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string rand_str(co.Hash(base::RandomString(200), "",
                               crypto::STRING_STRING, false));
  NodeId id(rand_str);
  ASSERT_TRUE(id.String() == rand_str);
}

TEST(TestKadId, BEH_KAD_EncodingCtr) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string known_raw(kKeySizeBytes, 0);
  for (char c = 0; c < kKeySizeBytes; ++c)
    known_raw.at(static_cast<boost::uint8_t>(c)) = c;
  for (int i = 0; i < 4; ++i) {
    std::string rand_str(co.Hash(base::RandomString(200), "",
                                 crypto::STRING_STRING, false));
    std::string bad_encoded("Bad Encoded"), encoded, known_encoded;
    NodeId::EncodingType type = static_cast<NodeId::EncodingType>(i);
    switch (type) {
      case NodeId::kBinary :
        encoded = ToBinary(rand_str);
        known_encoded = ToBinary(known_raw);
        break;
      case NodeId::kHex :
        encoded = base::EncodeToHex(rand_str);
        known_encoded = base::EncodeToHex(known_raw);
        break;
      case NodeId::kBase32 :
        encoded = base::EncodeToBase32(rand_str);
        known_encoded = base::EncodeToBase32(known_raw);
        break;
      case NodeId::kBase64 :
        encoded = base::EncodeToBase64(rand_str);
        known_encoded = base::EncodeToBase64(known_raw);
        break;
      default :
        break;
    }
    NodeId bad_id(bad_encoded, type);
    ASSERT_TRUE(bad_id.String().empty());
    ASSERT_FALSE(bad_id.IsValid());
    ASSERT_TRUE(bad_id.ToStringEncoded(type).empty());
    NodeId rand_id(encoded, type);
    ASSERT_EQ(rand_str, rand_id.String());
    ASSERT_EQ(encoded, rand_id.ToStringEncoded(type));
    NodeId known_id(known_encoded, type);
    ASSERT_EQ(known_raw, known_id.String());
    ASSERT_EQ(known_encoded, known_id.ToStringEncoded(type));
    switch (i) {
      case NodeId::kBinary :
        ASSERT_EQ("000000000000000100000010000000110000010000000101000001100000"
                  "011100001000000010010000101000001011000011000000110100001110"
                  "000011110001000000010001000100100001001100010100000101010001"
                  "011000010111000110000001100100011010000110110001110000011101"
                  "000111100001111100100000001000010010001000100011001001000010"
                  "010100100110001001110010100000101001001010100010101100101100"
                  "001011010010111000101111001100000011000100110010001100110011"
                  "010000110101001101100011011100111000001110010011101000111011"
                  "00111100001111010011111000111111", known_encoded);
        break;
      case NodeId::kHex :
        ASSERT_EQ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
                  "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b"
                  "3c3d3e3f", known_encoded);
        break;
      case NodeId::kBase32 :
        ASSERT_EQ("aaasea2eawdaqcajbifs2diqb6ibcesvcsktnf22depbyha7d2ruaijcenuc"
                  "kjthfawuwk3nfwzc8nbtgi3vipjyg66duqt5hs8v6r2", known_encoded);
        break;
      case NodeId::kBase64 :
        ASSERT_EQ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKiss"
                  "LS4vMDEyMzQ1Njc4OTo7PD0+Pw==", known_encoded);
        break;
      default :
        break;
    }
  }
}

TEST(TestKadId, BEH_KAD_CtrPower) {
  NodeId node_id(-2);
  ASSERT_FALSE(node_id.IsValid());
  node_id = NodeId(kKeySizeBits + 1);
  ASSERT_FALSE(node_id.IsValid());
  std::string bin_id(kKeySizeBits, '0');
  for (boost::int16_t i = 0; i < kKeySizeBits; ++i) {
    NodeId node_id(i);
    bin_id[kKeySizeBits - 1 - i] = '1';
    ASSERT_EQ(bin_id, node_id.ToStringEncoded(NodeId::kBinary))
        << "Fail to construct 2^" << i << std::endl;
    bin_id[kKeySizeBits - 1 - i] = '0';
  }
}

TEST(TestKadId, BEH_KAD_CtrBetweenIds) {
  NodeId id1(NodeId::kRandomId), id2(NodeId::kRandomId);
  NodeId bad_id(-2);
  NodeId id(id1, bad_id);
  ASSERT_FALSE(id.IsValid());
  id = NodeId(bad_id, id2);
  ASSERT_FALSE(id.IsValid());
  id = NodeId(id1, id1);
  ASSERT_TRUE(id.IsValid());
  ASSERT_EQ(id1.String(), id.String());
  for (int i = 0; i < 100; ++i) {
    id1 = NodeId(NodeId::kRandomId);
    id2 = NodeId(NodeId::kRandomId);
    std::string test_raw_id1 = id1.ToStringEncoded(NodeId::kBinary);
    std::string test_raw_id2 = id2.ToStringEncoded(NodeId::kBinary);
    id = NodeId(id1, id2);
    ASSERT_TRUE(id.IsValid());
    ASSERT_TRUE(id >= std::min(id1, id2)) << "id  = " <<
        id.ToStringEncoded(NodeId::kBinary) << std::endl << "id1 = "
        << id1.ToStringEncoded(NodeId::kBinary) << std::endl << "id2 = "
        << id2.ToStringEncoded(NodeId::kBinary) << std::endl << "min = "
        << std::min(id1, id2).ToStringEncoded(NodeId::kBinary) << std::endl;
    ASSERT_TRUE(id <= std::max(id1, id2)) << "id  = " <<
        id.ToStringEncoded(NodeId::kBinary) << std::endl << "id1 = "
        << id1.ToStringEncoded(NodeId::kBinary) << std::endl << "id2 = "
        << id2.ToStringEncoded(NodeId::kBinary) << std::endl << "max = "
        << std::max(id1, id2).ToStringEncoded(NodeId::kBinary) << std::endl;
  }
  NodeId min_range, max_range(NodeId::kMaxId);
  for (int i = 0; i < kKeySizeBits - 1; ++i) {
    min_range = NodeId(i);
    max_range = NodeId(i + 1);
    id = NodeId(min_range, max_range);
    ASSERT_TRUE(id >= min_range) << "id = " <<
        id.ToStringEncoded(NodeId::kBinary) << std::endl << "min_range = "
        << min_range.ToStringEncoded(NodeId::kBinary) << std::endl;
    ASSERT_TRUE(max_range >= id) << "id = " <<
        id.ToStringEncoded(NodeId::kBinary) << std::endl << "max_range = "
        << max_range.ToStringEncoded(NodeId::kBinary) << std::endl;
  }
}

TEST(TestKadId, BEH_KAD_SplitRange) {
  NodeId min, max1, min1, max(NodeId::kMaxId);
  NodeId::SplitRange(min, max, &max1, &min1);
  std::string exp_min(kKeySizeBits, '0');
  exp_min[0] = '1';
  std::string exp_max(kKeySizeBits, '1');
  exp_max[0] = '0';
  EXPECT_EQ(exp_min, min1.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max1.ToStringEncoded(NodeId::kBinary));

  NodeId min2, max2;
  exp_min[0] = '0';
  exp_min[1] = '1';
  exp_max[1] = '0';
  NodeId::SplitRange(min, max1, &max2, &min2);
  EXPECT_EQ(exp_min, min2.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max2.ToStringEncoded(NodeId::kBinary));

  NodeId min3, max3;
  exp_min[0] = '1';
  exp_max[0] = '1';
  NodeId::SplitRange(min1, max, &max3, &min3);
  EXPECT_EQ(exp_min, min3.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max3.ToStringEncoded(NodeId::kBinary));

  NodeId min4, max4;
  exp_min[1] = '0';
  exp_min[2] = '1';
  exp_max[1] = '0';
  exp_max[2] = '0';
  NodeId::SplitRange(min1, max3, &max4, &min4);
  EXPECT_EQ(exp_min, min4.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max4.ToStringEncoded(NodeId::kBinary));

  NodeId min5, max5;
  exp_min[0] = '0';
  exp_max[0] = '0';
  NodeId::SplitRange(min, max2, &max5, &min5);
  EXPECT_EQ(exp_min, min5.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max5.ToStringEncoded(NodeId::kBinary));

  NodeId min6, max6;
  exp_min[2] = '0';
  exp_min[3] = '1';
  exp_max[3] = '0';
  NodeId::SplitRange(min, max5, &max6, &min6);
  EXPECT_EQ(exp_min, min6.ToStringEncoded(NodeId::kBinary));
  EXPECT_EQ(exp_max, max6.ToStringEncoded(NodeId::kBinary));
}

TEST(TestKadId, BEH_KAD_InsertKadContact) {
  std::vector<Contact> contacts;
  for (char c = '9'; c >= '0'; --c)
    contacts.push_back(Contact(std::string(64, c), "IP", 10000));
  ASSERT_EQ(size_t(10), contacts.size());
  // Copy the vector.
  std::vector<Contact> contacts_before(contacts);
  std::string key(64, 'b');
  NodeId kad_key(key);
  Contact new_contact(std::string(64, 'a'), "IP", 10000);
  InsertKadContact(kad_key, new_contact, &contacts);
  ASSERT_EQ(size_t(11), contacts.size());
  // Check contacts have been re-ordered correctly.
  ASSERT_TRUE(contacts.at(0).node_id() == new_contact.node_id());
  ASSERT_TRUE(contacts.at(1).node_id() == contacts_before.at(7).node_id());
  ASSERT_TRUE(contacts.at(2).node_id() == contacts_before.at(6).node_id());
  ASSERT_TRUE(contacts.at(3).node_id() == contacts_before.at(9).node_id());
  ASSERT_TRUE(contacts.at(4).node_id() == contacts_before.at(8).node_id());
  ASSERT_TRUE(contacts.at(5).node_id() == contacts_before.at(3).node_id());
  ASSERT_TRUE(contacts.at(6).node_id() == contacts_before.at(2).node_id());
  ASSERT_TRUE(contacts.at(7).node_id() == contacts_before.at(5).node_id());
  ASSERT_TRUE(contacts.at(8).node_id() == contacts_before.at(4).node_id());
  ASSERT_TRUE(contacts.at(9).node_id() == contacts_before.at(1).node_id());
  ASSERT_TRUE(contacts.at(10).node_id() == contacts_before.at(0).node_id());
}

TEST(TestKadId, BEH_KAD_OperatorEqual) {
  NodeId kadid1(NodeId::kRandomId);
  std::string id(kadid1.String());
  NodeId kadid2(id);
  ASSERT_TRUE(kadid1 == kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid2 = " <<
      kadid2.ToStringEncoded(NodeId::kBinary) << std::endl;
  std::string id1;
  for (size_t i = 0; i < BitToByteCount(kKeySizeBits) * 2;
       ++i) {
    id1 += "f";
  }
  NodeId kadid3(id1, NodeId::kHex);
  ASSERT_FALSE(kadid1 == kadid3) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorDifferent) {
  NodeId kadid1(NodeId::kRandomId);
  std::string id(kadid1.String());
  NodeId kadid2(id);
  ASSERT_FALSE(kadid1 != kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) <<
      std::endl << "kadid2 = " << kadid2.ToStringEncoded(NodeId::kBinary) <<
      std::endl;
  std::string id1;
  for (size_t i = 0; i < BitToByteCount(kKeySizeBits) * 2; ++i)
    id1 += "f";
  NodeId kadid3(id1, NodeId::kHex);
  ASSERT_TRUE(kadid1 != kadid3) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorGreaterThan) {
  NodeId kadid1(NodeId::kRandomId);
  while (kadid1 == NodeId(NodeId::kMaxId))
    kadid1 = NodeId(NodeId::kRandomId);
  NodeId kadid2(kadid1);
  ASSERT_FALSE(kadid1 > kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid2 = " <<
      kadid2.ToStringEncoded(NodeId::kBinary) << std::endl;
  NodeId kadid3(IncreaseId(kadid1));
  ASSERT_TRUE(kadid3 > kadid1) << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl;
  ASSERT_FALSE(kadid1 > kadid3) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorLessThan) {
  NodeId kadid1(NodeId::kRandomId);
  while (kadid1 == NodeId(NodeId::kMaxId))
    kadid1 = NodeId(NodeId::kRandomId);
  NodeId kadid2(kadid1);
  ASSERT_FALSE(kadid1 < kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid2 = " <<
      kadid2.ToStringEncoded(NodeId::kBinary) << std::endl;
  NodeId kadid3(IncreaseId(kadid1));
  ASSERT_TRUE(kadid1 < kadid3) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl;
  ASSERT_FALSE(kadid3 < kadid1) << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorGreaterEqual) {
  NodeId kadid1(NodeId::kRandomId);
  while (kadid1 == NodeId(NodeId::kMaxId))
    kadid1 = NodeId(NodeId::kRandomId);
  NodeId kadid2(kadid1);
  ASSERT_TRUE(kadid1 >= kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid2 = " <<
      kadid2.ToStringEncoded(NodeId::kBinary) << std::endl;
  NodeId kadid3(IncreaseId(kadid1));
  ASSERT_TRUE(kadid3 >= kadid1) << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorLessEqual) {
  NodeId kadid1(NodeId::kRandomId);
  while (kadid1 == NodeId(NodeId::kMaxId))
    kadid1 = NodeId(NodeId::kRandomId);
  NodeId kadid2(kadid1);
  ASSERT_TRUE(kadid1 <= kadid2) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid2 = " <<
      kadid2.ToStringEncoded(NodeId::kBinary) << std::endl;
  NodeId kadid3(IncreaseId(kadid1));
  ASSERT_TRUE(kadid1 <= kadid3) << "kadid1 = " <<
      kadid1.ToStringEncoded(NodeId::kBinary) << std::endl << "kadid3 = " <<
      kadid3.ToStringEncoded(NodeId::kBinary) << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorXOR) {
  NodeId kadid1(NodeId::kRandomId), kadid2(NodeId::kRandomId);
  NodeId kadid3(kadid1 ^ kadid2);
  std::string binid1(kadid1.ToStringEncoded(NodeId::kBinary));
  std::string binid2(kadid2.ToStringEncoded(NodeId::kBinary));
  std::string binresult;
  for (size_t i = 0; i < binid1.size(); ++i) {
    if (binid1[i] == binid2[i]) {
      binresult += "0";
    } else {
      binresult += "1";
    }
  }
  std::string binzero;
  for (size_t i = 0; i < binid1.size(); ++i)
    binzero += "0";
  ASSERT_NE(binzero, kadid3.ToStringEncoded(NodeId::kBinary));
  ASSERT_EQ(binresult, kadid3.ToStringEncoded(NodeId::kBinary));
  NodeId kadid4(kadid2 ^ kadid1);
  ASSERT_EQ(binresult, kadid4.ToStringEncoded(NodeId::kBinary));
  NodeId kadid5(kadid1.String());
  NodeId kadid6(kadid1 ^ kadid5);
  ASSERT_EQ(binzero, kadid6.ToStringEncoded(NodeId::kBinary));
  std::string zero(kadid6.String());
  ASSERT_EQ(BitToByteCount(kKeySizeBits), zero.size());
  for (size_t i = 0; i < zero.size(); ++i)
    ASSERT_EQ('\0', zero[i]);
}

TEST(TestKadId, BEH_KAD_OperatorEql) {
  NodeId kadid1(NodeId::kRandomId), kadid2;
  kadid2 = kadid1;
  ASSERT_TRUE(kadid1 == kadid2);
  for (size_t i = 0; i < kadid1.String().size(); ++i)
    ASSERT_EQ(kadid1.String()[i], kadid2.String()[i]);
  ASSERT_EQ(kadid1.ToStringEncoded(NodeId::kBinary),
            kadid2.ToStringEncoded(NodeId::kBinary));
  ASSERT_EQ(kadid1.ToStringEncoded(NodeId::kHex),
            kadid2.ToStringEncoded(NodeId::kHex));
  ASSERT_EQ(kadid1.String(), kadid2.String());
}

}  // namespace test_kadid

}  // namespace kademlia
