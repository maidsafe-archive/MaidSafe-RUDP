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

#include <bitset>
#include <memory>

#include "gtest/gtest.h"
#include "boost/lexical_cast.hpp"

#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/routing_table.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/transport/utils.h"

namespace maidsafe {

namespace kademlia {

namespace test {

static const boost::uint16_t k = 16;

class RoutingTableTest : public testing::TestWithParam<int> {
 public:
  RoutingTableTest()
    : rank_info_(),
      holder_id_(NodeId::kRandomId),
      k_(GetParam()),
      routing_table_(holder_id_, k_) {
    contact_ = ComposeContact(NodeId(NodeId::kRandomId), 6101);
  }

  NodeId GenerateUniqueRandomId(const NodeId& holder, const int& pos) {
    std::string holder_id = holder.ToStringEncoded(NodeId::kBinary);
    std::bitset<kKeySizeBits> holder_id_binary_bitset(holder_id);
    NodeId new_node;
    std::string new_node_string;
    bool repeat(true);
    boost::uint16_t times_of_try(0);
    // generate a random ID and make sure it has not been generated previously
    do {
      new_node = NodeId(NodeId::kRandomId);
      std::string new_id = new_node.ToStringEncoded(NodeId::kBinary);
      std::bitset<kKeySizeBits> binary_bitset(new_id);
      for (int i = kKeySizeBits - 1; i >= pos; --i)
        binary_bitset[i] = holder_id_binary_bitset[i];
      binary_bitset[pos].flip();
      new_node_string = binary_bitset.to_string();
      new_node = NodeId(new_node_string, NodeId::kBinary);
      // make sure the new contact not already existed in the routing table
      Contact result;
      routing_table_.GetContact(new_node, &result);
      if (result == Contact())
        repeat = false;
      ++times_of_try;
    } while (repeat && (times_of_try < 1000));
    // prevent deadlock, throw out an error message in case of deadlock
    if (times_of_try == 1000)
      EXPECT_LT(1000, times_of_try);
    return new_node;
  }

 protected:
  void SetUp() {}

  Contact ComposeContact(const NodeId& node_id, boost::uint16_t port) {
    std::string ip("127.0.0.1");
    std::vector<transport::Endpoint> local_endpoints;
    transport::Endpoint end_point(ip, port);
    local_endpoints.push_back(end_point);
    Contact contact(node_id, end_point, local_endpoints, end_point, false,
                    false, "", "", "");
    return contact;
  }

  boost::uint16_t GetKBucketCount() const {
    return routing_table_.KBucketCount();
  }

  boost::uint16_t GetKBucketSizeForKey(const boost::uint16_t &key) {
    return routing_table_.KBucketSizeForKey(key);
  }

  RoutingTableContactsContainer GetContainer() {
    return routing_table_.contacts_;
  }

  size_t GetSize() {
    return routing_table_.Size();
  }

  void Clear() {
    routing_table_.Clear();
  }

  void CallToPrivateFunctions() {
    for (int i = 0; i < k_; ++i) {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, kKeySizeBits - 2);
      Contact contact = ComposeContact(node_id, 5431);
      routing_table_.AddContact(contact, rank_info_);
      EXPECT_EQ(0U, routing_table_.KBucketIndex(contact.node_id()));
    }
    {
      NodeId node_id = GenerateUniqueRandomId(holder_id_, kKeySizeBits - 1);
      Contact contact = ComposeContact(node_id, 4321);
      routing_table_.AddContact(contact, rank_info_);
      Contact contact1 = routing_table_.GetLastSeenContact(0);
      EXPECT_EQ(contact1.node_id(), contact.node_id());
      EXPECT_EQ(2U, routing_table_.KBucketCount());
      EXPECT_EQ(1U, routing_table_.KBucketSizeForKey(0));
    }
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 1);
    Contact contact = ComposeContact(node_id, 4323);
    routing_table_.AddContact(contact, rank_info_);
    boost::uint16_t distance = routing_table_.KDistanceTo(node_id);
    EXPECT_EQ(kKeySizeBits - 2, distance);
  }

  void FillContactToRoutingTable() {
    for (int i = 0; i < k_; ++i) {
      Contact contact = ComposeContact(NodeId(NodeId::kRandomId), i + 6111);
      (i == (k_ -1) ) ? routing_table_.AddContact(contact_, rank_info_) :
          routing_table_.AddContact(contact, rank_info_);
    }
    EXPECT_EQ(k_, GetSize());
  }

  RankInfoPtr rank_info_;
  NodeId holder_id_;
  boost::uint16_t k_;   
  RoutingTable routing_table_;
  Contact contact_;
};

class RoutingTableSingleKTest : public RoutingTableTest {
 public:
  RoutingTableSingleKTest() : RoutingTableTest() {}
};

INSTANTIATE_TEST_CASE_P(VariantKValues, RoutingTableTest,
                        testing::Range(2,21));

INSTANTIATE_TEST_CASE_P(SingleKValue, RoutingTableSingleKTest,
                        testing::Values(2,16));

TEST_P(RoutingTableTest, BEH_KAD_CallToPrivateFunctions) {
  // Test Private member functions (GetLastSeenContact)
  // (kBucketIndex) (KBucketCount) (KbucketSizeForKey) (KDistanceTo)
  this->CallToPrivateFunctions();
}

TEST_P(RoutingTableTest, BEH_KAD_Constructor) {
  ASSERT_EQ(0U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_KAD_Clear) {
  // create a contact and add it into the routing table
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  routing_table_.AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetSize());

  // Try to clear the routing table
  Clear();
  ASSERT_EQ(0U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());

  // Try to add the contact again
  routing_table_.AddContact(contact, rank_info_);
  ASSERT_EQ(1U, GetSize());
  ASSERT_EQ(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_KAD_GetContact) {
  // create a contact and add it into the routing table
  NodeId contact_id(NodeId::kRandomId);
  Contact contact = ComposeContact(contact_id, 5001);
  routing_table_.AddContact(contact, rank_info_);

  // Try to get an exist contact
  Contact result;
  routing_table_.GetContact(contact_id, &result);
  ASSERT_EQ(contact_id, result.node_id());

  // Try to get a non-exist contact
  Contact non_exist_result;
  NodeId non_exist_contact_id(NodeId::kRandomId);
  routing_table_.GetContact(non_exist_contact_id, &non_exist_result);
  ASSERT_EQ(non_exist_result, Contact());

  // Try to overload with an exist contact
  routing_table_.GetContact(contact_id, &non_exist_result);
  ASSERT_NE(non_exist_result, Contact());
}

TEST_P(RoutingTableTest, BEH_KAD_AddContactForRandomCommonLeadingBits) {
  // Compose contact with random common_leading_bits
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_,
                                            511 - (RandomUint32() % 511));
    Contact contact = ComposeContact(node_id, 5111 + i);
    routing_table_.AddContact(contact, rank_info_);
  }

  NodeId node_id = GenerateUniqueRandomId(holder_id_, 511 - 9);
  Contact contact = ComposeContact(node_id, 5113);
  routing_table_.AddContact(contact, rank_info_);
  boost::uint16_t num_of_contacts(0);
  for (int i = 0; i < GetKBucketCount(); ++i) {
    boost::uint16_t contacts_in_bucket = GetKBucketSizeForKey(i);
    EXPECT_GE(k_, contacts_in_bucket);
    num_of_contacts += contacts_in_bucket;
  }
  EXPECT_EQ(num_of_contacts, GetSize());
  EXPECT_LT(1U, GetKBucketCount());
}

TEST_P(RoutingTableTest, BEH_KAD_AddContactForHigherCommonLeadingBits) {
  // GenerateUniqueRandomId will flip the bit specified by the position
  // so the i=0 one will be the different to the holderId
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, i);
    Contact contact = ComposeContact(node_id, 5111 + i);
    routing_table_.AddContact(contact, rank_info_);
  }

  NodeId node_id = GenerateUniqueRandomId(holder_id_, 9);
  Contact contact = ComposeContact(node_id, 5113);
  routing_table_.AddContact(contact, rank_info_);
  EXPECT_EQ(k_ + 1, GetSize());
  boost::uint16_t expected_kbucket_count = kKeySizeBits - (k_ - 2);
  if (k_ <= 9 )
    expected_kbucket_count = kKeySizeBits - 9 + 1;
  EXPECT_EQ(expected_kbucket_count, GetKBucketCount());
}

TEST_P(RoutingTableSingleKTest, FUNC_KAD_ForceKAcceptNewPeer) {
  // As this test is not multi-threaded, for convenience we can safely use an
  // upgrade lock on a shared mutex which isn't the routing table's member mutex
  boost::shared_mutex shared_mutex;
  std::shared_ptr<boost::upgrade_lock<boost::shared_mutex>> upgrade_lock(
      new boost::upgrade_lock<boost::shared_mutex>(shared_mutex));

  for (int i = 0; i < k_ - 1; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(node_id, 5333);
    routing_table_.AddContact(contact, rank_info_);
  }
  {
    RankInfoPtr rank_info;
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(node_id, 5337);

    boost::int16_t result =
        routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info, upgrade_lock);
    EXPECT_EQ(boost::int16_t(-3), result);
  }
  Clear();
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(node_id, 5333);
    routing_table_.AddContact(contact, rank_info_);
  }
  for (int i = 0; i < k_; ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5333);
    routing_table_.AddContact(contact, rank_info_);
  }
  {
    EXPECT_EQ(2U, GetKBucketCount());
    EXPECT_EQ(k_ * 2, GetSize());
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    boost::int16_t force_result =
        routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info, upgrade_lock);
    EXPECT_EQ(boost::int16_t(-2), force_result);
  }
  // When new contact not exist in brother_bucket

  for (int i = 0; i < (k_ - 1); ++i) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 509);
    Contact contact = ComposeContact(node_id, 5333);
    routing_table_.AddContact(contact, rank_info_);
  }
  {
    EXPECT_EQ(3U, GetKBucketCount());
    EXPECT_EQ(k_ * 2 + (k_ - 1), GetSize());
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 511);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    boost::int16_t force_result =
        routing_table_.ForceKAcceptNewPeer(contact, 0, rank_info, upgrade_lock);
    EXPECT_EQ(boost::int16_t(-3), force_result);
  }
  boost::uint16_t retry(0);
  while (retry < 10000) {
    NodeId node_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(node_id, 5678);
    RankInfoPtr rank_info;
    auto pit =
        routing_table_.contacts_.get<KBucketDistanceToThisIdTag>().equal_range(
        boost::make_tuple(1));
    auto it_end = pit.second;
    --it_end;
    NodeId furthest_distance = (*it_end).distance_to_this_id;
    NodeId distance_to_node = routing_table_.kThisId_ ^ node_id;
    if (distance_to_node >= furthest_distance) {
      boost::int16_t force_result = routing_table_.ForceKAcceptNewPeer(
          contact, 1, rank_info, upgrade_lock);
      EXPECT_EQ(boost::int16_t(-4), force_result);
    } else {
      boost::int16_t force_result = routing_table_.ForceKAcceptNewPeer(
        contact, 1, rank_info, upgrade_lock);
      EXPECT_EQ(boost::int16_t(0), force_result);
    }
    ++retry;
  }
}

TEST_P(RoutingTableTest, BEH_KAD_AddContact) {
  {
    // try to add the holder itself into the routing table
    Contact contact = ComposeContact(holder_id_, 5000);
    routing_table_.AddContact(contact, rank_info_);
    EXPECT_EQ(0U, GetSize());
    EXPECT_EQ(1U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
  }
  {
    // Test update NumFailedRpc and LastSeen when new contact already exists
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);
    routing_table_.IncrementFailedRpcCount(contact_id);
    bptime::ptime old_last_seen = (*(GetContainer().get<NodeIdTag>().find(
        contact_.node_id()))).last_seen;
    ASSERT_EQ(1U, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).num_failed_rpcs);
    routing_table_.AddContact(contact, rank_info_);
    ASSERT_EQ(0U, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).num_failed_rpcs);
    ASSERT_NE(old_last_seen, (*(GetContainer().get<NodeIdTag>().find(
        contact_id))).last_seen);
  }
  Clear();
  boost::uint16_t i(0);
  {
    // create a list contacts having 3 common leading bits with the holder
    // and add them into the routing table
    for (; i < k_; ++i) {
      EXPECT_EQ(i, GetSize());
      EXPECT_EQ(1U, GetKBucketCount());
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(contact_id, (5000 + i));
      routing_table_.AddContact(contact, rank_info_);
    }
    EXPECT_EQ(k_, GetKBucketSizeForKey(0));
  }

  {
    // Test Split Bucket
    // create a contact having 1 common leading bits with the holder
    // and add it into the routing table
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 510);
    Contact contact = ComposeContact(contact_id, 5000 + i);
    routing_table_.AddContact(contact, rank_info_);
    ++i;
    EXPECT_EQ(i, GetSize());

    // all 16 contacts having 3 common leading bits sit in the kbucket
    // covering 2-512
    EXPECT_EQ(3U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
    EXPECT_EQ(1U, GetKBucketSizeForKey(1));
    EXPECT_EQ(k_, GetKBucketSizeForKey(2));
  }

  {
    // Test Split Bucket Advanced
    // create a contact having 4 common leading bits with the holder
    // and add it into the routing table
    NodeId contact_id = GenerateUniqueRandomId(holder_id_, 507);
    Contact contact = ComposeContact(contact_id, 5000 + i);
    routing_table_.AddContact(contact, rank_info_);
    ++i;
    EXPECT_EQ(i, GetSize());
    // all 16 contacts having 3 common leading bits sit in the kbucket
    // covering 3-3 now
    // an additonal kbucket covering 2-2 is now created
    EXPECT_EQ(5U, GetKBucketCount());
    EXPECT_EQ(0U, GetKBucketSizeForKey(0));
    EXPECT_EQ(1U, GetKBucketSizeForKey(1));
    EXPECT_EQ(0U, GetKBucketSizeForKey(2));
    EXPECT_EQ(k_, GetKBucketSizeForKey(3));
    EXPECT_EQ(1U, GetKBucketSizeForKey(4));
  }

  {
    // Test ForceK, reject and accept will be tested
    // create a contact having 3 common leading bits with the holder
    // and add it into the routing table
    // this contact shall be now attempting to add into the brother buckets
    // it shall be added (replace a previous one) if close enough or be rejected
    bool replaced(false);
    bool not_replaced(false);
    // To prevent test hanging
    boost::uint32_t times_of_try(0);
    while (((!not_replaced) || (!replaced)) && (times_of_try < 60000)) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 508);
      Contact contact = ComposeContact(contact_id, (5000 + i + times_of_try));
      routing_table_.AddContact(contact, rank_info_);
      EXPECT_EQ(i, GetSize());
      EXPECT_EQ(5U, GetKBucketCount());

      Contact result;
      routing_table_.GetContact(contact_id, &result);
      // Make sure both replace and reject situation covered in ForceK sim test
      if (result != Contact()) {
        replaced = true;
      } else {
        not_replaced = true;
      }
      ++times_of_try;
    }
    ASSERT_GT(60000, times_of_try);
  }
}

TEST_P(RoutingTableSingleKTest, FUNC_KAD_AddContactPerformanceMaxFullFill) {
  // the last four common bits will not split kbucket
  for (int common_head = 0; common_head < 500; ++common_head) {
    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 511 - common_head);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    EXPECT_EQ(((common_head + 1) * k_), GetSize());
    EXPECT_EQ((common_head + 1), GetKBucketCount());
  }
}

TEST_P(RoutingTableSingleKTest, FUNC_KAD_AddContactPerformance8000RandomFill) {
  for (int num_contact = 0; num_contact < 8000; ++num_contact) {
    NodeId contact_id(NodeId::kRandomId);
    Contact contact = ComposeContact(contact_id, 5000);
    routing_table_.AddContact(contact, rank_info_);

    boost::uint32_t contacts_in_table(0);
    for (int i = 0; i < GetKBucketCount(); ++i) {
      boost::uint32_t contacts_in_bucket = GetKBucketSizeForKey(i);
      ASSERT_GE(k_, contacts_in_bucket);
      contacts_in_table += contacts_in_bucket;
    }
    EXPECT_EQ(contacts_in_table, GetSize());
  }
}

TEST_P(RoutingTableTest, BEH_KAD_GetContactsClosestToOwnId) {
  {
    // try to get close contacts from an empty routing table
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetContactsClosestToOwnId(1, exclude_contacts,
                                   &close_contacts);
    EXPECT_EQ(0U, close_contacts.size());
  }

  {
    // try to get k close contacts from an k/2 filled routing table
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    EXPECT_EQ(k_ / 2, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetContactsClosestToOwnId(k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Clear();
  {
    // try to get k close contacts from a k+1 filled routing table
    for (int num_contact = 0; num_contact < (k_ - 1); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    routing_table_.AddContact(contact_close, rank_info_);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    routing_table_.AddContact(contact_furthest, rank_info_);
    EXPECT_EQ(k_ + 1, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetContactsClosestToOwnId(k_, exclude_contacts,
                                             &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
  }
  Clear();
  {
    // try to get k close contacts from a k+2 filled routing table,
    // with one defined exception contact
    for (int num_contact = 0; num_contact < (k_ - 1); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    routing_table_.AddContact(contact_close, rank_info_);
    NodeId contact_id_exclude = GenerateUniqueRandomId(holder_id_, 499);
    Contact contact_exclude = ComposeContact(contact_id_exclude, 5000);
    routing_table_.AddContact(contact_exclude, rank_info_);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    routing_table_.AddContact(contact_furthest, rank_info_);
    EXPECT_EQ(k_ + 2, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    exclude_contacts.push_back(contact_exclude);
    routing_table_.GetContactsClosestToOwnId(k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_exclude));
  }
}

TEST_P(RoutingTableTest, BEH_KAD_GetCloseContacts) {
  NodeId target_id = GenerateUniqueRandomId(holder_id_, 500);
  {
    // try to get close contacts from an empty routing table
    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, 1, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(0U, close_contacts.size());
  }

  {
    // try to get k close contacts from an k/2 filled routing table
    for (int num_contact = 0; num_contact < (k_ / 2); ++num_contact) {
      NodeId contact_id(NodeId::kRandomId);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    EXPECT_EQ(k_ / 2, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_ / 2, close_contacts.size());
  }
  Clear();
  {
    // try to get k close contacts from a k+1 filled routing table
    for (int num_contact = 0; num_contact < (k_ - 1); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    routing_table_.AddContact(contact_close, rank_info_);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    routing_table_.AddContact(contact_furthest, rank_info_);
    EXPECT_EQ(k_ + 1, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
  }
  Clear();
  {
    // try to get k close contacts from a k+1 filled routing table,
    // with one defined exception contact
    for (int num_contact = 0; num_contact < (k_ - 2); ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 500);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
    }
    NodeId contact_id_close = GenerateUniqueRandomId(holder_id_, 500);
    Contact contact_close = ComposeContact(contact_id_close, 5000);
    routing_table_.AddContact(contact_close, rank_info_);
    NodeId contact_id_exclude = GenerateUniqueRandomId(holder_id_, 499);
    Contact contact_exclude = ComposeContact(contact_id_exclude, 5000);
    routing_table_.AddContact(contact_exclude, rank_info_);
    NodeId contact_id_furthest = GenerateUniqueRandomId(holder_id_, 501);
    Contact contact_furthest = ComposeContact(contact_id_furthest, 5000);
    routing_table_.AddContact(contact_furthest, rank_info_);
    EXPECT_EQ(k_ + 1, GetSize());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    exclude_contacts.push_back(contact_exclude);
    routing_table_.GetCloseContacts(target_id, k_, exclude_contacts,
                                    &close_contacts);
    EXPECT_EQ(k_, close_contacts.size());
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_close));
    ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_furthest));
    ASSERT_EQ(close_contacts.end(), std::find(close_contacts.begin(),
                                              close_contacts.end(),
                                              contact_exclude));
  }
  Clear();
  {
    // try to get k+21 close_contacts from a distributed filled routing_table
    // with one bucket contains k contacts having 111 common leading bits
    // and 16 buckets contains 2 contacts each, having 0-15 common leading bits

    // Initialize a routing table having the target to be the holder
    NodeId target_id = GenerateUniqueRandomId(holder_id_, 505);
    RoutingTableContactsContainer target_routingtable;

    for (int num_contact = 0; num_contact < k_; ++num_contact) {
      NodeId contact_id = GenerateUniqueRandomId(holder_id_, 400);
      Contact contact = ComposeContact(contact_id, 5000);
      routing_table_.AddContact(contact, rank_info_);
      RoutingTableContact new_contact(contact, target_id, 0);
      target_routingtable.insert(new_contact);
    }

    for (int common_head = 0; common_head < 16; ++common_head) {
      for (int num_contact = 0; num_contact < 2; ++num_contact) {
        NodeId contact_id = GenerateUniqueRandomId(holder_id_,
                                                   511 - common_head);
        Contact contact = ComposeContact(contact_id, 5000);
        routing_table_.AddContact(contact, rank_info_);
        RoutingTableContact new_contact(contact, target_id, 0);
        target_routingtable.insert(new_contact);
      }
    }
    EXPECT_EQ(k_ + (16 * 2), GetSize());
    EXPECT_EQ(17U, GetKBucketCount());
    EXPECT_EQ(k_ + (16 * 2), target_routingtable.size());

    std::vector<Contact> close_contacts;
    std::vector<Contact> exclude_contacts;
    // make sure the target_id in the exclude_contacts list
    exclude_contacts.push_back(ComposeContact(target_id, 5000));

    routing_table_.GetCloseContacts(target_id, k_ + 21,
                                               exclude_contacts,
                                               &close_contacts);
    EXPECT_EQ(k_ + 21, close_contacts.size());

    ContactsByDistanceToThisId key_dist_indx
      = target_routingtable.get<DistanceToThisIdTag>();
    boost::uint32_t counter(0);
    auto it = key_dist_indx.begin();
    while ((counter < (k_ + 21)) && (it != key_dist_indx.end())) {
      ASSERT_NE(close_contacts.end(), std::find(close_contacts.begin(),
                                                close_contacts.end(),
                                                (*it).contact));
      // std::cout<<(*it).contact.node_id().ToStringEncoded(NodeId::kBinary)
      // <<std::endl;
      ++counter;
      ++it;
    }
  }
}

TEST_P(RoutingTableTest, BEH_KAD_SetPublicKey) {
  this->FillContactToRoutingTable();
  std::string new_public_key(RandomString(113));
  EXPECT_EQ(-1, routing_table_.SetPublicKey(NodeId(NodeId::kRandomId),
                                            new_public_key));
  EXPECT_NE(new_public_key , (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).public_key);
  ASSERT_EQ(0, routing_table_.SetPublicKey(contact_.node_id(),
                                           new_public_key));
  ASSERT_EQ(new_public_key , (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).public_key);
}

TEST_P(RoutingTableTest, BEH_KAD_UpdateRankInfo) {
  this->FillContactToRoutingTable();
  RankInfoPtr new_rank_info(new(transport::Info));
  new_rank_info->rtt = 13313;
  EXPECT_EQ(-1, routing_table_.UpdateRankInfo(NodeId(NodeId::kRandomId),
                                              new_rank_info));
  ASSERT_EQ(0, routing_table_.UpdateRankInfo(contact_.node_id(),
                                             new_rank_info));
  ASSERT_EQ(new_rank_info->rtt, (*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).rank_info->rtt);
}

TEST_P(RoutingTableTest, BEH_KAD_SetPreferredEndpoint) {
  this->FillContactToRoutingTable();
  IP ip = IP::from_string("127.0.0.1");
  EXPECT_EQ(-1, routing_table_.SetPreferredEndpoint(NodeId(NodeId::kRandomId),
                                                    ip));
  ASSERT_EQ(0, routing_table_.SetPreferredEndpoint(contact_.node_id(), ip));
  ASSERT_EQ(ip, (*(GetContainer().get<NodeIdTag>().find(
    contact_.node_id()))).contact.PreferredEndpoint().ip);
}

TEST_P(RoutingTableTest, BEH_KAD_IncrementFailedRpcCount) {
  this->FillContactToRoutingTable();
  EXPECT_EQ(-1, routing_table_.IncrementFailedRpcCount(
      NodeId(NodeId::kRandomId)));
  EXPECT_EQ(boost::uint16_t(0), (*(GetContainer().get<NodeIdTag>().find(
     contact_.node_id()))).num_failed_rpcs);
  ASSERT_EQ((*(GetContainer().get<NodeIdTag>().find(
      contact_.node_id()))).num_failed_rpcs,
      routing_table_.IncrementFailedRpcCount(contact_.node_id()));
  {
    // keep increasing one contact's failed RPC counter
    // till it gets removed
    size_t ori_size = GetSize();
    boost::uint16_t times_of_try = 0;
    do {
      ++times_of_try;
    } while ((routing_table_.IncrementFailedRpcCount(contact_.node_id()) != -1)
              && (times_of_try <= (kFailedRpcTolerance + 5)));
    // prevent deadlock
    if (times_of_try == (kFailedRpcTolerance + 5)) {
      FAIL();
    } else {
      ASSERT_EQ(ori_size-1, GetSize());
    }
  }
}

TEST_P(RoutingTableTest, BEH_KAD_GetBootstrapContacts) {
  this->FillContactToRoutingTable();
  std::vector<Contact> contacts;
  routing_table_.GetBootstrapContacts(&contacts);
  EXPECT_EQ(k_, contacts.size());
  EXPECT_EQ(contact_.node_id(),
            (std::find(contacts.begin(), contacts.end(), contact_))->node_id());
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
