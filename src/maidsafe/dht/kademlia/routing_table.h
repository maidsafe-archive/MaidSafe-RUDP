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

#ifndef MAIDSAFE_DHT_KADEMLIA_ROUTING_TABLE_H_
#define MAIDSAFE_DHT_KADEMLIA_ROUTING_TABLE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"

#ifdef __MSVC__
#pragma warning(push)
#pragma warning(disable:4512)
#endif
#include "boost/signals2/signal.hpp"
#ifdef __MSVC__
#pragma warning(pop)
#endif

#include "boost/lambda/lambda.hpp"
#include "boost/lambda/bind.hpp"
#include "boost/lambda/if.hpp"
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/mem_fun.hpp"
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"

#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/node_id.h"

namespace bptime = boost::posix_time;
namespace bmi = boost::multi_index;

namespace maidsafe {

namespace dht {

namespace transport { struct Info; }

namespace kademlia {

namespace test {
class RoutingTableTest;
class RoutingTableSingleKTest;
class RoutingTableTest_BEH_KAD_GetContactsClosestToOwnId_Test;
class RoutingTableSingleKTest_FUNC_KAD_ForceKAcceptNewPeer_Test;
class ServicesTest;
class RoutingTableSingleKTest_BEH_KAD_MutexTestWithMultipleThread_Test;
}  // namespace test

class KBucket;


struct RoutingTableContact {
  RoutingTableContact(const Contact &contact,
                      const NodeId &holder_id,
                      const RankInfoPtr &rank_info,
                      boost::uint16_t common_leading_bits)
      : contact(contact),
        node_id(contact.node_id()),
        public_key(),
        num_failed_rpcs(0),
        distance_to_this_id(holder_id ^ contact.node_id()),
        common_leading_bits(common_leading_bits),
        kbucket_index(0),
        last_seen(bptime::microsec_clock::universal_time()),
        rank_info(rank_info) {}
  RoutingTableContact(const Contact &contact,
                      const NodeId &holder_id,
                      boost::uint16_t common_leading_bits)
      : contact(contact),
        node_id(contact.node_id()),
        public_key(),
        num_failed_rpcs(0),
        distance_to_this_id(holder_id ^ contact.node_id()),
        common_leading_bits(common_leading_bits),
        kbucket_index(0),
        last_seen(bptime::microsec_clock::universal_time()),
        rank_info() {}
  RoutingTableContact(const RoutingTableContact &other)
      : contact(other.contact),
        node_id(other.node_id),
        public_key(other.public_key),
        num_failed_rpcs(other.num_failed_rpcs),
        distance_to_this_id(other.distance_to_this_id),
        common_leading_bits(other.common_leading_bits),
        kbucket_index(other.kbucket_index),
        last_seen(other.last_seen),
        rank_info(other.rank_info) {}
  bool DirectConnected() const {
    return contact.IsDirectlyConnected();
  }
  bool operator<(const RoutingTableContact &other) const {
    return contact < other.contact;
  }
  Contact contact;
  NodeId node_id;
  std::string public_key;
  boost::uint16_t num_failed_rpcs;
  NodeId distance_to_this_id;
  boost::uint16_t common_leading_bits;
  // the index of the kbucket which is responsible for the contact
  boost::uint16_t kbucket_index;
  bptime::ptime last_seen;
  RankInfoPtr rank_info;
};

struct ChangeContact {
  explicit ChangeContact(const Contact &contact) : contact(contact) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.contact = contact;
  }
  Contact contact;
};

struct ChangeKBucketIndex {
  explicit ChangeKBucketIndex(const boost::uint16_t &new_kbucket_index)
      : new_kbucket_index(new_kbucket_index) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.kbucket_index = new_kbucket_index;
  }
  boost::uint16_t new_kbucket_index;
};

struct ChangePublicKey {
  explicit ChangePublicKey(const std::string &new_public_key)
      : new_public_key(new_public_key) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.public_key = new_public_key;
  }
  std::string new_public_key;
};

struct ChangeRankInfo {
  explicit ChangeRankInfo(RankInfoPtr new_rank_info)
      : new_rank_info(new_rank_info) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.rank_info = new_rank_info;
  }
  RankInfoPtr new_rank_info;
};

struct ChangeNumFailedRpc {
  explicit ChangeNumFailedRpc(const boost::uint16_t &new_num_failed_rpcs)
      : new_num_failed_rpcs(new_num_failed_rpcs) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.num_failed_rpcs = new_num_failed_rpcs;
  }
  boost::uint16_t new_num_failed_rpcs;
};

struct ChangeLastSeen {
  explicit ChangeLastSeen(const bptime::ptime &new_last_seen)
      : new_last_seen(new_last_seen) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) {  // NOLINT
    routing_table_contact.last_seen = new_last_seen;
    routing_table_contact.num_failed_rpcs = 0;
  }
  bptime::ptime new_last_seen;
};

struct NodeIdTag;
struct DistanceToThisIdTag;
struct KBucketTag;
struct KBucketLastSeenTag;
struct KBucketDistanceToThisIdTag;
struct TimeLastSeenTag;
struct BootstrapTag;

// Struct to allow initialisation of RoutingTableContactsContainer to accept
// this node's ID as a parameter.
struct KadCloserToThisId {
  explicit KadCloserToThisId(const NodeId &id) : this_id(id) {}
  bool operator()(const RoutingTableContact &x,
                  const RoutingTableContact &y) const {
    return NodeId::CloserToTarget(x.node_id, y.node_id, this_id);
  }
  NodeId this_id;
};

typedef boost::multi_index_container<
  RoutingTableContact,
  bmi::indexed_by<
    bmi::ordered_unique<
      bmi::tag<NodeIdTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact, NodeId, node_id)
    >,
    bmi::ordered_non_unique<
      bmi::tag<DistanceToThisIdTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                               NodeId, distance_to_this_id)
    >,
    bmi::ordered_non_unique<
      bmi::tag<KBucketTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                               boost::uint16_t, kbucket_index)
    >,
    bmi::ordered_non_unique<
      bmi::tag<KBucketLastSeenTag>,
      bmi::composite_key<
        RoutingTableContact,
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                                 boost::uint16_t, kbucket_index),
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                                 bptime::ptime, last_seen)
      >
    >,
    bmi::ordered_non_unique<
      bmi::tag<KBucketDistanceToThisIdTag>,
      bmi::composite_key<
        RoutingTableContact,
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                                 boost::uint16_t, kbucket_index),
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact,
                                 NodeId, distance_to_this_id)
      >
    >,
    bmi::ordered_non_unique<
      bmi::tag<TimeLastSeenTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact, bptime::ptime, last_seen)
    >,
    bmi::ordered_non_unique<
      bmi::tag<BootstrapTag>,
      bmi::const_mem_fun<RoutingTableContact, bool,
                         &RoutingTableContact::DirectConnected>
    >
  >
> RoutingTableContactsContainer;

typedef RoutingTableContactsContainer::index<NodeIdTag>::type& ContactsById;
typedef RoutingTableContactsContainer::index<DistanceToThisIdTag>::type&
    ContactsByDistanceToThisId;

struct UnValidatedContact {
  UnValidatedContact(const Contact &contact,
                     const RankInfoPtr &rank_info)
      : contact(contact), node_id(contact.node_id()), rank_info(rank_info) {}

  Contact contact;
  NodeId node_id;
  RankInfoPtr rank_info;
};

typedef boost::multi_index_container<
  UnValidatedContact,
  bmi::indexed_by<
    bmi::ordered_unique<
      bmi::tag<NodeIdTag>,
      boost::multi_index::member<UnValidatedContact, NodeId,
          &UnValidatedContact::node_id>
    >
  >
> UnValidatedContactsContainer;

typedef UnValidatedContactsContainer::index<NodeIdTag>::type&
        UnValidatedContactsById;


typedef std::shared_ptr<boost::signals2::signal<void(const Contact&,
                                                     const Contact&,
                                                     RankInfoPtr)>>
        PingOldestContactPtr;

typedef std::shared_ptr<boost::signals2::signal<void(const Contact&)>>
        ValidateContactPtr;

/** Object containing a node's Kademlia Routing Table and all its contacts.
 *  @class RoutingTable */
class RoutingTable {
 public:
  /** Constructor.  To create a routing table, in all cases the node ID and
   *  k closest contacts parameter must be provided.
   *  @param[in] this_id The routing table holder's Kademlia ID.
   *  @param[in] k k closest contacts. */
  RoutingTable(const NodeId &this_id, const boost::uint16_t &k);
  /** Destructor. */
  ~RoutingTable();
  /** Add the given contact to the correct k-bucket; if it already
   *  exists, its status will be updated.  If the given k-bucket is full and not
   *  splittable, the signal ping_oldest_contact_ will be fired which will
   *  ultimately resolve whether the contact is added or not.
   *  @param[in] contact The new contact which needs to be added.
   *  @param[in] rank_info The contact's rank_info. */
  void AddContact(const Contact &contact, RankInfoPtr rank_info);
  /** Get the info of the contact based on the input Kademlia ID.
   *  @param[in] node_id The input Kademlia ID.
   *  @param[out] contact the return contact. */
  void GetContact(const NodeId &node_id, Contact *contact);
  /** Finds a number of known nodes closest to the target node in the current
   *  routing table.
   *  NOTE: unless for special purpose, the target shall be considered to be
   *  always put into the exclude_contacts list.
   *  @param[in] target_id The Kademlia ID of the target node.
   *  @param[in] count Number of closest nodes looking for.
   *  @param[in] exclude_contacts List of contacts that shall be excluded.
   *  @param[out] close_contacts Result of the find closest contacts. */
  void GetCloseContacts(const NodeId &target_id,
                        const size_t &count,
                        const std::vector<Contact> &exclude_contacts,
                        std::vector<Contact> *close_contacts);
  /** Finds a number of known nodes closest to the holder node in the current
   *  routing table.
   *  @param[in] count Number of closest nodes looking for.
   *  @param[in] exclude_contacts List of contacts that shall be excluded.
   *  @param[out] close_contacts Result of the find closest contacts. */
  void GetContactsClosestToOwnId(const size_t &count,
                                 const std::vector<Contact> &exclude_contacts,
                                 std::vector<Contact> *close_contacts);
  /** Set one node's public key.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] new_public_key The new value of the public key.
   *  @return Error code, 0 for success, -1 for failure */
  int SetPublicKey(const NodeId &node_id, const std::string &new_public_key);
  /** Update one node's rank info.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] rank_info The new value of the rank info.
   *  @return Error code, 0 for success, -1 for failure */
  int UpdateRankInfo(const NodeId &node_id, RankInfoPtr rank_info);
  /** Set one node's preferred endpoint.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] ip The new preferred endpoint.
   *  @return Error code, 0 for success, -1 for failure */
  int SetPreferredEndpoint(const NodeId &node_id, const IP &ip);
  /** Set one node's validation status.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] validated The validation status.
   *  @return Error code, 0 for success, -1 for failure */
  int SetValidated(const NodeId &node_id, bool validated);
  /** Increase one node's failedRPC counter by one.  If the count exceeds the
   *  value of kFailedRpcTolerance, the contact is removed from the routing
   *  table.
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @return The value of the contact's current failed RPC count.  If the
   *  contact has been removed, the value will be kFailedRpcTolerance + 1.  If
   *  operation fails, the value will be -1. */
  int IncrementFailedRpcCount(const NodeId &node_id);
  /** Get the routing table holder's direct-connected nodes.
   *  For a direct-connected node, there must be no rendezvous endpoint,
   *  but either of tcp443 or tcp80 may be true.
   *  @param[out] contacts The result of all directly connected contacts. */
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  /** Get the local RankInfo of the contact
   *  @param[in] contact The contact to find
   *  @return The localRankInfo of the contact */
  RankInfoPtr GetLocalRankInfo(const Contact &contact);
  /** Get all contacts in the routing table
   *  @param[out] contacts All contacts in the routing table */
  void GetAllContacts(std::vector<Contact> *contacts);
  /** Getter.
   *  @return The ping_oldest_contact_ signal. */
  PingOldestContactPtr ping_oldest_contact();
  /** Getter.
   *  @return The validate_contact_ signal. */
  ValidateContactPtr validate_contact();

  friend class test::RoutingTableTest;
  friend class test::RoutingTableSingleKTest;
  friend class test::RoutingTableTest_BEH_KAD_GetContactsClosestToOwnId_Test;
  friend class test::RoutingTableSingleKTest_FUNC_KAD_ForceKAcceptNewPeer_Test;
  friend class test::ServicesTest;
  friend class test::RoutingTableSingleKTest_BEH_KAD_MutexTestWithMultipleThread_Test; // NOLINT
 private:
  typedef boost::shared_lock<boost::shared_mutex> SharedLock;
  typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
  typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
  typedef boost::upgrade_to_unique_lock<boost::shared_mutex>
      UpgradeToUniqueLock;
  /** Return the contact which is the lastseen on in the target kbucket.
   *  @param[in] kbucket_index The index of the kbucket.
   *  @return The last seend contact in the kbucket. */
  Contact GetLastSeenContact(const boost::uint16_t &kbucket_index);
  /** Calculate the index of the k-bucket which is responsible for
   *  the specified key (or ID).
   *  @param[in] key The Kademlia ID of the target node.
   *  @return The index of the k-bucket which is in responsible. */
  boost::uint16_t KBucketIndex(const NodeId &key);
  /** Calculate the index of the k-bucket which is responsible for
   *  the specified common_heading_bits.
   *  @param[in] common_heading_bits The common_heading_bits the target node.
   *  @return The index of the k-bucket which is in responsible. */
  boost::uint16_t KBucketIndex(const boost::uint16_t &common_heading_bits);
  /** Getter.
   *  @return Num of kbuckets in the routing table. */
  boost::uint16_t KBucketCount() const;
  /** Get the number of contacts in a specified kbucket
   *  @param[in] key The index of the target k-bucket.
   *  @return Num of contacts in the specified kbucket */
  boost::uint16_t KBucketSizeForKey(const boost::uint16_t &key);
  /** Insert a contact into the routing table.
   *  @param[in] contact The new contact which needs to be added
   *  @param[in] rank_info The contact's rank_info
   *  @param[in] upgrade_lock An UpgradeLock held on shared_mutex_ */
  void InsertContact(const Contact &contact,
                     RankInfoPtr rank_info,
                     std::shared_ptr<UpgradeLock> upgrade_lock);
  /** Bisect the k-bucket into two new ones.
   *  @param[in] upgrade_lock An UpgradeLock held on shared_mutex_ */
  void SplitKbucket(std::shared_ptr<UpgradeLock> upgrade_lock);
  /** Forces the brother k-bucket of the holder to accept a new contact which
   *  would normally be dropped if it is within the k closest contacts to the
   *  holder's ID.
   *  @param[in] new_contact The new contact needs to be added.
   *  @param[in] target_bucket The kbucket shall in responsible of the new
   *  contact
   *  @param[in] upgrade_lock An UpgradeLock held on shared_mutex_
   *  @return Error Code:   0  for succeed,
   *                       -1  for No brother bucket
   *                       -2  for v==0
   *                       -3  for Not in Brother Bucket
   *                       -4  for New peer isn't among the k closest */
  int ForceKAcceptNewPeer(const Contact &new_contact,
                          const boost::uint16_t &target_bucket,
                          RankInfoPtr rank_info,
                          std::shared_ptr<UpgradeLock> upgrade_lock);
  /** XOR KBucket distance between two kademlia IDs.
   *  Measured by the number of common leading bits.
   *  The less the value is, the further the distance (the wider range) is.
   *  @param[in] rhs NodeId to which this is XOR
   *  @return the number of common bits from the beginning */
  boost::uint16_t KDistanceTo(const NodeId &rhs) const;
  int GetLeastCommonHeadingBitInKClosestContact();

  /** Getter.
   *  @return Num of contacts in the routing table. */
  size_t Size();
  /** Empty the routing table */
  void Clear();

  /** Holder's Kademlia ID */
  const NodeId kThisId_;
  /** Kademlia k */
  const boost::uint16_t k_;
  /** Multi_index container of all contacts */
  RoutingTableContactsContainer contacts_;
  /** Container of all un-validated contacts */
  UnValidatedContactsContainer unvalidated_contacts_;
  /** Signal to be fired when k-bucket is full and cannot be split.  In signal
   *  signature, last-seen contact is first, then new contact and new contact's
   *  rank info.  Slot should ping the old contact and if successful, should
   *  call AddContact for the old contact, or if unsuccessful, should call
   *  IncrementFailedRpcCount for the old contact.  If this removes the old
   *  contact, the slot should then call AddContact for the new contact. */
  PingOldestContactPtr ping_oldest_contact_;
  /** Signal to be fired when adding a new contact. The contact will be added
   *  into the routing table directly, but having the Validated tag to be false.
   *  The new added contact will be passed as signal signature. Slot should
   *  validate the contact (looking for its public_key and public_key_sig in
   *  KAD network, then to validate), then set the corresponding Validated tag
   *  in the routing table or to remove the contact from the routing table, if
   *  validation failed. */
  ValidateContactPtr validate_contact_;
  /** Thread safe mutex lock */
  boost::shared_mutex shared_mutex_;
  /** The index to the bucket that the holder shall sit in
   *  It shall always be the value that 1 greater than the brother bucket */
  boost::uint16_t bucket_of_holder_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_ROUTING_TABLE_H_
