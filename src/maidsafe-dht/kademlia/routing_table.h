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
#include "boost/signals2/signal.hpp"
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

#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/node_id.h"

namespace bptime = boost::posix_time;
namespace bmi = boost::multi_index;

namespace maidsafe {

namespace transport {
  struct Info;
}

namespace kademlia {

namespace test {
  class TestRoutingTable;
}
  
struct RoutingTableContact {
  RoutingTableContact(const Contact &contact,
                      const NodeId &holder_id,
                      const RankInfoPtr &rank_info,
                      boost::uint16_t common_heading_bits)
      : contact(contact),
        node_id(contact.node_id()),
        public_key(),
        num_failed_rpcs(0),
        distance_to_this_id(holder_id ^ contact.node_id()),
        common_heading_bits(common_heading_bits),
        kbucket_index(0),
        last_seen(bptime::microsec_clock::universal_time()),
        rank_info(rank_info) {}

  RoutingTableContact(const Contact &contact,
                      const NodeId &holder_id,
                      boost::uint16_t common_heading_bits)
      : contact(contact),
        node_id(contact.node_id()),
        public_key(),
        num_failed_rpcs(0),
        distance_to_this_id(holder_id ^ contact.node_id()),
        common_heading_bits(common_heading_bits),
        kbucket_index(0),
        last_seen(bptime::microsec_clock::universal_time()),
        rank_info() {}

  /** Copy constructor. */
  RoutingTableContact(const RoutingTableContact &other)
      : contact(other.contact),
        node_id(other.node_id),
        public_key(other.public_key),
        num_failed_rpcs(other.num_failed_rpcs),
        distance_to_this_id(other.distance_to_this_id),
        common_heading_bits(other.common_heading_bits),
        kbucket_index(other.kbucket_index),
        last_seen(other.last_seen),
        rank_info(other.rank_info) {}
  bool operator<(const RoutingTableContact &other) const {
    return contact < other.contact;
  }
  Contact contact;
  NodeId node_id;
  std::string public_key;
  boost::uint16_t num_failed_rpcs;
  NodeId distance_to_this_id;
  boost::uint16_t common_heading_bits;
  // the index of the kbucket which in responsible of the contact
  // unique and sorted, just use the upper_boundary
  boost::uint16_t kbucket_index;
  bptime::ptime last_seen;
  RankInfoPtr rank_info;
};

struct ChangeContact {
  explicit ChangeContact(Contact contact)
      : contact(contact) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.contact = contact;
  }
  private:
    Contact contact;
};

struct ChangeKBucketIndex {
  explicit ChangeKBucketIndex(boost::uint16_t new_kbucket_index)
      : new_kbucket_index(new_kbucket_index) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.kbucket_index = new_kbucket_index;
  }
  private:
    boost::uint16_t new_kbucket_index;
};

struct ChangePublicKey {
  explicit ChangePublicKey(std::string new_public_key)
      : new_public_key(new_public_key) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.public_key = new_public_key;
  }
  private:
    std::string new_public_key;
};

struct ChangeRankInfo {
  explicit ChangeRankInfo(RankInfoPtr new_rank_info)
      :new_rank_info(new_rank_info) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.rank_info = new_rank_info;
  }
  private:
    RankInfoPtr new_rank_info;
};

struct ChangeNumFailedRpc {
  explicit ChangeNumFailedRpc(boost::uint16_t new_num_failed_rpcs)
      : new_num_failed_rpcs(new_num_failed_rpcs) {}
  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.num_failed_rpcs = new_num_failed_rpcs;
  }
  
  private:
    boost::uint16_t new_num_failed_rpcs;
};

struct ChangeLastSeen {
  explicit ChangeLastSeen(bptime::ptime new_last_seen)
      :new_last_seen(new_last_seen) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(RoutingTableContact &routing_table_contact) { // NOLINT
    routing_table_contact.last_seen = new_last_seen;
  }
  private:
    bptime::ptime new_last_seen;
};

struct NodeIdTag;
struct DistanceToThisIdTag;
struct TimeLastSeenTag;
struct KBucketTag;
struct RankInfoTag;
struct KBucketLastSeenTag;
struct KBucketDistanceToThisIdTag;

// Struct to allow initialisation of RoutingTableContactsContainer to accept
// this node's ID as a parameter.
struct KadCloserToThisId {
  explicit KadCloserToThisId(const NodeId &id) : this_id(id) {}
  bool operator()(const RoutingTableContact &x,
                  const RoutingTableContact &y) const {
    return NodeId::CloserToTarget(x.node_id, y.node_id, this_id);
  }
 private:
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
    >
  >
> RoutingTableContactsContainer;

typedef RoutingTableContactsContainer::index<NodeIdTag>::type& ContactsById;
typedef RoutingTableContactsContainer::index<KBucketTag>::type&
    ContactsByKBucketIndex;
typedef RoutingTableContactsContainer::index<DistanceToThisIdTag>::type&
    ContactsByDistanceToThisId;
typedef RoutingTableContactsContainer::index<TimeLastSeenTag>::type&
    ContactsByTimeLastSeen;

/** The original idea of this struct is to allow one kbucket to cover user
 *  defined number of common heading bits (such as one kbucket cover 2 bits).
 *  However, according to the original Kademlia paper, one kbucket shall cover
 *  only one bit. So this struct can be removed.
 *  Keeping this struct provides a potential flexibility of kbucket
 *  coverage.
 *  @struct KBucketBoundary */
struct KBucketBoundary {
  KBucketBoundary(boost::uint16_t upper_boundary,
                  boost::uint16_t lower_boundary)
      : upper_boundary(upper_boundary),
        lower_boundary(lower_boundary) {}
  boost::uint16_t upper_boundary;
  boost::uint16_t lower_boundary;
};

struct ChangeUpperBoundary {
  explicit ChangeUpperBoundary(boost::uint16_t new_upper_boundary)
      : new_upper_boundary(new_upper_boundary) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(KBucketBoundary &kbucket_boundary) {  // NOLINT
    kbucket_boundary.upper_boundary = new_upper_boundary;
  }
  private:
    boost::uint16_t new_upper_boundary;
};

struct ChangeLowerBoundary {
  explicit ChangeLowerBoundary(boost::uint16_t new_lower_boundary)
      : new_lower_boundary(new_lower_boundary) {}

  // Anju: use nolint to satisfy multi-indexing
  void operator()(KBucketBoundary &kbucket_boundary) {  // NOLINT
    kbucket_boundary.lower_boundary = new_lower_boundary;
  }
  private:
    boost::uint16_t new_lower_boundary;
};

// Tags
struct UpperBoundaryTag;
struct LowerBoundaryTag;

typedef boost::multi_index_container<
  KBucketBoundary,
  bmi::indexed_by<
    bmi::ordered_unique<
      bmi::tag<UpperBoundaryTag>,
      BOOST_MULTI_INDEX_MEMBER(KBucketBoundary, boost::uint16_t, upper_boundary)
    >,
    bmi::ordered_unique<
      bmi::tag<LowerBoundaryTag>,
      BOOST_MULTI_INDEX_MEMBER(KBucketBoundary, boost::uint16_t, lower_boundary)
    >
  >
> KBucketBoundariesContainer;

typedef KBucketBoundariesContainer::index<UpperBoundaryTag>::type&
    KBucketBoundariesByUpperBoundary;

typedef std::shared_ptr<boost::signals2::signal<void(const Contact&,
                        const Contact&, RankInfoPtr)>>
    PingOldestContactStatusPtr;

/** Object containing a node's Kademlia Routing Table and all its contacts.
 *  @class RoutingTable */    
class RoutingTable {
 public:
  /** Constructor.  To create a routing table, in all cases the node ID and
   *  k closest contacts parameter must be provided.
   *  @param[in] this_id The routing table holder's Kademlia ID.
   *  @param[in] k k closest contacts. */
  RoutingTable(const NodeId &this_id, const boost::uint16_t &k);

  /** Dstructor. */
  ~RoutingTable();
  /** Add the given contact to the correct k-bucket; if it already
   *  exists, its status will be updated.  If the given k-bucket is full and not
   *  splittable, the signal on_ping_oldest_contact_ will be fired which will
   *  ultimately resolve whether the contact is added or not. 
   *  @param[in] contact The new contact needs to be added.
   *  @param[in] rank_info the contact's rank_info. */
  void AddContact(const Contact &contact, RankInfoPtr rank_info);

  /** Get the info of the contact based on the input Kademlia ID
   *  @param[in] node_id The input Kademlia ID.
   *  @param[out] contact the return contact. */
  void GetContact(const NodeId &node_id, Contact *contact);
  /** Remove the contact with the specified node ID from the routing table
   *  @param[in] node_id The input Kademlia ID.
   *  @param[in] force Bool switch of ForceK. */
  void RemoveContact(const NodeId &node_id, const bool &force);
  /** Finds a number of known nodes closest to the target node in the current
   *  routing table.
   *  NOTE: unless for special purpose, the target shall be considered to be
   *  always put into the exclude_contacts list
   *  @param[in] target_id The Kademlia ID of the target node.
   *  @param[in] count Number of closest nodes looking for.
   *  @param[in] exclude_contacts List of contacts that shall be excluded.
   *  @param[out] close_contacts Result of the find closest contacts. */
  void GetCloseContactsForTargetId(const NodeId &target_id,
                        const size_t &count,
                        const std::vector<Contact> &exclude_contacts,
                        std::vector<Contact> *close_contacts);

  /** Finds a number of known nodes closest to the holder node in the current
   *  routing table.
   *  @param[in] count Number of closest nodes looking for.
   *  @param[in] exclude_contacts List of contacts that shall be excluded.
   *  @param[out] close_contacts Result of the find closest contacts. */
  void GetCloseContacts(const size_t &count,
                        const std::vector<Contact> &exclude_contacts,
                        std::vector<Contact> *close_contacts);
  /** Set one node's publickey
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] new_public_key The new poblickey to be set to. */
  int SetPublicKey(const NodeId &node_id, const std::string &new_public_key);
  /** Update one node's rankinfo
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] rank_info The new rankinfo to be set to. */
  int UpdateRankInfo(const NodeId &node_id, RankInfoPtr rank_info);
  /** Set one node's preferred endpoint
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @param[in] ip The new preferred endpoint to be set to. */
  int SetPreferredEndpoint(const NodeId &node_id, const IP &ip);
  /** Increase one node's failedRPC counter by one
   *  @param[in] node_id The Kademlia ID of the target node.
   *  @return The value of the contact's latest num of failed RPC,
   *          will be -1 when failed */
  int IncrementFailedRpcCount(const NodeId &node_id);
  /** Get the routing table holder's direct-connected nodes.
   *  for a direct-connected node, there must be no rendezvous endpoint,
   *  but either of tcp443 or tcp80 may be true.
   *  @param[out] contacts The result of all directly connected contacts. */
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  /** Getter.
   *  @return Num of contacts in the routing table. */
  boost::uint16_t Size() const;
  /** Empty the routing table */
  void Clear();
  /** Getter.
   *  @return The singal handler. */
  PingOldestContactStatusPtr GetPingOldestContactSingalHandler();

  friend class test::TestRoutingTable;
 private:
  /** Return the contact which is the lastseen on in the target kbucket.
   *  @param[in] kbucket_index The index of the kbucket.
   *  @return The last seend contact in the kbucket. */
  Contact GetLastSeenContact(const boost::uint16_t &kbucket_index);    
  /** Calculate the index of the k-bucket which is responsible for the specified
  *  key (or ID).
  *  @param[in] key The Kademlia ID of the target node.
  *  @return The index of the k-bucket which is in responsible. */
  boost::uint16_t KBucketIndex(const NodeId &key);
  /** Getter.
   *  @return Num of kbuckets in the routing table. */
  boost::uint16_t KBucketSize() const;
  /** Get the number of contacts in a specified kbucket
   *  @param[in] key The index of the target k-bucket.
   *  @return Num of contacts in the specified kbucket */
  boost::uint16_t KBucketSizeForKey(const boost::uint16_t &key);  
  /** Bisect the k-bucket having the specified index into two new ones
  *  @param[in] key The index of the target k-bucket. */
  void SplitKbucket(const boost::uint16_t &kbucket_index);
  /** Forces the brother k-bucket of the holder to accept a new contact which
    *  would normally be dropped if it is within the k closest contacts to the
  *  holder's ID.
  *  @param[in] new_contact The new contact needs to be added.
  *  @param[in] target_bucket The kbucket shall in responsible of the new
  *  contact
  *  @return Error Code:  0   for succeed,
  *                       -1  for No brother bucket
  *                       -2  for v==0
  *                       -3  for Not in Brother Bucket
  *                       -4  for New peer isn't among the k closest */
  int ForceKAcceptNewPeer(const Contact &new_contact,
                          const boost::uint16_t &target_bucket,
                          const RankInfoPtr &rank_info);
  /**
  * XOR KBucket distance between two kademlia IDs.
  * Measured by the number of common heading bits.
  * The less the value is, the further the distance (the wider range) is.
  * @param[in] rhs NodeId to which this is XOR
  * @return the number of samed bits from the begining
  */
  boost::uint16_t KDistanceTo(const NodeId &rhs) const;
  /** Holder's Kademlia ID */
  const NodeId kThisId_;
  /** k closest to the holder */
  const boost::uint16_t k_;
  /** Multi_index container of all contacts */
  RoutingTableContactsContainer contacts_;
  /** Multi_index container of boundary pairs for all KBucket */
  KBucketBoundariesContainer kbucket_boundries_;
  /** Singal handler */
  PingOldestContactStatusPtr ping_oldest_contact_status_;
  /** Thread safe mutex lock */
  boost::shared_mutex shared_mutex_;   
  typedef boost::shared_lock<boost::shared_mutex> SharedLock;
  typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
  typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
  typedef boost::upgrade_to_unique_lock<boost::shared_mutex>
      UpgradeToUniqueLock;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_ROUTING_TABLE_H_
