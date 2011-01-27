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

#ifndef MAIDSAFE_KADEMLIA_ROUTING_TABLE_H_
#define MAIDSAFE_KADEMLIA_ROUTING_TABLE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/mem_fun.hpp"

#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/node_id.h"

namespace bptime = boost::posix_time;
namespace bmi = boost::multi_index;

namespace maidsafe {

namespace transport { struct Info; }

namespace kademlia {

class KBucket;

class RoutingTableContact {
  RoutingTableContact(const Contact &contact_in, const NodeId holder_id)
      : contact(contact_in),
        validated_public_keys(),
        num_failed_rpcs(0),
        distance_to_this_id(contact_in.node_id()^holder_id),
        kbucket_index(0),
        last_seen(bptime::microsec_clock::universal_time()) {}
        
  bool operator<(const RoutingTableContact &other) const {
    return contact < other.contact;
  }
  
  NodeId node_id() const { return contact.node_id(); }
  Contact contact;
  NodeId distance_to_this_id;
  
  // unique and sorted, just use the upper_boundary
  NodeId kbucket_index;
  
  std::vector<std::string> validated_public_keys;
  boost::uint16_t num_failed_rpcs;
  bptime::ptime last_seen;
  RankInfoPtr rank_info;
};

struct ChangeKBucketIndex {
  ChangePublicKey(NodeId new_kbucket_index)
      : new_kbucket_index(new_kbucket_index) {}

  void operator()(RoutingTableContact& contact){
    contact.kbucket_index=new_kbucket_index;
  }
private:
  NodeId new_kbucket_index;
};

struct ChangePublicKey {
  ChangePublicKey(std::vector<std::string> new_public_keys)
      : new_public_keys(new_public_keys) {}

  void operator()(RoutingTableContact& contact){
    contact.validated_public_keys=new_public_keys;
  }
private:
  std::vector<std::string> new_public_keys;
};

struct ChangeRankInfo {
  ChangeRankInfo(RankInfoPtr new_rank_info):new_rank_info(new_rank_info){}

  void operator()(RoutingTableContact& contact){
    contact.rank_info=new_rank_info;
  }
private:
  RankInfoPtr new_rank_info;
};

struct ChangeNumFailedRpc {
  ChangeNumFailedRpc(boost::uint16_t new_num_failed_rpcs)
      : new_num_failed_rpcs(new_num_failed_rpcs) {}

  void operator()(RoutingTableContact& contact){
    contact.num_failed_rpcs=new_num_failed_rpcs;
  }
private:
  boost::uint16_t new_num_failed_rpcs;
};

struct ChangeLastSeen {
  ChangeRankInfo(bptime::ptime new_last_seen):new_last_seen(new_last_seen){}

  void operator()(RoutingTableContact& contact){
    contact.last_seen=new_last_seen;
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

// Struct to allow initialisation of RoutingTableContactsContainer to accept
// this node's ID as a parameter.
struct KadCloserToThisId {
  KadCloserToThisId(const NodeId &id) : this_id(id) {}
  bool operator()(const RoutingTableContact &x,
                  const RoutingTableContact &y) const {
    return NodeId::CloserToTarget(x.node_id(), y.node_id(), this_id);
  }
private:
  NodeId this_id;
};

typedef boost::multi_index_container<
  RoutingTableContact,
  bmi::indexed_by<
    bmi::ordered_unique<
      bmi::tag<NodeIdTag>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(RoutingTableContact, NodeId, node_id)
    >,
    bmi::ordered_non_unique<
      bmi::tag<DistanceToThisIdTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact ,
                               NodeId, distance_to_this_id)
    >,
    bmi::ordered_non_unique<
      bmi::tag<KBucketTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact ,
                               NodeId, kbucket_index)
    >,
    bmi::ordered_non_unique<
      bmi::composite_key<
        bmi::tag<KBucketLastSeenTag>,
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact ,
                                NodeId, kbucket_index),
        BOOST_MULTI_INDEX_MEMBER(RoutingTableContact ,
                                bptime::ptime, last_seen)
      >
    >,    
    bmi::ordered_non_unique<
      bmi::tag<TimeLastSeenTag>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact, bptime::ptime, last_seen)
    >
  >
> RoutingTableContactsContainer;

typedef RoutingTableContactsContainer::index<NodeIdTag>::type ContactsById;
typedef RoutingTableContactsContainer::index<DistanceToThisIdTag>::type
    ContactsByDistanceToThisId;
typedef RoutingTableContactsContainer::index<TimeLastSeenTag>::type
    ContactsByTimeLastSeen;


struct KBucketBoundary {
  kbucket_boundary(NodeId upper_boundary, NodeId lower_boundary)
      : upper_boundary(upper_boundary) ,
        lower_boundary(lower_boundary) {}
  NodeId upper_boundary;
  NodeId lower_boundary;
};

struct ChangeUpperBoundary {
  ChangeUpperBoundary(NodeId new_upper_boundary)
      : new_upper_boundary(new_upper_boundary) {}

  void operator()(KBucketBoundary& kbucket_boundary){
    kbucket_boundary.upper_boundary=new_upper_boundary;
  }
private:
  NodeId new_upper_boundary;
};

struct ChangeLowerBoundary {
  ChangeLowerBoundary(NodeId new_lower_boundary)
      : new_lower_boundary(new_lower_boundary) {}

  void operator()(KBucketBoundary& kbucket_boundary){
    kbucket_boundary.lower_boundary=new_lower_boundary;
  }
private:
  NodeId new_lower_boundary;
};

// Tags
struct UpperBoundaryTag;
struct LowerBoundaryTag;

typedef boost::multi_index_container<
  KBucketBoundary,
  bmi::indexed_by<
    bmi::ordered_unique<
      bmi::tag<UpperBoundaryTag>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(KBucketBoundary, NodeId, upper_boundary)
    >,
    bmi::ordered_unique<
      bmi::tag<LowerBoundaryTag>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(KBucketBoundary, NodeId, lower_boundary)
    >
  >
> KBucketBoundariesContainer;

class RoutingTable {
 public:
  RoutingTable(const NodeId &this_id, const boost::uint16_t &k);
  ~RoutingTable();
  // Add the given contact to the correct k-bucket; if it already
  // exists, its status will be updated.  If the given k-bucket is full and not
  // splittable, the signal on_ping_oldest_contact_ will be fired which will
  // ultimately resolve whether the contact is added or not.
  void AddContact(const Contact &contact, RankInfoPtr rank_info);
  void GetContact(const NodeId &node_id, Contact *contact);
  // Remove the contact with the specified node ID from the routing table
  void RemoveContact(const NodeId &node_id, const bool &force);
  // Finds a number of known nodes closest to the target_id.
  void GetCloseContacts(const NodeId &target_id,
                        const size_t &count,
                        const std::vector<Contact> &exclude_contacts,
                        std::vector<Contact> *close_contacts);

  int SetPublicKey(const NodeId &node_id, const std::string &new_public_key);
  int UpdateRankInfo(const NodeId &node_id, RankInfoPtr rank_info);
  
  int SetPreferredEndpoint(const NodeId &node_id, const IP &ip);
  int IncrementFailedRpcCount(const NodeId &node_id);  

  // num of kbuckets in this node
  size_t KbucketSize() const;
  
  // num of contacts in the routing table
  size_t Size() const;
  
  void Clear();
  // Calculate the index of the k-bucket which is responsible for the specified
  // key (or ID)
  NodeId KBucketIndex(const NodeId &key);
  
  Contact GetLastSeenContact(const NodeId &kbucket_index);

 private:
// Calculate the index of the k-bucket which is responsible for the specified
// key (or ID)
//  int KBucketIndex(const std::string &key);
 
  // Bisect the k-bucket in the specified index into two new ones
  void SplitKbucket(const boost::uint16_t &index);
  // Forces the brother k-bucket of the holder to accept a new contact which
  // would normally be dropped if it is within the k closest contacts to the
  // holder's ID.
  int ForceKAcceptNewPeer(const Contact &new_contact);

  // num of contacts in a specified kbucket
  size_t KBucketSize(const NodeId &key) const;

  // Holder's node ID
  const NodeId kThisId_;

  RoutingTableContactsContainer contacts_;
  KBucketBoundariesContainer kbucket_boundries_;

  // Index of k-bucket covering address space which incorporates holder's own
  // node ID.  NB - holder's ID is never actually added to any of its k-buckets.
  // Index of the only k-bucket covering same amount of address space as
  // bucket_of_holder_ above.  This is the only bucket eligible to be considered
  // for the ForceK function.
  boost::uint16_t bucket_of_holder_, brother_bucket_of_holder_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_KADEMLIA_ROUTING_TABLE_H_
