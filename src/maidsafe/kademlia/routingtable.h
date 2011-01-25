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

#ifndef MAIDSAFE_KADEMLIA_ROUTINGTABLE_H_
#define MAIDSAFE_KADEMLIA_ROUTINGTABLE_H_

#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/nodeid.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace transport { struct Info; }

namespace kademlia {

class KBucket;

struct RoutingTableContact {
  RoutingTableContact(const Contact &contact_in)
      : contact(contact_in),
        public_key(),
        num_failed_rpcs(0),
        last_seen(bptime::microsec_clock::universal_time()) {}
  bool operator<(const RoutingTableContact &other) const {
    return contact < other.contact;
  }
  NodeId node_id() const { return contact.node_id(); }
  Contact contact;
  std::string public_key;
  boost::uint16_t num_failed_rpcs;
  bptime::ptime last_seen;
  std::shared_ptr<transport::Info> info;
};

struct TagNodeId {};
struct TagTimeLastSeen {};

typedef boost::multi_index_container<
  RoutingTableContact,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<TagNodeId>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(RoutingTableContact, NodeId, node_id>
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagTimeLastSeen>,
      BOOST_MULTI_INDEX_MEMBER(RoutingTableContact, bptime::ptime,
                               &RoutingTableContact::last_seen)
    >
  >
> RoutingTableContactsContainer;

class RoutingTable {
 public:
  RoutingTable(const NodeId &holder_id, const boost::uint16_t &k);
  ~RoutingTable();
  // Add the given contact to the correct k-bucket; if it already
  // exists, its status will be updated.  If the given k-bucket is full and not
  // splittable, the signal on_ping_oldest_contact_ will be fired which will
  // ultimately resolve whether the contact is added or not.
  void AddContact(const Contact &contact);
  void GetContact(const NodeId &node_id, Contact *contact);
  // Remove the contact with the specified node ID from the routing table
  void RemoveContact(const NodeId &node_id, const bool &force);
  // Finds a number of known nodes closest to the target_id.
  void GetCloseContacts(const NodeId &target_id,
                        const size_t &count,
                        const std::vector<Contact> &exclude_contacts,
                        std::vector<Contact> *close_contacts);
  void GetBootstrapContacts(std::vector<Contact> *contacts);
  int SetPublicKey(const NodeId &node_id, const std::string &new_public_key);
  int UpdateRankInfo(const NodeId &node_id, RankInfoPtr rank_info);
  int SetPreferredEndpoint(const NodeId &node_id, const IP &ip);
  int IncrementFailedRpcCount(const NodeId &node_id);  

  // Finds all k-buckets that need refreshing, starting at the k-bucket with
  // the specified index, and returns IDs to be searched for in order to
  // refresh those k-buckets
//  void GetRefreshList(const boost::uint16_t &start_kbucket, const bool &force,
//                      std::vector<NodeId> *ids);
//  // Get all contacts of a specified k_bucket
//  bool GetContacts(const boost::uint16_t &index,
//                   const std::vector<Contact> &exclude_contacts,
//                   std::vector<Contact> *contacts);
  size_t KbucketSize() const;
  size_t Size() const;
  void Clear();
  // Calculate the index of the k-bucket which is responsible for the specified
  // key (or ID)
  boost::int16_t KBucketIndex(const NodeId &key);
  Contact GetLastSeenContact(const boost::uint16_t &kbucket_index);

 private:
// Calculate the index of the k-bucket which is responsible for the specified
// key (or ID)
//  int KBucketIndex(const std::string &key);
  // Return vector of k-bucket indices sorted from closest to key to furthest
  std::vector<boost::uint16_t> SortBucketsByDistance(const NodeId &key);
  // Takes a vector of contacts arranged in arbitrary order and sorts them from
  // closest to key to furthest.  Returns 0 on success.
  int SortContactsByDistance(const NodeId &key, std::vector<Contact> *contacts);
  // Bisect the k-bucket in the specified index into two new ones
  void SplitKbucket(const boost::uint16_t &index);
  // Forces the brother k-bucket of the holder to accept a new contact which
  // would normally be dropped if it is within the k closest contacts to the
  // holder's ID.
  int ForceKAcceptNewPeer(const Contact &new_contact);

  RoutingTableContactsContainer contacts_;
  std::vector<std::shared_ptr<KBucket>> k_buckets_;
  // Mapping of each k-bucket's maximum address to its index in the vector of
  // k-buckets
  std::map<NodeId, boost::uint16_t> bucket_upper_address_;
  // Holder's node ID
  NodeId holder_id_;
  // Index of k-bucket covering address space which incorporates holder's own
  // node ID.  NB - holder's ID is never actually added to any of its k-buckets.
  // Index of the only k-bucket covering same amount of address space as
  // bucket_of_holder_ above.  This is the only bucket eligible to be considered
  // for the ForceK function.
  boost::uint16_t bucket_of_holder_, brother_bucket_of_holder_;
  // Upper limit of address space.
  NodeId address_space_upper_address_;
  const boost::uint16_t k_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_KADEMLIA_ROUTINGTABLE_H_
