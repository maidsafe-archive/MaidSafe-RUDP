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

#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/kademlia/routing_table.h"

namespace maidsafe {

namespace kademlia {

RoutingTable::RoutingTable(const NodeId &this_id, const boost::uint16_t &k)
    : kThisId_(this_id),
      k_(k),
      contacts_(),
      kbucket_boundaries_(),
      ping_oldest_contact_(new PingOldestContactPtr::element_type),
      shared_mutex_() {
  KBucketBoundary first_boundary(kKeySizeBits, 0);
  kbucket_boundaries_.insert(first_boundary);
}

RoutingTable::~RoutingTable() {
  UniqueLock unique_lock(shared_mutex_);
  contacts_.clear();
  kbucket_boundaries_.clear();
}

void RoutingTable::AddContact(const Contact &contact, RankInfoPtr rank_info) {
  const NodeId &node_id = contact.node_id();

  // If the contact has the same ID as the holder, return directly
  if (node_id == kThisId_)
    return;
  UpgradeLock upgrade_lock(shared_mutex_);
  // Check if the contact is already in the routing table; if so, set its last
  // seen time to now (will bring it to the top)
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it_node = key_indx.find(node_id);

  if (it_node == key_indx.end()) {
    boost::uint16_t target_kbucket_index = KBucketIndex(node_id);
    boost::uint16_t k_bucket_size = KBucketSizeForKey(target_kbucket_index);

    // if the corresponding bucket is full
    if (k_bucket_size == k_) {
      // try to split the bucket if the new contact appears to be in the same
      // bucket as the holder
      // KBucketIndex(kThisId_) shall always return kKeySizeBits
      if (target_kbucket_index == kKeySizeBits) {
        SplitKbucket(target_kbucket_index);
        upgrade_lock.unlock();
        AddContact(contact, rank_info);
      } else {
        // try to apply ForceK, otherwise fire the signal
        if (ForceKAcceptNewPeer(contact, target_kbucket_index,
                                rank_info) != 0) {
          // ForceK failed.  Find the oldest contact in the bucket
          Contact oldest_contact = GetLastSeenContact(target_kbucket_index);
          // fire a signal here to notify
          (*ping_oldest_contact_)(oldest_contact, contact, rank_info);
        }
      }
    } else {
      // bucket not full, insert the contact into routing table
      boost::uint16_t common_leading_bits = KDistanceTo(contact.node_id());
      UpgradeToUniqueLock unique_lock(upgrade_lock);
      RoutingTableContact new_routing_table_contact(contact, kThisId_,
                                                    rank_info,
                                                    common_leading_bits);
      new_routing_table_contact.kbucket_index = target_kbucket_index;
      contacts_.insert(new_routing_table_contact);
    }
  } else {
    UpgradeToUniqueLock unique_lock(upgrade_lock);
    contacts_.modify(it_node,
                     ChangeLastSeen(bptime::microsec_clock::universal_time()));
  }
}

void RoutingTable::GetContact(const NodeId &node_id, Contact *contact) {
  if (!contact)
    return;
  SharedLock shared_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it != key_indx.end())
    *contact = (*it).contact;
  else
    *contact = Contact();
}

void RoutingTable::GetCloseContacts(
    const NodeId &target_id,
    const size_t &count,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_contacts) {
  if (!close_contacts)
    return;
  SharedLock shared_lock(shared_mutex_);
  // the search will begin from a bucket having the similiar k-distance as the
  // target node to the current holder
  // then extend the range follows the rule:
  //      all kbuckets contains more common leading bits shall be considered
  //      if the total still smaller than the count, then recursively add
  //      kbuckets containing less leading bits till reach the count cap
  boost::uint16_t start_kbucket_index = KBucketIndex(target_id);

  KBucketBoundariesByUpperBoundary key_indx
      = kbucket_boundaries_.get<UpperBoundaryTag>();
  auto it_begin = key_indx.find(start_kbucket_index);
  auto it_end = it_begin;
  ++it_end;
  boost::uint32_t potential_size = KBucketSizeForKey(start_kbucket_index);
  boost::uint32_t target_size = count + exclude_contacts.size();
  // extend the search range step 1: add all kbuckets containing more
  // common leading bits
  while (it_end != key_indx.end()) {
    potential_size = potential_size + KBucketSizeForKey((
        *it_end).upper_boundary);
    ++it_end;
  }
  // extend the search range step 2:recursively add kbuckets containing
  // less common leading bits till reach the count cap
  while ((potential_size < target_size) && (it_begin != key_indx.begin())) {
    if (it_begin != key_indx.begin()) {
      --it_begin;
      potential_size = potential_size + KBucketSizeForKey((
          *it_begin).upper_boundary);
    }
  }

  // once we have the search range, put all contacts in the range buckets into
  // a candidate container, using target_id to re-calculate the distance
  RoutingTableContactsContainer candidate_contacts;
  while (it_begin != it_end) {
    bmi::index_iterator<RoutingTableContactsContainer,
        KBucketTag>::type ic0, ic1;
    boost::tuples::tie(ic0, ic1)
      = bmi::get<KBucketTag>(contacts_).equal_range((*it_begin).upper_boundary);
    while (ic0 != ic1) {
      // check if the candidate in the exclusion list
      auto it = std::find(exclude_contacts.begin(),
                          exclude_contacts.end(),
                          (*ic0).contact);
      // if not in the exclusion list, add the contact into the candidates
      // container
      if (it == exclude_contacts.end()) {
        RoutingTableContact new_contact((*ic0).contact, target_id, 0);
        candidate_contacts.insert(new_contact);
      }
      ++ic0;
    }
    ++it_begin;
  }

  // populate the result with the count defined top contacts
  // indexed by the new calculated distance
  ContactsByDistanceToThisId key_dist_indx
    = candidate_contacts.get<DistanceToThisIdTag>();
  boost::uint32_t counter(0);
  auto it = key_dist_indx.begin();
  while ((counter < count) && (it != key_dist_indx.end())) {
    close_contacts->push_back((*it).contact);
    ++counter;
    ++it;
  }
  return;
}

void RoutingTable::GetContactsClosestToOwnId(
    const boost::uint32_t &count,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_contacts) {
  if (!close_contacts)
    return;
  SharedLock shared_lock(shared_mutex_);
  // populate the result with the count defined top contacts
  // indexed by the distance
  ContactsByDistanceToThisId key_dist_indx
    = contacts_.get<DistanceToThisIdTag>();
  boost::uint32_t counter(0);
  auto it = key_dist_indx.begin();
  while ((counter < count) && (it != key_dist_indx.end())) {
    // check if the candidate in the exclusion list
    auto it_exclude = std::find(exclude_contacts.begin(),
                                exclude_contacts.end(),
                                (*it).contact);
    // if not in the exclusion list, add the contact into the result
    if (it_exclude == exclude_contacts.end()) {
      close_contacts->push_back((*it).contact);
      ++counter;
    }
    ++it;
  }
  return;
}

int RoutingTable::SetPublicKey(const NodeId &node_id,
                               const std::string &new_public_key) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end())
    return -1;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  key_indx.modify(it, ChangePublicKey(new_public_key));
  return 0;
}

int RoutingTable::UpdateRankInfo(const NodeId &node_id,
                                 RankInfoPtr new_rank_info) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end())
    return -1;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  key_indx.modify(it, ChangeRankInfo(new_rank_info));
  return 0;
}

int RoutingTable::SetPreferredEndpoint(const NodeId &node_id,
                                       const IP &ip) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  // return if can't find the contact having the nodeID
  if (it == key_indx.end())
    return -1;
  Contact new_local_contact((*it).contact);
  new_local_contact.SetPreferredEndpoint(ip);
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  key_indx.modify(it, ChangeContact(new_local_contact));
  return 0;
}

int RoutingTable::IncrementFailedRpcCount(const NodeId &node_id) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end())
    return -1;
  boost::uint16_t num_failed_rpcs = (*it).num_failed_rpcs + 1;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  if (num_failed_rpcs > kFailedRpcTolerance)
    key_indx.erase(it);
  else
    key_indx.modify(it, ChangeNumFailedRpc(num_failed_rpcs));
  return num_failed_rpcs;
}

void RoutingTable::GetBootstrapContacts(std::vector<Contact> *contacts) {
  if (!contacts)
    return;
  SharedLock shared_lock(shared_mutex_);
  RoutingTableContactsContainer::index<BootstrapTag>::type& key_indx =
      contacts_.get<BootstrapTag>();
  auto it = contacts_.get<BootstrapTag>().equal_range(true);
  contacts->clear();
  contacts->reserve(distance(it.first, it.second));
  while (it.first != it.second)
    contacts->push_back((*it.first++).contact);
}

PingOldestContactPtr RoutingTable::ping_oldest_contact() {
  return ping_oldest_contact_;
}

Contact RoutingTable::GetLastSeenContact(const boost::uint16_t &kbucket_index) {
  auto pit = contacts_.get<KBucketLastSeenTag>().equal_range(boost::make_tuple(
      kbucket_index));
  return (*pit.first).contact;
}

boost::uint16_t RoutingTable::KBucketIndex(const NodeId &key) {
//   if (key > NodeId::kMaxId)
//     return -1;
  KBucketBoundariesByUpperBoundary key_indx
      = kbucket_boundaries_.get<UpperBoundaryTag>();
  boost::uint16_t common_leading_bits = KDistanceTo(key);
  auto it = key_indx.lower_bound(common_leading_bits);
  return (*it).upper_boundary;
}

boost::uint16_t RoutingTable::KBucketCount() const {
  return kbucket_boundaries_.size();
}

boost::uint16_t RoutingTable::KBucketSizeForKey(const boost::uint16_t &key) {
  KBucketBoundariesByUpperBoundary key_indx
      = kbucket_boundaries_.get<UpperBoundaryTag>();
  auto it = key_indx.lower_bound(key);
  auto pit = contacts_.get<KBucketTag>().equal_range((*it).upper_boundary);
  return distance(pit.first, pit.second);
}

void RoutingTable::SplitKbucket(const boost::uint16_t &kbucket_index) {
  KBucketBoundariesByUpperBoundary key_indx
      = kbucket_boundaries_.get<UpperBoundaryTag>();
  auto it = key_indx.lower_bound(kbucket_index);

  // no need to check this as a kbucket will never be split until its full
  //   if (((*it).upper_boundary-(*it).lower_boundary)<5)
  //     return;

  // insert one new element into the kbucket boundaries container
  // and modify the corresponding old one
  // each time the split means:
  //    split a bucket (upper,lower) into (upper,lower+1) and (lower,lower)
  boost::uint16_t split_position = (*it).lower_boundary + 1;
  boost::uint16_t lower_boundary = (*it).lower_boundary;
  key_indx.modify(it, ChangeLowerBoundary(split_position));
  KBucketBoundary new_kbucket_boundary(lower_boundary, lower_boundary);
  key_indx.insert(new_kbucket_boundary);

  // modify all related contacts' kbucket index tag in the contact container
  auto pit = contacts_.get<KBucketTag>().equal_range((*it).upper_boundary);
  ContactsById key_node_indx = contacts_.get<NodeIdTag>();
  auto it_begin = pit.first;
  auto it_end = pit.second;
  while (it_begin != it_end) {
    if ((*it_begin).common_leading_bits <= lower_boundary) {
      auto it = key_node_indx.find((*it_begin).node_id);
      key_node_indx.modify(it, ChangeKBucketIndex(lower_boundary));
    }
    ++it_begin;
  }
}

int RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact,
                                      const boost::uint16_t &target_bucket,
                                      const RankInfoPtr &rank_info) {
  // find the bucket that shall contain the holder
  // KBucketIndex(kThisId_) shall always return kKeySizeBits
  boost::uint16_t bucket_of_holder = kKeySizeBits;

  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = k_ - KBucketSizeForKey(bucket_of_holder);
  if (v == 0) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (v == 0)" << std::endl;
    return -2;
  }
  // find the brother bucket
  KBucketBoundariesByUpperBoundary key_indx
      = kbucket_boundaries_.get<UpperBoundaryTag>();
  auto it = key_indx.find(bucket_of_holder);
  if (it == kbucket_boundaries_.begin()) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (no brother bucket)" <<
      std::endl;
    return -1;
  }

  --it;
  boost::uint16_t brother_bucket_of_holder = (*it).upper_boundary;

  if (brother_bucket_of_holder != target_bucket) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (Not in Brother Bucket!)"
        << std::endl;
    return -3;
  }

  // sort the brother bucket based on contacts' distance to the holder
  auto pit = contacts_.get<KBucketDistanceToThisIdTag>().equal_range(
      boost::make_tuple(brother_bucket_of_holder));

  // check if the new contact is among the top v closest
  NodeId distance_to_target = kThisId_ ^ new_contact.node_id();
  // pit.second shall point to the furthest contact (need one step forward)
  // as the list will sorted from least to highest
  // while the least value of XOR distance means the nearest
  auto it_end = pit.second;
  --it_end;
  // the result from the equal range will always points one step hehind
  NodeId furthest_distance = (*it_end).distance_to_this_id;
  NodeId furthest_node = (*it_end).node_id;

  if (furthest_distance <= distance_to_target) {
    // new peer isn't among the k closest neighbours
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - "
                    "new peer isn't among the k closest" << std::endl;
    return -4;
  }
  // new peer is among the k closest neighbours
  // drop the peer which is the furthest
  ContactsById key_node_indx = contacts_.get<NodeIdTag>();
  auto it_furthest = key_node_indx.find(furthest_node);
  contacts_.erase(it_furthest);
  RoutingTableContact new_local_contact(new_contact, kThisId_,
                                        rank_info,
                                        KDistanceTo(new_contact.node_id()));
  new_local_contact.kbucket_index = brother_bucket_of_holder;
  contacts_.insert(new_local_contact);
  return 0;
}

boost::uint16_t RoutingTable::KDistanceTo(const NodeId &rhs) const {
  boost::uint16_t distance = 0;
  std::string this_id_binary = kThisId_.ToStringEncoded(NodeId::kBinary);
  std::string rhs_id_binary = rhs.ToStringEncoded(NodeId::kBinary);
  std::string::const_iterator this_it = this_id_binary.begin();
  std::string::const_iterator rhs_it = rhs_id_binary.begin();
  for (; ((this_it != this_id_binary.end()) && (*this_it == *rhs_it));
      ++this_it, ++rhs_it)
    ++distance;
  return distance;
}

size_t RoutingTable::Size() const {
  return contacts_.size();
}

void RoutingTable::Clear() {
  UniqueLock unique_lock(shared_mutex_);
  contacts_.clear();
  kbucket_boundaries_.clear();
  KBucketBoundary first_boundary(kKeySizeBits, 0);
  kbucket_boundaries_.insert(first_boundary);
}

}  // namespace kademlia

}  // namespace maidsafe
