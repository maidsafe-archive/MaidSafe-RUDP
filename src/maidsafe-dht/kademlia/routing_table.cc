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

#ifdef __MSVC__
#pragma warning(disable:4996)
#endif
#include "maidsafe/common/log.h"
#ifdef __MSVC__
#pragma warning(default:4996)
#endif

#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/routing_table.h"

namespace maidsafe {

namespace kademlia {

RoutingTable::RoutingTable(const NodeId &this_id, const boost::uint16_t &k)
    : kThisId_(this_id),
      k_(k),
      contacts_(),
      unvalidated_contacts_(),
      ping_oldest_contact_(new PingOldestContactPtr::element_type),
      validate_contact_(new ValidateContactPtr::element_type),
      shared_mutex_(),
      bucket_of_holder_(0) {}

RoutingTable::~RoutingTable() {
  UniqueLock unique_lock(shared_mutex_);
  unvalidated_contacts_.clear();
  contacts_.clear();
}

void RoutingTable::AddContact(const Contact &contact, RankInfoPtr rank_info) {
  const NodeId &node_id = contact.node_id();

  // If the contact has the same ID as the holder, return directly
  if (node_id == kThisId_)
    return;

  // Check if the contact is already in the routing table; if so, set its last
  // seen time to now (will bring it to the top)
  std::shared_ptr<UpgradeLock> upgrade_lock(new UpgradeLock(shared_mutex_));
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it_node = key_indx.find(node_id);
  if (it_node != key_indx.end()) {
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    // will update the num_failed_rpcs to 0 as well
    contacts_.modify(it_node,
                     ChangeLastSeen(bptime::microsec_clock::universal_time()));
  } else {
    // put the contact into the unvalidated contacts container
    UnValidatedContactsById contact_indx =
        unvalidated_contacts_.get<NodeIdTag>();
    auto it_contact = contact_indx.find(node_id);
    if (it_contact == contact_indx.end()) {
      UnValidatedContact new_entry(contact, rank_info);
      unvalidated_contacts_.insert(new_entry);
      // fire the signal to validate the contact
      (*validate_contact_)(contact);
    }
  }
}

void RoutingTable::InsertContact(const Contact &contact,
                                 RankInfoPtr rank_info,
                                 std::shared_ptr<UpgradeLock> upgrade_lock) {
  boost::uint16_t common_leading_bits = KDistanceTo(contact.node_id());
  boost::uint16_t target_kbucket_index = KBucketIndex(common_leading_bits);
  boost::uint16_t k_bucket_size = KBucketSizeForKey(target_kbucket_index);

  // if the corresponding bucket is full
  if (k_bucket_size == k_) {
    // try to split the bucket if the new contact appears to be in the same
    // bucket as the holder
    if (target_kbucket_index == bucket_of_holder_) {
      SplitKbucket(upgrade_lock);
      InsertContact(contact, rank_info, upgrade_lock);
    } else {
      // try to apply ForceK, otherwise fire the signal
      if (ForceKAcceptNewPeer(contact, target_kbucket_index,
                              rank_info, upgrade_lock) != 0) {
        // ForceK failed.  Find the oldest contact in the bucket
        Contact oldest_contact = GetLastSeenContact(target_kbucket_index);
        // fire a signal here to notify
        (*ping_oldest_contact_)(oldest_contact, contact, rank_info);
      }
    }
  } else {
    // bucket not full, insert the contact into routing table
    RoutingTableContact new_routing_table_contact(contact, kThisId_,
                                                  rank_info,
                                                  common_leading_bits);
    new_routing_table_contact.kbucket_index = target_kbucket_index;
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    contacts_.insert(new_routing_table_contact);
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
  boost::uint16_t end_kbucket_index = start_kbucket_index +1;

  boost::uint32_t potential_size = KBucketSizeForKey(start_kbucket_index);
  boost::uint32_t target_size = count + exclude_contacts.size();
  // extend the search range step 1: add all kbuckets containing more
  // common heading bits, the bucket contains the holder will always be the last
  while (end_kbucket_index <= bucket_of_holder_) {
    potential_size = potential_size + KBucketSizeForKey(end_kbucket_index);
    ++end_kbucket_index;
  }
  // extend the search range step 2:recursively add kbuckets containing
  // less common heading bits till reach the count cap
  while ((potential_size < target_size) && (start_kbucket_index > 0)) {
    --start_kbucket_index;
    potential_size = potential_size + KBucketSizeForKey(start_kbucket_index);
  }

  // once we have the search range, put all contacts in the range buckets into
  // a candidate container, using target_id to re-calculate the distance
  RoutingTableContactsContainer candidate_contacts;
  while (start_kbucket_index < end_kbucket_index) {
    bmi::index_iterator<RoutingTableContactsContainer,
        KBucketTag>::type ic0, ic1;
    boost::tuples::tie(ic0, ic1)
      = bmi::get<KBucketTag>(contacts_).equal_range(start_kbucket_index);
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
    ++start_kbucket_index;
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
    const size_t &count,
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

int RoutingTable::SetValidated(const NodeId &node_id,
                               bool validated) {
  std::shared_ptr<UpgradeLock> upgrade_lock(new UpgradeLock(shared_mutex_));

  UnValidatedContactsById contact_indx =
      unvalidated_contacts_.get<NodeIdTag>();
  auto it_contact = contact_indx.find(node_id);

  // if the contact can be find in the un-validated contacts container
  if (it_contact != contact_indx.end()) {
    // If an un-validated entry proved to be valid
    // remove it from un-validated container and insert it into routing_table.
    // Otherwise, the entry shall be dropped.
    if (validated) {
      InsertContact((*it_contact).contact, (*it_contact).rank_info,
                    upgrade_lock);
    }
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    contact_indx.erase(it_contact);
    return 0;
  }

  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    if (!validated) {
      // if the contact proved to be invalid, remove it from the routing_table
      // and put it into the un-validated contacts container
      UpgradeToUniqueLock unique_lock(*upgrade_lock);
      UnValidatedContact new_entry((*it).contact, (*it).rank_info);
      unvalidated_contacts_.insert(new_entry);
      key_indx.erase(it);
    }
    return 0;
  }

  return -1;
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
  auto it = contacts_.get<BootstrapTag>().equal_range(true);
  contacts->clear();
  contacts->reserve(distance(it.first, it.second));
  while (it.first != it.second)
    contacts->push_back((*it.first++).contact);
}

PingOldestContactPtr RoutingTable::ping_oldest_contact() {
  return ping_oldest_contact_;
}

ValidateContactPtr RoutingTable::validate_contact() {
  return validate_contact_;
}

Contact RoutingTable::GetLastSeenContact(const boost::uint16_t &kbucket_index) {
  auto pit = contacts_.get<KBucketLastSeenTag>().equal_range(boost::make_tuple(
      kbucket_index));
  return (*pit.first).contact;
}

boost::uint16_t RoutingTable::KBucketIndex(const NodeId &key) {
//   if (key > NodeId::kMaxId)
//     return -1;
  boost::uint16_t common_leading_bits = KDistanceTo(key);
  if (common_leading_bits > bucket_of_holder_)
    common_leading_bits = bucket_of_holder_;
  return common_leading_bits;
}

boost::uint16_t RoutingTable::KBucketIndex(
    const boost::uint16_t &common_leading_bits) {
  if (common_leading_bits > bucket_of_holder_)
    return bucket_of_holder_;
  return common_leading_bits;
}

boost::uint16_t RoutingTable::KBucketCount() const {
  return bucket_of_holder_+1;
}

boost::uint16_t RoutingTable::KBucketSizeForKey(const boost::uint16_t &key) {
  if (key > bucket_of_holder_) {
    auto pit = contacts_.get<KBucketTag>().equal_range(bucket_of_holder_);
    return static_cast<boost::uint16_t>(distance(pit.first, pit.second));
  } else {
    auto pit = contacts_.get<KBucketTag>().equal_range(key);
    return static_cast<boost::uint16_t>(distance(pit.first, pit.second));
  }
}

void RoutingTable::SplitKbucket(std::shared_ptr<UpgradeLock> upgrade_lock) {
  // each time the split means:
  //    split the bucket of holder, contacts having common leading bits
  //    (bucket_of_holder_, 512) into (bucket_of_holder_+1,512) and
  //    bucket_of_holder_
  // modify all related contacts's kbucket index tag in the contact container
  auto pit = contacts_.get<KBucketTag>().equal_range(bucket_of_holder_);
  auto it_begin = pit.first;
  auto it_end = pit.second;
  std::vector<NodeId> contacts_need_change;
  while (it_begin != it_end) {
    if ((*it_begin).common_leading_bits > bucket_of_holder_) {
      // note, change the KBucket value here will cause re-sorting of the
      // multi-index container. So we can only collect the node_id of the
      // contacts need to be changed, then change their kbucket value later
      contacts_need_change.push_back((*it_begin).node_id);
    }
    ++it_begin;
  }
  ContactsById key_node_indx = contacts_.get<NodeIdTag>();
  UpgradeToUniqueLock unique_lock(*upgrade_lock);
  for (auto it = contacts_need_change.begin();
       it != contacts_need_change.end(); ++it) {
    auto it_contact = key_node_indx.find(*it);
    key_node_indx.modify(it_contact, ChangeKBucketIndex(bucket_of_holder_+1));
  }
  ++bucket_of_holder_;
}

int RoutingTable::ForceKAcceptNewPeer(
    const Contact &new_contact,
    const boost::uint16_t &target_bucket,
    RankInfoPtr rank_info,
    std::shared_ptr<UpgradeLock> upgrade_lock) {
  boost::uint16_t brother_bucket_of_holder = bucket_of_holder_ - 1;
  if (brother_bucket_of_holder != target_bucket) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (Not in Brother Bucket!)"
        << std::endl;
    return -3;
  }
  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = k_ - KBucketSizeForKey(bucket_of_holder_);
  if (v <= 0) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (v <= 0)" << std::endl;
    return -2;
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
  UpgradeToUniqueLock unique_lock(*upgrade_lock);
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

size_t RoutingTable::Size() {
  SharedLock shared_lock(shared_mutex_);
  return contacts_.size();
}

void RoutingTable::Clear() {
  UniqueLock unique_lock(shared_mutex_);
  unvalidated_contacts_.clear();
  contacts_.clear();
  bucket_of_holder_ = 0;
}

}  // namespace kademlia

}  // namespace maidsafe
