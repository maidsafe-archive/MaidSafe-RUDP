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

#include "maidsafe/dht/kademlia/routing_table.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/utils.h"
#include "maidsafe/dht/log.h"

namespace maidsafe {

namespace dht {

namespace kademlia {

RoutingTable::RoutingTable(const NodeId &this_id, const uint16_t &k)
    : kThisId_(this_id),
      kDebugId_(DebugId(kThisId_)),
      k_(k),
      contacts_(),
      unvalidated_contacts_(),
      ping_oldest_contact_(new PingOldestContactPtr::element_type),
      validate_contact_(new ValidateContactPtr::element_type),
      ping_down_contact_(new PingDownContactPtr::element_type),
      shared_mutex_(),
      bucket_of_holder_(0) {}

RoutingTable::~RoutingTable() {
  UniqueLock unique_lock(shared_mutex_);
  unvalidated_contacts_.clear();
  contacts_.clear();
}

int RoutingTable::AddContact(const Contact &contact, RankInfoPtr rank_info) {
  const NodeId &node_id = contact.node_id();

  // If the contact has the same ID as the holder, return directly
  if (node_id == kThisId_) {
    DLOG(WARNING) << kDebugId_ << ": Can't add own ID to routing table.";
    return kOwnIdNotIncludable;
  }

  // Check if the contact is already in the routing table; if so, set its last
  // seen time to now (will bring it to the top)
  std::shared_ptr<UpgradeLock> upgrade_lock(new UpgradeLock(shared_mutex_));
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it_node = key_indx.find(node_id);
  if (it_node != key_indx.end()) {
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    // will update the num_failed_rpcs to 0 as well
    if (contacts_.modify(it_node,
        ChangeLastSeen(bptime::microsec_clock::universal_time()))) {
      return kSuccess;
    } else {
      DLOG(WARNING) << kDebugId_ << ": Failed to update last seen time for "
                    << DebugId(contact);
      return kFailedToUpdateLastSeenTime;
    }
  } else {
    // put the contact into the unvalidated contacts container
    UnValidatedContactsById contact_indx =
        unvalidated_contacts_.get<NodeIdTag>();
    auto it_contact = contact_indx.find(node_id);
    if (it_contact == contact_indx.end()) {
      UnValidatedContact new_entry(contact, rank_info);
      unvalidated_contacts_.insert(new_entry);
      // fire the signal to validate the contact
      upgrade_lock->unlock();
      (*validate_contact_)(contact);
    }
    return kSuccess;
  }
}

void RoutingTable::InsertContact(const Contact &contact,
                                 RankInfoPtr rank_info,
                                 std::shared_ptr<UpgradeLock> upgrade_lock) {
  uint16_t common_leading_bits = KDistanceTo(contact.node_id());
  uint16_t target_kbucket_index = KBucketIndex(common_leading_bits);
  uint16_t k_bucket_size = KBucketSizeForKey(target_kbucket_index);

  // if the corresponding bucket is full
  if (k_bucket_size == k_) {
    // try to split the bucket if the new contact appears to be in the same
    // bucket as the holder
    if (target_kbucket_index == bucket_of_holder_) {
      SplitKbucket(upgrade_lock);
      InsertContact(contact, rank_info, upgrade_lock);
    } else {
      // try to apply ForceK, otherwise fire the signal
      int force_k_result(ForceKAcceptNewPeer(contact, target_kbucket_index,
                                             rank_info, upgrade_lock));
      if (force_k_result != kSuccess &&
          force_k_result != kFailedToInsertNewContact) {
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
    auto result = contacts_.insert(new_routing_table_contact);
    if (result.second) {
      DLOG(INFO) << kDebugId_ << ": Added node " << DebugId(contact) << ".  "
                 << contacts_.size() << " contacts.";
    } else {
      DLOG(WARNING) << kDebugId_ << ": Failed to insert node "
                    << DebugId(contact);
    }
  }
}

int RoutingTable::GetContact(const NodeId &node_id, Contact *contact) {
  if (!contact) {
    DLOG(WARNING) << kDebugId_ << ": Null pointer passed.";
    return kInvalidPointer;
  }
  SharedLock shared_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    *contact = (*it).contact;
    return kSuccess;
  } else {
    *contact = Contact();
    return kFailedToFindContact;
  }
}

void RoutingTable::GetCloseContacts(
    const NodeId &target_id,
    const size_t &count,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_contacts) {
  if (!close_contacts) {
    DLOG(WARNING) << kDebugId_ << ": Null pointer passed.";
    return;
  }
  SharedLock shared_lock(shared_mutex_);
  // the search will begin from a bucket having the similiar k-distance as the
  // target node to the current holder
  // then extend the range follows the rule:
  //      all kbuckets contains more common leading bits shall be considered
  //      if the total still smaller than the count, then recursively add
  //      kbuckets containing less leading bits till reach the count cap
  uint16_t start_kbucket_index = KBucketIndex(target_id);
  uint16_t end_kbucket_index = start_kbucket_index +1;

  uint32_t potential_size = KBucketSizeForKey(start_kbucket_index);
  uint32_t target_size = static_cast<uint32_t>(count + exclude_contacts.size());
  // extend the search range step 1: add all kbuckets containing more
  // common leading bits, the bucket contains the holder will always be the last
  while (end_kbucket_index <= bucket_of_holder_) {
    potential_size = potential_size + KBucketSizeForKey(end_kbucket_index);
    ++end_kbucket_index;
  }
  // extend the search range step 2:recursively add kbuckets containing
  // less common leading bits till reach the count cap
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
  uint32_t counter(0);
  auto it = key_dist_indx.begin();
  while ((counter < count) && (it != key_dist_indx.end())) {
    close_contacts->push_back((*it).contact);
    ++counter;
    ++it;
  }
  return;
}

void RoutingTable::Downlist(const NodeId &node_id) {
  SharedLock shared_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it != key_indx.end())
    (*ping_down_contact_)((*it).contact);
}

int RoutingTable::SetPublicKey(const NodeId &node_id,
                               const std::string &new_public_key) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  if (key_indx.modify(it, ChangePublicKey(new_public_key))) {
    return kSuccess;
  } else {
    DLOG(WARNING) << kDebugId_ << ": Failed to set public key for node "
                  << DebugId(node_id);
    return kFailedToSetPublicKey;
  }
}

int RoutingTable::UpdateRankInfo(const NodeId &node_id,
                                 RankInfoPtr new_rank_info) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  if (key_indx.modify(it, ChangeRankInfo(new_rank_info))) {
    return kSuccess;
  } else {
    DLOG(WARNING) << kDebugId_ << ": Failed to update rank info for node "
                  << DebugId(node_id);
    return kFailedToUpdateRankInfo;
  }
}

int RoutingTable::SetPreferredEndpoint(const NodeId &node_id, const IP &ip) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  Contact new_local_contact((*it).contact);
  new_local_contact.SetPreferredEndpoint(ip);
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  if (key_indx.modify(it, ChangeContact(new_local_contact))) {
    return kSuccess;
  } else {
    DLOG(WARNING) << kDebugId_ << ": Failed to set preferred endpt for node "
                  << DebugId(node_id);
    return kFailedToSetPreferredEndpoint;
  }
}

int RoutingTable::SetValidated(const NodeId &node_id, bool validated) {
  std::shared_ptr<UpgradeLock> upgrade_lock(new UpgradeLock(shared_mutex_));
  UnValidatedContactsById contact_indx =
      unvalidated_contacts_.get<NodeIdTag>();
  auto it_contact = contact_indx.find(node_id);

  // if the contact can be find in the un-validated contacts container
  if (it_contact != contact_indx.end()) {
    // If an un-validated entry proved to be valid remove it from un-validated
    // container and insert it into routing_table.  Otherwise, drop it.
    if (validated) {
      InsertContact((*it_contact).contact, (*it_contact).rank_info,
                    upgrade_lock);
    }
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    contact_indx.erase(it_contact);
    return kSuccess;
  }

  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }

  if (!validated) {
    // if the contact proved to be invalid, remove it from the routing_table
    // and put it into the un-validated contacts container.
    DLOG(WARNING) << kDebugId_ << ": Node " << DebugId(node_id)
                  << " removed from routing table - failed to validate.  "
                  << contacts_.size() << " contacts.";
    UpgradeToUniqueLock unique_lock(*upgrade_lock);
    UnValidatedContact new_entry((*it).contact, (*it).rank_info);
    unvalidated_contacts_.insert(new_entry);
    key_indx.erase(it);
  }
  return kSuccess;
}

int RoutingTable::IncrementFailedRpcCount(const NodeId &node_id) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(node_id);
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(node_id);
    return kFailedToFindContact;
  }
  uint16_t num_failed_rpcs = (*it).num_failed_rpcs + 1;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  if (num_failed_rpcs > kFailedRpcTolerance) {
    key_indx.erase(it);
    DLOG(INFO) << kDebugId_ << ": Removed node " << DebugId(node_id) << ".  "
               << contacts_.size() << " contacts.";
    return kSuccess;
  } else {
    if (key_indx.modify(it, ChangeNumFailedRpc(num_failed_rpcs))) {
      DLOG(INFO) << kDebugId_ << ": Incremented failed rpc count for node "
                 << DebugId(node_id) << " to " << num_failed_rpcs;
      return kSuccess;
    } else {
      DLOG(WARNING) << kDebugId_ << ": Failed to increment failed rpc count "
                    << "for node " << DebugId(node_id);
      return kFailedToIncrementFailedRpcCount;
    }
  }
}

void RoutingTable::GetBootstrapContacts(std::vector<Contact> *contacts) {
  if (!contacts)
    return;

  SharedLock shared_lock(shared_mutex_);
  auto it = contacts_.get<BootstrapTag>().equal_range(true);
  contacts->clear();
  while (it.first != it.second)
    contacts->push_back((*it.first++).contact);

  if (contacts->size() < kMinBootstrapContacts) {
    it = contacts_.get<BootstrapTag>().equal_range(false);
    while (it.first != it.second)
      contacts->push_back((*it.first++).contact);
  }
}

RankInfoPtr RoutingTable::GetLocalRankInfo(const Contact &contact) {
  SharedLock shared_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.find(contact.node_id());
  if (it == key_indx.end()) {
    DLOG(WARNING) << kDebugId_ << ": Failed to find node " << DebugId(contact);
    return RankInfoPtr();
  } else {
    return (*it).rank_info;
  }
}

void RoutingTable::GetAllContacts(std::vector<Contact> *contacts) {
  if (!contacts) {
    DLOG(WARNING) << kDebugId_ << ": Null pointer passed.";
    return;
  }
  SharedLock shared_lock(shared_mutex_);
  ContactsById key_indx = contacts_.get<NodeIdTag>();
  auto it = key_indx.begin();
  auto it_end = key_indx.end();
  contacts->clear();
  contacts->reserve(distance(it, it_end));
  while (it != it_end) {
    contacts->push_back((*it).contact);
    ++it;
  }
}

PingOldestContactPtr RoutingTable::ping_oldest_contact() {
  return ping_oldest_contact_;
}

ValidateContactPtr RoutingTable::validate_contact() {
  return validate_contact_;
}

PingDownContactPtr RoutingTable::ping_down_contact() {
  return ping_down_contact_;
}

Contact RoutingTable::GetLastSeenContact(const uint16_t &kbucket_index) {
  auto pit = contacts_.get<KBucketLastSeenTag>().equal_range(boost::make_tuple(
      kbucket_index));
  return (*pit.first).contact;
}

uint16_t RoutingTable::KBucketIndex(const NodeId &key) {
//   if (key > NodeId::kMaxId)
//     return -1;
  uint16_t common_leading_bits = KDistanceTo(key);
  if (common_leading_bits > bucket_of_holder_)
    common_leading_bits = bucket_of_holder_;
  return common_leading_bits;
}

uint16_t RoutingTable::KBucketIndex(const uint16_t &common_leading_bits) {
  if (common_leading_bits > bucket_of_holder_)
    return bucket_of_holder_;
  return common_leading_bits;
}

uint16_t RoutingTable::KBucketCount() const {
  return bucket_of_holder_+1;
}

uint16_t RoutingTable::KBucketSizeForKey(const uint16_t &key) {
  if (key > bucket_of_holder_) {
    auto pit = contacts_.get<KBucketTag>().equal_range(bucket_of_holder_);
    return static_cast<uint16_t>(distance(pit.first, pit.second));
  } else {
    auto pit = contacts_.get<KBucketTag>().equal_range(key);
    return static_cast<uint16_t>(distance(pit.first, pit.second));
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
    const uint16_t &target_bucket,
    RankInfoPtr rank_info,
    std::shared_ptr<UpgradeLock> upgrade_lock) {
  uint16_t brother_bucket_of_holder = bucket_of_holder_ - 1;
  int kclosest_bucket_index = GetLeastCommonLeadingBitInKClosestContact();
  if ((brother_bucket_of_holder != target_bucket) &&
      (kclosest_bucket_index != target_bucket)) {
    return kNotInBrotherBucket;
  }
  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int closest_outwith_bucket_of_holder =
      k_ - KBucketSizeForKey(bucket_of_holder_);
  if (closest_outwith_bucket_of_holder <= 0)
    return kOutwithClosest;

  // sort the brother bucket based on contacts' distance to the holder
  auto pit = contacts_.get<KBucketDistanceToThisIdTag>().equal_range(
      boost::make_tuple(target_bucket));
  // check if the new contact is among the k closest
  NodeId distance_to_target = kThisId_ ^ new_contact.node_id();
  // pit.second shall point to the furthest contact (need one step forward)
  // as the list will sorted from least to highest
  // while the least value of XOR distance means the nearest
  auto it_end = pit.second;
  --it_end;
  ContactsById key_node_indx = contacts_.get<NodeIdTag>();
  NodeId furthest_distance = (*it_end).distance_to_this_id;
  NodeId furthest_node = (*it_end).node_id;
  auto it_furthest = key_node_indx.find(furthest_node);

  if (furthest_distance <= distance_to_target)
    return kOutwithClosest;

  UpgradeToUniqueLock unique_lock(*upgrade_lock);
  contacts_.erase(it_furthest);
  RoutingTableContact new_local_contact(new_contact, kThisId_,
                                        rank_info,
                                        KDistanceTo(new_contact.node_id()));
  new_local_contact.kbucket_index = target_bucket;
  auto result = contacts_.insert(new_local_contact);
  if (result.second) {
    DLOG(INFO) << kDebugId_ << ": Added node " << DebugId(new_contact)
               << " via ForceK.  " << contacts_.size() << " contacts.";
    return kSuccess;
  } else {
    DLOG(WARNING) << kDebugId_ << ": Failed to insert node "
                  << DebugId(new_contact) << " via ForceK.";
    return kFailedToInsertNewContact;
  }
}

int RoutingTable::GetLeastCommonLeadingBitInKClosestContact() {
  std::vector<Contact> contacts, exclude_contacts;
  GetCloseContacts(kThisId_, k_, exclude_contacts, &contacts);
  ContactsById key_id_indx = contacts_.get<NodeIdTag>();
  auto it = key_id_indx.find(contacts[0].node_id());
  uint16_t kclosest_bucket_index = (*it).common_leading_bits;
  for (size_t i = 1; i < contacts.size(); ++i) {
    it = key_id_indx.find(contacts[i].node_id());
    if (kclosest_bucket_index > (*it).common_leading_bits)
      kclosest_bucket_index = (*it).common_leading_bits;
  }
  return kclosest_bucket_index;
}

uint16_t RoutingTable::KDistanceTo(const NodeId &rhs) const {
  uint16_t distance = 0;
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

}  // namespace dht

}  // namespace maidsafe
