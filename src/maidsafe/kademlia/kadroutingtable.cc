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

#include "maidsafe/kademlia/kadroutingtable.h"
#include <boost/cstdint.hpp>
#include "maidsafe/base/utils.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kbucket.h"

namespace kad {

RoutingTable::RoutingTable(const KadId &holder_id, const boost::uint16_t &rt_K)
    : k_buckets_(), bucket_upper_address_(), holder_id_(holder_id),
      bucket_of_holder_(0), brother_bucket_of_holder_(-1),
      address_space_upper_address_(KadId::kMaxId), K_(rt_K) {
  KadId min_range;
  boost::shared_ptr<KBucket> kbucket(new KBucket(min_range,
      address_space_upper_address_, K_));
  k_buckets_.push_back(kbucket);
  bucket_upper_address_.insert(std::pair<KadId, boost::uint16_t>
      (address_space_upper_address_, 0));
}

RoutingTable::~RoutingTable() {
  k_buckets_.clear();
  bucket_upper_address_.clear();
}

boost::int16_t RoutingTable::KBucketIndex(const KadId &key) {
  if (key > address_space_upper_address_)
    return -1;
  std::map<KadId, boost::uint16_t>::iterator lower_bound_iter =
      bucket_upper_address_.lower_bound(key);
  return (*lower_bound_iter).second;
}

std::vector<boost::uint16_t> RoutingTable::SortBucketsByDistance(
    const KadId &key) {
  std::map<KadId, boost::uint16_t> distance;
  // For a given k-bucket, all contacts are either all closer to or all further
  // from a given key than every other contact outwith that k-bucket.  Hence we
  // iterate through each k-bucket's max id and insert xor distance to map.
  std::map<KadId, boost::uint16_t>::iterator iter;
  for (iter = bucket_upper_address_.begin();
       iter != bucket_upper_address_.end(); ++iter) {
    distance.insert(std::pair<KadId, boost::uint16_t>(((*iter).first ^ key),
                                                       (*iter).second));
  }
  std::vector<boost::uint16_t> indices;
  for (std::map<KadId, boost::uint16_t>::iterator dist_iter = distance.begin();
       dist_iter != distance.end(); ++dist_iter) {
    indices.push_back((*dist_iter).second);
  }
  return indices;
}

// TODO(Team): optimise method.  A map is not neaded, sort the vector using
// std::sort
int RoutingTable::SortContactsByDistance(const KadId &key,
                                         std::vector<Contact> *contacts) {
  boost::uint32_t number_of_contacts = contacts->size();
  std::map<KadId, Contact> distance;
  for (boost::uint32_t i = 0; i < contacts->size(); ++i) {
    distance.insert(std::pair<KadId, Contact> (contacts->at(i).node_id() ^ key,
        contacts->at(i)));
  }
  contacts->clear();
  for (std::map<KadId, Contact>::const_iterator dist_iter = distance.begin();
       dist_iter != distance.end(); ++dist_iter)
    contacts->push_back((*dist_iter).second);
  return contacts->size() == number_of_contacts ? 0 : -1;
}

bool RoutingTable::GetContact(const KadId &node_id, Contact *contact) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return false;
  if (!k_buckets_[index]->GetContact(node_id, contact))
    return false;
  return true;
}

void RoutingTable::TouchKBucket(const KadId &node_id) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return;
  k_buckets_[index]->set_last_accessed(base::GetEpochTime());
}

void RoutingTable::RemoveContact(const KadId &node_id, const bool &force) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return;
  k_buckets_[index]->RemoveContact(node_id, force);
}

void RoutingTable::SplitKbucket(const boost::uint16_t &index) {
  KadId range_max_kb_left, range_min_kb_right;
  KadId::SplitRange(k_buckets_[index]->range_min(),
      k_buckets_[index]->range_max(), &range_max_kb_left, &range_min_kb_right);
  boost::shared_ptr<KBucket> kb_left(new KBucket
      (k_buckets_[index]->range_min(), range_max_kb_left, K_));
  boost::shared_ptr<KBucket> kb_right(new KBucket
      (range_min_kb_right, k_buckets_[index]->range_max(), K_));
  // Getting all contacts of the kbucket to be split
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[index]->GetContacts(K_, ex_contacts, &contacts);
  int clb(0), crb(0);
  for (int i = contacts.size()-1; i > -1; --i) {
    Contact contact = contacts[i];
    KBucketExitCode exitcode;
    if (kb_left->KeyInRange(contact.node_id())) {
      exitcode = kb_left->AddContact(contact);
      ++clb;
    } else {
      exitcode = kb_right->AddContact(contact);
      ++crb;
    }
  }
  // delete k_buckets_[index];
  k_buckets_.erase(k_buckets_.begin()+index);
  k_buckets_.insert(k_buckets_.begin()+index, kb_left);
  k_buckets_.insert(k_buckets_.begin()+index+1, kb_right);
  bucket_upper_address_.clear();
  for (size_t j = 0; j < k_buckets_.size(); ++j)
  bucket_upper_address_.insert(std::pair<KadId, boost::uint16_t>
      (k_buckets_[j]->range_max(), j));
  // Implement Force K algorithm
  // Keep tracking the bucket of the peer and brother bucket of the peer
  if (k_buckets_[index]->KeyInRange(holder_id_)) {
    bucket_of_holder_ = index;
    brother_bucket_of_holder_ = index + 1;
  } else {
    bucket_of_holder_ = index + 1;
    brother_bucket_of_holder_ = index;
  }
}

int RoutingTable::AddContact(const Contact &new_contact) {
  boost::int16_t index = KBucketIndex(new_contact.node_id());
  KBucketExitCode exitcode = FAIL;
  if (index < 0)
    return 3;
  exitcode = k_buckets_[index]->AddContact(new_contact);
  switch (exitcode) {
    case SUCCEED: return 0;
    case FULL: if (K_ > 2 && !k_buckets_[index]->KeyInRange(holder_id_)) {
                 if (index == brother_bucket_of_holder_) {
                   // Force a peer always accept peers belonging to the brother
                   // bucket of the peer in case they are amongst k closet
                   // neighbours
                   if (ForceKAcceptNewPeer(new_contact) != 0) {
                     return 2;
                   } else {
                     return 0;
                   }
                 }
                 return 2;
               }
               SplitKbucket(index);
               return AddContact(new_contact);
    case FAIL:
    default: return -2;
  }
}

void RoutingTable::FindCloseNodes(
    const KadId &key, int count, const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  int index = KBucketIndex(key);
  if (index < 0)
    return;
  k_buckets_[index]->GetContacts(count, exclude_contacts, close_nodes);
  bool full = (count == static_cast<int>(close_nodes->size()));
  if (full)
    return;
  std::vector<boost::uint16_t> indices = SortBucketsByDistance(key);
  // Start for loop at 1, as we have already added contacts from closest bucket.
  for (boost::uint32_t index_no = 1; index_no < indices.size(); ++index_no) {
    std::vector<Contact> contacts;
    k_buckets_[indices[index_no]]->GetContacts(K_, exclude_contacts, &contacts);
    if (0 != SortContactsByDistance(key, &contacts))
      continue;
    boost::uint32_t iter(0);
    while (!full && iter < contacts.size()) {
      close_nodes->push_back(contacts[iter]);
      ++iter;
      full = (count == static_cast<int>(close_nodes->size()));
    }
    if (full)
      return;
  }
}

void RoutingTable::GetRefreshList(const boost::uint16_t &start_kbucket,
                                  const bool &force, std::vector<KadId> *ids) {
  boost::uint32_t curr_time = base::GetEpochTime();
  for (size_t i = start_kbucket; i < k_buckets_.size(); ++i)
    if (force || curr_time-k_buckets_[i]->last_accessed() > kRefreshTime) {
      ids->push_back(KadId(k_buckets_[i]->range_min(),
                           k_buckets_[i]->range_max()));
    }
}

size_t RoutingTable::KbucketSize() const { return k_buckets_.size(); }

size_t RoutingTable::Size() const {
  size_t size(0);
  std::vector< boost::shared_ptr<KBucket> >::const_iterator it;
  for (it = k_buckets_.begin(); it != k_buckets_.end(); ++it) {
    size += (*it)->Size();
  }
  return size;
}

bool RoutingTable::GetContacts(const boost::uint16_t &index,
                               const std::vector<Contact> &exclude_contacts,
                               std::vector<Contact> *contacts) {
  if (index > k_buckets_.size())
    return false;
  contacts->clear();
  k_buckets_[index]->GetContacts(K_, exclude_contacts, contacts);
  return true;
}

void RoutingTable::Clear() {
  k_buckets_.clear();
  bucket_upper_address_.clear();
  KadId min_range;
  boost::shared_ptr<KBucket> kbucket(new KBucket(min_range,
      address_space_upper_address_, K_));
  k_buckets_.push_back(kbucket);
  bucket_upper_address_.insert(std::pair<KadId, boost::uint16_t>
      (address_space_upper_address_, 0));
}

namespace detail {
struct ForceKEntry {
  Contact contact;
  int score;
};

struct ContactWithTargetPeer {
  Contact contact;
  KadId holder_id;
};

bool compare_distance(const ContactWithTargetPeer &first,
                      const ContactWithTargetPeer &second) {
  KadId id;
  if (first.contact.node_id() == id)
    return true;
  if (second.contact.node_id() == id)
    return false;
  return KadId::CloserToTarget(first.contact.node_id(),
      second.contact.node_id(), first.holder_id);
}

bool compare_time(const ContactWithTargetPeer &first,
                  const ContactWithTargetPeer &second) {
  if (first.contact.last_seen() > second.contact.last_seen())
    return true;
  else
    return false;
}

bool compare_score(const ForceKEntry &first, const ForceKEntry &second) {
  if (first.score > second.score)
    return true;
  else
    return false;
}

bool get_least_useful_contact(std::list<ContactWithTargetPeer> l,
                              Contact *least_useful_contact) {
  l.sort(compare_distance);
  std::list<ForceKEntry> l_score;
  int d = 1;
  for (std::list<ContactWithTargetPeer>::iterator it = l.begin();
      it != l.end(); ++it) {
    ForceKEntry entry = {it->contact, d++};
    l_score.push_back(entry);
  }
  l.sort(compare_time);
  int t = 1;
  for (std::list<ContactWithTargetPeer>::iterator it = l.begin();
      it != l.end(); ++it) {
    for (std::list<ForceKEntry>::iterator it1 = l_score.begin();
        it1 != l_score.end(); ++it1) {
      if (it->contact.Equals(it1->contact))
        it1->score += t++;
    }
  }
  l_score.sort(compare_score);
  if (!l_score.empty()) {
    // return the contact with the highest score
    *least_useful_contact = l_score.front().contact;
    return true;
  } else {
    return false;
  }
}

}  // namespace detail

int RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact) {
  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = K_ - k_buckets_[bucket_of_holder_]->Size();
  if (v == 0) {
#ifdef DEBUG
    printf("RT::ForceKAcceptNewPeer - (v == 0)\n");
#endif
    return 1;
  }
  // Getting all contacts of the brother kbucket of the peer
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[brother_bucket_of_holder_]->GetContacts(K_, ex_contacts,
                                                     &contacts);
  std::list<detail::ContactWithTargetPeer> candidates_for_l;
  for (size_t i = 0; i < contacts.size(); ++i) {
    detail::ContactWithTargetPeer entry = {contacts[i], holder_id_};
    candidates_for_l.push_back(entry);
  }
  candidates_for_l.sort(detail::compare_distance);
  // Check whether the new peer is among the v nodes
  std::list<detail::ContactWithTargetPeer>::iterator it;
  it = candidates_for_l.begin();
  advance(it, v - 1);
  if (it == candidates_for_l.end()) {
#ifdef DEBUG
    printf("RT::ForceKAcceptNewPeer - (it == candidates_for_l.end())\n");
#endif
    return 1;
  }
  if (KadId::CloserToTarget(it->contact.node_id(), new_contact.node_id(),
                            holder_id_)) {
    // new peer isn't among the k closest neighbours
#ifdef DEBUG
    printf("RT::ForceKAcceptNewPeer - new peer isn't among the k closest\n");
#endif
    return 1;
  }
  // new peer is among the k closest neighbours
  // put all entries of Bp , which are not among the k closest peers into a
  // list l and drop the peer which is the least useful
  std::list<detail::ContactWithTargetPeer> l;
  for (; it != candidates_for_l.end(); ++it)
    l.push_back(*it);
  Contact least_useful_contact;
  if (detail::get_least_useful_contact(l, &least_useful_contact)) {
    k_buckets_[brother_bucket_of_holder_]->RemoveContact(
        least_useful_contact.node_id(), true);
    k_buckets_[brother_bucket_of_holder_]->AddContact(new_contact);
    return 0;
  }
#ifdef DEBUG
  printf("RT::ForceKAcceptNewPeer - -1 at the end\n");
#endif
  return -1;
}

Contact RoutingTable::GetLastSeenContact(const boost::uint16_t &kbucket_index) {
  Contact last_seen;
  if (static_cast<size_t>(kbucket_index + 1) > k_buckets_.size())
    return last_seen;
  return k_buckets_[kbucket_index]->LastSeenContact();
}

void RoutingTable::GetFurthestContacts(
    const KadId &key, const boost::int8_t count,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  if (count < -1 || count == 0) {
    close_nodes->clear();
    return;
  }

  for (size_t n = 0; n < k_buckets_.size(); ++n) {
    k_buckets_[n]->GetContacts(K_, exclude_contacts, close_nodes);
  }

  int a = SortContactsByDistance(key, close_nodes);
  if (a != 0) {
    close_nodes->clear();
    return;
  } else {
    std::reverse(close_nodes->begin(), close_nodes->end());
  }

  if (count > 0 && close_nodes->size() > size_t(count)) {
    close_nodes->resize(count);
  }

//  } else {
//    // Get contacts from buckets furthest away until required number reached
//    std::vector<boost::uint16_t> indexesiuma = SortBucketsByDistance(key);
//    std::reverse(indexesiuma.begin(), indexesiuma.end());
//    for (size_t nn = 0; nn < indexesiuma.size(); ++nn)
//      printf("%d\n", indexesiuma[nn]);
//    size_t nodes_needed(static_cast<size_t>(count));
//    std::vector<Contact> round_nodes;
//    boost::uint16_t nodes_remaining(static_cast<boost::uint16_t>(count));
//    for (size_t n = 0;
//         n < indexesiuma.size()  && close_nodes->size() < nodes_needed; ++n) {
//      if (nodes_remaining < K_) {
//        k_buckets_[n]->GetContacts(nodes_remaining, exclude_contacts,
//                                   &round_nodes);
//      } else {
//        k_buckets_[n]->GetContacts(K_, exclude_contacts, close_nodes);
//      }
//      nodes_remaining -= round_nodes.size();
//      close_nodes->insert(close_nodes->end(), round_nodes.begin(),
//                          round_nodes.end());
//    }
//  }
}

}  // namespace kad
