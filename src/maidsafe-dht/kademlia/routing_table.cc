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

#include "maidsafe-dht/kademlia/routing_table.h"

#include "maidsafe-dht/common/log.h"

#include "maidsafe-dht/common/utils.h"

namespace maidsafe {

namespace kademlia {

RoutingTable::RoutingTable(const NodeId &this_id, const boost::uint16_t &k)
    : kThisId_(this_id),
      K_(k),
      ping_oldest_contact_status_(new PingOldestContactStatusPtr::element_type),
      contacts_(
//           boost::make_tuple(
//           // Index 0 is default constructed
//           ContactsById::ctor_args(),
//           // Index 1 is constructed with KadCloserToThisId()
//           boost::make_tuple(bmi::identity<RoutingTableContact>(),
//                             KadCloserToThisId(kThisId_)),
//           // Index 2 is default constructed
//           ContactsByTimeLastSeen::ctor_args())
          ) {
  // KBucketBoundary first_boundary(NodeId::kMaxId,0);
  // kbucket_boundries_.insert(first_boundary);
}

RoutingTable::~RoutingTable() {
  contacts_.clear();
  kbucket_boundries_.clear();
}

void RoutingTable::AddContact(const Contact& new_contact, RankInfoPtr rank_info){

  // Check if the contact is already in the routing table
  // if so, set it's last seen to now (will bring it to the top)
  NodeId node_id=new_contact.node_id();
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it_node
      = key_indx.find(node_id);

  if (it_node == key_indx.end()) {
    NodeId target_kbucket_index=KBucketIndex(node_id);
    boost::uint16_t k_bucket_size=KBucketSize(target_kbucket_index);

    // if the corresponding bucket is full
    if (k_bucket_size == K_) {
      // try to split the bucket if the new contact appear to be in the same
      // bucket as the holder
      if (target_kbucket_index==KBucketIndex(kThisId_)) {
        SplitKbucket(target_kbucket_index);
        AddContact(new_contact, rank_info);
      } else {
        // try to apply ForceK, otherwise fire the signal
        if (ForceKAcceptNewPeer(new_contact,target_kbucket_index)!=0)
        {
          // ForceK Failed
          // find the oldest contact in the bucket
          Contact oldest_contact=GetLastSeenContact(target_kbucket_index);
          // fire a signal here to notify
//           (*ping_oldest_contact_status_)(&oldest_contact,
//                                          &new_contact, rank_info);
        } // ForceK Succeed
      }
    } else {
      // bucket not full, insert the contact into routing table
      RoutingTableContact new_routing_table_contact(new_contact , kThisId_);
      new_routing_table_contact.kbucket_index=target_kbucket_index;
      key_indx.insert(new_routing_table_contact);
    }
  }else {
    key_indx.modify(it_node,
                     ChangeLastSeen(bptime::microsec_clock::universal_time()));
  }
// Succeed
}

PingOldestContactStatusPtr RoutingTable::PingOldestContactStatus() {
  return this->ping_oldest_contact_status_;
}

NodeId RoutingTable::KBucketIndex(const NodeId &key) {
//   if (key > NodeId::kMaxId)
//     return -1;

  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  NodeId distance_to_this_id = key^kThisId_;
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it
      = key_indx.lower_bound(distance_to_this_id);

  return (*it).upper_boundary;
}

void RoutingTable::GetContact(const NodeId &target_id, Contact *contact){
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(target_id);
  if (it != key_indx.end()) {
    *contact = (*it).contact;
  }
  return;
}

void RoutingTable::RemoveContact(const NodeId &node_id, const bool &force){
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(node_id);
  if (it != key_indx.end()) {
    RoutingTableContact current_element((*it));
    current_element.num_failed_rpcs++;
    key_indx.erase(it);
    if (current_element.num_failed_rpcs <= kFailedRpcTolerance && !force) {
      // make sure SetLastSeenToNow will do thing expected
      // current_element.contact.SetLastSeenToNow();
      key_indx.insert(current_element);
    }
  }
}

int RoutingTable::SetPublicKey(const NodeId &node_id,
             const std::string &new_public_key){
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(node_id);
  if (it == key_indx.end())
    return 1;
  key_indx.modify(it,ChangePublicKey(new_public_key));
  return 0;
}

int RoutingTable::UpdateRankInfo(const NodeId &node_id, RankInfoPtr new_rank_info){
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(node_id);
  if (it == key_indx.end())
    return 1;
  key_indx.modify(it,ChangeRankInfo(new_rank_info));
  return 0;
}

int RoutingTable::SetPreferredEndpoint(const NodeId &node_id,
       const IP &ip) {
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(node_id);
  if (it == key_indx.end())
    return 1;
  RankInfoPtr local_rank_info((*it).rank_info);
  // TransportPtr(*local_rank_info).=ip;
  key_indx.modify(it,ChangeRankInfo(local_rank_info));
  return 0;
}

// int RoutingTable::IncrementFailedRpcsCount(const NodeId &node_id) {
//   RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
//       = contacts_.get<NodeIdTag>();
//   RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
//       = key_indx.find(node_id);
//   if (it == key_indx.end())
//     return -1;
//   boost::uint16_t num_failed_rpcs=(*it).num_failed_rpcs;
//   ++num_failed_rpcs;
//   key_indx.modify(it,ChangeNumFailedRpc(num_failed_rpcs));
//   return num_failed_rpcs;
// }

boost::uint16_t RoutingTable::KbucketSize() const {
//   KBucketBoundariesContainer::index<UpperBoundaryTag>::type key_indx
//     = kbucket_boundries_.get<UpperBoundaryTag>();
  return kbucket_boundries_.size();
}

boost::uint16_t RoutingTable::Size() const {
//   RoutingTableContactsContainer::index<NodeIdTag>::type key_indx
//       = contacts_.get<NodeIdTag>();
  return contacts_.size();
}

Contact RoutingTable::GetLastSeenContact(const NodeId &kbucket_index) {
  typedef RoutingTableContactsContainer::index<
      KBucketLastSeenTag>::type::iterator KBucketLastSeenQuery;
  std::pair< KBucketLastSeenQuery, KBucketLastSeenQuery > pit
      = contacts_.get<KBucketLastSeenTag>()
          .equal_range( boost::make_tuple(kbucket_index) );
  return (*pit.first).contact;
}

// Bisect the k-bucket in the specified index into two new ones
void RoutingTable::SplitKbucket(const NodeId &kbucket_index) {

  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it
      = key_indx.lower_bound(kbucket_index);

  // shall be increased by 1
  NodeId old_lower_boundary=kbucket_index;

  NodeId new_lower_boundary=(*it).lower_boundary;
  key_indx.modify(it,ChangeLowerBoundary(old_lower_boundary));
  KBucketBoundary new_kbucket_boundary(kbucket_index,new_lower_boundary);
  key_indx.insert(new_kbucket_boundary);

  typedef RoutingTableContactsContainer::index<
      KBucketTag>::type::iterator KBucketQuery;
  std::pair< KBucketQuery, KBucketQuery > pit
      = contacts_.get<KBucketTag>()
          .equal_range( (*it).upper_boundary );

  RoutingTableContactsContainer::index<NodeIdTag>::type& key_node_indx
      = contacts_.get<NodeIdTag>();
  KBucketQuery it_begin=pit.first;
  KBucketQuery it_end=pit.second;
  while (it_begin!=it_end) {
    if ((*it_begin).kbucket_index <= kbucket_index) {
      RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
          = key_node_indx.find((*it_begin).node_id());
      key_node_indx.modify(it,ChangeKBucketIndex(kbucket_index));
    }  
    ++it_begin;
  }
}

void RoutingTable::GetCloseContacts(const NodeId &target_id,
             const boost::uint32_t &count,
             const std::vector<Contact> &exclude_contacts,
             std::vector<Contact> *close_contacts) {
  if (target_id.String().size() != kademlia::kKeySizeBytes || close_contacts == NULL)
    return;

  // the search will begin from a bucket having the similiar distance as the
  // target node to the current holder
  // the recursively extend the range if neighbouring bucket's contact still
  // could among the count defined closest nodes
  NodeId start_kbucket_index=KBucketIndex(target_id);

  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it_begin
      = key_indx.find(start_kbucket_index);
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it_end;
  it_end=it_begin;
  it_end++;
  boost::uint32_t potential_size=KBucketSize(start_kbucket_index);
  // extend the search range
  while (potential_size < count) {
    if (it_begin!=key_indx.begin()) {
      it_begin--;
      potential_size=potential_size+KBucketSize((*it_begin).upper_boundary);
    }
    if (it_end!=key_indx.end()) {
      it_end--;
      potential_size=potential_size+KBucketSize((*it_begin).upper_boundary);
    }
  }
  if (it_end!=key_indx.end())
    it_end++;

  // once we have the search range, put all contacts in the range buckets into
  // a candidate container, using target_id to re-calculate the distance
  RoutingTableContactsContainer candidate_contacts;
  while (it_begin!=it_end) {
    boost::multi_index::index_iterator<RoutingTableContactsContainer,
        KBucketTag>::type ic0,ic1;
    boost::tuples::tie(ic0,ic1)
      = bmi::get<KBucketTag>(contacts_).equal_range((*it_begin).upper_boundary);
    while (ic0!=ic1) {
      RoutingTableContact new_contact((*ic0).contact,target_id);
      candidate_contacts.insert(new_contact);
    }
  }

  // populate the result with the count defined top contacts
  // indexed by the new calculated distance
  RoutingTableContactsContainer::index<DistanceToThisIdTag>::type& key_dist_indx
    = candidate_contacts.get<DistanceToThisIdTag>();
  boost::uint32_t counter(0);
  RoutingTableContactsContainer::index<DistanceToThisIdTag>::type::iterator
      it=key_dist_indx.begin();
  while (counter<count)
  {
    close_contacts->push_back((*it).contact);
    ++counter;
    ++it;
  }

  return ;
}

boost::uint16_t RoutingTable::KBucketSize(const NodeId &key) const {

}

int RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact, const NodeId &target_bucket) {

  // find the bucket that shall contain the holder
  NodeId bucket_of_holder=KBucketIndex(kThisId_);
  if (bucket_of_holder != target_bucket) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (ForceK not apply)" << std::endl;
    return 1;
  }

  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = K_ - KBucketSize(bucket_of_holder);
  if (v == 0) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (v == 0)" << std::endl;
    return 1;
  }  

  // find the brother bucket
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it
      = key_indx.find(bucket_of_holder);  
  it--;
  if (it==key_indx.begin()) {
   DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (no brother bucket)" << std::endl;
   return 1;    
  }
  NodeId brother_bucket_of_holder=(*it).upper_boundary;

  // sort the brother bucket based on contacts' distance to the holder
  RoutingTableContact new_local_contact(new_contact,kThisId_);

  typedef RoutingTableContactsContainer::index<
      KBucketDistanceToThisIdTag>::type::iterator KBucketDistanceQuery;
  std::pair< KBucketDistanceQuery, KBucketDistanceQuery > pit
      = contacts_.get<KBucketDistanceToThisIdTag>()
          .equal_range( boost::make_tuple(brother_bucket_of_holder) );

  // check if the new contact is among the top v closest
  bool among_top_v(false);

  KBucketDistanceQuery it_begin=pit.first;
  KBucketDistanceQuery it_end=pit.second;

  while ((v>0)&&(!among_top_v)) {
    if ((*it_begin).distance_to_this_id > new_local_contact.distance_to_this_id)
      among_top_v=true;
    it_begin++;
    v--;
  }
  if (v == 0) {
   // new peer isn't among the k closest neighbours
   DLOG(WARNING) << "RT::ForceKAcceptNewPeer - "
                    "new peer isn't among the k closest" << std::endl;
    return 1;
  }
  // new peer is among the k closest neighbours
  // put all entries of Bp , which are not among the k closest peers into a
  // list l and drop the peer which is the furthest
  // it_end from the previous shall point to the furthest contact
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_node_indx
      = contacts_.get<NodeIdTag>();  
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it_furthest
      = key_node_indx.find((*it_end).node_id());
  key_node_indx.erase(it_furthest);
  contacts_.insert(new_local_contact);
  return 0;
}

}  // namespace kademlia

}  // namespace maidsafe
