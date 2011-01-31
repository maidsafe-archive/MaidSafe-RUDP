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
      contacts_(),
      kbucket_boundries_(),
      ping_oldest_contact_status_
          (new PingOldestContactStatusPtr::element_type) {
  KBucketBoundary first_boundary(kKeySizeBytes*8,0);
  kbucket_boundries_.insert(first_boundary);
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
    boost::uint16_t target_kbucket_index=KBucketIndex(node_id);
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
           (*ping_oldest_contact_status_)(oldest_contact,
                                          new_contact, rank_info);
        } // ForceK Succeed
      }
    } else {
      // bucket not full, insert the contact into routing table
      RoutingTableContact new_routing_table_contact(new_contact , kThisId_,rank_info);
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

boost::uint16_t RoutingTable::KBucketIndex(const NodeId &key) {
//   if (key > NodeId::kMaxId)
//     return -1;

  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  boost::uint16_t distance_to_this_id = key.DistanceTo(kThisId_);
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
  Contact new_local_contact((*it).contact);
  new_local_contact.SetPreferredEndpoint(ip);
  key_indx.modify(it,ChangeContact(new_local_contact));
  return 0;
}

int RoutingTable::IncrementFailedRpcCount(const NodeId &node_id) {
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.find(node_id);
  if (it == key_indx.end())
    return -1;
  boost::uint16_t num_failed_rpcs=(*it).num_failed_rpcs;
  ++num_failed_rpcs;
  key_indx.modify(it,ChangeNumFailedRpc(num_failed_rpcs));
  return num_failed_rpcs;
}

boost::uint16_t RoutingTable::KbucketSize() const {
//   KBucketBoundariesContainer::index<UpperBoundaryTag>::type key_indx
//     = kbucket_boundries_.get<UpperBoundaryTag>();
  return kbucket_boundries_.size();
}

boost::uint16_t RoutingTable::KBucketSize(const boost::uint16_t &key) {
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it
      = key_indx.lower_bound(key);

  typedef RoutingTableContactsContainer::index<
      KBucketTag>::type::iterator KBucketQuery;
  std::pair< KBucketQuery, KBucketQuery > pit
      = contacts_.get<KBucketTag>()
          .equal_range( (*it).upper_boundary );

  boost::uint16_t kbucket_size(0);
  KBucketQuery it_begin=pit.first;
  KBucketQuery it_end=pit.second;
  while (it_begin!=it_end) {
    ++kbucket_size;
    ++it_begin;
  }
  return kbucket_size;
}

boost::uint16_t RoutingTable::Size() const {
//   RoutingTableContactsContainer::index<NodeIdTag>::type key_indx
//       = contacts_.get<NodeIdTag>();
  return contacts_.size();
}

Contact RoutingTable::GetLastSeenContact(const boost::uint16_t &kbucket_index) {
  typedef RoutingTableContactsContainer::index<
      KBucketLastSeenTag>::type::iterator KBucketLastSeenQuery;
  std::pair< KBucketLastSeenQuery, KBucketLastSeenQuery > pit
      = contacts_.get<KBucketLastSeenTag>()
          .equal_range( boost::make_tuple(kbucket_index) );
  return (*pit.first).contact;
}

// Bisect the k-bucket in the specified index into two new ones
void RoutingTable::SplitKbucket(const boost::uint16_t &kbucket_index) {
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it
      = key_indx.lower_bound(kbucket_index);

  // insert one new element into the kbucket boundaries container
  // and modify the corresponding old one
  boost::uint16_t split_position =
      ((*it).lower_boundary+(*it).upper_boundary)/2;
  boost::uint16_t old_lower_boundary=split_position+1;
  boost::uint16_t new_lower_boundary=(*it).lower_boundary;
  key_indx.modify(it,ChangeLowerBoundary(old_lower_boundary));
  KBucketBoundary new_kbucket_boundary(split_position,new_lower_boundary);
  key_indx.insert(new_kbucket_boundary);

  // modify all related contacts's kbucket index tag in the contact container
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
    if ((*it_begin).distance_to_this_id <= split_position) {
      RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
          = key_node_indx.find((*it_begin).node_id());
      key_node_indx.modify(it,ChangeKBucketIndex(split_position));
    }  
    ++it_begin;
  }
}

void RoutingTable::GetCloseContacts(const NodeId &target_id,
             const boost::uint32_t &count,
             std::vector<Contact> &exclude_contacts,
             std::vector<Contact> *close_contacts) {
  if (target_id.String().size() != kademlia::kKeySizeBytes || close_contacts == NULL)
    return;

  // the search will begin from a bucket having the similiar distance as the
  // target node to the current holder
  // the recursively extend the range if neighbouring bucket's contact still
  // could among the count defined closest nodes
  boost::uint16_t start_kbucket_index=KBucketIndex(target_id);

  KBucketBoundariesContainer::index<UpperBoundaryTag>::type& key_indx
      = kbucket_boundries_.get<UpperBoundaryTag>();
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it_begin
      = key_indx.find(start_kbucket_index);
  KBucketBoundariesContainer::index<UpperBoundaryTag>::type::iterator it_end;
  it_end=it_begin;
  it_end++;
  boost::uint32_t potential_size=KBucketSize(start_kbucket_index);
  boost::uint32_t target_size=count+exclude_contacts.size();
  // extend the search range
  while (potential_size < target_size) {
    if (it_begin!=key_indx.begin()) {
      it_begin--;
      potential_size=potential_size+KBucketSize((*it_begin).upper_boundary);
    }
    if (it_end!=key_indx.end()) {
      it_end++;
      potential_size=potential_size+KBucketSize((*it_begin).upper_boundary);
    }
  }
  if (it_end!=key_indx.end())
    it_end++;

  // once we have the search range, put all contacts in the range buckets into
  // a candidate container, using target_id to re-calculate the distance
  RoutingTableContactsContainer candidate_contacts;
  while (it_begin!=it_end) {
    bmi::index_iterator<RoutingTableContactsContainer,
        KBucketTag>::type ic0,ic1;
    boost::tuples::tie(ic0,ic1)
      = bmi::get<KBucketTag>(contacts_).equal_range((*it_begin).upper_boundary);
    while (ic0!=ic1) {
      // check if the candidate in the exclusion list
      std::vector<Contact>::iterator it=exclude_contacts.begin();
      bool in_exclusion_list=false;
      while ((!in_exclusion_list)&&(it!=exclude_contacts.end())) {
        if ((*it).node_id()==((*ic0).node_id()))
          in_exclusion_list=true;
        ++it;
      }
      // if not in the exclusion list, add the contact into the candidates
      // container
      if (!in_exclusion_list) {
        RoutingTableContact new_contact((*ic0).contact,target_id);
        candidate_contacts.insert(new_contact);
      }
      ++ic0;
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

int RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact,
                                      const boost::uint16_t &target_bucket) {
  // find the bucket that shall contain the holder
  boost::uint16_t bucket_of_holder=KBucketIndex(kThisId_);

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
  boost::uint16_t brother_bucket_of_holder=(*it).upper_boundary;
  
  if (brother_bucket_of_holder != target_bucket) {
    DLOG(WARNING) << "RT::ForceKAcceptNewPeer - (Not in Brother Bucket!)"
        << std::endl;
    return 1;
  }  

  // sort the brother bucket based on contacts' distance to the holder
  typedef RoutingTableContactsContainer::index<
      KBucketDistanceToThisIdTag>::type::iterator KBucketDistanceQuery;
  std::pair< KBucketDistanceQuery, KBucketDistanceQuery > pit
      = contacts_.get<KBucketDistanceToThisIdTag>()
          .equal_range( boost::make_tuple(brother_bucket_of_holder) );

  // check if the new contact is among the top v closest
  bool among_top_v(false);
  RoutingTableContact new_local_contact(new_contact,kThisId_);
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
  // drop the peer which is the furthest
  // it_end from the previous shall point to the furthest contact
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_node_indx
      = contacts_.get<NodeIdTag>();  
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it_furthest
      = key_node_indx.find((*it_end).node_id());
  key_node_indx.erase(it_furthest);
  contacts_.insert(new_local_contact);
  return 0;
}

void RoutingTable::GetBootstrapContacts(std::vector<Contact> *contacts) {
  RoutingTableContactsContainer::index<NodeIdTag>::type& key_indx
      = contacts_.get<NodeIdTag>();
  RoutingTableContactsContainer::index<NodeIdTag>::type::iterator it
      = key_indx.begin();
  while (it!=key_indx.end()) {
    if ( (*it).contact.IsDirectlyConnected() )
      contacts->push_back((*it).contact);
    ++it;
  }
}

void RoutingTable::Clear() {
  contacts_.clear();
  kbucket_boundries_.clear();
  KBucketBoundary first_boundary(kKeySizeBytes*8,0);
  kbucket_boundries_.insert(first_boundary);
}

}  // namespace kademlia

}  // namespace maidsafe
