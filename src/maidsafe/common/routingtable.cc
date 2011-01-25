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

#include "maidsafe/common/routingtable.h"
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <algorithm>
#include <vector>

namespace maidsafe {

PublicRoutingTable::~PublicRoutingTable() {
  contacts_.clear();
}  
  
void PublicRoutingTable::AddContact(const maidsafe::Contact& new_contact){
  boost::mutex::scoped_lock guard(mutex_);
  
  // if the routing table is full, return the oldest contact
  if (contacts_.size() == K_)
  {
      // fire a signal here to notify
      // return this->FindOldestContact();
  }
   
  // Check if the contact is already in the routing table
  // if so, set it's last seen to now (will bring it to the top) 
  NodeId node_id=new_contact.node_id();
  ContactsContainer::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  ContactsContainer::index<TagNodeId>::type::iterator it = key_indx.find(node_id); 
  if (it == key_indx.end()) {
    kademlia::RoutingTableContact new_contact_local(new_contact);
    contacts_.insert(new_contact_local);
  }else {
    kademlia::RoutingTableContact new_contact_local((*it));
     
    // make sure SetLastSeenToNow will do thing expected
    new_contact_local.contact.SetLastSeenToNow();
    
    contacts_.replace(it,new_contact_local);
  }

  // Succeed
}

bool PublicRoutingTable::GetContact(const kademlia::NodeId &node_id, Contact *contact){
  ContactsContainer::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  ContactsContainer::index<TagNodeId>::type::iterator it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    *contact = (*it).contact;
    return true;
  } 
  return false;
}

void PulbicRoutingTable::RemoveContact(const NodeId &node_id, const bool &force){
  ContactsContainer::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  ContactsContainer::index<TagNodeId>::type::iterator it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    kademlia::RoutingTableContact current_element((*it));
    current_element.contact.IncreaseFailedRpcs();
    contacts_.erase(it);

    if (current_element.contact.num_failed_rpcs() <= kFailedRpcTolerance && !force) {
      // make sure SetLastSeenToNow will do thing expected
      current_element.contact.SetLastSeenToNow();
            
      contacts_.insert(current_element);
    }       
  }  
}

void PublicRoutingTable::FindCloseContacts(const kademlia::NodeId &target_id, 
					   const boost::uint32_t &count,
					   std::vector<Contact> *close_contacts) {
  if (target_id.String().size() != kademlia::kKeySizeBytes || close_contacts == NULL)
    return -1;
  boost::mutex::scoped_lock guard(mutex_);
  
  std::vector< boost::reference_wrapper<const Contact> > temp;
  temp.reserve(contacts_.size());
  BOOST_FOREACH(const kademlia::RoutingTableContact &cur_contact, contacts_)temp.
      push_back(boost::cref(cur_contact.contact));
  std::sort(temp.begin(), temp.end(), boost::bind(
      &PublicRoutingTable::KadCloser, this, _1, _2, target_id));
  if (count == 0 || count > contacts_.size()) {
    close_contacts->assign(temp.begin(), temp.end());
  } else {
    std::vector< boost::reference_wrapper<
                 const Contact> >::iterator itr = temp.begin();
    itr += count;
    close_contacts->assign(temp.begin(), itr);
  }
  return 0;
}

int PublicRoutingTable::SetPublicKey(const kademlia::NodeId &node_id,
				     const std::string &new_public_key){
  boost::mutex::scoped_lock guard(mutex_);
  ContactsContainer::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  ContactsContainer::index<TagNodeId>::type::iterator it = key_indx.find(node_id);
  if (it == key_indx.end())
    return 1;
  
  kademlia::RoutingTableContact new_contact_local((*it));  
  new_contact_local.public_key = new_public_key; 
  // should the last_seen keeps the privous value or shall be set to now?
  
  contacts_.replace(it,new_contact_local);
  return 0;
}

int PublicRoutingTable::UpdateRankInfo(const kademlia::NodeId &node_id,const kademlia::RankInfoPtr info) {
  boost::mutex::scoped_lock guard(mutex_);
  ContactsContainer::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  ContactsContainer::index<TagNodeId>::type::iterator it = key_indx.find(node_id);  
  if (it == key_indx.end())
    return 1;
  
  kademlia::RoutingTableContact new_contact_local((*it)); 
  new_contact_local.info = *info;
  key_indx.replace(it, new_contact_local);
  return 0;  
}

int PublicRoutingTable::SetPreferredEndpoint(const kademlia::NodeId &node_id,
			  const std::string &ip) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  routingtable::index<TagNodeId>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  
  kademlia::RoutingTableContact new_contact_local((*it)); 
  new_contact_local.info.ip = ip;

  key_indx.replace(it, new_contact_local);
  return 0;  
}

int PublicRoutingTable::IncrementContactFailedRpcs(const kademlia::NodeId &node_id) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<TagNodeId>::type& key_indx = contacts_.get<TagNodeId>();
  routingtable::index<TagNodeId>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return -1;
  
  kademlia::RoutingTableContact new_contact_local((*it));
  new_contact_local.num_failed_rpcs++;
  
  key_indx.replace(it, new_contact_local);
  
  return new_contact_local.num_failed_rpcs;
}

int PublicRoutingTable::GetBootstrapContacts(std::vector<Contact> *contacts) {
  if (!contacts)
    return -1;

  boost::mutex::scoped_lock loch_doon(mutex_);
  typedef routingtable::index<TagRendezvousPort>::type RtByRvPort;
  RtByRvPort &rv_index = routingtable_.get<TagRendezvousPort>();
  std::pair<RtByRvPort::iterator, RtByRvPort::iterator> res =
      rv_index.equal_range(0);
  if (res.first == res.second)
    return -2;

  std::vector<kademlia::RoutingTableContact> all_contacts(res.first, res.second);
  std::random_shuffle(all_contacts.begin(), all_contacts.end());
  for (size_t n = 0; n < all_contacts.size(); ++n)
    nodes->insert(std::pair<std::string, boost::uint16_t>(
                  all_contacts.at(n).ip, all_contacts.at(n).port));
  return 0;
}

Contact PublicRoutingTable::FindOldestContact(){
  boost::mutex::scoped_lock guard(mutex_);
  
  ContactsContainer::index<TagTimeLastSeen>::type& key_indx = contacts_.get<TagTimeLastSeen>();
  ContactsContainer::index<TagTimeLastSeen>::type::iterator it = key_indx.begin();
  return (*it).contact;
}

bool PublicRoutingTable::KadCloser(const Contact &contact1,
                                   const Contact &contact2,
                                   const kademlia::NodeId &target_id) const {
  kademlia::NodeId id1(contact1.kademlia_id), id2(contact2.kademlia_id);
  return kademlia::NodeId::CloserToTarget(id1, id2, target_id);
}

}  // namespace maidsafe
