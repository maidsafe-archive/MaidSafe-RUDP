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

#include "maidsafe/kademlia/kbucket.h"

#include <boost/foreach.hpp>

namespace maidsafe {

namespace kademlia {

KBucket::KBucket(const NodeId &min, const NodeId &max,
                 const boost::uint16_t &kb_K)
    : last_accessed_(0), contacts_(), range_min_(min), range_max_(max),
      K_(kb_K) {}

KBucket::~KBucket() {
  contacts_.clear();
}

bool KBucket::KeyInRange(const NodeId &key) {
  return static_cast<bool>((range_min_ <= key) && (key <= range_max_));
}

size_t KBucket::Size() const { return contacts_.size(); }

boost::uint32_t KBucket::last_accessed() const { return last_accessed_; }

void KBucket::set_last_accessed(const boost::uint32_t &time_accessed) {
  last_accessed_  = time_accessed;
}

KBucketExitCode KBucket::AddContact(const Contact &new_contact) {
  if (contacts_.size() == K_)
  return FULL;
  
  Contact new_contact_local(new_contact);
  
  // Check if the contact is already in the kbucket
  // if so, set it's last seen to now (will bring it to the top) 
  NodeId node_id=new_contact_local.node_id();
  ContactsContainer::index<tNodeId>::type& key_indx = contacts_.get<tNodeId>();
  ContactsContainer::index<tNodeId>::type::iterator it = key_indx.find(node_id); 
  if (it == contacts_.end()) {  
    contacts_.insert(new_contact_local);
  }else {
    /* this part shall be enabled once SetLastSeenToNow is supported
    new_contact_local.SetLastSeenToNow();
    */
    contacts_.replace(it,new_contact_local);
  }

  return SUCCEED;
}

void KBucket::RemoveContact(const NodeId &node_id, const bool &force) {
  ContactsContainer::index<tNodeId>::type& key_indx = contacts_.get<tNodeId>();
  ContactsContainer::index<tNodeId>::type::iterator it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    Contact current_element = *it;
    current_element.IncreaseFailedRpcs();
    contacts_.erase(it);

    /* this part shall be enabled once kFailedRpcTolerance and SetLastSeenToNow is supported
    if (current_element.num_failed_rpcs() <= kFailedRpcTolerance && !force) {
      current_element.SetLastSeenToNow();
      contacts_.insert(current_element);
    }    
    */
  }
}

bool KBucket::GetContact(const NodeId &node_id, Contact *contact) {
  ContactsContainer::index<tNodeId>::type& key_indx = contacts_.get<tNodeId>();
  ContactsContainer::index<tNodeId>::type::iterator it = key_indx.find(node_id);
  if (it != key_indx.end()) {
    *contact = (*it);
    return true;
  } 
  return false;
}

void KBucket::GetContacts(const boost::uint16_t &count,
                          const std::vector<Contact> &exclude_contacts,
                          std::vector<Contact> *contacts) {
  bool insert;
 
  BOOST_FOREACH(Contact local_contact, contacts_) {
    insert = true;
    for (std::vector<Contact>::const_iterator it1 = exclude_contacts.begin();
         it1 != exclude_contacts.end() && insert; ++it1) {      
      if (local_contact.node_id() == it1->node_id())
        insert = false;
    }
    if (insert) {
      contacts->push_back(local_contact);
    }
    if (contacts->size()==count) {  
      return;
    }
  }
}

NodeId KBucket::range_min() const { return range_min_; }

NodeId KBucket::range_max() const { return range_max_; }

Contact KBucket::LastSeenContact() {
  if (contacts_.empty()) {
    Contact empty;
    return empty;
  }
  
  ContactsContainer::index<tTimeLastSeen>::type& key_indx = contacts_.get<tTimeLastSeen>();
  ContactsContainer::index<tTimeLastSeen>::type::iterator it = key_indx.begin();
  return (*it);
}

}  // namespace kademlia

}  // namespace maidsafe
