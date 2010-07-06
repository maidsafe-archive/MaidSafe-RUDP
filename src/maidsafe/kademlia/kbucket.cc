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
#include "maidsafe/kademlia/contact.h"

namespace kad {

KBucket::KBucket(const KadId &min, const KadId &max,
                 const boost::uint16_t &kb_K)
    : last_accessed_(0), contacts_(), range_min_(min), range_max_(max),
      K_(kb_K) {}

KBucket::~KBucket() {
  contacts_.clear();
}

bool KBucket::KeyInRange(const KadId &key) {
  return static_cast<bool>((range_min_ <= key) && (key <= range_max_));
}

size_t KBucket::Size() const { return contacts_.size(); }

boost::uint32_t KBucket::last_accessed() const { return last_accessed_; }

void KBucket::set_last_accessed(const boost::uint32_t &time_accessed) {
  last_accessed_  = time_accessed;
}

KBucketExitCode KBucket::AddContact(const Contact &new_contact) {
  Contact new_contact_local(new_contact);
  int position(-1), i(0);
  // Check if the contact is already in the kbucket to remove it from
  // it and adding it at the top of it
  for (std::list<Contact>::const_iterator it = contacts_.begin();
       it != contacts_.end() && position == -1; ++it) {
    Contact current_element = *it;
    if (new_contact_local.Equals(current_element))
      position = i;
    ++i;
  }
  if (position != -1) {
    std::list<Contact>::iterator it = contacts_.begin();
    std::advance(it, position);
    contacts_.erase(it);
  }

  if (contacts_.size() == K_)
    return FULL;

  contacts_.push_front(new_contact_local);
  return SUCCEED;
}

void KBucket::RemoveContact(const KadId &node_id, const bool &force) {
  int position(-1), i(0);
  for (std::list<Contact>::const_iterator it = contacts_.begin();
       it != contacts_.end(); ++it) {
    if (it->node_id() == node_id) {
      position = i;
    }
    ++i;
  }

  if (position != -1) {
    std::list<Contact>::iterator it = contacts_.begin();
    std::advance(it, position);
    Contact current_element = *it;
    current_element.IncreaseFailed_RPC();
    contacts_.erase(it);
    if (current_element.failed_rpc() <= kFailedRpc && !force) {
      std::list<Contact>::iterator new_it = contacts_.begin();
      std::advance(new_it, position);
      contacts_.insert(new_it, current_element);
    }
  }
}

bool KBucket::GetContact(const KadId &node_id, Contact *contact) {
  bool result = false;
  for (std::list<Contact>::const_iterator it = contacts_.begin();
       it != contacts_.end() && !result; ++it) {
    if (it->node_id() == node_id) {
      *contact = (*it);
      result = true;
    }
  }
  return result;
}

void KBucket::GetContacts(const boost::uint16_t &count,
                          const std::vector<Contact> &exclude_contacts,
                          std::vector<Contact> *contacts) {
  bool insert;
  boost::uint16_t i(0);
  for (std::list<Contact>::iterator it = contacts_.begin();
       it != contacts_.end() && i < count; ++it) {
    insert = true;
    for (std::vector<Contact>::const_iterator it1 = exclude_contacts.begin();
         it1 != exclude_contacts.end() && insert; ++it1) {
      if (it->node_id() == it1->node_id())
        insert = false;
    }
    if (insert) {
      contacts->push_back(*it);
      ++i;
    }
  }
}

KadId KBucket::range_min() const { return range_min_; }

KadId KBucket::range_max() const { return range_max_; }

Contact KBucket::LastSeenContact() {
  if (contacts_.empty()) {
    Contact empty;
    return empty;
  }
  return contacts_.back();
}

}  // namespace kad
