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

#include <boost/lexical_cast.hpp>
#include "maidsafe/base/utils.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/nodeid.h"

namespace kademlia {

Contact::Contact()
    : node_id_(),
      ep_(),
      rv_ep_(),
      local_eps_(),
      last_seen_(base::GetEpochMilliseconds())
      {}

Contact::Contact(const protobuf::Contact &contact)
     :failed_rpc_(0),
      local_eps_(),
      rv_ep_(),
      last_seen_(base::GetEpochMilliseconds()) {
  if (!FromProtobuf(contact)) {
   node_id_ = NodeId(kZeroId);
   ep_();
   rv_ep_();
   local_eps_.clear();
  }   
}

bool Contact::FromProtobuf(const protobuf::Contact &contact) {
  if (!contact.IsInitialized())
    return false;
  node_id_ = NodeId(contact.node_id());
  ep_(contact.enpoint());
  if (contact.has_rendezvous())
    rv_ep_(contact.rendezvous());
  for (int i = 0; i < contact.local_ips_size(); ++i) {
    Endpoint ep;
    if (!ep.ip.ParseFromString(contact.local_ips(i)))
      return false;
    ep.port = contact.local_port();
    local_eps_.push_back(ep);
  }
  return true;
}

protobuf::Contact& Contact::ToProtobuf() {
  protobuf::Contact contact;
  contact.set_node_id(node_id_.String());
  contact.enpoint() = ep_;
  contact.rendezvous() = rv_ep_;
  std::list<Endpoint>::iterator it = local_eps_.begin();
  for (; it != local_eps_.end(); ++it)
    contact.add_local_ips((*it).ip.to_string());
  contact.set_local_port((*it).port);
}

Contact::Contact(const Contact &other)
    : node_id_(other.node_id_), ep_(other.ep_),
      failed_rpc_(other.failed_rpc_),
      rv_ep_(other.rv_ep_),
      last_seen_(other.last_seen_), local_eps_(other.local_eps_)
      {}

bool Contact::Equals(const Contact &other) const {
  if (node_id_ == other.node_id_)
    return (node_id_.String() != kClientId) ||
           (ep_.ip == other.ep_.ip );
  return false;
}

Contact& Contact::operator=(const Contact &other) {
  this->node_id_ = other.node_id_;
  this->ep_ = other.ep_;
  this->failed_rpc_ = other.failed_rpc_;
  this->rv_ep_ = other.rv_ep_;
  this->last_seen_ = other.last_seen_;
  this->local_eps_ = other.local_eps_;
  return *this;
}

bool Contact::SetPreferredEndpoint(transport::IP ip) {
   prefer_local_ = false;
   if (ep_.ip != ip) {
     std::list<Endpoint>::iterator it = local_eps_.begin();
     for (; it != local_eps_.end(); ++it) {
       if ((ip == (*it).ip) && (it != local_eps_.begin())) {
         Endpoint ep = (*it);
         local_eps_.erase(it);
         local_eps_.push_front(ep);
         prefer_local_ = true;
         break;
       }
     }
   }      
 }

 Endpoint Contact::GetPreferredEndpoint() {
   if (prefer_local_ && (local_eps_.size() != 0))
     return local_eps_.front();
   else
     return ep_;
 }
 
bool Contact::operator<(const Contact &rhs) const {
  return this->node_id().String() < rhs.node_id().String();
}

}  // namespace kademlia
