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
#include "maidsafe/protobuf/contact_info.pb.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kadid.h"

namespace kademlia {

Contact::Contact()
    : node_id_(),
      ep_(),
      rv_ep_(),
      local_eps_(),
      last_seen_(base::GetEpochMilliseconds())
      {}


Contact::Contact(const ContactInfo &contact_info)
    : node_id_(contact_info.node_id()), ep_(),
      failed_rpc_(0),
      rv_ep_(),
      last_seen_(base::GetEpochMilliseconds()),
      local_eps_()
      {
        ep_.ip.from_string(contact_info.ip());
        ep_.port = contact_info.port();
        rv_ep_.ip.from_string(contact_info.rendezvous_ip());
        rv_ep_.port = contact_info.rendezvous_port();
        local_eps_.ip.from_string(contact_info.local_ips());
        local_eps_.port = contact_info.local_port();
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

bool Contact::SerialiseToString(std::string *serialised_output) {
  ContactInfo info;
  info.set_node_id(node_id_.String());
  info.set_ip(ep_.ip.to_string());
  info.set_port(ep_.port);
  info.set_rendezvous_ip(rv_ep_.ip.to_string());
  info.set_rendezvous_port(rv_ep_.port);
  info.set_local_ips(local_eps_.ip.to_string());
  info.set_local_port(local_eps_.port);
  return info.SerializeToString(serialised_output);
}

std::string Contact::SerialiseAsString() {
  ContactInfo info;
  info.set_node_id(node_id_.String());
  info.set_ip(ep_.ip.to_string());
  info.set_port(ep_.port);
  info.set_rendezvous_ip(rv_ep_.ip.to_string());
  info.set_rendezvous_port(rv_ep_.port);
  info.set_local_ips(local_eps_.ip.to_string());
  info.set_local_port(local_eps_.port);
  return info.SerializeAsString();
}

bool Contact::ParseFromString(const std::string &data) {
  kademlia::ContactInfo info;
  if (!info.ParseFromString(data))
    return false;
  node_id_ = KadId(info.node_id());
  if (!node_id_.IsValid())
    return false;
  
  ep_.ip.from_string(info.ip());
  ep_.port = info.port();
  if (info.has_rendezvous_ip()) {
    rv_ep_.ip.from_string(info.rendezvous_ip());
    rv_ep_.port = info.rendezvous_port();
  }
  local_eps_.ip.from_string(info.local_ips());
  local_eps_.port = info.local_port();
  last_seen_ = base::GetEpochMilliseconds();
  return true;
}



bool Contact::operator<(const Contact &rhs) const {
  return this->node_id().String() < rhs.node_id().String();
}

}  // namespace kad
