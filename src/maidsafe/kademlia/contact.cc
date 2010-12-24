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

#include "maidsafe/kademlia/contact.h"

#include <boost/lexical_cast.hpp>
#include "maidsafe/base/utils.h"

namespace kademlia {

Contact::Contact()
    : node_id_(),
      endpoint_(),
      rendezvous_endpoint_(),
      local_endpoints_(),
      num_failed_rpcs_(0),
      last_seen_(base::GetEpochMilliseconds()),
      prefer_local_(false) {}

Contact::Contact(const Contact &other)
    : node_id_(other.node_id_),
      endpoint_(other.endpoint_),
      rendezvous_endpoint_(other.rendezvous_endpoint_),
      local_endpoints_(other.local_endpoints_),
      num_failed_rpcs_(other.num_failed_rpcs_),
      last_seen_(other.last_seen_),
      prefer_local_(other.prefer_local_) {}

Contact::Contact(const protobuf::Contact &contact)
    : node_id_(),
      endpoint_(),
      rendezvous_endpoint_(),
      local_endpoints_(),
      num_failed_rpcs_(0),
      last_seen_(base::GetEpochMilliseconds()),
      prefer_local_(false) {
  FromProtobuf(contact);
}

Contact::Contact(const std::string &node_id,
                 const transport::Endpoint ep)
    : node_id_(node_id),
      endpoint_(ep),
      rendezvous_endpoint_(),
      local_endpoints_(),
      num_failed_rpcs_(0),
      last_seen_(base::GetEpochMilliseconds()),
      prefer_local_(false) {}

bool Contact::FromProtobuf(const protobuf::Contact &contact) {
  if (!contact.IsInitialized())
    return false;
  for (int i = 0; i < contact.local_ips_size(); ++i) {
    transport::Endpoint ep;
    boost::system::error_code ec;
    ep.ip = ep.ip.from_string(contact.local_ips(i), ec);
    if (!ec) {
      local_endpoints_.clear();
      return false;
    }
    ep.port = contact.local_port();
    local_endpoints_.push_back(ep);
  }
  node_id_ = NodeId(contact.node_id());
  endpoint_.ip.from_string(contact.endpoint().ip());
  endpoint_.port = contact.endpoint().port();
  if (contact.has_rendezvous()) {
    rendezvous_endpoint_.ip.from_string(contact.rendezvous().ip());
    rendezvous_endpoint_.port = contact.rendezvous().port();
  } else {
    rendezvous_endpoint_ = transport::Endpoint();
  }
  return true;
}

protobuf::Contact Contact::ToProtobuf() const {
  protobuf::Contact contact;
  boost::system::error_code ec;
  contact.set_node_id(node_id_.String());
  contact.mutable_endpoint()->set_ip(endpoint_.ip.to_string(ec));
  contact.mutable_endpoint()->set_port(endpoint_.port);
  if (rendezvous_endpoint_.port != 0) {
    contact.mutable_rendezvous()->set_ip(
        rendezvous_endpoint_.ip.to_string(ec));
    contact.mutable_rendezvous()->set_port(rendezvous_endpoint_.port);
  }
  for (std::list<transport::Endpoint>::const_iterator it =
         local_endpoints_.begin();
       it != local_endpoints_.end(); ++it) {
    contact.add_local_ips((*it).ip.to_string(ec));
    contact.set_local_port((*it).port);
  }
  return contact;
}

bool Contact::SetPreferredEndpoint(const transport::IP &ip) {
  prefer_local_ = false;
  if (endpoint_.ip == ip) {
    return true;
  } else {
    std::list<transport::Endpoint>::iterator it = local_endpoints_.begin();
    for (; it != local_endpoints_.end(); ++it) {
      if (ip == (*it).ip) {
        if (it != local_endpoints_.begin()) {
          transport::Endpoint ep = (*it);
          local_endpoints_.erase(it);
          local_endpoints_.push_front(ep);
        }
        prefer_local_ = true;
        return true;
      }
    }
  }
  return false;
}

transport::Endpoint Contact::GetPreferredEndpoint() const {
  if (prefer_local_ && !local_endpoints_.empty())
    return local_endpoints_.front();
  else
    return endpoint_;
}

bool Contact::Equals(const Contact &other) const {
  if (node_id_ == other.node_id_)
    return (node_id_.String() != kClientId) ||
           (endpoint_.ip == other.endpoint_.ip);
  return false;
}

bool Contact::operator<(const Contact &rhs) const {
  return node_id().String() < rhs.node_id().String();
}

Contact& Contact::operator=(const Contact &other) {
  node_id_ = other.node_id_;
  endpoint_ = other.endpoint_;
  rendezvous_endpoint_ = other.rendezvous_endpoint_;
  local_endpoints_ = other.local_endpoints_;
  num_failed_rpcs_ = other.num_failed_rpcs_;
  last_seen_ = other.last_seen_;
  prefer_local_ = other.prefer_local_;
  return *this;
}

}  // namespace kademlia
