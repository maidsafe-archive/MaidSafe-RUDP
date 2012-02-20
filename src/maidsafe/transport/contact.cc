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

#include "maidsafe/transport/contact.h"

#include <string>

#include "maidsafe/transport/transport_pb.h"

namespace maidsafe {

namespace transport {

Contact::Contact()
    : endpoint_(),
      local_endpoints_(),
      rendezvous_endpoint_(),
      tcp443_(false),
      tcp80_(false),
      prefer_local_(false) {}

Contact::Contact(const Contact &other)
    : endpoint_(other.endpoint_),
      local_endpoints_(other.local_endpoints_),
      rendezvous_endpoint_(other.rendezvous_endpoint_),
      tcp443_(other.tcp443_),
      tcp80_(other.tcp80_),
      prefer_local_(other.prefer_local_) {}

Contact::Contact(const transport::Endpoint &endpoint,
                 const std::vector<transport::Endpoint> &local_endpoints,
                 const transport::Endpoint &rendezvous_endpoint,
                 bool tcp443,
                 bool tcp80)
    : endpoint_(endpoint),
      local_endpoints_(local_endpoints),
      rendezvous_endpoint_(rendezvous_endpoint),
      tcp443_(tcp443),
      tcp80_(tcp80),
      prefer_local_(false) {
  Init();
}

bool Contact::Init() {
  if (!IsValid(endpoint_) || local_endpoints_.empty() ||
      !IsValid(local_endpoints_.at(0))) {
    Clear();
    return false;
  }

  // Contact can either have TCP endpoints OR rendezvous endpoints, not both.
  if ((tcp443_ || tcp80_) && IsValid(rendezvous_endpoint_)) {
    Clear();
    return false;
  }
  // All local endpoints must have the same port.
  Port first_local_port(local_endpoints_.at(0).port);
  if (local_endpoints_.size() > 1) {
    for (size_t i = 1; i < local_endpoints_.size(); ++i) {
      if (!IsValid(local_endpoints_.at(i)) ||
          local_endpoints_.at(i).port != first_local_port) {
        Clear();
        return false;
      }
    }
  }

  // If contact has TCP endpoints, first local IP must match the external IP.
  MoveLocalEndpointToFirst(endpoint_.ip);
  if ((tcp443_ || tcp80_) && (endpoint_.ip != local_endpoints_.at(0).ip)) {
    Clear();
    return false;
  }
  return true;
}

void Contact::Clear() {
  endpoint_ = transport::Endpoint();
  local_endpoints_.clear();
  rendezvous_endpoint_ = transport::Endpoint();
  tcp443_ = false;
  tcp80_ = false;
  prefer_local_ = false;
}

Contact::~Contact() {}

transport::Endpoint Contact::endpoint() const {
  return endpoint_;
}

std::vector<transport::Endpoint> Contact::local_endpoints() const {
  return local_endpoints_;
}

transport::Endpoint Contact::rendezvous_endpoint() const {
  return rendezvous_endpoint_;
}

transport::Endpoint Contact::tcp443endpoint() const {
  return tcp443_ ? transport::Endpoint(endpoint_.ip, 443) :
                   transport::Endpoint();
}

transport::Endpoint Contact::tcp80endpoint() const {
  return tcp80_ ? transport::Endpoint(endpoint_.ip, 80) : transport::Endpoint();
}

bool Contact::SetPreferredEndpoint(const transport::IP &ip) {
  if (rendezvous_endpoint_.ip != IP())
    return rendezvous_endpoint_.ip == ip;
  prefer_local_ = false;
  if (endpoint_.ip == ip)
    return true;
  bool result = MoveLocalEndpointToFirst(ip);
  if (result)
    prefer_local_ = true;
  return result;
}

bool Contact::MoveLocalEndpointToFirst(const transport::IP &ip) {
  auto it = std::find_if(local_endpoints_.begin(), local_endpoints_.end(),
            std::bind(&Contact::IpMatchesEndpoint, this, ip, args::_1));
  if (it == local_endpoints_.end()) {
    return false;
  } else {
    std::iter_swap(it, local_endpoints_.begin());
    return true;
  }
}

bool Contact::IpMatchesEndpoint(const transport::IP &ip,
                                const transport::Endpoint &endpoint) {
  return ip == endpoint.ip;
}

transport::Endpoint Contact::PreferredEndpoint() const {
  if (rendezvous_endpoint_.ip != IP())
    return rendezvous_endpoint_;
  if (prefer_local_ && !local_endpoints_.empty())
    return local_endpoints_.front();
  return endpoint_;
}

bool Contact::IsDirectlyConnected() const {
  return (tcp443_ || tcp80_ ||
             (!prefer_local_ && !local_endpoints_.empty() &&
              local_endpoints_.front().ip == endpoint_.ip));
}

Contact& Contact::operator=(const Contact &other) {
  if (this != &other) {
    endpoint_ = other.endpoint_;
    rendezvous_endpoint_ = other.rendezvous_endpoint_;
    local_endpoints_ = other.local_endpoints_;
    tcp443_ = other.tcp443_;
    tcp80_ = other.tcp80_;
    prefer_local_ = other.prefer_local_;
  }
  return *this;
}

int Contact::Serialise(std::string *serialised) const {
  protobuf::Contact pb_contact;
  boost::system::error_code ec;

  protobuf::Endpoint *mutable_endpoint = pb_contact.mutable_endpoint();
  mutable_endpoint->set_ip(endpoint().ip.to_string(ec));
  mutable_endpoint->set_port(endpoint().port);

  if (IsValid(rendezvous_endpoint())) {
    mutable_endpoint = pb_contact.mutable_rendezvous();
    mutable_endpoint->set_ip(rendezvous_endpoint().ip.to_string(ec));
    mutable_endpoint->set_port(rendezvous_endpoint().port);
  }

  std::vector<transport::Endpoint> local_endpoints(local_endpoints_);
  for (auto it = local_endpoints.begin(); it != local_endpoints.end(); ++it) {
    pb_contact.add_local_ips((*it).ip.to_string(ec));
    pb_contact.set_local_port((*it).port);
  }
  if (IsValid(tcp443endpoint()))
    pb_contact.set_tcp443(true);
  if (IsValid(tcp80endpoint()))
    pb_contact.set_tcp80(true);
  pb_contact.set_prefer_local(prefer_local_);

  if (!pb_contact.IsInitialized())
    return kError;

  if (!pb_contact.SerializeToString(serialised))
    return kError;
  return kSuccess;
}

int Contact::Parse(const std::string &serialised) {
  protobuf::Contact pb_contact;
  if (!pb_contact.ParseFromString(serialised) != kSuccess) {
    Clear();
    return kError;
  }

  endpoint_ = Endpoint(pb_contact.endpoint().ip(),
               static_cast<uint16_t>(pb_contact.endpoint().port()));

  for (int i = 0; i < pb_contact.local_ips_size(); ++i)
    local_endpoints_.push_back(
        Endpoint(pb_contact.local_ips(i),
                static_cast<uint16_t>(pb_contact.local_port())));

  rendezvous_endpoint_ = pb_contact.has_rendezvous() ?
      Endpoint(pb_contact.rendezvous().ip(),
               static_cast<uint16_t>(pb_contact.rendezvous().port())) :
      Endpoint();

  tcp443_ = pb_contact.has_tcp443() ? pb_contact.tcp443() : false,

  tcp80_ = pb_contact.has_tcp80() ? pb_contact.tcp80() : false;

  prefer_local_ =
      pb_contact.has_prefer_local() ? pb_contact.prefer_local() : false;

  if (!pb_contact.IsInitialized()) {
    Clear();
    return kError;
  }
  return kSuccess;
}

bool IsValid(const Endpoint &endpoint) {
  return !(endpoint.ip == transport::IP() || endpoint.port == 0);
}

}  // namespace dht

}  // namespace maidsafe
