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
#include "maidsafe-dht/kademlia/contact_impl.h"
#include <algorithm>
#include <string>
#include "boost/bind.hpp"
#include "maidsafe-dht/kademlia/utils.h"

#ifdef __MSVC__
#pragma warning(push)
#pragma warning(disable:4244)
#endif
#include "maidsafe-dht/kademlia/kademlia.pb.h"
#ifdef __MSVC__
#pragma warning(pop)
#endif

#include "maidsafe-dht/common/utils.h"


namespace maidsafe {

namespace kademlia {

Contact::Impl::Impl()
    : node_id_(),
      endpoint_(),
      local_endpoints_(),
      rendezvous_endpoint_(),
      tcp443_(false),
      tcp80_(false),
      prefer_local_(false),
      public_key_id_(),
      public_key_(),
      other_info_() {}

Contact::Impl::Impl(const Contact &other)
    : node_id_(other.pimpl_->node_id_),
      endpoint_(other.pimpl_->endpoint_),
      local_endpoints_(other.pimpl_->local_endpoints_),
      rendezvous_endpoint_(other.pimpl_->rendezvous_endpoint_),
      tcp443_(other.pimpl_->tcp443_),
      tcp80_(other.pimpl_->tcp80_),
      prefer_local_(other.pimpl_->prefer_local_),
      public_key_id_(other.pimpl_->public_key_id_),
      public_key_(other.pimpl_->public_key_),
      other_info_(other.pimpl_->other_info_) {}

Contact::Impl::Impl(const NodeId &node_id,
                    const transport::Endpoint &endpoint,
                    const std::vector<transport::Endpoint> &local_endpoints,
                    const transport::Endpoint &rendezvous_endpoint,
                    bool tcp443,
                    bool tcp80,
                    const std::string &public_key_id,
                    const std::string &public_key,
                    const std::string &other_info)
    : node_id_(node_id),
      endpoint_(endpoint),
      local_endpoints_(local_endpoints),
      rendezvous_endpoint_(rendezvous_endpoint),
      tcp443_(tcp443),
      tcp80_(tcp80),
      prefer_local_(false),
      public_key_id_(public_key_id),
      public_key_(public_key),
      other_info_(other_info) {
  Init();
}

void Contact::Impl::Init() {
  if (!node_id_.IsValid() || !IsValid(endpoint_)  || local_endpoints_.empty() ||
      !IsValid(local_endpoints_.at(0)))
    return Clear();

  // Contact can either have TCP endpoints OR rendezvous endpoints, not both.
  if ((tcp443_ || tcp80_) && IsValid(rendezvous_endpoint_))
    return Clear();

  // All local endpoints must have the same port.
  Port first_local_port(local_endpoints_.at(0).port);
  if (local_endpoints_.size() > 1) {
    for (size_t i = 1; i < local_endpoints_.size(); ++i) {
      if (!IsValid(local_endpoints_.at(i)) ||
          local_endpoints_.at(i).port != first_local_port)
        return Clear();
    }
  }

  // If contact has TCP endpoints, first local IP must match the external IP.
  MoveLocalEndpointToFirst(endpoint_.ip);
  if ((tcp443_ || tcp80_) && (endpoint_.ip != local_endpoints_.at(0).ip))
    Clear();
}

void Contact::Impl::Clear() {
  node_id_ = NodeId();
  endpoint_ = transport::Endpoint();
  local_endpoints_.clear();
  rendezvous_endpoint_ = transport::Endpoint();
  tcp443_ = false;
  tcp80_ = false;
  prefer_local_ = false;
}

transport::Endpoint Contact::Impl::tcp443endpoint() const {
  return tcp443_ ? transport::Endpoint(endpoint_.ip, 443) :
                   transport::Endpoint();
}

transport::Endpoint Contact::Impl::tcp80endpoint() const {
  return tcp80_ ? transport::Endpoint(endpoint_.ip, 80) : transport::Endpoint();
}

bool Contact::Impl::SetPreferredEndpoint(const transport::IP &ip) {
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

bool Contact::Impl::MoveLocalEndpointToFirst(const transport::IP &ip) {
  auto it = std::find_if(local_endpoints_.begin(), local_endpoints_.end(),
            boost::bind(&Contact::Impl::IpMatchesEndpoint, this, ip, _1));
  if (it == local_endpoints_.end()) {
    return false;
  } else {
    std::iter_swap(it, local_endpoints_.begin());
    return true;
  }
}

bool Contact::Impl::IpMatchesEndpoint(const transport::IP &ip,
                                      const transport::Endpoint &endpoint) {
  return ip == endpoint.ip;
}

transport::Endpoint Contact::Impl::PreferredEndpoint() const {
  if (rendezvous_endpoint_.ip != IP())
    return rendezvous_endpoint_;
  if (prefer_local_ && !local_endpoints_.empty())
    return local_endpoints_.front();
  return endpoint_;
}

bool Contact::Impl::IsDirectlyConnected() const {
  return (tcp443_ || tcp80_ ||
             (!prefer_local_ && !local_endpoints_.empty() &&
              local_endpoints_.front().ip == endpoint_.ip));
}

Contact::Impl& Contact::Impl::operator=(const Contact::Impl &other) {
  if (this != &other) {
    node_id_ = other.node_id_;
    endpoint_ = other.endpoint_;
    rendezvous_endpoint_ = other.rendezvous_endpoint_;
    local_endpoints_ = other.local_endpoints_;
    tcp443_ = other.tcp443_;
    tcp80_ = other.tcp80_;
    prefer_local_ = other.prefer_local_;
  }
  return *this;
}

bool Contact::Impl::operator==(const Contact::Impl &other) const {
  if (node_id_ == other.node_id_)
    return (node_id_.String() != kZeroId) ||
           (endpoint_.ip == other.endpoint_.ip);
  else
    return false;
}

bool Contact::Impl::operator!=(const Contact::Impl &other) const {
  return !(*this == other);
}

bool Contact::Impl::operator<(const Contact::Impl &other) const {
  return node_id_ < other.node_id_;
}

bool Contact::Impl::operator>(const Contact::Impl &other) const {
  return node_id_ > other.node_id_;
}

bool Contact::Impl::operator<=(const Contact::Impl &other) const {
  return (node_id_ < other.node_id_ || (*this == other));
}

bool Contact::Impl::operator>=(const Contact::Impl &other) const {
  return (node_id_ > other.node_id_ || (*this == other));
}

}  // namespace kademlia

}  // namespace maidsafe
