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

#include "maidsafe/kademlia/contact_impl.h"
#include <algorithm>
#include <boost/bind.hpp>
#include "maidsafe/common/utils.h"
#include "maidsafe/kademlia/kademlia.pb.h"

namespace maidsafe {

namespace kademlia {

Contact::Impl::Impl()
    : node_id_(),
      endpoint_(),
      rendezvous_endpoint_(),
      local_endpoints_(),
      prefer_local_(false) {}

Contact::Impl::Impl(const Contact &other)
    : node_id_(other.pimpl_->node_id_),
      endpoint_(other.pimpl_->endpoint_),
      rendezvous_endpoint_(other.pimpl_->rendezvous_endpoint_),
      local_endpoints_(other.pimpl_->local_endpoints_),
      prefer_local_(other.pimpl_->prefer_local_) {}

Contact::Impl::Impl(const NodeId &node_id,
                    const transport::Endpoint &endpoint)
    : node_id_(node_id),
      endpoint_(endpoint),
      rendezvous_endpoint_(),
      local_endpoints_(),
      prefer_local_(false) {}

Contact::Impl::Impl(const NodeId &node_id,
                    const transport::Endpoint &endpoint,
                    const transport::Endpoint &rendezvous_endpoint,
                    std::vector<transport::Endpoint> &local_endpoints)
    : node_id_(node_id),
      endpoint_(endpoint),
      rendezvous_endpoint_(rendezvous_endpoint),
      local_endpoints_(local_endpoints),
      prefer_local_(false) {}

bool Contact::Impl::SetPreferredEndpoint(const transport::IP &ip) {
  prefer_local_ = false;
  if (endpoint_.ip == ip) {
    return true;
  } else {
    boost::system::error_code ec;
    auto it = std::find_if(local_endpoints_.begin(), local_endpoints_.end(),
              boost::bind(&Contact::Impl::IpMatchesEndpoint, this, ip, _1));
    if (it == local_endpoints_.end()) {
      return false;
    } else {
      std::iter_swap(it, local_endpoints_.begin());
      prefer_local_ = true;
      return true;
    }
  }
}

bool Contact::Impl::IpMatchesEndpoint(const transport::IP &ip,
                                      const transport::Endpoint &endpoint) {
  return ip == endpoint.ip;
}

transport::Endpoint Contact::Impl::GetPreferredEndpoint() const {
  if (prefer_local_ && !local_endpoints_.empty())
    return local_endpoints_.front();
  else
    return endpoint_;
}

Contact::Impl& Contact::Impl::operator=(const Contact::Impl &other) {
  if (this != &other) {
    node_id_ = other.node_id_;
    endpoint_ = other.endpoint_;
    rendezvous_endpoint_ = other.rendezvous_endpoint_;
    local_endpoints_ = other.local_endpoints_;
    prefer_local_ = other.prefer_local_;
  }
  return *this;
}

bool Contact::Impl::operator<(const Contact::Impl &other) const {
  return node_id_ < other.node_id_;
}

bool Contact::Impl::operator==(const Contact::Impl &other) const {
  if (node_id_ == other.node_id_)
    return (node_id_.String() != kClientId) ||
           (endpoint_.ip == other.endpoint_.ip);
  else
    return false;
}

}  // namespace kademlia

}  // namespace maidsafe
