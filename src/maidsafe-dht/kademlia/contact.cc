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

#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/contact_impl.h"
#include "maidsafe-dht/kademlia/node_id.h"

namespace maidsafe {

namespace kademlia {

Contact::Contact() : pimpl_(new Contact::Impl) {}

Contact::Contact(const Contact &other) : pimpl_(new Contact::Impl(other)) {}

Contact::Contact(const NodeId &node_id,
                 const transport::Endpoint &endpoint)
    : pimpl_(new Contact::Impl(node_id, endpoint)) {}

Contact::Contact(const NodeId &node_id,
                 const transport::Endpoint &endpoint,
                 const transport::Endpoint &rendezvous_endpoint,
                 std::vector<transport::Endpoint> &local_endpoints)
    : pimpl_(new Contact::Impl(node_id, endpoint, rendezvous_endpoint,
                               local_endpoints)) {}

Contact::~Contact() {}

NodeId Contact::node_id() const {
  return pimpl_->node_id();
}

transport::Endpoint Contact::endpoint() const {
  return pimpl_->endpoint();
}

transport::Endpoint Contact::rendezvous_endpoint() const {
  return pimpl_->rendezvous_endpoint();
}

std::vector<transport::Endpoint> Contact::local_endpoints() const {
  return pimpl_->local_endpoints();
}

bool Contact::SetPreferredEndpoint(const transport::IP &ip) {
  return pimpl_->SetPreferredEndpoint(ip);
}

transport::Endpoint Contact::GetPreferredEndpoint() const {
  return pimpl_->GetPreferredEndpoint();
}

Contact& Contact::operator=(const Contact &other) {
  if (this != &other)
    *pimpl_ = *other.pimpl_;
  return *this;
}

bool Contact::operator<(const Contact &other) const {
  return *pimpl_ < *other.pimpl_;
}

bool Contact::operator==(const Contact &other) const {
  return *pimpl_ == *other.pimpl_;
}

}  // namespace kademlia

}  // namespace maidsafe
