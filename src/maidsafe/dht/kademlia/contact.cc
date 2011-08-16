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

#include "maidsafe/dht/kademlia/contact.h"
#include <string>
#include "maidsafe/dht/kademlia/contact_impl.h"
#include "maidsafe/dht/kademlia/utils.h"

namespace maidsafe {

namespace dht {

namespace kademlia {

Contact::Contact() : pimpl_(new Contact::Impl) {}

Contact::Contact(const Contact &other) : pimpl_(new Contact::Impl(other)) {}

Contact::Contact(const NodeId &node_id,
                 const transport::Endpoint &endpoint,
                 const std::vector<transport::Endpoint> &local_endpoints,
                 const transport::Endpoint &rendezvous_endpoint,
                 bool tcp443,
                 bool tcp80,
                 const std::string &public_key_id,
                 const std::string &public_key,
                 const std::string &other_info)
    : pimpl_(new Contact::Impl(node_id, endpoint, local_endpoints,
                               rendezvous_endpoint, tcp443, tcp80,
                               public_key_id, public_key, other_info)) {}

Contact::~Contact() {}

NodeId Contact::node_id() const {
  return pimpl_->node_id();
}

transport::Endpoint Contact::endpoint() const {
  return pimpl_->endpoint();
}

std::vector<transport::Endpoint> Contact::local_endpoints() const {
  return pimpl_->local_endpoints();
}

transport::Endpoint Contact::rendezvous_endpoint() const {
  return pimpl_->rendezvous_endpoint();
}

transport::Endpoint Contact::tcp443endpoint() const {
  return pimpl_->tcp443endpoint();
}

transport::Endpoint Contact::tcp80endpoint() const {
  return pimpl_->tcp80endpoint();
}

std::string Contact::public_key_id() const {
  return pimpl_->public_key_id();
}

std::string Contact::public_key() const {
  return pimpl_->public_key();
}

std::string Contact::other_info() const {
  return pimpl_->other_info();
}

bool Contact::SetPreferredEndpoint(const transport::IP &ip) {
  return pimpl_->SetPreferredEndpoint(ip);
}

transport::Endpoint Contact::PreferredEndpoint() const {
  return pimpl_->PreferredEndpoint();
}

bool Contact::IsDirectlyConnected() const {
  return pimpl_->IsDirectlyConnected();
}

Contact& Contact::operator=(const Contact &other) {
  if (this != &other)
    *pimpl_ = *other.pimpl_;
  return *this;
}

bool Contact::operator==(const Contact &other) const {
  return *pimpl_ == *other.pimpl_;
}

bool Contact::operator!=(const Contact &other) const {
  return *pimpl_ != *other.pimpl_;
}

bool Contact::operator<(const Contact &other) const {
  return *pimpl_ < *other.pimpl_;
}

bool Contact::operator>(const Contact &other) const {
  return *pimpl_ > *other.pimpl_;
}

bool Contact::operator<=(const Contact &other) const {
  return *pimpl_ <= *other.pimpl_;
}

bool Contact::operator>=(const Contact &other) const {
  return *pimpl_ >= *other.pimpl_;
}

std::string DebugId(const Contact &contact) {
  return DebugId(contact.node_id());
}

bool CloserToTarget(const NodeId &node_id,
                    const Contact &contact,
                    const NodeId &target) {
  return NodeId::CloserToTarget(node_id, contact.node_id(), target);
}

bool CloserToTarget(const Contact &contact1,
                    const Contact &contact2,
                    const NodeId &target) {
  return NodeId::CloserToTarget(contact1.node_id(), contact2.node_id(), target);
}

bool NodeWithinClosest(const NodeId &node_id,
                       const std::vector<Contact> &closest_contacts,
                       const NodeId &target) {
  return std::find_if(closest_contacts.rbegin(), closest_contacts.rend(),
      std::bind(static_cast<bool(*)(const NodeId&,  // NOLINT
                                    const Contact&,
                                    const NodeId&)>(&CloserToTarget),
                node_id, arg::_1, target)) != closest_contacts.rend();
}

bool RemoveContact(const NodeId &node_id, std::vector<Contact> *contacts) {
  if (!contacts)
    return false;
  size_t size_before(contacts->size());
  contacts->erase(std::remove_if(contacts->begin(), contacts->end(),
                                 std::bind(&HasId, arg::_1, node_id)),
                  contacts->end());
  return contacts->size() != size_before;
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
