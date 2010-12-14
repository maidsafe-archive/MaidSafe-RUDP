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

#include "maidsafe/kademlia/nodeimpl.h"
#include "maidsafe/kademlia/node-api.h"

namespace kademlia {

Node::Node(boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager,
             boost::shared_ptr<transport::Transport> transport,
             const NodeConstructionParameters &node_parameters)
    : pimpl_(new NodeImpl(channel_manager, transport, node_parameters)) {}

Node::~Node() {}

void Node::Join(const NodeId &node_id, const std::string &kad_config_file,
                 VoidFunctorOneString callback) {
  pimpl_->Join(node_id, kad_config_file, callback);
}

void Node::Join(const std::string &kad_config_file,
                 VoidFunctorOneString callback) {
  pimpl_->Join(kad_config_file, callback);
}

void Node::JoinFirstNode(const NodeId &node_id,
                          const std::string &kad_config_file,
                          const IP &ip, const Port &port,
                          VoidFunctorOneString callback) {
  pimpl_->JoinFirstNode(node_id, kad_config_file, ip, port, callback);
}

void Node::JoinFirstNode(const std::string &kad_config_file,
                          const IP &ip, const Port &port,
                          VoidFunctorOneString callback) {
  pimpl_->JoinFirstNode(kad_config_file, ip, port, callback);
}

void Node::Leave() {
  pimpl_->Leave();
}

void Node::StoreValue(const NodeId &key, const SignedValue &signed_value,
                       const SignedRequest &signed_request,
                       const boost::int32_t &ttl,
                       VoidFunctorOneString callback) {
  pimpl_->StoreValue(key, signed_value, signed_request, ttl, callback);
}

void Node::StoreValue(const NodeId &key, const std::string &value,
                       const boost::int32_t &ttl,
                       VoidFunctorOneString callback) {
  pimpl_->StoreValue(key, value, ttl, callback);
}

void Node::FindValue(const NodeId &key, const bool &check_alternative_store,
                      VoidFunctorOneString callback) {
  pimpl_->FindValue(key, check_alternative_store, callback);
}

void Node::GetNodeContactDetails(const NodeId &node_id,
                                  VoidFunctorOneString callback,
                                  const bool &local) {
  pimpl_->GetNodeContactDetails(node_id, callback, local);
}

void Node::FindKClosestNodes(const NodeId &node_id,
                              VoidFunctorOneString callback) {
  pimpl_->FindKClosestNodes(node_id, callback);
}

void Node::GetNodesFromRoutingTable(
    const NodeId &key,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  pimpl_->GetNodesFromRoutingTable(key, exclude_contacts, close_nodes);
}

void Node::Ping(const NodeId &node_id, VoidFunctorOneString callback) {
  pimpl_->Ping(node_id, callback);
}

void Node::Ping(const Contact &remote, VoidFunctorOneString callback) {
  pimpl_->Ping(remote, callback);
}

int Node::AddContact(Contact new_contact, const float &rtt,
                      const bool &only_db) {
  return pimpl_->AddContact(new_contact, rtt, only_db);
}

void Node::RemoveContact(const NodeId &node_id) {
  pimpl_->RemoveContact(node_id);
}

bool Node::GetContact(const NodeId &id, Contact *contact) {
  return pimpl_->GetContact(id, contact);
}

bool Node::FindValueLocal(const NodeId &key, std::vector<std::string> *values) {
  return pimpl_->FindValueLocal(key, values);
}

bool Node::StoreValueLocal(const NodeId &key, const std::string &value,
                            const boost::int32_t &ttl) {
  return pimpl_->StoreValueLocal(key, value, ttl);
}

bool Node::RefreshValueLocal(const NodeId &key, const std::string &value,
                              const boost::int32_t &ttl) {
  return pimpl_->RefreshValueLocal(key, value, ttl);
}

void Node::GetRandomContacts(const size_t &count,
                              const std::vector<Contact> &exclude_contacts,
                              std::vector<Contact> *contacts) {
  pimpl_->GetRandomContacts(count, exclude_contacts, contacts);
}

void Node::HandleDeadRendezvousServer(const bool &dead_server) {
  pimpl_->HandleDeadRendezvousServer(dead_server);
}

ConnectionType Node::CheckContactLocalAddress(const NodeId &id,
                                               const IP &ip,
                                               const Port &port,
                                               const IP &ext_ip) {
  return pimpl_->CheckContactLocalAddress(id, ip, port, ext_ip);
}

void Node::UpdatePDRTContactToRemote(const NodeId &node_id,
                                      const IP &ip) {
  pimpl_->UpdatePDRTContactToRemote(node_id, ip);
}

ContactInfo Node::contact_info() const {
  return pimpl_->contact_info();
}

NodeId Node::node_id() const {
  return pimpl_->node_id();
}

IP Node::ip() const {
  return pimpl_->ip();
}

Port Node::port() const {
  return pimpl_->port();
}

IP Node::local_ip() const {
  return pimpl_->local_ip();
}

Port Node::local_port() const {
  return pimpl_->local_port();
}

IP Node::rendezvous_ip() const {
  return pimpl_->rendezvous_ip();
}

Port Node::rendezvous_port() const {
  return pimpl_->rendezvous_port();
}

bool Node::is_joined() const {
  return pimpl_->is_joined();
}

boost::shared_ptr<rpcs> Node::rpcs() {
  return pimpl_->rpcs();
}

boost::uint32_t Node::KeyLastRefreshTime(const NodeId &key,
                                          const std::string &value) {
  return pimpl_->KeyLastRefreshTime(key, value);
}

boost::uint32_t Node::KeyExpireTime(const NodeId &key,
                                     const std::string &value) {
  return pimpl_->KeyExpireTime(key, value);
}

bool Node::using_signatures() {
  return pimpl_->using_signatures();
}

boost::int32_t Node::KeyValueTTL(const NodeId &key,
                                  const std::string &value) const {
  return pimpl_->KeyValueTTL(key, value);
}

void Node::set_alternative_store(base::AlternativeStore* alternative_store) {
  pimpl_->set_alternative_store(alternative_store);
}

base::AlternativeStore* Node::alternative_store() {
  return pimpl_->alternative_store();
}

void Node::set_signature_validator(base::SignatureValidator *validator) {
  pimpl_->set_signature_validator(validator);
}

void Node::UpdateValue(const NodeId &key, const SignedValue &old_value,
                        const SignedValue &new_value,
                        const SignedRequest &signed_request,
                        boost::uint32_t ttl, VoidFunctorOneString callback) {
  pimpl_->UpdateValue(key, old_value, new_value, signed_request, ttl, callback);
}

void Node::DeleteValue(const NodeId &key, const SignedValue &signed_value,
                        const SignedRequest &signed_request,
                        VoidFunctorOneString callback) {
  pimpl_->DeleteValue(key, signed_value, signed_request, callback);
}

NatType Node::nat_type() {
  return pimpl_->nat_type();
}

}  // namespace kademlia
