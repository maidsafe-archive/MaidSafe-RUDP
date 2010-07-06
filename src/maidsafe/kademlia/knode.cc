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

#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/kademlia/knode-api.h"

namespace kad {

KNode::KNode(rpcprotocol::ChannelManager *channel_manager,
             transport::TransportHandler *transport_handler,
             NodeType type, const std::string &private_key,
             const std::string &public_key, const bool &port_forwarded,
             const bool &use_upnp, const boost::uint16_t &k)
      : pimpl_(new KNodeImpl(channel_manager, transport_handler, type,
               private_key, public_key, port_forwarded, use_upnp, k)) {}

KNode::KNode(rpcprotocol::ChannelManager *channel_manager,
             transport::TransportHandler *transport_handler,
             NodeType type, const boost::uint16_t &k,
             const boost::uint16_t &alpha, const boost::uint16_t &beta,
             const boost::uint32_t &refresh_time,
             const std::string &private_key, const std::string &public_key,
             const bool &port_forwarded, const bool &use_upnp)
      : pimpl_(new KNodeImpl(channel_manager, transport_handler, type, k, alpha,
               beta, refresh_time, private_key, public_key, port_forwarded,
               use_upnp)) {}

KNode::~KNode() {}

void KNode::set_transport_id(const boost::int16_t &transport_id) {
  pimpl_->set_transport_id(transport_id);
}

void KNode::Join(const KadId &node_id, const std::string &kad_config_file,
                 VoidFunctorOneString callback) {
  pimpl_->Join(node_id, kad_config_file, callback);
}

void KNode::Join(const std::string &kad_config_file,
                 VoidFunctorOneString callback) {
  pimpl_->Join(kad_config_file, callback);
}

void KNode::Join(const KadId &node_id, const std::string &kad_config_file,
                 const std::string &external_ip,
                 const boost::uint16_t &external_port,
                 VoidFunctorOneString callback) {
  pimpl_->Join(node_id, kad_config_file, external_ip, external_port, callback);
}

void KNode::Join(const std::string &kad_config_file,
                 const std::string &external_ip,
                 const boost::uint16_t &external_port,
                 VoidFunctorOneString callback) {
  pimpl_->Join(kad_config_file, external_ip, external_port, callback);
}

void KNode::Leave() {
  pimpl_->Leave();
}

void KNode::StoreValue(const KadId &key, const SignedValue &signed_value,
                       const SignedRequest &signed_request,
                       const boost::int32_t &ttl,
                       VoidFunctorOneString callback) {
  pimpl_->StoreValue(key, signed_value, signed_request, ttl, callback);
}

void KNode::StoreValue(const KadId &key, const std::string &value,
                       const boost::int32_t &ttl,
                       VoidFunctorOneString callback) {
  pimpl_->StoreValue(key, value, ttl, callback);
}

void KNode::FindValue(const KadId &key, const bool &check_alternative_store,
                      VoidFunctorOneString callback) {
  pimpl_->FindValue(key, check_alternative_store, callback);
}

void KNode::GetNodeContactDetails(const KadId &node_id,
                                  VoidFunctorOneString callback,
                                  const bool &local) {
  pimpl_->GetNodeContactDetails(node_id, callback, local);
}

void KNode::FindKClosestNodes(const KadId &node_id,
                              VoidFunctorOneString callback) {
  pimpl_->FindKClosestNodes(node_id, callback);
}

void KNode::GetKNodesFromRoutingTable(
    const KadId &key,
    const std::vector<Contact> &exclude_contacts,
    std::vector<Contact> *close_nodes) {
  pimpl_->GetKNodesFromRoutingTable(key, exclude_contacts, close_nodes);
}

void KNode::Ping(const KadId &node_id, VoidFunctorOneString callback) {
  pimpl_->Ping(node_id, callback);
}

void KNode::Ping(const Contact &remote, VoidFunctorOneString callback) {
  pimpl_->Ping(remote, callback);
}

int KNode::AddContact(Contact new_contact, const float &rtt,
                      const bool &only_db) {
  return pimpl_->AddContact(new_contact, rtt, only_db);
}

void KNode::RemoveContact(const KadId &node_id) {
  pimpl_->RemoveContact(node_id);
}

bool KNode::GetContact(const KadId &id, Contact *contact) {
  return pimpl_->GetContact(id, contact);
}

bool KNode::FindValueLocal(const KadId &key,
                           std::vector<std::string> *values) {
  return pimpl_->FindValueLocal(key, values);
}

bool KNode::StoreValueLocal(const KadId &key,
                            const std::string &value,
                            const boost::int32_t &ttl) {
  return pimpl_->StoreValueLocal(key, value, ttl);
}

bool KNode::RefreshValueLocal(const KadId &key,
                              const std::string &value,
                              const boost::int32_t &ttl) {
  return pimpl_->RefreshValueLocal(key, value, ttl);
}

void KNode::GetRandomContacts(const size_t &count,
                              const std::vector<Contact> &exclude_contacts,
                              std::vector<Contact> *contacts) {
  pimpl_->GetRandomContacts(count, exclude_contacts, contacts);
}

void KNode::HandleDeadRendezvousServer(const bool &dead_server) {
  pimpl_->HandleDeadRendezvousServer(dead_server);
}

ConnectionType KNode::CheckContactLocalAddress(const KadId &id,
                                               const std::string &ip,
                                               const boost::uint16_t &port,
                                               const std::string &ext_ip) {
  return pimpl_->CheckContactLocalAddress(id, ip, port, ext_ip);
}

void KNode::UpdatePDRTContactToRemote(const KadId &node_id,
                                      const std::string &host_ip) {
  pimpl_->UpdatePDRTContactToRemote(node_id, host_ip);
}

ContactInfo KNode::contact_info() const {
  return pimpl_->contact_info();
}

KadId KNode::node_id() const {
  return pimpl_->node_id();
}

std::string KNode::host_ip() const {
  return pimpl_->host_ip();
}

boost::uint16_t KNode::host_port() const {
  return pimpl_->host_port();
}

std::string KNode::local_host_ip() const {
  return pimpl_->local_host_ip();
}

boost::uint16_t KNode::local_host_port() const {
  return pimpl_->local_host_port();
}

std::string KNode::rendezvous_ip() const {
  return pimpl_->rendezvous_ip();
}

boost::uint16_t KNode::rendezvous_port() const {
  return pimpl_->rendezvous_port();
}

bool KNode::is_joined() const {
  return pimpl_->is_joined();
}

KadRpcs* KNode::kadrpcs() {
  return pimpl_->kadrpcs();
}

boost::uint32_t KNode::KeyLastRefreshTime(const KadId &key,
                                          const std::string &value) {
  return pimpl_->KeyLastRefreshTime(key, value);
}
boost::uint32_t KNode::KeyExpireTime(const KadId &key,
                                     const std::string &value) {
  return pimpl_->KeyExpireTime(key, value);
}

bool KNode::HasRSAKeys() {
  return pimpl_->HasRSAKeys();
}

boost::int32_t KNode::KeyValueTTL(const KadId &key,
                                  const std::string &value) const {
  return pimpl_->KeyValueTTL(key, value);
}

void KNode::set_alternative_store(base::AlternativeStore* alternative_store) {
  pimpl_->set_alternative_store(alternative_store);
}

base::AlternativeStore *KNode::alternative_store() {
  return pimpl_->alternative_store();
}

void KNode::set_signature_validator(base::SignatureValidator *validator) {
  pimpl_->set_signature_validator(validator);
}

void KNode::UpdateValue(const KadId &key,
                        const SignedValue &old_value,
                        const SignedValue &new_value,
                        const SignedRequest &signed_request,
                        boost::uint32_t ttl,
                        VoidFunctorOneString callback) {
  pimpl_->UpdateValue(key, old_value, new_value, signed_request, ttl, callback);
}

void KNode::DeleteValue(const KadId &key, const SignedValue &signed_value,
                        const SignedRequest &signed_request,
                        VoidFunctorOneString callback) {
  pimpl_->DeleteValue(key, signed_value, signed_request, callback);
}

NatType KNode::host_nat_type() {
  return pimpl_->host_nat_type();
}

bool KNode::recheck_nat_type() {
  return pimpl_->recheck_nat_type();
}

}  // namespace kad
