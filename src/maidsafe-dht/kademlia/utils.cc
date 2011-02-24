/* Copyright (c) 2011 maidsafe.net limited
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

#include <algorithm>
#include "boost/bind.hpp"
#include "maidsafe-dht/kademlia/utils.h"
#include "maidsafe-dht/kademlia/contact.h"
#include "maidsafe-dht/kademlia/kademlia.pb.h"
#include "maidsafe-dht/kademlia/node_id.h"
#include "maidsafe-dht/transport/transport.h"

namespace maidsafe {

using transport::Endpoint;

namespace kademlia {

bool IsValid(const Endpoint &endpoint) {
  return !(endpoint.ip == transport::IP() || endpoint.port == 0);
}

bool HasId(const Contact &contact, const NodeId &node_id) {
  return contact.node_id() == node_id;
}

Contact FromProtobuf(const protobuf::Contact &pb_contact) {
  if (!pb_contact.IsInitialized())
    return Contact();

  std::vector<Endpoint> local_endpoints;
  for (int i = 0; i < pb_contact.local_ips_size(); ++i)
    local_endpoints.push_back(
        Endpoint(pb_contact.local_ips(i), pb_contact.local_port()));

  return Contact(
      NodeId(pb_contact.node_id()),
      Endpoint(pb_contact.endpoint().ip(), pb_contact.endpoint().port()),
      local_endpoints,
      pb_contact.has_rendezvous() ?
          Endpoint(pb_contact.rendezvous().ip(),
                   pb_contact.rendezvous().port()) :
          Endpoint(),
      pb_contact.has_tcp443() ? pb_contact.tcp443() : false,
      pb_contact.has_tcp80() ? pb_contact.tcp80() : false,
      pb_contact.has_public_key_id() ? pb_contact.public_key_id() : "",
      pb_contact.has_public_key() ? pb_contact.public_key() : "",
      pb_contact.has_other_info() ? pb_contact.other_info() : "");
}

protobuf::Contact ToProtobuf(const Contact &contact) {
  protobuf::Contact pb_contact;
  boost::system::error_code ec;

  pb_contact.set_node_id(contact.node_id().String());

  transport::protobuf::Endpoint *mutable_endpoint =
      pb_contact.mutable_endpoint();
  mutable_endpoint->set_ip(contact.endpoint().ip.to_string(ec));
  mutable_endpoint->set_port(contact.endpoint().port);

  if (IsValid(contact.rendezvous_endpoint())) {
    mutable_endpoint = pb_contact.mutable_rendezvous();
    mutable_endpoint->set_ip(contact.rendezvous_endpoint().ip.to_string(ec));
    mutable_endpoint->set_port(contact.rendezvous_endpoint().port);
  }

  std::vector<transport::Endpoint> local_endpoints(contact.local_endpoints());
  for (auto it = local_endpoints.begin(); it != local_endpoints.end(); ++it) {
    pb_contact.add_local_ips((*it).ip.to_string(ec));
    pb_contact.set_local_port((*it).port);
  }

  if (IsValid(contact.tcp443endpoint()))
    pb_contact.set_tcp443(true);
  if (IsValid(contact.tcp80endpoint()))
    pb_contact.set_tcp80(true);

  pb_contact.set_public_key_id(contact.public_key_id());
  pb_contact.set_public_key(contact.public_key());
  pb_contact.set_other_info(contact.other_info());
  return pb_contact;
}

bool IsListeningOnTCP(const Contact &contact) {
  return IsValid(contact.tcp443endpoint()) || IsValid(contact.tcp80endpoint());
}

void SortContacts(const NodeId &target_key, std::vector<Contact> *contacts) {
  if (!contacts || contacts->empty())
    return;
  std::sort(contacts->begin(), contacts->end(),
      boost::bind(static_cast<bool(*)(const Contact&,  // NOLINT
                                      const Contact&,
                                      const NodeId&)>(&CloserToTarget),
                  _1, _2, target_key));
}

// void SortLookupContact(const Key &target_key,
//                       std::vector<LookupContact> *lookup_contacts) {
//  if (contact_list->empty()) {
//    return;
//  }
//  std::list<ContactAndTargetKey> temp_list;
//  std::list<LookupContact>::iterator it;
//  // clone the contacts into a temporary list together with the target key
//  for (it = contact_list->begin(); it != contact_list->end(); ++it) {
//    ContactAndTargetKey new_ck;
//    new_ck.contact = it->kad_contact;
//    new_ck.target_key = target_key;
//    new_ck.contacted = it->contacted;
//    temp_list.push_back(new_ck);
//  }
//  temp_list.sort(CompareContact);
//  // restore the sorted contacts from the temporary list.
//  contact_list->clear();
//  std::list<ContactAndTargetKey>::iterator it1;
//  for (it1 = temp_list.begin(); it1 != temp_list.end(); ++it1) {
//    struct LookupContact ctc;
//    ctc.kad_contact = it1->contact;
//    ctc.contacted = it1->contacted;
//    contact_list->push_back(ctc);
//  }
// }

}  // namespace kademlia

}  // namespace maidsafe
