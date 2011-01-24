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

#include "maidsafe/kademlia/utils.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

using transport::Endpoint;

namespace kademlia {

bool IsValid(const Endpoint &endpoint) {
  return !(endpoint.ip == transport::IP() && endpoint.port == 0);
}

Contact FromProtobuf(const protobuf::Contact &pb_contact) {
  if (!pb_contact.IsInitialized())
    return Contact();

  NodeId node_id(pb_contact.node_id());
  if (!node_id.IsValid())
    return Contact();

  Endpoint endpoint(pb_contact.endpoint().ip(), pb_contact.endpoint().port());
  if (!IsValid(endpoint))
    return Contact();

  std::vector<Endpoint> local_endpoints;
  for (int i = 0; i < pb_contact.local_ips_size(); ++i) {
    Endpoint local_endpoint(pb_contact.local_ips(i), pb_contact.local_port());
    if (IsValid(local_endpoint))
      local_endpoints.push_back(local_endpoint);
  }

  Endpoint rendezvous_endpoint;
  if (pb_contact.has_rendezvous()) {
    rendezvous_endpoint = Endpoint(pb_contact.rendezvous().ip(),
                                   pb_contact.rendezvous().port());
  }

  return Contact(node_id, endpoint, rendezvous_endpoint, local_endpoints);
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

  for (auto it = contact.local_endpoints().begin();
       it != contact.local_endpoints().end(); ++it) {
    pb_contact.add_local_ips((*it).ip.to_string(ec));
    pb_contact.set_local_port((*it).port);
  }

  return pb_contact;
}

}  // namespace kademlia

}  // namespace maidsafe
