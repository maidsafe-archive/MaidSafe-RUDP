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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_KADEMLIA_CONTACT_H_
#define MAIDSAFE_KADEMLIA_CONTACT_H_

#include <boost/cstdint.hpp>

#include "maidsafe/kademlia/kademlia.pb.h"
#include "maidsafe/kademlia/nodeid.h"
#include "maidsafe/transport/transport.h"

#include <string>

namespace kademlia {

class Contact {
 public:
  Contact();
  explicit Contact(const Contact &other);
  explicit Contact(const protobuf::Contact &contact);
  Contact(const std::string &node_id,
          const transport::Endpoint ep);
  bool FromProtobuf(const protobuf::Contact &contact);
  protobuf::Contact ToProtobuf() const;
  bool SetPreferredEndpoint(const transport::IP &ip);
  transport::Endpoint GetPreferredEndpoint() const;
  
  NodeId node_id() const { return node_id_; }
  void set_node_id(const NodeId &node_id) { node_id_ = node_id; }
  transport::Endpoint endpoint() const { return endpoint_; }
  void set_endpoint(const transport::Endpoint &endpoint) {
    endpoint_ = endpoint;
  }
  transport::Endpoint rendezvous_endpoint() const {
    return rendezvous_endpoint_;
  }
  void set_rendezvous_endpoint(const transport::Endpoint &rendezvous_endpoint) {
    rendezvous_endpoint_ = rendezvous_endpoint;
  }
  std::list<transport::Endpoint> local_endpoints() const {
    return local_endpoints_;
  }
  void add_local_endpoint(const transport::Endpoint &local_endpoint) {
    local_endpoints_.push_back(local_endpoint);
  }
  boost::uint16_t num_failed_rpcs() const { return num_failed_rpcs_; }
  void IncreaseFailedRpcs() { ++num_failed_rpcs_; }
  boost::uint64_t last_seen() const { return last_seen_; }
  void set_last_seen(const boost::uint64_t &last_seen) {
    last_seen_ = last_seen;
  }
  
  // Equality is based on node id or (IP and port) if dummy
  bool Equals(const Contact &other) const;
  bool operator<(const Contact &rhs) const;
  bool operator==(const Contact &rhs) const { return Equals(rhs); }
  Contact& operator=(const Contact &other);
 private:
  NodeId node_id_;
  transport::Endpoint endpoint_, rendezvous_endpoint_;
  std::list<transport::Endpoint> local_endpoints_;
  boost::uint16_t num_failed_rpcs_;
  boost::uint64_t last_seen_;
  bool prefer_local_;
};

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_CONTACT_H_
