/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_RUDP_CONTACT_H_
#define MAIDSAFE_RUDP_CONTACT_H_

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/types.h"

namespace maidsafe {

namespace rudp {

struct EndpointPair {
  EndpointPair() = default;
  EndpointPair(const EndpointPair&) = default;
  EndpointPair(EndpointPair&& other) MAIDSAFE_NOEXCEPT : local(std::move(other.local)),
                                                         external(std::move(other.external)) {}
  EndpointPair& operator=(const EndpointPair&) = default;
  EndpointPair& operator=(EndpointPair&& other) {
    local = std::move(other.local);
    external = std::move(other.external);
    return *this;
  }

  explicit EndpointPair(Endpoint both) : local(both), external(std::move(both)) {}

  EndpointPair(Endpoint local, Endpoint external)
      : local(std::move(local)), external(std::move(external)) {}

  Endpoint local, external;
};

inline bool operator==(const EndpointPair& lhs, const EndpointPair& rhs) {
  return lhs.local == rhs.local && lhs.external == rhs.external;
}

inline std::ostream& operator<<(std::ostream& os, const EndpointPair& ep) {
  return os << "(local: " << ep.local << "; external: " << ep.external << ")";
}

struct Contact {
  Contact() = default;
  Contact(const Contact&) = default;
  Contact(Contact&& other) MAIDSAFE_NOEXCEPT : id(std::move(other.id)),
                                               endpoint_pair(std::move(other.endpoint_pair)),
                                               public_key(std::move(other.public_key)) {}
  Contact& operator=(const Contact&) = default;
  Contact& operator=(Contact&& other) {
    id = std::move(other.id);
    endpoint_pair = std::move(other.endpoint_pair);
    public_key = std::move(other.public_key);
    return *this;
  }

  Contact(NodeId node_id, Endpoint both, asymm::PublicKey public_key_in)
      : id(std::move(node_id)),
        endpoint_pair(std::move(both)),
        public_key(std::move(public_key_in)) {}

  Contact(NodeId node_id, EndpointPair endpoint_pair_in, asymm::PublicKey public_key_in)
      : id(std::move(node_id)),
        endpoint_pair(std::move(endpoint_pair_in)),
        public_key(std::move(public_key_in)) {}

  NodeId id;
  EndpointPair endpoint_pair;
  asymm::PublicKey public_key;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONTACT_H_
