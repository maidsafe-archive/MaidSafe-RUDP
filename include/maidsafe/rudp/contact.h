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

struct endpoint_pair {
  endpoint_pair() = default;
  endpoint_pair(const endpoint_pair&) = default;
  endpoint_pair(endpoint_pair&& other) MAIDSAFE_NOEXCEPT : local(std::move(other.local)),
                                                           external(std::move(other.external)) {}
  endpoint_pair& operator=(const endpoint_pair&) = default;
  endpoint_pair& operator=(endpoint_pair&& other) {
    local = std::move(other.local);
    external = std::move(other.external);
    return *this;
  }

  explicit endpoint_pair(endpoint both) : local(both), external(std::move(both)) {}

  endpoint_pair(endpoint local, endpoint external)
      : local(std::move(local)), external(std::move(external)) {}

  endpoint local, external;
};

inline bool operator==(const endpoint_pair& lhs, const endpoint_pair& rhs) {
  return lhs.local == rhs.local && lhs.external == rhs.external;
}

struct contact {
  contact() = default;
  contact(const contact&) = default;
  contact(contact&& other) MAIDSAFE_NOEXCEPT : id(std::move(other.id)),
                                               endpoints(std::move(other.endpoints)),
                                               public_key(std::move(other.public_key)) {}
  contact& operator=(const contact&) = default;
  contact& operator=(contact&& other) {
    id = std::move(other.id);
    endpoints = std::move(other.endpoints);
    public_key = std::move(other.public_key);
    return *this;
  }

  contact(node_id node_id, endpoint both, asymm::PublicKey public_key_in)
      : id(std::move(node_id)),
        endpoints(std::move(both)),
        public_key(std::move(public_key_in)) {}

  contact(node_id node_id, endpoint local, endpoint external, asymm::PublicKey public_key_in)
      : id(std::move(node_id)),
        endpoints(std::move(local), std::move(external)),
        public_key(std::move(public_key_in)) {}

  node_id id;
  endpoint_pair endpoints;
  asymm::PublicKey public_key;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONTACT_H_
