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

#ifndef MAIDSAFE_RUDP_CONFIG_H_
#define MAIDSAFE_RUDP_CONFIG_H_

#include <functional>
#include <vector>

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/tagged_value.h"

namespace maidsafe {

namespace rudp {

struct endpoint_pair;
struct contact;

using connection_id = TaggedValue<NodeId, struct connection_id_tag>;
using endpoint = boost::asio::ip::udp::endpoint;
using sendable_message = std::vector<unsigned char>;
using received_message = std::vector<unsigned char>;
using bootstrap_functor = std::function<void(maidsafe_error, contact)>;  // chosen bootstrap contact
using get_available_endpoints_functor = std::function<void(maidsafe_error, endpoint_pair)>;
using connection_added_functor = std::function<void(maidsafe_error)>;
using connection_removed_functor = std::function<void(maidsafe_error)>;
using message_sent_functor = std::function<void(maidsafe_error)>;
using bootstrap_list = std::vector<contact>;

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONFIG_H_
