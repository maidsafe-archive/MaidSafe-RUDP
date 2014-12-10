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

#ifndef MAIDSAFE_RUDP_TYPES_H_
#define MAIDSAFE_RUDP_TYPES_H_

#include <functional>
#include <system_error>
#include <vector>

#include "asio/async_result.hpp"
#include "asio/handler_type.hpp"
#include "asio/ip/udp.hpp"

namespace maidsafe {

namespace rudp {

struct EndpointPair;
struct Contact;

using Endpoint = boost::asio::ip::udp::endpoint;
using SendableMessage = std::vector<unsigned char>;
using ReceivedMessage = std::vector<unsigned char>;
using error_code      = std::error_code;

template <typename CompletionToken>
using BootstrapHandler =
    typename asio::handler_type<CompletionToken, void(error_code, Contact)>::type;

template <typename CompletionToken>
using BootstrapReturn =
    typename asio::async_result<BootstrapHandler<CompletionToken>>::type;

template <typename CompletionToken>
using GetAvailableEndpointsHandler =
    typename asio::handler_type<CompletionToken, void(error_code, EndpointPair)>::type;

template <typename CompletionToken>
using GetAvailableEndpointsReturn = typename asio::async_result<
                                      GetAvailableEndpointsHandler<CompletionToken>>::type;

template <typename CompletionToken>
using AddHandler = typename asio::handler_type<CompletionToken, void(error_code)>::type;

template <typename CompletionToken>
using AddReturn =
    typename asio::async_result<AddHandler<CompletionToken>>::type;

template <typename CompletionToken>
using RemoveHandler =
    typename asio::handler_type<CompletionToken, void(error_code)>::type;

template <typename CompletionToken>
using RemoveReturn =
    typename asio::async_result<typename RemoveHandler<CompletionToken>::type>::type;

template <typename CompletionToken>
using SendHandler =
    typename asio::handler_type<CompletionToken, void(error_code)>::type;

template <typename CompletionToken>
using SendReturn =
    typename asio::async_result<typename SendHandler<CompletionToken>::type>::type;



// TODO(Fraser#5#): 2014-12-01 - Remove for RUDPv2
using ConnectionAddedFunctor = std::function<void(error_code)>;
using MessageSentFunctor = std::function<void(error_code)>;
using BootstrapContacts = std::vector<Contact>;

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TYPES_H_
