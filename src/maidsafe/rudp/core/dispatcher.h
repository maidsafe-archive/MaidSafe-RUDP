/*  Copyright 2012 MaidSafe.net limited

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

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_CORE_DISPATCHER_H_
#define MAIDSAFE_RUDP_CORE_DISPATCHER_H_

#include <cstdint>
#include <mutex>

#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"

namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Socket;

class Dispatcher {
 public:
  Dispatcher();

  void SetConnectionManager(ConnectionManager* connection_manager);

  // Add a socket. Returns a new unique id for the socket.
  uint32_t AddSocket(Socket* socket);

  // Remove the socket corresponding to the given id.
  void RemoveSocket(uint32_t id);

  // Handle a new packet by dispatching to the appropriate socket.
  void HandleReceiveFrom(const boost::asio::const_buffer& data,
                         const boost::asio::ip::udp::endpoint& endpoint);

 private:
  // Disallow copying and assignment.
  Dispatcher(const Dispatcher&);
  Dispatcher& operator=(const Dispatcher&);

  std::mutex mutex_;
  ConnectionManager* connection_manager_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_DISPATCHER_H_
