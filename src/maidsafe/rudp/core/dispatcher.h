/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_CORE_DISPATCHER_H_
#define MAIDSAFE_RUDP_CORE_DISPATCHER_H_

#include <cstdint>

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

  ConnectionManager* connection_manager_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_DISPATCHER_H_
