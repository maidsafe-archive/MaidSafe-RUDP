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

#include "maidsafe/rudp/core/dispatcher.h"

#include <cassert>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/core/socket.h"


namespace asio = boost::asio;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace detail {

Dispatcher::Dispatcher() : connection_manager_(nullptr) {}

void Dispatcher::SetConnectionManager(ConnectionManager* connection_manager) {
  connection_manager_ = connection_manager;
}

uint32_t Dispatcher::AddSocket(Socket* socket) {
  return connection_manager_ ? connection_manager_->AddSocket(socket) : 0;
}

void Dispatcher::RemoveSocket(uint32_t id) {
  if (connection_manager_)
    connection_manager_->RemoveSocket(id);
}

void Dispatcher::HandleReceiveFrom(const asio::const_buffer& data,
                                   const ip::udp::endpoint& endpoint) {
  if (connection_manager_) {
    Socket* socket(connection_manager_->GetSocket(data, endpoint));
    if (socket)
      socket->HandleReceiveFrom(data, endpoint);
  }
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
