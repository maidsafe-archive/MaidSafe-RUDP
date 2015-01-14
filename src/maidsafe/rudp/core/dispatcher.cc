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

#include "maidsafe/rudp/core/dispatcher.h"

#include <cassert>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/packets/packet.h"
#include "maidsafe/rudp/core/socket.h"

namespace ip = boost::asio::ip;

namespace maidsafe {

namespace rudp {

namespace detail {

Dispatcher::Dispatcher() : connection_manager_(nullptr) {}

void Dispatcher::SetConnectionManager(ConnectionManager *connection_manager) {
  std::lock_guard<decltype(mutex_)> guard(mutex_);
  connection_manager_ = connection_manager;
}

uint32_t Dispatcher::AddSocket(Socket* socket) {
  ConnectionManager *connection_manager;
  {
    std::lock_guard<decltype(mutex_)> guard(mutex_);
    connection_manager = connection_manager_;
  }
  return connection_manager ? connection_manager->AddSocket(socket) : 0;
}

void Dispatcher::RemoveSocket(uint32_t id) {
  ConnectionManager *connection_manager;
  {
    std::lock_guard<decltype(mutex_)> guard(mutex_);
    connection_manager = connection_manager_;
  }
  if (connection_manager)
    connection_manager->RemoveSocket(id);
}

void Dispatcher::HandleReceiveFrom(const boost::asio::const_buffer& data,
                                   const ip::udp::endpoint& endpoint) {
  ConnectionManager* connection_manager;
  {
    std::lock_guard<decltype(mutex_)> guard(mutex_);
    connection_manager = connection_manager_;
  }
  if (connection_manager) {
    Socket* socket(connection_manager->GetSocket(data, endpoint));
    if (socket) {
      socket->HandleReceiveFrom(data, endpoint);
    }
  }
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
