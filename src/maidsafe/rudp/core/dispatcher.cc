/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/
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
                                                                                            uint32_t tprt(0);
                                                                                            uint32_t conn(0);
                                                                                            uint32_t disp(0);


namespace maidsafe {

namespace rudp {

namespace detail {

Dispatcher::Dispatcher() : connection_manager_(nullptr) {
                                                                                                my_disp_ = disp++;
                                                                                                LOG(kWarning) << "Ctor Dispatcher " << my_disp_;
}

                                                                                  Dispatcher::~Dispatcher() {
                                                                                                LOG(kWarning) << "\tDtor Dispatcher " << my_disp_;
                                                                                                            }

void Dispatcher::SetConnectionManager(ConnectionManager* connection_manager) {
  connection_manager_ = connection_manager;
}

uint32_t Dispatcher::AddSocket(Socket* socket) {
  assert(connection_manager_);
  return connection_manager_ ? connection_manager_->AddSocket(socket) : 0;
}

void Dispatcher::RemoveSocket(uint32_t id) {
  if (connection_manager_)
    connection_manager_->RemoveSocket(id);
}

void Dispatcher::HandleReceiveFrom(const asio::const_buffer& data,
                                   const ip::udp::endpoint& endpoint) {
                                                                        LOG(kWarning) << "HandleReceiveFrom Dispatcher " << my_disp_;
  if (connection_manager_) {
    Socket* socket(connection_manager_->GetSocket(data, endpoint));
    if (socket)
      socket->HandleReceiveFrom(data, endpoint);
  }
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
