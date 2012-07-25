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

#include "maidsafe/rudp/transport.h"

#include <algorithm>
#include <cassert>

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/connection_manager.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace { typedef boost::asio::ip::udp::endpoint Endpoint; }


Transport::Transport(AsioService& asio_service)  // NOLINT (Fraser)
    : asio_service_(asio_service),
      strand_(asio_service.service()),
      multiplexer_(new detail::Multiplexer(asio_service.service())),
      connection_manager_(),
      on_message_(),
      on_connection_added_(),
      on_connection_lost_() {}

Transport::~Transport() {
  Close();
}

void Transport::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    Endpoint local_endpoint,
    bool bootstrap_off_existing_connection,
    const OnMessage::slot_type& on_message_slot,
    const OnConnectionAdded::slot_type& on_connection_added_slot,
    const OnConnectionLost::slot_type& on_connection_lost_slot,
    Endpoint* chosen_endpoint,
    boost::signals2::connection* on_message_connection,
    boost::signals2::connection* on_connection_added_connection,
    boost::signals2::connection* on_connection_lost_connection) {
  BOOST_ASSERT(chosen_endpoint);
  BOOST_ASSERT(on_message_connection);
  BOOST_ASSERT(on_connection_added_connection);
  BOOST_ASSERT(on_connection_lost_connection);
  BOOST_ASSERT(!multiplexer_->IsOpen());

  *chosen_endpoint = Endpoint();
  *on_message_connection = on_message_.connect(on_message_slot);
  *on_connection_added_connection =
      on_connection_added_.connect(on_connection_added_slot);
  *on_connection_lost_connection =
      on_connection_lost_.connect(on_connection_lost_slot);

  ReturnCode result = multiplexer_->Open(local_endpoint);
  if (result != kSuccess) {
    LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    return;
  }

  connection_manager_.reset(new ConnectionManager(shared_from_this(), strand_, multiplexer_));
  StartDispatch();

  for (auto itr(bootstrap_endpoints.begin()); itr != bootstrap_endpoints.end(); ++itr) {
    if (!IsValid(*itr)) {
      LOG(kError) << *itr << " is an invalid endpoint.";
      continue;
    }
    connection_manager_->Connect(*itr, "", bootstrap_off_existing_connection ?
                                     bptime::time_duration() :
                                     Parameters::bootstrap_disconnection_timeout);

    // TODO(Fraser#5#): 2012-04-25 - Wait until these are valid or timeout.
    int count(0);
    while (!IsValid(multiplexer_->external_endpoint()) ||
           !IsValid(multiplexer_->local_endpoint())) {
      if (count > 50) {
         LOG(kError) << "Timed out waiting for connection. External endpoint: "
                     << multiplexer_->external_endpoint() << "  Local endpoint: "
                     << multiplexer_->local_endpoint();
         break;
      }
      Sleep(bptime::milliseconds(100));
      ++count;
    }

    if (IsValid(multiplexer_->external_endpoint()) && IsValid(multiplexer_->local_endpoint())) {
      *chosen_endpoint = *itr;
      break;
    }
  }
}

void Transport::Close() {
  if (connection_manager_)
    connection_manager_->Close();
  if (multiplexer_)
    multiplexer_->Close();
}

void Transport::Connect(const Endpoint& peer_endpoint, const std::string& validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(), peer_endpoint,
                             validation_data));
}

void Transport::DoConnect(const Endpoint& peer_endpoint, const std::string& validation_data) {
  bool opened_multiplexer(false);

  if (!multiplexer_->IsOpen()) {
    ReturnCode result =
        multiplexer_->Open(Endpoint(peer_endpoint.protocol(), 0));
    if (result != kSuccess) {
      LOG(kError) << "Failed to open multiplexer.  Error " << result;
      return;
    }
    opened_multiplexer = true;
  }

  connection_manager_->Connect(peer_endpoint, validation_data, bptime::pos_infin);

  if (opened_multiplexer)
    StartDispatch();
}

int Transport::CloseConnection(const Endpoint& peer_endpoint) {
  return connection_manager_->CloseConnection(peer_endpoint);
}

void Transport::Send(const Endpoint& peer_endpoint,
                     const std::string& message,
                     const MessageSentFunctor& message_sent_functor) {
  connection_manager_->Send(peer_endpoint, message, message_sent_functor);
}

Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Endpoint Transport::local_endpoint() const {
  return multiplexer_->local_endpoint();
}

bool Transport::IsTemporaryConnection(const Endpoint& peer_endpoint) {
  return connection_manager_->IsTemporaryConnection(peer_endpoint);
}

void Transport::MakeConnectionPermanent(const Endpoint& peer_endpoint,
                                        const std::string& validation_data) {
  connection_manager_->MakeConnectionPermanent(peer_endpoint, validation_data);
}

size_t Transport::ConnectionsCount() const {
  return connection_manager_->size();
}

void Transport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&Transport::HandleDispatch, shared_from_this(),
                                        multiplexer_, args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void Transport::HandleDispatch(MultiplexerPtr multiplexer,
                               const boost::system::error_code &/*ec*/) {
  if (!multiplexer->IsOpen())
    return;

  StartDispatch();
}

void Transport::SignalMessageReceived(const std::string& message) {
  strand_.dispatch(std::bind(&Transport::DoSignalMessageReceived,
                             shared_from_this(), message));
// TODO(Prakash) Test the performance with below option.
// Dispatch the message outside the strand.
// strand_.get_io_service().post(std::bind(&Transport::DoSignalMessageReceived,
//                                         shared_from_this(), message));
}

void Transport::DoSignalMessageReceived(const std::string& message) {
  on_message_(message);
}

void Transport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoInsertConnection, shared_from_this(), connection));
}

void Transport::DoInsertConnection(ConnectionPtr connection) {
  connection_manager_->InsertConnection(connection);
  on_connection_added_(connection->Socket().RemoteEndpoint(), shared_from_this());
}

void Transport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoRemoveConnection, shared_from_this(), connection));
}

void Transport::DoRemoveConnection(ConnectionPtr connection) {
  bool connections_empty(false), temporary_connection(false);
  connection_manager_->RemoveConnection(connection, connections_empty, temporary_connection);
  on_connection_lost_(connection->Socket().RemoteEndpoint(), shared_from_this(),
                      connections_empty, temporary_connection);
}

}  // namespace rudp

}  // namespace maidsafe
