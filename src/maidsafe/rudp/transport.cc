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
#include <functional>

#include "maidsafe/rudp/connection.h"
#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/core/socket.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {
int g_transport_id(1);
Transport::Transport(std::shared_ptr<AsioService> asio_service)          // NOLINT (Fraser)
    : asio_service_(asio_service),
      strand_(asio_service->service()),
      multiplexer_(new detail::Multiplexer(asio_service->service())),
      connections_(),
      mutex_(),
      on_message_(),
      on_connection_added_(),
      on_connection_lost_(),
      bootstrap_endpoint_(), id(g_transport_id++),
      bootstrap_disconnection_timer_(asio_service->service()) {}

Transport::~Transport() {
  Close();
}

void Transport::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    Endpoint local_endpoint,
    const OnMessage::slot_type &on_message_slot,
    const OnConnectionAdded::slot_type &on_connection_added_slot,
    const OnConnectionLost::slot_type &on_connection_lost_slot,
    Endpoint *chosen_endpoint,
    boost::signals2::connection *on_message_connection,
    boost::signals2::connection *on_connection_added_connection,
    boost::signals2::connection *on_connection_lost_connection) {
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
    DLOG(ERROR) << "Failed to open multiplexer.  Result: " << result;
    return;
  }

  StartDispatch();

  for (auto itr(bootstrap_endpoints.begin());
       itr != bootstrap_endpoints.end();
       ++itr) {
    if (!IsValid(*itr)) {
      DLOG(ERROR) << *itr << " is an invalid endpoint.";
      continue;
    }
    ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(),
                                                          strand_,
                                                          multiplexer_, *itr));
    connection->set_temporary(false);
    connection->set_bootstrapping(true);
    connection->StartConnecting("");

 // TODO(Fraser#5#): 2012-04-25 - Wait until these are valid or timeout.
                                             //Sleep(bptime::milliseconds((RandomUint32() % 100) + 1000));
    int count(0);
    while (!IsValid(multiplexer_->external_endpoint()) ||
           !IsValid(multiplexer_->local_endpoint())) {
        if (count > 3) {
           DLOG(ERROR) << "Timed out waiting for connection";
           break;
        }
           Sleep(bptime::seconds(1));
           ++count;
    }

    if (IsValid(multiplexer_->external_endpoint()) &&
        IsValid(multiplexer_->local_endpoint())) {
      bootstrap_endpoint_ = *itr;
      *chosen_endpoint = bootstrap_endpoint_;
      return;
    }
  }
}

void Transport::Close() {
  bootstrap_disconnection_timer_.cancel();
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    (*it)->Close();
  if (multiplexer_)
    multiplexer_->Close();
  multiplexer_.reset();
}

void Transport::Connect(const Endpoint &peer_endpoint,
                        const std::string &validation_data) {
  strand_.dispatch(std::bind(&Transport::DoConnect, shared_from_this(),
                             peer_endpoint, validation_data));
}

void Transport::DoConnect(const Endpoint &peer_endpoint,
                          const std::string &validation_data) {
  bool opened_multiplexer(false);

  if (!multiplexer_->IsOpen()) {
    ReturnCode result =
        multiplexer_->Open(Endpoint(peer_endpoint.protocol(), 0));
    if (result != kSuccess) {
      DLOG(ERROR) << "Failed to open multiplexer.  Error " << result;
      return;
    }
    opened_multiplexer = true;
  }

  ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(),
                                                        strand_,
                                                        multiplexer_,
                                                        peer_endpoint));
  connection->set_temporary(false);
  connection->StartConnecting(validation_data);

  if (opened_multiplexer)
    StartDispatch();
}

int Transport::CloseConnection(const Endpoint &peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(std::find_if(connections_.begin(),
                        connections_.end(),
                        [peer_endpoint](const ConnectionPtr &connection) {
                          return connection->Socket().RemoteEndpoint() ==
                                 peer_endpoint;
                        }));
  if (itr == connections_.end()) {
    DLOG(WARNING) << "Not currently connected to " << peer_endpoint;
    return kInvalidConnection;
  }

  strand_.dispatch(std::bind(&Transport::DoCloseConnection,
                             shared_from_this(), *itr));
  return kSuccess;
}

void Transport::DoCloseConnection(ConnectionPtr connection) {
  connection->Close();
}

int Transport::Send(const Endpoint &peer_endpoint, const std::string &message) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(std::find_if(connections_.begin(),
                        connections_.end(),
                        [peer_endpoint](const ConnectionPtr &connection) {
                          return connection->Socket().RemoteEndpoint() ==
                                 peer_endpoint;
                        }));
  if (itr == connections_.end()) {
    DLOG(WARNING) << "Not currently connected to " << peer_endpoint;
    return kInvalidConnection;
  }

  strand_.dispatch(std::bind(&Transport::DoSend, shared_from_this(),
                             *itr, message));
  return kSuccess;
}

void Transport::DoSend(ConnectionPtr connection, const std::string &message) {
  connection->StartSending(message);
}

Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Endpoint Transport::local_endpoint() const {
  return multiplexer_->local_endpoint();
}

Endpoint Transport::bootstrap_endpoint() const {
  return bootstrap_endpoint_;
}

size_t Transport::ConnectionsCount() const {
  boost::mutex::scoped_lock lock(mutex_);
  return connections_.size();
}

void Transport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&Transport::HandleDispatch,
                                        shared_from_this(),
                                        multiplexer_, args::_1));
  multiplexer_->AsyncDispatch(handler);
}

void Transport::HandleDispatch(MultiplexerPtr multiplexer,
                               const boost::system::error_code &/*ec*/) {
  if (!multiplexer->IsOpen())
    return;
  Endpoint bootstrapping_endpoint(multiplexer->GetBootstrappingEndpoint());
  if (IsValid(bootstrapping_endpoint)) {
    DLOG(INFO) << "GetBootstrappingEndpoint called with valid ep!!! transport -" << id << "ep - " <<bootstrapping_endpoint;
    ConnectionPtr connection(
        std::make_shared<Connection>(shared_from_this(),
                                     strand_,
                                     multiplexer_,
                                     bootstrapping_endpoint));
    connection->set_temporary(true);
    connection->StartConnecting("");
    // TODO(Fraser#5#): 2012-04-18 - Drop this connection after 1 min.  Ensure
    //                  when connection is dropped that ManagedConnections'
    //                  connection_lost_functor is not called.
    //bootstrap_disconnection_timer_.expires_from_now(
    //    Parameters::bootstrap_disconnection_timeout);
    //bootstrap_disconnection_timer_.async_wait(
    //    std::bind(&Transport::DoCloseConnection,
    //              shared_from_this(), connection));
    //DLOG(INFO) << "Scheduled disconnection of bootstrapping connection to "
    //           << connection->Socket().RemoteEndpoint();
  }
  StartDispatch();
}

void Transport::SignalMessageReceived(const std::string &message) {
  strand_.dispatch(std::bind(&Transport::DoSignalMessageReceived,
                             shared_from_this(), message));
// TODO(Prakash) Test the performance with below option.
// Dispatch the message outside the strand.
// strand_.get_io_service().post(std::bind(&Transport::DoSignalMessageReceived,
//                                         shared_from_this(), message));
}

void Transport::DoSignalMessageReceived(const std::string &message) {
  on_message_(message);
}

void Transport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoInsertConnection,
                             shared_from_this(), connection));
}

void Transport::DoInsertConnection(ConnectionPtr connection) {
  DLOG(INFO) << "DoInsertConnection with" << connection->Socket().RemoteEndpoint();
  connections_.insert(connection);
  if (!connection->temporary())
    on_connection_added_(connection->Socket().RemoteEndpoint(),
                         shared_from_this());
}

void Transport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoRemoveConnection,
                             shared_from_this(), connection));
}

void Transport::DoRemoveConnection(ConnectionPtr connection) {
  if (connection->temporary())  // This is bootstrapping connection
    return;

  bool bootstraped_connection(false);
  if (Endpoint() != bootstrap_endpoint_) {  // This is my bootstrapped connection
    if (connection->Socket().RemoteEndpoint() == bootstrap_endpoint_) {
      bootstraped_connection = true;
      bootstrap_endpoint_ = Endpoint();
    }
  }
  connections_.erase(connection);
  if (connections_.empty()) {
    on_connection_lost_(connection->Socket().RemoteEndpoint(),
                        shared_from_this(), bootstraped_connection);
  } else {
    on_connection_lost_(connection->Socket().RemoteEndpoint(), nullptr,
                        bootstraped_connection);
  }
}

}  // namespace rudp

}  // namespace maidsafe
