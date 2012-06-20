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

#include "maidsafe/common/log.h"

#include "maidsafe/rudp/connection.h"
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

namespace {
typedef boost::asio::ip::udp::endpoint Endpoint;
}  // unnamed namespace

Transport::Transport(std::shared_ptr<AsioService> asio_service)          // NOLINT (Fraser)
    : asio_service_(asio_service),
      strand_(asio_service->service()),
      multiplexer_(new detail::Multiplexer(asio_service->service())),
      connections_(),
      mutex_(),
      on_message_(),
      on_connection_added_(),
      on_connection_lost_() {
                                                                                static std::atomic<int> count(0);
                                                                                trans_id_ = "Transport " + boost::lexical_cast<std::string>(count++);
                                                                                LOG(kVerbose) << trans_id_ << " constructor";
}

Transport::~Transport() {
                                                                                LOG(kVerbose) << trans_id_ << " destructor";
  Close();
}

void Transport::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    Endpoint local_endpoint,
    bool bootstrap_off_existing_connection,
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
    LOG(kError) << "Failed to open multiplexer.  Result: " << result;
    return;
  }

  StartDispatch();

  for (auto itr(bootstrap_endpoints.begin()); itr != bootstrap_endpoints.end(); ++itr) {
    if (!IsValid(*itr)) {
      LOG(kError) << *itr << " is an invalid endpoint.";
      continue;
    }
    ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(), strand_,
                                                          multiplexer_, *itr));
    connection->StartConnecting("", bootstrap_off_existing_connection ?
                                    bptime::time_duration() :
                                    Parameters::bootstrap_disconnection_timeout);

                                                                                                    //bootstrap_connection_ = std::make_shared<Connection>(shared_from_this(), strand_,
                                                                                                    //                                                     multiplexer_, *itr);
                                                                                                    //bootstrap_connection_->StartConnecting("", bootstrap_off_existing_connection ?
                                                                                                    //                                           bptime::time_duration() :
                                                                                                    //                                           Parameters::bootstrap_disconnection_timeout);

 // TODO(Fraser#5#): 2012-04-25 - Wait until these are valid or timeout.
                                             //Sleep(bptime::milliseconds((RandomUint32() % 100) + 1000));
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
      assert(*itr == connection->Socket().RemoteEndpoint());
      *chosen_endpoint = *itr;
      return;
    }
  }
}

void Transport::Close() {
                                                                                LOG(kVerbose) << trans_id_ << " closing.";
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    (*it)->Close();
  if (multiplexer_)
    multiplexer_->Close();
  multiplexer_.reset();
                                                                                LOG(kVerbose) << trans_id_ << " closed.";
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
      LOG(kError) << "Failed to open multiplexer.  Error " << result;
      return;
    }
    opened_multiplexer = true;
  }

  ConnectionPtr connection(std::make_shared<Connection>(shared_from_this(),
                                                        strand_,
                                                        multiplexer_,
                                                        peer_endpoint));
  connection->StartConnecting(validation_data, bptime::pos_infin);

  if (opened_multiplexer)
    StartDispatch();
}

int Transport::CloseConnection(const Endpoint &peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return kInvalidConnection;
  }

  strand_.dispatch(std::bind(&Transport::DoCloseConnection,
                             shared_from_this(), *itr));
  return kSuccess;
}

void Transport::DoCloseConnection(ConnectionPtr connection) {
  connection->Close();
}

void Transport::Send(const Endpoint &peer_endpoint,
                     const std::string &message,
                     const MessageSentFunctor &message_sent_functor) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    if (message_sent_functor)
      asio_service_->service().dispatch([message_sent_functor] { message_sent_functor(false); });
    return;
  }

  strand_.dispatch(std::bind(&Transport::DoSend, shared_from_this(),
                             *itr, message, message_sent_functor));
}

void Transport::DoSend(ConnectionPtr connection,
                       const std::string &message,
                       const MessageSentFunctor &message_sent_functor) {
  connection->StartSending(message, message_sent_functor);
}

Endpoint Transport::external_endpoint() const {
  return multiplexer_->external_endpoint();
}

Endpoint Transport::local_endpoint() const {
  return multiplexer_->local_endpoint();
}

bool Transport::IsTemporaryConnection(const Endpoint &peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end())
    return false;
  return (*itr)->IsTemporary();
}

void Transport::MakeConnectionPermanent(const Endpoint &peer_endpoint,
                                        const std::string &validation_data) {
  boost::mutex::scoped_lock lock(mutex_);
  auto itr(FindConnection(peer_endpoint));
  if (itr == connections_.end()) {
    LOG(kWarning) << "Not currently connected to " << peer_endpoint;
    return;
  }
  (*itr)->MakePermanent();
  strand_.dispatch(std::bind(&Transport::DoSend, shared_from_this(),
                             *itr, validation_data, MessageSentFunctor()));
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
  Endpoint joining_peer_endpoint(multiplexer->GetJoiningPeerEndpoint());
  if (IsValid(joining_peer_endpoint)) {
            LOG(kVerbose) << trans_id_ << " GetJoiningPeerEndpoint called with valid endpoint: " << joining_peer_endpoint;
    // Check if this joining node is already connected
    boost::mutex::scoped_lock lock(mutex_);
    auto itr(FindConnection(joining_peer_endpoint));
    if (itr == connections_.end()) {
      // Joining node is not already connected - start new temporary connection
      ConnectionPtr connection(
          std::make_shared<Connection>(shared_from_this(),
                                       strand_,
                                       multiplexer_,
                                       joining_peer_endpoint));
      connection->StartConnecting("", Parameters::bootstrap_disconnection_timeout);
    } else {
      if (!(*itr)->IsTemporary()) {
        LOG(kWarning) << "Received another bootstrap connection request from currently "
                      << "connected endpoint " << joining_peer_endpoint << " - closing connection.";
        (*itr)->Close();
      }
    }
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
  strand_.dispatch(std::bind(&Transport::DoInsertConnection, shared_from_this(), connection));
}

void Transport::DoInsertConnection(ConnectionPtr connection) {
                              LOG(kVerbose) << trans_id_ << " DoInsertConnection with " << connection->Socket().RemoteEndpoint();
  connections_.insert(connection);
                                                                              //if (!connection->temporary())
  on_connection_added_(connection->Socket().RemoteEndpoint(), shared_from_this());
}

void Transport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&Transport::DoRemoveConnection, shared_from_this(), connection));
}

void Transport::DoRemoveConnection(ConnectionPtr connection) {
                                                                                                  //if (connection->temporary())  // This is bootstrapping connection
                                                                                                  //  return;

  //if (Endpoint() != bootstrap_endpoint_) {  // This is my bootstrapped connection
  //  if (connection->Socket().RemoteEndpoint() == bootstrap_endpoint_) {
  //    bootstraped_connection = true;
  //    bootstrap_endpoint_ = Endpoint();
  //  }
  //}
  connections_.erase(connection);
  if (connections_.empty()) {
    on_connection_lost_(connection->Socket().RemoteEndpoint(), shared_from_this());
  } else {
    on_connection_lost_(connection->Socket().RemoteEndpoint(), nullptr);
  }
}

Transport::ConnectionSet::iterator Transport::FindConnection(const Endpoint &peer_endpoint) {
  assert(!mutex_.try_lock());
  return std::find_if(connections_.begin(),
                      connections_.end(),
                      [&peer_endpoint](const ConnectionPtr &connection) {
                          return connection->Socket().RemoteEndpoint() == peer_endpoint;
                        });
}


}  // namespace rudp

}  // namespace maidsafe
