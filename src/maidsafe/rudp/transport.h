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

#ifndef MAIDSAFE_RUDP_TRANSPORT_H_
#define MAIDSAFE_RUDP_TRANSPORT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/core/session.h"


namespace maidsafe {

namespace rudp {

namespace detail {

class ConnectionManager;
class Connection;
class Multiplexer;
class Socket;

#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
class Transport : public std::enable_shared_from_this<Transport> {
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

 public:
  typedef boost::signals2::signal<void(const std::string&)> OnMessage;

  typedef boost::signals2::signal<
      void(const NodeId&, std::shared_ptr<Transport>, bool, bool&)> OnConnectionAdded;

  typedef boost::signals2::signal<
      void(const NodeId&, std::shared_ptr<Transport>, bool, bool)> OnConnectionLost;

  Transport(AsioService& asio_service, NatType& nat_type_);  // NOLINT (Fraser)

  virtual ~Transport();

  void Bootstrap(
      const std::vector<std::pair<NodeId, boost::asio::ip::udp::endpoint>> &bootstrap_peers,
      const NodeId& this_node_id,
      std::shared_ptr<asymm::PublicKey> this_public_key,
      boost::asio::ip::udp::endpoint local_endpoint,
      bool bootstrap_off_existing_connection,
      const OnMessage::slot_type& on_message_slot,
      const OnConnectionAdded::slot_type& on_connection_added_slot,
      const OnConnectionLost::slot_type& on_connection_lost_slot,
      const Session::OnNatDetectionRequested::slot_function_type& on_nat_detection_requested_slot,
      NodeId& chosen_id);

  void Close();

  void Connect(const NodeId& peer_id,
               const EndpointPair& peer_endpoint_pair,
               const std::string& validation_data);

  // If this causes the size of connected_endpoints_ to drop to 0, this transport will remove
  // itself from ManagedConnections which will cause it to be destroyed.
  bool CloseConnection(const NodeId& peer_id);

  bool Send(const NodeId& peer_id,
            const std::string& message,
            const std::function<void(int)> &message_sent_functor);  // NOLINT (Fraser)

  void Ping(const NodeId& peer_id,
            const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::function<void(int)> &ping_functor);  // NOLINT (Fraser)

  std::shared_ptr<Connection> GetConnection(const NodeId& peer_id);

  boost::asio::ip::udp::endpoint external_endpoint() const;
  boost::asio::ip::udp::endpoint local_endpoint() const;
  boost::asio::ip::udp::endpoint ThisEndpointAsSeenByPeer(const NodeId& peer_id);
  void SetBestGuessExternalEndpoint(const boost::asio::ip::udp::endpoint& external_endpoint);

  bool MakeConnectionPermanent(const NodeId& peer_id,
                               bool validated,
                               boost::asio::ip::udp::endpoint& peer_endpoint);

  bool IsResilienceTransport() const { return is_resilience_transport_; }

  size_t NormalConnectionsCount() const;
  bool IsIdle() const;

  static int kMaxConnections() { return 50; }

  std::string DebugString() const;
  std::string ThisDebugId() const;
  void SetManagedConnectionsDebugPrintout(std::function<std::string()> functor);

  friend class Connection;

 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);

  typedef std::shared_ptr<Multiplexer> MultiplexerPtr;
  typedef std::shared_ptr<Connection> ConnectionPtr;

  NodeId ConnectToBootstrapEndpoint(const NodeId& bootstrap_node_id,
                                    const boost::asio::ip::udp::endpoint& bootstrap_endpoint,
                                    const boost::posix_time::time_duration& lifespan);

  void DoConnect(const NodeId& peer_id,
                 const EndpointPair& peer_endpoint_pair,
                 const std::string& validation_data);

  void StartDispatch();
  void HandleDispatch(const boost::system::error_code& ec);

  NodeId node_id() const;
  std::shared_ptr<asymm::PublicKey> public_key() const;

  void SignalMessageReceived(const std::string& message);
  void DoSignalMessageReceived(const std::string& message);
  void AddConnection(ConnectionPtr connection);
  void DoAddConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection, bool timed_out);
  void DoRemoveConnection(ConnectionPtr connection, bool timed_out);

  AsioService& asio_service_;
  NatType& nat_type_;
  boost::asio::io_service::strand strand_;
  MultiplexerPtr multiplexer_;
  std::unique_ptr<ConnectionManager> connection_manager_;
  OnMessage on_message_;
  OnConnectionAdded on_connection_added_;
  OnConnectionLost on_connection_lost_;
  Session::OnNatDetectionRequested::slot_function_type on_nat_detection_requested_slot_;
  // These signal connections are the ones made in the Bootstrap call; the slots will be in
  // ManagedConnections.
  boost::signals2::connection on_message_connection_;
  boost::signals2::connection on_connection_added_connection_;
  boost::signals2::connection on_connection_lost_connection_;
  bool is_resilience_transport_;
  std::function<std::string()> managed_connections_debug_printout_;
};

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TRANSPORT_H_
