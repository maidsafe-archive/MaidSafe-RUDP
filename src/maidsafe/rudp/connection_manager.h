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

#ifndef MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
#define MAIDSAFE_RUDP_CONNECTION_MANAGER_H_

#include <functional>
#include <memory>
#include <set>
#include <string>

#include "boost/asio/buffer.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/thread/mutex.hpp"


namespace maidsafe {

namespace rudp {

class Transport;
class Connection;

namespace detail { class Multiplexer; }


class ConnectionManager {
 public:
  ConnectionManager(std::shared_ptr<Transport> transport,
                    const boost::asio::io_service::strand& strand,
                    std::shared_ptr<detail::Multiplexer> multiplexer);
  ~ConnectionManager();

  void Close();

  void Connect(const boost::asio::ip::udp::endpoint& peer_endpoint,
               const std::string& validation_data,
               const boost::posix_time::time_duration& lifespan);
  void InsertConnection(std::shared_ptr<Connection> connection);

  // Returns kSuccess if the connection existed and was closed.  Returns
  // kInvalidConnection if the connection didn't exist.
  int CloseConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);
  void RemoveConnection(std::shared_ptr<Connection> connection,
                        bool& connections_empty,
                        bool& temporary_connection);

  void Send(const boost::asio::ip::udp::endpoint& peer_endpoint,
            const std::string& message,
            const std::function<void(bool)> &message_sent_functor);  // NOLINT (Fraser)

  // Called by the Dispatcher when a new packet arrives for the socket.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &joining_peer_endpoint);

  bool IsTemporaryConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);
  void MakeConnectionPermanent(const boost::asio::ip::udp::endpoint& peer_endpoint,
                               const std::string& validation_data);

  size_t size() const;

 private:
  ConnectionManager(const ConnectionManager&);
  ConnectionManager& operator=(const ConnectionManager&);

  typedef std::shared_ptr<detail::Multiplexer> MultiplexerPtr;
  typedef std::shared_ptr<Connection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;

  ConnectionSet::iterator FindConnection(const boost::asio::ip::udp::endpoint& peer_endpoint);

  // Because the connections can be in an idle state with no pending async operations, they are kept
  // alive with a shared_ptr in this set, as well as in the async operation handlers.
  ConnectionSet connections_;
  mutable boost::mutex mutex_;
  std::weak_ptr<Transport> transport_;
  boost::asio::io_service::strand strand_;
  std::shared_ptr<detail::Multiplexer> multiplexer_;
};

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CONNECTION_MANAGER_H_
