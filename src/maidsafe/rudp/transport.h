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
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/rudp/parameters.h"
#include "maidsafe/rudp/core/message_handler.h"


namespace maidsafe {

namespace rudp {

class Acceptor;
class Connection;
class Multiplexer;
class Socket;

typedef std::function<void(const ReturnCode&)> ConnectFunctor;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class Transport : public std::enable_shared_from_this<Transport> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

 public:
  explicit Transport(boost::asio::io_service &asio_service);  // NOLINT
  virtual ~Transport();

//  virtual ReturnCode StartListening(const Endpoint &endpoint);
//  virtual ReturnCode Bootstrap(const std::vector<Contact> &candidates);
//
//  virtual void StopListening();
//  // This timeout defines the max allowed duration for the receiver to respond
//  // to a request. If the receiver is expected to respond slowly (e.g. because
//  // of a large request msg to be processed), a long duration shall be given for
//  // this timeout. If no response is expected, kImmediateTimeout shall be given.
//  virtual void Send(const std::string &data,
//                    const Endpoint &endpoint,
//                    const Timeout &timeout);
//  static DataSize kMaxTransportMessageSize() { return 67108864; }


  void RendezvousConnect(const Endpoint &peer_endpoint,
                         const std::string &validation_data);
  // Returns kSuccess if the connection existed and was closed.  Returns
  // kInvalidConnection if the connection didn't exist.  If this causes the
  // size of connected_endpoints_ to dop to 0, this transport will remove
  // itself from ManagedConnections which will cause it to be destroyed.
  int CloseConnection(const Endpoint &peer_endpoint);
  int Send(const Endpoint &peer_endpoint, const std::string &message) const;
  Endpoint this_endpoint() const;
  Endpoint Bootstrap(const std::vector<Endpoint> &bootstrap_endpoints);
  std::vector<Endpoint> connected_endpoints() const;
  size_t connected_endpoints_size() const;
  static uint32_t kMaxConnections() { return 50; }

 private:
  Transport(const Transport&);
  Transport &operator=(const Transport&);

  typedef std::shared_ptr<Multiplexer> MultiplexerPtr;
  typedef std::shared_ptr<Acceptor> AcceptorPtr;
  typedef std::shared_ptr<Connection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;

  void StartRendezvousConnect(const Endpoint &peer_endpoint,
                              const std::string &validation_data,
                              const Timeout &timeout);

  static void CloseAcceptor(AcceptorPtr acceptor);
  static void CloseMultiplexer(MultiplexerPtr multiplexer);

  void StartDispatch();
  void HandleDispatch(MultiplexerPtr multiplexer,
                      const boost::system::error_code &ec);

  void StartAccept();
  void HandleAccept(AcceptorPtr acceptor,
                    ConnectionPtr connection,
                    const boost::system::error_code &ec);

  void DoSend(const std::string &data,
              const Endpoint &endpoint,
              const Timeout &timeout);
  void DoConnect(const Endpoint &endpoint,
                 const Timeout &timeout,
                 ConnectFunctor callback);
  friend class Connection;
  void InsertConnection(ConnectionPtr connection);
  void DoInsertConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection);
  void DoRemoveConnection(ConnectionPtr connection);

  boost::asio::io_service::strand strand_;
  MultiplexerPtr multiplexer_;
  AcceptorPtr acceptor_;

  // Because the connections can be in an idle initial state with no pending
  // async operations (after calling PrepareSend()), they are kept alive with
  // a shared_ptr in this map, as well as in the async operation handlers.
  ConnectionSet connections_;
};

typedef std::shared_ptr<Transport> TransportPtr;

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_TRANSPORT_H_
