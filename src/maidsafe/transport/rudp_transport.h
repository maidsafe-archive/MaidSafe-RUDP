/* Copyright (c) 2010 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_RUDP_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_RUDP_TRANSPORT_H_

#include <memory>
#include <set>
#include <string>
#include <vector>
#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/contact.h"
#include "maidsafe/transport/rudp_parameters.h"
#include "maidsafe/transport/message_handler.h"

#if MAIDSAFE_TRANSPORT_VERSION != 300
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif

namespace maidsafe {

namespace transport {

class RudpAcceptor;
class RudpConnection;
class RudpMultiplexer;
class RudpSocket;

typedef std::function<void(const TransportCondition&)> ConnectFunctor;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class RudpTransport : public Transport,
                      public std::enable_shared_from_this<RudpTransport> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
 public:
  explicit RudpTransport(boost::asio::io_service &asio_service);  // NOLINT
  virtual ~RudpTransport();

  virtual TransportCondition StartListening(const Endpoint &endpoint);
  virtual TransportCondition Bootstrap(const std::vector<Contact> &candidates);

  virtual void StopListening();
  // This timeout define the max allowed duration for the receiver to respond
  // a received request. If the receiver is to be expected respond slow
  // (say because of the large request msg to be processed), a long duration
  // shall be given for this timeout.
  // If no response to be expected, kImmediateTimeout shall be given.
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout);
  virtual void Send(const std::string &data,
                    const Contact &remote_contact,
                    const Timeout &timeout);
  void Connect(const Endpoint &endpoint, const Timeout &timeout,
               ConnectFunctor callback);
  static DataSize kMaxTransportMessageSize() { return 67108864; }

 private:
  // Disallow copying and assignment.
  RudpTransport(const RudpTransport&);
  RudpTransport &operator=(const RudpTransport&);

  typedef std::shared_ptr<RudpMultiplexer> MultiplexerPtr;
  typedef std::shared_ptr<RudpAcceptor> AcceptorPtr;
  typedef std::shared_ptr<RudpConnection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;

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
  void DoConnect(const Endpoint &endpoint, const Timeout &timeout,
                 ConnectFunctor callback);

  void ConnectCallback(const int &result,
                       const std::string &data,
                       const Endpoint &endpoint,
                       const Timeout &timeout);

  friend class RudpConnection;
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

typedef std::shared_ptr<RudpTransport> RudpTransportPtr;

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_TRANSPORT_H_
