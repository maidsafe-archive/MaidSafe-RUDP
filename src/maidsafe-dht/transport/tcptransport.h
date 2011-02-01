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

#ifndef MAIDSAFE_DHT_TRANSPORT_TCPTRANSPORT_H_
#define MAIDSAFE_DHT_TRANSPORT_TCPTRANSPORT_H_

#include <set>
#include <vector>
#include "boost/asio/io_service.hpp"
#include "boost/thread/thread.hpp"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/rawbuffer.h"
#include "maidsafe-dht/transport/tcpconnection.h"

namespace maidsafe {

namespace transport {

class TcpTransport : public Transport {
 public:
  TcpTransport(boost::shared_ptr<boost::asio::io_service> asio_service);
  ~TcpTransport();
  virtual TransportCondition StartListening(const Endpoint &endpoint);
  virtual void StopListening();
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout);
 private:
  TcpTransport(const TcpTransport&);
  TcpTransport& operator=(const TcpTransport&);
  friend class TcpConnection;
  typedef boost::shared_ptr<boost::asio::ip::tcp::acceptor> AcceptorPtr;
  typedef boost::shared_ptr<TcpConnection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;
  void HandleAccept(ConnectionPtr connection,
                    const boost::system::error_code &ec);

  void RemoveConnection(ConnectionPtr connection);

  AcceptorPtr acceptor_;

  // Because the connections can be in an idle initial state with no pending
  // async operations (after calling PrepareSend()), they are kept alive with
  // a shared_ptr in this map, as well as in the async operation handlers.
  ConnectionSet connections_;
  boost::mutex mutex_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_TCPTRANSPORT_H_
