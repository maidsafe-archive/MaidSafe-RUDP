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

#ifndef MAIDSAFE_TRANSPORT_TCPTRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TCPTRANSPORT_H_

#include <maidsafe/transport/transport.h>
#include <maidsafe/transport/rawbuffer.h>
#include <maidsafe/transport/tcpconnection.h>
#include <boost/asio/io_service.hpp>
#include <boost/thread/thread.hpp>
#include <map>
#include <vector>

namespace transport {

class TcpTransport : public Transport {
 public:
  TcpTransport();
  ~TcpTransport();

  boost::asio::io_service &IOService();

  Port StartListening(const IP &ip,
                      const Port &try_port,
                      TransportCondition *condition);

  bool StopListening(const Port &port);
  bool StopAllListening();

  SocketId PrepareToSend(const IP &remote_ip,
                         const Port &remote_port,
                         const IP &rendezvous_ip,
                         const Port &rendezvous_port);

  void Send(const TransportMessage &transport_message,
            const SocketId &socket_id,
            const boost::uint32_t &timeout_wait_for_response);

  void SendFile(const boost::filesystem::path &path,
                const SocketId &socket_id);

 private:
  friend class TcpConnection;

  typedef boost::shared_ptr<boost::asio::ip::tcp::acceptor> AcceptorPtr;
  typedef std::vector<AcceptorPtr> AcceptorList;
  typedef boost::shared_ptr<TcpConnection> ConnectionPtr;
  typedef std::map<SocketId, ConnectionPtr> ConnectionMap;

  SocketId NextSocketId();
  void Run();
  void HandleAccept(const AcceptorPtr &acceptor,
                    const ConnectionPtr &connection,
                    const boost::system::error_code &ec);

  void RemoveConnection(SocketId id);

  boost::asio::io_service io_service_;
  boost::shared_ptr<boost::asio::io_service::work> keep_alive_;
  boost::thread worker_thread_;

  AcceptorList acceptors_;
  SocketId current_socket_id_;

  // Because the connections can be in an idle initial state with no pending
  // async operations (after calling PrepareSend()), they are kept alive with
  // a shared_ptr in this map, as well as in the async operation handlers.
  ConnectionMap connections_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TCPTRANSPORT_H_
