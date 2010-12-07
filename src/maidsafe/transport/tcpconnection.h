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

#ifndef MAIDSAFE_TRANSPORT_TCPCONNECTION_H_
#define MAIDSAFE_TRANSPORT_TCPCONNECTION_H_

#include <maidsafe/transport/transport.h>
#include <maidsafe/transport/rawbuffer.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/enable_shared_from_this.hpp>

namespace transport {

class TcpTransport;

class TcpConnection : public boost::enable_shared_from_this<TcpConnection> {
 public:
  TcpConnection(TcpTransport *tcp_transport,
                const boost::asio::ip::tcp::endpoint &remote);
  ~TcpConnection();

  void SetSocketId(SocketId id);
  boost::asio::ip::tcp::socket &Socket();
  void StartReceiving();
  void Send(const TransportMessage &msg,
            boost::uint32_t timeout_wait_for_response);

  void Close();

 private:
  TcpConnection(const TcpConnection&);
  TcpConnection &operator=(const TcpConnection&);
  void StartTimeout(int seconds);

  void HandleTimeout(boost::system::error_code const& ec);
  void HandleSize(boost::system::error_code const& ec);
  void HandleRead(boost::system::error_code const& ec);
  void HandleConnect(boost::system::error_code const& ec);
  void HandleWrite(const boost::system::error_code &ec);

  void DispatchMessage(const TransportMessage &msg);

  TcpTransport *transport_;
  SocketId socket_id_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::deadline_timer timer_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  RawBuffer buffer_;
  boost::uint32_t timeout_for_response_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TCPCONNECTION_H_
