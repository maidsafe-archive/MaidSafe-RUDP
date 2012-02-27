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

#ifndef MAIDSAFE_TRANSPORT_TCP_CONNECTION_H_
#define MAIDSAFE_TRANSPORT_TCP_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class TcpTransport;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

 public:
  TcpConnection(const std::shared_ptr<TcpTransport> &tcp_transport,
                const boost::asio::ip::tcp::endpoint &remote);
  ~TcpConnection();

  boost::asio::ip::tcp::socket &Socket();

  void Close();
  void StartReceiving();
  void StartSending(const std::string &data, const Timeout &timeout);

 private:
  TcpConnection(const TcpConnection&);
  TcpConnection &operator=(const TcpConnection&);

  void DoClose();
  void DoStartReceiving();
  void DoStartSending();

  void CheckTimeout(const boost::system::error_code &ec);

  void StartConnect();
  void HandleConnect(const boost::system::error_code &ec);

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code &ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code &ec, size_t length);

  void StartWrite();
  void HandleWrite(const boost::system::error_code &ec);

  void DispatchMessage();
  void EncodeData(const std::string &data);
  void CloseOnError(const TransportCondition &error);

  std::weak_ptr<TcpTransport> transport_;
  boost::asio::io_service::strand strand_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::deadline_timer timer_;
  boost::posix_time::ptime response_deadline_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  std::vector<unsigned char> size_buffer_, data_buffer_;
  size_t data_size_, data_received_;
  Timeout timeout_for_response_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_TCP_CONNECTION_H_
