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

#ifndef MAIDSAFE_DHT_TRANSPORT_UDT_SOCKET_H_
#define MAIDSAFE_DHT_TRANSPORT_UDT_SOCKET_H_

#ifdef __MSVC__
#pragma warning(disable:4996)
#endif
#include <memory>
#ifdef __MSVC__
#pragma warning(default:4996)
#endif

#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "maidsafe-dht/transport/transport.h"

namespace maidsafe {

namespace transport {

class UdtMultiplexer;

class UdtSocket : public std::enable_shared_from_this<UdtSocket> {
 public:
  ~UdtSocket();

  // Initiate an asynchronous connect operation.
  template <typename ConnectHandler>
  void AsyncConnect(ConnectHandler handler) {
    waiting_op_.async_wait(ConnectOp<ConnectHandler>(handler, &waiting_op_ec_));
    StartConnect();
  }

  // Close the socket and cancel pending asynchronous operations.
  void Close();

  // Enqueue bytes to be sent. Returns without blocking.
  void Send(const boost::asio::const_buffer &data);

  // Initiate an asynchronous operation to receive data.
  template <typename ReadHandler>
  void AsyncReceive(const boost::asio::mutable_buffer &data,
                    ReadHandler handler) {
    waiting_op_.async_wait(ReadOp<ReadHandler>(handler, &waiting_op_ec_,
                                               &waiting_op_bytes_transferred_));
    StartReceive(data);
  }

 private:
  // Only the multiplexer can create socket instances.
  friend class UdtMultiplexer;
  UdtSocket(const std::shared_ptr<UdtMultiplexer> &udt_multiplexer,
            boost::asio::io_service &asio_service, const Endpoint& endpoint);

  // Disallow copying and assignment.
  UdtSocket(const UdtSocket&);
  UdtSocket &operator=(const UdtSocket&);

  void StartConnect();
  void StartReceive(const boost::asio::mutable_buffer &data);

  std::weak_ptr<UdtMultiplexer> multiplexer_;
  Endpoint remote_endpoint_;

  // The class allows only one outstanding asynchronous operation at a time.
  // The following data members store that pending operation and the result
  // that is intended for its completion handler.
  boost::asio::deadline_timer waiting_op_;
  boost::system::error_code waiting_op_ec_;
  size_t waiting_op_bytes_transferred_;

  // Helper class to adapt a connect handler into a waiting operation.
  template <typename ConnectHandler>
  class ConnectOp {
   public:
    ConnectOp(ConnectHandler handler,
              const boost::system::error_code *ec)
      : handler_(handler),
        ec_(ec) {
    }

    void operator()(boost::system::error_code) {
      handler_(*ec_);
    }

   private:
    ConnectHandler handler_;
    const boost::system::error_code *ec_;
  };

  // Helper class to adapt a read handler into a waiting operation.
  template <typename ReadHandler>
  class ReadOp {
   public:
    ReadOp(ReadHandler handler,
           const boost::system::error_code *ec,
           const size_t *bytes_transferred)
      : handler_(handler),
        ec_(ec),
        bytes_transferred_(bytes_transferred) {
    }

    void operator()(boost::system::error_code) {
      handler_(*ec_, *bytes_transferred_);
    }

   private:
    ReadHandler handler_;
    const boost::system::error_code *ec_;
    const size_t *bytes_transferred_;
  };
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_UDT_SOCKET_H_
