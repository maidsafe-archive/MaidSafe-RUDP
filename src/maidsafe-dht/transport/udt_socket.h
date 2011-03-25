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

#include <deque>

#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/udt_connect_op.h"
#include "maidsafe-dht/transport/udt_data_packet.h"
#include "maidsafe-dht/transport/udt_read_op.h"
#include "maidsafe-dht/transport/udt_write_op.h"

namespace maidsafe {

namespace transport {

class UdtAcceptor;
class UdtMultiplexer;

class UdtSocket {
 public:
  explicit UdtSocket(UdtMultiplexer &multiplexer);
  ~UdtSocket();

  // Get the unique identifier that has been assigned to the socket.
  boost::uint32_t Id() const;

  // Get the remote endpoint to which the socket is connected.
  boost::asio::ip::udp::endpoint RemoteEndpoint() const;

  // Get the remote socket identifier to which the socket is connected.
  boost::uint32_t RemoteId() const;

  // Returns whether the connection is open.
  bool IsOpen() const;

  // Close the socket and cancel pending asynchronous operations.
  void Close();

  // Initiate an asynchronous connect operation for the client side.
  template <typename ConnectHandler>
  void AsyncConnect(const boost::asio::ip::udp::endpoint &remote,
                    ConnectHandler handler) {
    UdtConnectOp<ConnectHandler> op(handler, &waiting_connect_ec_);
    waiting_connect_.async_wait(op);
    StartConnect(remote);
  }

  // Initiate an asynchronous connect operation for the server side. This
  // function performs UDT handshaking after a socket has been accepted to
  // complete the connection establishment.
  template <typename ConnectHandler>
  void AsyncConnect(ConnectHandler handler) {
    UdtConnectOp<ConnectHandler> op(handler, &waiting_connect_ec_);
    waiting_connect_.async_wait(op);
    StartConnect();
  }

  // Initiate an asynchronous operatio to write data. The operation will
  // generally complete immediately unless congestion has caused the internal
  // buffer for unprocessed send data to fill up.
  template <typename WriteHandler>
  void AsyncWrite(const boost::asio::const_buffer &data,
                  WriteHandler handler) {
    UdtWriteOp<WriteHandler> op(handler, &waiting_write_ec_,
                                &waiting_write_bytes_transferred_);
    waiting_write_.async_wait(op);
    StartWrite(data);
  }

  // Initiate an asynchronous operation to read data.
  template <typename ReadHandler>
  void AsyncRead(const boost::asio::mutable_buffer &data,
                 size_t transfer_at_least, ReadHandler handler) {
    UdtReadOp<ReadHandler> op(handler, &waiting_read_ec_,
                              &waiting_read_bytes_transferred_);
    waiting_read_.async_wait(op);
    StartRead(data, transfer_at_least);
  }

 private:
  friend class UdtAcceptor;
  friend class UdtDispatcher;

  // Disallow copying and assignment.
  UdtSocket(const UdtSocket&);
  UdtSocket &operator=(const UdtSocket&);

  void StartConnect(const boost::asio::ip::udp::endpoint &remote);
  void StartConnect();
  void StartWrite(const boost::asio::const_buffer &data);
  void ProcessWrite();
  void StartRead(const boost::asio::mutable_buffer &data,
                 size_t transfer_at_least);
  void ProcessRead();

  // Called by the UdtDispatcher when a new packet arrives for the socket.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

  // The multiplexer used to send and receive UDP packets.
  UdtMultiplexer &multiplexer_;

  // The unique socket identifier assigned by the dispatcher.
  boost::uint32_t id_;

  // The remote socket's endpoint and identifier.
  boost::asio::ip::udp::endpoint remote_endpoint_;
  boost::uint32_t remote_id_;

  // The sequence number to be used for the next outbound packet.
  boost::uint32_t next_packet_sequence_number_;

  // This class allows for a single asynchronous connect operation. The
  // following data members store the pending connect, and the result that is
  // intended for its completion handler.
  boost::asio::deadline_timer waiting_connect_;
  boost::system::error_code waiting_connect_ec_;

  // The buffer used to store application data that is waiting to be sent.
  // Asynchronous write operations will complete immediately as long as the
  // buffer size remains below the maximum.
  static const int kMaxWriteBufferSize = 65536;
  std::deque<unsigned char> write_buffer_;

  // This class allows only one outstanding asynchronous write operation at a
  // time. The following data members store the pending write, and the result
  // that is intended for its completion handler.
  boost::asio::deadline_timer waiting_write_;
  boost::asio::const_buffer waiting_write_buffer_;
  boost::system::error_code waiting_write_ec_;
  size_t waiting_write_bytes_transferred_;

  // This class allows only one outstanding asynchronous read operation at a
  // time. The following data members store the pending read, its associated
  // buffer, and the result that is intended for its completion handler.
  boost::asio::deadline_timer waiting_read_;
  boost::asio::mutable_buffer waiting_read_buffer_;
  size_t waiting_read_transfer_at_least_;
  boost::system::error_code waiting_read_ec_;
  size_t waiting_read_bytes_transferred_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_UDT_SOCKET_H_
