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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_SOCKET_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_SOCKET_H_

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
#include "maidsafe-dht/transport/rudp_ack_packet.h"
#include "maidsafe-dht/transport/rudp_connect_op.h"
#include "maidsafe-dht/transport/rudp_data_packet.h"
#include "maidsafe-dht/transport/rudp_handshake_packet.h"
#include "maidsafe-dht/transport/rudp_peer.h"
#include "maidsafe-dht/transport/rudp_read_op.h"
#include "maidsafe-dht/transport/rudp_sender.h"
#include "maidsafe-dht/transport/rudp_session.h"
#include "maidsafe-dht/transport/rudp_write_op.h"

namespace maidsafe {

namespace transport {

class RudpAcceptor;
class RudpDispatcher;

class RudpSocket {
 public:
  explicit RudpSocket(RudpMultiplexer &multiplexer);
  ~RudpSocket();

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
    RudpConnectOp<ConnectHandler> op(handler, &waiting_connect_ec_);
    waiting_connect_.async_wait(op);
    StartConnect(remote);
  }

  // Initiate an asynchronous connect operation for the server side. This
  // function performs RUDP handshaking after a socket has been accepted to
  // complete the connection establishment.
  template <typename ConnectHandler>
  void AsyncConnect(ConnectHandler handler) {
    RudpConnectOp<ConnectHandler> op(handler, &waiting_connect_ec_);
    waiting_connect_.async_wait(op);
    StartConnect();
  }

  // Initiate an asynchronous operatio to write data. The operation will
  // generally complete immediately unless congestion has caused the internal
  // buffer for unprocessed send data to fill up.
  template <typename WriteHandler>
  void AsyncWrite(const boost::asio::const_buffer &data,
                  WriteHandler handler) {
    RudpWriteOp<WriteHandler> op(handler, &waiting_write_ec_,
                                &waiting_write_bytes_transferred_);
    waiting_write_.async_wait(op);
    StartWrite(data);
  }

  // Initiate an asynchronous operation to read data.
  template <typename ReadHandler>
  void AsyncRead(const boost::asio::mutable_buffer &data,
                 size_t transfer_at_least, ReadHandler handler) {
    RudpReadOp<ReadHandler> op(handler, &waiting_read_ec_,
                              &waiting_read_bytes_transferred_);
    waiting_read_.async_wait(op);
    StartRead(data, transfer_at_least);
  }

 private:
  friend class RudpAcceptor;
  friend class RudpDispatcher;

  // Disallow copying and assignment.
  RudpSocket(const RudpSocket&);
  RudpSocket &operator=(const RudpSocket&);

  void StartConnect(const boost::asio::ip::udp::endpoint &remote);
  void StartConnect();
  void StartWrite(const boost::asio::const_buffer &data);
  void ProcessWrite();
  void StartRead(const boost::asio::mutable_buffer &data,
                 size_t transfer_at_least);
  void ProcessRead();

  // Called by the RudpDispatcher when a new packet arrives for the socket.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

  // Called to process a newly received handshake packet.
  void HandleHandshake(const RudpHandshakePacket &packet);

  // Called to process a newly received data packet.
  void HandleData(const RudpDataPacket &packet);

  // Called to process a newly received acknowledgement packet.
  void HandleAck(const RudpAckPacket &packet);

  // The dispatcher that holds this sockets registration.
  RudpDispatcher &dispatcher_;

  // The remote peer with which we are communicating.
  RudpPeer peer_;

  // The session state associated with the connection.
  RudpSession session_;

  // The send side of the connection.
  RudpSender sender_;

  // This class allows for a single asynchronous connect operation. The
  // following data members store the pending connect, and the result that is
  // intended for its completion handler.
  boost::asio::deadline_timer waiting_connect_;
  boost::system::error_code waiting_connect_ec_;

  // The buffer used to store application data that is waiting to be sent.
  // Asynchronous read operations will complete immediately as long as there is
  // sufficient data to complete the read.
  enum { kMaxReadBufferSize = 65536 };
  std::deque<unsigned char> read_buffer_;

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

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_SOCKET_H_
