/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_CORE_SOCKET_H_
#define MAIDSAFE_RUDP_CORE_SOCKET_H_

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>

#include "boost/asio/buffer.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/rudp/core/congestion_control.h"
#include "maidsafe/rudp/core/peer.h"
#include "maidsafe/rudp/core/receiver.h"
#include "maidsafe/rudp/core/sender.h"
#include "maidsafe/rudp/core/session.h"
#include "maidsafe/rudp/core/tick_timer.h"

#include "maidsafe/rudp/operations/connect_op.h"
#include "maidsafe/rudp/operations/flush_op.h"
#include "maidsafe/rudp/operations/probe_op.h"
#include "maidsafe/rudp/operations/read_op.h"
#include "maidsafe/rudp/operations/tick_op.h"
#include "maidsafe/rudp/operations/write_op.h"

#include "maidsafe/rudp/nat_type.h"
#include "maidsafe/rudp/parameters.h"

namespace maidsafe {

namespace rudp {

namespace detail {

class AckPacket;
class AckOfAckPacket;
class DataPacket;
class Dispatcher;
class HandshakePacket;
class KeepalivePacket;
class NegativeAckPacket;

class Socket {
 public:
  Socket(Multiplexer& multiplexer, NatType& nat_type);  // NOLINT (Fraser)
  ~Socket();

  // Get the unique identifier that has been assigned to the socket.
  uint32_t Id() const;

  // Get the remote endpoint to which the socket is connected.
  boost::asio::ip::udp::endpoint PeerEndpoint() const;

  // Get the remote socket identifier to which the socket is connected.
  uint32_t PeerSocketId() const;

  // Get the remote socket identifier to which the socket is connected.
  NodeId PeerNodeId() const;

  // Returns whether the connection is open.
  bool IsOpen() const;

  // Returns whether the connection has been established (i.e. handshaking successfully completed).
  bool IsConnected() const;

  // This should only be called by the ConnectionManager if this node discovers that the peer has a
  // different endpoint than it predicted (i.e. the peer is behind symmetric NAT).
  void UpdatePeerEndpoint(const boost::asio::ip::udp::endpoint& remote);

  // If the peer endpoint was updated using UpdatePeerEndpoint, this returns the port originally
  // provided by the peer as its best guess.  Otherwise 0 is returned.
  uint16_t PeerGuessedPort() const;

  // Get the remote endpoint offered for NAT detection.
  boost::asio::ip::udp::endpoint RemoteNatDetectionEndpoint() const;

  // Notify the peer that the socket is about to close.
  void NotifyClose();

  // Close the socket and cancel pending asynchronous operations.
  void Close();

  // Return the best read-buffer size calculated by congestion_control
  int32_t BestReadBufferSize() const;

  // Calculate if the transmission speed is too slow
  bool IsSlowTransmission(size_t length) { return congestion_control_.IsSlowTransmission(length); }

  // Asynchronously process one "tick". The internal tick size varies based on
  // the next time-based event that is of interest to the socket.
  template <typename TickHandler>
  void AsyncTick(TickHandler handler) {
    TickOp<TickHandler, Socket> op(handler, *this, tick_timer_);
    tick_timer_.AsyncWait(op);
  }

  // Initiate an asynchronous rendezvous connect operation. Note that the socket
  // will continue to make connection attempts indefinitely. It is up to the
  // caller to set a timeout and close the socket after the timeout period
  // expires.
  template <typename ConnectHandler>
  uint32_t AsyncConnect(const NodeId& this_node_id,
                    std::shared_ptr<asymm::PublicKey> this_public_key,
                    const boost::asio::ip::udp::endpoint& remote, const NodeId& peer_node_id,
                    ConnectHandler handler, Session::Mode open_mode, uint32_t cookie_syn,
                    Session::OnNatDetectionRequested::slot_type on_nat_detection_requested_slot) {
    ConnectOp<ConnectHandler> op(handler, waiting_connect_ec_);
    waiting_connect_.async_wait(op);
    return StartConnect(this_node_id, this_public_key, remote, peer_node_id, open_mode, cookie_syn,
                        on_nat_detection_requested_slot);
  }

  // Initiate an asynchronous operation to write data. The operation will
  // generally complete immediately unless congestion has caused the internal
  // buffer for unprocessed send data to fill up. when the operation completes, the handler is
  // invoked, but the message_sent_functor is not invoked until the last packet of the message has
  // been acknowledged by the peer.
  template <typename WriteHandler>
  void AsyncWrite(const boost::asio::const_buffer& data,
                  const std::function<void(int)>& message_sent_functor,  // NOLINT (Fraser)
                  WriteHandler handler) {
    WriteOp<WriteHandler> op(handler, waiting_write_ec_, waiting_write_bytes_transferred_);
    waiting_write_.async_wait(op);
    StartWrite(data, message_sent_functor);
  }

  // Initiate an asynchronous operation to read data.
  template <typename ReadHandler>
  void AsyncRead(const boost::asio::mutable_buffer& data, size_t transfer_at_least,
                 ReadHandler handler) {
    ReadOp<ReadHandler> op(handler, waiting_read_ec_, waiting_read_bytes_transferred_);
    waiting_read_.async_wait(op);
    StartRead(data, transfer_at_least);
  }

  // Initiate an asynchronous operation to flush all outbound data.
  template <typename FlushHandler>
  void AsyncFlush(FlushHandler handler) {
    FlushOp<FlushHandler> op(handler, waiting_flush_ec_);
    waiting_flush_.async_wait(op);
    StartFlush();
  }

  // Initiate an asynchronous probe to send keepalive packet to the peer & the
  // handler is called upon receiving valid keepalive response.
  template <typename ProbeHandler>
  void AsyncProbe(ProbeHandler handler) {
    ProbeOp<ProbeHandler> op(handler, waiting_probe_ec_);
    waiting_probe_.expires_from_now(Parameters::keepalive_timeout);
    waiting_probe_.async_wait(op);
    StartProbe();
  }

  bool IsPermanent() const { return session_.mode() == Session::kNormal; }

  // Changes mode of session to kNormal
  void MakeNormal();

  // This node's endpoint as viewed by peer
  boost::asio::ip::udp::endpoint ThisEndpoint() const;

  // Public key of remote peer, used to encrypt all outgoing messages on this socket
  std::shared_ptr<asymm::PublicKey> PeerPublicKey() const;

  friend class Dispatcher;

 private:
  // Disallow copying and assignment.
  Socket(const Socket&);
  Socket& operator=(const Socket&);

  uint32_t StartConnect(
      const NodeId& this_node_id, std::shared_ptr<asymm::PublicKey> this_public_key,
      const boost::asio::ip::udp::endpoint& remote, const NodeId& peer_node_id,
      Session::Mode open_mode, uint32_t cookie_syn,
      const Session::OnNatDetectionRequested::slot_type& on_nat_detection_requested_slot);
  void StartWrite(const boost::asio::const_buffer& data,
                  const std::function<void(int)>& message_sent_functor);  // NOLINT (Fraser)
  void ProcessWrite();
  void StartRead(const boost::asio::mutable_buffer& data, size_t transfer_at_least);
  void ProcessRead();
  void StartFlush();
  void ProcessFlush();

  void StartProbe();

  // Called by the Dispatcher when a new packet arrives for the socket.
  void HandleReceiveFrom(const boost::asio::const_buffer& data,
                         const boost::asio::ip::udp::endpoint& endpoint);

  // Called to process a newly received handshake packet.
  void HandleHandshake(const HandshakePacket& packet);

  // Called to process a newly received data packet.
  void HandleData(const DataPacket& packet);

  // Called to process a newly received acknowledgement packet.
  void HandleAck(const AckPacket& packet);

  // Called to process a newly received acknowledgement of an acknowledgement.
  void HandleAckOfAck(const AckOfAckPacket& packet);

  // Called to process a newly received negative acknowledgement packet.
  void HandleNegativeAck(const NegativeAckPacket& packet);

  // Called to process a newly received Keepalive packet.
  void HandleKeepalive(const KeepalivePacket& packet);

  // Called to handle a tick event.
  void HandleTick();
  friend void DispatchTick(Socket& socket) { socket.HandleTick(); }

  // The dispatcher that holds this sockets registration.
  Dispatcher& dispatcher_;

  // The remote peer with which we are communicating.
  Peer peer_;

  // This class requires a single outstanding tick operation at all times. The
  // following timer stores the pending tick operation, with the timer set to
  // expire at the time of the next interesting time-based event.
  TickTimer tick_timer_;

  // The session state associated with the connection.
  Session session_;

  // The congestion control information associated with the connection.
  CongestionControl congestion_control_;

  // The send side of the connection.
  Sender sender_;

  // The receive side of the connection.
  Receiver receiver_;

  // This class allows for a single asynchronous connect operation. The
  // following data members store the pending connect, and the result that is
  // intended for its completion handler.
  boost::asio::deadline_timer waiting_connect_;
  boost::system::error_code waiting_connect_ec_;

  // This class allows only one outstanding asynchronous write operation at a
  // time. The following data members store the pending write, and the result
  // that is intended for its completion handler.
  boost::asio::deadline_timer waiting_write_;
  boost::asio::const_buffer waiting_write_buffer_;
  boost::system::error_code waiting_write_ec_;
  size_t waiting_write_bytes_transferred_;
  uint32_t waiting_write_message_number_;
  std::map<uint32_t, std::function<void(int)>> message_sent_functors_;  // NOLINT (Fraser)

  // This class allows only one outstanding asynchronous read operation at a
  // time. The following data members store the pending read, its associated
  // buffer, and the result that is intended for its completion handler.
  boost::asio::deadline_timer waiting_read_;
  boost::asio::mutable_buffer waiting_read_buffer_;
  size_t waiting_read_transfer_at_least_;
  boost::system::error_code waiting_read_ec_;
  size_t waiting_read_bytes_transferred_;

  uint32_t waiting_keepalive_sequence_number_;
  boost::asio::deadline_timer waiting_probe_;
  boost::system::error_code waiting_probe_ec_;

  // This class allows only one outstanding flush operation at a time. The
  // following data members store the pending flush, and the result that is
  // intended for its completion handler.
  boost::asio::deadline_timer waiting_flush_;
  boost::system::error_code waiting_flush_ec_;
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_CORE_SOCKET_H_
