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

#include "maidsafe/rudp/core/socket.h"

#include <algorithm>
#include <utility>
#include <limits>
#include <vector>

#include "boost/assert.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/rudp/core/multiplexer.h"
#include "maidsafe/rudp/packets/ack_of_ack_packet.h"
#include "maidsafe/rudp/packets/ack_packet.h"
#include "maidsafe/rudp/packets/data_packet.h"
#include "maidsafe/rudp/packets/handshake_packet.h"
#include "maidsafe/rudp/packets/keepalive_packet.h"
#include "maidsafe/rudp/packets/negative_ack_packet.h"
#include "maidsafe/rudp/packets/shutdown_packet.h"

namespace ip = boost::asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace rudp {

namespace detail {

Socket::Socket(Multiplexer& multiplexer, NatType& nat_type)  // NOLINT (Fraser)
    : dispatcher_(multiplexer.dispatcher_),
      peer_(multiplexer),
      tick_timer_(multiplexer.socket_.get_io_service()),
      session_(peer_, tick_timer_, multiplexer.external_endpoint_, multiplexer.mutex_,
               multiplexer.local_endpoint(), nat_type),
      congestion_control_(),
      sender_(peer_, tick_timer_, congestion_control_),
      receiver_(peer_, tick_timer_, congestion_control_),
      waiting_connect_(multiplexer.socket_.get_io_service()),
      waiting_connect_ec_(),
      waiting_write_(multiplexer.socket_.get_io_service()),
      waiting_write_buffer_(),
      waiting_write_ec_(),
      waiting_write_bytes_transferred_(0),
      waiting_write_message_number_(0),
      message_sent_functors_(),
      waiting_read_(multiplexer.socket_.get_io_service()),
      waiting_read_buffer_(),
      waiting_read_transfer_at_least_(0),
      waiting_read_ec_(),
      waiting_read_bytes_transferred_(0),
      // Request packet sequence numbers must be odd
      waiting_keepalive_sequence_number_(RandomUint32() | 0x00000001),
      waiting_probe_(multiplexer.socket_.get_io_service()),
      waiting_probe_ec_(),
      waiting_flush_(multiplexer.socket_.get_io_service()),
      waiting_flush_ec_() {
  waiting_connect_.expires_at(bptime::pos_infin);
  waiting_write_.expires_at(bptime::pos_infin);
  waiting_read_.expires_at(bptime::pos_infin);
  waiting_flush_.expires_at(bptime::pos_infin);
}

Socket::~Socket() {
  if (IsOpen())
    dispatcher_.RemoveSocket(session_.Id());
  for (auto message_sent_functor : message_sent_functors_)
    message_sent_functor.second(kConnectionClosed);
}

uint32_t Socket::Id() const { return session_.Id(); }

int32_t Socket::BestReadBufferSize() const { return congestion_control_.BestReadBufferSize(); }

ip::udp::endpoint Socket::PeerEndpoint() const { return peer_.PeerEndpoint(); }

uint32_t Socket::PeerSocketId() const { return peer_.SocketId(); }

NodeId Socket::PeerNodeId() const { return peer_.node_id(); }

bool Socket::IsOpen() const { return session_.IsOpen(); }

bool Socket::IsConnected() const { return session_.IsConnected(); }

void Socket::UpdatePeerEndpoint(const ip::udp::endpoint& remote) {
  peer_.SetPeerGuessedPort();
  peer_.SetPeerEndpoint(remote);
}

uint16_t Socket::PeerGuessedPort() const { return peer_.PeerGuessedPort(); }

ip::udp::endpoint Socket::RemoteNatDetectionEndpoint() const {
  return session_.RemoteNatDetectionEndpoint();
}

void Socket::NotifyClose() {
  if (session_.IsOpen())
    sender_.NotifyClose();
}

void Socket::Close() {
  waiting_connect_ec_ =
      session_.IsConnected() ? boost::system::error_code() : boost::asio::error::operation_aborted;
  if (session_.IsOpen()) {
    sender_.NotifyClose();
    congestion_control_.OnClose();
    dispatcher_.RemoveSocket(session_.Id());
  }
  session_.Close();
  peer_.SetSocketId(0);
  tick_timer_.Cancel();
  waiting_connect_.cancel();
  waiting_write_ec_ = boost::asio::error::operation_aborted;
  waiting_write_bytes_transferred_ = 0;
  waiting_write_.cancel();
  waiting_read_ec_ = boost::asio::error::operation_aborted;
  waiting_read_bytes_transferred_ = 0;
  waiting_read_.cancel();
  waiting_flush_ec_ = boost::asio::error::operation_aborted;
  waiting_flush_.cancel();
  waiting_probe_ec_ = boost::asio::error::shut_down;
  waiting_probe_.cancel();
}

uint32_t Socket::StartConnect(
    const NodeId& this_node_id,
    std::shared_ptr<asymm::PublicKey> this_public_key,
    const ip::udp::endpoint& remote,
    const NodeId& peer_node_id,
    Session::Mode open_mode,
    uint32_t cookie_syn,
    const Session::OnNatDetectionRequested::slot_type& on_nat_detection_requested) {
  peer_.SetPeerEndpoint(remote);
  peer_.set_node_id(peer_node_id);
  peer_.SetSocketId(0);  // Assigned when handshake response is received.
  return session_.Open(dispatcher_.AddSocket(this), this_node_id, this_public_key,
                       sender_.GetNextPacketSequenceNumber(), open_mode, cookie_syn,
                       on_nat_detection_requested);
}

void Socket::StartProbe() {
  waiting_probe_ec_ = boost::asio::error::operation_aborted;
  if (!session_.IsConnected()) {
    waiting_probe_ec_ = boost::asio::error::not_connected;
    waiting_probe_.cancel();
    waiting_keepalive_sequence_number_ = 0;
    return;
  }
  KeepalivePacket keepalive_packet;
  keepalive_packet.SetDestinationSocketId(peer_.SocketId());
  keepalive_packet.SetSequenceNumber(waiting_keepalive_sequence_number_);
  if (kSuccess != sender_.SendKeepalive(keepalive_packet)) {
    waiting_probe_ec_ = boost::asio::error::try_again;
    waiting_probe_.cancel();
  }
}

void Socket::StartWrite(const boost::asio::const_buffer& data,
                        const std::function<void(int)>& message_sent_functor) {  // NOLINT (Fraser)
  // Check for a no-op write.
  if (boost::asio::buffer_size(data) == 0) {
    waiting_write_ec_.clear();
    waiting_write_.cancel();
    return;
  }

  // Try processing the write immediately. If there's space in the write buffer then the operation
  // will complete immediately. Otherwise, it will wait until some other event frees up space in the
  // buffer.
  waiting_write_buffer_ = data;
  waiting_write_bytes_transferred_ = 0;
  ++waiting_write_message_number_;
  message_sent_functors_[waiting_write_message_number_] = message_sent_functor;
  ProcessWrite();
}

void Socket::ProcessWrite() {
  // There's only a waiting write if the write buffer is non-empty.
  if (boost::asio::buffer_size(waiting_write_buffer_) == 0)
    return;

  // Copy whatever data we can into the write buffer.
  size_t length(sender_.AddData(waiting_write_buffer_, waiting_write_message_number_));
  waiting_write_buffer_ = waiting_write_buffer_ + length;
  waiting_write_bytes_transferred_ += length;
  // If we have finished writing all of the data then it's time to trigger the write's completion
  // handler.
  if (boost::asio::buffer_size(waiting_write_buffer_) == 0) {
    // The write is done. Trigger the write's completion handler.
    waiting_write_ec_.clear();
    waiting_write_.cancel();
  }
}

void Socket::StartRead(const boost::asio::mutable_buffer& data, size_t transfer_at_least) {
  // Check for a no-read write.
  if (boost::asio::buffer_size(data) == 0) {
    waiting_read_ec_.clear();
    waiting_read_.cancel();
    return;
  }

  // Try processing the read immediately. If there's available data then the operation will complete
  // immediately. Otherwise it will wait until the next data packet arrives.
  waiting_read_buffer_ = data;
  waiting_read_transfer_at_least_ = transfer_at_least;
  waiting_read_bytes_transferred_ = 0;
  ProcessRead();
}

void Socket::ProcessRead() {
  // There's only a waiting read if the read buffer is non-empty.
  if (boost::asio::buffer_size(waiting_read_buffer_) == 0)
    return;

  // Copy whatever data we can into the read buffer.
  size_t length = receiver_.ReadData(waiting_read_buffer_);
  waiting_read_buffer_ = waiting_read_buffer_ + length;
  waiting_read_bytes_transferred_ += length;

  // If we have filled the buffer, or read more than the minimum number of bytes required, then it's
  // time to trigger the read's completion handler.
  if (boost::asio::buffer_size(waiting_read_buffer_) == 0 ||
      waiting_read_bytes_transferred_ >= waiting_read_transfer_at_least_) {
    // the read is done. Trigger the read's completion handler.
    waiting_read_ec_.clear();
    waiting_read_.cancel();
  }
}

void Socket::StartFlush() { ProcessFlush(); }

void Socket::ProcessFlush() {
  if (sender_.Flushed() && receiver_.Flushed()) {
    waiting_flush_ec_.clear();
    waiting_flush_.cancel();
  }
}

void Socket::HandleReceiveFrom(const boost::asio::const_buffer& data,
                               const ip::udp::endpoint& endpoint) {
  if (endpoint == peer_.PeerEndpoint()) {
    // TODO(Team): Surely this can be templetised somehow to avoid all the obejct creation
    DataPacket data_packet;
    AckPacket ack_packet;
    AckOfAckPacket ack_of_ack_packet;
    NegativeAckPacket negative_ack_packet;
    HandshakePacket handshake_packet;
    ShutdownPacket shutdown_packet;
    KeepalivePacket keepalive_packet;
    if (data_packet.Decode(data)) {
      // LOG(kVerbose) << "Received DataPacket " << data_packet.PacketSequenceNumber() << ":"
      //               << data_packet.MessageNumber();
      HandleData(data_packet);
    } else if (ack_packet.Decode(data)) {
      // LOG(kVerbose) << "Received AckPacket";
      HandleAck(ack_packet);
    } else if (ack_of_ack_packet.Decode(data)) {
      // LOG(kVerbose) << "Received AckOfAckPacket";
      HandleAckOfAck(ack_of_ack_packet);
    } else if (negative_ack_packet.Decode(data)) {
      // LOG(kVerbose) << "Received NegativeAckPacket";
      HandleNegativeAck(negative_ack_packet);
    } else if (keepalive_packet.Decode(data)) {
      // LOG(kVerbose) << "Received KeepalivePacket";
      HandleKeepalive(keepalive_packet);
    } else if (handshake_packet.Decode(data)) {
      // LOG(kVerbose) << "Received HandshakePacket InitialPacketSequenceNumber="
      //               << handshake_packet.InitialPacketSequenceNumber();
      HandleHandshake(handshake_packet);
    } else if (shutdown_packet.Decode(data)) {
      // LOG(kVerbose) << "Received ShutdownPacket";
      Close();
    } else {
      LOG(kWarning) << "Socket " << session_.Id() << " ignoring invalid packet from " << endpoint;
    }
  } else {
    LOG(kWarning) << "Socket " << session_.Id() << " ignoring spurious packet from " << endpoint;
  }
}

void Socket::HandleHandshake(const HandshakePacket& packet) {
  bool was_connected = session_.IsConnected();
  session_.HandleHandshake(packet);

  if (!session_.IsOpen()) {
    sender_.NotifyClose();
    dispatcher_.RemoveSocket(session_.Id());
    return Close();
  }

  if (!was_connected && session_.IsConnected()) {
    if (session_.mode() == Session::kBootstrapAndDrop) {
      Close();
    } else {
      congestion_control_.OnOpen(sender_.GetNextPacketSequenceNumber(),
                                 session_.ReceivingSequenceNumber());
      congestion_control_.SetPeerConnectionType(session_.PeerConnectionType());
      receiver_.Reset(session_.ReceivingSequenceNumber());
      waiting_connect_ec_.clear();
      waiting_connect_.cancel();
    }
  }
}

void Socket::HandleKeepalive(const KeepalivePacket& packet) {
  if (session_.IsConnected()) {
    if (packet.IsResponse()) {
      if (waiting_keepalive_sequence_number_ &&
          packet.IsResponseOf(waiting_keepalive_sequence_number_)) {
        waiting_probe_ec_.clear();
        waiting_probe_.cancel();
        waiting_keepalive_sequence_number_ += 2;
        if (waiting_keepalive_sequence_number_ + 1 == 0)
          waiting_keepalive_sequence_number_ = 1;
        return;
      } else {
        LOG(kWarning) << "Socket " << session_.Id() << " ignoring unexpected keepalive response "
                      << packet.SequenceNumber() << " from " << peer_.PeerEndpoint()
                      << ".  Current sequence number: " << waiting_keepalive_sequence_number_;
      }
    } else {
      sender_.HandleKeepalive(packet);
    }
  }
}

void Socket::HandleData(const DataPacket& packet) {
  if (session_.IsConnected()) {
    receiver_.HandleData(packet);
    ProcessRead();
    ProcessWrite();
  }
}

void Socket::HandleAck(const AckPacket& packet) {
  if (session_.IsConnected()) {
    std::vector<uint32_t> completed_message_numbers;
    sender_.HandleAck(packet, completed_message_numbers);
    for (auto num : completed_message_numbers) {
      auto itr(message_sent_functors_.find(num));
      if (itr == message_sent_functors_.end()) {
        LOG(kError) << "Lost sent functor for message " << num;
      } else {
        (*itr).second(kSuccess);
        message_sent_functors_.erase(itr);
      }
    }
    ProcessRead();
    ProcessWrite();
    ProcessFlush();
  }
}

void Socket::HandleAckOfAck(const AckOfAckPacket& packet) {
  if (session_.IsConnected()) {
    receiver_.HandleAckOfAck(packet);
    ProcessRead();
    ProcessWrite();
    ProcessFlush();
  }
}

void Socket::HandleNegativeAck(const NegativeAckPacket& packet) {
  if (session_.IsConnected()) {
    sender_.HandleNegativeAck(packet);
  }
}

void Socket::HandleTick() {
  session_.HandleTick();
  if (session_.IsConnected()) {
    sender_.HandleTick();
    receiver_.HandleTick();
    ProcessRead();
    ProcessWrite();
    ProcessFlush();
  }
}

void Socket::MakeNormal() { session_.MakeNormal(); }

ip::udp::endpoint Socket::ThisEndpoint() const { return peer_.ThisEndpoint(); }

std::shared_ptr<asymm::PublicKey> Socket::PeerPublicKey() const { return peer_.public_key(); }

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
