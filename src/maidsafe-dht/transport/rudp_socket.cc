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

#include "maidsafe-dht/transport/rudp_socket.h"

#include <algorithm>
#include <utility>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/transport/rudp_handshake_packet.h"
#include "maidsafe-dht/transport/rudp_multiplexer.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

RudpSocket::RudpSocket(RudpMultiplexer &multiplexer)
  : id_(0),
    dispatcher_(multiplexer.dispatcher_),
    peer_(multiplexer),
    state_(kNotYetOpen),
    sender_(peer_),
    waiting_connect_(multiplexer.socket_.get_io_service()),
    waiting_connect_ec_(),
    waiting_write_(multiplexer.socket_.get_io_service()),
    waiting_write_ec_(),
    waiting_write_bytes_transferred_(0),
    waiting_read_(multiplexer.socket_.get_io_service()),
    waiting_read_transfer_at_least_(0),
    waiting_read_ec_(),
    waiting_read_bytes_transferred_(0) {
  waiting_connect_.expires_at(boost::posix_time::pos_infin);
  waiting_write_.expires_at(boost::posix_time::pos_infin);
  waiting_read_.expires_at(boost::posix_time::pos_infin);
}

RudpSocket::~RudpSocket() {
  if (IsOpen())
    dispatcher_.RemoveSocket(id_);
}

boost::uint32_t RudpSocket::Id() const {
  return id_;
}

boost::asio::ip::udp::endpoint RudpSocket::RemoteEndpoint() const {
  return peer_.Endpoint();
}

boost::uint32_t RudpSocket::RemoteId() const {
  return peer_.Id();
}

bool RudpSocket::IsOpen() const {
  return id_ != 0;
}

void RudpSocket::Close() {
  if (IsOpen())
    dispatcher_.RemoveSocket(id_);
  id_ = 0;
  peer_.SetEndpoint(ip::udp::endpoint());
  peer_.SetId(0);
  waiting_connect_ec_ = asio::error::operation_aborted;
  waiting_connect_.cancel();
  waiting_write_ec_ = asio::error::operation_aborted;
  waiting_write_bytes_transferred_ = 0;
  waiting_write_.cancel();
  waiting_read_ec_ = asio::error::operation_aborted;
  waiting_read_bytes_transferred_ = 0;
  waiting_read_.cancel();
}

void RudpSocket::StartConnect(const ip::udp::endpoint &remote) {
  id_ = dispatcher_.AddSocket(this);
  peer_.SetEndpoint(remote);
  peer_.SetId(0); // Assigned when handshake response is received.

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sender_.GetNextPacketSequenceNumber());
  packet.SetMaximumPacketSize(RudpDataPacket::kMaxSize);
  packet.SetMaximumFlowWindowSize(1); // Not used in this implementation.
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);

  peer_.Send(packet);
  state_ = kClientAwaitingHandshakeResponse;
}

void RudpSocket::StartConnect() {
  assert(IsOpen()); // Socket must already have been accepted.
  assert(peer_.Endpoint() != ip::udp::endpoint());
  assert(peer_.Id() != 0);

  RudpHandshakePacket packet;
  packet.SetRudpVersion(4);
  packet.SetSocketType(RudpHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(sender_.GetNextPacketSequenceNumber());
  packet.SetMaximumPacketSize(RudpDataPacket::kMaxSize);
  packet.SetMaximumFlowWindowSize(1); // Not used in this implementation.
  packet.SetSocketId(id_);
  packet.SetIpAddress(peer_.Endpoint().address());
  packet.SetDestinationSocketId(peer_.Id());
  packet.SetConnectionType(0xffffffff);
  packet.SetSynCookie(0); // TODO calculate cookie

  peer_.Send(packet);
  state_ = kServerAwaitingHandshakeResponse;
}

void RudpSocket::StartWrite(const asio::const_buffer &data) {
  // Check for a no-op write.
  if (asio::buffer_size(data) == 0) {
    waiting_write_ec_.clear();
    waiting_write_.cancel();
    return;
  }

  // Try processing the write immediately. If there's space in the write buffer
  // then the operation will complete immediately. Otherwise, it will wait until
  // some other event frees up space in the buffer.
  waiting_write_buffer_ = data;
  waiting_write_bytes_transferred_ = 0;
  ProcessWrite();
}

void RudpSocket::ProcessWrite() {
  // There's only a waiting write if the write buffer is non-empty.
  if (asio::buffer_size(waiting_write_buffer_) == 0)
    return;

  // If the write buffer is full then the write is going to have to wait.
  if (sender_.GetFreeSpace() == 0)
    return;

  // Copy whatever data we can into the write buffer.
  size_t length = sender_.AddData(waiting_write_buffer_);
  waiting_write_buffer_ = waiting_write_buffer_ + length;
  waiting_write_bytes_transferred_ += length;

  // If we have finished writing all of the data then it's time to trigger the
  // write's completion handler.
  if (asio::buffer_size(waiting_write_buffer_) == 0) {
    // The write is done. Trigger the write's completion handler.
    waiting_write_ec_.clear();
    waiting_write_.cancel();
  }
}

void RudpSocket::StartRead(const asio::mutable_buffer &data,
                          size_t transfer_at_least) {
  // Check for a no-read write.
  if (asio::buffer_size(data) == 0) {
    waiting_read_ec_.clear();
    waiting_read_.cancel();
    return;
  }

  // Try processing the read immediately. If there's available data then the
  // operation will complete immediately. Otherwise it will wait until the next
  // data packet arrives.
  waiting_read_buffer_ = data;
  waiting_read_transfer_at_least_ = transfer_at_least;
  waiting_read_bytes_transferred_ = 0;
  ProcessRead();
}

void RudpSocket::ProcessRead() {
  // There's only a waiting read if the read buffer is non-empty.
  if (asio::buffer_size(waiting_read_buffer_) == 0)
    return;

  // If the read buffer is empty then the read is going to have to wait.
  if (read_buffer_.empty())
    return;

  // Copy whatever data we can into the read buffer.
  size_t length = std::min(read_buffer_.size(),
                           asio::buffer_size(waiting_read_buffer_));
  unsigned char* data = asio::buffer_cast<unsigned char*>(waiting_read_buffer_);
  std::copy(read_buffer_.begin(), read_buffer_.begin() + length, data);
  read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + length);
  waiting_read_buffer_ = waiting_read_buffer_ + length;
  waiting_read_bytes_transferred_ += length;

  // If we have filled the buffer, or read more than the minimum number of
  // bytes required, then it's time to trigger the read's completion handler.
  if (asio::buffer_size(waiting_read_buffer_) == 0 ||
      waiting_read_bytes_transferred_ >= waiting_read_transfer_at_least_) {
    // the read is done. Trigger the read's completion handler.
    waiting_read_ec_.clear();
    waiting_read_.cancel();
  }
}

void RudpSocket::HandleReceiveFrom(const asio::const_buffer &data,
                                   const ip::udp::endpoint &endpoint) {
  RudpDataPacket data_packet;
  RudpAckPacket ack_packet;
  RudpHandshakePacket handshake_packet;
  if (data_packet.Decode(data)) {
    HandleData(data_packet);
  } else if (ack_packet.Decode(data)) {
    HandleAck(ack_packet);
  } else if (handshake_packet.Decode(data)) {
    HandleHandshake(handshake_packet);
  } else {
    DLOG(ERROR) << "Socket " << id_
                << " ignoring invalid packet from "
                << endpoint << std::endl;
  }
}

void RudpSocket::HandleHandshake(const RudpHandshakePacket &packet) {
  switch (state_) {
  case kClientAwaitingHandshakeResponse:
    peer_.SetId(packet.SocketId());
    state_ = kConnected;
    waiting_connect_ec_.clear();
    waiting_connect_.cancel();
    {
      RudpHandshakePacket response_packet(packet);
      response_packet.SetSocketId(id_);
      response_packet.SetIpAddress(peer_.Endpoint().address());
      response_packet.SetDestinationSocketId(peer_.Id());
      response_packet.SetConnectionType(0xffffffff);
      peer_.Send(response_packet);
    }
    break;
  case kServerAwaitingHandshakeResponse:
    state_ = kConnected;
    waiting_connect_ec_.clear();
    waiting_connect_.cancel();
    break;
  default:
    break;
  }
}

void RudpSocket::HandleData(const RudpDataPacket &packet) {
  if (state_ == kConnected) {
    if (read_buffer_.size() + packet.Data().size() < kMaxReadBufferSize) {
      read_buffer_.insert(read_buffer_.end(),
                          packet.Data().begin(),
                          packet.Data().end());
      ProcessRead();
    } else {
      // Packet is dropped because we have nowhere to store it.
    }
  }
}

void RudpSocket::HandleAck(const RudpAckPacket &packet) {
  if (state_ == kConnected) {
    sender_.HandleAck(packet);
  }
}

}  // namespace transport

}  // namespace maidsafe
