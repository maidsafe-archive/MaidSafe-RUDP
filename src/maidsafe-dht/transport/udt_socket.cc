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

#include "maidsafe-dht/transport/udt_socket.h"

#include <algorithm>
#include <utility>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/transport/udt_handshake_packet.h"
#include "maidsafe-dht/transport/udt_multiplexer.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

UdtSocket::UdtSocket(UdtMultiplexer &multiplexer)
  : multiplexer_(multiplexer),
    id_(0),
    remote_endpoint_(),
    remote_id_(0),
    state_(kNotYetOpen),
    next_packet_sequence_number_(SRandomUint32() & 0x7fffffff),
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

UdtSocket::~UdtSocket() {
  if (IsOpen())
    multiplexer_.dispatcher_.RemoveSocket(id_);
}

boost::uint32_t UdtSocket::Id() const {
  return id_;
}

boost::asio::ip::udp::endpoint UdtSocket::RemoteEndpoint() const {
  return remote_endpoint_;
}

boost::uint32_t UdtSocket::RemoteId() const {
  return remote_id_;
}

bool UdtSocket::IsOpen() const {
  return id_ != 0;
}

void UdtSocket::Close() {
  if (IsOpen())
    multiplexer_.dispatcher_.RemoveSocket(id_);
  id_ = 0;
  remote_endpoint_ = ip::udp::endpoint();
  remote_id_ = 0;
  waiting_connect_ec_ = asio::error::operation_aborted;
  waiting_connect_.cancel();
  waiting_write_ec_ = asio::error::operation_aborted;
  waiting_write_bytes_transferred_ = 0;
  waiting_write_.cancel();
  waiting_read_ec_ = asio::error::operation_aborted;
  waiting_read_bytes_transferred_ = 0;
  waiting_read_.cancel();
}

void UdtSocket::StartConnect(const ip::udp::endpoint &remote) {
  id_ = multiplexer_.dispatcher_.AddSocket(this);
  remote_endpoint_ = remote;
  remote_id_ = 0; // Assigned when handshake response is received.

  UdtHandshakePacket packet;
  packet.SetUdtVersion(4);
  packet.SetSocketType(UdtHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(next_packet_sequence_number_);
  packet.SetMaximumPacketSize(UdtDataPacket::kMaxSize);
  packet.SetMaximumFlowWindowSize(1); // Not used in this implementation.
  packet.SetSocketId(id_);
  packet.SetIpAddress(remote_endpoint_.address());
  packet.SetDestinationSocketId(0);
  packet.SetConnectionType(1);

  multiplexer_.SendTo(packet, remote_endpoint_);
  state_ = kClientAwaitingHandshakeResponse;
}

void UdtSocket::StartConnect() {
  assert(IsOpen()); // Socket must already have been accepted.
  assert(remote_endpoint_ != ip::udp::endpoint());
  assert(remote_id_ != 0);

  UdtHandshakePacket packet;
  packet.SetUdtVersion(4);
  packet.SetSocketType(UdtHandshakePacket::kStreamSocketType);
  packet.SetInitialPacketSequenceNumber(next_packet_sequence_number_);
  packet.SetMaximumPacketSize(UdtDataPacket::kMaxSize);
  packet.SetMaximumFlowWindowSize(1); // Not used in this implementation.
  packet.SetSocketId(id_);
  packet.SetIpAddress(remote_endpoint_.address());
  packet.SetDestinationSocketId(remote_id_);
  packet.SetConnectionType(0xffffffff);
  packet.SetSynCookie(0); // TODO calculate cookie

  multiplexer_.SendTo(packet, remote_endpoint_);
  state_ = kServerAwaitingHandshakeResponse;
}

void UdtSocket::StartWrite(const asio::const_buffer &data) {
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

void UdtSocket::ProcessWrite() {
  // There's only a waiting write if the write buffer is non-empty.
  if (asio::buffer_size(waiting_write_buffer_) == 0)
    return;

  // If the write buffer is full then the write is going to have to wait.
  if (write_buffer_.size() == kMaxWriteBufferSize)
    return;

  // Copy whatever data we can into the write buffer.
  size_t length = std::min(kMaxWriteBufferSize - write_buffer_.size(),
                           asio::buffer_size(waiting_write_buffer_));
  const unsigned char* data =
    asio::buffer_cast<const unsigned char*>(waiting_write_buffer_);
  write_buffer_.insert(write_buffer_.end(), data, data + length);
  waiting_write_buffer_ = waiting_write_buffer_ + length;
  waiting_write_bytes_transferred_ += length;

  // If we have finished writing all of the data then it's time to trigger the
  // write's completion handler.
  if (asio::buffer_size(waiting_write_buffer_) == 0) {
    // The write is done. Trigger the write's completion handler.
    waiting_write_ec_.clear();
    waiting_write_.cancel();
  }

  // Send the data we've got. (TODO This is a temporary hack only.)
  UdtDataPacket packet;
  packet.SetPacketSequenceNumber(next_packet_sequence_number_);
  packet.SetFirstPacketInMessage(true);
  packet.SetLastPacketInMessage(true);
  packet.SetInOrder(true);
  packet.SetMessageNumber(0);
  packet.SetTimeStamp(0);
  packet.SetDestinationSocketId(remote_id_);
  packet.SetData(std::string(write_buffer_.begin(), write_buffer_.end()));
  multiplexer_.SendTo(packet, remote_endpoint_);

  ++next_packet_sequence_number_;
  if (next_packet_sequence_number_ > 0x7fffffff);
    next_packet_sequence_number_ = 0;
}

void UdtSocket::StartRead(const asio::mutable_buffer &data,
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

void UdtSocket::ProcessRead() {
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

void UdtSocket::HandleReceiveFrom(const asio::const_buffer &data,
                                  const asio::ip::udp::endpoint &endpoint) {
  UdtDataPacket data_packet;
  UdtHandshakePacket handshake_packet;
  if (data_packet.Decode(data)) {
    HandleData(data_packet, endpoint);
  } else if (handshake_packet.Decode(data)) {
    HandleHandshake(handshake_packet, endpoint);
  } else {
    DLOG(ERROR) << "Socket " << id_
                << " ignoring invalid packet from "
                << endpoint << std::endl;
  }
}

void UdtSocket::HandleHandshake(const UdtHandshakePacket &packet,
                                const ip::udp::endpoint &endpoint) {
  switch (state_) {
  case kClientAwaitingHandshakeResponse:
    remote_id_ = packet.SocketId();
    state_ = kConnected;
    waiting_connect_ec_.clear();
    waiting_connect_.cancel();
    {
      UdtHandshakePacket response_packet(packet);
      response_packet.SetSocketId(id_);
      response_packet.SetIpAddress(remote_endpoint_.address());
      response_packet.SetDestinationSocketId(remote_id_);
      response_packet.SetConnectionType(0xffffffff);
      multiplexer_.SendTo(response_packet, remote_endpoint_);
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

void UdtSocket::HandleData(const UdtDataPacket &packet,
                           const ip::udp::endpoint &endpoint) {
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

}  // namespace transport

}  // namespace maidsafe
