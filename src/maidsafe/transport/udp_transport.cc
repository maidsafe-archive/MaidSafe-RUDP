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

#include "maidsafe/transport/udp_transport.h"

#include <array>
#include <cstring>
#include <functional>

#include "maidsafe/transport/udp_request.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace bptime = boost::posix_time;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

UdpTransport::UdpTransport(asio::io_service &asio_service)  // NOLINT
  : Transport(asio_service),
    strand_(asio_service),
    socket_(),
    read_buffer_(),
    sender_endpoint_(),
    next_request_id_(0),
    outstanding_requests_() {
  // If a UdpTransport is restarted and listens on the same port number as
  // before, it may receive late replies intended for the previous incarnation.
  // To avoid this, we use a random number as the first request id.
  next_request_id_ <<= 32;
  bptime::time_duration time = maidsafe::GetDurationSinceEpoch();
  next_request_id_ |= time.total_microseconds() & 0xffffffff;
  if (next_request_id_ == 0)
    ++next_request_id_;
}

UdpTransport::~UdpTransport() {
}

TransportCondition UdpTransport::StartListening(const Endpoint &endpoint) {
  if (listening_port_ != 0)
    return kAlreadyStarted;

  if (endpoint.port == 0)
    return kInvalidPort;

  // Even though the listening port is 0, we may have an open socket that has
  // been used for sending messages. We need to close that socket now before
  // reopening it on the specified listening endpoint.
  StopListening();

  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  socket_.reset(new ip::udp::socket(asio_service_));
  sender_endpoint_.reset(new ip::udp::endpoint);
  read_buffer_.reset(new std::vector<unsigned char>(0xffff));

  bs::error_code ec;
  socket_->open(ep.protocol(), ec);

  if (ec)
    return kInvalidAddress;

  socket_->bind(ep, ec);

  if (ec)
    return kBindError;

  listening_port_ = socket_->local_endpoint().port();

  StartRead();

  return kSuccess;
}

TransportCondition UdpTransport::Bootstrap(
    const std::vector<Contact> &/*candidates*/) {
  return kSuccess;
}

void UdpTransport::StopListening() {
  if (socket_)
    strand_.dispatch(std::bind(&UdpTransport::CloseSocket, socket_));
  listening_port_ = 0;
}

void UdpTransport::Send(const std::string &data,
                        const Endpoint &endpoint,
                        const Timeout &timeout) {
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  if (static_cast<DataSize>(data.size()) > kMaxTransportMessageSize()) {
    DLOG(ERROR) << "Data size " << data.size() << " bytes (exceeds limit of "
                << kMaxTransportMessageSize() << ")";
    (*on_error_)(kMessageSizeTooLarge, endpoint);
    return;
  }
  RequestPtr request(new UdpRequest(data, ep, asio_service_, timeout));
  strand_.dispatch(std::bind(&UdpTransport::DoSend,
                             shared_from_this(), request));
}

void UdpTransport::DoSend(RequestPtr request) {
  // Open a socket for sending if we don't have one already.
  if (!socket_) {
    socket_.reset(new ip::udp::socket(asio_service_));
    sender_endpoint_.reset(new ip::udp::endpoint);
    read_buffer_.reset(new std::vector<unsigned char>(0xffff));

    bs::error_code ec;
    socket_->open(request->Endpoint().protocol(), ec);
    if (ec) {
      socket_.reset();
      (*on_error_)(kInvalidAddress, Endpoint(request->Endpoint().address(),
                                             request->Endpoint().port()));
      return;
    }

    // Passing 0 as the port number will bind the socket to an OS-assigned port.
    socket_->bind(ip::udp::endpoint(request->Endpoint().protocol(), 0), ec);
    if (ec) {
      socket_.reset();
      (*on_error_)(kBindError, Endpoint(request->Endpoint().address(),
                                        request->Endpoint().port()));
      return;
    }

    StartRead();
  }

  // Generate a new id for the message.
  uint64_t request_id = next_request_id_++;
  if (next_request_id_ == 0)
    ++next_request_id_;

  // Encode the size of the message data.
  DataSize size = static_cast<DataSize>(request->Data().size());
  std::array<unsigned char, 4> size_buffer;
  for (int i = 0; i != 4; ++i)
    size_buffer[i] = static_cast<char>(size >> (8 * (3 - i)));

  // There's no need to encode the ids as they are opaque to the peer.
  std::array<uint64_t, 2> ids;
  ids[0] = request_id;
  ids[1] = request->ReplyToId();

  // There's no need to do an asynchronous operation here as UDP sends
  // generally don't block.
  std::array<boost::asio::const_buffer, 3> asio_buffer;
  asio_buffer[0] = boost::asio::buffer(size_buffer.data(),
                                       size_buffer.size());
  asio_buffer[1] = boost::asio::buffer(ids.data(),
                                       ids.size() * sizeof(uint64_t));
  asio_buffer[2] = boost::asio::buffer(request->Data());
  bs::error_code ec;
  socket_->send_to(asio_buffer, request->Endpoint(), 0, ec);
  if (ec) {
    (*on_error_)(kSendFailure, Endpoint(request->Endpoint().address(),
                                        request->Endpoint().port()));
    return;
  }

  // The message has been sent successfully, start waiting for a reply.
  if (request->ReplyTimeout() != kImmediateTimeout) {
    outstanding_requests_[request_id] = request;
    request->WaitForTimeout(strand_.wrap(std::bind(&UdpTransport::HandleTimeout,
                                                   shared_from_this(),
                                                   request_id, args::_1)));
  }
}

void UdpTransport::CloseSocket(SocketPtr socket) {
  bs::error_code ec;
  socket->close(ec);
}

void UdpTransport::StartRead() {
  assert(socket_->is_open());

  socket_->async_receive_from(asio::buffer(*read_buffer_),
                              *sender_endpoint_,
                              strand_.wrap(std::bind(&UdpTransport::HandleRead,
                                                     shared_from_this(),
                                                     socket_,
                                                     read_buffer_,
                                                     sender_endpoint_,
                                                     args::_1, args::_2)));
}

void UdpTransport::HandleRead(SocketPtr socket,
                              BufferPtr read_buffer,
                              EndpointPtr sender_endpoint,
                              const bs::error_code &ec,
                              size_t bytes_transferred) {
  if (!socket->is_open())
    return;

  // Ignore any message that is too short to contain all necessary fields.
  const size_t size_length = 4;
  const size_t ids_length = 2 * sizeof(uint64_t);
  if (!ec && bytes_transferred >= size_length + ids_length) {
    DataSize size = (((((read_buffer->at(0) << 8) |
                      read_buffer->at(1)) << 8) |
                      read_buffer->at(2)) << 8) |
                      read_buffer->at(3);

    // Check the size matches the actual amount of data received.
    if (size_length + ids_length + size == bytes_transferred) {
      // There's no need to decode the ids as they treated as opaque values.
      std::array<uint64_t, 2> ids;
      std::memcpy(ids.data(), &(*read_buffer)[size_length], ids_length);
      uint64_t request_id = ids[0];
      uint64_t reply_to_id = ids[1];

      // If this is a reply we can remove the corresponding outstanding request.
      // Removal of the request will cancel the WaitForTimeout operation.
      if (reply_to_id != 0) {
        RequestMap::iterator request = outstanding_requests_.find(reply_to_id);
        if (request == outstanding_requests_.end())
          return;  // Late or unexpected reply is ignored.
        outstanding_requests_.erase(request);
      }

      std::string data(read_buffer->begin() + size_length + ids_length,
                       read_buffer->begin() + size_length + ids_length + size);

      Info info;
      info.endpoint.ip = sender_endpoint->address();
      info.endpoint.port = sender_endpoint->port();
      // info.rtt = ?;

      // Dispatch the message outside the strand.
      strand_.get_io_service().post(std::bind(&UdpTransport::DispatchMessage,
                                              shared_from_this(),
                                              data, info, request_id));
    }
  }

  StartRead();
}

void UdpTransport::DispatchMessage(const std::string &data,
                                   const Info &info,
                                   uint64_t reply_to_id) {
  std::string response;
  Timeout response_timeout(kImmediateTimeout);
  (*on_message_received_)(data, info, &response, &response_timeout);

  if (!response.empty()) {
    ip::udp::endpoint ep(info.endpoint.ip, info.endpoint.port);
    RequestPtr request(new UdpRequest(response, ep,
                                      asio_service_,
                                      response_timeout,
                                      reply_to_id));
    strand_.dispatch(std::bind(&UdpTransport::DoSend,
                               shared_from_this(), request));
  }
}

void UdpTransport::HandleTimeout(uint64_t request_id,
                                 const bs::error_code &ec) {
  if (!ec) {
    RequestMap::iterator request = outstanding_requests_.find(request_id);
    if (request != outstanding_requests_.end()) {
      Endpoint peer_endpoint((*request).second->Endpoint().address(),
                             (*request).second->Endpoint().port());
      outstanding_requests_.erase(request);
      (*on_error_)(kReceiveTimeout, peer_endpoint);
    }
  }
}

}  // namespace transport

}  // namespace maidsafe
