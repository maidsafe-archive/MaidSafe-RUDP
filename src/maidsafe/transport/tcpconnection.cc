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

#include <maidsafe/transport/tcptransport.h>
#include <maidsafe/transport/tcpconnection.h>
#include <maidsafe/transport/udtconnection.h>  // for timeout constants
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/base/log.h>

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <google/protobuf/descriptor.h>

#include <algorithm>
#include <vector>

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace pt = boost::posix_time;

namespace transport {
/*
TcpConnection::TcpConnection(TcpTransport *tcp_transport,
                             ip::tcp::endpoint const& remote_ep)
  : transport_(tcp_transport),
    socket_id_(0),
    socket_(transport_->IOService()),
    timer_(transport_->IOService()),
    remote_endpoint_(remote_ep),
    buffer_(),
    timeout_for_response_(kDefaultInitialTimeout) {}

TcpConnection::~TcpConnection() {}

void TcpConnection::Close() {
  socket_.close();
  timer_.cancel();
  transport_->RemoveConnection(socket_id_);
}

void TcpConnection::SetSocketId(SocketId id) {
  socket_id_ = id;
}

ip::tcp::socket &TcpConnection::Socket() {
  return socket_;
}

void TcpConnection::StartTimeout(int seconds) {
  timer_.expires_from_now(pt::seconds(seconds));
  timer_.async_wait(boost::bind(&TcpConnection::HandleTimeout,
                                shared_from_this(), _1));
}

void TcpConnection::StartReceiving() {
  // Start by receiving the message size.
  // socket_.async_receive(...);
  buffer_.Allocate(sizeof(DataSize));
  asio::async_read(socket_, asio::buffer(buffer_.Data(), buffer_.Size()),
                   boost::bind(&TcpConnection::HandleSize,
                               shared_from_this(), _1));
  StartTimeout(timeout_for_response_);
}

void TcpConnection::HandleTimeout(boost::system::error_code const& ec) {
  if (ec) return;
  socket_.close();
}

void TcpConnection::HandleSize(boost::system::error_code const& ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    transport_->signals()->on_error_(socket_id_, kReceiveTimeout);
    return Close();
  }

  if (ec) {
    transport_->signals()->on_error_(socket_id_, kReceiveFailure);
    return Close();
  }

  DataSize size = *reinterpret_cast<DataSize*>(buffer_.Data());
  buffer_.Allocate(size);

  asio::async_read(socket_, asio::buffer(buffer_.Data(), buffer_.Size()),
                   boost::bind(&TcpConnection::HandleRead,
                               shared_from_this(), _1));
}

void TcpConnection::HandleRead(boost::system::error_code const& ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    transport_->signals()->on_error_(socket_id_, kReceiveTimeout);
    return Close();
  }

  if (ec) {
    transport_->signals()->on_error_(socket_id_, kReceiveFailure);
    return Close();
  }

  TransportMessage msg;
  if (!msg.ParseFromArray(buffer_.Data(), buffer_.Size())) {
    transport_->signals()->on_error_(socket_id_, kReceiveParseFailure);
    return Close();
  }

  timer_.cancel();

  DispatchMessage(msg);
}

void TcpConnection::DispatchMessage(const TransportMessage &msg) {
  bool is_request(msg.type() == TransportMessage::kKeepAlive);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      msg.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(msg.data(), &field_descriptors);
  if (field_descriptors.size() != 1U) {
    DLOG(INFO) << "Bad data - doesn't contain exactly one field." << std::endl;
    if (!is_request)
      transport_->signals()->on_error_(socket_id_, kReceiveParseFailure);
    return Close();
  }

  float rtt = 0.f;

  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      transport_->signals()->on_message_received_(socket_id_,
          msg.data().raw_message(), rtt);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        transport_->signals()->on_message_received_(socket_id_,
            msg.data().rpc_message(), rtt);
        // Leave socket open to send response on.
      } else {
        transport_->signals()->on_message_received_(socket_id_,
            msg.data().rpc_message(), rtt);
        Close();
      }
      break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
      Close();
      break;
    case TransportMessage::Data::kPingFieldNumber:
      Close();
      break;
    case TransportMessage::Data::kProxyPingFieldNumber:
      Close();
      break;
    case TransportMessage::Data::kManagedEndpointMessageFieldNumber:
      Close();
      break;
    default:
      DLOG(INFO) << "Unrecognised data type in TransportMessage." << std::endl;
      Close();
  }
}

void TcpConnection::Send(const TransportMessage &msg,
                         boost::uint32_t timeout_wait_for_response) {
  // Serialize message to internal buffer
  DataSize msg_size = msg.ByteSize();
  buffer_.Allocate(msg_size + sizeof(DataSize));
  *reinterpret_cast<DataSize*>(buffer_.Data()) = msg_size;
  msg.SerializeToArray(buffer_.Data() + sizeof(DataSize), msg_size);

  bool is_request = msg.type() == TransportMessage::kKeepAlive;

  if (is_request) {
    assert(!socket_.is_open());
    timeout_for_response_ = timeout_wait_for_response;
    StartTimeout(kDefaultInitialTimeout);
    socket_.async_connect(remote_endpoint_,
                          boost::bind(&TcpConnection::HandleConnect,
                                      shared_from_this(), _1));
  } else {
    assert(socket_.is_open());
    timeout_for_response_ = 0;
    boost::uint32_t timeout(
        std::max(static_cast<boost::uint32_t>(buffer_.Size() *
                                              kTimeoutFactor), kMinTimeout));
    StartTimeout(timeout);
    asio::async_write(socket_, asio::buffer(buffer_.Data(), buffer_.Size()),
                      boost::bind(&TcpConnection::HandleWrite,
                                  shared_from_this(), _1));
  }
}

void TcpConnection::HandleConnect(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    transport_->signals()->on_error_(socket_id_, kSendTimeout);
    return Close();
  }

  if (ec) {
    transport_->signals()->on_error_(socket_id_, kSendFailure);
    return Close();
  }

  boost::uint32_t timeout(
      std::max(static_cast<boost::uint32_t>(buffer_.Size() *
                                            kTimeoutFactor), kMinTimeout));
  StartTimeout(timeout);

  asio::async_write(socket_, asio::buffer(buffer_.Data(), buffer_.Size()),
                    boost::bind(&TcpConnection::HandleWrite,
                                shared_from_this(), _1));
}

void TcpConnection::HandleWrite(const bs::error_code &ec) {
  // If the socket is closed, it means the timeout has been triggered.
  if (!socket_.is_open()) {
    transport_->signals()->on_error_(socket_id_, kSendTimeout);
    return Close();
  }

  if (ec) {
    transport_->signals()->on_error_(socket_id_, kSendFailure);
    return Close();
  }

//  transport_->signals()->on_error_(socket_id_, kSuccess);

  // Start receiving response
  if (timeout_for_response_ != 0) {
    StartReceiving();
  } else {
    Close();
  }
}
*/
}  // namespace transport
