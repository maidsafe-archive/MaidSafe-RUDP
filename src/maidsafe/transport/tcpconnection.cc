/* Copyright (c) 2009 maidsafe.net limited
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

#include <boost/bind.hpp>
#include "maidsafe/base/log.h"
#include "maidsafe/transport/tcpconnection.h"

namespace transport {

TCPConnection::TCPConnection(boost::asio::io_service &io_service,  // NOLINT
    boost::function<void(const boost::uint32_t&, const bool&, const bool&,
    const boost::system::error_code&)> send_notifier,
    boost::function<void(const std::string, const boost::uint32_t&,
    const boost::system::error_code&)> read_notifier)
    : socket_(io_service), in_data_(), out_data_(), tmp_data_(),
      in_data_size_(0), connection_id_(0), send_notifier_(send_notifier),
      read_notifier_(read_notifier), out_port_(0), send_once_(true),
      sending_rpc_(false), closed_(false), receiving_(false) {
}

boost::asio::ip::tcp::endpoint TCPConnection::RemoteEndPoint(
    boost::system::error_code &ec) {
  boost::asio::ip::tcp::endpoint remote = socket_.remote_endpoint(ec);
  return remote;
}

void TCPConnection::StartReceiving() {
  if (closed_ || receiving_)
    return;
  in_data_.clear();
  in_data_size_ = 0;
  sending_rpc_ = false;

  socket_.async_read_some(boost::asio::buffer(
      reinterpret_cast<char*>(&in_data_size_), sizeof(size_t)),
      boost::bind(&TCPConnection::ReadHandle, shared_from_this(), true,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));
  receiving_ = true;
}

void TCPConnection::Send(const std::string &data) {
  if (closed_)
    return;
  out_data_ = data;
  size_t size = out_data_.size();
  boost::asio::async_write(socket_,
    boost::asio::buffer(reinterpret_cast<char*>(&size), sizeof(size_t)),
    boost::bind(&TCPConnection::WriteHandle, shared_from_this(),
      boost::asio::placeholders::error, true));
}

void TCPConnection::ReadHandle(const bool &read_size,
    const boost::system::error_code &ec, size_t bytes_read) {
  if (closed_)
    return;

  if (ec) {
    receiving_ = false;
    // io service has been stopped, no need to notify
    if (ec == boost::asio::error::operation_aborted) {
      Close();
      return;
    }
    DLOG(ERROR) << "error reading in a connection: " << ec << " - "
      << ec.message() << "\n";
    read_notifier_(in_data_, connection_id_, ec);
    return;
  }

  if (!read_size) {
    if (bytes_read == 0) {
      receiving_ = false;
      read_notifier_(in_data_, connection_id_, ec);
      return;
    }
    std::string rec_string(tmp_data_.data(), bytes_read);
    in_data_ += rec_string;
    if (in_data_.size() >= in_data_size_) {
      receiving_ = false;
      read_notifier_(in_data_, connection_id_, ec);
      return;
    }
  }

  socket_.async_read_some(boost::asio::buffer(tmp_data_, 1024),
    boost::bind(&TCPConnection::ReadHandle, shared_from_this(), false,
      boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));
}

void TCPConnection::WriteHandle(const boost::system::error_code &ec,
    const bool &size_sent) {
  if (closed_)
    return;
  if (ec) {
    // io service has been stopped, no need to notify
    if (ec == boost::asio::error::operation_aborted) {
      Close();
      return;
    }
    DLOG(ERROR) << "error sending in a connection: " << ec << " - "
      << ec.message() << "\n";
    send_notifier_(connection_id_, send_once_, sending_rpc_, ec);
    return;
  }
  if (size_sent) {
    boost::asio::async_write(socket_,
      boost::asio::buffer(out_data_.c_str(), out_data_.size()),
      boost::bind(&TCPConnection::WriteHandle, shared_from_this(),
        boost::asio::placeholders::error, false));
  } else {
    send_notifier_(connection_id_, send_once_, sending_rpc_, ec);
  }
}

void TCPConnection::Close() {
  if (closed_)
    return;
  boost::system::error_code ec;
  socket_.close(ec);
  if (ec)
    DLOG(WARNING) << "error closing a socket: " << ec << " : " <<
      ec.message() << "\n";
  closed_ = true;
}

bool TCPConnection::Connect(const boost::asio::ip::tcp::endpoint &remote_addr,
    const boost::uint16_t &out_port) {
  boost::system::error_code ec;
  socket_.open(boost::asio::ip::tcp::v4());
  socket_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  socket_.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
    out_port_));
  socket_.connect(remote_addr, ec);
  if (ec) {
    DLOG(ERROR) << "error trying to connect: " << ec << " - "
      << ec.message() << "\n";
    return false;
  }
  out_port_ = out_port;
  return true;
}

bool TCPConnection::Connect(const boost::asio::ip::tcp::endpoint &remote_addr) {
  boost::system::error_code ec;
  socket_.open(boost::asio::ip::tcp::v4());
  socket_.set_option(boost::asio::ip::tcp::socket::reuse_address(true));
  boost::asio::socket_base::keep_alive option(true);
  socket_.set_option(option);
  socket_.connect(remote_addr, ec);
  if (ec) {
    out_port_ = 0;
    DLOG(ERROR) << "error trying to connect to " << remote_addr << ": "
      << ec << " - " << ec.message() << "\n";
    return false;
  }
  out_port_ = socket_.local_endpoint(ec).port();
  return true;
}
}
