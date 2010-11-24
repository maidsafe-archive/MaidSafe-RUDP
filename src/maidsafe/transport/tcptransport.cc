//  Copyright (c) 2010 maidsafe.net limited
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//
//      * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//      * Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//      * Neither the name of the maidsafe.net limited nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVERCAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OFTHIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.

#include <maidsafe/transport/tcptransport.h>
#include <maidsafe/base/log.h>

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <google/protobuf/descriptor.h>

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace pt = boost::posix_time;

namespace transport {

TcpTransport::TcpTransport()
    : Transport(),
      keep_alive_(new asio::io_service::work(io_service_)),
      current_socket_id_(1) {
  worker_thread_ = boost::thread(&TcpTransport::Run, this);
}

TcpTransport::~TcpTransport() {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);

  keep_alive_.reset();

//  if (!keep_alive_)
//    printf("NOT KEEPING ALIVE\n");
//  else 
//    printf("KEEPING ALIVE\n");

  BOOST_FOREACH(ConnectionMap::value_type const& connection, connections_) {
    io_service_.post(boost::bind(&TcpConnection::Close, connection.second));
  }
  lock.unlock();

  StopAllListening();
  worker_thread_.join();
}

asio::io_service &TcpTransport::IOService() {
  return io_service_;
}

Port TcpTransport::StartListening(const IP &ip,
                                  const Port &try_port,
                                  TransportCondition *condition) {
  bs::error_code ec;
  ip::address addr = ip.empty() ?
      ip::address_v4::any() : ip::address::from_string(ip.c_str(), ec);

  if (ec) {
    if (condition)
      *condition = kInvalidAddress;
    return 0;
  }

  ip::tcp::endpoint ep(addr, try_port);
  AcceptorPtr acceptor(new ip::tcp::acceptor(io_service_));

  acceptor->open(ep.protocol(), ec);

  if (ec) {
    if (condition)
      *condition = kInvalidAddress;
    return 0;
  }

  acceptor->bind(ep, ec);

  if (ec) {
    if (condition)
      *condition = kBindError;
    return 0;
  }

  acceptor->listen(asio::socket_base::max_connections, ec);

  if (ec) {
    if (condition)
      *condition = kListenError;
    return 0;
  }

  boost::mutex::scoped_lock lock(listening_ports_mutex_);

  ConnectionPtr new_connection(new TcpConnection(*this));

  // The connection object is kept alive in the acceptor handler until
  // HandleAccept() is called.
  acceptor->async_accept(new_connection->Socket(),
                         boost::bind(&TcpTransport::HandleAccept,
                                     this, acceptor, new_connection, _1));

  Port actual_port = acceptor->local_endpoint().port();

  acceptors_.push_back(acceptor);
  listening_ports_.push_back(actual_port);

  if (condition)
    *condition = kSuccess;

  return actual_port;
}

bool TcpTransport::StopListening(const Port& port) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);

  std::vector<Port>::iterator i = std::find(listening_ports_.begin(),
                                            listening_ports_.end(),
                                            port);

  if (i == listening_ports_.end())
      return false;

  acceptors_.erase(acceptors_.begin() + (i - listening_ports_.begin()));
  listening_ports_.erase(i);

  return true;
}

bool TcpTransport::StopAllListening() {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  listening_ports_.clear();

  BOOST_FOREACH(AcceptorPtr const& acceptor, acceptors_) {
    acceptor->close();
  }

  acceptors_.clear();
  return true;
}

void TcpTransport::Run() {
  for (;;) {
    bs::error_code ec;
    io_service_.run(ec);
    if (!ec) break;
  }
}

void TcpTransport::HandleAccept(const AcceptorPtr &acceptor,
                                const ConnectionPtr &connection,
                                const bs::error_code &ec) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);

  if (!keep_alive_)
    return;

  if (!ec) {
    SocketId socket_id = NextSocketId();
    connection->SetSocketId(socket_id);
    connections_.insert(std::make_pair(socket_id, connection));
    connection->StartReceiving();
  }

  ConnectionPtr new_connection(new TcpConnection(*this));

  // The connection object is kept alive in the acceptor handler until
  // HandleAccept() is called.
  acceptor->async_accept(new_connection->Socket(),
                         boost::bind(&TcpTransport::HandleAccept,
                                     this, acceptor, new_connection, _1));
}

SocketId TcpTransport::NextSocketId() {
  SocketId id = current_socket_id_++;
  if (id == 0) ++id;
  return id;
}

SocketId TcpTransport::PrepareToSend(const IP &remote_ip,
                                     const Port &remote_port,
                                     const IP &/*rendezvous_ip*/,
                                     const Port &/*rendezvous_port*/) {
  bs::error_code ec;
  ip::address addr = ip::address::from_string(remote_ip.c_str(), ec);

  if (ec)
    return 0;

  ip::tcp::endpoint ep(addr, remote_port);

  ConnectionPtr connection(new TcpConnection(*this, ep));

  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  SocketId socket_id = NextSocketId();
  connection->SetSocketId(socket_id);
  connections_.insert(std::make_pair(socket_id, connection));

  return socket_id;
}

void TcpTransport::Send(const TransportMessage &msg,
                        const SocketId &socket_id,
                        const boost::uint32_t &timeout_wait_for_response) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);

  ConnectionMap::iterator i = connections_.find(socket_id);
  if (i == connections_.end())
    return;
  ConnectionPtr connection = i->second;

  lock.unlock();

  connection->Send(msg, timeout_wait_for_response);
}

void TcpTransport::SendFile(const boost::filesystem::path &path,
                            const SocketId &socket_id) {
  (void)path;
  (void)socket_id;
}

void TcpTransport::RemoveConnection(SocketId id) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  connections_.erase(id);
}

}  // namespace transport
