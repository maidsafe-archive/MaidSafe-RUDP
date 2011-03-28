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

#include "maidsafe-dht/transport/udt_transport.h"

#include <cassert>
#include <functional>

#include "maidsafe-dht/transport/udt_acceptor.h"
#include "maidsafe-dht/transport/udt_connection.h"
#include "maidsafe-dht/transport/udt_multiplexer.h"
#include "maidsafe-dht/transport/udt_socket.h"
#include "maidsafe/common/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

UdtTransport::UdtTransport(
    boost::asio::io_service &asio_service)
        : Transport(asio_service),
          strand_(asio_service),
          multiplexer_(new UdtMultiplexer(asio_service)),
          acceptor_(),
          connections_() {}

UdtTransport::~UdtTransport() {
  for (auto it = connections_.begin(); it != connections_.end(); ++it)
    (*it)->Close();
}

TransportCondition UdtTransport::StartListening(const Endpoint &endpoint) {
  if (listening_port_ != 0)
    return kAlreadyStarted;

  ip::udp::endpoint ep(endpoint.ip, endpoint.port);
  TransportCondition condition = multiplexer_->Open(ep);
  if (condition != kSuccess)
    return condition;

  acceptor_.reset(new UdtAcceptor(*multiplexer_));
  listening_port_ = endpoint.port;

  StartAccept();
  StartDispatch();

  return kSuccess;
}

TransportCondition UdtTransport::Bootstrap(
    const std::vector<Endpoint> &candidates) {
  return kSuccess;
}

void UdtTransport::StopListening() {
  if (acceptor_)
    strand_.dispatch(std::bind(&UdtTransport::CloseAcceptor, acceptor_));
  if (multiplexer_)
    strand_.dispatch(std::bind(&UdtTransport::CloseMultiplexer, multiplexer_));
  listening_port_ = 0;
  acceptor_.reset();
  multiplexer_.reset(new UdtMultiplexer(asio_service_));
}

void UdtTransport::CloseAcceptor(AcceptorPtr acceptor) {
  acceptor->Close();
}

void UdtTransport::CloseMultiplexer(MultiplexerPtr multiplexer) {
  multiplexer->Close();
}

void UdtTransport::StartDispatch() {
  auto handler = strand_.wrap(std::bind(&UdtTransport::HandleDispatch,
                                        shared_from_this(),
                                        multiplexer_, arg::_1));
  multiplexer_->AsyncDispatch(handler);
}

void UdtTransport::HandleDispatch(MultiplexerPtr multiplexer,
                                  const bs::error_code &ec) {
  if (!multiplexer->IsOpen())
    return;

  StartDispatch();
}

void UdtTransport::StartAccept() {
  ip::udp::endpoint endpoint; // Endpoint is assigned when socket is accepted.
  ConnectionPtr connection(std::make_shared<UdtConnection>(shared_from_this(),
                                                           strand_,
                                                           multiplexer_,
                                                           endpoint));

  acceptor_->AsyncAccept(connection->Socket(),
                         strand_.wrap(std::bind(&UdtTransport::HandleAccept,
                                                shared_from_this(), acceptor_,
                                                connection, arg::_1)));
}

void UdtTransport::HandleAccept(AcceptorPtr acceptor,
                                ConnectionPtr connection,
                                const bs::error_code &ec) {
  if (!acceptor->IsOpen())
    return;

  if (!ec) {
    // It is safe to call DoInsertConnection directly because HandleAccept() is
    // already being called inside the strand.
    DoInsertConnection(connection);
    connection->StartReceiving();
  }

  StartAccept();
}

void UdtTransport::Send(const std::string &data,
                        const Endpoint &endpoint,
                        const Timeout &timeout) {
  strand_.dispatch(std::bind(&UdtTransport::DoSend,
                             shared_from_this(),
                             data, endpoint, timeout));
}

void UdtTransport::DoSend(const std::string &data,
                        const Endpoint &endpoint,
                        const Timeout &timeout) {
  ip::udp::endpoint ep(endpoint.ip, endpoint.port);

  if (!multiplexer_->IsOpen()) {
    TransportCondition condition = multiplexer_->Open(ep.protocol());
    // TODO error
    StartDispatch();
  }

  ConnectionPtr connection(std::make_shared<UdtConnection>(shared_from_this(),
                                                           strand_,
                                                           multiplexer_, ep));

  DoInsertConnection(connection);
  connection->StartSending(data, timeout);
}

void UdtTransport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&UdtTransport::DoInsertConnection,
                             shared_from_this(), connection));
}

void UdtTransport::DoInsertConnection(ConnectionPtr connection) {
  connections_.insert(connection);
}

void UdtTransport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&UdtTransport::DoRemoveConnection,
                             shared_from_this(), connection));
}

void UdtTransport::DoRemoveConnection(ConnectionPtr connection) {
  connections_.erase(connection);
}

}  // namespace transport

}  // namespace maidsafe
