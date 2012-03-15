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

#include "maidsafe/transport/managed_connection.h"

#include <functional>

#include "maidsafe/transport/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace transport {

ManagedConnection::ManagedConnection()
    : asio_services_(new AsioService),
      keep_alive_timer_(),
      transport_(),
      connected_endpoints_(),
      lost_functor_() {
}

void ManagedConnection::ConnectionLost(LostFunctor lost_functor) {
  lost_functor_ = lost_functor;
}

OnMessageReceived ManagedConnection::on_message_received() {
  assert(transport_);
  return transport_->on_message_received();
}

TransportCondition ManagedConnection::Init(uint8_t thread_count,
    std::pair<uint16_t, uint16_t> port_range) {
  asio_services_->Start(thread_count);
  keep_alive_timer_.reset(
      new asio::deadline_timer(asio_services_->service()));
                               //boost::posix_time::seconds(10));
  TransportCondition result(kError);
  transport_.reset(new RudpTransport(asio_services_->service()));
  // Workaround until NAT detection is integrated.
  std::vector<transport::IP> ips = transport::GetLocalAddresses();
  transport::Endpoint endpoint(
      ips.empty() ? IP::from_string("127.0.0.1") : ips.front(), 0);
  for (uint16_t port(std::min(port_range.first, port_range.second));
         port != std::min(port_range.first, port_range.second); ++port) {
    endpoint.port = port;
    result = transport_->StartListening(endpoint);
    if (transport::kSuccess == result) {
      break;
    } else {
      transport_->StopListening();
    }
  }
  if (kSuccess != result)
    return result;

  keep_alive_timer_->async_wait(
    std::bind(&ManagedConnection::SendKeepAlive, this, args::_1));
  return result;
}

void ManagedConnection::SendKeepAlive(const boost::system::error_code& ec) {
  if (ec == boost::asio::error::operation_aborted) {
    return;
  }
  // lock
  for (auto itr(connected_endpoints_.begin());
      itr !=connected_endpoints_.end(); ++itr) {
    WriteCompleteFunctor cb(std::bind(&ManagedConnection::KeepAliveCallback,
                                      this, *itr, args::_1));
    transport_->WriteOnManagedConnection("KeepAlive", *itr,
                                         kDefaultInitialTimeout, cb);
  }
  keep_alive_timer_->async_wait(
    std::bind(&ManagedConnection::SendKeepAlive, this, args::_1));
}

void ManagedConnection::KeepAliveCallback(const Endpoint &endpoint,
                                          const TransportCondition& result) {
  if (kSuccess != result) {
    if (lost_functor_)
      lost_functor_(endpoint);
    //  lock
    connected_endpoints_.remove(endpoint);
  }
}

Endpoint ManagedConnection::GetOurEndpoint() {
  return transport_->transport_details().endpoint;
}

void ManagedConnection::AddConnection(const Endpoint &peer_endpoint,
                                      const std::string &validation_data,
                                      AddFunctor add_functor) {
  ResponseFunctor response_functor(
    std::bind(&ManagedConnection::AddConnectionCallback, this, args::_1,
              args::_2, peer_endpoint, add_functor));
  transport_->Send(validation_data, peer_endpoint, kDefaultInitialTimeout,
                   true, response_functor);
}

TransportCondition ManagedConnection::AcceptConnection(
  const Endpoint &peer_endpoint, bool accept) {
  TransportCondition result(kError);
  if (accept) {
    result = transport_->SetConnectionAsManaged(peer_endpoint);
    if (kSuccess == result) {
      //  lock
      connected_endpoints_.push_back(peer_endpoint);
    }
  }
  return result;
}

void ManagedConnection::AddConnectionCallback(TransportCondition result,
                                              const std::string &response,
                                              const Endpoint &peer_endpoint,
                                              AddFunctor add_functor) {
  if (kSuccess != result)
    add_functor(result);
  if ("Accepted" != response) {
    add_functor(kError); //  Rejected error code
    return;
  } else {
    //  lock
    connected_endpoints_.push_back(peer_endpoint);
    add_functor(result);
  }
}

void ManagedConnection::Send(const Endpoint &peer_endpoint,
                             const std::string &message,
                             ResponseFunctor response_functor) {
  transport_->Send(message, peer_endpoint, kDefaultInitialTimeout,
                   false, response_functor);
}

ManagedConnection::~ManagedConnection() {
  transport_->StopListening();
}

}  // namespace transport

}  // namespace maidsafe
