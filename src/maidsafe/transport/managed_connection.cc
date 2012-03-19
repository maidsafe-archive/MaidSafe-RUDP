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

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/utils.h"

namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace transport {

ManagedConnection::ManagedConnection()
    : asio_services_(new AsioService),
      keep_alive_interval_(bptime::seconds(20)),
      keep_alive_timer_(),
      transport_(),
      connected_endpoints_(),
      lost_functor_(),
      mutex_() {
}

void ManagedConnection::ConnectionLost(LostFunctor lost_functor) {
  lost_functor_ = lost_functor;
}

OnMessageReceived ManagedConnection::on_message_received() {
  BOOST_ASSERT(transport_);
  return transport_->on_message_received();
}

TransportCondition ManagedConnection::Init(uint8_t thread_count) {
  // TODO use random port to start
  std::pair<uint16_t, uint16_t> port_range(8000, 9000);
  asio_services_->Start(thread_count);
  keep_alive_timer_.reset(
      new asio::deadline_timer(asio_services_->service(),
                               keep_alive_interval_));
  TransportCondition result(kError);
  transport_.reset(new RudpTransport(asio_services_->service()));
  // Workaround until NAT detection is integrated.
  std::vector<transport::IP> ips = transport::GetLocalAddresses();
  transport::Endpoint endpoint(
      ips.empty() ? IP::from_string("127.0.0.1") : ips.front(), 0);
  for (uint16_t port(std::min(port_range.first, port_range.second));
         port != std::max(port_range.first, port_range.second); ++port) {
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
  // Copying entire list
  std::list<Endpoint> connected_endpoints = GetEndpoints();
  // TODO For debugging purpose. Remove later
  if (!connected_endpoints.size())
    DLOG(INFO) << "SendKeepAlive list EMPTY !!!!!!!!!!";

  for (auto itr(connected_endpoints.begin());
      itr !=connected_endpoints.end(); ++itr) {
    WriteCompleteFunctor cb(std::bind(&ManagedConnection::KeepAliveCallback,
                                      this, *itr, args::_1));
    DLOG(INFO) << "Sending KeepAlive to :" << (*itr).port;
    transport_->WriteOnManagedConnection("KeepAlive", *itr,
                                         kDefaultInitialTimeout, cb);
  }
  keep_alive_timer_->expires_at(
      keep_alive_timer_->expires_at() + keep_alive_interval_);
  keep_alive_timer_->async_wait(
      std::bind(&ManagedConnection::SendKeepAlive, this, args::_1));
}

void ManagedConnection::KeepAliveCallback(const Endpoint &endpoint,
                                          const TransportCondition& result) {
  DLOG(INFO) << "KeepAliveCallback - called for endpoint : "
             << endpoint.port  << "result = " << result;
  if (kSuccess != result) {
    DLOG(INFO) << "Connection with endpoint " << endpoint.port << "Lost";
    RemoveConnection(endpoint);
    if (lost_functor_)
      lost_functor_(endpoint);
  }
}

Endpoint ManagedConnection::GetOurEndpoint() {
  if (transport_)
    return transport_->transport_details().endpoint;
  return Endpoint();
}

void ManagedConnection::AddConnection(const Endpoint &peer_endpoint,
                                      const std::string &validation_data,
                                      AddFunctor add_functor) {
  if (peer_endpoint == GetOurEndpoint()) {
    if (add_functor)
      add_functor(kError);  //  Cannot connect to own
  }
  ResponseFunctor response_functor(
      std::bind(&ManagedConnection::AddConnectionCallback, this, args::_1,
                args::_2, peer_endpoint, add_functor));
  transport_->Send(validation_data, peer_endpoint, kDefaultInitialTimeout,
                   true, response_functor);
}

TransportCondition ManagedConnection::AcceptConnection(
  // Do nothing if already connected
  const Endpoint &peer_endpoint, bool accept) {
//  TransportCondition result(kError);
  if (accept) {
    transport_->SetConnectionAsManaged(peer_endpoint);
    InsertEndpoint(peer_endpoint);
  }
  // TODO Need call back from rudp
  return kSuccess;
}

void ManagedConnection::AddConnectionCallback(TransportCondition result,
                                              const std::string &response,
                                              const Endpoint &peer_endpoint,
                                              AddFunctor add_functor) {
  if (kSuccess != result)
  if (add_functor)
    add_functor(result);

  if ("Accepted" != response) {
    DLOG(INFO) << "AddConnectionCallback failed - received : " << response;
    if (add_functor)
      add_functor(kError); //  Rejected error code
    RemoveEndpoint(peer_endpoint);
    return;
  } else {
    DLOG(INFO) << "AddConnectionCallback success - received : " << response;
    InsertEndpoint(peer_endpoint);
    if (add_functor)
      add_functor(result);
  }
}

void ManagedConnection::RemoveConnection(const Endpoint &peer_endpoint) {
  transport_->RemoveManagedConnection(peer_endpoint);
  RemoveEndpoint(peer_endpoint);
}


std::list<Endpoint> ManagedConnection::GetEndpoints() {
  boost::mutex::scoped_lock lock(mutex_);
  return connected_endpoints_;
}

void ManagedConnection::InsertEndpoint(const Endpoint &peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  connected_endpoints_.push_back(peer_endpoint);
 }

void ManagedConnection::RemoveEndpoint(const Endpoint &peer_endpoint) {
  boost::mutex::scoped_lock lock(mutex_);
  connected_endpoints_.remove(peer_endpoint);
}

void ManagedConnection::Send(const Endpoint &peer_endpoint,
                             const std::string &message,
                             ResponseFunctor response_functor) {
  transport_->Send(message, peer_endpoint, kDefaultInitialTimeout,
                   false, response_functor);
}

ManagedConnection::~ManagedConnection() {
  keep_alive_timer_->cancel();
  transport_->StopListening();
}

}  // namespace transport

}  // namespace maidsafe
