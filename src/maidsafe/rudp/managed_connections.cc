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

#include "maidsafe/transport/managed_connections.h"

#include <functional>
#include <iterator>

#include "maidsafe/transport/log.h"
#include "maidsafe/transport/utils.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/mc_transport.h"

namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace transport {

namespace {
const int kMaxTransports(10);
}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(new AsioService),
      message_received_functor_(),
      connection_lost_functor_(),
      keep_alive_interval_(bptime::seconds(20)),
      mc_transports_(),
      shared_mutex_() {}

std::vector<Endpoint> ManagedConnections::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    MessageReceivedFunctor message_received_functor,
    ConnectionLostFunctor connection_lost_functor) {
  {
    SharedLock shared_lock(shared_mutex_);
    if (!mc_transports_.empty()) {
      DLOG(ERROR) << "Already bootstrapped.";
      return std::vector<Endpoint>();
    }
  }

  auto itr(bootstrap_endpoints.begin());
  std::vector<Endpoint> successful_endpoints;
  while (itr != bootstrap_endpoints.end() &&
         mc_transports_.size() < kMaxTransports) {
    ...
  }
  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;
  return successful_endpoints;
}

Endpoint ManagedConnections::StartNewTransport(
    const std::vector<Endpoint> &bootstrap_endpoints) {
  std::unique_ptr<McTransport> mc_transport(
      new McTransport(asio_service_->service()));
  std::vector<Endpoint> all_endpoints;
  all_endpoints.reserve((kMaxTransports * McTransport::kMaxConnections()) +
                        bootstrap_endpoints.size());

  // Collect all current connections first, then append bootstrap list
  {
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        mc_transports_.begin(),
        mc_transports_.end(),
        [&all_endpoints](const std::unique_ptr<McTransport> &mc_transport) {
      std::vector<Endpoint> connected_endpoints(
          mc_transport->connected_endpoints());
      std::copy(connected_endpoints.begin(),
                connected_endpoints.end(),
                std::back_inserter(all_endpoints));
    });
  }
  std::copy(bootstrap_endpoints.begin(),
            bootstrap_endpoints.end(),
            std::back_inserter(all_endpoints));

  // Bootstrap new transport and if successful, add it to the vector.
  Endpoint chosen_endpoint(mc_transport->Bootstrap(all_endpoints));
  if (!IsValid(chosen_endpoint)) {
    DLOG(WARNING) << "Failed to start a new McTransport.  "
                  << mc_transports_.size() << " currently running.";
    return Endpoint();
  }

  UniqueLock unique_lock(shared_mutex_);
  mc_transports_.push_back(std::move(mc_transport));
  return chosen_endpoint;
}

int ManagedConnections::GetAvailableEndpoint(Endpoint *endpoint) {
  if (!endpoint) {
    DLOG(ERROR) << "Null parameter passed.";
    return kNullParameter;
  }

  size_t mc_transports_size(0);
  {
    SharedLock shared_lock(shared_mutex_);
    mc_transports_size = mc_transports_.size();
  }

  if (mc_transports_size < kMaxTransports) {
    if (mc_transports_size == 0) {
      DLOG(ERROR) << "No running McTransports.";
      return kNoneAvailable;
    }

    Endpoint new_endpoint(StartNewTransport(std::vector<Endpoint>()));
    if (IsValid(new_endpoint)) {
      *endpoint = new_endpoint;
      return kSuccess;
    }
  }

  // Get transport with least connections.
  {
    uint32_t least_connections(McTransport::kMaxConnections());
    Endpoint chosen_endpoint;
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        mc_transports_.begin(),
        mc_transports_.end(),
        [&least_connections, &chosen_endpoint]
            (const std::unique_ptr<McTransport> &mc_transport) {
      if (mc_transport->connected_endpoints_size() < least_connections) {
        least_connections = mc_transport->connected_endpoints_size();
        chosen_endpoint = mc_transport->this_endpoint();
      }
    });

    if (!IsValid(chosen_endpoint)) {
      DLOG(ERROR) << "All McTransports are full.";
      return kFull;
    }

    *endpoint = chosen_endpoint;
    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint &this_endpoint,
                            const Endpoint &peer_endpoint,
                            const std::string &this_node_id) {
  // TODO(Fraser#5#): 2012-03-28 - Disallow duplicate peer endpoints, even
  //                               across different McTransports?
  SharedLock shared_lock(shared_mutex_);
  auto itr(std::find_if(
      mc_transports_.begin(),
      mc_transports_.end(),
      [&this_endpoint] (const std::unique_ptr<McTransport> &mc_transport) {
    return mc_transport->this_endpoint() == this_endpoint;
  }));
  if (itr == mc_transports_.end()) {
    DLOG(ERROR) << "No McTransports have endpoint "
                << this_endpoint.ip.to_string() << ":" << this_endpoint.port;
    return kInvalidMcTransport;
  }

  (*itr)->RendezvousConnect(peer_endpoint, this_node_id);
  return kSuccess;
}

void ManagedConnections::Remove(const Endpoint &peer_endpoint) {
  SharedLock shared_lock(shared_mutex_);
  for (auto itr(mc_transports_.begin()); itr != mc_transports_.end(); ++itr) {
    int result((*itr)->CloseConnection(peer_endpoint));
    if (result == kSuccess) {
      return;
    } else if (result != kInvalidMcConnection) {
      DLOG(ERROR) << "Failed to close connection to "
                  << peer_endpoint.ip.to_string() << ":" << peer_endpoint.port;
    }
  }
}

int ManagedConnections::Send(const Endpoint &peer_endpoint,
                             const std::string &message) const {
  SharedLock shared_lock(shared_mutex_);
  for (auto itr(mc_transports_.begin()); itr != mc_transports_.end(); ++itr) {
    int result((*itr)->Send(peer_endpoint, message));
    if (result == kSuccess) {
      return;
    } else if (result != kInvalidMcConnection) {
      DLOG(ERROR) << "Failed to send message to "
                  << peer_endpoint.ip.to_string() << ":" << peer_endpoint.port;
    }
  }
}

void ManagedConnections::Ping(const Endpoint &peer_endpoint) const {
}

//TransportCondition ManagedConnections::Init(uint8_t thread_count) {
//  // TODO(Prakash) Use random port to start
//  std::pair<uint16_t, uint16_t> port_range(8000, 9000);
//  asio_services_->Start(thread_count);
//  TransportCondition result(kError);
//  transport_.reset(new RudpTransport(asio_services_->service()));
//  // Workaround until NAT detection is integrated.
//  std::vector<transport::IP> ips = transport::GetLocalAddresses();
//  transport::Endpoint endpoint(
//      ips.empty() ? IP::from_string("127.0.0.1") : ips.front(), 0);
//  for (uint16_t port(std::min(port_range.first, port_range.second));
//         port != std::max(port_range.first, port_range.second); ++port) {
//    endpoint.port = port;
//    result = transport_->StartListening(endpoint);
//    if (transport::kSuccess == result) {
//      break;
//    } else {
//      transport_->StopListening();
//    }
//  }
//  if (kSuccess != result)
//    return result;
//  keep_alive_timer_.async_wait(
//      std::bind(&ManagedConnections::SendKeepAlive, this, args::_1));
//  return result;
//}
//
//void ManagedConnections::SendKeepAlive(const boost::system::error_code& ec) {
//  if (ec == boost::asio::error::operation_aborted) {
//    return;
//  }
//  // Copying entire list
//  std::set<Endpoint> connected_endpoints = GetEndpoints();
//  if (!connected_endpoints.size())
//    DLOG(INFO) << "SendKeepAlive list EMPTY !!!!!!!!!!";
////  for (auto itr(connected_endpoints.begin());
////      itr !=connected_endpoints.end(); ++itr) {
////    WriteCompleteFunctor cb(std::bind(&ManagedConnections::KeepAliveCallback,
////                                      this, *itr, args::_1));
////    DLOG(INFO) << "Sending KeepAlive to :" << (*itr).port;
////    transport_->WriteOnManagedConnection("KeepAlive", *itr,
////                                         kDefaultInitialTimeout, cb);
////  }
//  keep_alive_timer_.expires_at(
//      keep_alive_timer_.expires_at() + keep_alive_interval_);
//  keep_alive_timer_.async_wait(
//      std::bind(&ManagedConnections::SendKeepAlive, this, args::_1));
//}
//
//void ManagedConnections::KeepAliveCallback(const Endpoint &endpoint,
//                                          const TransportCondition& result) {
//  DLOG(INFO) << "KeepAliveCallback - called for endpoint : "
//             << endpoint.port  << "result = " << result;
//  if (kSuccess != result) {
//    DLOG(INFO) << "Connection with endpoint " << endpoint.port << "Lost!";
//    RemoveConnection(endpoint);
//    if (lost_functor_)
//      lost_functor_(endpoint);
//  }
//}
//
//Endpoint ManagedConnections::GetOurEndpoint() {
//  if (transport_)
//    return transport_->transport_details().endpoint;
//  return Endpoint();
//}
//
//void ManagedConnections::AddConnection(const Endpoint &peer_endpoint,
//                                      const std::string &/*validation_data*/,
//                                      AddFunctor add_functor) {
//  if (peer_endpoint == GetOurEndpoint()) {
//    if (add_functor)
//      add_functor(kError, "");  //  Cannot connect to own
//    DLOG(ERROR) << "Trying to add to ourself.";
//  }
//  ResponseFunctor response_functor(
//      std::bind(&ManagedConnections::AddConnectionCallback, this, args::_1,
//                args::_2, peer_endpoint, add_functor));
////  transport_->Send(validation_data, peer_endpoint, kDefaultInitialTimeout,
////                   true, response_functor);
//}
//
//TransportCondition ManagedConnections::AcceptConnection(
//  // Do nothing if already connected
//  const Endpoint &peer_endpoint, bool accept) {
//  if (peer_endpoint == GetOurEndpoint()) {
//    DLOG(ERROR) << "Trying to accept to ourself.";
//    return kError;  // Accepting ourself.
//  }
//  if (accept) {
//    // TODO(Prakash) Need call back from rudp
////    transport_->SetConnectionAsManaged(peer_endpoint);
//    if (InsertEndpoint(peer_endpoint))
//      return kSuccess;
//  }
//  return kError;
//}
//
//void ManagedConnections::AddConnectionCallback(TransportCondition result,
//                                              const std::string &response,
//                                              const Endpoint &peer_endpoint,
//                                              AddFunctor add_functor) {
//  if (kSuccess != result) {
//    if (add_functor)
//      add_functor(result, "");
//  }
//
//  if ("Accepted" != response) {
//    DLOG(WARNING) << "AddConnectionCallback failed - received : " << response;
//    if (add_functor)
//      add_functor(kError, "");  // Rejected error code
//    RemoveEndpoint(peer_endpoint);
//  } else {
//    DLOG(INFO) << "AddConnectionCallback success - received : " << response;
//    if (InsertEndpoint(peer_endpoint)) {
//      if (add_functor)
//        add_functor(kSuccess, response);
//    } else {
//      if (add_functor)
//        add_functor(kError, "");
//    }
//  }
//}
//
//void ManagedConnections::RemoveConnection(const Endpoint &peer_endpoint) {
////  transport_->RemoveManagedConnection(peer_endpoint);
//  RemoveEndpoint(peer_endpoint);
//}
//
//
//std::set<Endpoint> ManagedConnections::GetEndpoints() {
//  boost::mutex::scoped_lock lock(mutex_);
//  return connected_endpoints_;
//}
//
//bool ManagedConnections::InsertEndpoint(const Endpoint &peer_endpoint) {
//  boost::mutex::scoped_lock lock(mutex_);
//  auto ret_val = connected_endpoints_.insert(peer_endpoint);
//  return ret_val.second;
//}
//
//void ManagedConnections::RemoveEndpoint(const Endpoint &peer_endpoint) {
//  boost::mutex::scoped_lock lock(mutex_);
//  connected_endpoints_.erase(peer_endpoint);
//}
//
//void ManagedConnections::Send(const Endpoint &/*peer_endpoint*/,
//                             const std::string &/*message*/,
//                             ResponseFunctor /*response_functor*/) {
////  transport_->Send(message, peer_endpoint, kDefaultInitialTimeout,
////                   false, response_functor);
//}
//
//ManagedConnections::~ManagedConnections() {
//  keep_alive_timer_.cancel();
//  transport_->StopListening();
//}

}  // namespace transport

}  // namespace maidsafe
