/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#include "maidsafe/rudp/managed_connections.h"

#include <functional>
#include <iterator>

#include "maidsafe/rudp/endpoint.h"
#include "maidsafe/rudp/log.h"
#include "maidsafe/rudp/return_codes.h"
#include "maidsafe/rudp/transport.h"
#include "maidsafe/rudp/utils.h"

namespace args = std::placeholders;
namespace asio = boost::asio;
namespace bptime = boost::posix_time;
namespace ip = asio::ip;

namespace maidsafe {

namespace rudp {

namespace {
const int kMaxTransports(10);
}  // unnamed namespace

ManagedConnections::ManagedConnections()
    : asio_service_(new AsioService),
      message_received_functor_(),
      connection_lost_functor_(),
      keep_alive_interval_(bptime::seconds(20)),
      transports_(),
      connection_map_(),
      shared_mutex_() {}

Endpoint ManagedConnections::Bootstrap(
    const std::vector<Endpoint> &bootstrap_endpoints,
    MessageReceivedFunctor message_received_functor,
    ConnectionLostFunctor connection_lost_functor) {
  {
    SharedLock shared_lock(shared_mutex_);
    if (!connection_map_.empty()) {
      DLOG(ERROR) << "Already bootstrapped.";
      return Endpoint();
    }
    BOOST_ASSERT(transports_.empty());
  }

  Endpoint new_endpoint(StartNewTransport(bootstrap_endpoints));
  if (!IsValid(new_endpoint)) {
    DLOG(ERROR) << "Failed to bootstrap managed connections.";
    return Endpoint();
  }

  message_received_functor_ = message_received_functor;
  connection_lost_functor_ = connection_lost_functor;
  return new_endpoint;
}

Endpoint ManagedConnections::StartNewTransport(
    std::vector<Endpoint> bootstrap_endpoints) {
  TransportPtr transport(new Transport(asio_service_->service()));

  bool bootstrapping(!bootstrap_endpoints.empty());
  if (!bootstrapping) {
    bootstrap_endpoints.reserve(kMaxTransports * Transport::kMaxConnections());
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        connection_map_.begin(),
        connection_map_.end(),
        [&bootstrap_endpoints](const ConnectionMap::value_type &entry) {
      bootstrap_endpoints.push_back(entry.first);
    });
  }

  Endpoint chosen_endpoint(transport->Bootstrap(bootstrap_endpoints));
  if (!IsValid(chosen_endpoint)) {
    SharedLock shared_lock(shared_mutex_);
    DLOG(WARNING) << "Failed to start a new Transport.  "
                  << connection_map_.size() << " currently running.";
    return Endpoint();
  }

  UniqueLock unique_lock(shared_mutex_);
  transports_.push_back(transport);
  if (bootstrapping)
    connection_map_.insert(std::make_pair(chosen_endpoint, transport));
  return chosen_endpoint;
}

int ManagedConnections::GetAvailableEndpoint(Endpoint *endpoint) {
  if (!endpoint) {
    DLOG(ERROR) << "Null parameter passed.";
    return kNullParameter;
  }

  size_t transports_size(0);
  {
    SharedLock shared_lock(shared_mutex_);
    transports_size = transports_.size();
  }

  if (transports_size < kMaxTransports) {
    if (transports_size == 0) {
      DLOG(ERROR) << "No running Transports.";
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
    uint32_t least_connections(Transport::kMaxConnections());
    Endpoint chosen_endpoint;
    SharedLock shared_lock(shared_mutex_);
    std::for_each(
        transports_.begin(),
        transports_.end(),
        [&least_connections, &chosen_endpoint] (const TransportPtr &transport) {
      if (transport->connected_endpoints_size() < least_connections) {
        least_connections = transport->connected_endpoints_size();
        chosen_endpoint = transport->this_endpoint();
      }
    });

    if (!IsValid(chosen_endpoint)) {
      DLOG(ERROR) << "All Transports are full.";
      return kFull;
    }

    *endpoint = chosen_endpoint;
    return kSuccess;
  }
}

int ManagedConnections::Add(const Endpoint &this_endpoint,
                            const Endpoint &peer_endpoint,
                            const std::string &validation_data) {
  std::vector<TransportPtr>::iterator itr;
  {
    SharedLock shared_lock(shared_mutex_);
    itr = std::find_if(transports_.begin(),
                       transports_.end(),
                       [&this_endpoint] (const TransportPtr &transport) {
      return transport->this_endpoint() == this_endpoint;
    });
    if (itr == transports_.end()) {
      DLOG(ERROR) << "No Transports have endpoint " << this_endpoint;
      return kInvalidTransport;
    }

    if (connection_map_.find(peer_endpoint) != connection_map_.end()) {
      DLOG(ERROR) << "A managed connection to " << peer_endpoint
                  << " already exists.";
      return kConnectionAlreadyExists;
    }
  }

  (*itr)->RendezvousConnect(peer_endpoint, validation_data);
  return kSuccess;
}

void ManagedConnections::Remove(const Endpoint &/*peer_endpoint*/) {
//  SharedLock shared_lock(shared_mutex_);
//  for (auto itr(connection_map_.begin()); itr != connection_map_.end(); ++itr) {
//    int result((*itr)->CloseConnection(peer_endpoint));
//    if (result == kSuccess) {
//      return;
//    } else if (result != kInvalidConnection) {
//      DLOG(ERROR) << "Failed to close connection to " << peer_endpoint;
//    }
//  }
}

int ManagedConnections::Send(const Endpoint &/*peer_endpoint*/,
                             const std::string &/*message*/) const {
//  SharedLock shared_lock(shared_mutex_);
//  for (auto itr(connection_map_.begin()); itr != connection_map_.end(); ++itr) {
//    int result((*itr)->Send(peer_endpoint, message));
//    if (result == kSuccess) {
//      return;
//    } else if (result != kInvalidConnection) {
//      DLOG(ERROR) << "Failed to send message to " << peer_endpoint;
//    }
//  }
                                                                             return 0;
}

void ManagedConnections::Ping(const Endpoint &/*peer_endpoint*/) const {
}






//ReturnCode ManagedConnections::Init(uint8_t thread_count) {
//  // TODO(Prakash) Use random port to start
//  std::pair<uint16_t, uint16_t> port_range(8000, 9000);
//  asio_services_->Start(thread_count);
//  ReturnCode result(kError);
//  transport_.reset(new Transport(asio_services_->service()));
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
//                                          const ReturnCode& result) {
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
//ReturnCode ManagedConnections::AcceptConnection(
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
//void ManagedConnections::AddConnectionCallback(ReturnCode result,
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

}  // namespace rudp

}  // namespace maidsafe
