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
#ifndef MAIDSAFE_TRANSPORT_MANAGED_CONNECTION_H_
#define MAIDSAFE_TRANSPORT_MANAGED_CONNECTION_H_

#include <set>
#include <string>

#include "boost/asio/io_service.hpp"
#include "boost/asio/deadline_timer.hpp"
#include "boost/signals2.hpp"

#include "maidsafe/common/asio_service.h"

#include "maidsafe/transport/rudp_transport.h"
#include "maidsafe/transport/transport.h"

#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 300
# error This API is not compatible with the installed library.\
  Please update the maidsafe_transport library.
#endif

namespace maidsafe {

namespace transport {

typedef std::function<void (const TransportCondition&)> AddFunctor;
typedef std::function<void (const Endpoint&)> LostFunctor;
typedef std::function<void (const TransportCondition&, const std::string&)>
    ResponseFunctor;


class ManagedConnection {
 public:
  ManagedConnection();

  ~ManagedConnection();

  TransportCondition Init(uint8_t thread_count);

  Endpoint GetOurEndpoint();

  // Try to open a connection with peer_endpoint.
  void AddConnection(const Endpoint &peer_endpoint,
                     const std::string &validation_data,
                     AddFunctor add_functor);

  // Should be called after validating new connection request
  TransportCondition AcceptConnection(const Endpoint &peer_endpoint,
                                      bool accept);

  void RemoveConnection(const Endpoint &peer_endpoint);

  void ConnectionLost(LostFunctor lost_functor);

  void Send(const Endpoint &peer_endpoint, const std::string &message,
            ResponseFunctor response_functor);

  // Only fires Signal on request from other side. (not on response)
  OnMessageReceived on_message_received();

 private:
  void AddConnectionCallback(TransportCondition result,
                             const std::string &response,
                             const Endpoint &peer_endpoint,
                             AddFunctor add_functor);
  void SendKeepAlive(const boost::system::error_code& ec);
  void KeepAliveCallback(const Endpoint &endpoint,
                         const TransportCondition& result);

  std::set<Endpoint> GetEndpoints();
  bool InsertEndpoint(const Endpoint &peer_endpoint);
  void RemoveEndpoint(const Endpoint &peer_endpoint);


  std::shared_ptr<AsioService> asio_services_;
  bptime::time_duration keep_alive_interval_;
  boost::asio::deadline_timer keep_alive_timer_;
  std::shared_ptr<RudpTransport> transport_;
  std::set<Endpoint> connected_endpoints_;
  LostFunctor lost_functor_;
  boost::mutex mutex_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_MANAGED_CONNECTION_H_
