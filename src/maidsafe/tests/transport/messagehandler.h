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

#ifndef MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_
#define MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportconditions.h>
#include <list>
#include <set>
#include <string>


namespace  bs2 = boost::signals2;

namespace  rpcprotocol {
class RpcMessage;
}  // namespace  rpcprotocol

namespace transport {

class Signals;
class ManagedEndpointMessage;
class SocketPerformanceStats;

namespace test {

class MessageHandler {
 public:
  typedef std::list< boost::tuple<std::string, SocketId, float> >
      RawMessageList;
  typedef std::list< boost::tuple<rpcprotocol::RpcMessage, SocketId, float> >
      RpcMessageList;
  typedef std::list< boost::tuple<SocketId, TransportCondition> >
      MessageResultList;
  typedef std::list< boost::tuple<ManagedEndpointId, ManagedEndpointMessage> >
      ManagedEndpointMessageList;
  MessageHandler(boost::shared_ptr<Signals> signals,
                 const std::string &message_handler_id,
                 bool display_stats);
  ~MessageHandler();
  void OnMessageReceived(const std::string &message,
                         const int &socket_id,
                         const float &rtt);
  void OnRpcMessageReceived(const rpcprotocol::RpcMessage &rpc_message,
                            const int &socket_id,
                            const float &rtt,
                            bool is_request);
  void OnManagedEndpointReceived(const ManagedEndpointId &managed_endpoint_id,
                                 const ManagedEndpointMessage &message);
  void OnManagedEndpointLost(const ManagedEndpointId &managed_endpoint_id);
  void OnResult(const int &socket_id,
                const TransportCondition &result,
                bool is_send);
  void OnStats(boost::shared_ptr<SocketPerformanceStats> stats);
  void ClearContainers();
  // Getters
  RawMessageList raw_messages();
  RpcMessageList rpc_requests();
  RpcMessageList rpc_responses();
  MessageResultList sent_results();
  MessageResultList received_results();
  ManagedEndpointMessageList managed_endpoint_messages();
  std::set<ManagedEndpointId> managed_endpoint_ids();
  std::set<ManagedEndpointId> lost_managed_endpoint_ids();

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  boost::shared_ptr<Signals> signals_;
  RawMessageList raw_messages_;
  RpcMessageList rpc_requests_, rpc_responses_;
  MessageResultList sent_results_, received_results_;
  ManagedEndpointMessageList managed_endpoint_messages_;
  std::set<ManagedEndpointId> managed_endpoint_ids_;
  std::set<ManagedEndpointId> lost_managed_endpoint_ids_;
  std::string message_handler_id_;
  boost::mutex mutex_;
  bs2::connection message_received_connection_;
  bs2::connection rpc_request_received_connection_;
  bs2::connection rpc_response_received_connection_;
  bs2::connection managed_endpoint_received_connection_;
  bs2::connection managed_endpoint_lost_connection_;
  bs2::connection send_connection_;
  bs2::connection receive_connection_;
  bs2::connection stats_connection_;
};

}  // namespace test

}  // namespace transport

#endif  // MAIDSAFE_TESTS_TRANSPORT_MESSAGEHANDLER_H_

