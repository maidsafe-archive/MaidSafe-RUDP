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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_

#include <boost/signals2/signal.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportconditions.h>


namespace  bs2 = boost::signals2;

namespace transport {

struct SocketPerformanceStats;
class TransportUDT;
class TransportTCP;
class RpcMessage;

typedef bs2::signal<void(const std::string&,
                         const SocketId&,
                         const float&)> OnMessageReceived;
typedef bs2::signal<void(const rpcprotocol::RpcMessage&,
                         const SocketId&,
                         const float&)> OnRpcRequestReceived,
                                        OnRpcResponseReceived;
typedef bs2::signal<void(const ManagedEndpointId&)> OnLostManagedEndpoint;
typedef bs2::signal<void(const SocketId&,
                         const TransportCondition&)> OnSend, OnReceive;
typedef bs2::signal<void(boost::shared_ptr<SocketPerformanceStats>)> OnStats;

class Signals {
 public:
  Signals() : on_message_received_(),
              on_rpc_request_received_(),
              on_rpc_response_received_(),
              on_lost_managed_endpoint_(),
              on_send_(),
              on_receive_(),
              on_stats_() {}
  ~Signals() {}

  // OnMessageReceived =========================================================
  bs2::connection ConnectOnMessageReceived(
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(slot);
  }

  bs2::connection GroupConnectOnMessageReceived(
      const int &group,
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(group, slot);
  }

  // OnRpcRequestReceived ======================================================
  bs2::connection ConnectOnRpcRequestReceived(
      const OnRpcRequestReceived::slot_type &slot) {
    return on_rpc_request_received_.connect(slot);
  }

  bs2::connection GroupConnectOnRpcRequestReceived(
      const int &group,
      const OnRpcRequestReceived::slot_type &slot) {
    return on_rpc_request_received_.connect(group, slot);
  }

  // OnRpcResponseReceived =====================================================
  bs2::connection ConnectOnRpcResponseReceived(
      const OnRpcResponseReceived::slot_type &slot) {
    return on_rpc_response_received_.connect(slot);
  }

  bs2::connection GroupConnectOnRpcResponseReceived(
      const int &group,
      const OnRpcResponseReceived::slot_type &slot) {
    return on_rpc_response_received_.connect(group, slot);
  }

  // OnLostManagedEndpoint =====================================================
  bs2::connection ConnectOnLostManagedEndpoint(
      const OnLostManagedEndpoint::slot_type &slot) {
    return on_lost_managed_endpoint_.connect(slot);
  }

  bs2::connection GroupConnectOnLostManagedEndpoint(
      const int &group,
      const OnLostManagedEndpoint::slot_type &slot) {
    return on_lost_managed_endpoint_.connect(group, slot);
  }

  // OnSend ====================================================================
  bs2::connection ConnectOnSend(const OnSend::slot_type &slot) {
    return on_send_.connect(slot);
  }

  bs2::connection GroupConnectOnSend(const int &group,
                                     const OnSend::slot_type &slot) {
    return on_send_.connect(group, slot);
  }

  // OnReceive =================================================================
  bs2::connection ConnectOnReceive(const OnReceive::slot_type &slot) {
    return on_receive_.connect(slot);
  }

  bs2::connection GroupConnectOnReceive(const int &group,
                                        const OnReceive::slot_type &slot) {
    return on_receive_.connect(group, slot);
  }

  // OnStats ===================================================================
  bs2::connection ConnectOnStats(const OnStats::slot_type &slot) {
    return on_stats_.connect(slot);
  }

  bs2::connection GroupConnectOnStats(const int &group,
                                      const OnStats::slot_type &slot) {
    return on_stats_.connect(group, slot);
  }

  friend class TransportUDT;
  friend class TransportTCP;
 private:
  OnMessageReceived on_message_received_;
  OnRpcRequestReceived on_rpc_request_received_;
  OnRpcResponseReceived on_rpc_response_received_;
  OnLostManagedEndpoint on_lost_managed_endpoint_;
  OnSend on_send_;
  OnReceive on_receive_;
  OnStats on_stats_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTSIGNALS_H_

