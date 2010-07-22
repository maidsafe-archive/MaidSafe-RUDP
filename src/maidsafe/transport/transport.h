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
 * NOTE: This API is unlikely to have any breaking changes applied.  However,  *
 *       it should not be regarded as a final API until this notice is removed.*
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_API_H_

#include <boost/function.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/signals-inl.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace transport {

enum TransportCondition {
  kSuccess = 0,
  kError = 1,
  kRemoteUnreachable = 2,
  kNoConnection = 3,
  kNoNetwork = 4,
  kInvalidIP = 5,
  kInvalidPort = 6,
  kInvalidData = 7,
  kNoSocket = 8,
  kInvalidAddress = 9,
  kNoRendezvous = 10,
  kBehindFirewall = 11,
  kBindError = 12,
  kConnectError = 13,
  kAlreadyStarted = 14,
  kListenError = 15,
  kThreadResourceError = 16,
  kCloseSocketError = 17,
  kSendUdtFailure = 18,
  kSendTimeout = 19,
  kSendParseFailure = 20,
  kSendSizeFailure = 21,
  kReceiveUdtFailure = 22,
  kReceiveTimeout = 23,
  kReceiveParseFailure = 24,
  kReceiveSizeFailure = 25
};

struct SocketPerformanceStats;

typedef bs2::signal<void(const std::string&,
                         const SocketId&,
                         const float&)> SignalMessageReceived;
typedef bs2::signal<void(const transport::RpcMessage&,
                         const SocketId&,
                         const float&)> SignalRpcRequestReceived,
                                        SignalRpcResponseReceived;
typedef bs2::signal<void(const ManagedEndpointId&)> SignalLostManagedEndpoint;
typedef bs2::signal<void(const SocketId&,
                         const TransportCondition&)> SignalSend, SignalReceive;
typedef bs2::signal<void(boost::shared_ptr<SocketPerformanceStats>)>
                            SignalStats;

typedef boost::int64_t DataSize;

inline bool ValidIP(const IP &ip) {
  boost::system::error_code ec;
  boost::asio::ip::address::from_string(ip, ec);
  return ec == boost::system::errc::success;
}

inline bool ValidPort(const Port &port) {
  return ((5000 < port) && (port < 65535));
}

struct SocketPerformanceStats {
 public:
  virtual ~SocketPerformanceStats() {}
};

class Transport : public Signals {
  /* Transport API, all transports require to inherit these public methods
  *   as well as the signals (inherited). Slots must be defined and connected.
  *   Common parameters listed below
  *  @param port - The port the transport has been given
  *  @param remote_ip - Remote IP adress in dotted decimal i.e. 123.123.123.123
  *  @param remote_port - Remote port [integer]
  *  @param rendezvous_ip - if required (otherwise pass "") to traverse NAT's
  *  @param rendezvous_port - if required (otherwise pass 0) to traverse NAT's
  *  @param conn_id - where connections are maintained (or pseudo maintained)
  *                   the connection identifier is passed up and used to
  *                   respond to the sender on the same IP/PORT (or socket
  *                   in connection oriented implementations such as UDT or TCP)
  */
 public:
  virtual ~Transport() {}
  virtual Port StartListening(const IP &ip, const Port &port) = 0;
  virtual bool StopListening(const Port &port) = 0;
  virtual bool StopAllListening() = 0;
  virtual void Send(const TransportMessage &transport_message,
                    const IP &remote_ip,
                    const Port &remote_port,
                    const int &response_timeout) = 0;
  virtual void SendResponse(const TransportMessage &transport_message,
                            const SocketId &socket_id) = 0;
  virtual void SendFile(fs::path &path, const SocketId &socket_id) = 0;
  virtual ManagedEndpointId AddManagedEndpoint(
      const IP &remote_ip,
      const Port &remote_port,
      const IP &rendezvous_ip,
      const Port &rendezvous_port,
      const boost::uint16_t &frequency,
      const boost::uint16_t &retry_count,
      const boost::uint16_t &retry_frequency);
  virtual TransportCondition RemoveManagedEndpoint(
      const ManagedEndpointId &managed_endpoint_id);
  std::vector<Port> listening_ports() { return listening_ports_; }
  // Connect to signals
  bs2::connection ConnectMessageReceived(
      const SignalMessageReceived::slot_type &message_received_slot) {
    return signal_message_received_.connect(message_received_slot);
  }
  bs2::connection ConnectRpcRequestReceived(
      const SignalRpcRequestReceived::slot_type &rpc_request_received_slot) {
    return signal_rpc_request_received_.connect(rpc_request_received_slot);
  }
  bs2::connection ConnectRpcResponseReceived(
      const SignalRpcResponseReceived::slot_type &rpc_response_received_slot) {
    return signal_rpc_response_received_.connect(rpc_response_received_slot);
  }
  bs2::connection ConnectConnectionDown(
      const SignalLostManagedEndpoint::slot_type &lost_managed_endpoint_slot) {
    return signal_lost_managed_endpoint_.connect(lost_managed_endpoint_slot);
  }
  bs2::connection ConnectSend(const SignalSend::slot_type &send_slot) {
    return signal_send_.connect(send_slot);
  }
  bs2::connection ConnectReceive(const SignalReceive::slot_type &receive_slot) {
    return signal_receive_.connect(receive_slot);
  }
  bs2::connection ConnectStats(const SignalStats::slot_type &stats_slot) {
    return signal_stats_.connect(stats_slot);
  }
 protected:
  Transport() : listening_ports_(),
                signal_message_received_(),
                signal_rpc_request_received_(),
                signal_rpc_response_received_(),
                signal_lost_managed_endpoint_(),
                signal_send_(),
                signal_receive_(),
                signal_stats_() {}
  std::vector<Port> listening_ports_;
  SignalMessageReceived signal_message_received_;
  SignalRpcRequestReceived signal_rpc_request_received_;
  SignalRpcResponseReceived signal_rpc_response_received_;
  SignalLostManagedEndpoint signal_lost_managed_endpoint_;
  SignalSend signal_send_;
  SignalReceive signal_receive_;
  SignalStats signal_stats_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
