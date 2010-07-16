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
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace transport {

enum TransportCondition {
  kSuccess = 0,
  kError = -1,
  kRemoteUnreachable = -2,
  kNoConnection = -3,
  kNoNetwork = -4,
  kInvalidIP = -5,
  kInvalidPort = -6,
  kInvalidData = -7,
  kNoSocket = -8,
  kInvalidAddress = -9,
  kNoRendezvous = -10,
  kBehindFirewall = -11,
  kBindError = -12,
  kConnectError = -13,
  kSendError = -14,
  kAlreadyStarted = -15,
  kListenError = -16,
  kThreadResourceError = -17,
  kCloseSocketError = -18
};

typedef bs2::signal<void(const std::string&,
                         const ConnectionId&,
                         const float&)> SignalMessageReceived;
typedef bs2::signal<void(const transport::RpcMessage&,
                         const ConnectionId&,
                         const float&)> SignalRpcRequestReceived,
                                        SignalRpcResponseReceived;
typedef bs2::signal<void(const bool&,
                         const IP&,
                         const Port&)> SignalConnectionDown;
typedef bs2::signal<void(const ConnectionId&, const bool&)> SignalSent;

typedef boost::int64_t DataSize;

class Transport {
  /* Transport API, all transports require to inherit these public methods
  *   as well as the signals. Slots must be defined and connected. Common
  *   parameters listed below
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
  virtual TransportCondition Send(const TransportMessage &transport_message,
                                  const IP &remote_ip,
                                  const Port &remote_port,
                                  const int &response_timeout) = 0;
  virtual TransportCondition Send(const TransportMessage &transport_message,
                                  const SocketId &socket_id) = 0;
//   virtual TransportCondition SendWithRendezvous(const std::string &data,
//                                   const IP &remote_ip,
//                                   const Port &remote_port,
//                                   const IP &rendezvous_ip,
//                                   const Port &rendezvous_port) = 0;
//   virtual TransportCondition SendFile(const std::string &data,
//                                   const IP &remote_ip,
//                                   const Port &remote_port) = 0;
//   virtual TransportCondition SendFileWithRendezvous(const std::string &data,
//                                   const IP &remote_ip,
//                                   const Port &remote_port,
//                                   const IP &rendezvous_ip,
//                                   const Port &rendezvous_port) = 0;

  virtual TransportCondition StartListening(const IP &ip, const Port &port) = 0;
// return value is the connection_id or -1 on error
//   virtual ConnectionId ManagedConnection(const IP &remote_ip,
//                                          const Port &remote_port,
//                                          const IP &rendezvous_ip,
//                                          const Port &rendezvous_port,
//                                          const boost::uint16_t &frequency,
//                                          const boost::uint16_t &retry_count,
//                                          const boost::uint16_t &retry_frequency) = 0;

  virtual TransportCondition CloseConnection(
      const ConnectionId &connection_id) = 0;
  // Close even incoming sockets and exit
  bool ImmediateStop() { stop_now_ = true; }
  // Close on all data received and RPCs responded
  bool DeferredStop() { stop_ = true; }
  virtual TransportCondition GetPeerAddress(const SocketId &socket_id,
                                            struct sockaddr *peer_address) = 0;
//   virtual bool ConnectionExists(const ConnectionId &connection_id) = 0;
//   virtual void peer_info(const ConnectionId &connection_id) = 0;
  bool stopped() const { return stopped_; }
  bool nat_pnp() const { return nat_pnp_; }
  bool upnp() const { return upnp_; }
  virtual Port listening_port() const = 0;

  void set_nat_pnp(bool nat_pnp) { nat_pnp_ = nat_pnp; }
  void set_upnp(bool upnp) { upnp_ = upnp; }
  virtual bool HasReceivedData(const ConnectionId &connection_id,
                               DataSize *size) = 0;
  virtual void StartPingRendezvous(bool directly_connected,
                                   const IP &my_rendezvous_ip,
                                   const Port &my_rendezvous_port) = 0;
  virtual void StopPingRendezvous() = 0;
  virtual bool CanConnect(const IP &ip, const Port &port) = 0;
//   virtual bool IsAddressUsable(const IP &local_ip,
//                                const IP &remote_ip,
//                                const Port &remote_port) = 0;
//   virtual bool IsPortAvailable(const std::string &port) = 0;

 // CONNECTIONS (method is basically the same as sig.connect().)
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
      const SignalConnectionDown::slot_type &connection_down_slot) {
    return signal_connection_down_.connect(connection_down_slot);
  }
  bs2::connection ConnectSent(const SignalSent::slot_type &sent_slot) {
    return signal_sent_.connect(sent_slot);
  }

 protected:
  Transport() : signal_rpc_request_received_(),
                signal_rpc_response_received_(),
                signal_message_received_(),
                signal_connection_down_(),
                signal_sent_(),
                upnp_(false),
                nat_pnp_(false),
                rendezvous_(false),
                local_port_only_(false),
                stopped_(true),
                stop_(false),
                stop_now_(false) {}
  SignalRpcRequestReceived signal_rpc_request_received_;
  SignalRpcResponseReceived signal_rpc_response_received_;
  SignalMessageReceived signal_message_received_;
  SignalConnectionDown signal_connection_down_;
  SignalSent signal_sent_;
  bool upnp_, nat_pnp_, rendezvous_, local_port_only_, stopped_, stop_;
  bool stop_now_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
