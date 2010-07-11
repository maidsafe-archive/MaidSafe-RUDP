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
#include "maidsafe/protobuf/transport_message.pb.h"
#include <maidsafe/maidsafe-dht_config.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace transport {

  enum TransportCondition {
  kSucess            = 0,
  kRemoteUnreachable = 1,
  kNoConnection      = 2,
  kNoNetwork         = 3,
  kInvalidIP         = 4,
  kInvalidPort       = 5,
  kInvalidData       = 6,
  kNoSocket          = 7,
  kInvalidAddress    = 8,
  kNoRendezvous      = 9,
  kBehindFirewall    = 10,
  kBindError         = 11,
  kConnectError      = 12,
  kSendError         = 13,
  kAlreadyStarted    = 14,
  kListenError       = 15,
  kThreadResourceErr = 16,
  kError             = 17
  };


  typedef boost::uint32_t connection_id;
  typedef std::string remote_ip, rendezvous_ip;
  typedef boost::uint16_t remote_port;
  // SIGNALS
  typedef bs2::signal<void(const std::string&,
                                      const boost::uint32_t&,
                                      const float&)>SignalMessageReceived;
  typedef bs2::signal<void(const transport::RpcMessage&,
                                      const boost::uint32_t&,
                                      const float &)>SignalRPCRequestReceived;
  typedef bs2::signal<void(const transport::RpcMessage&,
                                      const boost::uint32_t&,
                                      const float &)>SignalRPCResponseReceived;                                            
  typedef bs2::signal<void(const bool &,
                           const std::string&,
                           const boost::uint16_t&)>
                            SignalConnectionDown;
  typedef bs2::signal<void(const boost::uint32_t&, const bool&)> SignalSent;

// UPDATE: this will be replced with a protocol buffer implementation
// using different message types and identifying these on reciept
// at the transport layer.

/*
Protocol (message) implementation (use Google protobufs for serialisation)
_______________________________________________________________
Type          | SubType
===============================================================
Ping          | Request / Response / None
ProxyPing     |
RPC           |
AcceptConnect |
HolePunching  |
_______________________________________________________________
*/
// This is a partially implmented base clase which is inherited by
// the different transports such as UDT / TCP etc.

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
  virtual TransportCondition Send(const TransportMessage &t_mesg,
                                  const std::string &remote_ip,
                                  const boost::uint16_t &remote_port) = 0;
//   virtual TransportCondition SendWithRendezvous(const std::string &data,
//                                   const std::string &remote_ip,
//                                   const boost::uint16_t &remote_port,
//                                   const std::string &rendezvous_ip,
//                                   const boost::uint16_t &rendezvous_port) = 0;
//   virtual TransportCondition SendFile(const std::string &data,
//                                   const std::string &remote_ip,
//                                   const boost::uint16_t &remote_port) = 0;
//   virtual TransportCondition SendFileWithRendezvous(const std::string &data,
//                                   const std::string &remote_ip,
//                                   const boost::uint16_t &remote_port,
//                                   const boost::uint16_t &rendezvous_ip,
//                                   const std::string &rendezvous_port) = 0;

  virtual TransportCondition StartListening(const boost::uint16_t &port,
                                            const std::string &ip) = 0;
// return value is the connection_id or -1 on error
//   virtual boost::uint32_t ManagedConnection(const std::string &remote_ip,
//                                             const boost::uint16_t &remote_port,
//                                             const std::string &rv_ip,
//                                             const boost::uint16_t &rv_port,
//                                             const boost::uint16_t &freq,
//                                             const boost::uint16_t &num_retires,
//                                             const boost::uint16_t &retry_freq)
//                                             = 0;

  virtual TransportCondition CloseConnection(const boost::uint32_t &connection_id) = 0;
  // Close even incoming sockets and exist
  virtual bool ImmediateStop() { stopnow_ = true; }
  // Close on all data recieved and RPC's responded
  virtual bool DeferredStop() { stop_ = true; };
  virtual bool GetPeerAddr(const boost::uint32_t &connection_id,
                           struct sockaddr *peer_address) = 0;
//   virtual bool ConnectionExists(const boost::uint32_t &connection_id) = 0;

//   virtual void peer_info(const boost::uint32_t &connection_id) = 0;
  // accessors
  virtual bool stopped() { return stopped_; }
  virtual bool nat_pnp() { return nat_pnp_; }
  virtual bool upnp() { return upnp_; }
  virtual boost::uint16_t listening_port() = 0;

// mutators
  virtual void set_nat_pnp(bool nat_pnp) { nat_pnp_ = nat_pnp; }
  virtual void set_upnp(bool upnp) { upnp_ = upnp; }
  virtual bool peer_address(struct sockaddr *peer_addr) = 0;
  virtual bool HasReceivedData(const boost::uint32_t &connection_id,
                               boost::int64_t *size) = 0;
  virtual void StartPingRendezvous(
      const bool &directly_connected, const std::string &my_rendezvous_ip,
      const boost::uint16_t &my_rendezvous_port) = 0;
  virtual void StopPingRendezvous() = 0;
  virtual bool CanConnect(const std::string &ip,
                          const boost::uint16_t &port) = 0;
//   virtual bool IsAddressUsable(const boost::uint16_t &local_ip,
//                                const std::string &remote_ip,
//                                const boost::uint16_t &remote_port) = 0;
//   virtual bool IsPortAvailable(const std::string &port) = 0;

public: 
 // CONNECTIONS (method is basically the same as sig.connect().)
  virtual bs2::connection connect_message_recieved(const
                                          SignalMessageReceived::slot_type &
                                          SignalMessageReceived){
    return SignalMessageReceived_.connect(SignalMessageReceived);
  }
  virtual bs2::connection connect_rpc_request_recieved(const
                                          SignalRPCRequestReceived::slot_type &
                                          SignalRPCRequestReceived){
    return SignalRPCRequestReceived_.connect(SignalRPCRequestReceived);
  }
  virtual bs2::connection connect_rpc_response_recieved(const
                                          SignalRPCResponseReceived::slot_type &
                                          SignalRPCResponseReceived){
    return SignalRPCResponseReceived_.connect(SignalRPCResponseReceived);
  }
  virtual bs2::connection connect_connection_down(const
                                           SignalConnectionDown::slot_type &
                                           SignalConnectionDown) {
    return SignalConnectionDown_.connect(SignalConnectionDown);
  }
  virtual bs2::connection connect_sent(const SignalSent::slot_type &SignalSent)
  {
    return SignalSent_.connect(SignalSent);
  }
protected:

  SignalRPCRequestReceived SignalRPCRequestReceived_;
  SignalRPCResponseReceived SignalRPCResponseReceived_;
  SignalMessageReceived    SignalMessageReceived_;
  SignalConnectionDown     SignalConnectionDown_;
  SignalSent               SignalSent_;
  bool upnp_;
  bool nat_pnp_;
  bool rendezvous_;
  bool local_port_only_;
  bool stopped_;
  bool stop_;
  bool stopnow_;
};


}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
