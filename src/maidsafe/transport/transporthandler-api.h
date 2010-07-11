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

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTHANDLER_API_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTHANDLER_API_H_

#include <maidsafe/maidsafe-dht_config.h>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <string>
#include <map>
#include <utility>
#include <list>
#include "maidsafe/protobuf/transport_message.pb.h"

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif



namespace transport {

class Transport;

/**
* @class TransportHandler
* A class to manage all Transports
*   Can only safely register 32767 Transports before transport_id might be reused.
*/
class TransportHandler {
 public:
  TransportHandler();
  ~TransportHandler();

  /**
  * Register a new transport
  *  @param transport_object pointer to transport to be registered
  *  @param transport_id The id that will be assigned to the transport
  *  @return
  */
  int Register(transport::Transport *transport_object,
               boost::int16_t *transport_id);

  /**
  * Unregister a transport
  *  @param transport_id The id of the transport to unregister
  */
  void Remove(const boost::int16_t &transport_id);

  /** Retrieve a Transport pointer
  * @param transport_id The id of the transport to retrieve
  * @return Transport pointer or NULL
  */
  Transport* Get(const boost::int16_t &transport_id);

  /** Start a transport.
  *  @param port - The port the transport has been given
  *  @param transport_id - The assigned id of the transport
  *  @see - IsPortAvailable, Register
  *  @return -
  */
  int Start(const boost::uint16_t &port, const boost::int16_t &transport_id);

  /** Stop a transport.  Transport still remains, just not running
  *  @see - Remove
  *  @param transport_id - The assigned id of the transport
  */
  void Stop(const boost::int16_t &transport_id);

  /** Stops all registered transports.
  */
  void StopAll();

  /** Declares whether all transports are stopped or not
  */
  bool AllAreStopped();

  /** Hands back the ID of a registered and running UDT Transport
  *  @param transport_type Type of transports to return
  *  @return list of all transport ids where the transport type matches
  *  transport_type in FIFO order
  */
  std::list<boost::int16_t> GetTransportIDByType(TransportType transport_type);

  /** Declares whether the Transport corrosponding to transport_object is already registered
  *  @param transport_object - pointer to transport to be checked
  *  @return - True if Transport is already registered, false otherwise
  */
  bool IsRegistered(transport::Transport *transport_object);

  bool IsAddressUsable(const std::string &local_ip,
                       const std::string &remote_ip,
                       const boost::uint16_t &remote_port,
                       const boost::int16_t &transport_id);
  bool IsPortAvailable(const boost::uint16_t &port,
                       const boost::int16_t &transport_id);
//   bool RegisterOnMessage(
//       boost::function<void(const std::string&,
//                            const boost::uint32_t&,
//                            const boost::int16_t&,
//                            const float &)> on_message);
//   bool RegisterOnRPCMessage(
//       boost::function<void(const rpcprotocol::RpcMessage&,
//                            const boost::uint32_t&,
//                            const boost::int16_t&,
//                            const float &)> on_rpcmessage);
//   bool RegisterOnSend(
//       boost::function<void(const boost::uint32_t&, const bool&)> on_send);
//   bool RegisterOnServerDown(
//       boost::function<void(const bool&,
//                            const std::string&,
//                            const boost::uint16_t&)> on_server_down);
  int ConnectToSend(const std::string &remote_ip,
                    const boost::uint16_t &remote_port,
                    const std::string &local_ip,
                    const boost::uint16_t &local_port,
                    const std::string &rendezvous_ip,
                    const boost::uint16_t &rendezvous_port,
                    const bool &keep_connection,
                    boost::uint32_t *connection_id,
                    const boost::int16_t &transport_id);
  int Send(const TransportMessage &t_mesg,
           const boost::uint32_t &connection_id, const bool &new_socket,
           const boost::int16_t &transport_id);
  int Send(const std::string &data, const boost::uint32_t &connection_id,
           const bool &new_socket, const boost::int16_t &transport_id);
  int StartLocal(const boost::uint16_t &port,
                 const boost::int16_t &transport_id);
  void CloseConnection(const boost::uint32_t &connection_id,
                       const boost::int16_t &transport_id);
  bool is_stopped(const boost::int16_t &transport_id);
  bool peer_address(const boost::int16_t &transport_id,
                    struct sockaddr* addr);
  bool GetPeerAddr(const boost::uint32_t &connection_id,
                   const boost::int16_t &transport_id,
                   struct sockaddr *peer_address);
  bool ConnectionExists(const boost::uint32_t &connection_id,
                        const boost::int16_t &transport_id);
  bool HasReceivedData(const boost::uint32_t &connection_id,
                       const boost::int16_t &transport_id,
                       boost::int64_t *size);
  boost::uint16_t listening_port(const boost::int16_t &transport_id);
  void StartPingRendezvous(const bool &directly_connected,
                           const std::string &my_rendezvous_ip,
                           const boost::uint16_t &my_rendezvous_port,
                           const boost::int16_t &transport_id);
  void StopPingRendezvous();
  bool CanConnect(const std::string &ip, const boost::uint16_t &port,
                  const boost::int16_t &transport_id);
//   void OnRPCMessage(const transport::RpcMessage &request,
//                     const boost::uint32_t &connection_id,
//                     const boost::int16_t &transport_id, const float &rtt);
//   void OnMessage(const std::string &request,
//                  const boost::uint32_t &connection_id,
//                  const boost::int16_t &transport_id, const float &rtt);
//   void OnServerDown(const bool &dead_server, const std::string &ip,
//                     const boost::uint16_t &port);
  void OnSend(const boost::uint32_t &connection_id, const bool &success);
 private:
  TransportHandler& operator=(const TransportHandler&);
  TransportHandler(TransportHandler&);
  bool Registered(transport::Transport* transport_object);
  std::map < boost::int16_t, transport::Transport* > transports_;
  boost::int16_t next_id_;
  boost::int16_t started_count_;
//   boost::function<void(const rpcprotocol::RpcMessage&,
//                        const boost::uint32_t&,
//                        const boost::int16_t&,
//                        const float&)> rpc_message_notifier_;
//   boost::function<void(const std::string&,
//                        const boost::uint32_t&,
//                        const boost::int16_t&,
//                        const float&)> message_notifier_;
//   boost::function<void(const bool&,
//                        const std::string&,
//                        const boost::uint16_t&)> server_down_notifier_;
//   boost::function<void(const boost::uint32_t&, const bool&)> send_notifier_;
public: // SIGNALS
  typedef bs2::signal<void(const std::string&,
                                      const boost::uint32_t&,
                                      const boost::int16_t&,
                                      const float&)>SignalMessageReceived;
  typedef bs2::signal<void(const transport::RpcMessage&,
                                      const boost::uint32_t&,
                                      const float &)>SignalRPCRequestReceived;                                     
  typedef bs2::signal<void(const transport::RpcMessage&,
                                      const boost::uint32_t&,
                                      const float &)>SignalRPCResponseReceived;
  typedef bs2::signal<void(const bool &,
                           const std::string&,
                           const boost::uint16_t)>
                            SignalConnectionDown;
  typedef bs2::signal<void(const boost::uint32_t&, const bool&)> SignalSent;
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
  virtual  bs2::connection connect_connection_down(const
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


};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTHANDLER_API_H_
