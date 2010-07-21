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

typedef boost::int64_t DataSize;

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
  virtual TransportCondition Send(const TransportMessage &transport_message,
                                  const IP &remote_ip,
                                  const Port &remote_port,
                                  const int &response_timeout,
                                  SocketId *socket_id) = 0;
  virtual TransportCondition SendResponse(
      const TransportMessage &transport_message,
      const SocketId &socket_id) = 0;

  // Create a rendezvous connection - pass server as well
// this will block as we need the result
//   virtual TransportCondition Open(const IP &remote_ip,
//                                    const Port &remote_port,
//                                    const IP &rendezvous_peer_ip,
//                                    const Port &rendezvous_peer_port) = 0;
//                                    
  virtual Port StartListening(const IP &ip, const Port &port) = 0;
// return value is the connection_id or -1 on error
//   virtual ConnectionId ManagedConnection(const IP &remote_ip,
//                                          const Port &remote_port,
//                                          const IP &rendezvous_ip,
//                                          const Port &rendezvous_port,
//                                          const boost::uint16_t &frequency,
//                                          const boost::uint16_t &retry_count,
//                                          const boost::uint16_t &retry_frequency) = 0;
  void StartPingRendezvous(const bool &directly_connected,
                           const IP &rendezvous_ip,
                           const Port &rendezvous_port) {}
  bool CheckIP(const IP &ip) {
    boost::system::error_code ec;
    boost::asio::ip::address::from_string(ip, ec);
    return ec == boost::system::errc::success;
  }
  bool CheckListeningPort(const Port &port) {
    return ((5000 < port) && (port < 65535));
  }
  bool ImmediateStop() { return stop_now_ = true; }
  bool DeferredStop() { return stop_all_ = true; }
  virtual TransportCondition GetPeerAddress(const SocketId &socket_id,
                                            struct sockaddr *peer_address) = 0;
  bool stopped() const { return stopped_; }
  bool nat_pnp() const { return nat_pnp_; }
  bool upnp() const { return upnp_; }
  virtual std::vector<Port> listening_ports() { return listening_ports_; }
  void set_nat_pnp(bool nat_pnp) { nat_pnp_ = nat_pnp; }
  void set_upnp(bool upnp) { upnp_ = upnp; }
 protected:
  Transport() : upnp_(false),
                nat_pnp_(false),
                rendezvous_(false),
                local_port_only_(false),
                stopped_(true),
                stop_all_(false),
                stop_now_(false),
                listening_ports_() {}

  bool upnp_, nat_pnp_, rendezvous_, local_port_only_, stopped_, stop_all_;
  bool stop_now_;
  std::vector<Port> listening_ports_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_API_H_
