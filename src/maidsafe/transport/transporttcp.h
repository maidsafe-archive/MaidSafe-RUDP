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


#ifndef MAIDSAFE_TRANSPORT_TRANSPORTTCP_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTTCP_H_

#include <boost/cstdint.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/asio.hpp>
#include <string>
#include <map>
#include "maidsafe/transport/transport-api.h"
#include "maidsafe/transport/tcpconnection.h"

using boost::asio::ip::tcp;

namespace transport {

class TransportTCP : public Transport {
 public:
  TransportTCP();
  ~TransportTCP();
  TransportType transport_type() { return kTcp; }
  boost::int16_t transport_id() { return transport_id_; }
  void set_transport_id(const boost::int16_t &transport_id) {
    transport_id_ = transport_id;
  }
  int Start(const boost::uint16_t &port);
  int StartLocal(const boost::uint16_t &port);
  int ConnectToSend(const std::string &remote_ip,
                    const boost::uint16_t &remote_port,
                    const std::string &local_ip,
                    const boost::uint16_t &local_port,
                    const std::string &rendezvous_ip,
                    const boost::uint16_t &rendezvous_port,
                    const bool &keep_connection,
                    boost::uint32_t *connection_id);
  int Send(const rpcprotocol::RpcMessage &data,
           const boost::uint32_t &connection_id, const bool &new_socket);
  int Send(const std::string &data, const boost::uint32_t &connection_id,
           const bool &new_socket);
  bool RegisterOnRPCMessage(
      boost::function<void(const rpcprotocol::RpcMessage&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float &)> on_rpcmessage);
  bool RegisterOnMessage(
      boost::function<void(const std::string&,
                           const boost::uint32_t&,
                           const boost::int16_t&,
                           const float &)> on_message);
  bool RegisterOnSend(
      boost::function<void(const boost::uint32_t&, const bool&)> on_send);
  void CloseConnection(const boost::uint32_t &connection_id);
  void Stop();
  bool is_stopped() const { return stop_; }
  bool peer_address(struct sockaddr *peer_addr);
  bool GetPeerAddr(const boost::uint32_t &connection_id,
                   struct sockaddr *peer_address);
  bool ConnectionExists(const boost::uint32_t &connection_id);
  bool HasReceivedData(const boost::uint32_t &connection_id,
                       boost::int64_t *size);
  boost::uint16_t listening_port() { return listening_port_; }
  bool CanConnect(const std::string &ip, const boost::uint16_t &port);
  bool IsPortAvailable(const boost::uint16_t &port);
  // This test for address does not apply for tcp since it always works
  bool IsAddressUsable(const std::string&, const std::string&,
                       const boost::uint16_t&) { return true; }
  // Rendezvous servers are not used in TCP
  void StartPingRendezvous(const bool&, const std::string&,
                           const boost::uint16_t&) {}
  void StopPingRendezvous() {}
  bool RegisterOnServerDown(
      boost::function<void(const bool&,
                           const std::string&,
                           const boost::uint16_t&)>) { return true; }
 private:
  void HandleAccept(const boost::system::error_code &ec);
  void HandleConnSend(const boost::uint32_t &connection_id,
                      const bool &send_once, const bool &rpc_sent,
                      const boost::system::error_code &ec);
  void HandleConnRecv(const std::string &msg,
                      const boost::uint32_t &connection_id,
                      const boost::system::error_code &ec);
  void StartService();
  void HandleStop();
  void HandleStopIOService();
  boost::int16_t transport_id_;
  boost::uint16_t listening_port_, outgoing_port_;
  boost::uint32_t current_id_;
  boost::asio::io_service io_service_;
  tcp::acceptor acceptor_;
  bool stop_;
  boost::function<void(const rpcprotocol::RpcMessage&,
                       const boost::uint32_t&,
                       const boost::int16_t&,
                       const float&)> rpc_message_notifier_;
  boost::function<void(const std::string&,
                       const boost::uint32_t&,
                       const boost::int16_t&,
                       const float&)> message_notifier_;
  boost::function<void(const boost::uint32_t&, const bool&)> send_notifier_;
  boost::shared_ptr<boost::thread> service_routine_;
  std::map<boost::uint32_t, tcpconnection_ptr> connections_;
  boost::mutex conn_mutex_, msg_handler_mutex_, rpcmsg_handler_mutex_;
  boost::mutex send_handler_mutex_;
  boost::asio::ip::tcp::endpoint peer_addr_;
  tcpconnection_ptr new_connection_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTTCP_H_
