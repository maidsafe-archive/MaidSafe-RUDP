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

#ifndef MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/thread.hpp>
#include <boost/detail/atomic_count.hpp>
#include <maidsafe/transport/transport-api.h>
#include <list>
#include <map>
#include <set>
#include <string>


namespace transport {

class HolePunchingMessage;
struct IncomingMessages;

typedef int UdtSocketId;

struct IncomingData {
  explicit IncomingData(const UdtSocketId &udt_socket_id)
      : udt_socket_id(udt_socket_id), expect_size(0), received_size(0), data(NULL),
        cumulative_rtt(0.0), observations(0) {}
  IncomingData()
      : udt_socket_id(), expect_size(0), received_size(0), data(NULL),
        cumulative_rtt(0.0), observations(0) {}
  UdtSocketId udt_socket_id;
  DataSize expect_size;
  DataSize received_size;
  boost::shared_array<char> data;
  double cumulative_rtt;
  boost::uint32_t observations;
};

struct OutgoingData {
  OutgoingData()
      : udt_socket_id(), data_size(0), data_sent(0), data(NULL), sent_size(false),
        connection_id(0), is_rpc(false) {}
  OutgoingData(UdtSocketId udt_socket_id, DataSize data_size,
               ConnectionId connection_id, bool is_rpc)
      : udt_socket_id(udt_socket_id), data_size(data_size), data_sent(0),
        data(new char[data_size]), sent_size(false),
        connection_id(connection_id), is_rpc(is_rpc) {}
  UdtSocketId udt_socket_id;
  DataSize data_size;
  DataSize data_sent;
  boost::shared_array<char> data;
  bool sent_size;
  ConnectionId connection_id;
  bool is_rpc;
};

class TransportUDT : public Transport {
 public:
  enum DataType { kString, kFile };
  TransportUDT();
  ~TransportUDT();
  static void CleanUp();
  // This method is used to create a new socket and send data.  It assumes a
  // response is expected if timeout is > 0, and keeps the socket alive
  // for timeout (in milliseconds)
  TransportCondition Send(const TransportMessage &transport_message,
                          const IP &remote_ip,
                          const Port &remote_port,
                          const int &response_timeout);
  TransportCondition Send(const TransportMessage &transport_message,
                          const SocketId &socket_id);
  bool CheckIP(const IP &ip);
  bool CheckPort(const Port &port);
  bool CheckSocketSend(const SocketId &udt_socket_id);
  bool CheckSocketReceive(const SocketId &udt_socket_id);
  TransportCondition StartListening(const IP &ip, const Port &port);
/*  int ConnectToSend(const IP &remote_ip,
                    const Port &remote_port,
                    const IP &local_ip,
                    const Port &local_port,
                    const IP &rendezvous_ip,
                    const Port &rendezvous_port,
                    const bool &keep_connection,
                    ConnectionId *connection_id);
  int Send(const rpcprotocol::RpcMessage &data,
           const ConnectionId &connection_id, const bool &new_socket);
  int Send(const TransportMessage &t_mesg, const ConnectionId &connection_id,
           const bool &new_socket);*/

  int StartLocal(const Port &port);


//   bool RegisterOnRPCMessage(
//       boost::function<void(const rpcprotocol::RpcMessage&,
//                            const ConnectionId&,
//                            const boost::int16_t&,
//                            const float &)> on_rpcmessage);
//   bool RegisterOnMessage(
//       boost::function<void(const std::string&,
//                            const ConnectionId&,
//                            const boost::int16_t&,
//                            const float &)> on_message);
//   bool RegisterOnSend(
//       boost::function<void(const ConnectionId&,
//                            const bool&)> on_send);
//   bool RegisterOnServerDown(
//       boost::function<void(const bool&,
//                            const IP&,
//                            const Port&)> on_server_down);
  TransportCondition CloseConnection(const ConnectionId &connection_id);
  void Stop();
  bool is_stopped() const { return stop_; }
  TransportCondition GetPeerAddress(const SocketId &socket_id,
                                    struct sockaddr *peer_address);
  bool ConnectionExists(const ConnectionId &connection_id);
  bool HasReceivedData(const ConnectionId &connection_id,
                       DataSize *size);
  Port listening_port() const { return listening_port_; }
  void StartPingRendezvous(bool directly_connected,
                           const IP &my_rendezvous_ip,
                           const Port &my_rendezvous_port);
  void StopPingRendezvous();
  bool CanConnect(const IP &ip, const Port &port);
  bool IsAddressUsable(const IP &local_ip,
                       const IP &remote_ip,
                       const Port &remote_port);
  bool IsPortAvailable(const Port &port);
 private:
  TransportUDT& operator=(const TransportUDT&);
  TransportUDT(const TransportUDT&);
  void AddUdtSocketId(const UdtSocketId &udt_socket_id);
  void CloseSocket(const UdtSocketId &udt_socket_id);
  void RemoveUdtSocketId(const UdtSocketId &udt_socket_id);
  void RemoveDeadSocketId(const UdtSocketId &udt_socket_id);
  int GetAndRefreshSocketStates(
      std::vector<UdtSocketId> *sockets_ready_to_receive,
      std::vector<UdtSocketId> *sockets_ready_to_send);
  TransportCondition Send(const std::string &data,
                          const UdtSocketId &udt_socket_id,
                          const int &response_timeout);


  ConnectionId NextConnectionID() {
    boost::detail::atomic_count connection_id_(1);
    return ++connection_id_;
  }
  void AddIncomingConnection(UdtSocketId udt_socket_id);
  void ReceiveData(const UdtSocketId &udt_socket_id,
                   const int &timeout);
  bool ParseTransportMessage(const std::string &data,
                             const UdtSocketId &udt_socket_id,
                             const float &rtt);
  void AddIncomingConnection(UdtSocketId udt_socket_id,
                             ConnectionId *connection_id);
  void HandleRendezvousMessage(const HolePunchingMessage &message);

  void SendHandle();
  int Connect(const IP &peer_address, const Port &peer_port,
              UdtSocketId *udt_socket_id);
  void PingHandle();
  void AcceptConnectionHandler(const UdtSocketId &udt_socket_id);
  void ReceiveHandler();
  void MessageHandler();
  boost::shared_ptr<boost::thread> accept_routine_, recv_routine_;
  boost::shared_ptr<boost::thread> send_routine_, ping_rendz_routine_;
  boost::shared_ptr<boost::thread> handle_msgs_routine_;
  UdtSocketId listening_socket_;
  Port listening_port_, my_rendezvous_port_;
// TODO (dirvine) allow multiple listening ports, map numbers with names
  std::map<Port, std::string> listening_ports_;

  IP my_rendezvous_ip_;
  std::map<ConnectionId, IncomingData> incoming_sockets_;
  std::list<OutgoingData> outgoing_queue_;
  std::list<IncomingMessages> incoming_msgs_queue_;
  boost::mutex send_mutex_, ping_rendez_mutex_, recv_mutex_, msg_hdl_mutex_;
  boost::mutex s_skts_mutex_;
  struct addrinfo addrinfo_hints_;
  struct addrinfo *addrinfo_result_;
  ConnectionId current_id_;
  boost::condition_variable send_cond_, ping_rend_cond_, recv_cond_;
  boost::condition_variable msg_hdl_cond_;
  bool ping_rendezvous_, directly_connected_/*, handle_non_transport_msgs_*/;
  int accepted_connections_, msgs_sent_;
  ConnectionId last_id_;
  std::set<ConnectionId> data_arrived_;
  std::map<ConnectionId, struct sockaddr> ips_from_connections_;
  boost::function<void(const ConnectionId&, const bool&)> send_notifier_;
  std::map<ConnectionId, UdtSocketId> send_sockets_;
  TransportType transport_type_;
  std::vector<UdtSocketId> udt_socket_ids_;
  boost::mutex udt_socket_ids_mutex_;
 // static ConnectionId connection_id_;
  //boost::shared_array<char> data_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_

