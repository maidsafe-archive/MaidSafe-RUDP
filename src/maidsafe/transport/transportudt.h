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
/*
* TODO 
* 1:  Allow Listening ports to be closed individually and as a group
* 2:  Create managed connection interface
* 3:  Add an Open method for rendezvous connections
* 4:  Create a ping at network level (in UDT this is a connect)
* 5:  Use managed connections for rendezvous
* 6:  Add tcp listen capability, may be another transport  
* 7:  Provide a brodcast tcp method " " " " "
* 8:  When a knode can it will start a tcp listener on 80 and 443 and add this
*     to the contact tuple (prononced toople apparently :-) )
* 9:  Thread send
* 10  Use thread pool
* 11: On thread pool filling up move all incoming connecitons to an async
*     connection method until a thread becomes available.
* 12: Complete NAT traversal management (use upnp, nat-pmp and hole punching)
*     allong prioratising of method type.
* 13: Use TCP to beackon on port 5483 when contact with kademlia network lost
* 14: Profile profile and profile. The send recive test should be under 100ms
*     preferrably less than 25ms. 
*/

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
// struct IncomingMessages;

typedef int UdtSocketId;

class TransportUDT : public Transport {
 public:
  enum DataType { kString, kFile };
  TransportUDT();
  ~TransportUDT();
  static void CleanUp();
  // Used to create a new socket and send data.  It assumes a
  // response is expected if timeout is > 0, and keeps the socket alive
  // for timeout (in milliseconds)
  TransportCondition Send(const TransportMessage &transport_message,
                          const IP &remote_ip,
                          const Port &remote_port,
                          const int &response_timeout);
  // Used to send a response to a request recived on socket_id.
  TransportCondition SendResponse(const TransportMessage &transport_message,
                          const SocketId &socket_id);

  TransportCondition Send(const std::string &data,
            const UdtSocketId &udt_socket_id,
            const int &response_timeout,
            const Port & receive_port);
  // Checks a socket can send data.(close it otherwise)
  bool CheckSocketSend(const SocketId &udt_socket_id);
  // Check a socket can recieve data (close it otherwise)
  bool CheckSocketReceive(const SocketId &udt_socket_id);
  // return 1-5000 for fail or port number (check > 5000)
  // this port number is passed up with every message received
  // add sucessful ports to listening_ports_ vector.
  Port StartListening(const IP &ip, const Port &port);
  // Stop a particular port
  bool StopListening(const Port);
  // Stop all listening ports
  bool StopAllListening();
  bool is_stopped() const { return stop_all_; }
  TransportCondition GetPeerAddress(const SocketId &socket_id,
                                    struct sockaddr *peer_address);
  bool ConnectionExists(const ConnectionId &connection_id);
  std::vector<Port> GetListeningPorts() { return listening_ports_; }
//   bool HasReceivedData(const ConnectionId &connection_id,
//                        DataSize *size);
  Port listening_port() const { return listening_port_; }

  bool IsAddressUsable(const IP &local_ip,
                       const IP &remote_ip,
                       const Port &remote_port);
  bool IsPortAvailable(const Port &port);
 private:
   // No copy or assign
  TransportUDT& operator=(const TransportUDT&);
  TransportUDT(const TransportUDT&);
  void AddUdtSocketId(const UdtSocketId &udt_socket_id);
  void CloseSocket(const UdtSocketId &udt_socket_id);
  void RemoveUdtSocketId(const UdtSocketId &udt_socket_id);
  void RemoveDeadSocketId(const UdtSocketId &udt_socket_id);
  int GetAndRefreshSocketStates(
      std::vector<UdtSocketId> *sockets_ready_to_receive,
      std::vector<UdtSocketId> *sockets_ready_to_send);



  ConnectionId NextConnectionID() {
    boost::detail::atomic_count connection_id_(1);
    return ++connection_id_;
  }
  void AddIncomingConnection(UdtSocketId udt_socket_id);
  void ReceiveData(const UdtSocketId &udt_socket_id,
                   const int &timeout,
                   const Port& receive_port);
  void AsyncReceiveData(const UdtSocketId &udt_socket_id,
                               const int &timeout);
  bool ParseTransportMessage(const std::string &data,
                             const UdtSocketId &udt_socket_id,
                             const float &rtt,
                             const Port & receive_port);
  void AddIncomingConnection(UdtSocketId udt_socket_id,
                             ConnectionId *connection_id);
  void HandleRendezvousMessage(const HolePunchingMessage &message);

  void SendHandle();
  int Connect(const IP &peer_address, const Port &peer_port,
              UdtSocketId *udt_socket_id);
  void PingHandle();
  void AcceptConnectionHandler(const UdtSocketId &udt_socket_id,
                               const Port & receive_port);
  void ReceiveHandler();
  void MessageHandler();
  boost::shared_ptr<boost::thread> accept_routine_, recv_routine_;
  boost::shared_ptr<boost::thread> send_routine_, ping_rendz_routine_;
  boost::shared_ptr<boost::thread> handle_msgs_routine_;
  UdtSocketId listening_socket_;
  Port listening_port_, my_rendezvous_port_;
  IP my_rendezvous_ip_;
//   std::map<ConnectionId, IncomingData> incoming_sockets_;
//   std::list<OutgoingData> outgoing_queue_;
//   std::list<IncomingMessages> incoming_msgs_queue_;
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
  std::vector<Port> listening_ports_;

 // static ConnectionId connection_id_;
  //boost::shared_array<char> data_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORTUDT_H_

