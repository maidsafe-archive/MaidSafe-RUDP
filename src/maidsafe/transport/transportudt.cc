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

#include "maidsafe/transport/transportudt.h"
#include <boost/scoped_array.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/cstdint.hpp>
#include <google/protobuf/descriptor.h>
#include <algorithm>
#include <exception>
#include "maidsafe/base/utils.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/online.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/udt/udt.h"

namespace transport {

// struct IncomingMessages {
//   explicit IncomingMessages(const ConnectionId &id)
//       : msg(), raw_data(), connection_id(id), rtt(0) {}
//   IncomingMessages()
//       : msg(), raw_data(), connection_id(0), rtt(0) {}
//   transport::RpcMessage msg;
//   std::string raw_data;
//   ConnectionId connection_id;
//   double rtt;
// };

TransportUDT::TransportUDT() : Transport(),
                               accept_routine_(),
                               recv_routine_(),
                               send_routine_(),
                               ping_rendz_routine_(),
                               handle_msgs_routine_(),
                               listening_socket_(0),
                               listening_port_(0),
                               my_rendezvous_port_(0),
                               my_rendezvous_ip_(),
//                                incoming_sockets_(),
//                                outgoing_queue_(),
//                                incoming_msgs_queue_(),
                               send_mutex_(),
                               ping_rendez_mutex_(),
                               recv_mutex_(),
                               msg_hdl_mutex_(),
                               s_skts_mutex_(),
                               addrinfo_hints_(),
                               addrinfo_result_(NULL),
                               current_id_(0),
                               send_cond_(),
                               ping_rend_cond_(),
                               recv_cond_(),
                               msg_hdl_cond_(),
                               ping_rendezvous_(false),
                               directly_connected_(false),
                               accepted_connections_(0),
                               msgs_sent_(0),
                               last_id_(0),
                               data_arrived_(),
                               ips_from_connections_(),
                               send_notifier_(),
                               send_sockets_(),
                               transport_type_(kUdt),
                               udt_socket_ids_(),
                               udt_socket_ids_mutex_(),
                               listening_ports_() {
  UDT::startup();
}

TransportUDT::~TransportUDT() {
  if (!stop_all_)
    StopAllListening();
}

void TransportUDT::CleanUp() {
  UDT::cleanup();
}

void TransportUDT::AddUdtSocketId(const UdtSocketId &udt_socket_id) {
  boost::mutex::scoped_lock lock(udt_socket_ids_mutex_);
  udt_socket_ids_.push_back(udt_socket_id);
}

void TransportUDT::CloseSocket(const UdtSocketId &udt_socket_id) {
  UDT::close(udt_socket_id);
  RemoveUdtSocketId(udt_socket_id);
}

void TransportUDT::RemoveUdtSocketId(const UdtSocketId &udt_socket_id) {
  boost::mutex::scoped_lock lock(udt_socket_ids_mutex_);
  RemoveDeadSocketId(udt_socket_id);
}

void TransportUDT::RemoveDeadSocketId(const UdtSocketId &udt_socket_id) {
  std::vector<UdtSocketId>::iterator it =
      std::find(udt_socket_ids_.begin(), udt_socket_ids_.end(), udt_socket_id);
  if (it != udt_socket_ids_.end())
    udt_socket_ids_.erase(it);
}

int TransportUDT::GetAndRefreshSocketStates(
    std::vector<UdtSocketId> *sockets_ready_to_receive,
    std::vector<UdtSocketId> *sockets_ready_to_send) {
  std::vector<UdtSocketId> dead_sockets;
  {
    boost::mutex::scoped_lock lock(udt_socket_ids_mutex_);
    if (UDT::ERROR == UDT::selectEx(udt_socket_ids_, sockets_ready_to_receive,
        sockets_ready_to_send, &dead_sockets, 10)) {
     DLOG(INFO) << "TransportUDT::GetAndRefreshSocketStates: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
      return UDT::ERROR;
    }
  }
 DLOG(INFO) << "TransportUDT::GetAndRefreshSocketStates: " <<
      dead_sockets.size() << " sockets being removed." << std::endl;
  std::for_each(dead_sockets.begin(), dead_sockets.end(),
                boost::bind(&TransportUDT::RemoveDeadSocketId, this, _1));
  return kSuccess;
}

TransportCondition TransportUDT::GetPeerAddress(const SocketId &socket_id,
                                                struct sockaddr *peer_address) {
  int peer_address_size = sizeof(*peer_address);
  if (UDT::ERROR == UDT::getpeername(socket_id, peer_address,
                                     &peer_address_size)) {
   DLOG(INFO) << "Failed to get valid peer address." <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kInvalidAddress;
  }
  return kSuccess;
}

TransportCondition TransportUDT::Send(const TransportMessage &transport_message,
                                      const IP &remote_ip,
                                      const Port &remote_port,
                                      const int &response_timeout) {
  struct addrinfo addrinfo_hints, *peer, *addrinfo_result;
  memset(&addrinfo_hints, 0, sizeof(addrinfo_hints));
  addrinfo_hints.ai_flags = AI_PASSIVE;
  addrinfo_hints.ai_family = AF_INET;
  addrinfo_hints.ai_socktype = SOCK_STREAM;
  std::string peer_port = boost::lexical_cast<std::string>(remote_port);
  if (0 != getaddrinfo(NULL, peer_port.c_str(), &addrinfo_hints,
                       &addrinfo_result)) {
    freeaddrinfo(addrinfo_result);
    return kInvalidAddress;
  }
  UdtSocketId udt_socket_id = UDT::socket(addrinfo_result->ai_family,
                                          addrinfo_result->ai_socktype,
                                          addrinfo_result->ai_protocol);
  // Windows UDP problems fix !! argh !!!
#ifdef WIN32
  UDT::setsockopt(udt_socket_id, 0, UDT_MSS, new int(1052), sizeof(int));
#endif
  if (0 != getaddrinfo(remote_ip.c_str(), peer_port.c_str(), &addrinfo_hints,
                       &peer)) {
   DLOG(INFO) << "Incorrect peer address. " << remote_ip << ":" <<
        remote_port << std::endl;
    return kInvalidAddress;
  }
  // connect to the peer, implict bind
  // TODO FIXME - This can delay by up to 3 seconds !!!! even on pass
  if (UDT::ERROR == UDT::connect(udt_socket_id, peer->ai_addr, peer->ai_addrlen)) {
   DLOG(INFO) << "Connect: " << UDT::getlasterror().getErrorMessage() <<
        std::endl;
    return kConnectError;
  }

  std::string data;
  if (!transport_message.SerializeToString(&data))
    return kInvalidData;
  boost::thread(&TransportUDT::SendNow,this ,data,
                udt_socket_id, response_timeout, 0);
  return kSuccess; // SendNow(data, udt_socket_id, response_timeout, 0);

}

TransportCondition TransportUDT::SendResponse(const TransportMessage &transport_message,
                                      const SocketId &socket_id) {
  std::string data;
  if (!transport_message.SerializeToString(&data))
    return kInvalidData;
  boost::thread(&TransportUDT::SendNow,this ,data,
                socket_id, 0, 0);
  return kSuccess; // SendNow(data, socket_id, 0, 0);
}

bool TransportUDT::CheckSocketReceive(const SocketId &udt_socket_id) {
  timeval tv;
  UDT::UDSET readfds;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  UD_ZERO(&readfds);
  UD_SET(udt_socket_id, &readfds);
  int res = UDT::select(0, &readfds, NULL, NULL, &tv);
  if ((res == UDT::ERROR) && (UD_ISSET(udt_socket_id, &readfds))) {
   LOG(INFO) << "Cannot use this socket to receive closing it !" << std::endl;
    UDT::close(udt_socket_id);
    return false;
  } else {
    return true;
  }
}

bool TransportUDT::CheckSocketSend(const SocketId &udt_socket_id) {
  timeval tv;
  UDT::UDSET writefds;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  UD_ZERO(&writefds);
  UD_SET(udt_socket_id, &writefds);
  int res = UDT::select(0, &writefds, NULL, NULL, &tv);
  if ((res == UDT::ERROR) && (UD_ISSET(udt_socket_id, &writefds))) {
   LOG(INFO) << "Cannot use this socket to send closing it !" << std::endl;
    UDT::close(udt_socket_id);
    return false;
  } else {
    return true;
  }
}


TransportCondition TransportUDT::SendNow(const std::string &data,
                                      const UdtSocketId &udt_socket_id,
                                      const int &response_timeout,
                                      const Port &receive_port) {
  std::string data_size_as_string =
      boost::lexical_cast<std::string>(data.size());
   DataSize data_size = static_cast<DataSize>(data.size());
  if (data_size != data.size()) {
   DLOG(INFO) << "TransportUDT::Send: data > max buffer size." << std::endl;
    signal_sent_(udt_socket_id, false);
    return kInvalidData;
  }
 DLOG(INFO) << "Attempting to send data of size" << data_size_as_string <<
      std::endl;
      // Here we must check the socket is alive
      // any socket that fails is closed in this method.
// TODO FIXME - This adds massive time to all tests
// So do we really need it as we do pick up the error 
//   if (!CheckSocketSend(udt_socket_id)) {
//     signal_sent_(udt_socket_id, false);
//     LOG(INFO) << "bad socket cannot send on it (SendNow) " << std::endl;
//     return kNoSocket;
//   }


  if (UDT::ERROR == UDT::send(udt_socket_id, data_size_as_string.data(),
      static_cast<int>(data_size_as_string.size()), 0)) {
   DLOG(INFO) << "Send: " << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(udt_socket_id);
    signal_sent_(udt_socket_id, false); 
    return kSendError;
  }
  DataSize sent_total = 0;
  int sent_size = 0;
  // Don't think we need a while loop here. 
   while (sent_total < data.size()) {
    if (UDT::ERROR == (sent_size = UDT::send(udt_socket_id,
        data.data() + sent_total, data_size - sent_total, 0))) {
     DLOG(INFO) << "Send: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      signal_sent_(udt_socket_id, false);
      return kSendError;
    }
    sent_total += sent_size;
   }
 DLOG(INFO) << "Sent data of size " << sent_total << std::endl;

//   if (response_timeout > 0) {
// TODO FIXME (dirvine) - need to bind a recieving socket and pass that.
//     boost::thread(&TransportUDT::ReceiveData, this, udt_socket_id,
//                   response_timeout, receive_port);
//   } else {
//   signal_sent_(udt_socket_id, false);    
//     UDT::close(udt_socket_id);
//   }
  signal_sent_(udt_socket_id, true);
  return kSuccess;
}

Port TransportUDT::StartListening(const IP &ip, const Port &port) {
  Port try_port = port;
  memset(&addrinfo_hints_, 0, sizeof(addrinfo_hints_));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(try_port);
  std::string address;
  if (ip != "")
    address = ip;
  // TODO FIXME
//   else
//     address = NULL;
  
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
                       &addrinfo_result_)) {
    return kInvalidPort;
  }
  listening_socket_ = UDT::socket(addrinfo_result_->ai_family,
                                  addrinfo_result_->ai_socktype,
                                  addrinfo_result_->ai_addrlen);
                                  
  if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_result_->ai_addr,
      addrinfo_result_->ai_addrlen)) {
    DLOG(WARNING) << "(" << listening_port_ << ") UDT bind error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_result_);
    return kBindError;
  }
  // Modify the port to reflect the port UDT has chosen
  struct sockaddr_in name;
  int name_size;
  if (try_port == 0) {
    UDT::getsockname(listening_socket_, reinterpret_cast<sockaddr*>(&name),
                     &name_size);
    try_port = ntohs(name.sin_port);
    service = boost::lexical_cast<std::string>(try_port);
    freeaddrinfo(addrinfo_result_);
    if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
                         &addrinfo_result_)) {
      freeaddrinfo(addrinfo_result_);
      return kInvalidPort;
    } 
  } 

  if (UDT::ERROR == UDT::listen(listening_socket_, 10)) {
   DLOG(ERROR) << "Failed to start listening port "<< port << ": " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_result_);
    return kListenError;
  }

  try {
    accept_routine_.reset(new boost::thread(
        &TransportUDT::AcceptConnectionHandler, this, listening_socket_, try_port));
  }
  catch(const boost::thread_resource_error&) {
    UDT::close(listening_socket_);
    freeaddrinfo(addrinfo_result_);
    return kThreadResourceError;
  }
  stop_all_ = false;
  listening_ports_.push_back(try_port);
  return try_port;
}

bool TransportUDT::StopAllListening() {
  if (stop_all_)
    return true;
  // iterate through vector
  stop_all_ = true;
//    while (!listening_ports_.empty()) {
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//    }
//     
      return true;
}

int TransportUDT::Connect(const IP &peer_address, const Port &peer_port,
                          UdtSocketId *udt_socket_id) {
  if (stop_all_)
    return -1;
  *udt_socket_id = UDT::socket(addrinfo_result_->ai_family,
                               addrinfo_result_->ai_socktype,
                               addrinfo_result_->ai_protocol);
  if (UDT::ERROR == UDT::bind(*udt_socket_id, addrinfo_result_->ai_addr,
      addrinfo_result_->ai_addrlen)) {
   DLOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
        UDT::getlasterror().getErrorMessage()<< std::endl;
    return -1;
  }

  sockaddr_in peer_addr;
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_port = htons(peer_port);
#ifndef WIN32
  if (inet_pton(AF_INET, peer_address.c_str(), &peer_addr.sin_addr) <= 0) {
#else
  if (INADDR_NONE == (peer_addr.sin_addr.s_addr =
      inet_addr(peer_address.c_str()))) {
#endif
   DLOG(ERROR) << "Invalid remote address " << peer_address << ":"<< peer_port
        << std::endl;
    return -1;
  }
  if (UDT::ERROR == UDT::connect(*udt_socket_id,
      reinterpret_cast<sockaddr*>(&peer_addr), sizeof(peer_addr))) {
   DLOG(ERROR) << "(" << listening_port_ << ") UDT connect to " << peer_address
        << ":" << peer_port << " -- " << UDT::getlasterror().getErrorMessage()
        << std::endl;
    return UDT::getlasterror().getErrorCode();
  }
  return 0;
}


void TransportUDT::AcceptConnectionHandler(const UdtSocketId &udt_socket_id,
                                           const Port &receive_port) {
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UdtSocketId receiver_socket_id;
  while (true) {
// //     if (stop_all_) {
//       LOG(INFO) << "trying to stop " << std::endl;
//       for (std::vector<Port>::iterator it = listening_ports_.begin();
//             it != listening_ports_.end(); ++it) {
//         if ((*it) == receive_port) {
//           listening_ports_.erase(it);
//            UDT::close(receiver_socket_id);
//           break;
//         }
//       }
//     } // FIXME This would leave unsent/received data !!
    if (UDT::INVALID_SOCK == (receiver_socket_id = UDT::accept(udt_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {

      LOG(ERROR) << "(" << listening_port_ << ") UDT::accept error: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
      return;

    }
    struct sockaddr peer_address;
    if (kSuccess == GetPeerAddress(receiver_socket_id, &peer_address)) {
      boost::thread(&TransportUDT::ReceiveData, this, receiver_socket_id, -1,
                    receive_port);
    } else {
     LOG(INFO) << "Problem passing socket off to handler, (closing socket)"
                << std::endl;
      UDT::close(receiver_socket_id);
    }
  }
  
}
/*
void TransportUDT::AsyncReceiveData(const UdtSocketId &udt_socket_id,
                               const int &timeout) {
 DLOG(INFO) << "running receive data loop!" << std::endl;
 AddUdtSocketId(udt_socket_id);

  std::vector<UdtSocketId> sockets_ready_to_receive;
  if (UDT::ERROR ==
      GetAndRefreshSocketStates(&sockets_ready_to_receive, NULL)) {
    UDT::close(udt_socket_id);
    return;
  }

 DLOG(INFO) << sockets_ready_to_receive.size() <<
      " receiving sockets available." << std::endl;
  std::vector<UdtSocketId>::iterator it =
      std::find(sockets_ready_to_receive.begin(),
                sockets_ready_to_receive.end(), udt_socket_id);
  if (it == sockets_ready_to_receive.end()) {
   DLOG(INFO) << "Receiving socket unavailable." << std::endl;
    UDT::close(udt_socket_id);
    return;
  }

  // Get the incoming message size
  std::string data_size_as_string(sizeof(DataSize), 0);
  DataSize data_size;
  int received_count;
  UDT::getlasterror().clear();
  if (UDT::ERROR == (received_count = UDT::recv(udt_socket_id,
      &data_size_as_string.at(0), sizeof(DataSize), 0))) {
   DLOG(INFO) << "Cannot get data size: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
  try {
    data_size_as_string.resize(received_count);
    data_size =
        boost::lexical_cast<DataSize>(data_size_as_string);
  }
  catch(const std::exception &e) {
   DLOG(INFO) << "Cannot get data size: " << e.what() << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
  if (data_size < 1) {
   DLOG(INFO) << "Data size is " << data_size << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
 DLOG(INFO) << "OK we have the data size " << data_size <<
      " now read it from the socket." << std::endl;

  // Get message
  std::string data(data_size, 0);

  UDT::setsockopt(udt_socket_id, 0, UDT_RCVTIMEO, &timeout, sizeof(timeout));
  DataSize received_total = 0;
  int received_size = 0;
  while (received_total < data_size) {
    if (UDT::ERROR == (received_size = UDT::recv(udt_socket_id,
        &data.at(0) + received_total, data_size - received_total, 0))) {
     DLOG(INFO) << "Recv: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      UDT::close(udt_socket_id);
      return;
    }
    received_total += received_size;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
 DLOG(INFO) << "SUCCESS we have read " << received_total << " bytes of data." <<
      std::endl;
  float rtt;
  UDT::TRACEINFO performance_monitor;
  if (UDT::ERROR == UDT::perfmon(udt_socket_id, &performance_monitor)) {
    DLOG(ERROR) << "UDT perfmon error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
  } else {
    float rtt = performance_monitor.msRTT;
    float bandwidth = performance_monitor.mbpsBandwidth;
    float receive_rate = performance_monitor.mbpsRecvRate;
    float send_rate = performance_monitor.mbpsSendRate;
   DLOG(INFO) << "looked for " << data_size << " got " << received_total <<
        std::endl;
   DLOG(INFO) <<"RTT = : " << rtt << "msecs " << std::endl;
   DLOG(INFO) <<"B/W used = : " << bandwidth << " Mb/s " << std::endl;
   DLOG(INFO) <<"RcvRate = : " << receive_rate << " Mb/s " << std::endl;
   DLOG(INFO) <<"SndRate = : " << send_rate << " Mb/s " << std::endl;
  }

  ParseTransportMessage(data, udt_socket_id, rtt);
}*/

void TransportUDT::ReceiveData(const UdtSocketId &udt_socket_id,
                               const int &timeout,
                               const Port &receive_port) {
 //LOG(INFO) << "receiving a message of some kind !" << std::endl;
  // Get the incoming message size
  std::string data_size_as_string(sizeof(DataSize), 0);
  DataSize data_size;
  int received_count;
  UDT::getlasterror().clear();
//   while (true) {
    if (UDT::ERROR == (received_count = UDT::recv(udt_socket_id,
        &data_size_as_string.at(0), sizeof(DataSize), 0))) {
    LOG(ERROR) << "Cannot get data size: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
  //     UDT::close(udt_socket_id);
      return;
    }
//   }
LOG(INFO) << "Size as string " << data_size_as_string << std::endl;
  try {
    data_size_as_string.resize(received_count);
    data_size =
        boost::lexical_cast<DataSize>(data_size_as_string);
  }
  catch(const std::exception &e) {
   LOG(ERROR) << "Cannot get data size (2): " << e.what() << std::endl;
     UDT::close(udt_socket_id);
    return;
  }
  if (data_size < 1) {
   LOG(INFO) << "Data size is " << data_size << std::endl;
     UDT::close(udt_socket_id);
    return;
  }
 DLOG(INFO) << "OK we have the data size " << data_size <<
      " now read it from the socket." << std::endl;

  // Get message
  std::string data(data_size, 0);
  if (timeout != 0) {
    UDT::setsockopt(udt_socket_id, 0, UDT_RCVTIMEO, &timeout, sizeof(timeout));
  }
  DataSize received_total = 0;
  int received_size = 0;
  while (received_total < data_size) {
    if (UDT::ERROR == (received_size = UDT::recv(udt_socket_id,
        &data.at(0) + received_total, data_size - received_total, 0))) {
     LOG(ERROR) << "Recv: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      UDT::close(udt_socket_id);
      return;
    }
    received_total += received_size;
   // boost::this_thread::sleep(boost::posix_time::milliseconds(2));
  }
 DLOG(INFO) << "SUCCESS we have read " << received_total << " bytes of data." <<
      std::endl;
  float rtt;
  UDT::TRACEINFO performance_monitor;
  if (UDT::ERROR == UDT::perfmon(udt_socket_id, &performance_monitor)) {
    DLOG(ERROR) << "UDT perfmon error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
  } else {
    float rtt = performance_monitor.msRTT;
    float bandwidth = performance_monitor.mbpsBandwidth;
    float receive_rate = performance_monitor.mbpsRecvRate;
    float send_rate = performance_monitor.mbpsSendRate;
   DLOG(INFO) << "looked for " << data_size << " got " << received_total <<
        std::endl;
   DLOG(INFO) <<"RTT = : " << rtt << "msecs " << std::endl;
   DLOG(INFO) <<"B/W used = : " << bandwidth << " Mb/s " << std::endl;
   DLOG(INFO) <<"RcvRate = : " << receive_rate << " Mb/s " << std::endl;
   DLOG(INFO) <<"SndRate = : " << send_rate << " Mb/s " << std::endl;
  }

  ParseTransportMessage(data, udt_socket_id, rtt, receive_port);
}

bool TransportUDT::ParseTransportMessage(const std::string &data,
                                         const UdtSocketId &udt_socket_id,
                                         const float &rtt,
                                         const Port & receive_port) {
  TransportMessage transport_message;
  if (!transport_message.ParseFromString(data)) {
   LOG(INFO) << "Bad data - not parsed." << std::endl;
    UDT::close(udt_socket_id);
    return false;
  }
  bool is_request(transport_message.type() == TransportMessage::kRequest);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      transport_message.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(transport_message.data(), &field_descriptors);
  if (field_descriptors.size() != 1U) {
   LOG(INFO) << "Bad data - doesn't contain exactly one field." << std::endl;
    UDT::close(udt_socket_id);
    return false;
  }
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      signal_message_received_(transport_message.data().raw_message(),
                               udt_socket_id, rtt, receive_port);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        signal_rpc_request_received_(transport_message.data().rpc_message(),
                                     udt_socket_id, rtt, receive_port);
        // Leave socket open to send response on.
        DLOG(INFO) << "Got request RPC" << std::endl;
      } else {
        signal_rpc_response_received_(transport_message.data().rpc_message(),
                                      udt_socket_id, rtt, receive_port);
        UDT::close(udt_socket_id);
      }
      break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
     // HandleRendezvousMessage(transport_message.data().hole_punching_message());
      UDT::close(udt_socket_id);
      break;
    case TransportMessage::Data::kPingFieldNumber:
      UDT::close(udt_socket_id);
      break;
    case TransportMessage::Data::kProxyPingFieldNumber:
      UDT::close(udt_socket_id);
      break;
    case TransportMessage::Data::kAcceptConnectFieldNumber:
      UDT::close(udt_socket_id);
      break;
    default:
     LOG(INFO) << "Unrecognised data type in TransportMessage." << std::endl;
      UDT::close(udt_socket_id);
      return false;
  }
  return true;
}

bool TransportUDT::IsAddressUsable(const IP &local_ip, const IP &remote_ip,
                                   const Port &remote_port) {
  // Ensure that local and remote addresses aren't empty
  if (local_ip.empty() || remote_ip.empty())
    return false;

  struct addrinfo hints, *local;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  IP dec_lip;
  if (local_ip.size() == 4)
    dec_lip = base::IpBytesToAscii(local_ip);
  else
    dec_lip = local_ip;
  if (0 != getaddrinfo(dec_lip.c_str(), "0", &hints, &local)) {
   DLOG(ERROR) << "Invalid local address " << local_ip << std::endl;
    return false;
  }

  UdtSocketId skt = UDT::socket(local->ai_family, local->ai_socktype,
                              local->ai_protocol);
  if (UDT::ERROR == UDT::bind(skt, local->ai_addr, local->ai_addrlen)) {
   DLOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return false;
  }

  freeaddrinfo(local);
  sockaddr_in remote_addr;
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_port = htons(remote_port);

#ifndef WIN32
  if (inet_pton(AF_INET, remote_ip.c_str(), &remote_addr.sin_addr) <= 0) {
    DLOG(ERROR) << "Invalid remote address " << remote_ip << ":"<< remote_port
        << std::endl;
    return false;
  }
#else
  if (INADDR_NONE == (remote_addr.sin_addr.s_addr =
      inet_addr(remote_ip.c_str()))) {
    DLOG(ERROR) << "Invalid remote address " << remote_ip << ":"<< remote_port
        << std::endl;
    return false;
  }
#endif

  if (UDT::ERROR == UDT::connect(skt,
      reinterpret_cast<sockaddr*>(&remote_addr), sizeof(remote_addr))) {
    DLOG(ERROR) << "(" << listening_port_ << ") UDT connect to " << remote_ip
        << ":" << remote_port <<" -- " << UDT::getlasterror().getErrorMessage()
        << std::endl;
    return false;
  }
  UDT::close(skt);
  return true;
}

bool TransportUDT::IsPortAvailable(const Port &port) {
  struct addrinfo addrinfo_hints;
  struct addrinfo* addrinfo_res;
  memset(&addrinfo_hints, 0, sizeof(struct addrinfo));
  addrinfo_hints.ai_flags = AI_PASSIVE;
  addrinfo_hints.ai_family = AF_INET;
  addrinfo_hints.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints,
      &addrinfo_res)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  UdtSocketId skt = UDT::socket(addrinfo_res->ai_family,
      addrinfo_res->ai_socktype, addrinfo_res->ai_protocol);
  if (UDT::ERROR == UDT::bind(skt, addrinfo_res->ai_addr,
      addrinfo_res->ai_addrlen)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  if (UDT::ERROR == UDT::listen(skt, 20)) {
    freeaddrinfo(addrinfo_res);
    return false;
  }
  UDT::close(skt);
  freeaddrinfo(addrinfo_res);
  return true;
}

// bool TransportUDT::RegisterOnRPCMessage(
//     boost::function<void(const rpcprotocol::RpcMessage&,
//                          const ConnectionId&,
//                          const boost::int16_t&,
//                          const float &)> on_rpcmessage) {
//   if (stop_) {
//     rpc_message_notifier_ = on_rpcmessage;
//     return true;
//   }
//   return false;
// }
//
// bool TransportUDT::RegisterOnMessage(
//     boost::function<void(const std::string&,
//                          const ConnectionId&,
//                          const boost::int16_t&,
//                          const float &)> on_message) {
//   if (stop_) {
//     message_notifier_ = on_message;
//     return true;
//   }
//   return false;
// }
//
// bool TransportUDT::RegisterOnSend(
//     boost::function<void(const ConnectionId&, const bool&)> on_send) {
//   if (stop_) {
//     send_notifier_ = on_send;
//     return true;
//   }
//   return false;
// }
//
// bool TransportUDT::RegisterOnServerDown(
//     boost::function<void(const bool&,
//                          const IP&,
//                          const Port&)> on_server_down) {
//   if (stop_) {
//     server_down_notifier_ = on_server_down;
//     return true;
//   }
//   return false;
// }
}  // namespace transport
