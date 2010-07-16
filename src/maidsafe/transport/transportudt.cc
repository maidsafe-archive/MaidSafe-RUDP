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

struct IncomingMessages {
  explicit IncomingMessages(const ConnectionId &id)
      : msg(), raw_data(), connection_id(id), rtt(0) {}
  IncomingMessages()
      : msg(), raw_data(), connection_id(0), rtt(0) {}
  transport::RpcMessage msg;
  std::string raw_data;
  ConnectionId connection_id;
  double rtt;
};

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
                               incoming_sockets_(),
                               outgoing_queue_(),
                               incoming_msgs_queue_(),
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
                               udt_socket_ids_mutex_() {
  UDT::startup();
}

TransportUDT::~TransportUDT() {
  if (!stop_)
    Stop();
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
      LOG(INFO) << "TransportUDT::GetAndRefreshSocketStates: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
      return UDT::ERROR;
    }
  }
  LOG(INFO) << "TransportUDT::GetAndRefreshSocketStates: " <<
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
    LOG(INFO) << "Failed to get valid peer address." <<
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
    return kSuccess;
  }
  UdtSocketId udt_socket_id = UDT::socket(addrinfo_result->ai_family,
                                          addrinfo_result->ai_socktype,
                                          addrinfo_result->ai_protocol);
  // UDT Options
//  UDT::setsockopt(client, 0, UDT_CC, new CCCFactory<CUDPBlast>, sizeof(CCCFactory<CUDPBlast>));
//  UDT::setsockopt(client, 0, UDT_MSS, new int(9000), sizeof(int));
//  UDT::setsockopt(client, 0, UDT_SNDBUF, new int(10000000), sizeof(int));
//  UDT::setsockopt(client, 0, UDP_SNDBUF, new int(10000000), sizeof(int));
  // Windows UDP problems fix !! argh !!!
#ifdef WIN32
  UDT::setsockopt(udt_socket_id, 0, UDT_MSS, new int(1052), sizeof(int));
#endif
// This is the default, we're just making sure UDT API does not change
  bool blocking = true;
  bool reuse_address = true;
  UDT::setsockopt(udt_socket_id, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
  UDT::setsockopt(udt_socket_id, 0, UDT_SNDSYN, &blocking, sizeof(blocking));
  UDT::setsockopt(udt_socket_id, 0, UDT_REUSEADDR, &reuse_address,
                  sizeof(reuse_address));
  if (0 != getaddrinfo(remote_ip.c_str(), peer_port.c_str(), &addrinfo_hints,
                       &peer)) {
    LOG(INFO) << "Incorrect peer address. " << remote_ip << ":" <<
        remote_port << std::endl;
    return kInvalidAddress;
  }

  // connect to the server, implict bind
  if (UDT::ERROR == UDT::connect(udt_socket_id, peer->ai_addr, peer->ai_addrlen)) {
    LOG(INFO) << "Connect: " << UDT::getlasterror().getErrorMessage() <<
        std::endl;
    return kConnectError;
  }
  std::string data;
  if (!transport_message.SerializeToString(&data))
    return kInvalidData;
  return Send(data, udt_socket_id, response_timeout);
}

TransportCondition TransportUDT::Send(const TransportMessage &transport_message,
                                      const SocketId &socket_id) {
  std::string data;
  if (!transport_message.SerializeToString(&data))
    return kInvalidData;
  return Send(data, socket_id, 0);
}

TransportCondition TransportUDT::Send(const std::string &data,
                                      const UdtSocketId &udt_socket_id,
                                      const int &response_timeout) {
  std::string data_size_as_string =
      boost::lexical_cast<std::string>(data.size());
  DataSize data_size = static_cast<DataSize>(data.size());
  if (data_size != data.size()) {
    LOG(INFO) << "TransportUDT::Send: data > max buffer size." << std::endl;
    return kInvalidData;
  }
  LOG(INFO) << "Attempting to send data of size " << data_size_as_string <<
      std::endl;
  if (UDT::ERROR == UDT::send(udt_socket_id, data_size_as_string.data(),
      static_cast<int>(data_size_as_string.size()), 0)) {
    LOG(INFO) << "Send: " << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(udt_socket_id);
    return kSendError;
  }
  DataSize sent_total = 0;
  int sent_size = 0;
  while (sent_total < data.size()) {
    if (UDT::ERROR == (sent_size = UDT::send(udt_socket_id,
        data.data() + sent_total, data_size - sent_total, 0))) {
      LOG(INFO) << "Send: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      return kSendError;
    }
    sent_total += sent_size;
  }
  LOG(INFO) << "Sent data of size " << sent_total << std::endl;

  if (response_timeout > 0) {
    boost::thread(&TransportUDT::ReceiveData, this, udt_socket_id,
                  response_timeout);
  } else {
    UDT::close(udt_socket_id);
  }
  return kSuccess;
}

bool TransportUDT::CheckIP(const IP &ip) {
  memset(&addrinfo_hints_, 0, sizeof(addrinfo_hints_));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  return 0 == getaddrinfo(ip.c_str(), NULL, &addrinfo_hints_,
                          &addrinfo_result_);
}

bool TransportUDT::CheckPort(const Port &port) {
  memset(&addrinfo_hints_, 0, sizeof(addrinfo_hints_));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  return 0 == getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
                          &addrinfo_result_);
}

TransportCondition TransportUDT::StartListening(const IP &ip,
                                                const Port &port) {
  if (!stopped_) {
    DLOG(WARNING) << "TransportUDT::StartListening: Already listening." <<
        std::endl;
    return kAlreadyStarted;
  }
  memset(&addrinfo_hints_, 0, sizeof(addrinfo_hints_));
  addrinfo_hints_.ai_flags = AI_PASSIVE;
  addrinfo_hints_.ai_family = AF_INET;
  addrinfo_hints_.ai_socktype = SOCK_STREAM;
  std::string service = boost::lexical_cast<std::string>(port);
  if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
                       &addrinfo_result_)) {
    return kInvalidPort; 
  }
  listening_socket_ = UDT::socket(addrinfo_result_->ai_family,
                                  addrinfo_result_->ai_socktype,
                                  addrinfo_result_->ai_addrlen);
  // UDT Options
  bool blocking = true;
  UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, &blocking,
                  sizeof(blocking));
  
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
  if (listening_port_ == 0) {
    UDT::getsockname(listening_socket_, reinterpret_cast<sockaddr*>(&name),
                     &name_size);
    listening_port_ = ntohs(name.sin_port);
    service = boost::lexical_cast<std::string>(listening_port_);
    freeaddrinfo(addrinfo_result_);
    if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
                         &addrinfo_result_)) {
      freeaddrinfo(addrinfo_result_);
      return kInvalidPort;
    }
  } else {
    listening_port_ = port;
  }

  if (UDT::ERROR == UDT::listen(listening_socket_, 20)) {
    LOG(ERROR) << "Failed to start listening port "<< listening_port_ << ": " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    freeaddrinfo(addrinfo_result_);
    return kListenError;
  }

  try {
    accept_routine_.reset(new boost::thread(
        &TransportUDT::AcceptConnectionHandler, this, listening_socket_));
  }
  catch(const boost::thread_resource_error&) {
    stop_ = true;
    int result = UDT::close(listening_socket_);
    freeaddrinfo(addrinfo_result_);
    return kThreadResourceError;
  }
  current_id_ = base::GenerateNextTransactionId(current_id_);
  stopped_ = false;
  return kSuccess;
}

// TransportCondition TransportUDT::Send(const rpcprotocol::RpcMessage &data,
//                        const ConnectionId &connection_id,
//                        const bool &new_socket) {
//   TransportMessage msg;
//   rpcprotocol::RpcMessage *rpc_msg = msg.mutable_rpc();
//   *rpc_msg = data;
//   if (data.IsInitialized()) {
//     std::string ser_msg;
//     msg.SerializeToString(&ser_msg);
//     return Send(ser_msg, kString, connection_id, new_socket, true);
//   } else {
//     {
//       boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//       std::map<ConnectionId, UdtSocketId>::iterator it =
//           send_sockets_.find(connection_id);
//       if (it != send_sockets_.end())
//         send_sockets_.erase(it);
//     }
//     return 1;
//   }
// }

// int TransportUDT::Send(const TransportMessage &t_mesg,
//                        const ConnectionId &connection_id,
//                        const bool &new_socket) {
//   if (data != "") {
//     return Send(data, kString, connection_id, new_socket, false);
//   } else {
//     {
//       boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//       std::map<ConnectionId, UdtSocketId>::iterator it =
//           send_sockets_.find(connection_id);
//       if (it != send_sockets_.end())
//         send_sockets_.erase(it);
//     }
//     return 1;
//   }
// }
// 
// int TransportUDT::Send(const std::string &data, DataType type,
//                        const ConnectionId &connection_id,
//                        const bool &new_socket, const bool &is_rpc) {
//   UdtSocketId skt;
//   if (new_socket) {
//     std::map<ConnectionId, UdtSocketId>::iterator it;
//     {
//       boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//       it = send_sockets_.find(connection_id);
//       if (it == send_sockets_.end()) {
//         signal_sent_(connection_id, false);
//         return 1;
//       }
//       skt = (*it).second;
//       send_sockets_.erase(it);
//     }
//   } else {
//     std::map<ConnectionId, IncomingData>::iterator it;
//     {
//       boost::mutex::scoped_lock guard(recv_mutex_);
//       it = incoming_sockets_.find(connection_id);
//       if (it == incoming_sockets_.end()) {
//         signal_sent_(connection_id, false);
//         return 1;
//       }
//       skt = (*it).second.udt_socket_id;
//     }
//   }
// 
//   if (type == kString) {
//     int64_t data_size = data.size();
//     OutgoingData out_data(skt, data_size, connection_id, is_rpc);
//     memcpy(out_data.data.get(),
//       const_cast<char*>(static_cast<const char*>(data.c_str())), data_size);
//     {
//       boost::mutex::scoped_lock(send_mutex_);
//       outgoing_queue_.push_back(out_data);
//     }
//     send_cond_.notify_one();
//   } else if (type == kFile) {
//     char *file_name = const_cast<char*>(static_cast<const char*>(data.c_str()));
//     std::fstream ifs(file_name, std::ios::in | std::ios::binary);
//     ifs.seekg(0, std::ios::end);
//     int64_t data_size = ifs.tellg();
//     ifs.seekg(0, std::ios::beg);
//     // send file size information
//     if (UDT::ERROR == UDT::send(skt, reinterpret_cast<char*>(&data_size),
//         sizeof(int64_t), 0)) {
//       return 1;
//     }
//     // send the file
//     if (UDT::ERROR == UDT::sendfile(skt, ifs, 0, data_size)) {
//       return 1;
//     }
//   }
//   return 0;
// }

void TransportUDT::Stop() {
  if (stop_)
    return;
  stop_ = true;
//   if (send_routine_.get()) {
//     send_cond_.notify_one();
//     if (!send_routine_->timed_join(boost::posix_time::seconds(5))) {
//       // forcing to interrupt the thread
//       send_routine_->interrupt();
//       send_routine_->join();
//     }
//   }
//   if (accept_routine_.get()) {
//     if (!accept_routine_->timed_join(boost::posix_time::seconds(5))) {
//       // forcing to interrupt the thread
//       accept_routine_->interrupt();
//       accept_routine_->join();
//     }
//   }
//   if (recv_routine_.get()) {
//     recv_cond_.notify_one();
//     if (!recv_routine_->timed_join(boost::posix_time::seconds(5))) {
//       // forcing to interrupt the thread
//       recv_routine_->interrupt();
//       recv_routine_->join();
//     }
//   }
//   if (ping_rendz_routine_.get()) {
//     {
//       boost::mutex::scoped_lock lock(ping_rendez_mutex_);
//       if (!ping_rendezvous_) {
//         ping_rendezvous_ = true;
//       }
//       ping_rend_cond_.notify_one();
//     }
//     if (!ping_rendz_routine_->timed_join(boost::posix_time::seconds(5))) {
//       // forcing to interrupt the thread
//       ping_rendz_routine_->interrupt();
//       ping_rendz_routine_->join();
//     }
//     ping_rendezvous_ = false;
//   }
//   if (handle_msgs_routine_.get()) {
//     msg_hdl_cond_.notify_one();
//     if (!handle_msgs_routine_->timed_join(boost::posix_time::seconds(5))) {
//       // forcing to interrupt the thread
//       handle_msgs_routine_->interrupt();
//       handle_msgs_routine_->join();
//     }
//   }
  {
    boost::mutex::scoped_lock lock(udt_socket_ids_mutex_);
    std::for_each(udt_socket_ids_.begin(), udt_socket_ids_.end(),
                  boost::bind(&UDT::close, _1));
    udt_socket_ids_.clear();
  }
  //UDT::close(listening_socket_);
  //std::map<ConnectionId, IncomingData>::iterator it;
  //for (it = incoming_sockets_.begin(); it != incoming_sockets_.end(); it++)
  //  UDT::close((*it).second.udt_socket_id);
  //incoming_sockets_.clear();
  //std::map<ConnectionId, UdtSocketId>::iterator it1;
  //for (it1 = send_sockets_.begin(); it1 != send_sockets_.end(); ++it1) {
  //  UDT::close((*it1).second);
  //}
  //send_sockets_.clear();
  //outgoing_queue_.clear();
  /*  Should these be cleared when the transport is only stopped?
  rpc_message_notifier_ = 0;
  message_notifier_ = 0;
  send_notifier_ = 0;*/
  freeaddrinfo(addrinfo_result_);
  DLOG(INFO) << "(" << listening_port_ << ") Accepted connections: " <<
      accepted_connections_ << ". Msgs Sent: " << msgs_sent_ << ". Msgs Recv "
      << last_id_ << std::endl;
}

// void TransportUDT::ReceiveHandler() {
//   timeval tv;
//   tv.tv_sec = 0;
//   tv.tv_usec = 1000;
//   UDT::UDSET readfds;
//   while (true) {
//     boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//     {
//       boost::mutex::scoped_lock guard(recv_mutex_);
//       while (incoming_sockets_.empty() && !stop_) {
//         recv_cond_.wait(guard);
//       }
//     }
//     if (stop_) return;
//     // read data.
//     std::list<ConnectionId> dead_connections_ids;
//     std::map<ConnectionId, IncomingData>::iterator it;
//     {
//     boost::mutex::scoped_lock guard(recv_mutex_);
//     UD_ZERO(&readfds);
//     for (it = incoming_sockets_.begin(); it != incoming_sockets_.end(); ++it) {
//       int res = UDT::send((*it).second.udt_socket_id, NULL, 0, 0);
//       if (res == 0) {
//         UD_SET((*it).second.udt_socket_id, &readfds);
//       } else {
//         dead_connections_ids.push_back((*it).first);
//       }
//     }
//     }
//     int res = UDT::select(0, &readfds, NULL, NULL, &tv);
//     {
//     boost::mutex::scoped_lock guard(recv_mutex_);
//     if (res != UDT::ERROR) {
//       for (it = incoming_sockets_.begin(); it != incoming_sockets_.end();
//            ++it) {
//         if (UD_ISSET((*it).second.udt_socket_id, &readfds)) {
//           int result = 0;
//           // save the remote peer address
//           int peer_addr_size = sizeof(struct sockaddr);
//           if (UDT::ERROR == UDT::getpeername((*it).second.udt_socket_id,
//               &peer_address_, &peer_addr_size)) {
//             continue;
//           }
//           if ((*it).second.expect_size == 0) {
//             // get size information
//             int64_t size;
//             if (UDT::ERROR == UDT::recv((*it).second.udt_socket_id,
//                 reinterpret_cast<char*>(&size), sizeof(size), 0)) {
//               if (UDT::getlasterror().getErrorCode() !=
//                   CUDTException::EASYNCRCV) {
//                 UDT::close((*it).second.udt_socket_id);
//                 dead_connections_ids.push_back((*it).first);
//                 continue;
//               }
//               continue;
//             }
//             if (size > 0) {
//               (*it).second.expect_size = size;
//             } else {
//               UDT::close((*it).second.udt_socket_id);
//               dead_connections_ids.push_back((*it).first);
//               continue;
//             }
//           } else {
//             if ((*it).second.data == NULL)
//               (*it).second.data = boost::shared_array<char>
//                   (new char[(*it).second.expect_size]);
//             int rsize = 0;
//             if (UDT::ERROR == (rsize = UDT::recv((*it).second.udt_socket_id,
//                 (*it).second.data.get() + (*it).second.received_size,
//                 (*it).second.expect_size - (*it).second.received_size,
//                 0))) {
//               if (UDT::getlasterror().getErrorCode() !=
//                   CUDTException::EASYNCRCV) {
//                 UDT::close((*it).second.udt_socket_id);
//                 dead_connections_ids.push_back((*it).first);
//                 continue;
//               }
//               continue;
//             }
//             (*it).second.received_size += rsize;
//             UDT::TRACEINFO perf;
//             if (UDT::ERROR == UDT::perfmon((*it).second.udt_socket_id, &perf)) {
//               DLOG(ERROR) << "UDT permon error: " <<
//                   UDT::getlasterror().getErrorMessage() << std::endl;
//             } else {
//               (*it).second.cumulative_rtt += perf.msRTT;
//               ++(*it).second.observations;
//             }
//             if ((*it).second.expect_size <= (*it).second.received_size) {
//               ++last_id_;
//               std::string message = std::string((*it).second.data.get(),
//                                     (*it).second.expect_size);
//               ConnectionId connection_id = (*it).first;
//               (*it).second.expect_size = 0;
//               (*it).second.received_size = 0;
//               TransportMessage t_msg;
//               if (t_msg.ParseFromString(message)) {
//                 if (t_msg.has_hp()) {
//                   HandleRendezvousMessage(t_msg.hp());
//                   result = UDT::close((*it).second.udt_socket_id);
//                   dead_connections_ids.push_back((*it).first);
//                 } else if (t_msg.has_rpc()) {
//                   IncomingMessages msg(connection_id);
//                   msg.msg = t_msg.rpc();
//                   DLOG(INFO) << "(" << listening_port_ << ") message for id "
//                       << connection_id << " arrived" << std::endl;
//                   UDT::TRACEINFO perf;
//                   if (UDT::ERROR == UDT::perfmon((*it).second.udt_socket_id,
//                       &perf)) {
//                     DLOG(ERROR) << "UDT permon error: " <<
//                         UDT::getlasterror().getErrorMessage() << std::endl;
//                   } else {
//                     msg.rtt = perf.msRTT;
//                     if ((*it).second.observations != 0) {
//                       msg.rtt = (*it).second.cumulative_rtt /
//                           static_cast<double>((*it).second.observations);
//                     } else {
//                       msg.rtt = 0.0;
//                     }
//                   }
//                   data_arrived_.insert(connection_id);
//                   {  // NOLINT Fraser
//                     boost::mutex::scoped_lock guard1(msg_hdl_mutex_);
//                     ips_from_connections_[connection_id] = peer_address_;
//                     incoming_msgs_queue_.push_back(msg);
//                   }
//                   msg_hdl_cond_.notify_one();
//                 } else {
//                   LOG(WARNING) << "( " << listening_port_ <<
//                       ") Invalid Message received" << std::endl;
//                 }
//               } else /* TODO FIXME if (!message_notifier_.empty()) */{
//                 IncomingMessages msg(connection_id);
//                 msg.raw_data = message;
//                 DLOG(INFO) << "(" << listening_port_ << ") message for id "
//                     << connection_id << " arrived" << std::endl;
//                 UDT::TRACEINFO perf;
//                 if (UDT::ERROR == UDT::perfmon((*it).second.udt_socket_id,
//                     &perf)) {
//                   DLOG(ERROR) << "UDT permon error: " <<
//                       UDT::getlasterror().getErrorMessage() << std::endl;
//                 } else {
//                   msg.rtt = perf.msRTT;
//                   if ((*it).second.observations != 0) {
//                     msg.rtt = (*it).second.cumulative_rtt /
//                         static_cast<double>((*it).second.observations);
//                   } else {
//                     msg.rtt = 0.0;
//                   }
//                 }
//                 data_arrived_.insert(connection_id);
//                 {  // NOLINT Fraser
//                   boost::mutex::scoped_lock guard1(msg_hdl_mutex_);
//                   ips_from_connections_[connection_id] = peer_address_;
//                   incoming_msgs_queue_.push_back(msg);
//                 }
//                 msg_hdl_cond_.notify_one();
//               } /*TODO FIXME else {
//                 LOG(WARNING) << "( " << listening_port_ <<
//                     ") Invalid Message received" << std::endl;
//               }*/
//             }
//           }
//         }
//       }
//     }
//     // Deleting dead connections
//     std::list<ConnectionId>::iterator it1;
//     for (it1 = dead_connections_ids.begin(); it1 != dead_connections_ids.end();
//          ++it1) {
//       UDT::close(incoming_sockets_[*it1].udt_socket_id);
//       incoming_sockets_.erase(*it1);
//     }
//     }
//   }
// }
// 
// void TransportUDT::AddIncomingConnection(UdtSocketId udt_socket_id,
//                                          ConnectionId *connection_id) {
//   boost::mutex::scoped_lock guard(recv_mutex_);
//   current_id_ = base::GenerateNextTransactionId(current_id_);
//   IncomingData data(udt_socket_id);
//   incoming_sockets_[current_id_] = data;
//   *connection_id = current_id_;
//   recv_cond_.notify_one();
// }
// 
// void TransportUDT::AddIncomingConnection(UdtSocketId udt_socket_id) {
//   boost::mutex::scoped_lock guard(recv_mutex_);
//   current_id_ = base::GenerateNextTransactionId(current_id_);
//   IncomingData data(udt_socket_id);
//   incoming_sockets_[current_id_] = data;
//   recv_cond_.notify_one();
// }

TransportCondition TransportUDT::CloseConnection(
    const ConnectionId &connection_id) {
  std::map<ConnectionId, IncomingData>::iterator it;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it = incoming_sockets_.find(connection_id);
  if (it == incoming_sockets_.end()) {
    LOG(ERROR) << "Failed to find socket for closing." << std::endl;
    return kCloseSocketError;
  }
  int result = UDT::close(incoming_sockets_[connection_id].udt_socket_id);
  if (result == UDT::ERROR) {
    LOG(ERROR) << "Failed to close socket: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kCloseSocketError;
  }
  incoming_sockets_.erase(connection_id);
  data_arrived_.erase(connection_id);
  return kSuccess;
}

bool TransportUDT::ConnectionExists(const ConnectionId &connection_id) {
  std::map<ConnectionId, IncomingData>::iterator it;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it = incoming_sockets_.find(connection_id);
  return it != incoming_sockets_.end();
}

bool TransportUDT::HasReceivedData(const ConnectionId &connection_id,
                                   DataSize *size) {
  std::map<ConnectionId, IncomingData>::iterator it1;
  std::set<ConnectionId>::iterator it2;
  bool result = false;
  boost::mutex::scoped_lock guard(recv_mutex_);
  it1 = incoming_sockets_.find(connection_id);
  if (it1 != incoming_sockets_.end()) {
    if ((*it1).second.received_size > *size) {
      *size = (*it1).second.received_size;
      result = true;
    } else {
      it2 = data_arrived_.find(connection_id);
      if (it2 != data_arrived_.end()) {
        result = true;
      } else {
        result = false;
      }
    }
  } else {
    it2 = data_arrived_.find(connection_id);
    if (it2 != data_arrived_.end()) {
      result = true;
    } else {
      result = false;
    }
  }
  return result;
}

void TransportUDT::SendHandle() {
  while (true) {
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    {
      boost::mutex::scoped_lock guard(send_mutex_);
      while (outgoing_queue_.empty() && !stop_) {
        send_cond_.wait(guard);
      }
    }
    if (stop_)
      return;
    std::list<OutgoingData>::iterator it;
    {
      boost::mutex::scoped_lock guard(send_mutex_);
      for (it = outgoing_queue_.begin(); it != outgoing_queue_.end(); ++it) {
        if (!it->sent_size) {
          if (UDT::ERROR == UDT::send(it->udt_socket_id,
              reinterpret_cast<char*>(&it->data_size), sizeof(int64_t), 0)) {
            if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCSND) {
              DLOG(ERROR) << "(" << listening_port_ <<
                  ") Error sending message size: " <<
                  UDT::getlasterror().getErrorMessage() << std::endl;
              if (it->is_rpc)
                signal_sent_(it->connection_id, false);
              outgoing_queue_.erase(it);
              break;
            }
            continue;
          } else {
            it->sent_size = true;
          }
        }
        if (it->data_sent < it->data_size) {
          int64_t ssize;
          if (UDT::ERROR == (ssize = UDT::send(it->udt_socket_id,
              it->data.get() + it->data_sent,
              it->data_size - it->data_sent,
              0))) {
            if (UDT::getlasterror().getErrorCode() !=
                  CUDTException::EASYNCSND) {
              DLOG(ERROR) << "(" << listening_port_ <<
                  ") Error sending message data: " <<
                  UDT::getlasterror().getErrorMessage() << std::endl;
              if (it->is_rpc)
                signal_sent_(it->connection_id, false);
              outgoing_queue_.erase(it);
              break;
            }
            continue;
          }
          it->data_sent += ssize;
        } else {
          // Finished sending data
          if (it->is_rpc)
            signal_sent_(it->connection_id, true);
          outgoing_queue_.erase(it);
          ++msgs_sent_;
          break;
        }
      }
    }  // lock scope end here
  }
}

int TransportUDT::Connect(const IP &peer_address, const Port &peer_port,
                          UdtSocketId *udt_socket_id) {
  if (stop_)
    return -1;
//   bool blocking = false;
//   bool reuse_addr = true;
//   UDT::setsockopt(*udt_socket_id, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
//   UDT::setsockopt(*udt_socket_id, 0, UDT_SNDSYN, &blocking, sizeof(blocking));
//   UDT::setsockopt(*udt_socket_id, 0, UDT_REUSEADDR, &reuse_addr,
//                   sizeof(reuse_addr));

  *udt_socket_id = UDT::socket(addrinfo_result_->ai_family,
                               addrinfo_result_->ai_socktype,
                               addrinfo_result_->ai_protocol);
  if (UDT::ERROR == UDT::bind(*udt_socket_id, addrinfo_result_->ai_addr,
      addrinfo_result_->ai_addrlen)) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
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
    LOG(ERROR) << "Invalid remote address " << peer_address << ":"<< peer_port
        << std::endl;
    return -1;
  }
  if (UDT::ERROR == UDT::connect(*udt_socket_id,
      reinterpret_cast<sockaddr*>(&peer_addr), sizeof(peer_addr))) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT connect to " << peer_address
        << ":" << peer_port << " -- " << UDT::getlasterror().getErrorMessage()
        << std::endl;
    return UDT::getlasterror().getErrorCode();
  }
  return 0;
}

void TransportUDT::HandleRendezvousMessage(const HolePunchingMessage &message) {
//   if (message.type() == FORWARD_REQ) {
//     TransportMessage t_msg;
//     HolePunchingMsg *forward_msg = t_msg.mutable_hp();
//     IP peer_ip(inet_ntoa(((
//       struct sockaddr_in *)&peer_address_)->sin_addr));
//     Port peer_port = ntohs(((struct sockaddr_in *)&peer_address_)->sin_port);
//     forward_msg->set_ip(peer_ip);
//     forward_msg->set_port(peer_port);
//     forward_msg->set_type(FORWARD_MSG);
//     std::string ser_msg;
//     t_msg.SerializeToString(&ser_msg);
//     ConnectionId connection_id;
//     if (0 == ConnectToSend(message.ip(), message.port(), "", 0, "", 0, false,
//                            &connection_id))
//       Send(ser_msg, kString, connection_id, true, false);
//   } else if (message.type() == FORWARD_MSG) {
//     UdtSocketId skt;
//     if (Connect(message.ip(), message.port(), &skt) == 0) {
//       UDT::close(skt);
//     }
//   }
}
 
void TransportUDT::StartPingRendezvous(bool directly_connected,
                                       const IP &my_rendezvous_ip,
                                       const Port &my_rendezvous_port) {
//   my_rendezvous_port_ = my_rendezvous_port;
//   if (my_rendezvous_ip.length() == 4)
//     my_rendezvous_ip_ = base::IpBytesToAscii(my_rendezvous_ip);
//   else
//     my_rendezvous_ip_ = my_rendezvous_ip;
//   {
//     boost::mutex::scoped_lock lock(ping_rendez_mutex_);
//     directly_connected_ = directly_connected;
//     ping_rendezvous_ = true;
//   }
//   ping_rend_cond_.notify_one();
 }
 
 void TransportUDT::StopPingRendezvous() {
//   boost::mutex::scoped_lock guard(ping_rendez_mutex_);
//   ping_rendezvous_ = false;
 }

void TransportUDT::PingHandle() {
  while (true) {
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      while (!ping_rendezvous_) {
        ping_rend_cond_.wait(lock);
      }
    }
    if (stop_) return;
    {
      boost::mutex::scoped_lock lock(ping_rendez_mutex_);
      if (directly_connected_) return;
    }
    UdtSocketId skt;
    if (Connect(my_rendezvous_ip_, my_rendezvous_port_, &skt) == 0) {
      UDT::close(skt);
      bool dead_rendezvous_server = false;
      // it is not dead, no nead to return the ip and port
      signal_connection_down_(dead_rendezvous_server, "", 0);
      boost::this_thread::sleep(boost::posix_time::seconds(8));
    } else {
      // retrying two more times to connect to make sure
      // two seconds between each ping
      bool alive = false;
      for (int i = 0; i < 2 && !alive; ++i) {
        boost::this_thread::sleep(boost::posix_time::seconds(2));
        if (Connect(my_rendezvous_ip_, my_rendezvous_port_, &skt) == 0) {
          UDT::close(skt);
          alive = true;
        }
      }
      if (!alive) {
        {
          boost::mutex::scoped_lock lock(ping_rendez_mutex_);
          ping_rendezvous_ = false;
        }
        base::OnlineController::Instance()->SetOnline(listening_port_, false);
        // check in case Stop was called before timeout of connection, then
        // there is no need to call rendezvous_notifier_
        if (stop_) return;
        bool dead_rendezvous_server = true;
        signal_connection_down_(dead_rendezvous_server, my_rendezvous_ip_,
          my_rendezvous_port_);
      } else {
        base::OnlineController::Instance()->SetOnline(listening_port_, true);
        bool dead_rendezvous_server = false;
        signal_connection_down_(dead_rendezvous_server, "", 0);
        boost::this_thread::sleep(boost::posix_time::seconds(8));
      }
    }
  }
}

bool TransportUDT::CanConnect(const IP &ip, const Port &port) {
  UdtSocketId skt;
  IP dec_lip;
  if (ip.size() == 4)
    dec_lip = base::IpBytesToAscii(ip);
  else
    dec_lip = ip;
  bool result = false;
  if (Connect(dec_lip, port, &skt) == 0)
    result = true;
  UDT::close(skt);
  return result;
}

void TransportUDT::AcceptConnectionHandler(const UdtSocketId &udt_socket_id) {
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UdtSocketId receiver_socket_id;
  while (true) {
    if (stop_) return;
    if (UDT::INVALID_SOCK == (receiver_socket_id = UDT::accept(udt_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {
      //  The following only applies for non-blocking sockets
      //if (UDT::getlasterror().getErrorCode() == CUDTException::EASYNCRCV) {
      //  boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      //  continue;
      //} else {
      DLOG(ERROR) << "(" << listening_port_ << ") UDT::accept error: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
      return;
      //}
    }
    struct sockaddr peer_address;
    if (kSuccess == GetPeerAddress(receiver_socket_id, &peer_address)) {
      boost::thread(&TransportUDT::ReceiveData, this, receiver_socket_id, -1);
     // ++accepted_connections_;
     // AddIncomingConnection(receiver_socket_id);
    } else {
      LOG(INFO) << "Problem passing socket off to handler, (closing socket)"
                << std::endl;
      UDT::close(receiver_socket_id);
    }
    //  The following is only useful for non-blocking sockets
    //boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
}

void TransportUDT::ReceiveData(const UdtSocketId &udt_socket_id,
                               const int &timeout) {
  LOG(INFO) << "OK receiving data!" << std::endl;
  AddUdtSocketId(udt_socket_id);

//  bool blocking = true;
//   bool reuse_addr = true;
//  UDT::setsockopt(udt_socket_id, 0, UDT_RCVSYN, &blocking, sizeof(blocking));
//  UDT::setsockopt(udt_socket_id, 0, UDT_SNDSYN, &blocking, sizeof(blocking));
 // if (stop_) return;
  // read data.
//   UD_ZERO(&readfds);
//   int res = UDT::send(udt_socket_id, NULL, 0, 0);
//   if (res == 0) {
//     LOG(INFO) << "Socket seems fine" << std::endl;
//     UD_SET(udt_socket_id, &readfds);
//   } else {
//     LOG(INFO) << "Socket problem" << std::endl;
//     UDT::close(udt_socket_id);
//     return;
//   }

  std::vector<UdtSocketId> sockets_ready_to_receive;
  if (UDT::ERROR == 
      GetAndRefreshSocketStates(&sockets_ready_to_receive, NULL)) {
    UDT::close(udt_socket_id);
    return;
  }

  LOG(INFO) << sockets_ready_to_receive.size() <<
      " receiving sockets available." << std::endl;
  std::vector<UdtSocketId>::iterator it =
      std::find(sockets_ready_to_receive.begin(),
                sockets_ready_to_receive.end(), udt_socket_id);
  if (it == sockets_ready_to_receive.end()) {
    LOG(INFO) << "Receiving socket unavailable." << std::endl;
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
    LOG(INFO) << "Cannot get data size: " <<
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
    LOG(INFO) << "Cannot get data size: " << e.what() << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
  if (data_size < 1) {
    LOG(INFO) << "Data size is " << data_size << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
  LOG(INFO) << "OK we have the data size " << data_size <<
      " now read it from the socket." << std::endl;

  // Get message
  std::string data(data_size, 0);

//  boost::shared_array<char> data(new char[data_size]);
//  char *data;
//  data = new char[data_size];
  

  UDT::setsockopt(udt_socket_id, 0, UDT_RCVTIMEO, &timeout, sizeof(timeout)); 
  DataSize received_total = 0;
  int received_size = 0;
  while (received_total < data_size) {
//    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    if (UDT::ERROR == (received_size = UDT::recv(udt_socket_id, 
        &data.at(0) + received_total, data_size - received_total, 0))) {
      LOG(INFO) << "Recv: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      UDT::close(udt_socket_id);
      return;
    }
    received_total += received_size;
  }
  LOG(INFO) << "SUCCESS we have read " << received_total << " bytes of data." <<
      std::endl;
  UDT::TRACEINFO performance_monitor;
  float rtt;
  if (UDT::ERROR == UDT::perfmon(udt_socket_id, &performance_monitor)) {
    DLOG(ERROR) << "UDT perfmon error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
  } else {
    rtt = performance_monitor.msRTT;
    float bandwidth = performance_monitor.mbpsBandwidth;
    float receive_rate = performance_monitor.mbpsRecvRate;
    float send_rate = performance_monitor.mbpsSendRate;
    LOG(INFO) << "looked for " << data_size << " got " << received_total <<
        std::endl;
    LOG(INFO) <<"RTT = : " << rtt << "msecs " << std::endl;
    LOG(INFO) <<"B/W used = : " << bandwidth << " Mb/s " << std::endl;
    LOG(INFO) <<"RcvRate = : " << receive_rate << " Mb/s " << std::endl;
    LOG(INFO) <<"SndRate = : " << send_rate << " Mb/s " << std::endl;
  }

  ConnectionId connection_id = NextConnectionID();
  LOG(INFO) << "Connection ID: " << connection_id << "  -- Socket ID: " << udt_socket_id << std::endl;
  ParseTransportMessage(data, udt_socket_id, rtt);
}

bool TransportUDT::ParseTransportMessage(const std::string &data,
                                         const UdtSocketId &udt_socket_id,
                                         const float &rtt) {
//   std::string message = std::string(data_.get());
//   LOG(INFO) << "Message is " << message << std::endl;
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
  LOG(INFO) << "Message parsed as " << field_descriptors.at(0)->name() <<
      std::endl;
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      signal_message_received_(transport_message.data().raw_message(),
                               udt_socket_id, rtt);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        signal_rpc_request_received_(transport_message.data().rpc_message(),
                                     udt_socket_id, rtt);
        // Leave socket open to send response on.
      } else {
        signal_rpc_response_received_(transport_message.data().rpc_message(),
                                      udt_socket_id, rtt);
        UDT::close(udt_socket_id);
      }
      break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
      HandleRendezvousMessage(transport_message.data().hole_punching_message());
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

// void TransportUDT::MessageHandler() {
//   while (true) {
//     {
//       {
//         boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//         while (incoming_msgs_queue_.empty() && !stop_) {
//           msg_hdl_cond_.wait(guard);
//         }
//       }
//       if (stop_) return;
//       IncomingMessages msg;
//       {
//         boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//         msg.msg = incoming_msgs_queue_.front().msg;
//         msg.raw_data = incoming_msgs_queue_.front().raw_data;
//         msg.connection_id = incoming_msgs_queue_.front().connection_id;
//         msg.rtt = incoming_msgs_queue_.front().rtt;
//         incoming_msgs_queue_.pop_front();
//       }
//       {
//         boost::mutex::scoped_lock gaurd(recv_mutex_);
//         data_arrived_.erase(msg.connection_id);
//       }
//       if (msg.raw_data.empty())
//         SignalRPCMessageReceived_(msg.msg, msg.connection_id,
//                               msg.rtt);
//       else
//         signal_message_received_(msg.raw_data, msg.connection_id,
//                           msg.rtt);
//       ips_from_connections_.erase(msg.connection_id);
//       boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//     }
//   }
// }
// 


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
    LOG(ERROR) << "Invalid local address " << local_ip << std::endl;
    return false;
  }

  UdtSocketId skt = UDT::socket(local->ai_family, local->ai_socktype,
                              local->ai_protocol);
  if (UDT::ERROR == UDT::bind(skt, local->ai_addr, local->ai_addrlen)) {
    LOG(ERROR) << "(" << listening_port_ << ") UDT Bind error: " <<
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

//bool TransportUDT::GetPeerAddr(const ConnectionId &connection_id,
//                               struct sockaddr *peer_address) {
//  std::map<ConnectionId, struct sockaddr>::iterator it;
//  it = ips_from_connections_.find(connection_id);
//  if (it == ips_from_connections_.end())
//    return false;
//  *peer_address = ips_from_connections_[connection_id];
//  return true;
//}
//
// int TransportUDT::ConnectToSend(const IP &remote_ip,
//                                 const Port &remote_port,
//                                 const IP &local_ip,
//                                 const Port &local_port,
//                                 const IP &rendezvous_ip,
//                                 const Port &rendezvous_port,
//                                 const bool &keep_connection,
//                                 ConnectionId *connection_id) {
//   UdtSocketId skt;
//   // the node receiver is directly connected, no rendezvous information
//   if (rendezvous_ip.empty() && rendezvous_port == 0) {
//     bool remote(local_ip.empty() || local_port == 0);
//     // the node is believed to be local
//     if (!remote) {
//       int conn_result = Connect(local_ip, local_port, &skt);
//       if (conn_result != 0) {
//         DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend "
//             << "failed to connect to local port " << local_port <<
//             " with udp error " << conn_result << std::endl;
//         UDT::close(skt);
//         remote = true;
//         (*base::PublicRoutingTable::GetInstance())
//             [base::IntToString(listening_port_)]->
//                 UpdateLocalToUnknown(local_ip, local_port);
//       }
//     }
//     if (remote) {
//       int conn_result = Connect(remote_ip, remote_port, &skt);
//       if (conn_result != 0) {
//         DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend "
//             << "failed to connect to remote port " << remote_port << std::endl;
//         UDT::close(skt);
//         return conn_result;
//       }
//     }
//   } else {
//     UdtSocketId rend_skt;
//     int conn_result = Connect(rendezvous_ip, rendezvous_port, &rend_skt);
//     if (conn_result != 0) {
//       DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend " <<
//           "failed to connect to rendezvouz port " << rendezvous_port <<
//           std::endl;
//       UDT::close(rend_skt);
//       return conn_result;
//     }
//     TransportMessage t_msg;
//     HolePunchingMsg *msg = t_msg.mutable_hp();
//     msg->set_ip(remote_ip);
//     msg->set_port(remote_port);
//     msg->set_type(FORWARD_REQ);
//     std::string ser_msg;
//     t_msg.SerializeToString(&ser_msg);
//     int64_t rend_data_size = ser_msg.size();
// 
//     // send rendezvous msg size information
//     if (UDT::ERROR == UDT::send(rend_skt,
//         reinterpret_cast<char*>(&rend_data_size),
//         sizeof(rend_data_size), 0)) {
//       UDT::close(rend_skt);
//       return 1;
//     }
// 
//     if (UDT::ERROR == UDT::send(rend_skt, ser_msg.c_str(), rend_data_size, 0)) {
//       UDT::close(rend_skt);
//       return 1;
//     }
//     // TODO(jose): establish connect in a thread or in another asynchronous
//     // way to avoid blocking in the upper layers
//     int retries = 4;
//     bool connected = false;
//     for (int i = 0; i < retries && !connected; ++i) {
//       conn_result = Connect(remote_ip, remote_port, &skt);
//       if (conn_result == 0)
//         connected = true;
//     }
//     if (!connected) {
//       DLOG(ERROR) << "(" << listening_port_ << ") Transport::ConnectToSend " <<
//           "failed to connect to remote port " << remote_port << std::endl;
//       UDT::close(skt);
//       return conn_result;
//     }
//   }
//   if (keep_connection) {
//    // AddIncomingConnection(skt, connection_id);
//   } else  {
//     current_id_ = base::GenerateNextTransactionId(current_id_);
//     *connection_id = current_id_;
//   }
//   {
//     boost::mutex::scoped_lock guard(msg_hdl_mutex_);
//     send_sockets_[*connection_id] = skt;
//   }
//   return 0;
// }

// int TransportUDT::StartLocal(const Port &port) {
//   if (!stop_)
//     return 1;
// //   if ((rpc_message_notifier_.empty() && message_notifier_.empty()) ||
// //      send_notifier_.empty())
// //     return 1;
//   listening_port_ = port;
//   memset(&addrinfo_hints_, 0, sizeof(struct addrinfo));
//   addrinfo_hints_.ai_flags = AI_PASSIVE;
//   addrinfo_hints_.ai_family = AF_INET;
//   addrinfo_hints_.ai_socktype = SOCK_STREAM;
//   std::string service = boost::lexical_cast<std::string>(port);
//   if (0 != getaddrinfo("127.0.0.1", service.c_str(), &addrinfo_hints_,
//       &addrinfo_result_)) {
//     return 1;
//   }
//   listening_socket_ = UDT::socket(addrinfo_result_->ai_family,
//       addrinfo_result_->ai_socktype, addrinfo_result_->ai_protocol);
//   // UDT Options
// //   bool blockng = false;
// //   UDT::setsockopt(listening_socket_, 0, UDT_RCVSYN, &blockng, sizeof(blockng));
//   if (UDT::ERROR == UDT::bind(listening_socket_, addrinfo_result_->ai_addr,
//       addrinfo_result_->ai_addrlen)) {
//     LOG(ERROR) << "Error binding listening socket" <<
//         UDT::getlasterror().getErrorMessage() << std::endl;
//     freeaddrinfo(addrinfo_result_);
//     return 1;
//   }
//   // Modify the port to reflect the port UDT has chosen
//   struct sockaddr_in name;
//   int namelen;
//   if (listening_port_ == 0) {
//     UDT::getsockname(listening_socket_, (struct sockaddr *)&name, &namelen);
//     listening_port_ = ntohs(name.sin_port);
//         UDT::getsockname(listening_socket_, (struct sockaddr *)&name, &namelen);
//     listening_port_ = ntohs(name.sin_port);
//     std::string service = boost::lexical_cast<std::string>(listening_port_);
//     freeaddrinfo(addrinfo_result_);
//     if (0 != getaddrinfo(NULL, service.c_str(), &addrinfo_hints_,
//       &addrinfo_result_)) {
//       freeaddrinfo(addrinfo_result_);
//       return 1;
//     }
//   }
// 
//   if (UDT::ERROR == UDT::listen(listening_socket_, 20)) {
//     LOG(ERROR) << "Failed to start the listening socket " << listening_socket_
//         << " : " << UDT::getlasterror().getErrorMessage() << std::endl;
//     freeaddrinfo(addrinfo_result_);
//     return 1;
//   }
//   stop_ = false;
//   // start the listening loop
//   try {
//     accept_routine_.reset(new boost::thread(
//       &TransportUDT::AcceptConnHandler, this));
//     recv_routine_.reset(new boost::thread(&TransportUDT::ReceiveHandler,
//         this));
//     send_routine_.reset(new boost::thread(&TransportUDT::SendHandle, this));
//     handle_msgs_routine_.reset(new boost::thread(
//       &TransportUDT::MessageHandler, this));
//   } catch(const boost::thread_resource_error& ) {
//     stop_ = true;
//     int result;
//     result = UDT::close(listening_socket_);
//     freeaddrinfo(addrinfo_result_);
//     return 1;
//   }
//   current_id_ = base::GenerateNextTransactionId(current_id_);
//   return 0;
// }

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
