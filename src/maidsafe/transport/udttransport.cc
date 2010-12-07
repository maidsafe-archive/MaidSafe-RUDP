/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/transport/udttransport.h"

#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/scoped_array.hpp>
#include <google/protobuf/descriptor.h>
#include "maidsafe/base/log.h"

#include "maidsafe/base/online.h"
#include "maidsafe/base/routingtable.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/protobuf/transport_message.pb.h"

namespace transport {

NatDetails UdtTransport::nat_details_;

UdtTransport::UdtTransport()
    : Transport(),
      listening_map_(),
      unused_sockets_(),
      managed_endpoint_sockets_(),
      pending_managed_endpoint_sockets_(),
      stop_managed_connections_(false),
      managed_connections_stopped_(true),
      managed_endpoint_sockets_mutex_(),
      managed_endpoints_cond_var_(),
      managed_endpoint_listening_addrinfo_(),
      managed_endpoint_listening_port_(0),
      listening_threadpool_(new base::Threadpool(kDefaultThreadpoolSize)),
      general_threadpool_(new base::Threadpool(kDefaultThreadpoolSize)),
      check_connections_(),
      nat_detection_nodes_(),
      nat_detection_thread_() {
  UDT::startup();
}

UdtTransport::UdtTransport(std::vector<NatDetectionNode> nat_detection_nodes)
    : Transport(),
      listening_map_(),
      unused_sockets_(),
      managed_endpoint_sockets_(),
      pending_managed_endpoint_sockets_(),
      stop_managed_connections_(false),
      managed_connections_stopped_(true),
      managed_endpoint_sockets_mutex_(),
      managed_endpoints_cond_var_(),
      managed_endpoint_listening_addrinfo_(),
      managed_endpoint_listening_port_(0),
      listening_threadpool_(new base::Threadpool(0)),
      general_threadpool_(new base::Threadpool(kDefaultThreadpoolSize)),
      check_connections_(),
      nat_detection_nodes_(nat_detection_nodes),
      nat_detection_thread_() {
  UDT::startup();
}

UdtTransport::~UdtTransport() {
  StopAllListening();
  StopManagedConnections();
}

void UdtTransport::CleanUp() {
  UDT::cleanup();
}

void UdtTransport::ReportRendezvousResult(const SocketId &udt_socket_id,
                                          const IP &connection_node_ip,
                                          const Port &connection_node_port) {
  SocketId rendezvous_socket_id;
  TransportCondition tc = TryRendezvous(connection_node_ip,
                                        connection_node_port,
                                        &rendezvous_socket_id);

  DLOG(INFO) << "Result of rendezvous connect = " << tc << std::endl;
  if (udt_socket_id == UDT::INVALID_SOCK) {
    UdtConnection conn(this, rendezvous_socket_id);
    NatInformation *ni =
        conn.transport_message_.mutable_data()->mutable_nat_information();
    ni->set_ip(connection_node_ip);
    ni->set_port(connection_node_port);
    ni->set_nat_type(kPortRestricted);
    conn.Send(conn.transport_message_, 0);
  } else {
    UdtConnection udt_connection(this, udt_socket_id);
    udt_connection.transport_message_.set_type(TransportMessage::kClose);
    ConnectionResult *cr =
        udt_connection.transport_message_.mutable_data()->
            mutable_connection_result();
    cr->set_result(tc == kSuccess);
    udt_connection.Send(udt_connection.transport_message_, 0);
  }
}

void UdtTransport::PerformNatDetection(
    const SocketId &socket_id,
    const NatDetection &nat_detection_message) {
  // TODO(Team#5#) - Decide on maximum number of simultaneous NAT detections.
  struct sockaddr_in peer_sockaddr;
  int peer_sockaddr_size;
  if (UDT::ERROR ==
      UDT::getpeername(socket_id,
                       reinterpret_cast<sockaddr*>(&peer_sockaddr),
                       &peer_sockaddr_size)) {
    DLOG(ERROR) << "HandleManagedSocketRequest getpeername error: "
                << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(socket_id);
    return;
  }
  IP remote_ip(inet_ntoa(peer_sockaddr.sin_addr));
  Port remote_port(ntohs(peer_sockaddr.sin_port));

  TransportMessage tm;
  tm.set_type(TransportMessage::kClose);
  if (remote_port == nat_detection_message.candidate_port()) {
    for (int n = 0; n < nat_detection_message.candidate_ips_size(); ++n) {
      if (nat_detection_message.candidate_ips(n) == remote_ip) {
        // Send directly connected message
        NatInformation *ni =  tm.mutable_data()->mutable_nat_information();
        ni->set_ip(remote_ip);
        ni->set_port(remote_port);
        ni->set_nat_type(kDirectlyConnected);
        UdtConnection conn(this, socket_id);
        conn.Send(tm, 0);
        return;
      }
    }
  }

  std::multimap<std::string, boost::uint16_t> nodes;
  (*base::PublicRoutingTable::GetInstance())
      [boost::lexical_cast<std::string>(listening_ports_[0])]->
          GetShuflledDirectlyConnectedNodes(&nodes);
  ConnectionNode *cn = tm.mutable_data()->mutable_connection_node();
  cn->set_connection_node_ip(remote_ip);
  cn->set_connection_node_port(remote_port);
  tm.set_type(TransportMessage::kKeepAlive);
  std::multimap<std::string, boost::uint16_t>::iterator it = nodes.begin();
  for (; it != nodes.end(); ++it) {
    // Send request to random directly connected node
    UdtConnection udt_conn(this, (*it).first, (*it).second, "", 0);
    if (udt_conn.socket_id() == UDT::INVALID_SOCK)
      continue;
    udt_conn.Send(tm, 0);

    // Get the incoming message size
    boost::uint32_t timeout(456);
    udt_conn.ReceiveData(timeout);

    const google::protobuf::Message::Reflection *reflection =
        udt_conn.transport_message_.data().GetReflection();
    std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
    reflection->ListFields(udt_conn.transport_message_.data(),
                           &field_descriptors);
    if (field_descriptors.size() != 1U) {
      UDT::close(udt_conn.socket_id());
      continue;
    }

    UDT::close(udt_conn.socket_id());
    if (field_descriptors.at(0)->number() !=
        TransportMessage::Data::kConnectionResultFieldNumber) {
      UDT::close(udt_conn.socket_id());
      continue;
    }

    ConnectionResult connection_result =
          udt_conn.transport_message_.data().connection_result();
    UdtConnection conn_to_a(this, socket_id);
    conn_to_a.transport_message_.set_type(TransportMessage::kClose);
    if (connection_result.result()) {
      // We're done with Nat Detection. Node's full cone.
      NatInformation *ni =
          conn_to_a.transport_message_.mutable_data()->
              mutable_nat_information();
      ni->set_ip(remote_ip);
      ni->set_port(remote_port);
      ni->set_nat_type(kFullCone);
      conn_to_a.Send(conn_to_a.transport_message_, 0);
      return;
    } else {
      // WARNING! This might be very dodgy coding! It just might.
      bool connected_to_d(false);
      while (++it != nodes.end()) {
        // Connect to D
        UdtConnection toD(this, (*it).first, (*it).second, "", 0);
        if (toD.socket_id_ == UDT::INVALID_SOCK)
          continue;
        toD.transport_message_.set_type(TransportMessage::kClose);
        connected_to_d = true;

        // Send the rendezvous message to A and contact D to connect to A
        RendezvousNode *rn =
            conn_to_a.transport_message_.mutable_data()->
                mutable_rendezvous_node();
        rn->set_rendezvous_node_ip((*it).first);
        rn->set_rendezvous_node_port((*it).second);
        conn_to_a.Send(conn_to_a.transport_message_, 0);

        ConnectionNode *cn =
            toD.transport_message_.mutable_data()->mutable_connection_node();
        cn->set_connection_node_ip(remote_ip);
        cn->set_connection_node_port(remote_port);
        toD.Send(toD.transport_message_, 0);
        return;
      }

      if (!connected_to_d) {
        NatInformation *ni =
            conn_to_a.transport_message_.mutable_data()->
                mutable_nat_information();
        ni->set_ip(remote_ip);
        ni->set_port(remote_port);
        ni->set_nat_type(kUnableToDetect);
        conn_to_a.Send(conn_to_a.transport_message_, 0);
        return;
      }
    }
  }
}

void UdtTransport::DoNatDetection() {
  boost::shared_ptr<addrinfo const> address_info;
  for (size_t b = 0; b < nat_detection_nodes_.size(); ++b) {
    UdtConnection udt_conn(this, nat_detection_nodes_.at(b).rendezvous_ip,
                           nat_detection_nodes_.at(b).rendezvous_port, "", 0);

    // Create message
    TransportMessage transport_message;
    transport_message.set_type(TransportMessage::kKeepAlive);
    NatDetection *nd =
        transport_message.mutable_data()->mutable_nat_detection();
    nd->set_candidate_port(listening_ports().at(0));
    std::vector<IP> addresses(base::GetLocalAddresses());
    for (size_t n = 0; n < addresses.size(); ++n)
      nd->add_candidate_ips(addresses.at(n));

    // Send message
    udt_conn.transport_message_ = transport_message;
    TransportCondition tc = udt_conn.SendDataSize();
    if (tc != kSuccess) {
      UDT::close(udt_conn.socket_id());
      continue;
    }

    tc = udt_conn.SendDataContent();
    if (tc != kSuccess) {
      UDT::close(udt_conn.socket_id());
      continue;
    }

    // Get the incoming message size
    boost::uint32_t timeout(456);
    udt_conn.ReceiveData(timeout);

    // Analyse message
    const google::protobuf::Message::Reflection *reflection =
        udt_conn.transport_message_.data().GetReflection();
    std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
    reflection->ListFields(udt_conn.transport_message_.data(),
                           &field_descriptors);
    if (field_descriptors.size() != 1U) {
      UDT::close(udt_conn.socket_id());
      continue;
    }

    UDT::close(udt_conn.socket_id());
    if (field_descriptors.at(0)->number() ==
        TransportMessage::Data::kNatInformationFieldNumber) {
      // We're done with Nat Detection. We're directly connected or full cone
      b = nat_detection_nodes_.size();
      NatInformation nat_info =
          udt_conn.transport_message_.data().nat_information();
      if (!nat_info.IsInitialized())
        continue;
      if (nat_info.nat_type() != kFullCone ||
          nat_info.nat_type() != kDirectlyConnected) {
        DLOG(ERROR) << "something's very very wrong. Not awesome." << std::endl;
        continue;
      } else {
        nat_details_.nat_type = static_cast<NatType>(nat_info.nat_type());
        nat_details_.external_ip = nat_info.ip();
        nat_details_.external_port = nat_info.port();
      }
    } else if (TransportMessage::Data::kRendezvousNodeFieldNumber) {
      RendezvousNode rv_node =
          udt_conn.transport_message_.data().rendezvous_node();
      if (!rv_node.IsInitialized())
        continue;
      SocketId rendezvous_socket_id(UDT::INVALID_SOCK);
      if (TryRendezvous(rv_node.rendezvous_node_ip(),
                        rv_node.rendezvous_node_port(),
                        &rendezvous_socket_id) !=
          kSuccess) {
        continue;
      }
      UdtConnection rv_connection(this, rendezvous_socket_id);
      boost::uint32_t rendezvous_timeout(456);
      rv_connection.ReceiveData(rendezvous_timeout);
      UDT::close(rendezvous_socket_id);
      if (!rv_connection.transport_message_.IsInitialized() ||
          !rv_connection.transport_message_.data().has_nat_information())
        continue;
      b = nat_detection_nodes_.size();
      NatInformation nat_info =
          rv_connection.transport_message_.data().nat_information();
      nat_details_.nat_type = kPortRestricted;
      nat_details_.external_ip = nat_info.ip();
      nat_details_.external_port = nat_info.port();
      nat_details_.rendezvous_ip = nat_detection_nodes_.at(b).rendezvous_ip;
      nat_details_.rendezvous_port = nat_detection_nodes_.at(b).rendezvous_port;
    }
  }
  if (nat_details_.nat_type == kFullCone ||
      nat_details_.nat_type == kPortRestricted) {}  // Setup pinging routine
}

TransportCondition UdtTransport::TryRendezvous(const IP &ip, const Port &port,
                                               SocketId *rendezvous_socket_id) {
  if (nat_details_.nat_type == kNotConnected)
    return kError;
  // Get a new socket descriptor
  boost::shared_ptr<addrinfo const> address_info;
  TransportCondition transport_condition(
      udtutils::GetNewSocket(ip, port, true, rendezvous_socket_id,
                             &address_info));
  if (transport_condition != kSuccess)
    return transport_condition;

  // Set socket options
  bool rendezvous(true);
  if (UDT::ERROR == UDT::setsockopt(*rendezvous_socket_id, 0, UDT_RENDEZVOUS,
                                    &rendezvous, sizeof(rendezvous))) {
    DLOG(ERROR) << "UDT TryRendezvous error: "
                << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(*rendezvous_socket_id);
    return kSetOptionFailure;
  }

  // Bind this socket
  if (UDT::ERROR == UDT::bind(*rendezvous_socket_id, address_info->ai_addr,
                              address_info->ai_addrlen)) {
    DLOG(WARNING) << "UDT bind error: " << UDT::getlasterror().getErrorMessage()
                  << std::endl;
    UDT::close(*rendezvous_socket_id);
    return kBindError;
  }

  // Try to connect this socket
  return udtutils::Connect(*rendezvous_socket_id, address_info);
}

Port UdtTransport::DoStartListening(const IP &ip,
                                    const Port &try_port,
                                    bool managed_connection_listener,
                                    TransportCondition *transport_condition) {
  // Get a new socket descriptor
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  if (udtutils::GetNewSocket(ip, try_port, true, &listening_socket_id,
                             &address_info) != kSuccess) {
    if (transport_condition != NULL)
      *transport_condition = kInvalidAddress;
    return 0;
  }

  // Set socket options
  if (managed_connection_listener) {
    if (SetManagedSocketOptions(listening_socket_id) != kSuccess) {
      DLOG(ERROR) << "DoStartListening setsockopt error." << std::endl;
      UDT::close(listening_socket_id);
      return 0;
    }
  }

  // Bind this socket
  if (UDT::ERROR == UDT::bind(listening_socket_id, address_info->ai_addr,
                              address_info->ai_addrlen)) {
    DLOG(WARNING) << "UDT bind error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(listening_socket_id);
    if (transport_condition != NULL)
      *transport_condition = kBindError;
    return 0;
  }

  // Get the actual listening port UDT has assigned
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(listening_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port listening_port = ntohs(name.sin_port);

  // For managed connections, this must be the same port as the one requested
  if (managed_connection_listener && (try_port != listening_port)) {
    DLOG(ERROR) << "Failed to bind to requested port "<< try_port <<
        ": " << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(listening_socket_id);
    if (transport_condition != NULL)
      *transport_condition = kBindError;
    return 0;
  }

  // Start listening
  if (UDT::ERROR == UDT::listen(listening_socket_id, 10240)) {
    DLOG(ERROR) << "Failed to start listening on port "<< listening_port <<
        ": " << UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(listening_socket_id);
    if (transport_condition != NULL)
      *transport_condition = kListenError;
    return 0;
  }

  // Increment the size of the listening threadpool and start accepting new
  // incoming connections
  size_t listening_ports_size;
  {
    boost::mutex::scoped_lock lock(listening_ports_mutex_);
    listening_ports_size = listening_ports_.size();
  }
//  if (!listening_threadpool_->Resize(listening_ports_size + 1)) {
//    UDT::close(listening_socket_id);
//    if (transport_condition != NULL)
//      *transport_condition = kThreadResourceError;
//    return 0;
//  }
  {
    boost::mutex::scoped_lock lock(listening_ports_mutex_);
    listening_ports_.push_back(listening_port);
    listening_map_.insert(
        std::pair<Port, SocketId>(listening_port, listening_socket_id));
  }

  if (!listening_threadpool_->EnqueueTask(
      boost::bind(&UdtTransport::AcceptConnection, this, listening_port,
                  listening_socket_id))) {
    UDT::close(listening_socket_id);
    if (transport_condition != NULL)
      *transport_condition = kThreadResourceError;
    return 0;
  }
  if (managed_connection_listener) {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    managed_endpoint_listening_addrinfo_ = address_info;
    managed_endpoint_listening_port_ = listening_port;
  }

  if (transport_condition != NULL)
    *transport_condition = kSuccess;

  // Do NAT traversing if needed
  if (ValidIP(nat_detection_nodes_.at(0).rendezvous_ip) &&
      ValidPort(nat_detection_nodes_.at(0).rendezvous_port)) {
//  nat_detection_thread_ = boost::thread(&UdtTransport::DoNatDetection, this);
    DoNatDetection();
  }

  return listening_port;
}

Port UdtTransport::StartListening(const IP &ip,
                                  const Port &try_port,
                                  TransportCondition *transport_condition) {
  return DoStartListening(ip, try_port, false, transport_condition);
}

bool UdtTransport::StopListening(const Port &port) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  listening_ports_.erase(
      std::remove(listening_ports_.begin(), listening_ports_.end(), port),
      listening_ports_.end());
  std::map<Port, SocketId>::iterator it = listening_map_.find(port);
  if (it != listening_map_.end()) {
    UDT::close((*it).second);
    listening_map_.erase(it);
  }
//  listening_threadpool_->Resize(listening_ports_.size());
  return true;
}

bool UdtTransport::StopAllListening() {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  listening_ports_.clear();
  std::map<Port, SocketId>::iterator it = listening_map_.begin();
  for (; it != listening_map_.end(); ++it)
    UDT::close((*it).second);
  return true;
}

void UdtTransport::StopManagedConnections() {
  try {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    stop_managed_connections_ = true;
    managed_endpoints_cond_var_.notify_all();
    bool success = managed_endpoints_cond_var_.timed_wait(lock,
        boost::posix_time::milliseconds(110),
        boost::bind(&std::vector<SocketId>::empty,
                    boost::ref(managed_endpoint_sockets_)));
    if (!success)
      DLOG(WARNING) << "StopManagedConxns timed_wait timeout." << std::endl;
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "StopManagedConxns timed_wait: " << e.what() << std::endl;
  }
  if (check_connections_.get() != NULL) {
    try {
      bool success =
          check_connections_->timed_join(boost::posix_time::milliseconds(1010));
      if (!success)
        DLOG(WARNING) << "StopManagedConxns timed_join timeout." << std::endl;
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "StopManagedConxns timed_join: " << e.what() << std::endl;
    }
  }
}

void UdtTransport::ReAllowIncomingManagedConnections() {
  boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
  stop_managed_connections_ = false;
}

TransportCondition UdtTransport::PunchHole(const IP &/*remote_ip*/,
                                           const Port &/*remote_port*/,
                                           const IP &/*rendezvous_ip*/,
                                           const Port &/*rendezvous_port*/) {
  return kSuccess;
}

SocketId UdtTransport::PrepareToSend(const IP &remote_ip,
                                     const Port &remote_port,
                                     const IP &/*rendezvous_ip*/,
                                     const Port &/*rendezvous_port*/) {
  UdtConnection udt_connection(this, remote_ip, remote_port, "", 0);
  // socket ID at map.begin() should be lowest value, so oldest
  if (unused_sockets_.size() == kMaxUnusedSocketsCount)
    unused_sockets_.erase(unused_sockets_.begin());
  UnusedSockets::value_type rtss(udt_connection.socket_id_,
                                 udt_connection.peer_);
  if (unused_sockets_.empty())
    unused_sockets_.insert(rtss);
  else
    unused_sockets_.insert(--unused_sockets_.end(), rtss);
  return udt_connection.socket_id();
}

void UdtTransport::Send(const TransportMessage &transport_message,
                        const SocketId &socket_id,
                        const boost::uint32_t &timeout_wait_for_response) {
  std::vector<SocketId> to_check, checked;
  to_check.push_back(socket_id);
  if (UDT::ERROR == UDT::selectEx(to_check, NULL, &checked, NULL, 50)) {
    DLOG(ERROR) << "Send error: " << UDT::getlasterror().getErrorMessage()
                << std::endl;
    return;
  }
  UdtConnection udt_connection(this, socket_id);
  if (checked.empty()) {
    UnusedSockets::iterator it = unused_sockets_.find(socket_id);
    if (it == unused_sockets_.end())
      return;
    udt_connection.peer_ = (*it).second;
    unused_sockets_.erase(it);
  }
  udt_connection.Send(transport_message, timeout_wait_for_response);
}

void UdtTransport::SendFile(const fs::path &/*path*/,
                            const SocketId &/*socket_id*/) {
}

ManagedEndpointId UdtTransport::AddManagedEndpoint(
    const IP &remote_ip,
    const Port &remote_port,
    const IP &rendezvous_ip,
    const Port &rendezvous_port,
    const std::string &our_identifier,
    const boost::uint16_t &/*frequency*/,
    const boost::uint16_t &/*retry_count*/,
    const boost::uint16_t &/*retry_frequency*/) {
  // Get temp socket bound to managed_endpoint_listening_port_ to send request
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    stop_managed_connections_ = false;
  }
  SocketId initial_peer_socket_id =
      GetNewManagedEndpointSocket(remote_ip, remote_port, rendezvous_ip,
                                  rendezvous_port);
  if (initial_peer_socket_id < 0)
    return kNoSocket;

  // Prepare & send transport message to peer.  Keep initial socket alive to
  // allow peer time to call getpeerinfo
  UdtConnection udt_connection(this, initial_peer_socket_id);
  udt_connection.transport_message_.set_type(TransportMessage::kKeepAlive);
  ManagedEndpointMessage *managed_endpoint_message = udt_connection.
      transport_message_.mutable_data()->mutable_managed_endpoint_message();
  managed_endpoint_message->set_message_id(initial_peer_socket_id);
  managed_endpoint_message->set_identifier(our_identifier);
//  managed_endpoint_message->set_identifier(std::string(1500, 'A'));
//  std::cout << "SIZE 2: " << transport_message.ByteSize() << std::endl;

  // Wait for peer to send response to managed_endpoint_listening_port_
  try {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    pending_managed_endpoint_sockets_.insert(
        std::pair<SocketId, SocketId>(initial_peer_socket_id, 0));
    udt_connection.SendData(UdtConnection::kKeepAlive,
                            kAddManagedConnectionTimeout);
    bool success = managed_endpoints_cond_var_.timed_wait(lock,
        boost::posix_time::milliseconds(kAddManagedConnectionTimeout + 100),
        boost::bind(&UdtTransport::PendingManagedSocketReplied, this,
                    initial_peer_socket_id));
    UDT::close(initial_peer_socket_id);
    if (success) {
      std::map<SocketId, SocketId>::iterator it =
          pending_managed_endpoint_sockets_.find(initial_peer_socket_id);
      if (it == pending_managed_endpoint_sockets_.end()) {
        // This shouldn't happen - pending_managed_endpoint_sockets_ only gets
        // modified here.
        DLOG(ERROR) << "AddManagedEndpoint error." << std::endl;
        return kAddManagedEndpointError;
      }
      return (*it).second;
    } else {
      pending_managed_endpoint_sockets_.erase(initial_peer_socket_id);
      DLOG(INFO) << "AddManagedEndpoint timeout." << std::endl;
      return kAddManagedEndpointTimeout;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "In AddManagedEndpoint: " << e.what() << std::endl;
    UDT::close(initial_peer_socket_id);
    return kAddManagedEndpointError;
  }
}

TransportCondition UdtTransport::StartManagedEndpointListener(
    const SocketId &initial_peer_socket_id,
    boost::shared_ptr<addrinfo const> peer) {
  // Check not already started and set managed_endpoint_listening_port_ to 1 to
  // indicate that startup has begun.
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    if (managed_endpoint_listening_port_ > 1)
      return kAlreadyStarted;
    managed_endpoint_listening_port_ = 1;
  }

  // Connect to peer
  TransportCondition transport_condition =
      udtutils::Connect(initial_peer_socket_id, peer);
  if (transport_condition != kSuccess) {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    managed_endpoint_listening_port_ = 0;
    return transport_condition;
  }

  // Get connected socket local port
  struct sockaddr_in name;
  int name_size;
  UDT::getsockname(initial_peer_socket_id, reinterpret_cast<sockaddr*>(&name),
                   &name_size);
  Port sending_port = ntohs(name.sin_port);

  // Start a listening socket on this port
  if (sending_port != DoStartListening("", sending_port, true, NULL)) {
    UDT::close(initial_peer_socket_id);
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    managed_endpoint_listening_port_ = 0;
    return kListenError;
  }
  return kSuccess;
}

TransportCondition UdtTransport::SetManagedSocketOptions(
    const SocketId &udt_socket_id) {
  // Buffer will be set to minimum of requested size and socket's MSS (maximum
  // packet size).
  int mtu(100);
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDT_MSS, &mtu,
      sizeof(mtu))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDT_MSS error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  int fc(16);
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDT_FC, &fc,
                                    sizeof(fc))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDT_FC error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDT_SNDBUF,
      &kManagedSocketBufferSize, sizeof(kManagedSocketBufferSize))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDT_SNDBUF error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDT_RCVBUF,
      &kManagedSocketBufferSize, sizeof(kManagedSocketBufferSize))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDT_RCVBUF error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDP_SNDBUF,
      &kManagedSocketBufferSize, sizeof(kManagedSocketBufferSize))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDP_SNDBUF error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDP_RCVBUF,
      &kManagedSocketBufferSize, sizeof(kManagedSocketBufferSize))) {
    DLOG(ERROR) << "SetManagedSocketOptions UDP_RCVBUF error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSetOptionFailure;
  }
  return kSuccess;
}

SocketId UdtTransport::GetNewManagedEndpointSocket(
    const IP &remote_ip,
    const Port &remote_port,
    const IP &/*rendezvous_ip*/,
    const Port &/*rendezvous_port*/) {
  // Get a new socket descriptor to send on managed_endpoint_listening_port_
  SocketId initial_peer_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> peer;
  if (udtutils::GetNewSocket(remote_ip, remote_port, true,
                             &initial_peer_socket_id, &peer) != kSuccess) {
    DLOG(ERROR) << "GetNewManagedEndpointInitialSocket error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kNoSocket;
  }
  if (SetManagedSocketOptions(initial_peer_socket_id) != kSuccess) {
    DLOG(ERROR) << "GetNewManagedEndpointSocket setsockopt error." << std::endl;
    UDT::close(initial_peer_socket_id);
    return kNoSocket;
  }

  Port listening_port(1);
  int attempts(0);
  const int kMaxAttempts(3);
  // Start listening socket for all managed endpoints if not already done
  while (listening_port < 2) {
    {
      boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
      listening_port = managed_endpoint_listening_port_;
    }
    if (listening_port == 0) {  // Need to start listening socket
      ++attempts;
      if (StartManagedEndpointListener(initial_peer_socket_id, peer) ==
          kSuccess) {
        boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
        listening_port = managed_endpoint_listening_port_;
        return initial_peer_socket_id;
      } else {
        if (attempts == kMaxAttempts)
          return kListenError;
      }
    } else if (listening_port == Port(-1)) {  // Startup is already in progress
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
  }

  // Bind this new socket
  if (UDT::ERROR ==
      UDT::bind(initial_peer_socket_id,
                managed_endpoint_listening_addrinfo_->ai_addr,
                managed_endpoint_listening_addrinfo_->ai_addrlen)) {
    DLOG(WARNING) << "UDT bind error in GetNewManagedEndpointInitialSocket: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(initial_peer_socket_id);
    return kBindError;
  }

  // Connect to peer
  if (udtutils::Connect(initial_peer_socket_id, peer) != kSuccess) {
    DLOG(ERROR) << "GetNewManagedEndpointInitialSocket connect error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(initial_peer_socket_id);
    return kConnectError;
  }

  return initial_peer_socket_id;
}

bool UdtTransport::RemoveManagedEndpoint(
      const ManagedEndpointId &managed_endpoint_id) {
  // Send '-' to peer to indicate socket closure.
  char close_indicator('-');
  UDT::send(managed_endpoint_id, &close_indicator, 1, 0);
  UDT::close(managed_endpoint_id);
  std::vector<ManagedEndpointId>::iterator endpoint_iterator;
  boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
  endpoint_iterator = std::find(managed_endpoint_sockets_.begin(),
                                managed_endpoint_sockets_.end(),
                                managed_endpoint_id);
  if (endpoint_iterator != managed_endpoint_sockets_.end())
    managed_endpoint_sockets_.erase(endpoint_iterator);
  return true;
}

void UdtTransport::AcceptConnection(const Port &port,
                                    const SocketId &udt_socket_id) {
  // Accept incoming connections asynchronously
  bool accept_synchronously(false);
  if (UDT::ERROR == UDT::setsockopt(udt_socket_id, 0, UDT_RCVSYN,
      &accept_synchronously, sizeof(accept_synchronously))) {
    DLOG(ERROR) << "AcceptConnection UDT_RCVSYN error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(udt_socket_id);
    return;
  }

  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  SocketId receiver_socket_id;
  std::vector<Port>::iterator port_iterator;
  while (true) {
    {
      boost::mutex::scoped_lock lock(listening_ports_mutex_);
      port_iterator =
          find(listening_ports_.begin(), listening_ports_.end(), port);
      if (port_iterator == listening_ports_.end()) {
        UDT::close(udt_socket_id);
        return;
      }
    }
    if (UDT::INVALID_SOCK == (receiver_socket_id = UDT::accept(udt_socket_id,
        reinterpret_cast<sockaddr*>(&clientaddr), &addrlen))) {
      // If we lose the listening socket, check that it's a deliberate closure.
      boost::mutex::scoped_lock lock(listening_ports_mutex_);
      port_iterator =
          find(listening_ports_.begin(), listening_ports_.end(), port);
      if (port_iterator != listening_ports_.end()) {
        if (UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::EASYNCRCV) {
          boost::this_thread::sleep(boost::posix_time::milliseconds(1));
          continue;
        } else {
          DLOG(ERROR) << "UDT::accept error: " <<
              UDT::getlasterror().getErrorMessage() << std::endl;
          listening_ports_.erase(port_iterator);
          std::map<Port, SocketId>::iterator it = listening_map_.find(port);
          if (it != listening_map_.end())
            listening_map_.erase(it);
//          listening_threadpool_->Resize(listening_ports_.size());
          UDT::close(udt_socket_id);
          // If this is managed_endpoint_listening_port_, reset it to allow
          // restart if required
          {
            boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
            if (managed_endpoint_listening_port_ == *port_iterator) {
              managed_endpoint_listening_addrinfo_.reset();
              managed_endpoint_listening_port_ = 0;
            }
          }
        }
      }
      return;
    } else {
      bool receive_synchronously(true);
      if (UDT::ERROR == UDT::setsockopt(receiver_socket_id, 0, UDT_RCVSYN,
          &receive_synchronously, sizeof(receive_synchronously))) {
        DLOG(ERROR) << "UDT::accept (UDT_RCVSYN) error: " <<
            UDT::getlasterror().getErrorMessage() << std::endl;
        continue;
      }
      UdtConnection udt_connection(this, receiver_socket_id);
      if (!general_threadpool_->EnqueueTask(boost::bind(
          &UdtConnection::ReceiveData, udt_connection, kDynamicTimeout))) {
        DLOG(ERROR) << "AcceptConnection: failed to enqueue task." << std::endl;
        UDT::close(receiver_socket_id);
        continue;
      }
    }
  }
}

void UdtTransport::CheckManagedSockets() {
  std::vector<SocketId>::iterator socket_iterator;
  boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
  managed_connections_stopped_ = false;
  boost::scoped_array<char> holder(new char[10]);
  int received_count;
//  int indicator = base::RandomInt32();
//  std::cout << "CheckManagedSockets START  " << indicator << std::endl;
  while (true) {
    if (stop_managed_connections_) {
      // Send '-' to peer to indicate socket closure.
      char close_indicator('-');
      for (socket_iterator = managed_endpoint_sockets_.begin();
           socket_iterator != managed_endpoint_sockets_.end();
           ++socket_iterator) {
        UDT::send(*socket_iterator, &close_indicator, 1, 0);
        UDT::close(*socket_iterator);
      }
      managed_endpoint_sockets_.clear();
      managed_connections_stopped_ = true;
      managed_endpoints_cond_var_.notify_all();
      break;
    }
    std::vector<SocketId> copy_of_managed_ids(managed_endpoint_sockets_);
    lock.unlock();
    // Try to receive on each socket to check if connection is still OK.  If
    // "-" is received, close the socket.
    for (socket_iterator = copy_of_managed_ids.begin();
         socket_iterator != copy_of_managed_ids.end();
         ++socket_iterator) {
      UDT::getlasterror().clear();
      received_count = UDT::recv(*socket_iterator, holder.get(), 1, 0);
      if ((received_count && (holder[0] == '-')) ||
          UDT::getlasterror().getErrorCode() == UDT::ERRORINFO::ECONNLOST) {
//  if (received_count && (holder[0] == '-'))
//    std::cout << "\tRECEIVED '-' :  " << indicator << std::endl;
//  else
//    std::cout << "\tDIDN'T RECEIVE '-' :  " << indicator << std::endl;
        RemoveManagedEndpoint(*socket_iterator);
// std::cout << "FIRING on_managed_endpoint_lost_  " << indicator << std::endl;
        signals_->on_managed_endpoint_lost_(*socket_iterator);
        holder[0] = '\0';
      }
    }
    lock.lock();
    managed_endpoints_cond_var_.timed_wait(lock,
        boost::posix_time::milliseconds(1000));
  }
//  std::cout << "  CheckManagedSockets STOP " << indicator << std::endl;
}

void UdtTransport::HandleManagedSocketRequest(
    const SocketId &udt_socket_id,
    const ManagedEndpointMessage &request) {
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    if (stop_managed_connections_) {
      UDT::close(udt_socket_id);
      return;
    }
  }

  // Check that we're still accepting managed connections and that the request
  // has correct entries
  if (!request.has_message_id() || !request.has_identifier()) {
    DLOG(ERROR) << "HandleManagedSocketRequest request error." << std::endl;
    UDT::close(udt_socket_id);
    return;
  }

  // Get address of peer to reply to and close original socket
  struct sockaddr_in peer_sockaddr;
  int peer_sockaddr_size;
  if (UDT::ERROR == UDT::getpeername(udt_socket_id,
      reinterpret_cast<sockaddr*>(&peer_sockaddr), &peer_sockaddr_size)) {
    DLOG(ERROR) << "HandleManagedSocketRequest getpeername error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(udt_socket_id);
    return;
  }
  std::string remote_ip(inet_ntoa(peer_sockaddr.sin_addr));
  Port remote_port(ntohs(peer_sockaddr.sin_port));
  UDT::close(udt_socket_id);

  // Get new socket bound to managed_endpoint_listening_port_ to send response
  SocketId managed_socket_id =
      GetNewManagedEndpointSocket(remote_ip, remote_port, "", 0);
  if (managed_socket_id < 0) {
    DLOG(ERROR) << "HandleManagedSocketRequest get new socket error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return;
  }

  // Prepare & send transport message to peer.  Keep initial socket alive to
  // allow peer time to call getpeerinfo
  UdtConnection udt_connection(this, managed_socket_id);
  udt_connection.transport_message_.set_type(TransportMessage::kClose);
  ManagedEndpointMessage *managed_endpoint_message = udt_connection.
      transport_message_.mutable_data()->mutable_managed_endpoint_message();
  // TODO(Fraser#5#): 2010-07-31 - Use authentication to set_identifier & result
  managed_endpoint_message->set_result(true);
  managed_endpoint_message->set_message_id(request.message_id());
  // std::cout << "SIZE 1: " << transport_message.ByteSize() << std::endl;
  // managed_endpoint_message->set_identifier(our_identifier);
  udt_connection.SendData(UdtConnection::kKeepAlive, -1);

  // Add newly connected socket to managed endpoints - start checking thread if
  // this is the first
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    if (stop_managed_connections_)
      return;
    if (managed_connections_stopped_) {
      check_connections_.reset(new boost::thread(
                               &UdtTransport::CheckManagedSockets, this));
    }
    managed_endpoint_sockets_.push_back(managed_socket_id);
  }

  // Set to asynchronous
  if (udtutils::SetSyncMode(managed_socket_id, false) != kSuccess) {
    UDT::close(managed_socket_id);
    return;
  }

//  std::cout << "FIRING on_managed_endpoint_received_" << std::endl;
  signals_->on_managed_endpoint_received_(managed_socket_id, request);
}

void UdtTransport::HandleManagedSocketResponse(
    const SocketId &managed_socket_id,
    const ManagedEndpointMessage &response) {
  // Check response has correct entries
  // TODO(Fraser#5#): 2010-07-31 - add !response.has_identifier() below
  if (!response.has_message_id() || !response.has_result()) {
    DLOG(ERROR) << "HandleManagedSocketResponse response error." << std::endl;
    UDT::close(managed_socket_id);
    return;
  }

  // Check response indicates success and set managed socket to asynchronous
  // TODO(Fraser#5#): 2010-07-31 - Use authentication to check identifier()
  SocketId pending_managed_socket_id = response.message_id();
  bool success(response.has_result() && response.result() &&
               (udtutils::SetSyncMode(managed_socket_id, false) == kSuccess));
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    if (stop_managed_connections_)
      return;
    // Adjust pending_managed_endpoint_sockets_ entry
    std::map<SocketId, SocketId>::iterator it =
        pending_managed_endpoint_sockets_.find(pending_managed_socket_id);
    if (it == pending_managed_endpoint_sockets_.end()) {
      DLOG(ERROR) << "In HandleManagedSocketResp, pending_managed_socket_id " <<
          pending_managed_socket_id << " not found." << std::endl;
      UDT::close(managed_socket_id);
      return;
    }
    if (!success) {
      (*it).second = UDT::INVALID_SOCK;
      UDT::close(managed_socket_id);
      managed_endpoints_cond_var_.notify_all();
      return;
    } else {
      (*it).second = managed_socket_id;
    }

    // Add newly accepted socket to managed endpoints - start checking thread if
    // this is the first
    if (managed_connections_stopped_) {
      check_connections_.reset(new boost::thread(
                               &UdtTransport::CheckManagedSockets, this));
    }
    managed_endpoint_sockets_.push_back(managed_socket_id);
    managed_endpoints_cond_var_.notify_all();
  }
}

bool UdtTransport::PendingManagedSocketReplied(
    const SocketId &udt_socket_id) {
  std::map<SocketId, SocketId>::iterator it =
      pending_managed_endpoint_sockets_.find(udt_socket_id);
  if (it == pending_managed_endpoint_sockets_.end())
    return true;
  return (*it).second != 0;
}

}  // namespace transport
