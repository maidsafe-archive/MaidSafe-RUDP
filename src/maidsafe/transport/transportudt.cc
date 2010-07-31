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

boost::shared_ptr<addrinfo const> SocketGetAddrinfo(char const *node,
                                                    char const *service,
                                                    addrinfo const &hints,
                                                    int *result) {
  addrinfo *servinfo;
  *result = getaddrinfo(node, service, &hints, &servinfo);
  return (*result == 0) ? boost::shared_ptr<addrinfo>(servinfo, freeaddrinfo) :
                          boost::shared_ptr<addrinfo>();
}

boost::shared_ptr<addrinfo const> Next(
    boost::shared_ptr<addrinfo const> const &node) {
  return boost::shared_ptr<addrinfo const>(node, node->ai_next);
}

TransportUDT::TransportUDT() : Transport(),
                               listening_map_(),
                               managed_endpoint_sockets_(),
                               pending_managed_endpoint_sockets_(),
                               stop_managed_connections_(false),
                               managed_endpoint_sockets_mutex_(),
                               pending_managed_endpoints_cond_var_(),
                               managed_endpoint_listening_addrinfo_(),
                               managed_endpoint_listening_port_(0),
                               listening_threadpool_(0),
                               general_threadpool_(kDefaultThreadpoolSize),
                               check_connections_() {
  UDT::startup();
}

TransportUDT::~TransportUDT() {
  StopAllListening();
  StopManagedConnections();
  if (check_connections_.get() != NULL)
    check_connections_->join();
}

void TransportUDT::CleanUp() {
  UDT::cleanup();
}

Port TransportUDT::StartListening(const IP &ip,
                                  const Port &try_port,
                                  TransportCondition *transport_condition) {
  return DoStartListening(ip, try_port, false, transport_condition);
}

Port TransportUDT::DoStartListening(const IP &ip,
                                    const Port &try_port,
                                    bool managed_connection_listener,
                                    TransportCondition *transport_condition) {
  // Get a new socket descriptor
  SocketId listening_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> address_info;
  if (GetNewSocket(ip, try_port, &listening_socket_id, &address_info) !=
      kSuccess) {
    if (transport_condition != NULL)
      *transport_condition = kInvalidAddress;
    return 0;
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
  if (UDT::ERROR == UDT::listen(listening_socket_id, 1024)) {
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
  if (!listening_threadpool_.Resize(listening_ports_size + 1)) {
    UDT::close(listening_socket_id);
    if (transport_condition != NULL)
      *transport_condition = kThreadResourceError;
    return 0;
  }
  {
    boost::mutex::scoped_lock lock(listening_ports_mutex_);
    listening_ports_.push_back(listening_port);
    listening_map_.insert(
        std::pair<Port, UdtSocketId>(listening_port, listening_socket_id));
  }

  listening_threadpool_.EnqueueTask(
      boost::bind(&TransportUDT::AcceptConnection, this, listening_port,
                  listening_socket_id));
  if (managed_connection_listener) {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    managed_endpoint_listening_addrinfo_ = address_info;
    managed_endpoint_listening_port_ = listening_port;
  }

  if (transport_condition != NULL)
    *transport_condition = kSuccess;
  return listening_port;
}

bool TransportUDT::StopListening(const Port &port) {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  listening_ports_.erase(
      std::remove(listening_ports_.begin(), listening_ports_.end(), port),
      listening_ports_.end());
  std::map<Port, UdtSocketId>::iterator it = listening_map_.find(port);
  if (it != listening_map_.end()) {
    UDT::close((*it).second);
    listening_map_.erase(it);
  }
  listening_threadpool_.Resize(listening_ports_.size());
  return true;
}

bool TransportUDT::StopAllListening() {
  boost::mutex::scoped_lock lock(listening_ports_mutex_);
  listening_ports_.clear();
  std::map<Port, UdtSocketId>::iterator it = listening_map_.begin();
  for (; it != listening_map_.end(); ++it)
    UDT::close((*it).second);
  return true;
}

void TransportUDT::StopManagedConnections() {
  boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
  stop_managed_connections_ = true;
}

TransportCondition TransportUDT::PunchHole(const IP &remote_ip,
                                           const Port &remote_port,
                                           const IP &rendezvous_ip,
                                           const Port &rendezvous_port) {
  return kSuccess;
}

SocketId TransportUDT::Send(const TransportMessage &transport_message,
                            const IP &remote_ip,
                            const Port &remote_port,
                            const int &response_timeout) {
  SocketId udt_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> peer;
  if (GetNewSocket(remote_ip, remote_port, &udt_socket_id, &peer) != kSuccess) {
    return UDT::INVALID_SOCK;
  } else {
    bool reuse = false;
    UDT::setsockopt(udt_socket_id, 0, UDT_REUSEADDR, &reuse, sizeof(reuse));
    int timeout(response_timeout < 0 ? 0 : response_timeout);
    general_threadpool_.EnqueueTask(
        boost::bind(&TransportUDT::ConnectThenSend, this, transport_message,
                    udt_socket_id, timeout, timeout, peer));
    return udt_socket_id;
  }
}

void TransportUDT::SendWithRendezvous(const TransportMessage &transport_message,
                                      const IP &remote_ip,
                                      const Port &remote_port,
                                      const IP &rendezvous_ip,
                                      const Port &rendezvous_port,
                                      int &response_timeout,
                                      SocketId *socket_id) {
}

void TransportUDT::SendResponse(const TransportMessage &transport_message,
                                const SocketId &socket_id) {
  general_threadpool_.EnqueueTask(
      boost::bind(&TransportUDT::SendData, this, transport_message, socket_id,
                  kDefaultSendTimeout, 0));
}

void TransportUDT::SendFile(fs::path &path, const SocketId &socket_id) {
}

ManagedEndpointId TransportUDT::AddManagedEndpoint(
    const IP &remote_ip,
    const Port &remote_port,
    const IP &rendezvous_ip,
    const Port &rendezvous_port,
    const std::string &our_identifier,
    const boost::uint16_t &frequency,
    const boost::uint16_t &retry_count,
    const boost::uint16_t &retry_frequency) {
  // Get temp socket bound to managed_endpoint_listening_port_ to send request
  UdtSocketId initial_peer_socket_id =
      GetNewManagedEndpointSocket(remote_ip, remote_port, rendezvous_ip,
                                  rendezvous_port);
  if (initial_peer_socket_id < 0)
    return kNoSocket;

  // Prepare & send transport message to peer.  Keep initial socket alive to
  // allow peer time to call getpeerinfo
  TransportMessage transport_message;
  transport_message.set_type(TransportMessage::kRequest);
  ManagedEndpointMessage *managed_endpoint_message =
      transport_message.mutable_data()->mutable_managed_endpoint_message();
  managed_endpoint_message->set_message_id(initial_peer_socket_id);
  managed_endpoint_message->set_identifier(our_identifier);
  SendData(transport_message, initial_peer_socket_id,
           kAddManagedConnectionTimeout, -1);

  // Wait for peer to send response to managed_endpoint_listening_port_
  try {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    pending_managed_endpoint_sockets_.insert(
        std::pair<UdtSocketId, UdtSocketId>(initial_peer_socket_id, 0));
    bool success = pending_managed_endpoints_cond_var_.timed_wait(lock,
        boost::posix_time::milliseconds(kAddManagedConnectionTimeout),
        boost::bind(&TransportUDT::PendingManagedSocketReplied, this,
                    initial_peer_socket_id));
    UDT::close(initial_peer_socket_id);
    if (success) {
      std::map<UdtSocketId, UdtSocketId>::iterator it =
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

TransportCondition TransportUDT::StartManagedEndpointListener(
    const UdtSocketId &initial_peer_socket_id,
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
  TransportCondition transport_condition(Connect(initial_peer_socket_id, peer));
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

UdtSocketId TransportUDT::GetNewManagedEndpointSocket(
    const IP &remote_ip,
    const Port &remote_port,
    const IP &rendezvous_ip,
    const Port &rendezvous_port) {
  // Get a new socket descriptor to send on managed_endpoint_listening_port_
  UdtSocketId initial_peer_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> peer;
  if (GetNewSocket(remote_ip, remote_port, &initial_peer_socket_id, &peer) !=
      kSuccess) {
    DLOG(ERROR) << "GetNewManagedEndpointInitialSocket error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
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
        bool receive_synchronously = false;
        if (UDT::ERROR == UDT::setsockopt(initial_peer_socket_id, 0, UDT_RCVSYN,
            &receive_synchronously, sizeof(receive_synchronously))) {
          DLOG(ERROR) << "GetNewManagedEndpointSocket setsockopt error: " <<
              UDT::getlasterror().getErrorMessage() << std::endl;
          UDT::close(initial_peer_socket_id);
          return kNoSocket;
        }
        boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
        listening_port = managed_endpoint_listening_port_;
        return initial_peer_socket_id;
      } else {
        if (attempts == kMaxAttempts)
          return kListenError;
      }
    } else if (listening_port == -1) {  // Startup is already in progress
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
  bool receive_synchronously = false;
  if (UDT::ERROR == UDT::setsockopt(initial_peer_socket_id, 0, UDT_RCVSYN,
      &receive_synchronously, sizeof(receive_synchronously))) {
    DLOG(ERROR) << "GetNewManagedEndpointInitialSocket setsockopt error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(initial_peer_socket_id);
    return kNoSocket;
  }

  // Connect to peer
  if (Connect(initial_peer_socket_id, peer) != kSuccess) {
    DLOG(ERROR) << "GetNewManagedEndpointInitialSocket connect error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    UDT::close(initial_peer_socket_id);
    return kConnectError;
  }

  return initial_peer_socket_id;
}

bool TransportUDT::RemoveManagedEndpoint(
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

void TransportUDT::AcceptConnection(const Port &port,
                                    const UdtSocketId &udt_socket_id) {
  sockaddr_storage clientaddr;
  int addrlen = sizeof(clientaddr);
  UdtSocketId receiver_socket_id;
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
        LOG(ERROR) << "UDT::accept error: " <<
            UDT::getlasterror().getErrorMessage() << std::endl;
        listening_ports_.erase(port_iterator);
        std::map<Port, UdtSocketId>::iterator it = listening_map_.find(port);
        if (it != listening_map_.end())
          listening_map_.erase(it);
        listening_threadpool_.Resize(listening_ports_.size());
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
      return;
    } else {
      general_threadpool_.EnqueueTask(boost::bind(
          &TransportUDT::ReceiveData, this, receiver_socket_id, -1));
    }
  }
}

void TransportUDT::ConnectThenSend(
    const TransportMessage &transport_message,
    const UdtSocketId &udt_socket_id,
    const int &send_timeout,
    const int &receive_timeout,
    boost::shared_ptr<addrinfo const> peer) {
  TransportCondition transport_condition = Connect(udt_socket_id, peer);
  if (transport_condition != kSuccess) {
    signals_.on_send_(udt_socket_id, kSendUdtFailure);
    return;
  }
  SendData(transport_message, udt_socket_id, send_timeout, receive_timeout);
}

void TransportUDT::SendData(const TransportMessage &transport_message,
                            const UdtSocketId &udt_socket_id,
                            const int &send_timeout,
                            const int &receive_timeout) {
  // Set timeout
  if (send_timeout > 0) {
    UDT::setsockopt(udt_socket_id, 0, UDT_SNDTIMEO, &send_timeout,
                    sizeof(send_timeout));
  }

  // Send the message size
  TransportCondition result = SendDataSize(transport_message, udt_socket_id);
  if (result != kSuccess) {
    signals_.on_send_(udt_socket_id, result);
    UDT::close(udt_socket_id);
    return;
  }

  // Send the message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(udt_socket_id,
                                                     UdtStats::kSend));
  result = SendDataContent(transport_message, udt_socket_id);
  signals_.on_send_(udt_socket_id, result);
  if (result != kSuccess) {
    UDT::close(udt_socket_id);
    return;
  }

  // Get stats
  if (UDT::ERROR == UDT::perfmon(udt_socket_id,
                                 &udt_stats->performance_monitor_)) {
#ifdef DEBUG
    if (UDT::getlasterror().getErrorCode() != 2001)
      DLOG(ERROR) << "UDT perfmon error: " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
#endif
  } else {
    signals_.on_stats_(udt_stats);
  }
  if (receive_timeout > 0) {
    general_threadpool_.EnqueueTask(
        boost::bind(&TransportUDT::ReceiveData, this, udt_socket_id,
                    receive_timeout));
  } else if (receive_timeout == 0) {
    UDT::close(udt_socket_id);
  }
}

TransportCondition TransportUDT::SendDataSize(
    const TransportMessage &transport_message,
    const UdtSocketId &udt_socket_id) {
  DataSize data_size = static_cast<DataSize>(transport_message.ByteSize());
  if (data_size != transport_message.ByteSize()) {
    LOG(INFO) << "TransportUDT::SendDataSize: data > max buffer size." <<
        std::endl;
    return kSendUdtFailure;
  }
  DataSize data_buffer_size = sizeof(DataSize);

  int sent_count;
  if (UDT::ERROR == (sent_count = UDT::send(udt_socket_id,
      reinterpret_cast<char*>(&data_size), data_buffer_size, 0))) {
    DLOG(ERROR) << "Cannot send data size to " << udt_socket_id << ": " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSendUdtFailure;
  } else if (sent_count != data_buffer_size) {
    LOG(INFO) << "Sending socket " << udt_socket_id << " timed out" <<
        std::endl;
    return kSendTimeout;
  }
  return kSuccess;
}

TransportCondition TransportUDT::SendDataContent(
    const TransportMessage &transport_message,
    const UdtSocketId &udt_socket_id) {
  DataSize data_size = static_cast<DataSize>(transport_message.ByteSize());
  boost::scoped_array<char> serialised_message(new char[data_size]);
  // Check for valid message
  if (!transport_message.SerializeToArray(serialised_message.get(),
                                          data_size)) {
    DLOG(ERROR) << "TransportUDT::SendDataContent: failed to serialise." <<
        std::endl;
    return kInvalidData;
  }
  DataSize sent_total = 0;
  int sent_size = 0;
  while (sent_total < data_size) {
    if (UDT::ERROR == (sent_size = UDT::send(udt_socket_id,
        serialised_message.get() + sent_total, data_size - sent_total, 0))) {
      LOG(ERROR) << "Send: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      return kSendUdtFailure;
    } else if (sent_size == 0) {
      LOG(INFO) << "Sending socket " << udt_socket_id << " timed out" <<
          std::endl;
      return kSendTimeout;
    }
    sent_total += sent_size;
  }
  return kSuccess;
}

void TransportUDT::ReceiveData(const UdtSocketId &udt_socket_id,
                               const int &receive_timeout) {

  // Set timeout
  if (receive_timeout > 0) {
    UDT::setsockopt(udt_socket_id, 0, UDT_RCVTIMEO, &receive_timeout,
                    sizeof(receive_timeout));
  }

  // Get the incoming message size
  DataSize data_size = ReceiveDataSize(udt_socket_id);
  if (data_size == 0)
    return;

  // Get message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(udt_socket_id,
                                                     UdtStats::kReceive));
  TransportMessage transport_message;
  if (!ReceiveDataContent(udt_socket_id, data_size, &transport_message))
    return;

  // Get stats
  float rtt;
  if (UDT::ERROR == UDT::perfmon(udt_socket_id,
                                 &udt_stats->performance_monitor_)) {
#ifdef DEBUG
    if (UDT::getlasterror().getErrorCode() != 2001)
      DLOG(ERROR) << "UDT perfmon error: " <<
          UDT::getlasterror().getErrorCode() << std::endl;
#endif
  } else {
    signals_.on_stats_(udt_stats);
    rtt = udt_stats->performance_monitor_.msRTT;
  }

  // Handle message
  HandleTransportMessage(transport_message, udt_socket_id, rtt);
}

DataSize TransportUDT::ReceiveDataSize(const UdtSocketId &udt_socket_id) {
  DataSize data_buffer_size = sizeof(DataSize);
  DataSize data_size;
  int received_count;
  UDT::getlasterror().clear();
  if (UDT::ERROR == (received_count = UDT::recv(udt_socket_id,
      reinterpret_cast<char*>(&data_size), data_buffer_size, 0))) {
    LOG(ERROR) << "Cannot get data size: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    signals_.on_receive_(udt_socket_id, kReceiveUdtFailure);
    UDT::close(udt_socket_id);
    return 0;
  } else if (received_count == 0) {
    LOG(INFO) << "Receiving socket " << udt_socket_id << " timed out" <<
        std::endl;
    signals_.on_receive_(udt_socket_id, kReceiveTimeout);
    UDT::close(udt_socket_id);
    return 0;
  }
  if (data_size < 1) {
    LOG(ERROR) << "Data size is " << data_size << std::endl;
    signals_.on_receive_(udt_socket_id, kReceiveSizeFailure);
    UDT::close(udt_socket_id);
    return 0;
  }
  return data_size;
}

bool TransportUDT::ReceiveDataContent(
    const UdtSocketId &udt_socket_id,
    const DataSize &data_size,
    TransportMessage *transport_message) {
  boost::scoped_array<char> serialised_message(new char[data_size]);
  DataSize received_total = 0;
  int received_size = 0;
  while (received_total < data_size) {
    if (UDT::ERROR == (received_size = UDT::recv(udt_socket_id,
        serialised_message.get() + received_total, data_size - received_total,
        0))) {
      LOG(ERROR) << "Recv: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      signals_.on_receive_(udt_socket_id, kReceiveUdtFailure);
      UDT::close(udt_socket_id);
      return false;
    } else if (received_size == 0) {
      LOG(INFO) << "Receiving socket " << udt_socket_id << " timed out" <<
          std::endl;
      signals_.on_receive_(udt_socket_id, kReceiveTimeout);
      UDT::close(udt_socket_id);
      return false;
    }
    received_total += received_size;
  }
  return transport_message->ParseFromArray(serialised_message.get(), data_size);
}

bool TransportUDT::HandleTransportMessage(
    const TransportMessage &transport_message,
    const UdtSocketId &udt_socket_id,
    const float &rtt) {
  bool is_request(transport_message.type() == TransportMessage::kRequest);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      transport_message.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(transport_message.data(), &field_descriptors);
  if (field_descriptors.size() != 1U) {
    LOG(INFO) << "Bad data - doesn't contain exactly one field." << std::endl;
    if (!is_request)
      signals_.on_receive_(udt_socket_id, kReceiveParseFailure);
    UDT::close(udt_socket_id);
    return false;
  }
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      signals_.on_message_received_(transport_message.data().raw_message(),
                               udt_socket_id, rtt);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        signals_.on_rpc_request_received_(
            transport_message.data().rpc_message(), udt_socket_id, rtt);
        // Leave socket open to send response on.
      } else {
        signals_.on_rpc_response_received_(
            transport_message.data().rpc_message(), udt_socket_id, rtt);
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
    case TransportMessage::Data::kManagedEndpointMessageFieldNumber:
      if (is_request) {
        HandleManagedSocketRequest(udt_socket_id,
            transport_message.data().managed_endpoint_message());
        // Leave socket open.
      } else {
        HandleManagedSocketResponse(udt_socket_id,
            transport_message.data().managed_endpoint_message());
        // Leave socket open.
      }
      break;
    default:
      LOG(INFO) << "Unrecognised data type in TransportMessage." << std::endl;
      UDT::close(udt_socket_id);
      return false;
  }
  return true;
}

TransportCondition TransportUDT::GetNewSocket(
    const IP &ip,
    const Port &port,
    UdtSocketId *udt_socket_id,
    boost::shared_ptr<addrinfo const> *address_info) {
  if (udt_socket_id == NULL)
    return kConnectError;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = (ip.empty() ? AI_PASSIVE : 0);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  const char *address(ip.empty() ? NULL : ip.c_str());
  std::string port_str = boost::lexical_cast<std::string>(port);
  int result(0);
  *address_info = SocketGetAddrinfo(address, port_str.c_str(), hints, &result);
  if (result != 0) {
    DLOG(ERROR) << "Incorrect endpoint. " << ip << ":" << port << std::endl;
    *udt_socket_id = UDT::INVALID_SOCK;
    return kInvalidAddress;
  }
  return GetNewSocket(udt_socket_id, *address_info);
}

TransportCondition TransportUDT::GetNewSocket(
    UdtSocketId *udt_socket_id,
    boost::shared_ptr<addrinfo const> address_info) {
  if (udt_socket_id == NULL)
    return kConnectError;

  *udt_socket_id = UDT::socket(address_info->ai_family,
                               address_info->ai_socktype,
                               address_info->ai_protocol);

  if (UDT::INVALID_SOCK == *udt_socket_id) {
    DLOG(ERROR) << "GetNewSocket error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kNoSocket;
  }

  // Windows UDP problems fix
#ifdef WIN32
  int mtu(1052);
  UDT::setsockopt(*udt_socket_id, 0, UDT_MSS, &mtu, sizeof(mtu));
#endif
  return kSuccess;
}

TransportCondition TransportUDT::Connect(
    const UdtSocketId &udt_socket_id,
    boost::shared_ptr<addrinfo const> peer) {
  if (UDT::ERROR == UDT::connect(udt_socket_id, peer->ai_addr,
                                 peer->ai_addrlen)) {
    DLOG(ERROR) << "Connect: " << UDT::getlasterror().getErrorMessage() <<
        std::endl;
    UDT::close(udt_socket_id);
    return kConnectError;
  }
  return kSuccess;
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
    DLOG(INFO) << "UDT perfmon error: " <<
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

void TransportUDT::CheckManagedSockets() {
  int result;
  std::vector<UdtSocketId>::iterator socket_iterator;
  boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
  boost::scoped_array<char> holder(new char[10]);
  int received_count;
  while (true) {
    if (stop_managed_connections_) {
      // Send '-' to peer to indicate socket closure.
      char close_indicator('-');
      for (socket_iterator = managed_endpoint_sockets_.begin();
           socket_iterator != managed_endpoint_sockets_.end();
           ++socket_iterator) {
        UDT::send(*socket_iterator, &close_indicator, 1, 0);
        UDT::close(*socket_iterator);
// std::cout << "FIRING on_managed_endpoint_lost_ 1" << std::endl;
        signals_.on_managed_endpoint_lost_(*socket_iterator);
      }
      managed_endpoint_sockets_.clear();
      break;
    }
    std::vector<UdtSocketId> copy_of_managed_ids(managed_endpoint_sockets_);
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
        RemoveManagedEndpoint(*socket_iterator);
        signals_.on_managed_endpoint_lost_(*socket_iterator);
        holder[0] = '\0';
// std::cout << "FIRING on_managed_endpoint_lost_ 2" << std::endl;
      }
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
    lock.lock();
  }
}

void TransportUDT::HandleManagedSocketRequest(
    const UdtSocketId &udt_socket_id,
    const ManagedEndpointMessage &request) {
  // Check request has correct entries
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
  UdtSocketId managed_socket_id =
      GetNewManagedEndpointSocket(remote_ip, remote_port, "", 0);
  if (managed_socket_id < 0) {
    DLOG(ERROR) << "HandleManagedSocketRequest get new socket error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return;
  }

  // Prepare & send transport message to peer.  Keep initial socket alive to
  // allow peer time to call getpeerinfo
  TransportMessage transport_message;
  transport_message.set_type(TransportMessage::kResponse);
  ManagedEndpointMessage *managed_endpoint_message =
      transport_message.mutable_data()->mutable_managed_endpoint_message();
  // TODO(Fraser#5#): 2010-07-31 - Use authentication to set_identifier & result
  managed_endpoint_message->set_result(true);
  managed_endpoint_message->set_message_id(request.message_id());
  // managed_endpoint_message->set_identifier(our_identifier);
  SendData(transport_message, managed_socket_id, kAddManagedConnectionTimeout,
           -1);

  // Add newly connected socket to managed endpoints - start checking thread if
  // this is the first
  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    if (managed_endpoint_sockets_.empty()) {
      check_connections_.reset(new boost::thread(
                               &TransportUDT::CheckManagedSockets, this));
    }
    managed_endpoint_sockets_.push_back(managed_socket_id);
  }

  // Send single char to allow for fast closing on peer side if socket dropped
  char open_indicator('+');
  UDT::send(managed_socket_id, &open_indicator, 1, 0);

// std::cout << "FIRING on_managed_endpoint_received_" << std::endl;
  signals_.on_managed_endpoint_received_(managed_socket_id, request);
}

void TransportUDT::HandleManagedSocketResponse(
    const UdtSocketId &managed_socket_id,
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
  UdtSocketId pending_managed_socket_id = response.message_id();
  bool success(response.has_result() && response.result());
  bool receive_synchronously = false;
  if (UDT::ERROR == UDT::setsockopt(managed_socket_id, 0, UDT_RCVSYN,
      &receive_synchronously, sizeof(receive_synchronously))) {
    DLOG(ERROR) << "HandleManagedSocketResponse setsockopt error: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    success = false;
  }

  {
    boost::mutex::scoped_lock lock(managed_endpoint_sockets_mutex_);
    // Adjust pending_managed_endpoint_sockets_ entry
    std::map<UdtSocketId, UdtSocketId>::iterator it =
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
      pending_managed_endpoints_cond_var_.notify_all();
      return;
    } else {
      (*it).second = managed_socket_id;
    }

    // Add newly accepted socket to managed endpoints - start checking thread if
    // this is the first
    if (managed_endpoint_sockets_.empty()) {
      check_connections_.reset(new boost::thread(
                               &TransportUDT::CheckManagedSockets, this));
    }
    managed_endpoint_sockets_.push_back(managed_socket_id);
    pending_managed_endpoints_cond_var_.notify_all();
  }

  // Send single char to allow for fast closing on peer side if socket dropped
  char open_indicator('+');
  UDT::send(managed_socket_id, &open_indicator, 1, 0);
}

bool TransportUDT::PendingManagedSocketReplied(
    const UdtSocketId &udt_socket_id) {
  std::map<UdtSocketId, UdtSocketId>::iterator it =
      pending_managed_endpoint_sockets_.find(udt_socket_id);
  if (it == pending_managed_endpoint_sockets_.end())
    return true;
  return (*it).second != 0;
}

}  // namespace transport
