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

#include "maidsafe/transport/udtconnection.h"
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/scoped_array.hpp>
#include <google/protobuf/descriptor.h>
#include "maidsafe/base/log.h"
#include "maidsafe/base/threadpool.h"
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/transport/transportudt.h"

namespace transport {

UdtConnection::UdtConnection() : transport_udt_(NULL),
                                 signals_(new Signals),
                                 send_worker_(),
                                 receive_worker_() {}

UdtConnection::UdtConnection(TransportUDT *transport_udt)
    : transport_udt_(transport_udt),
      signals_(transport_udt->signals()),
      send_worker_(),
      receive_worker_() {}

UdtConnection::~UdtConnection() {
  if (send_worker_.get() != NULL)
    send_worker_->join();
  if (receive_worker_.get() != NULL)
    receive_worker_->join();
}

SocketId UdtConnection::Send(const TransportMessage &transport_message,
                             const IP &remote_ip,
                             const Port &remote_port,
                             const int &response_timeout) {
  UdtSocketId udt_socket_id(UDT::INVALID_SOCK);
  boost::shared_ptr<addrinfo const> peer;
  if (udtutils::GetNewSocket(remote_ip, remote_port, false, &udt_socket_id,
                             &peer) != kSuccess)
    return UDT::INVALID_SOCK;
  int timeout(response_timeout < 0 ? 0 : response_timeout);
  send_worker_.reset(new boost::thread(&UdtConnection::ConnectThenSend, this,
      transport_message, udt_socket_id, timeout, timeout, peer));
  return udt_socket_id;
}

void UdtConnection::SendResponse(const TransportMessage &transport_message,
                                 const SocketId &socket_id) {
  if (transport_udt_) {
    SendData(transport_message, socket_id, kDefaultSendTimeout, 0);
  } else {
    send_worker_.reset(new boost::thread(&UdtConnection::SendData, this,
        transport_message, socket_id, kDefaultSendTimeout, 0));
  }
}

void UdtConnection::ConnectThenSend(
    const TransportMessage &transport_message,
    const UdtSocketId &udt_socket_id,
    const int &send_timeout,
    const int &receive_timeout,
    boost::shared_ptr<addrinfo const> peer) {
  TransportCondition transport_condition =
      udtutils::Connect(udt_socket_id, peer);
  if (transport_condition != kSuccess) {
    signals_->on_send_(udt_socket_id, kSendUdtFailure);
    return;
  }
  SendData(transport_message, udt_socket_id, send_timeout, receive_timeout);
}

void UdtConnection::SendData(const TransportMessage &transport_message,
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
    signals_->on_send_(udt_socket_id, result);
    UDT::close(udt_socket_id);
    return;
  }

  // Send the message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(udt_socket_id,
                                                     UdtStats::kSend));
  result = SendDataContent(transport_message, udt_socket_id);
  signals_->on_send_(udt_socket_id, result);
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
    signals_->on_stats_(udt_stats);
  }
  if (receive_timeout > 0) {
    receive_worker_.reset(new boost::thread(&UdtConnection::ReceiveData, this,
                                            udt_socket_id, receive_timeout));
  } else if (receive_timeout == 0) {
    UDT::close(udt_socket_id);
  }
}

TransportCondition UdtConnection::SendDataSize(
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

TransportCondition UdtConnection::SendDataContent(
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

void UdtConnection::ReceiveData(const UdtSocketId &udt_socket_id,
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
    signals_->on_stats_(udt_stats);
    rtt = udt_stats->performance_monitor_.msRTT;
  }

  // Handle message
  HandleTransportMessage(transport_message, udt_socket_id, rtt);
}

DataSize UdtConnection::ReceiveDataSize(const UdtSocketId &udt_socket_id) {
  DataSize data_buffer_size = sizeof(DataSize);
  DataSize data_size;
  int received_count;
  UDT::getlasterror().clear();
  if (UDT::ERROR == (received_count = UDT::recv(udt_socket_id,
      reinterpret_cast<char*>(&data_size), data_buffer_size, 0))) {
    LOG(ERROR) << "Cannot get data size: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    signals_->on_receive_(udt_socket_id, kReceiveUdtFailure);
    UDT::close(udt_socket_id);
    return 0;
  } else if (received_count == 0) {
    LOG(INFO) << "Receiving socket " << udt_socket_id << " timed out" <<
        std::endl;
    signals_->on_receive_(udt_socket_id, kReceiveTimeout);
    UDT::close(udt_socket_id);
    return 0;
  }
  if (data_size < 1) {
    LOG(ERROR) << "Data size is " << data_size << std::endl;
    signals_->on_receive_(udt_socket_id, kReceiveSizeFailure);
    UDT::close(udt_socket_id);
    return 0;
  }
  return data_size;
}

bool UdtConnection::ReceiveDataContent(
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
      signals_->on_receive_(udt_socket_id, kReceiveUdtFailure);
      UDT::close(udt_socket_id);
      return false;
    } else if (received_size == 0) {
      LOG(INFO) << "Receiving socket " << udt_socket_id << " timed out" <<
          std::endl;
      signals_->on_receive_(udt_socket_id, kReceiveTimeout);
      UDT::close(udt_socket_id);
      return false;
    }
    received_total += received_size;
  }
  return transport_message->ParseFromArray(serialised_message.get(), data_size);
}

bool UdtConnection::HandleTransportMessage(
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
      signals_->on_receive_(udt_socket_id, kReceiveParseFailure);
    UDT::close(udt_socket_id);
    return false;
  }
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      signals_->on_message_received_(transport_message.data().raw_message(),
                                    udt_socket_id, rtt);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        signals_->on_rpc_request_received_(
            transport_message.data().rpc_message(), udt_socket_id, rtt);
        // Leave socket open to send response on.
      } else {
        signals_->on_rpc_response_received_(
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
      if (transport_udt_) {
        if (is_request) {
          transport_udt_->HandleManagedSocketRequest(udt_socket_id,
              transport_message.data().managed_endpoint_message());
          // Leave socket open.
        } else {
          transport_udt_->HandleManagedSocketResponse(udt_socket_id,
              transport_message.data().managed_endpoint_message());
          // Leave socket open.
        }
      } else {
        UDT::close(udt_socket_id);
      }
      break;
    default:
      LOG(INFO) << "Unrecognised data type in TransportMessage." << std::endl;
      UDT::close(udt_socket_id);
      return false;
  }
  return true;
}

}  // namespace transport
