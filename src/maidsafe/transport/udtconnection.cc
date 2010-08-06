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
#include "maidsafe/transport/transportudt.h"

namespace transport {

UdtConnection::UdtConnection(const IP &remote_ip,
                             const Port &remote_port,
                             const IP &rendezvous_ip,
                             const Port &rendezvous_port)
    : transport_udt_(NULL),
      signals_(new Signals),
      threadpool_(),
      worker_(),
      udt_connection_id_(UDT::INVALID_SOCK),
      remote_ip_(remote_ip),
      remote_port_(remote_port),
      rendezvous_ip_(rendezvous_ip),
      rendezvous_port_(rendezvous_port),
      peer_(),
      transport_message_() {
  Init();
}

UdtConnection::UdtConnection(TransportUDT *transport_udt,
                             const IP &remote_ip,
                             const Port &remote_port,
                             const IP &rendezvous_ip,
                             const Port &rendezvous_port)
    : transport_udt_(transport_udt),
      signals_(transport_udt->signals()),
      threadpool_(transport_udt->general_threadpool_),
      worker_(),
      udt_connection_id_(UDT::INVALID_SOCK),
      remote_ip_(remote_ip),
      remote_port_(remote_port),
      rendezvous_ip_(rendezvous_ip),
      rendezvous_port_(rendezvous_port),
      peer_(),
      transport_message_() {
  Init();
}

UdtConnection::UdtConnection(TransportUDT *transport_udt,
                             const UdtConnectionId &udt_connection_id)
    : transport_udt_(transport_udt),
      signals_(transport_udt->signals()),
      threadpool_(transport_udt->general_threadpool_),
      worker_(),
      udt_connection_id_(udt_connection_id),
      remote_ip_(""),
      remote_port_(0),
      rendezvous_ip_(""),
      rendezvous_port_(0),
      peer_(),
      transport_message_() {}

UdtConnection::UdtConnection(const UdtConnection &other)
    : transport_udt_(other.transport_udt_),
      signals_(other.signals_),
      threadpool_(other.threadpool_),
      worker_(other.worker_),
      udt_connection_id_(other.udt_connection_id_),
      remote_ip_(other.remote_ip_),
      remote_port_(other.remote_port_),
      rendezvous_ip_(other.rendezvous_ip_),
      rendezvous_port_(other.rendezvous_port_),
      peer_(other.peer_),
      transport_message_(other.transport_message_) {}

UdtConnection& UdtConnection::operator=(const UdtConnection &other) {
  transport_udt_ = other.transport_udt_;
  signals_ = other.signals_;
  threadpool_ = other.threadpool_;
  worker_ = other.worker_;
  udt_connection_id_ = other.udt_connection_id_;
  remote_ip_ = other.remote_ip_;
  remote_port_ = other.remote_port_;
  rendezvous_ip_ = other.rendezvous_ip_;
  rendezvous_port_ = other.rendezvous_port_;
  peer_ = other.peer_;
  transport_message_ = other.transport_message_;
  return *this;
}

UdtConnection::~UdtConnection() {
  if (worker_.get() != NULL)
    worker_->join();
}

void UdtConnection::Init() {
  if (udtutils::GetNewSocket(remote_ip_, remote_port_, false,
                             &udt_connection_id_, &peer_) != kSuccess)
    udt_connection_id_ = UDT::INVALID_SOCK;
}

void UdtConnection::Send(const TransportMessage &transport_message,
                         const int &response_timeout) {
  transport_message_ = transport_message;
  int timeout(response_timeout < 0 ? 0 : response_timeout);
  boost::function<void()> functor =
      boost::bind(&UdtConnection::ConnectThenSend, this, timeout, timeout);
  if (threadpool_.get()) {
//    threadpool_->EnqueueTask(functor);
    worker_.reset(new boost::thread(functor));
  } else {
    worker_.reset(new boost::thread(functor));
  }
}

void UdtConnection::SendResponse(const TransportMessage &transport_message) {
  transport_message_ = transport_message;
  boost::function<void()> functor =
      boost::bind(&UdtConnection::SendData, this, kDefaultSendTimeout, 0);
  if (threadpool_.get()) {
//    threadpool_->EnqueueTask(functor);
    worker_.reset(new boost::thread(functor));
  } else {
    worker_.reset(new boost::thread(functor));
  }
}

void UdtConnection::ConnectThenSend(const int &send_timeout,
                                    const int &receive_timeout) {
  TransportCondition transport_condition =
      udtutils::Connect(udt_connection_id_, peer_);
  if (transport_condition != kSuccess) {
    signals_->on_send_(udt_connection_id_, kSendUdtFailure);
    return;
  }
  SendData(send_timeout, receive_timeout);
}

void UdtConnection::SendData(const int &send_timeout,
                             const int &receive_timeout) {
  // Set timeout
  if (send_timeout > 0) {
    UDT::setsockopt(udt_connection_id_, 0, UDT_SNDTIMEO, &send_timeout,
                    sizeof(send_timeout));
  }

  // Send the message size
  TransportCondition result = SendDataSize();
  if (result != kSuccess) {
    signals_->on_send_(udt_connection_id_, result);
    UDT::close(udt_connection_id_);
    return;
  }

  // Send the message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(udt_connection_id_,
                                                     UdtStats::kSend));
  result = SendDataContent();
  signals_->on_send_(udt_connection_id_, result);
  if (result != kSuccess) {
    UDT::close(udt_connection_id_);
    return;
  }

  // Get stats
  if (UDT::ERROR == UDT::perfmon(udt_connection_id_,
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
    ReceiveData(receive_timeout);
  } else if (receive_timeout == 0) {
    UDT::close(udt_connection_id_);
  }
}

TransportCondition UdtConnection::SendDataSize() {
  DataSize data_size = static_cast<DataSize>(transport_message_.ByteSize());
  if (data_size != transport_message_.ByteSize()) {
    LOG(INFO) << "TransportUDT::SendDataSize: data > max buffer size." <<
        std::endl;
    return kSendUdtFailure;
  }
  DataSize data_buffer_size = sizeof(DataSize);

  int sent_count;
  if (UDT::ERROR == (sent_count = UDT::send(udt_connection_id_,
      reinterpret_cast<char*>(&data_size), data_buffer_size, 0))) {
    DLOG(ERROR) << "Cannot send data size to " << udt_connection_id_ << ": " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    return kSendUdtFailure;
  } else if (sent_count != data_buffer_size) {
    LOG(INFO) << "Sending socket " << udt_connection_id_ << " timed out" <<
        std::endl;
    return kSendTimeout;
  }
  return kSuccess;
}

TransportCondition UdtConnection::SendDataContent() {
  DataSize data_size = static_cast<DataSize>(transport_message_.ByteSize());
  boost::scoped_array<char> serialised_message(new char[data_size]);
  // Check for valid message
  if (!transport_message_.SerializeToArray(serialised_message.get(),
                                           data_size)) {
    DLOG(ERROR) << "TransportUDT::SendDataContent: failed to serialise." <<
        std::endl;
    return kInvalidData;
  }
  DataSize sent_total = 0;
  int sent_size = 0;
  while (sent_total < data_size) {
    if (UDT::ERROR == (sent_size = UDT::send(udt_connection_id_,
        serialised_message.get() + sent_total, data_size - sent_total, 0))) {
      LOG(ERROR) << "Send: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      return kSendUdtFailure;
    } else if (sent_size == 0) {
      LOG(INFO) << "Sending socket " << udt_connection_id_ << " timed out" <<
          std::endl;
      return kSendTimeout;
    }
    sent_total += sent_size;
  }
  return kSuccess;
}

void UdtConnection::ReceiveData(const int &receive_timeout) {
  // Set timeout
  if (receive_timeout > 0) {
    UDT::setsockopt(udt_connection_id_, 0, UDT_RCVTIMEO, &receive_timeout,
                    sizeof(receive_timeout));
  }

  // Get the incoming message size
  DataSize data_size = ReceiveDataSize();
  if (data_size == 0)
    return;

  // Get message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(udt_connection_id_,
                                                     UdtStats::kReceive));
  transport_message_.Clear();
  if (!ReceiveDataContent(data_size))
    return;

  // Get stats
  float rtt;
  if (UDT::ERROR == UDT::perfmon(udt_connection_id_,
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
  HandleTransportMessage(rtt);
}

DataSize UdtConnection::ReceiveDataSize() {
  DataSize data_buffer_size = sizeof(DataSize);
  DataSize data_size;
  int received_count;
  UDT::getlasterror().clear();
  if (UDT::ERROR == (received_count = UDT::recv(udt_connection_id_,
      reinterpret_cast<char*>(&data_size), data_buffer_size, 0))) {
    LOG(ERROR) << "Cannot get data size: " <<
        UDT::getlasterror().getErrorMessage() << std::endl;
    signals_->on_receive_(udt_connection_id_, kReceiveUdtFailure);
    UDT::close(udt_connection_id_);
    return 0;
  } else if (received_count == 0) {
    LOG(INFO) << "Receiving socket " << udt_connection_id_ << " timed out" <<
        std::endl;
    signals_->on_receive_(udt_connection_id_, kReceiveTimeout);
    UDT::close(udt_connection_id_);
    return 0;
  }
  if (data_size < 1) {
    LOG(ERROR) << "Data size is " << data_size << std::endl;
    signals_->on_receive_(udt_connection_id_, kReceiveSizeFailure);
    UDT::close(udt_connection_id_);
    return 0;
  }
  return data_size;
}

bool UdtConnection::ReceiveDataContent(const DataSize &data_size) {
  boost::scoped_array<char> serialised_message(new char[data_size]);
  DataSize received_total = 0;
  int received_size = 0;
  while (received_total < data_size) {
    if (UDT::ERROR == (received_size = UDT::recv(udt_connection_id_,
        serialised_message.get() + received_total, data_size - received_total,
        0))) {
      LOG(ERROR) << "Recv: " << UDT::getlasterror().getErrorMessage() <<
          std::endl;
      signals_->on_receive_(udt_connection_id_, kReceiveUdtFailure);
      UDT::close(udt_connection_id_);
      return false;
    } else if (received_size == 0) {
      LOG(INFO) << "Receiving socket " << udt_connection_id_ << " timed out" <<
          std::endl;
      signals_->on_receive_(udt_connection_id_, kReceiveTimeout);
      UDT::close(udt_connection_id_);
      return false;
    }
    received_total += received_size;
  }
  return transport_message_.ParseFromArray(serialised_message.get(), data_size);
}

bool UdtConnection::HandleTransportMessage(const float &rtt) {
  bool is_request(transport_message_.type() == TransportMessage::kRequest);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      transport_message_.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(transport_message_.data(), &field_descriptors);
  if (field_descriptors.size() != 1U) {
    LOG(INFO) << "Bad data - doesn't contain exactly one field." << std::endl;
    if (!is_request)
      signals_->on_receive_(udt_connection_id_, kReceiveParseFailure);
    UDT::close(udt_connection_id_);
    return false;
  }
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
      signals_->on_message_received_(transport_message_.data().raw_message(),
                                    udt_connection_id_, rtt);
      break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
      if (is_request) {
        signals_->on_rpc_request_received_(
            transport_message_.data().rpc_message(), udt_connection_id_, rtt);
        // Leave socket open to send response on.
      } else {
        signals_->on_rpc_response_received_(
            transport_message_.data().rpc_message(), udt_connection_id_, rtt);
        UDT::close(udt_connection_id_);
      }
      break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
//      HandleRendezvousMessage(
//          transport_message_.data().hole_punching_message());
      UDT::close(udt_connection_id_);
      break;
    case TransportMessage::Data::kPingFieldNumber:
      UDT::close(udt_connection_id_);
      break;
    case TransportMessage::Data::kProxyPingFieldNumber:
      UDT::close(udt_connection_id_);
      break;
    case TransportMessage::Data::kManagedEndpointMessageFieldNumber:
      if (transport_udt_) {
        if (is_request) {
          transport_udt_->HandleManagedSocketRequest(udt_connection_id_,
              transport_message_.data().managed_endpoint_message());
          // Leave socket open.
        } else {
          transport_udt_->HandleManagedSocketResponse(udt_connection_id_,
              transport_message_.data().managed_endpoint_message());
          // Leave socket open.
        }
      } else {
        UDT::close(udt_connection_id_);
      }
      break;
    default:
      LOG(INFO) << "Unrecognised data type in TransportMessage." << std::endl;
      UDT::close(udt_connection_id_);
      return false;
  }
  return true;
}

}  // namespace transport
