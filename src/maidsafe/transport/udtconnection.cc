
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

#include "maidsafe/transport/udtconnection.h"

#include <boost/cstdint.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/scoped_array.hpp>
#include <google/protobuf/descriptor.h>

#include <algorithm>
#include <vector>

#include "maidsafe/base/log.h"
#include "maidsafe/base/threadpool.h"
#include "maidsafe/transport/udttransport.h"

namespace transport {

UdtConnection::UdtConnection(UdtTransport *transport, const Endpoint &endpoint)
    : transport_(transport),
      socket_id_(UDT::INVALID_SOCK),
      endpoint_(endpoint),
      peer_(),
      data_(),
      send_timeout_(kDefaultInitialTimeout),
      receive_timeout_(kDefaultInitialTimeout) {
  Init();
}

UdtConnection::UdtConnection(UdtTransport *transport, const SocketId &socket_id)
    : transport_(transport),
      socket_id_(socket_id),
      endpoint_(),
      peer_(),
      data_(),
      send_timeout_(kDefaultInitialTimeout),
      receive_timeout_(kDefaultInitialTimeout) {}

UdtConnection::UdtConnection(const UdtConnection &other)
    : transport_(other.transport_),
      socket_id_(other.socket_id_),
      endpoint_(other.endpoint_),
      peer_(other.peer_),
      data_(other.data_),
      send_timeout_(other.send_timeout_),
      receive_timeout_(other.receive_timeout_) {}

UdtConnection& UdtConnection::operator=(const UdtConnection &other) {
  if (this != &other) {
    transport_ = other.transport_;
    socket_id_ = other.socket_id_;
    endpoint_ = other.endpoint_;
    peer_ = other.peer_;
    data_ = other.data_;
    send_timeout_ = other.send_timeout_;
    receive_timeout_ = other.receive_timeout_;
  }
  return *this;
}

void UdtConnection::Init() {
  peer_ = boost::shared_ptr<addrinfo const>(new addrinfo);
  if (udtutils::GetNewSocket(endpoint_, false, &socket_id_, &peer_) != kSuccess)
    socket_id_ = UDT::INVALID_SOCK;
  if (udtutils::SetSyncMode(socket_id_, false) != kSuccess)
    socket_id_ = UDT::INVALID_SOCK;
}

bool UdtConnection::SetDataSizeSendTimeout() {
  return SetTimeout(kDefaultInitialTimeout, true);
}

bool UdtConnection::SetDataSizeReceiveTimeout(const Timeout &timeout) {
  if (timeout == kDynamicTimeout)
    return SetTimeout(kDefaultInitialTimeout, false);
  else
    return SetTimeout(timeout, false);
}

bool UdtConnection::SetDataContentSendTimeout() {
  Timeout timeout(std::max(static_cast<Timeout>(data_.size() * kTimeoutFactor),
                           kMinTimeout));
  return SetTimeout(timeout, true);
}

bool UdtConnection::SetDataContentReceiveTimeout(const DataSize &data_size,
                                                 const Timeout &timeout) {
  if (timeout == kDynamicTimeout)
    return SetTimeout(std::max(static_cast<Timeout>(data_size * kTimeoutFactor),
                               kMinTimeout), false);
  else
    return SetTimeout(timeout, false);
}

bool UdtConnection::SetTimeout(const Timeout &timeout, bool send) {
  if (send)
    send_timeout_ = timeout;
  else
    receive_timeout_ = timeout;
  if (UDT::ERROR == UDT::setsockopt(socket_id_, 0,
                                    (send ? UDT_SNDTIMEO : UDT_RCVTIMEO),
                                    &timeout, sizeof(timeout))) {
    DLOG(ERROR) << "UDT SetTimeout error: " <<
                   UDT::getlasterror().getErrorMessage() << std::endl;
    return false;
  } else {
    return true;
  }
}

TransportCondition UdtConnection::CheckMessage(bool *is_request) {
  DataSize data_size = static_cast<DataSize>(data_.size());
  if (data_size > kMaxTransportMessageSize) {
    DLOG(ERROR) << "Data size " << data_size << " bytes (exceeds limit of " <<
        kMaxTransportMessageSize << ")" << std::endl;
    return kMessageSizeTooLarge;
  }
//                               *is_request = (data_.type() == TransportMessage::kKeepAlive);
  return kSuccess;
}

void UdtConnection::Send(const std::string &data,
                         const Timeout &timeout_wait_for_response) {
  data_ = data;
  bool is_request(false);
  TransportCondition result = CheckMessage(&is_request);
  if (result != kSuccess) {
    transport_->on_error_->operator()(socket_id_, result);
    return;
  }
  ActionAfterSend action_after_send(kClose);
  if (is_request) {
    result = udtutils::Connect(socket_id_, peer_);
    if (result != kSuccess) {
      transport_->on_error_->operator()(socket_id_, kSendFailure);
      return;
    }
    if (timeout_wait_for_response != kImmediateTimeout)
      action_after_send = kReceive;
  }
  try {
    boost::function<void()> functor(boost::bind(&UdtConnection::SendData,
        *this, action_after_send, timeout_wait_for_response));
    transport_->asio_service_->post(functor);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "In UdtConnection::Send: " << e.what() << std::endl;
    transport_->on_error_->operator()(socket_id_, kSendFailure);
  }
}

void UdtConnection::SendData(const ActionAfterSend &action_after_send,
                             const Timeout &timeout_wait_for_response) {
  // Send the message size
  TransportCondition result = SendDataSize();
  if (result != kSuccess) {
    transport_->on_error_->operator()(socket_id_, result);
    UDT::close(socket_id_);
    return;
  }

  // Send the message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(socket_id_,
                                                     UdtStats::kSend));
  result = SendDataContent();
  if (result != kSuccess) {
    transport_->on_error_->operator()(socket_id_, result);
    UDT::close(socket_id_);
    return;
  }

//    // Get stats
//    if (UDT::ERROR == UDT::perfmon(socket_id_,
//                                   &udt_stats->performance_monitor_)) {
//  #ifdef DEBUG
//      if (UDT::getlasterror().getErrorCode() != 2001)
//        DLOG(ERROR) << "UDT perfmon error: " <<
//            UDT::getlasterror().getErrorMessage() << std::endl;
//  #endif
//    } else {
//      signals_->on_stats_(udt_stats);
//    }
  if (action_after_send == kClose) {
    UDT::close(socket_id_);
  } else if (action_after_send == kReceive) {
    ReceiveData(timeout_wait_for_response);
  } else {
    return;
  }
}

TransportCondition UdtConnection::SendDataSize() {
  if (!SetDataSizeSendTimeout()) {
    DLOG(WARNING) << "UdtTransport::SendDataSize: SetDataSizeSendTimeout "
                     "failed." << std::endl;
  }
  DataSize data_size = static_cast<DataSize>(data_.size());
  DataSize data_buffer_size = sizeof(data_size);
  return MoveData(true, data_buffer_size, reinterpret_cast<char*>(&data_size));
}

TransportCondition UdtConnection::SendDataContent() {
  if (!SetDataContentSendTimeout()) {
    DLOG(WARNING) << "UdtTransport::SendDataContent: SetDataContentSendTimeout "
                     "failed." << std::endl;
  }
  DataSize data_size = static_cast<DataSize>(data_.size());
  boost::scoped_array<char> serialised_message(new char[data_size]);
  return MoveData(true, data_size, &data_.at(0));
}

void UdtConnection::ReceiveData(const Timeout &timeout) {
  boost::posix_time::ptime
      start_time(boost::posix_time::microsec_clock::universal_time());

  // Get the incoming message size
  DataSize data_size = ReceiveDataSize(timeout);
  if (data_size == 0)
    return;

  // Get message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(socket_id_,
                                                     UdtStats::kReceive));
  Timeout remaining_timeout(kDynamicTimeout);
  if (timeout != kDynamicTimeout) {
    Timeout elapsed(
        (boost::posix_time::microsec_clock::universal_time() - start_time).
            total_milliseconds());
    if (timeout < elapsed)
      remaining_timeout = Timeout(0);
    else
      remaining_timeout = timeout - elapsed;
  }
  if (!ReceiveDataContent(data_size, remaining_timeout))
    return;

  // Get stats
  float rtt;
  if (UDT::ERROR == UDT::perfmon(socket_id_,
                                 &udt_stats->performance_monitor_)) {
#ifdef DEBUG
    if (UDT::getlasterror().getErrorCode() != 2001)
      DLOG(ERROR) << "UDT perfmon error: " <<
          UDT::getlasterror().getErrorCode() << std::endl;
#endif
  } else {
//    signals_->on_stats_(udt_stats);
    rtt = udt_stats->performance_monitor_.msRTT;
  }

  // Handle message
  HandleTransportMessage(rtt);
}

DataSize UdtConnection::ReceiveDataSize(const Timeout &timeout) {
  if (!SetDataSizeReceiveTimeout(timeout)) {
    DLOG(WARNING) << "UdtTransport::ReceiveDataSize: "
                     "SetDataSizeReceiveTimeout failed." << std::endl;
  }
  DataSize data_buffer_size = sizeof(DataSize);
  DataSize data_size;
  TransportCondition result =
      MoveData(false, data_buffer_size, reinterpret_cast<char*>(&data_size));
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot get data size." << std::endl;
    transport_->on_error_->operator()(socket_id_, result);
    UDT::close(socket_id_);
    return 0;
  }
  if (data_size < 1) {
    DLOG(ERROR) << "Data size is " << data_size << std::endl;
    transport_->on_error_->operator()(socket_id_, kReceiveSizeFailure);
    UDT::close(socket_id_);
    return 0;
  }
  if (data_size > kMaxTransportMessageSize) {
    DLOG(ERROR) << "Data size " << data_size << " bytes (exceeds limit of "
                << kMaxTransportMessageSize << ")" << std::endl;
    transport_->on_error_->operator()(socket_id_, kMessageSizeTooLarge);
    UDT::close(socket_id_);
    return 0;
  }
  return data_size;
}

bool UdtConnection::ReceiveDataContent(const DataSize &data_size,
                                       const Timeout &timeout) {
  if (!SetDataContentReceiveTimeout(data_size, timeout)) {
    DLOG(WARNING) << "UdtTransport::ReceiveDataContent: "
                     "SetDataContentReceiveTimeout failed." << std::endl;
  }
  transport_message_.Clear();
  boost::scoped_array<char> serialised_message(new char[data_size]);
  TransportCondition result =
      MoveData(false, data_size, serialised_message.get());
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot get data content." << std::endl;
    transport_->on_error_->operator()(socket_id_, result);
    UDT::close(socket_id_);
    return false;
  }
  if (!transport_message_.ParseFromArray(serialised_message.get(), data_size)) {
    DLOG(ERROR) << "UdtTransport::ReceiveDataContent: failed to parse." <<
        std::endl;
    transport_->on_error_->operator()(socket_id_, kReceiveFailure);
    UDT::close(socket_id_);
    return false;
  }
  return true;
}

TransportCondition UdtConnection::MoveData(bool sending,
                                           const DataSize &data_size,
                                           char *data) {
  DataSize moved_total = 0;
  int moved_size = 0;
  boost::posix_time::ptime
      start_time(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::ptime
      last_success_time(boost::posix_time::neg_infin);
  Timeout timeout(sending ? send_timeout_ : receive_timeout_);

  while (true) {
    if (sending) {
      moved_size = UDT::send(socket_id_, data + moved_total,
                             data_size - moved_total, 0);
    } else {
      moved_size = UDT::recv(socket_id_, data + moved_total,
                             data_size - moved_total, 0);
    }

    // Check if complete
    if (moved_size > 0) {
      moved_total += moved_size;
      if (moved_total == data_size)
        return kSuccess;
      if (moved_total > data_size) {
        DLOG(ERROR) << (sending ? "Send " : "Recv ") << socket_id_ << ": " <<
            "Exceeded expected size." << std::endl;
        return (sending ? kSendFailure : kReceiveFailure);
      }
      last_success_time = boost::posix_time::ptime(
          boost::posix_time::microsec_clock::universal_time());
    }

    // Check for overall timeout
    boost::posix_time::ptime
        now(boost::posix_time::microsec_clock::universal_time());
    Timeout elapsed((now - start_time).total_milliseconds());
    if (elapsed > timeout) {
      DLOG(INFO) << (sending ? "Sending socket " : "Receiving socket ") <<
          socket_id_ << " timed out in MoveData." << std::endl;
      return (sending ? kSendTimeout : kReceiveTimeout);
    }

    // Check for stalled transmission timeout
    Timeout stalled(0);
    if (!last_success_time.is_neg_infinity())
      stalled = (now - last_success_time).total_milliseconds();
    if (stalled > kStallTimeout) {
      DLOG(INFO) << (sending ? "Sending socket " : "Receiving socket ") <<
          socket_id_ << " stalled in MoveData." << std::endl;
      return (sending ? kSendStalled : kReceiveStalled);
    }

    // Check for UDT errors
    if (UDT::ERROR == moved_size &&
        UDT::getlasterror().getErrorCode() != UDT::ERRORINFO::EASYNCSND &&
        UDT::getlasterror().getErrorCode() != UDT::ERRORINFO::EASYNCRCV) {
      DLOG(ERROR) << (sending ? "Send " : "Recv ") << socket_id_ << ": " <<
          UDT::getlasterror().getErrorMessage() << std::endl;
      return (sending ? kSendFailure : kReceiveFailure);
    }
  }
}

bool UdtConnection::HandleTransportMessage(const float &rtt) {
/*  bool is_request(data_.type() == TransportMessage::kKeepAlive);
  // message data should contain exactly one optional field
  const google::protobuf::Message::Reflection *reflection =
      transport_message_.data().GetReflection();
  std::vector<const google::protobuf::FieldDescriptor*> field_descriptors;
  reflection->ListFields(transport_message_.data(), &field_descriptors);
  if (field_descriptors.size() != 1U) {
    DLOG(INFO) << "Bad data - doesn't contain exactly one field." << std::endl;
    if (!is_request)
      transport_->on_error_->operator()(socket_id_, kReceiveParseFailure);
    UDT::close(socket_id_);
    return false;
  }
  switch (field_descriptors.at(0)->number()) {
    case TransportMessage::Data::kRawMessageFieldNumber:
        signals_->on_message_received_(socket_id_,
            transport_message_.data().raw_message(), rtt);
        break;
    case TransportMessage::Data::kRpcMessageFieldNumber:
        if (is_request) {
          signals_->on_message_received_(socket_id_, 
              transport_message_.data().rpc_message(), rtt);
          // Leave socket open to send response on.
        } else {
          signals_->on_message_received_(socket_id_, 
              transport_message_.data().rpc_message(), rtt);
          UDT::close(socket_id_);
        }
        break;
    case TransportMessage::Data::kHolePunchingMessageFieldNumber:
//      HandleRendezvousMessage(
//          transport_message_.data().hole_punching_message());
        UDT::close(socket_id_);
        break;
    case TransportMessage::Data::kPingFieldNumber:
        UDT::close(socket_id_);
        break;
    case TransportMessage::Data::kProxyPingFieldNumber:
        UDT::close(socket_id_);
        break;
    case TransportMessage::Data::kManagedEndpointMessageFieldNumber:
        if (transport_) {
          if (is_request) {
            transport_->HandleManagedSocketRequest(socket_id_,
                transport_message_.data().managed_endpoint_message());
            // Leave socket open.
          } else {
            transport_->HandleManagedSocketResponse(socket_id_,
                transport_message_.data().managed_endpoint_message());
            // Leave socket open.
          }
        } else {
          UDT::close(socket_id_);
        }
    case TransportMessage::Data::kNatDetectionFieldNumber:
        transport_->PerformNatDetection(socket_id_,
            transport_message_.data().nat_detection());
        break;
    case TransportMessage::Data::kRendezvousNodeFieldNumber:
        {
          SocketId rendezvous_socket_id;
          RendezvousNode rn = transport_message_.data().rendezvous_node();
          TransportCondition tc =
              transport_->TryRendezvous(rn.rendezvous_node_ip(),
                                        rn.rendezvous_node_port(),
                                        &rendezvous_socket_id);
          DLOG(INFO) << "Result of rendezvous connect = " << tc
                     << std::endl;
        }
        break;
    case TransportMessage::Data::kNatInformationFieldNumber:
        break;
    case TransportMessage::Data::kConnectionNodeFieldNumber:
        if (transport_message_.type() == TransportMessage::kClose) {
          UDT::close(socket_id_);
          socket_id_ = UDT::INVALID_SOCK;
        }
        transport_->ReportRendezvousResult(
            socket_id_,
            transport_message_.data().connection_node().connection_node_ip(),
            transport_message_.data().connection_node().connection_node_port());
        break;
    default:
        DLOG(INFO) << "Unrecognised data type in TransportMessage."
                   << std::endl;
        UDT::close(socket_id_);
        return false;
  }*/
  return true;
}

}  // namespace transport
