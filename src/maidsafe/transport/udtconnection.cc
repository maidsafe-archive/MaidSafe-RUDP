
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

#include <boost/scoped_array.hpp>

#include <algorithm>
#include <vector>

#include "maidsafe/base/log.h"
#include "maidsafe/transport/udttransport.h"

namespace transport {

UdtConnection::UdtConnection(boost::shared_ptr<UdtTransport> transport,
                             const Endpoint &endpoint,
                             const ConnectionType &connection_type)
    : transport_(transport),
      socket_id_(UDT::INVALID_SOCK),
      endpoint_(endpoint),
      connection_type_(connection_type),
      peer_(),
      data_(),
      timeout_timer_(new boost::asio::deadline_timer(*transport_->asio_service_,
                                                     kDefaultInitialTimeout)),
      stall_timer_(new boost::asio::deadline_timer(*transport_->asio_service_,
                                                   kStallTimeout)) {
  Init();
}

UdtConnection::UdtConnection(boost::shared_ptr<UdtTransport> transport,
                             const SocketId &socket_id,
                             const ConnectionType &connection_type)
    : transport_(transport),
      socket_id_(socket_id),
      endpoint_(),
      connection_type_(connection_type),
      peer_(),
      data_(),
      timeout_timer_(new boost::asio::deadline_timer(*transport_->asio_service_,
                                                     kDefaultInitialTimeout)),
      stall_timer_(new boost::asio::deadline_timer(*transport_->asio_service_,
                                                   kStallTimeout)) {}

UdtConnection::UdtConnection(const UdtConnection &other)
    : transport_(other.transport_),
      socket_id_(other.socket_id_),
      endpoint_(other.endpoint_),
      connection_type_(other.connection_type_),
      peer_(other.peer_),
      data_(other.data_),
      timeout_timer_(other.timeout_timer_),
      stall_timer_(other.stall_timer_) {}

UdtConnection& UdtConnection::operator=(const UdtConnection &other) {
  if (this != &other) {
    transport_ = other.transport_;
    socket_id_ = other.socket_id_;
    endpoint_ = other.endpoint_;
    connection_type_ = other.connection_type_;
    peer_ = other.peer_;
    data_ = other.data_;
    timeout_timer_ = other.timeout_timer_;
    stall_timer_ = other.stall_timer_;
  }
  return *this;
}

UdtConnection::~UdtConnection() {
  UDT::close(socket_id_);
  if (connection_type_ == kAccepted)
    --transport_->accepted_connection_count_;
}

void UdtConnection::Init() {
  peer_ = boost::shared_ptr<addrinfo const>(new addrinfo);
  if (udtutils::GetNewSocket(endpoint_, true, &socket_id_, &peer_) != kSuccess)
    socket_id_ = UDT::INVALID_SOCK;
  if (udtutils::SetSyncMode(socket_id_, false) != kSuccess)
    socket_id_ = UDT::INVALID_SOCK;
}

void UdtConnection::SetDataSizeTimeout(const Timeout &timeout) {
  if (timeout == kDynamicTimeout)
    timeout_timer_->expires_from_now(kStallTimeout);
  else
    timeout_timer_->expires_from_now(timeout);
}

void UdtConnection::SetDataContentTimeout(const DataSize &data_size,
                                          const Timeout &timeout) {
  if (timeout == kDynamicTimeout)
    timeout_timer_->expires_from_now(std::max(
        static_cast<Timeout>(data_size * kTimeoutFactor), kMinTimeout));
  else
    timeout_timer_->expires_from_now(timeout);
}

void UdtConnection::Send(const std::string &data,
                         const Timeout &timeout_wait_for_response) {
  if (data.size() > static_cast<size_t>(kMaxTransportMessageSize)) {
    DLOG(ERROR) << "Data size " << data.size() << " bytes (exceeds limit of "
                << kMaxTransportMessageSize << ")" << std::endl;
    (*transport_->on_error_)(kMessageSizeTooLarge);
    return;
  }
  if (udtutils::Connect(socket_id_, peer_) != kSuccess) {
    (*transport_->on_error_)(kSendFailure);
    return;
  }
  data_ = data;
  transport_->asio_service_->post(boost::bind(&UdtConnection::SendData,
                                              shared_from_this(),
                                              timeout_wait_for_response));
}

void UdtConnection::SendData(const Timeout &timeout_wait_for_response) {
  // Send the message size
  SetDataSizeTimeout(kStallTimeout);
  DataSize data_size = static_cast<DataSize>(data_.size());
  DataSize data_buffer_size = sizeof(data_size);
  TransportCondition result = MoveData(true, data_buffer_size,
                                       reinterpret_cast<char*>(&data_size));
  if (result != kSuccess) {
    (*transport_->on_error_)(result);
    UDT::close(socket_id_);
    return;
  }

  // Send the message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(socket_id_,
                                                     UdtStats::kSend));
  SetDataContentTimeout(data_size, kDynamicTimeout);
  result = MoveData(true, data_size, &data_.at(0));
  if (result != kSuccess) {
    (*transport_->on_error_)(result);
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
//      (*transport_->on_stats_)(udt_stats);
//    }

  if (timeout_wait_for_response == kImmediateTimeout) {
    UDT::close(socket_id_);
  } else {
    ReceiveData(timeout_wait_for_response);
  }
}

void UdtConnection::ReceiveData(const Timeout &timeout) {
  // Check if deadline has already expired
  if (timeout_timer_->expires_at() <=
      boost::asio::deadline_timer::traits_type::now()) {
    DLOG(ERROR) << "Receive deadline already expired." << std::endl;
    (*transport_->on_error_)(kReceiveTimeout);
    UDT::close(socket_id_);
    return;
  }

  // Get the incoming message size
  SetDataSizeTimeout(timeout);
  DataSize data_buffer_size = sizeof(DataSize);
  DataSize data_size;
  TransportCondition result =
      MoveData(false, data_buffer_size, reinterpret_cast<char*>(&data_size));
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot get data size." << std::endl;
    (*transport_->on_error_)(result);
    UDT::close(socket_id_);
    return;
  }
  if (data_size < 1) {
    DLOG(ERROR) << "Data size is " << data_size << std::endl;
    (*transport_->on_error_)(kReceiveSizeFailure);
    UDT::close(socket_id_);
    return;
  }
  if (data_size > kMaxTransportMessageSize) {
    DLOG(ERROR) << "Data size " << data_size << " bytes (exceeds limit of "
                << kMaxTransportMessageSize << ")" << std::endl;
    (*transport_->on_error_)(kMessageSizeTooLarge);
    UDT::close(socket_id_);
    return;
  }

  // Get message
  boost::shared_ptr<UdtStats> udt_stats(new UdtStats(socket_id_,
                                                     UdtStats::kReceive));
  if (timeout == kDynamicTimeout)
    SetDataContentTimeout(data_size, kDynamicTimeout);
  data_.clear();
  boost::scoped_array<char> data(new char[data_size]);
  result = MoveData(false, data_size, data.get());
  if (result != kSuccess) {
    DLOG(ERROR) << "Cannot get data content." << std::endl;
    (*transport_->on_error_)(result);
    UDT::close(socket_id_);
    return;
  }
  data_.assign(data.get(), data_size);

  // Get stats
  if (UDT::ERROR == UDT::perfmon(socket_id_,
                                 &udt_stats->performance_monitor_)) {
#ifdef DEBUG
    if (UDT::getlasterror().getErrorCode() != 2001)
      DLOG(ERROR) << "UDT perfmon error: "
                  << UDT::getlasterror().getErrorCode() << std::endl;
#endif
  } else {
    udt_stats->rtt = udt_stats->performance_monitor_.msRTT;
  }

  // Signal message received and send response if applicable
  std::string response;
  Timeout response_timeout(kImmediateTimeout);
  (*transport_->on_message_received_)
      (data_,
      *boost::static_pointer_cast<Info>(udt_stats),
      &response,
      &response_timeout);
  if (response.empty())
    return;
  if (response.size() > static_cast<size_t>(kMaxTransportMessageSize)) {
    DLOG(ERROR) << "Response size " << response.size() << " bytes (exceeds "
                "limit of " << kMaxTransportMessageSize << ")" << std::endl;
    (*transport_->on_error_)(kMessageSizeTooLarge);
    return;
  }
  data_ = response;
  SendData(response_timeout);
}

TransportCondition UdtConnection::MoveData(bool sending,
                                           const DataSize &data_size,
                                           char *data) {
  stall_timer_->expires_from_now(kStallTimeout);
  DataSize moved_total = 0;
  int moved_size = 0;

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
      stall_timer_->expires_from_now(kStallTimeout);
    }

    // Check for overall timeout
    if (timeout_timer_->expires_at() <=
        boost::asio::deadline_timer::traits_type::now()) {
      DLOG(INFO) << (sending ? "Sending socket " : "Receiving socket ") <<
          socket_id_ << " timed out in MoveData." << std::endl;
      return (sending ? kSendTimeout : kReceiveTimeout);
    }

    // Check for stalled transmission timeout
    if (stall_timer_->expires_at() <=
        boost::asio::deadline_timer::traits_type::now()) {
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

}  // namespace transport
