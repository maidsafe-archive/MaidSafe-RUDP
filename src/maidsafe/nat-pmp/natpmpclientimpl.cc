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

Created by Julian Cain on 11/3/09.

*/

#include "maidsafe/nat-pmp/natpmpclientimpl.h"

#include <boost/bind.hpp>

#include "maidsafe/base/gateway.h"
#include "maidsafe/base/log.h"

namespace natpmp {

NatPmpClientImpl::NatPmpClientImpl(boost::asio::io_service *ios)
    : m_public_ip_address_(boost::asio::ip::address_v4::any()),
      io_service_(ios),
      retry_timer_(*ios) {}

NatPmpClientImpl::~NatPmpClientImpl() {
  // If the socket is valid call stop.
  if (socket_)
    Stop();

  // Clear the mappings.
  mappings_.clear();

  // Clear the request queue.
  request_queue_.clear();
}

void NatPmpClientImpl::Start() {
  if (socket_) {
    throw std::runtime_error(
        "Attempted to start nat-pmp client while socket is in use.");
  } else {
    // Allocate the socket.
    socket_.reset(new boost::asio::ip::udp::socket(*io_service_));

    boost::system::error_code ec;

    // Obtain the default gateway/route.
    m_gateway_address_ = base::Gateway::DefaultRoute(*io_service_, ec);

    if (ec) {
      throw std::runtime_error(ec.message());
    } else {
      DLOG(INFO) << "Started NAT-PMP client, default route to gateway is " <<
          m_gateway_address_ << "." << std::endl;
    }

    boost::asio::ip::udp::endpoint ep(m_gateway_address_, Protocol::kPort);

    // Connect the socket so that we receive ICMP errors.
    socket_->lowest_layer().async_connect(
        ep,
        boost::bind(&NatPmpClientImpl::HandleConnect,
            this,
            boost::asio::placeholders::error));
  }
}

void NatPmpClientImpl::Stop() {
  if (socket_ && socket_->is_open()) {
    DLOG(INFO) << "Stopping NAT-PMP client..." << std::endl;

    std::vector< std::pair<
        Protocol::MappingRequest, Protocol::MappingResponse> >::iterator it =
        mappings_.begin();

    for (; it != mappings_.end(); ++it) {
      DLOG(INFO) << "Removing NAT-PMP mapping: " <<
          static_cast<boost::uint32_t>((*it).first.buffer[1]) << ":" <<
          (*it).second.private_port << ":" << (*it).second.public_port <<
          std::endl;

      // Send the mapping request with a lifetime of 0.
      SendMappingRequest((*it).first.buffer[1], (*it).second.private_port,
        (*it).second.public_port, 0);
    }

    // Close the socket.
    socket_->close();

    // Cleanup.
    socket_.reset();

    DLOG(INFO) << "NAT-PMP client stop complete." << std::endl;
  } else {
    DLOG(ERROR) << "NAT-PMP client is already stopped." << std::endl;
  }
}

void NatPmpClientImpl::SetMapPortSuccessCallback(
    const NatPmpMapPortSuccessCbType & map_port_success_cb) {
  nat_pmp_map_port_success_cb_ = map_port_success_cb;
}

void NatPmpClientImpl::SendMappingRequest(boost::uint16_t protocol,
                                          boost::uint16_t private_port,
                                          boost::uint16_t public_port,
                                          boost::uint32_t lifetime) {
  io_service_->post(boost::bind(&NatPmpClientImpl::DoSendMappingRequest,
      this, protocol, private_port, public_port, lifetime));
}

void NatPmpClientImpl::DoSendMappingRequest(boost::uint16_t protocol,
                                            boost::uint16_t private_port,
                                            boost::uint16_t public_port,
                                            boost::uint32_t lifetime) {
  if (socket_ && socket_->is_open()) {
    DLOG(INFO) << "Queueing mapping request for protocol = " << protocol <<
        ", private_port = " << private_port << ", public_port = " <<
        public_port << ", lifetime = " << lifetime << std::endl;

    Protocol::MappingRequest r;

    r.buffer[0] = 0;
    r.buffer[1] = static_cast<char>(protocol);
    r.buffer[2] = 0;
    r.buffer[3] = 0;

    *((boost::uint16_t *)(r.buffer + 4)) = htons(private_port);
    *((boost::uint16_t *)(r.buffer + 6)) = htons(public_port);
    *((boost::uint32_t *)(r.buffer + 8)) = htonl(lifetime);

    r.length = 12;
    r.retry_count = 0;

    request_queue_.push_back(r);
  }
}

void NatPmpClientImpl::SendPublicAddressRequest() {
  DLOG(INFO) <<
      "NAT-PMP client sending public address request to gateway device." <<
      std::endl;

  public_ip_request_.buffer[0] = 0;
  public_ip_request_.buffer[1] = 0;
  public_ip_request_.length = 2;

//  public_ip_request_.retry_time =
//      boost::posix_time::microsec_clock::universal_time() +
//      boost::posix_time::milliseconds(250);

  public_ip_request_.retry_count = 1;

  SendRequest(public_ip_request_);

  retry_timer_.expires_from_now(boost::posix_time::milliseconds(
      250 * public_ip_request_.retry_count));

  retry_timer_.async_wait(boost::bind(
      &NatPmpClientImpl::RetransmitPublicAdddressRequest, this, _1));
}

void NatPmpClientImpl::RetransmitPublicAdddressRequest(
    const boost::system::error_code & ec) {
  if (ec) {
  // operation aborted
  } else if (public_ip_request_.retry_count >= 9) {
    DLOG(ERROR) << "No NAT-PMP gateway device found, calling stop." <<
        std::endl;

    retry_timer_.cancel();

    Stop();
  } else if (m_public_ip_address_ == boost::asio::ip::address_v4::any()) {
  // Increment retry count.
  ++public_ip_request_.retry_count;

  // Retransmit the request.
  SendRequest(public_ip_request_);

  DLOG(INFO) << "Retransmitting public address request, retry = " <<
      (boost::uint32_t)public_ip_request_.retry_count << "." << std::endl;

  retry_timer_.expires_from_now(boost::posix_time::milliseconds(
      250 * public_ip_request_.retry_count));

  retry_timer_.async_wait(boost::bind(
      &NatPmpClientImpl::RetransmitPublicAdddressRequest, this, _1));
  }
}

void NatPmpClientImpl::SendRequest(Protocol::MappingRequest & req) {
  if (socket_ && socket_->is_open()) {
    Send(reinterpret_cast<const char *>(req.buffer), req.length);
  } else {
    DLOG(ERROR) << "Cannot send NAT-PMP request while not started!" <<
        std::endl;
  }
}

void NatPmpClientImpl::SendQueuedRequests() {
  if (socket_ && socket_->is_open()) {
    if (!request_queue_.empty()) {
      DLOG(INFO) << "Sending queued NAT-PMP requests, " <<
          request_queue_.size() << " remaing."<< std::endl;
      Protocol::MappingRequest r = request_queue_.front();

      SendRequest(r);
    }
  }
}

void NatPmpClientImpl::Send(const char * buf, std::size_t len) {
  socket_->async_send(
      boost::asio::buffer(buf, len),
      boost::bind(
          &NatPmpClientImpl::HandleSend,
          this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
}

void NatPmpClientImpl::HandleSend(const boost::system::error_code & ec,
                                  std::size_t) {
  if (ec == boost::asio::error::operation_aborted) {
    // ...
  } else if (ec) {
    DLOG(ERROR) << Protocol::StringFromOpcode(Protocol::kErrorSend) << " : " <<
        ec.message() << std::endl;
  } else {
    socket_->async_receive_from(
        boost::asio::buffer(data_, kReceiveBufferLength),
        endpoint_,
        boost::bind(
            &NatPmpClientImpl::HandleReceiveFrom,
            this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));
  }
}

void NatPmpClientImpl::HandleConnect(const boost::system::error_code & ec) {
  if (ec == boost::asio::error::operation_aborted) {
    // ...
  } else if (ec) {
    DLOG(ERROR) << "No NAT-PMP compatible gateway found, calling stop." <<
        std::endl;

  // Call stop.
  Stop();
  } else {
    DLOG(INFO) << "Sending public address request to gateway." << std::endl;

    // Send a request for the NAT-PMP gateway's public ip address. This is also
    // used to determine if the gateway is valid.
    SendPublicAddressRequest();
  }
}

void NatPmpClientImpl::HandleReceiveFrom(const boost::system::error_code & ec,
                                         std::size_t bytes) {
  if (ec == boost::asio::error::operation_aborted) {
    // ...
  } else if (ec) {
#if NDEBUG
    DLOG(ERROR) << Protocol::StringFromOpcode(Protocol::kErrorReceiveFrom) <<
        " : " << ec.message() << std::endl;
#endif
#ifndef NDEBUG
    DLOG(ERROR) << "No NAT-PMP compatible gateway found, calling stop." <<
        std::endl;
#endif
    // Call stop.
    Stop();
  } else {
  // Handle the response.
  HandleResponse(data_, bytes);

  socket_->async_receive_from(
      boost::asio::buffer(data_, kReceiveBufferLength),
      endpoint_,
      boost::bind(
          &NatPmpClientImpl::HandleReceiveFrom,
          this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }
}

void NatPmpClientImpl::HandleResponse(const char * buf, std::size_t) {
  boost::uint32_t opcode = 0;

  Protocol::MappingResponse response;

  if (endpoint_.address() == m_gateway_address_) {
    response.result_code = ntohs(*((boost::uint16_t *)(buf + 2)));

    response.epoch = ntohl(*((boost::uint32_t *)(buf + 4)));

    if (buf[0] != 0) {
      opcode = Protocol::kResultUnsupportedVersion;
    } else if (static_cast<unsigned char> (buf[1]) < 128 ||
               static_cast<unsigned char> (buf[1]) > 130) {
      opcode = Protocol::kResultUnsupportedOpcode;
    } else if (response.result_code != 0) {
      switch (response.result_code) {
        case 1:
          opcode = Protocol::kResultUnsupportedVersion;
          break;
        case 2:
          opcode = Protocol::kResultNotAuthorisedRefused;
          break;
        case 3:
          opcode = Protocol::kResultNetworkFailure;
          break;
        case 4:
          opcode = Protocol::kResultOutOfResources;
          break;
        case 5:
          opcode = Protocol::kResultUnsupportedOpcode;
          break;
        default:
          opcode = Protocol::kResultUndefined;
          break;
      }
    } else {
      response.type = static_cast<unsigned char>(buf[1]) & 0x7f;

      if (static_cast<unsigned char> (buf[1]) == 128) {
        boost::uint32_t ip = ntohl(*((boost::uint32_t *)(buf + 8)));

        response.public_address = boost::asio::ip::address_v4(ip);

        m_public_ip_address_ = response.public_address;

        retry_timer_.cancel();

        DLOG(INFO) <<
        "Obtained public ip address " << response.public_address <<
        " from NAT-PMP gateway, sending any queued requests." <<
        std::endl;

        /**
        * A NAT-PMP compatible gateway has been found, send queued
        * requests.
        */
        SendQueuedRequests();
      } else {
        response.private_port = ntohs(*((boost::uint16_t *)(buf + 8)));

        response.public_port = ntohs(*((boost::uint16_t *)(buf + 10)));

        response.lifetime = ntohl(*((boost::uint32_t *)(buf + 12)));

        Protocol::MappingRequest request = request_queue_.front();

        std::pair<Protocol::MappingRequest, Protocol::MappingResponse> mapping =
            std::make_pair(request, response);

        if (std::find(mappings_.begin(), mappings_.end(), mapping) ==
            mappings_.end()) {
          DLOG(INFO) << "NatPmpClientImpl::on_nat_pmp_mapping_success: " <<
              response.public_port << ":" << std::endl;

          if (nat_pmp_map_port_success_cb_) {
            nat_pmp_map_port_success_cb_(mapping.first.buffer[1],
                response.private_port, response.public_port);
          }

          mappings_.push_back(mapping);
        }

        request_queue_.pop_front();

        // Send queued requests.
        SendQueuedRequests();
      }

      opcode = 0;
    }
  } else {
    opcode = Protocol::kErrorSourceConflict;
  }

  if (opcode) {
#ifndef NDBEUG
    DLOG(ERROR) << "DEBUG: NAT-PMP response opcode: " <<
        Protocol::StringFromOpcode(opcode) << std::endl;
#endif
  }
}

}  // namespace natpmp
