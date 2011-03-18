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

#include "maidsafe-dht/transport/udt_socket.h"

#include "maidsafe/common/log.h"

namespace asio = boost::asio;
namespace bs = boost::system;
namespace bptime = boost::posix_time;
namespace arg = std::placeholders;

namespace maidsafe {

namespace transport {

UdtSocket::UdtSocket(const std::shared_ptr<UdtMultiplexer> &udt_multiplexer,
                     asio::io_service &asio_service,
                     const Endpoint &remote_endpoint)
  : multiplexer_(udt_multiplexer),
    remote_endpoint_(remote_endpoint),
    waiting_op_(asio_service),
    waiting_op_ec_(),
    waiting_op_bytes_transferred_(0) {
  waiting_op_.expires_at(boost::posix_time::pos_infin);
}

UdtSocket::~UdtSocket() {
}

void UdtSocket::Close() {
  waiting_op_ec_ = asio::error::operation_aborted;
  waiting_op_bytes_transferred_ = 0;
  waiting_op_.cancel();
}

void UdtSocket::Send(const boost::asio::const_buffer &data) {
}

void UdtSocket::StartConnect() {
}

void UdtSocket::StartReceive(const boost::asio::mutable_buffer &data) {
}

}  // namespace transport

}  // namespace maidsafe

