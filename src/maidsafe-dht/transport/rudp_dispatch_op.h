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

#ifndef MAIDSAFE_DHT_TRANSPORT_RUDP_DISPATCH_OP_H_
#define MAIDSAFE_DHT_TRANSPORT_RUDP_DISPATCH_OP_H_

#include "boost/asio/buffer.hpp"
#include "boost/system/error_code.hpp"
#include "maidsafe-dht/transport/transport.h"
#include "maidsafe-dht/transport/rudp_dispatcher.h"

namespace maidsafe {

namespace transport {

// Helper class to perform an asynchronous dispatch operation.
template <typename DispatchHandler>
class RudpDispatchOp {
 public:
  RudpDispatchOp(DispatchHandler handler,
                const boost::asio::const_buffer &buffer,
                const boost::asio::ip::udp::endpoint *sender_endpoint,
                RudpDispatcher *dispatcher)
    : handler_(handler),
      buffer_(buffer),
      sender_endpoint_(sender_endpoint),
      dispatcher_(dispatcher) {
  }

  void operator()(const boost::system::error_code &ec,
                  size_t bytes_transferred) {
    if (!ec) {
      dispatcher_->HandleReceiveFrom(boost::asio::buffer(buffer_,
                                                         bytes_transferred),
                                     *sender_endpoint_);
    }

    handler_(ec);
  }

 private:
  DispatchHandler handler_;
  boost::asio::const_buffer buffer_;
  const boost::asio::ip::udp::endpoint *sender_endpoint_;
  RudpDispatcher *dispatcher_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_TRANSPORT_RUDP_DISPATCH_OP_H_
