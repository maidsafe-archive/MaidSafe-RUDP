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

#ifndef MAIDSAFE_TRANSPORT_UDP_REQUEST_H_
#define MAIDSAFE_TRANSPORT_UDP_REQUEST_H_

#include <cstdint>
#include <string>
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class UdpRequest {
 public:
  UdpRequest(const std::string &data,
             const boost::asio::ip::udp::endpoint &endpoint,
             boost::asio::io_service &asio_service,
             const Timeout &timeout,
             uint64_t reply_to_id = 0);

  const std::string &Data() const;
  const boost::asio::ip::udp::endpoint& Endpoint() const;
  const Timeout& ReplyTimeout() const;
  uint64_t ReplyToId() const;

  template <typename WaitHandler>
  void WaitForTimeout(WaitHandler handler) {
    timer_.async_wait(handler);
  }

 private:
  UdpRequest(const UdpRequest&);
  UdpRequest &operator=(const UdpRequest&);

  std::string data_;
  boost::asio::ip::udp::endpoint endpoint_;
  boost::asio::deadline_timer timer_;
  Timeout reply_timeout_;
  uint64_t reply_to_id_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_UDP_REQUEST_H_
