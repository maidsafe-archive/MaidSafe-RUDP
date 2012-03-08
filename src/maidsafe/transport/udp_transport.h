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

#ifndef MAIDSAFE_TRANSPORT_UDP_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_UDP_TRANSPORT_H_

#include <cstdint>
#include <unordered_map>
#include <memory>
#include <string>
#include <vector>
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif


namespace maidsafe {

namespace transport {

class UdpRequest;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class UdpTransport : public Transport,
                     public std::enable_shared_from_this<UdpTransport> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
 public:
  explicit UdpTransport(boost::asio::io_service &asio_service);  // NOLINT
  virtual ~UdpTransport();

  virtual TransportCondition StartListening(const Endpoint &endpoint);
  virtual TransportCondition Bootstrap(const std::vector<Contact> &candidates);
  virtual void StopListening();
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout);
  static DataSize kMaxTransportMessageSize() { return 65535; }
 private:
  UdpTransport(const UdpTransport&);
  UdpTransport &operator=(const UdpTransport&);

  typedef std::shared_ptr<boost::asio::ip::udp::socket> SocketPtr;
  typedef std::shared_ptr<boost::asio::ip::udp::endpoint> EndpointPtr;
  typedef std::shared_ptr<std::vector<unsigned char>> BufferPtr;
  typedef std::shared_ptr<UdpRequest> RequestPtr;
  typedef std::unordered_map<uint64_t, RequestPtr> RequestMap;

  void DoSend(RequestPtr request);
  static void CloseSocket(SocketPtr socket);

  void StartRead();
  void HandleRead(SocketPtr socket,
                  BufferPtr read_buffer,
                  EndpointPtr sender_endpoint,
                  const boost::system::error_code &ec,
                  size_t bytes_transferred);
  void DispatchMessage(const std::string &data,
                       const Info &info,
                       uint64_t reply_to_id);
  void HandleTimeout(uint64_t request_id,
                     const boost::system::error_code &ec);

  boost::asio::io_service::strand strand_;
  SocketPtr socket_;
  BufferPtr read_buffer_;
  EndpointPtr sender_endpoint_;
  uint64_t next_request_id_;
  RequestMap outstanding_requests_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_UDP_TRANSPORT_H_
