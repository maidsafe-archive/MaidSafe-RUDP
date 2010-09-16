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

#ifndef MAIDSAFE_NAT_PMP_NATPMPCLIENTIMPL_H_
#define MAIDSAFE_NAT_PMP_NATPMPCLIENTIMPL_H_

#include <boost/asio.hpp>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>

#include <deque>
#include <utility>
#include <vector>

#include "maidsafe/nat-pmp/natpmpprotocol.h"

namespace natpmp {

typedef boost::function <void (
    boost::uint16_t protocol,
    boost::uint16_t private_port,
    boost::uint16_t public_port)> NatPmpMapPortSuccessCbType;

/**
  * Implements the underlying NAT-PMP client implementation.
  */
class NatPmpClientImpl {
 public:

/**
  * Constructor
  * @param ios The boost::asio::io_service object to use.
  */
  explicit NatPmpClientImpl(boost::asio::io_service *ios);

/**
  * Destructor
  */
  ~NatPmpClientImpl();

/**
  * Start the nat-pmp client.
  */
  void Start();

/**
  * Stops the nat-pmp client removing all mappings.
  */
  void Stop();

/**
  * Set the port map success callback.
  */
  void SetMapPortSuccessCallback(
      const NatPmpMapPortSuccessCbType &map_port_success_cb);

/**
  * Sends a mapping request by posting it to the
  * boost::asio::io_service object with the given protocol,
  * private port, public port and lifetime.
  * @param protocol
  * @param private_port
  * @param public_port
  * @param lifetime
  * @note thread-safe
  */
  void SendMappingRequest(boost::uint16_t protocol,
                          boost::uint16_t private_port,
                          boost::uint16_t public_port,
                          boost::uint32_t lifetime);

 private:

/**
  * Sends a mapping.
  */
  void DoSendMappingRequest(boost::uint16_t protocol,
                            boost::uint16_t private_port,
                            boost::uint16_t public_port,
                            boost::uint32_t lifetime);

/**
  * Sends a public address request to the gateway.
  */
  void SendPublicAddressRequest();

/**
  * Performs a public address request re-transmission.
  */
  void RetransmitPublicAdddressRequest(const boost::system::error_code & ec);

/**
  * Sends a request to the gateway.
  */
  void SendRequest(Protocol::MappingRequest & req);

/**
  * Sends any queued requests.
  */
  void SendQueuedRequests();

/**
  * Sends buf of size len to the gateway.
  */
  void Send(const char * buf, std::size_t len);

/**
  * Asynchronous send handler.
  */
  void HandleSend(const boost::system::error_code & ec, std::size_t);

/**
  * Asynchronous cannot handler.
  */
  void HandleConnect(const boost::system::error_code & ec);

/**
  * Asynchronous receive from handler.
  */
  void HandleReceiveFrom(const boost::system::error_code & ec,
                         std::size_t bytes);

/**
  * Asynchronous response handler.
  */
  void HandleResponse(const char * buf, std::size_t);

/**
  * The ip address of the gateway.
  */
  boost::asio::ip::address m_gateway_address_;

/**
  * The ip address on the WAN side of the gateway.
  */
  boost::asio::ip::address m_public_ip_address_;

 protected:

/**
  * A reference to the boost::asio::io_service.
  */
  boost::asio::io_service *io_service_;

/**
  * The request retry timer.
  */
  boost::asio::deadline_timer retry_timer_;

/**
  * The udp socket.
  */
  boost::shared_ptr<boost::asio::ip::udp::socket> socket_;

/**
  * The gateway endpoint.
  */
  boost::asio::ip::udp::endpoint endpoint_;

/**
  * The non-parallel public ip address request.
  */
  Protocol::MappingRequest public_ip_request_;

/**
  * The parallel reuqest queue.
  */
  std::deque<Protocol::MappingRequest> request_queue_;

/**
  * The receive buffer length.
  */
  enum { kReceiveBufferLength = 512 };

/**
  * The receive buffer.
  */
  char data_[kReceiveBufferLength];

/**
  * Mappings that we are responsible for.
  */
  std::vector< std::pair<Protocol::MappingRequest, Protocol::MappingResponse> >
      mappings_;

/**
  * Map port success callback.
  */
  NatPmpMapPortSuccessCbType nat_pmp_map_port_success_cb_;
};

}  // namespace natpmp

#endif  // MAIDSAFE_NAT_PMP_NATPMPCLIENTIMPL_H_
