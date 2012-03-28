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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_
#define MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_

#include <unordered_map>
#include "boost/asio/buffer.hpp"
#include "boost/asio/ip/udp.hpp"
#include "boost/cstdint.hpp"
#include "maidsafe/transport/transport.h"

namespace maidsafe {

namespace transport {

class RudpAcceptor;
class RudpSocket;

class RudpDispatcher {
 public:
  RudpDispatcher();

  // Get the one-and-only acceptor.
  RudpAcceptor *GetAcceptor() const;

  // Set the one-and-only acceptor.
  void SetAcceptor(RudpAcceptor *acceptor);

  // Add a socket. Returns a new unique id for the socket.
  boost::uint32_t AddSocket(RudpSocket *socket);

  // Remove the socket corresponding to the given id.
  void RemoveSocket(boost::uint32_t id);

  // Handle a new packet by dispatching to the appropriate socket or acceptor.
  void HandleReceiveFrom(const boost::asio::const_buffer &data,
                         const boost::asio::ip::udp::endpoint &endpoint);

 private:
  // Disallow copying and assignment.
  RudpDispatcher(const RudpDispatcher&);
  RudpDispatcher &operator=(const RudpDispatcher&);

  // The one-and-only acceptor.
  RudpAcceptor* acceptor_;

  // Map of destination socket id to corresponding socket object.
  typedef std::unordered_map<boost::uint32_t, RudpSocket*> SocketMap;
  SocketMap sockets_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RUDP_DISPATCHER_H_
