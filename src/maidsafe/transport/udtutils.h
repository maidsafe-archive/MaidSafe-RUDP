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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_UDTUTILS_H_
#define MAIDSAFE_TRANSPORT_UDTUTILS_H_

#include <boost/shared_ptr.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportconditions.h>
#include "maidsafe/udt/udt.h"


namespace transport {

namespace udtutils {

boost::shared_ptr<addrinfo const> SocketGetAddrinfo(char const *node,
                                                    char const *service,
                                                    addrinfo const &hints,
                                                    int *result);
boost::shared_ptr<addrinfo const> Next(
    boost::shared_ptr<addrinfo const> const &node);

TransportCondition GetNewSocket(
    const IP &ip,
    const Port &port,
    bool reuse_address,
    SocketId *udt_socket_id,
    boost::shared_ptr<addrinfo const> *address_info);

TransportCondition GetNewSocket(bool reuse_address,
                                SocketId *udt_socket_id,
                                boost::shared_ptr<addrinfo const> address_info);

TransportCondition Connect(const SocketId &udt_socket_id,
                           boost::shared_ptr<addrinfo const> peer);

TransportCondition SetSyncMode(const SocketId &udt_socket_id,
                               bool synchronous);

}  // namespace udtutils

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTUTILS_H_

