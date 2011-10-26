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

#ifndef MAIDSAFE_TRANSPORT_RPCS_H_
#define MAIDSAFE_TRANSPORT_RPCS_H_

#include <vector>

#include "boost/function.hpp"

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4127 4244 4267)
#endif
#include "maidsafe/transport/transport.pb.h"
#ifdef __MSVC__
#  pragma warning(pop)
#endif

namespace maidsafe {

namespace transport {

class Transport;
struct Endpoint;
struct TransportDetails;

class Contact;

class Rpcs {
  typedef boost::function<void(int, TransportDetails)> NatResultFunctor;

 public:
  void NatDetection(const std::vector<Contact> &candidates,
                    bool full, /* not required */
                    NatResultFunctor nrf);
  void NatDetection(const std::vector<Endpoint> &candidates,
                    std::shared_ptr<Transport> listening_transport,
                    bool full, /* not required */
                    NatResultFunctor nrf);
  void Ping(const Contact &peer, RpcPingFunctor callback);

  // Rendezvous nat detection
  // Investigates 
  // 1) whether the peer is directly connected
  // 2) if not directly connected act as rendezvous to check whether 
  // node is full con, port restricted or none.
  void NatDetection(const protobuf::NatDetectionRequest &request,
                             const Contact &peer,
                             protobuf::NatDetectionResponse *response);
  // Proxy nat detection
  // Tries full con nat first, on failure notifies bootstrap and tries 
  // port restricted
  void NatDetection(const protobuf::ProxyConnectRequest &request,
                              Contact bootstrap,
                              protobuf::ProxyConnectResponse *response);
 private:
  // Proxy & originator
  void RendezvousConnect(Contact &peer); 
  // At joining node
  void NatDetectionCallback(const protobuf::NatDetectionResponse &response,
                            const std::vector<Endpoint> &candidates,
                            NatResultFunctor nrf,
                            int index);
  // At bootstrap
  bool DirectlyConnected(Contact &requester, Contact &peer);
  void ProxyConnect(Contact &originator, Contact &rendezvous, bool full,
                    ProxyConnectCallback pccb);
  void RendezvouzRequest(Contact &originator, Contact &proxy);
  
  // At Proxy
  bool FullConNatDetection(Contact &originator);
  bool PortRestrictedNatDetection(Contact &originator);
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_RPCS_H_
