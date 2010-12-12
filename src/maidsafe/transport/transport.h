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
 * NOTE: This header should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <maidsafe/transport/transportconditions.h>
#include <maidsafe/transport/transportsignals.h>
#include <vector>
#include <iostream>
#include <boost/concept_check.hpp>

#if MAIDSAFE_DHT_VERSION < 25
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

namespace transport {

typedef boost::asio::ip::address IP;
typedef boost::uint16_t Port;
typedef int ManagedEndpointId;
typedef boost::int32_t DataSize;
typedef boost::uint16_t SocketId;
struct Stats {
  IP peer_ip;
  Port peer_port;
  IP ip;
  Port port;
  boost::uint16_t ttl;
};  

struct Endpoint {
  Endpoint() : ip(ip), port(port) {}
  IP ip;
  Port port;
};

const DataSize kMaxTransportMessageSize = 67108864;

// Base class for all transport types.
class Transport {
 public:
  virtual ~Transport() {}
  /**
   * Enables the transport to accept incoming communication. Fails if already
   * listening or the requested endpoint is unavailable.
   * @param endpoint The endpoint to listen for messages on.
   * @return Success or an appropriate error code.
   */
  virtual TransportCondition StartListening(const Endpoint &endpoint) = 0;
  /**
   * Stops the transport from accepting incoming communication.
   */
  virtual void StopListening() = 0;
  /**
   * Sends the given message to the specified receiver. The result is signalled
   * by on_send_.
   * @param data The message data to transmit.
   * @param endpoint The data receiver's endpoint.
   * @param close Whether to close the established connection after send, if
   * applicable. Non-connection-oriented transports should ignore this.
   */
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    bool close) = 0;
  /**
   * Sends data that is being streamed from the given source.
   * @param data The input stream delivering data to send.
   * @param endpoint The data receiver's endpoint.
   */
  virtual void SendStream(const std::istream &data,
                          const Endpoint &endpoint) = 0;
  /**
   * Getter for the transport's signals.
   * @return A pointer to the signals object.
   */
  boost::shared_ptr<Signals> signals() { return signals_; }
  /**
   * Getter for the listening port.
   * @return The port number or 0 if not listening.
   */
  Port listening_port() const { return listening_port_; }
 protected:
  Transport() : signals_(new Signals), listening_port_(0) {}
  boost::shared_ptr<Signals> signals_;
  Port listening_port_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_H_
