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
 * NOTE: This API is unlikely to have any breaking changes applied.  However,  *
 *       it should not be regarded as a final API until this notice is removed.*
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportconditions.h>
#include <maidsafe/transport/transportsignals.h>
#include <maidsafe/transport/transportutils.h>
#include <vector>

#if MAIDSAFE_DHT_VERSION < 25
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

namespace  fs = boost::filesystem;

namespace transport {

class TransportMessage;

class Transport {
  // Base class for all transport types.
 public:
  virtual ~Transport() {}
  // Tries to open a listening socket on the suggested IP, Port.  If port == 0,
  // a random port is chosen.  On success, the actual local port opened is
  // returned and the port is added to listening_ports_ vector.  On failure,
  // 0 is returned and if transport_condition != NULL, it is set appropriately.
  virtual Port StartListening(const IP &ip,
                              const Port &try_port,
                              TransportCondition *transport_condition) = 0;
  // Stops listening on the chosen port and removes the port from
  // listening_ports_ vector.
  virtual bool StopListening(const Port &port) = 0;
  // Stops all listening ports and clears listening_ports_ vector.
  virtual bool StopAllListening() = 0;
  // Used to create a new socket for sending data.
  virtual SocketId PrepareToSend(const IP &remote_ip,
                                 const Port &remote_port,
                                 const IP &rendezvous_ip,
                                 const Port &rendezvous_port) = 0;
  // Used to send transport_message on socket_id.  If the message is a request,
  // the socket is kept alive awaiting a response for timeout_wait_for_response
  // milliseconds, after which it is closed.  Internal sending of message has
  // its own timeout, so method may signal failure before
  // timeout_wait_for_response milliseconds have passed if sending times out.
  // If the message is a response, the socket is closed immediately after
  // sending.  Result is signalled by on_send_.
  virtual void Send(const TransportMessage &transport_message,
                    const SocketId &socket_id,
                    const boost::uint32_t &timeout_wait_for_response) = 0;
  // Used to send a file in response to a request received on socket_id.
  virtual void SendFile(const fs::path &path, const SocketId &socket_id) = 0;
  boost::shared_ptr<Signals> signals() { return signals_; }
  std::vector<Port> listening_ports() { return listening_ports_; }
 protected:
  Transport() : signals_(new Signals), listening_ports_(),
                listening_ports_mutex_() {}
  boost::shared_ptr<Signals> signals_;
  std::vector<Port> listening_ports_;
  boost::mutex listening_ports_mutex_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_H_
