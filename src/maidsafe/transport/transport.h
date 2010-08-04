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
*/

/*******************************************************************************
 * NOTE: This API is unlikely to have any breaking changes applied.  However,  *
 *       it should not be regarded as a final API until this notice is removed.*
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/thread/mutex.hpp>
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportconditions.h>
#include <maidsafe/transport/transportsignals.h>
#include <string>

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

namespace  fs = boost::filesystem;

namespace transport {

typedef boost::int64_t DataSize;

inline bool ValidIP(const IP &ip) {
  boost::system::error_code ec;
  boost::asio::ip::address::from_string(ip, ec);
  return ec == boost::system::errc::success;
}

inline bool ValidPort(const Port &port) {
  return ((5000 < port) && (port < 65535));
}

struct SocketPerformanceStats {
 public:
  virtual ~SocketPerformanceStats() {}
};

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
  // Used to create a new socket and send data.  It assumes a
  // response is expected if timeout is > 0, and keeps the socket alive.
  // The result is signalled with the new socket ID the appropriate
  // TransportCondition.
  virtual SocketId Send(const TransportMessage &transport_message,
                        const IP &remote_ip,
                        const Port &remote_port,
                        const int &response_timeout) = 0;
  // Used to send a response to a request received on socket_id.
  virtual void SendResponse(const TransportMessage &transport_message,
                            const SocketId &socket_id) = 0;
  // Used to send a file in response to a request received on socket_id.
  virtual void SendFile(fs::path &path, const SocketId &socket_id) = 0;
  boost::shared_ptr<Signals> signals() { return signals_; }
  std::vector<Port> listening_ports() { return listening_ports_; }
 protected:
  Transport() : signals_(new Signals),
                listening_ports_(),
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
