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

#ifndef MAIDSAFE_TRANSPORT_UDTCONNECTION_H_
#define MAIDSAFE_TRANSPORT_UDTCONNECTION_H_

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals2.hpp>
#include <boost/thread/thread.hpp>
#include <maidsafe/transport/transport.h>
#include "maidsafe/transport/udtutils.h"
#include "maidsafe/udt/udt.h"


namespace  bs2 = boost::signals2;
namespace  fs = boost::filesystem;

namespace base {
class Threadpool;
}  // namespace base


namespace transport {

class TransportUDT;
class TransportMessage;

const int kDefaultSendTimeout(10000);  // milliseconds

struct UdtStats : public SocketPerformanceStats {
 public:
  enum UdtSocketType { kSend, kReceive };
  UdtStats(const UdtSocketId &udt_socket_id,
           const UdtSocketType &udt_socket_type)
      : udt_socket_id_(udt_socket_id),
        udt_socket_type_(udt_socket_type),
        performance_monitor_() {}
  ~UdtStats() {}
  UdtSocketId udt_socket_id_;
  UdtSocketType udt_socket_type_;
  UDT::TRACEINFO performance_monitor_;
};

class UdtConnection {
 public:
  UdtConnection();
  explicit UdtConnection(TransportUDT *transport_udt);
  ~UdtConnection();
  SocketId Send(const TransportMessage &transport_message,
                const IP &remote_ip,
                const Port &remote_port,
                const int &response_timeout);
  void SendResponse(const TransportMessage &transport_message,
                    const SocketId &socket_id);
  boost::shared_ptr<Signals> signals() { return signals_; }
  friend class TransportUDT;
 private:
  SocketId PrepareToSend(const TransportMessage &transport_message,
                         const IP &remote_ip,
                         const Port &remote_port);
  // General method for connecting then sending data
  void ConnectThenSend(const TransportMessage &transport_message,
                       const UdtSocketId &udt_socket_id,
                       const int &send_timeout,
                       const int &receive_timeout,
                       boost::shared_ptr<addrinfo const> peer);
  // General method for sending data once connection made.  Unlike public Send,
  // the socket is only closed iff receive_timeout == 0.  For receive_timeout >
  // 0, the socket switches to receive after sending.  For receive_timeout < 0,
  // the socket is simply left open.
  void SendData(const TransportMessage &transport_message,
                const UdtSocketId &udt_socket_id,
                const int &send_timeout,
                const int &receive_timeout);
  // Send the size of the pending message
  TransportCondition SendDataSize(const TransportMessage &transport_message,
                                  const UdtSocketId &udt_socket_id);
  // Send the content of the message
  TransportCondition SendDataContent(const TransportMessage &transport_message,
                                     const UdtSocketId &udt_socket_id);
  // General method for receiving data
  void ReceiveData(const UdtSocketId &udt_socket_id,
                   const int &receive_timeout);
  // Receive the size of the forthcoming message
  DataSize ReceiveDataSize(const UdtSocketId &udt_socket_id);
  // Receive the content of the message
  bool ReceiveDataContent(const UdtSocketId &udt_socket_id,
                          const DataSize &data_size,
                          TransportMessage *transport_message);
  bool HandleTransportMessage(const TransportMessage &transport_message,
                              const UdtSocketId &udt_socket_id,
                              const float &rtt);
  TransportUDT *transport_udt_;
  boost::shared_ptr<Signals> signals_;
  boost::shared_ptr<boost::thread> send_worker_, receive_worker_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTCONNECTION_H_

