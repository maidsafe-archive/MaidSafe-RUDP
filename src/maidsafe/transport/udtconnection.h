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
#include <maidsafe/protobuf/transport_message.pb.h>
#include <maidsafe/transport/transport.h>
#include "maidsafe/transport/udtutils.h"
#include "maidsafe/udt/udt.h"


namespace  bs2 = boost::signals2;
namespace  fs = boost::filesystem;

namespace base {
class Threadpool;
}  // namespace base


namespace transport {

namespace test {
class UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataSize_Test;
class UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataContent_Test;
class UdtConnectionTest_FUNC_TRANS_UdtConnHandleTransportMessage_Test;
class UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataFull_Test;
}  // namespace test

class UdtTransport;

const int kDefaultSendTimeout(10000);
const int kDefaultReceiveTimeout(10000);

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
  UdtConnection(const IP &remote_ip,
                const Port &remote_port,
                const IP &rendezvous_ip,
                const Port &rendezvous_port);
  UdtConnection(const UdtConnection &other);
  UdtConnection& operator=(const UdtConnection &other);
  ~UdtConnection();
  void Send(const TransportMessage &transport_message,
            const int &response_timeout);
  boost::shared_ptr<Signals> signals() const { return signals_; }
  UdtSocketId udt_socket_id() const { return udt_socket_id_; }
  friend class UdtTransport;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataSize_Test;
  friend class
     test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataContent_Test;
  friend class
     test::UdtConnectionTest_FUNC_TRANS_UdtConnHandleTransportMessage_Test;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataFull_Test;
 private:
  UdtConnection(UdtTransport *udt_transport,
                const IP &remote_ip,
                const Port &remote_port,
                const IP &rendezvous_ip,
                const Port &rendezvous_port);
  UdtConnection(UdtTransport *udt_transport,
                const UdtSocketId &udt_socket_id);
  void Init();
  bool SetTimeout(const int &timeout, bool send);
  // Method to allow sending on a socket which is already connected to a peer.
  void SendResponse(const TransportMessage &transport_message);
  // General method for connecting then sending data
  void ConnectThenSend();
  // General method for sending data once connection made.  If
  // keep_alive_after_send is true, the socket switches to receive after sending
  // (where receive_timeout_ > 0) or is simply left open.
  void SendData(bool keep_alive_after_send);
  // Send the size of the pending message
  TransportCondition SendDataSize();
  // Send the content of the message.
  TransportCondition SendDataContent();
  // General method for receiving data
  void ReceiveData();
  // Receive the size of the forthcoming message
  DataSize ReceiveDataSize();
  // Receive the content of the message
  bool ReceiveDataContent(const DataSize &data_size);
  // Send or receive contents of a buffer
  TransportCondition MoveData(bool sending,
                              const DataSize &data_size,
                              char *data);
  bool HandleTransportMessage(const float &rtt);
  UdtTransport *udt_transport_;
  boost::shared_ptr<Signals> signals_;
  boost::shared_ptr<base::Threadpool> threadpool_;
  boost::shared_ptr<boost::thread> worker_;
  UdtSocketId udt_socket_id_;
  IP remote_ip_;
  Port remote_port_;
  IP rendezvous_ip_;
  Port rendezvous_port_;
  boost::shared_ptr<addrinfo const> peer_;
  TransportMessage transport_message_;
  int send_timeout_, receive_timeout_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTCONNECTION_H_

