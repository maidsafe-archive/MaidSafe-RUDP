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
class UdtConnectionTest_BEH_TRANS_UdtMoveDataTimeout_Test;
class UdtConnectionTest_FUNC_TRANS_UdtConnHandleTransportMessage_Test;
class UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataFull_Test;
class UdtConnectionTest_BEH_TRANS_UdtConnBigMessage_Test;
}  // namespace test

class UdtTransport;

const boost::uint32_t kDefaultInitialTimeout(rpcprotocol::kRpcTimeout);
const boost::uint32_t kDynamicTimeout(-1);
const boost::uint32_t kMinTimeout(500);
const float kTimeoutFactor(0.01);
const boost::uint32_t kStallTimeout(3000);

struct UdtStats : public SocketPerformanceStats {
 public:
  enum UdtSocketType { kSend, kReceive };
  UdtStats(const SocketId &socket_id,
           const UdtSocketType &udt_socket_type)
      : socket_id_(socket_id),
        udt_socket_type_(udt_socket_type),
        performance_monitor_() {}
  ~UdtStats() {}
  SocketId socket_id_;
  UdtSocketType udt_socket_type_;
  UDT::TRACEINFO performance_monitor_;
};

class UdtConnection {
 public:
  UdtConnection(const IP &ip, const Port &port,
                const IP &rendezvous_ip, const Port &rendezvous_port);
  UdtConnection(const UdtConnection &other);
  UdtConnection& operator=(const UdtConnection &other);
  ~UdtConnection();
  // Send message on connected socket.  If message is a request, then
  // timeout_wait_for_response defines timeout for receiving response in
  // milliseconds.  If 0, no response is expected and the socket is closed
  // after sending message.  Internal sending of message has its own timeout, so
  // method may signal failure before timeout_wait_for_response if sending
  // times out.
  void Send(const TransportMessage &transport_message,
            const boost::uint32_t &timeout_wait_for_response);
  boost::shared_ptr<Signals> signals() const { return signals_; }
  SocketId socket_id() const { return socket_id_; }
  friend class UdtTransport;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataSize_Test;
  friend class
     test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataContent_Test;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtMoveDataTimeout_Test;
  friend class
     test::UdtConnectionTest_FUNC_TRANS_UdtConnHandleTransportMessage_Test;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtConnSendRecvDataFull_Test;
  friend class test::UdtConnectionTest_BEH_TRANS_UdtConnBigMessage_Test;
 private:
  enum ActionAfterSend { kClose, kKeepAlive, kReceive};
  UdtConnection(UdtTransport *transport,
                const IP &ip,
                const Port &port,
                const IP &rendezvous_ip,
                const Port &rendezvous_port);
  UdtConnection(UdtTransport *transport,
                const SocketId &socket_id);
  void Init();
  bool SetDataSizeSendTimeout();
  bool SetDataSizeReceiveTimeout(const boost::uint32_t &timeout);
  bool SetDataContentSendTimeout();
  bool SetDataContentReceiveTimeout(const DataSize &data_size,
                                    const boost::uint32_t &timeout);
  bool SetTimeout(const boost::uint32_t &timeout, bool send);
  TransportCondition CheckMessage(bool *is_request);
  // General method for sending data once connection made.
  void SendData(const ActionAfterSend &action_after_send,
                const boost::uint32_t &timeout_wait_for_response);
  // Send the size of the pending message
  TransportCondition SendDataSize();
  // Send the content of the message.
  TransportCondition SendDataContent();
  // General method for receiving data
  void ReceiveData(const boost::uint32_t &timeout);
  // Receive the size of the forthcoming message
  DataSize ReceiveDataSize(const boost::uint32_t &timeout);
  // Receive the content of the message
  bool ReceiveDataContent(const DataSize &data_size,
                          const boost::uint32_t &timeout);
  // Send or receive contents of a buffer
  TransportCondition MoveData(bool sending,
                              const DataSize &data_size,
                              char *data);
  bool HandleTransportMessage(const float &rtt);

  UdtTransport *transport_;
  boost::shared_ptr<Signals> signals_;
  boost::shared_ptr<base::Threadpool> threadpool_;
  boost::shared_ptr<boost::thread> worker_;
  SocketId socket_id_;
  IP ip_;
  Port port_;
  IP rendezvous_ip_;
  Port rendezvous_port_;
  boost::shared_ptr<addrinfo const> peer_;
  TransportMessage transport_message_;
  boost::uint32_t send_timeout_, receive_timeout_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTCONNECTION_H_

