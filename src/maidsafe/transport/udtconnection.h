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

#include <boost/asio/deadline_timer.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <maidsafe/transport/transport.h>
#include <maidsafe/transport/transport.pb.h>
#include "maidsafe/transport/udtutils.h"
#include "maidsafe/udt/udt.h"

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

struct UdtStats : public Info {
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

class UdtConnection : public boost::enable_shared_from_this<UdtConnection> {
 public:
  ~UdtConnection();
  // Send message on connected socket.  timeout_wait_for_response defines
  // timeout for receiving response in milliseconds.  If 0, no response is
  // expected and the socket is closed after sending message.  Internal sending
  // of message has its own timeout, so method may signal failure before
  // timeout_wait_for_response if sending times out.
  void Send(const std::string &data, const Timeout &timeout_wait_for_response);
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
  enum ConnectionType { kOutgoing, kAccepted, kManaged };
  UdtConnection(boost::shared_ptr<UdtTransport> transport,
                const Endpoint &endpoint,
                const ConnectionType &connection_type);
  UdtConnection(boost::shared_ptr<UdtTransport> transport,
                const SocketId &socket_id,
                const ConnectionType &connection_type);
  UdtConnection(const UdtConnection &other);
  UdtConnection& operator=(const UdtConnection &other);
  void Init();
  void SetDataSizeTimeout(const Timeout &timeout);
  void SetDataContentTimeout(const DataSize &data_size, const Timeout &timeout);
  // General method for sending data once connection made.
  void SendData(const Timeout &timeout_wait_for_response);
  // General method for receiving data
  void ReceiveData(const Timeout &timeout);
  // Send or receive contents of a buffer
  TransportCondition MoveData(bool sending,
                              const DataSize &data_size,
                              char *data);

  boost::shared_ptr<UdtTransport> transport_;
  SocketId socket_id_;
  Endpoint endpoint_;
  ConnectionType connection_type_;
  boost::shared_ptr<addrinfo const> peer_;
  std::string data_;
  boost::shared_ptr<boost::asio::deadline_timer> timeout_timer_;
  boost::shared_ptr<boost::asio::deadline_timer> stall_timer_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_UDTCONNECTION_H_

