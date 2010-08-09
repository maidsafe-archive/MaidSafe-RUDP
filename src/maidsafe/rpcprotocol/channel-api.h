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

#ifndef MAIDSAFE_RPCPROTOCOL_CHANNEL_API_H_
#define MAIDSAFE_RPCPROTOCOL_CHANNEL_API_H_

#include <string>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <google/protobuf/service.h>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/maidsafe-dht_config.h"

#if MAIDSAFE_DHT_VERSION < 23
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace transport {
class UdtConnection;
class UdtTransport;
}  // namespace transport


namespace rpcprotocol {

class ControllerImpl;
class ChannelImpl;
class ChannelManager;

/**
* @class Controller
* Implementation of Google Protocol Buffers RpcController interface.  An
* object of this class is used for a single method call. This
* implementation has as members the seconds after which the call times out, the
* RTT (round trip time) to the peer it is communicating, and the id of the
* request(call).
*/

class Controller : public google::protobuf::RpcController {
 public:
  Controller();
  ~Controller();
  void SetFailed(const std::string &failure);
  void Reset();
  bool Failed() const;
  std::string ErrorText() const;
  void StartCancel();
  bool IsCanceled() const;
  void NotifyOnCancel(google::protobuf::Closure*);
  /**
  * Returns time between sending and receiving the RPC request/response.
  * @return time in milliseconds
  */
  boost::uint64_t Duration() const;
  /**
  * Set the time the RPC request was sent.
  */
  void StartRpcTimer();
  /**
  * Set the time the RPC response was received.
  */
  void StopRpcTimer();
  /**
  * Sets the timeout for the RPC request.
  * @param id timeout time in seconds.
  */
  void set_timeout(const boost::uint32_t &seconds);
  /**
  * Returns the timeout for the RPC request.
  * @return the timeout time in milliseconds.
  */
  boost::uint64_t timeout() const;
  /**
  * Sets the RTT of the communication between the client who is requesting
  * a remote procedure and the server that is executing the procedure.
  * @param rtt RTT in milliseconds
  */
  void set_rtt(const float &rtt);
  /**
  * @return The RTT in milliseconds
  */
  float rtt() const;
  /**
  * Sets the ID of the RPC request.
  * @param id Identifier of the rpc request/response
  */
  void set_rpc_id(const RpcId &rpc_id);
  /**
  * @return the identifier of the rpc request/response
  */
  RpcId rpc_id() const;
  /**
  * Sets the ID of the transport socket being used by the RPC.
  * @param id Identifier of the transport socket
  */
  void set_socket_id(const SocketId &socket_id);
  /**
  * @return the identifier of the transport socket
  */
  SocketId socket_id() const;
  /**
  * Set the name of the method being called remotely.
  * @param method The name of the method being called remotely.
  */
  void set_method(const std::string &method);
  /**
  * Get the name of the method being called remotely, if stored.
  */
  std::string method() const;
  /**
  * Set the UDT transport being used for the operation.
  * @param udt_transport The transport used.
  */
  void set_udt_transport(
      boost::shared_ptr<transport::UdtTransport> udt_transport);
  /**
  * Get the UDT transport being used, if not NULL.
  */
  boost::shared_ptr<transport::UdtTransport> udt_transport() const;
  /**
  * Set the UDT connection being used for the operation.
  * @param udt_connection The connection used.
  */
  void set_udt_connection(
      boost::shared_ptr<transport::UdtConnection> udt_connection);
  /**
  * Get the UDT connection being used, if not NULL.
  */
  boost::shared_ptr<transport::UdtConnection> udt_connection() const;
 private:
  boost::shared_ptr<ControllerImpl> controller_pimpl_;
};

/**
* @class Controller
* Implementation of Google Protocol Buffers RpcChannel interface.
*/
class Channel : public google::protobuf::RpcChannel {
 public:
  /**
  * Constructor. Used for the server that is going to receive RPC's of a service
  * through this object.
  * @param channelmanager Pointer to a ChannelManager object
  * @param transport Pointer to a Transport object
  */
  Channel(boost::shared_ptr<ChannelManager> channel_manager,
          boost::shared_ptr<transport::UdtTransport> udt_transport);
  /**
  * Constructor. Used for the client that is going to send an RPC.
  * @param channelmanager Pointer to a ChannelManager object
  * @param transport Pointer to a Transport object
  * @param remote_ip remote ip of the endpoint that is going to receive the RPC
  * @param remote_port remote port of the endpoint that is going to receive
  * the RPC
  * @param local_ip local ip of the endpoint that is going to receive the RPC
  * @param local_port local port of the endpoint that is going to receive
  * the RPC
  */
  Channel(boost::shared_ptr<ChannelManager> channel_manager,
          const IP &remote_ip, const Port &remote_port,
          const IP &local_ip, const Port &local_port,
          const IP &rendezvous_ip, const Port &rendezvous_port);
  ~Channel();
  /**
  * Implementation of virtual method of the interface.
  */
  void CallMethod(const google::protobuf::MethodDescriptor *method,
                  google::protobuf::RpcController *rpc_controller,
                  const google::protobuf::Message *request,
                  google::protobuf::Message *response,
                  google::protobuf::Closure *done);
  /**
  * Sets the service for which it is going to receive RPC's requests.
  * @param service pointer to a Service object (implemenation of the server)
  */
  void SetService(google::protobuf::Service *service);
  /**
  * Handles the request for a RPC of the service registered.
  * @param rpc_message message containg the request of the RPC
  * @param connection_id id of the connection from which it received the request
  * message
  * @param rtt round trip time to the peer from which it received the request
  */
  void HandleRequest(const rpcprotocol::RpcMessage &rpc_message,
                     const SocketId &socket_id, const float &rtt);
 private:
  boost::shared_ptr<ChannelImpl> pimpl_;
};

}  // namespace rpcprotocol

#endif  // MAIDSAFE_RPCPROTOCOL_CHANNEL_API_H_
