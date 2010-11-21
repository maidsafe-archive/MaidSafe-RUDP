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

#ifndef MAIDSAFE_RPCPROTOCOL_CHANNELMANAGER_API_H_
#define MAIDSAFE_RPCPROTOCOL_CHANNELMANAGER_API_H_

#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <map>
#include <string>
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/base/utils.h"

#if MAIDSAFE_DHT_VERSION < 25
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif


namespace transport {
// class UdtTransport;
// class TcpTransport;
class Transport;
}  // namespace transport


namespace rpcprotocol {

typedef std::map<std::string, base::Stats<boost::uint64_t> > RpcStatsMap;

class Channel;
class ChannelManagerImpl;
class RpcMessage;
struct PendingMessage;

// Ensure that a one-to-one relationship is maintained between channelmanager &
// knode.
/**
* @class ChannelManager
* This object is responsible for handling the RPC messages that come in through
* the Transport object and handle them accordingly to their type: REQUEST or
* RESPONSE.  It also keeps all the pending requests of the RPCs sent and makes
* sure to call the response when the response arrives or the time set for
* timeout expires.
* Ensure that a one-to-one relationship is maintained between ChannelManager
* and KNode.
*/

// template <class T>
// boost::shared_ptr<Transport> CreateTransport() {
//   return  boost::shared_ptr<Transport>(new T);
// }
// 
// template <class T>
class ChannelManager {
 public:
  /**
  * Constructor
  */
  ChannelManager();
  /**
  * Constructor
  * @param transport Pointer to a Transport object
  */
//   explicit ChannelManager(
//       boost::shared_ptr<transport::UdtTransport> transport);
//   explicit ChannelManager(
//       boost::shared_ptr<transport::TcpTransport> transport);
     explicit ChannelManager(
       boost::shared_ptr<transport::Transport> transport_);
  ~ChannelManager();
  /**
  * Registers a channel and identifies it with the name of the RPC service that
  * uses that Channel to receive requests.
  * @param service_name name that identifies the channel
  * @param channel pointer to a Channel object
  */
  void RegisterChannel(const std::string &service_name, Channel *channel);
  /**
  * Removes a previously registered channel.
  * @param service_name name that identifies the channel
  */
  void UnRegisterChannel(const std::string &service_name);
  /**
  * Removes all the channels that have been registered.
  */
  void ClearChannels();
  /**
  * Clears the list of all RPC requests sent that are waiting for their response
  * and have not time out.
  */
  void ClearCallLaters();
  /**
  * Sets status as not stopped if the Transport object has been started.
  * @return 0 if success otherwise 1
  */
  int Start();
  /**
  * Sets status of the ChannelManager as stopped and clears pending requests
  * and registered channels.
  * @return 1 if success and 0 if the status when called was stopped.
  */
  int Stop();
  /**
  * Registeres the notifier to receive RPC messages with the Transport object
  * and the notifier to now when a message has been sent.
  * @return True if it succeeds in registering the notifiers, False otherwise
  */
  bool RegisterNotifiersToTransport();
  /**
  * Adds a new pending request after an RPC has been sent.
  * @param rpc_id id to identify the request
  * @param pending_request structure holding all the information of the request
  * @return True if pending request successfully added, False otherwise
  */
  bool AddPendingRequest(const SocketId &socket_id,
                         PendingMessage pending_request);
  /**
  * Removes a pending request from the list and calls the callback of the
  * request with status Cancelled.
  * @param rpc_id id of the request
  * @return True if success, False if status of the object is stopped or
  * no request was found for the id.
  */
  bool TriggerPendingRequest(const SocketId &socket_id);
  /**
  * Removes a pending request from the list. Doesn't run the callback. When the
  * response arrives, it will be silently dropped.
  * @param rpc_id id of the request
  * @return True if success, False if status of the object is stopped or
  * no request was found for the id.
  */
  bool DeletePendingRequest(const SocketId &socket_id);
  /**
  * Creates and adds the id of a Channel to a list that holds all the channels
  * using the objet.
  * @param id pointer where the id created is returned
  */
  void AddChannelId(boost::uint32_t *id);
  /**
  * Removes the id of a Channel registered with using the objet.
  * @param id pointer where the id created is returned
  */
  void RemoveChannelId(const boost::uint32_t &id);
  /**
  * Retrieve statistics about the duration of each RPC.
  * @return A map of RPC name and statistics pairs.
  */
  RpcStatsMap RpcTimings();
  /**
  * Remove all entries from the RPC timings map.
  */
  void ClearRpcTimings();
 private:
  boost::shared_ptr<ChannelManagerImpl> pimpl_;
  boost::shared_ptr<transport::Transport> transport_;
};

}  // namespace rpcprotocol

#endif  // MAIDSAFE_RPCPROTOCOL_CHANNELMANAGER_API_H_
