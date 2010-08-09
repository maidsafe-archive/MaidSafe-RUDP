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

#ifndef MAIDSAFE_RPCPROTOCOL_RPCSTRUCTS_H_
#define MAIDSAFE_RPCPROTOCOL_RPCSTRUCTS_H_

#include <google/protobuf/service.h>
#include <google/protobuf/message.h>

namespace rpcprotocol {

class Controller;

enum MessageStatus {
  kPending,
  kAwaitingRequestSend,
  kRequestSent,
  kAwaitingResponseSend,
  kResponseSent
};

struct PendingMessage {
  PendingMessage() : status(kPending), args(NULL), callback(NULL),
                     controller(), rpc_reponse(), data_sent(), timeout(),
                     local_transport(false) {}
  PendingMessage(const PendingMessage &pm)
      : status(pm.status), args(pm.args), callback(pm.callback),
        controller(pm.controller), rpc_reponse(pm.rpc_reponse),
        data_sent(pm.data_sent), timeout(pm.timeout),
        local_transport(pm.local_transport) {}
  PendingMessage &operator=(const PendingMessage &pm) {
    if (this != &pm) {
      status = pm.status;
      rpc_reponse = pm.rpc_reponse;
      data_sent = pm.data_sent;
      timeout = pm.timeout;
      local_transport = pm.local_transport;
      controller = pm.controller;
      delete args;
      args = pm.args;
    }
    return *this;
  }
  MessageStatus status;
  google::protobuf::Message *args;
  google::protobuf::Closure *callback;
  Controller *controller;
  boost::signals2::connection rpc_reponse;
  boost::signals2::connection data_sent;
  boost::signals2::connection timeout;
  bool local_transport;
};

}  // namespace rpcprotocol

#endif  // MAIDSAFE_RPCPROTOCOL_RPCSTRUCTS_H_
