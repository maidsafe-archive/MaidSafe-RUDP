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

#ifndef MAIDSAFE_TRANSPORT_MESSAGE_HANDLER_H_
#define MAIDSAFE_TRANSPORT_MESSAGE_HANDLER_H_

#include <memory>
#include <string>

#include "boost/signals2/signal.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/transport/transport.h"
#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif


namespace bs2 = boost::signals2;
namespace Asym = maidsafe::rsa;
typedef std::shared_ptr<maidsafe::rsa::PrivateKey> PrivateKeyPtr;
typedef maidsafe::rsa::PublicKey PublicKey;

namespace maidsafe {

typedef char SecurityType;
const SecurityType kNone(0x0);
const SecurityType kSign(0x1);
const SecurityType kSignWithParameters(0x2);
const SecurityType kAsymmetricEncrypt(0x4);
const SecurityType kSignAndAsymEncrypt(0x5);

namespace transport {

enum MessageType {
  kManagedEndpointMessage = 1,
  kNatDetectionRequest,
  kNatDetectionResponse,
  kProxyConnectRequest,
  kProxyConnectResponse,
  kForwardRendezvousRequest,
  kForwardRendezvousResponse,
  kRendezvousRequest,
  kRendezvousAcknowledgement
};

namespace protobuf {
class Endpoint;
class WrapperMessage;
}  // namespace protobuf

namespace test {
class TransportMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
class RudpMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
}  // namespace test

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(1000);

class MessageHandler {
 public:
  typedef std::shared_ptr<bs2::signal<void(const TransportCondition&,
                                           const Endpoint&)>>
          ErrorSigPtr;

  explicit MessageHandler(PrivateKeyPtr private_key)
    : private_key_(private_key),
      on_error_(new ErrorSigPtr::element_type) {}
  virtual ~MessageHandler() {}

  void OnMessageReceived(const std::string &request,
                         const Info &info,
                         std::string *response,
                         Timeout *timeout);
  void OnError(const TransportCondition &transport_condition,
               const Endpoint &remote_endpoint);


  ErrorSigPtr on_error() { return on_error_; }

 protected:
  virtual void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const SecurityType &security_type,
                                        const std::string &message_signature,
                                        const Info &info,
                                        std::string *message_response,
                                        Timeout *timeout);
  std::string MakeSerialisedWrapperMessage(
      const int &message_type,
      const std::string &payload,
      SecurityType security_type,
      const PublicKey &recipient_public_key);
  PrivateKeyPtr private_key_;

 private:
  friend class test::TransportMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;  // NOLINT
  friend class test::RudpMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;  // NOLINT
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);

  ErrorSigPtr on_error_;
};

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_MESSAGE_HANDLER_H_
