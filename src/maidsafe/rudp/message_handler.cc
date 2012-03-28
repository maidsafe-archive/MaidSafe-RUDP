/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#include "maidsafe/transport/message_handler.h"
#include "boost/lexical_cast.hpp"
#include "maidsafe/transport/log.h"
#include "maidsafe/transport/transport_pb.h"

namespace maidsafe {

namespace transport {

void MessageHandler::OnMessageReceived(const std::string &request,
                                       const Info &info,
                                       std::string *response,
                                       Timeout *timeout) {
  if (request.empty())
    return;
  SecurityType security_type = request.at(0);
  std::string encrypted_message(request.substr(1));
  std::string decrypted_message;

  if (security_type != kNone) {
    if (!private_key_) {
      DLOG(WARNING) << "Failed to decrypt: encrypt_aes_seed is empty.";
      return;
    }

    if (security_type & kAsymmetricEncrypt) {
      asymm::Decrypt(encrypted_message, *private_key_, &decrypted_message);
      if (decrypted_message.empty()) {
        DLOG(WARNING) << "Failed to decrypt: encrypt_aes_seed is empty.";
        return;
      }
    }
  } else {
    decrypted_message = encrypted_message;
  }

  protobuf::WrapperMessage wrapper;
  if (wrapper.ParseFromString(decrypted_message) && wrapper.IsInitialized()) {
    return ProcessSerialisedMessage(wrapper.msg_type(), wrapper.payload(),
                                    security_type, wrapper.message_signature(),
                                    info, response, timeout);
  }
}

void MessageHandler::OnError(const TransportCondition &transport_condition,
                             const Endpoint &remote_endpoint) {
  (*on_error_)(transport_condition, remote_endpoint);
}

void MessageHandler::ProcessSerialisedMessage(
    const int &/*message_type*/,
    const std::string &/*payload*/,
    const SecurityType &/*security_type*/,
    const std::string &/*message_signature*/,
    const Info & /*info*/,
    std::string* /*message_response*/,
    Timeout* /*timeout*/) {}

std::string MessageHandler::MakeSerialisedWrapperMessage(
    const int &message_type,
    const std::string &payload,
    SecurityType security_type,
    const PublicKey &recipient_public_key) {
  protobuf::WrapperMessage wrapper_message;
  wrapper_message.set_msg_type(message_type);
  wrapper_message.set_payload(payload);
  std::string final_message(1, security_type);

  // No security.
  if (security_type == kNone) {
    final_message += wrapper_message.SerializeAsString();
  } else {
    // If we asked for security but provided no securifier, fail.
    if (security_type && !private_key_) {
      DLOG(ERROR) << "MakeSerialisedWrapperMessage - type " << message_type
                  << " - PrivateKey Validation Failed.";
      return "";
    }

    // Handle signing
    if (security_type & kSign) {
      std::string signature;
      if (asymm::Sign(boost::lexical_cast<std::string>(message_type) + payload,
                     *private_key_,
                     &signature) != kSuccess) {
       DLOG(ERROR) << "MakeSerialisedWrapperMessage - type " << message_type
                   << " - Sign Failed.";
       return "";
      }
      wrapper_message.set_message_signature(signature);
    }

    // Handle encryption
    if (security_type & kAsymmetricEncrypt) {
      if (!asymm::ValidateKey(recipient_public_key)) {
        DLOG(ERROR) << "MakeSerialisedWrapperMessage - type " << message_type
                    << " - PublicKey Validation Failed.";
        return "";
      }

      std::string encrypted_message;
      if (asymm::Encrypt(wrapper_message.SerializeAsString(),
                         recipient_public_key,
                         &encrypted_message) != kSuccess) {
        DLOG(ERROR) << "MakeSerialisedWrapperMessage - type " << message_type
                    << " - Encryption Failed.";
        return "";
      }
      final_message += encrypted_message;
    } else {
      final_message += wrapper_message.SerializeAsString();
    }
  }
  return final_message;
}

}  // namespace transport

}  // namespace maidsafe
