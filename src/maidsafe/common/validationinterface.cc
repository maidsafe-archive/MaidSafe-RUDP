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

#include <maidsafe/common/validation.pb.h>
#include <maidsafe/common/validationinterface.h>
#include "maidsafe/common/crypto.h"

namespace maidsafe {

SignedValue::SignedValue() : value_(), signature_() {}

SignedValue::SignedValue(const protobuf::SignedValue &signed_value)
    : value_(),
      signature_() {
  FromProtobuf(signed_value);
}

SignedValue::SignedValue(const std::string &value, const std::string &signature)
    : value_(value),
      signature_(signature) {}

bool SignedValue::FromProtobuf(const protobuf::SignedValue &signed_value) {
  if (signed_value.IsInitialized()) {
    value_ = signed_value.value();
    signature_ = signed_value.signature();
    return true;
  } else {
    return false;
  }
}

protobuf::SignedValue SignedValue::ToProtobuf() const {
  protobuf::SignedValue signed_value;
  signed_value.set_value(value_);
  signed_value.set_signature(signature_);
  return signed_value;
}

std::string SignedValue::value() const { return value_; }

std::string SignedValue::signature() const { return signature_; }


Signature::Signature()
    : signer_id_(),
      public_key_(),
      public_key_validation_(),
      signature_() {}

Signature::Signature(const protobuf::MessageSignature &message_signature)
    : signer_id_(),
      public_key_(),
      public_key_validation_(),
      signature_() {
  FromProtobuf(message_signature);
}

Signature::Signature(const std::string &signer_id,
                     const std::string &public_key,
                     const std::string &public_key_validation,
                     const std::string &signature)
    : signer_id_(signer_id),
      public_key_(public_key),
      public_key_validation_(public_key_validation),
      signature_(signature) {}

bool Signature::FromProtobuf(
    const protobuf::MessageSignature &message_signature) {
  if (message_signature.IsInitialized()) {
    signer_id_ = message_signature.signer_id();
    public_key_ = message_signature.public_key();
    public_key_validation_ = message_signature.public_key_validation();
    signature_ = message_signature.signature();
    return true;
  } else {
    return false;
  }
}

protobuf::MessageSignature Signature::ToProtobuf() const {
  protobuf::MessageSignature message_signature;
  message_signature.set_signer_id(signer_id_);
  message_signature.set_public_key(public_key_);
  message_signature.set_public_key_validation(public_key_validation_);
  message_signature.set_signature(signature_);
  return message_signature;
}

std::string Signature::signer_id() const { return signer_id_; }

std::string Signature::public_key() const { return public_key_; }

std::string Signature::public_key_validation() const {
  return public_key_validation_;
}

std::string Signature::signature() const { return signature_; }


Securifier::Securifier(const std::string &id,
                       const std::string &public_key,
                       const std::string &public_key_validation,
                       const std::string &private_key)
    : kId_(id),
      kPublicKey_(public_key),
      kPublicKeyValidation_(public_key_validation),
      kPrivateKey_(private_key) {}

Securifier::~Securifier() {}

void Securifier::SetData(const std::string &kademlia_key,
                         const std::string &kademlia_value,
                         const std::string &kademlia_updated_value,
                         const std::string &recipient_id) {
  kademlia_key_ = kademlia_key;
  kademlia_value_ = kademlia_value;
  kademlia_updated_value_ = kademlia_updated_value;
  recipient_id_ = recipient_id;
}

protobuf::SignedValue Securifier::Sign(bool updated_value) const {
  protobuf::SignedValue signed_value;
  if (kPrivateKey_.empty())
    return;
  signed_value.set_value(updated_value ? kademlia_updated_value_ :
                         kademlia_value_);
  crypto::Crypto co;
  signed_value.set_signature(co.AsymSign(
      updated_value ? kademlia_updated_value_ : kademlia_value_, "",
      kPrivateKey_, crypto::STRING_STRING));
}

protobuf::SignedValue Securifier::SignValue() const {
  return Sign(false);
}

protobuf::SignedValue Securifier::SignUpdatedValue() const {
  return Sign(true);
}


Validator::Validator(const std::string &id) : kId_(id) {}

Validator::~Validator() {}

}  // namespace maidsafe
