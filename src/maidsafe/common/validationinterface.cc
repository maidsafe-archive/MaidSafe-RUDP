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

namespace maidsafe {

SignedValue::SignedValue(const protobuf::SignedValue &signed_value)
    : value_(),
      signature_() {
  FromProtobuf(signed_value);
}

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

Signature::Signature(const protobuf::Signature &signature)
    : signer_id_(),
      public_key_(),
      public_key_signature_(),
      request_signature_() {
  FromProtobuf(signature);
}

bool Signature::FromProtobuf(const protobuf::Signature &signature) {
  if (signature.IsInitialized()) {
    signer_id_ = signature.signer_id();
    public_key_ = signature.public_key();
    public_key_signature_ = signature.public_key_signature();
    request_signature_ = signature.request_signature();
    return true;
  } else {
    return false;
  }
}

protobuf::Signature Signature::ToProtobuf() const {
  protobuf::Signature signature;
  signature.set_signer_id(signer_id_);
  signature.set_public_key(public_key_);
  signature.set_public_key_signature(public_key_signature_);
  signature.set_request_signature(request_signature_);
  return signature;
}

}  // namespace maidsafe
