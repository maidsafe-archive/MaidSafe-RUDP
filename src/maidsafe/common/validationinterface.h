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
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_COMMON_VALIDATIONINTERFACE_H_
#define MAIDSAFE_COMMON_VALIDATIONINTERFACE_H_

#include <string>

namespace maidsafe {

namespace protobuf { class SignedValue; }

class SignedValue {
 public:
  SignedValue();
  SignedValue(const protobuf::SignedValue &signed_value);
  SignedValue(const std::string &value, const std::string &signature);
  bool FromProtobuf(const protobuf::SignedValue &signed_value);
  protobuf::SignedValue ToProtobuf() const;
  std::string value() const;
  std::string signature() const;
 private:
  std::string value_;
  std::string signature_;
};


/**
 * Base class used to secure values and messages with a private key.  Method
 * virtual int Secure() should be provided and should return 0 for success, and
 * any other value for failure.
 */
class Securifier {
 public:
  /**
   * Constructor
   * @param id ID of Securifier
   * @param public_key Public key to be used by recipient to validate the data
   * @param public_key_validation Validation data to be used by recipient to
   * validate the public key
   * @param private_key Private key used to secure the data
   */
  Securifier(const std::string &id,
             const std::string &public_key,
             const std::string &public_key_validation,
             const std::string &private_key);
  /**
   * Destructor
   */
  virtual ~Securifier();
  /**
   * Sets the data to be secured by sender
   * @param kademlia_key kademlia key under which to store/delete/update
   * @param kademlia_value kademlia value to be handled
   * @param kademlia_updated_value kademlia value to replace old value if
   * applicable (can be empty for Store or Delete operations)
   * @param recipient_id ID of recipient's Validator
   */
  void SetData(const std::string &kademlia_key,
               const std::string &kademlia_value,
               const std::string &kademlia_updated_value,
               const std::string &recipient_id);
  /**
   * Signs the kademlia_value_ using the private_key
   * @return the signature of kademlia_value_
   */
  virtual std::string SignValue() const;
  /**
   * Signs the kademlia_updated_value_ using the private_key
   * @return the signature of kademlia_updated_value_
   */
  virtual std::string SignUpdatedValue() const;
  /**
   * Signs the message
   * @param secured_message Pointer to message which takes the result of the
   * securing process
   * @return an error code - 0 indicates success, anything else failure
   */
  virtual std::string SignMessage(const std::string &message) = 0;
 protected:
  const std::string kId_, kPublicKey_, kPublicKeyValidation_, kPrivateKey_;
  std::string kademlia_key_, kademlia_value_, kademlia_updated_value_;
  std::string recipient_id_;
};


/**
 * Base class used to validate secured values and messages.  Method
 * virtual bool Validate() should be provided and should return true for success
 */
class Validator {
 public:
  /**
   * Constructor
   * @param id ID of Validator
   */
  explicit Validator(const std::string &id);
  /**
   * Destructor
   */
  virtual ~Validator();
  /**
   * Validates the data secured by sender
   * @param sender_id ID of the message sender's Securifier
   * @param message_signature signature of message to be validated with the
   * public key
   * @param public_key used to validate signature of the message
   * @param public_key_validation object to allow validation of public key
   * @param kademlia_key kademlia key under which to store/delete/update
   * @return true if all tested data is valid, else false
   */
  virtual bool Validate(const std::string &sender_id,
                        const std::string &message_signature,
                        const std::string &public_key,
                        const std::string &public_key_validation,
                        const std::string &kademlia_key) = 0;
 protected:
  const std::string kId_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_VALIDATIONINTERFACE_H_
