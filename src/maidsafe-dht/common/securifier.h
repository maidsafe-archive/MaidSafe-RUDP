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

#ifndef MAIDSAFE_DHT_COMMON_SECURIFIER_H_
#define MAIDSAFE_DHT_COMMON_SECURIFIER_H_

#include <string>
#include <vector>
#include "boost/function.hpp"

namespace maidsafe {

typedef boost::function<void(const std::string&, const std::string)>
    GetPublicKeyAndValidationCallback;

/** Base class used to cryptographically secure and validate values and
 *  messages. */
class Securifier {
 public:

  /** Constructor.
   *  @param[in] id ID of Securifier.
   *  @param[in] signing_private_key Private key used to sign the data.
   *  @param[in] asymmetric_decryption_private_key Public key used to
   *             asymmetrically decrypt the data. */
  Securifier(const std::string &id,
             const std::string &signing_private_key,
             const std::string &asymmetric_decryption_private_key);

  /** Destructor. */
  virtual ~Securifier();

  /** Setter.
   *  @param[in] recipient_public_key Public key used to asymmetrically encrypt
   *             data. */
  void set_recipient_public_key(const std::string &recipient_public_key);

  /** Adds data which can be subsequently used in the signing or encrypting.
   *  @param[in] parameters data to be used during signing or encrypting.  It is
   *             appended to class member parameters_. */
  void AddParameters(const std::vector<std::string> &parameters);

  /** Clears parameters_ variable. */
  void ClearParameters();

  /** @return class member parameters_. */
  std::vector<std::string> parameters() const;

  /** Signs the value using kSigningPrivateKey_.
   *  @param[in] value value to be signed.
   *  @return signature. */
  virtual std::string Sign(const std::string &value) const;

  /** Signs the value using kSigningPrivateKey_, but may incorporate data from
   *  parameters_ in the signing process.
   *  @param[in] value value to be signed.
   *  @return signature. */
  virtual std::string SignWithParameters(const std::string &value) const;

  /** Asymmetrically encrypts the value using recipient_public_key_.
   *  @param[in] value value to be encrypted.
   *  @return encrypted value. */
  virtual std::string AsymmetricEncrypt(const std::string &value) const;

  /** Retrieve the public key and the public key validation certificate.
   *  Results are passed in GetPublicKeyAndValidationCallback.
   *  @param[in] public_key_id ID of public key. */
  virtual void GetPublicKeyAndValidation(
      const std::string &public_key_id,
      GetPublicKeyAndValidationCallback callback);

  /** Validates the signature of the value.
   *  @param[in] value value which has been signed.
   *  @param[in] sender_id ID of the message sender's Securifier.
   *  @param[in] value_signature signature of value to be validated with
   *             public_key.
   *  @param[in] public_key used to validate signature of the value.
   *  @param[in] public_key_validation object to allow validation of public_key.
   *  @param[in] kademlia_key kademlia key under which to store/delete/update.
   *  @return true if all tested data is valid, else false. */
  virtual bool Validate(const std::string &value,
                        const std::string &sender_id,
                        const std::string &value_signature,
                        const std::string &public_key,
                        const std::string &public_key_validation,
                        const std::string &kademlia_key) const;

  /** Validates the signature of the value, but may incorporate data from
   *  parameters_ in the validation process.
   *  @param[in] value value which has been signed.
   *  @param[in] sender_id ID of the message sender's Securifier.
   *  @param[in] value_signature signature of value to be validated with
   *             public_key.
   *  @param[in] public_key used to validate signature of the value.
   *  @param[in] public_key_validation object to allow validation of public_key.
   *  @param[in] kademlia_key kademlia key under which to store/delete/update.
   *  @return true if all tested data is valid, else false. */
  virtual bool ValidateWithParameters(const std::string &value,
                                      const std::string &sender_id,
                                      const std::string &value_signature,
                                      const std::string &public_key,
                                      const std::string &public_key_validation,
                                      const std::string &kademlia_key) const;

  /** Asymmetrically decrypts the value using kAsymmetricDecryptionPrivateKey_.
   *  @param[in] encrypted_value value encrypted with recipient's public_key.
   *  @return decrypted value. */
  virtual std::string AsymmetricDecrypt(
      const std::string &encrypted_value) const;

 protected:
  const std::string kId_, kSigningPrivateKey_, kAsymmetricDecryptionPrivateKey_;
  std::string recipient_public_key_;
  std::vector<std::string> parameters_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_COMMON_SECURIFIER_H_
