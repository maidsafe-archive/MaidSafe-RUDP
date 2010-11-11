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

#ifndef MAIDSAFE_BASE_VALIDATIONINTERFACE_H_
#define MAIDSAFE_BASE_VALIDATIONINTERFACE_H_

#include <string>


namespace base {
/**
 * Base class to validate with a public key requests signed with a private key
 * and to validate the id of the sender of the request.  This methods should be
 * implemented by the user.
 * id_ is the ID of the node doing the validation.
 */
class SignatureValidator {
 public:
  explicit SignatureValidator(const std::string &id) : id_(id) {}
  SignatureValidator() : id_() {}
  virtual ~SignatureValidator() {}
  /**
   * Validates the Id of the signer
   * @param signer_id id to be validated
   * @param public_key public key
   * @param signed_public_key public key signed
   */
  virtual bool ValidateSignerId(const std::string &signer_id,
                                const std::string &public_key,
                                const std::string &signed_public_key) = 0;
  /**
   * Validates the request signed by sender
   * @param signed_request request to be validated with the public key
   * @param public_key used to validate signature of the request
   * @param signed_public_key public key signed
   * @param key key to store/delete value
   * @param rec_id id of the node receiving the request
   */
  virtual bool ValidateRequest(const std::string &signed_request,
                               const std::string &public_key,
                               const std::string &signed_public_key,
                               const std::string &key) = 0;
  inline std::string id() const { return id_; }
  inline void set_id(const std::string &id) { id_ = id; }

 private:
  std::string id_;
};

}  // namespace base

#endif  // MAIDSAFE_BASE_VALIDATIONINTERFACE_H_
