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

#ifndef MAIDSAFE_TESTS_VALIDATIONIMPL_H_
#define MAIDSAFE_TESTS_VALIDATIONIMPL_H_

#include <string>
#include "maidsafe/base/validationinterface.h"


namespace base {

class TestValidator : public SignatureValidator {
 public:
  TestValidator() : SignatureValidator() {}
  /**
   * Signer Id is not validated, return always true
   */
  bool ValidateSignerId(const std::string &, const std::string &,
      const std::string &) {
    return true;
  }
  /**
   * Validates the request signed with private key that corresponds
   * to public_key
   */
  bool ValidateRequest(const std::string &signed_request,
      const std::string &public_key, const std::string &signed_public_key,
      const std::string &key) {
    if (signed_request == kad::kAnonymousSignedRequest)
      return true;
    crypto::Crypto checker;
    return checker.AsymCheckSig(checker.Hash(public_key + signed_public_key
      + key, "", crypto::STRING_STRING, true), signed_request, public_key,
      crypto::STRING_STRING);
  }
};

}  // namespace base
#endif  // MAIDSAFE_TESTS_VALIDATIONIMPL_H_
