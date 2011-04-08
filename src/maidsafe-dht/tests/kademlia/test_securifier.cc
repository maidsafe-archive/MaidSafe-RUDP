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

#include "gtest/gtest.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/securifier.h"

namespace arg = std::placeholders;

namespace maidsafe {

namespace kademlia {

namespace test {

class SecurifierTest : public testing::Test {
 public:
  SecurifierTest() : test_pubki_("test_pubki"),
                     test_pubk_("test_pubk"),
                     test_prik_("test_prik"),
                     securifier_(new Securifier(test_pubki_,
                                                test_pubk_,
                                                test_prik_)) {}
  ~SecurifierTest() {}
 protected:
  std::string test_pubki_, test_pubk_, test_prik_;
  SecurifierPtr securifier_;
};

TEST_F(SecurifierTest, BEH_KAD_ConstructionAndGetters) {
  ASSERT_EQ(test_pubki_, securifier_->kSigningKeyId());
  ASSERT_EQ(test_pubki_, securifier_->kAsymmetricDecryptionKeyId());
  ASSERT_EQ(test_pubk_, securifier_->kSigningPublicKey());
  ASSERT_EQ(test_pubk_, securifier_->kAsymmetricDecryptionPublicKey());
  ASSERT_EQ(test_prik_, securifier_->kSigningPrivateKey());
  ASSERT_EQ(test_prik_, securifier_->kAsymmetricDecryptionPrivateKey());

  std::string test_spubki("test_spubki"), test_spubk("test_spubk"),
              test_sprik("test_sprik");
  securifier_.reset(new Securifier(test_pubki_, test_pubk_, test_prik_,
                                   test_spubki, test_spubk, test_sprik));
  ASSERT_EQ(test_pubki_, securifier_->kSigningKeyId());
  ASSERT_EQ(test_spubki, securifier_->kAsymmetricDecryptionKeyId());
  ASSERT_EQ(test_pubk_, securifier_->kSigningPublicKey());
  ASSERT_EQ(test_spubk, securifier_->kAsymmetricDecryptionPublicKey());
  ASSERT_EQ(test_prik_, securifier_->kSigningPrivateKey());
  ASSERT_EQ(test_sprik, securifier_->kAsymmetricDecryptionPrivateKey());
}

TEST_F(SecurifierTest, BEH_KAD_Parameters) {
  ASSERT_EQ(size_t(0), securifier_->parameters().size());

  int params_size(10);
  std::vector<std::string> params;
  for (int n = 0; n < params_size; ++n)
    params.push_back("param" + IntToString(n));

  securifier_->AddParameters(params);
  ASSERT_EQ(size_t(params_size), securifier_->parameters().size());
  for (size_t a = 0; a < securifier_->parameters().size(); ++a)
    ASSERT_EQ(params[a], securifier_->parameters().at(a));

  securifier_->ClearParameters();
  ASSERT_EQ(size_t(0), securifier_->parameters().size());

  securifier_->AddParameters(params);
  securifier_->AddParameters(params);
  ASSERT_EQ(size_t(2 * params_size), securifier_->parameters().size());
  for (size_t a = 0; a < securifier_->parameters().size(); ++a)
    ASSERT_EQ(params[a % 10], securifier_->parameters().at(a));

  securifier_->ClearParameters();
  ASSERT_EQ(size_t(0), securifier_->parameters().size());
}

void GenerateRandomValues(std::vector<std::string> *random_values) {
  int desired_size(15), upper_value_size_limit(470);
  for (int n = 0; n < desired_size; ++n)
    random_values->push_back(RandomString(RandomUint32() %
                                          upper_value_size_limit));
}

TEST_F(SecurifierTest, BEH_KAD_AsymmetricEncryptDecrypt) {
  crypto::RsaKeyPair rsa_key_pair;
  rsa_key_pair.GenerateKeys(4096);
  securifier_.reset(new Securifier(test_pubki_,
                                   rsa_key_pair.public_key(),
                                   rsa_key_pair.private_key()));

  std::vector<std::string> random_values;
  GenerateRandomValues(&random_values);

  for (size_t n = 0; n < random_values.size(); ++n) {
    ASSERT_EQ(random_values[n],
              securifier_->AsymmetricDecrypt(
                  securifier_->AsymmetricEncrypt(random_values[n],
                                                 rsa_key_pair.public_key())));
  }
}

void TestCb(const std::string &retrieved1, const std::string &retrieved2,
            std::string *element1, std::string *element2) {
  *element1 = retrieved1;
  *element2 = retrieved2;
}

TEST_F(SecurifierTest, BEH_KAD_GetPublicKeyAndValidation) {
  ASSERT_NE("", test_pubk_);
  ASSERT_NE("", test_prik_);
  securifier_->GetPublicKeyAndValidation(test_pubki_, &test_pubk_, &test_prik_);
  ASSERT_EQ("", test_pubk_);
  ASSERT_EQ("", test_prik_);

  test_pubk_ = "test_pubk_";
  std::string test_pubkv("test_pubkv");
  securifier_->GetPublicKeyAndValidation(test_pubki_,
                                         std::bind(&TestCb, arg::_1, arg::_2,
                                                   &test_pubk_, &test_pubkv));
  ASSERT_EQ("", test_pubk_);
  ASSERT_EQ("", test_pubkv);
}

TEST_F(SecurifierTest, BEH_KAD_Validation) {
  securifier_.reset(new Securifier("", "", ""));
  std::string empty_string;
  ASSERT_EQ(empty_string, securifier_->Sign("anything"));
  ASSERT_TRUE(securifier_->Validate("", "", "", "", "", ""));
  ASSERT_TRUE(securifier_->Validate("a", "b", "c", "", "d", "e"));
  ASSERT_FALSE(securifier_->Validate("", "", "", "pub_key", "", ""));
  ASSERT_FALSE(securifier_->Validate("a", "b", "c", "pub_key", "d", "e"));

  crypto::RsaKeyPair rsa_key_pair;
  rsa_key_pair.GenerateKeys(4096);
  securifier_.reset(new Securifier(test_pubki_,
                                   rsa_key_pair.public_key(),
                                   rsa_key_pair.private_key()));

  std::string anythings_signature(securifier_->Sign("anything"));
  ASSERT_NE(empty_string, anythings_signature);
  ASSERT_TRUE(securifier_->Validate("anything", anythings_signature, "",
                                    rsa_key_pair.public_key(), "", ""));

  // Params
  int params_size(10);
  std::vector<std::string> params;
  std::string concatenated_params, signature_concatenated_params;
  for (int n = 0; n < params_size; ++n) {
    params.push_back("param" + IntToString(n));
    concatenated_params += params[n];
  }
  concatenated_params = "anything" + concatenated_params;
  signature_concatenated_params = securifier_->Sign("anything");
  ASSERT_NE(empty_string, signature_concatenated_params);
  ASSERT_TRUE(securifier_->ValidateWithParameters("", "", "", "", "", ""));
  ASSERT_TRUE(securifier_->ValidateWithParameters("a", "b", "c", "", "d", "e"));
  ASSERT_FALSE(securifier_->ValidateWithParameters("", "", "",
                                                   "pub_key", "", ""));
  ASSERT_FALSE(securifier_->ValidateWithParameters("a", "b", "c",
                                                   "pub_key", "d", "e"));
  ASSERT_TRUE(securifier_->Validate("anything", signature_concatenated_params,
                                    "", rsa_key_pair.public_key(), "", ""));
}

}  // namespace test

}  // namespace kademlia

}  // namespace maidsafe
