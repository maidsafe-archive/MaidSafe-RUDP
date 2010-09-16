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

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/scoped_ptr.hpp>
#include <cstdlib>
#include "maidsafe/base/crypto.h"
#include "maidsafe/maidsafe-dht.h"

namespace fs = boost::filesystem;

namespace crypto {

namespace test {

TEST(CryptoTest, BEH_BASE_Obfuscation) {
  Crypto test_crypto;
  EXPECT_TRUE(test_crypto.Obfuscate("A", "", XOR).empty());
  EXPECT_TRUE(test_crypto.Obfuscate("", "B", XOR).empty());
  EXPECT_TRUE(test_crypto.Obfuscate("A", "BB", XOR).empty());
  EXPECT_TRUE(test_crypto.Obfuscate("A", "B",
              static_cast<crypto::ObfuscationType>(999)).empty());
  const size_t kStringSize(1024);
  std::string str1 = base::RandomString(kStringSize);
  std::string str2 = base::RandomString(kStringSize);
  std::string obfuscated = test_crypto.Obfuscate(str1, str2, XOR);
  EXPECT_EQ(kStringSize, obfuscated.size());
  EXPECT_EQ(obfuscated, test_crypto.Obfuscate(str2, str1, XOR));
  EXPECT_EQ(str1, test_crypto.Obfuscate(obfuscated, str2, XOR));
  EXPECT_EQ(str2, test_crypto.Obfuscate(obfuscated, str1, XOR));
  const std::string kZeros(kStringSize, 0);
  EXPECT_EQ(kZeros, test_crypto.Obfuscate(str1, str1, XOR));
  EXPECT_EQ(str1, test_crypto.Obfuscate(kZeros, str1, XOR));
  const std::string kKnown1("\xa5\x5a");
  const std::string kKnown2("\x5a\xa5");
  EXPECT_EQ(std::string("\xff\xff"),
            test_crypto.Obfuscate(kKnown1, kKnown2, XOR));
}

TEST(CryptoTest, BEH_BASE_SecurePasswordGeneration) {
  Crypto test_crypto;
  EXPECT_TRUE(test_crypto.SecurePassword("", "salt", 100).empty());
  EXPECT_TRUE(test_crypto.SecurePassword("password", "", 100).empty());
  EXPECT_TRUE(test_crypto.SecurePassword("password", "salt", 0).empty());
  const std::string kKnownPassword1(base::DecodeFromHex("70617373776f7264"));
  const std::string kKnownSalt1(base::DecodeFromHex("1234567878563412"));
  const boost::uint32_t kKnownIterations1(5);
  const std::string kKnownDerived1(base::DecodeFromHex("0a89927670e292af98080a3"
      "c3e2bdee4289b768de74570f9f470282756390fe36de6da2cbc407f4ecf6a9f62ef6249c"
      "c"));
  EXPECT_EQ(kKnownDerived1, test_crypto.SecurePassword(kKnownPassword1,
            kKnownSalt1, kKnownIterations1));
  const std::string kKnownPassword2(base::DecodeFromHex("416c6c206e2d656e746974"
      "696573206d75737420636f6d6d756e69636174652077697468206f74686572206e2d656e"
      "74697469657320766961206e2d3120656e746974656568656568656573"));
  const std::string kKnownSalt2(base::DecodeFromHex("1234567878563412"));
  const boost::uint32_t kKnownIterations2(500);
  const std::string kKnownDerived2(base::DecodeFromHex("ecae5ed132d15bac4c67cc5"
      "de7c4a5559ca448334bdf9dc8f2b9aa86a363ddaaf7b431a8456e51582508c74405dba27"
      "9"));
  EXPECT_EQ(kKnownDerived2, test_crypto.SecurePassword(kKnownPassword2,
            kKnownSalt2, kKnownIterations2));
}

struct HashTestData {
  HashTestData(const std::string &input_data,
               const std::string &SHA1_hex_res,
               const std::string &SHA256_hex_res,
               const std::string &SHA384_hex_res,
               const std::string &SHA512_hex_res)
      : input(input_data),
        SHA1_hex_result(SHA1_hex_res),
        SHA256_hex_result(SHA256_hex_res),
        SHA384_hex_result(SHA384_hex_res),
        SHA512_hex_result(SHA512_hex_res),
        SHA1_raw_result(base::DecodeFromHex(SHA1_hex_res)),
        SHA256_raw_result(base::DecodeFromHex(SHA256_hex_res)),
        SHA384_raw_result(base::DecodeFromHex(SHA384_hex_res)),
        SHA512_raw_result(base::DecodeFromHex(SHA512_hex_res)) {}
  std::string input;
  std::string SHA1_hex_result;
  std::string SHA256_hex_result;
  std::string SHA384_hex_result;
  std::string SHA512_hex_result;
  std::string SHA1_raw_result;
  std::string SHA256_raw_result;
  std::string SHA384_raw_result;
  std::string SHA512_raw_result;
};

TEST(CryptoTest, BEH_BASE_Hash) {
  // Set up industry standard test data
  std::vector<HashTestData> test_data;
  test_data.push_back(HashTestData("abc",
      "a9993e364706816aba3e25717850c26c9cd0d89d",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072b"
      "a1e7cc2358baeca134c825a7",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a"
      "274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
  test_data.push_back(HashTestData(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      "",
      ""));
  test_data.push_back(HashTestData(
      std::string(64 * 15625, 'a'),
      "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc"
      "38ecc4ebae97ddd87f3d8985",
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244"
      "877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"));
  test_data.push_back(HashTestData(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
      "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "",
      "",
      "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a"
      "557e2db966c3e9fa91746039",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e"
      "4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));

  // Set up vector of hash types to be tested
  std::vector<HashType> hash_types;
  hash_types.push_back(crypto::SHA_1);
  hash_types.push_back(crypto::SHA_256);
  hash_types.push_back(crypto::SHA_384);
  hash_types.push_back(crypto::SHA_512);

  // Set up temp test dir and files
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(base::RandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  std::vector<std::string> input_files;
  for (size_t i = 0; i < test_data.size(); ++i) {
    fs::path input_path(kTestDir);
    input_path /= "Input" + boost::lexical_cast<std::string>(i) + ".txt";
    input_files.push_back(input_path.string());
    fs::fstream input_file(input_path.string().c_str(),
                           std::ios::out | std::ios::trunc | std::ios::binary);
    input_file << test_data.at(i).input;
    input_file.close();
  }
  Crypto test_crypto;

  // Check hash type can be set correctly
  test_crypto.set_hash_algorithm(SHA_1);
  EXPECT_EQ(test_crypto.hash_algorithm(), SHA_1);
  test_crypto.set_hash_algorithm(SHA_256);
  EXPECT_EQ(test_crypto.hash_algorithm(), SHA_256);
  test_crypto.set_hash_algorithm(SHA_384);
  EXPECT_EQ(test_crypto.hash_algorithm(), SHA_384);
  test_crypto.set_hash_algorithm(SHA_512);
  EXPECT_EQ(test_crypto.hash_algorithm(), SHA_512);

  // Run tests
  for (size_t i = 0; i < hash_types.size(); ++i) {
    test_crypto.set_hash_algorithm(hash_types.at(i));
    for (size_t j = 0; j < test_data.size(); ++j) {
      std::string input(test_data.at(j).input);
      std::string hex_result, raw_result;
      switch (hash_types.at(i)) {
        case SHA_1:
          hex_result = test_data.at(j).SHA1_hex_result;
          raw_result = test_data.at(j).SHA1_raw_result;
          break;
        case SHA_256:
          hex_result = test_data.at(j).SHA256_hex_result;
          raw_result = test_data.at(j).SHA256_raw_result;
          break;
        case SHA_384:
          hex_result = test_data.at(j).SHA384_hex_result;
          raw_result = test_data.at(j).SHA384_raw_result;
          break;
        case SHA_512:
          hex_result = test_data.at(j).SHA512_hex_result;
          raw_result = test_data.at(j).SHA512_raw_result;
          break;
        default:
          FAIL() << "Unknown hash type.";
          return;
      }
      if (hex_result.empty() || raw_result.empty())
        continue;
      // string input, string output
      EXPECT_EQ(hex_result, test_crypto.Hash(input, "", STRING_STRING, true));
      EXPECT_EQ(raw_result, test_crypto.Hash(input, "", STRING_STRING, false));
      // file input, string output
      EXPECT_EQ(hex_result, test_crypto.Hash(input_files.at(j), "", FILE_STRING,
                                             true));
      EXPECT_EQ(raw_result, test_crypto.Hash(input_files.at(j), "", FILE_STRING,
                                             false));
    }
  }

  // Check using invalid filename
  EXPECT_TRUE(test_crypto.Hash("/", "", FILE_STRING, true).empty());
  EXPECT_TRUE(test_crypto.Hash("NonExistent", "", FILE_STRING, true). empty());
  EXPECT_TRUE(test_crypto.Hash("/", "", FILE_STRING, false).empty());
  EXPECT_TRUE(test_crypto.Hash("NonExistent", "", FILE_STRING, false). empty());

  // Check using invalid operation types
  EXPECT_TRUE(test_crypto.Hash("A", "Output.txt", STRING_FILE, true).empty());
  EXPECT_TRUE(test_crypto.Hash(input_files.at(0), "Output.txt", FILE_FILE,
                               true).empty());

  // Use invalid hash algorithm - should default to SHA_512
  test_crypto.set_hash_algorithm(SHA_1);
  EXPECT_EQ(test_data.at(0).SHA1_hex_result,
            test_crypto.Hash(test_data.at(0).input, "", STRING_STRING, true));
  test_crypto.hash_algorithm_ = static_cast<HashType>(999);
  EXPECT_EQ(test_data.at(0).SHA512_hex_result,
            test_crypto.Hash(test_data.at(0).input, "", STRING_STRING, true));

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

testing::AssertionResult ValidateOutputFile(
    const fs::path &file,
    const std::string &expected_contents) {
  try {
    if (!fs::exists(file))
      return testing::AssertionFailure() << file.string() << " doesn't exist.";
    fs::ifstream result_filestream;
    result_filestream.open(file.string().c_str(),
                           std::ios::in | std::ios::binary);
    std::string result;
    while (true) {
      char c = result_filestream.get();
      if (result_filestream.good())
        result += c;
      else
        break;
    }
    result_filestream.close();
    if (expected_contents != result)
      return testing::AssertionFailure() << "Result of " << result << " doesn't"
          " equal expectation of " << expected_contents;
  }
  catch(const std::exception &e) {
    return testing::AssertionFailure() << e.what();
  }
  return testing::AssertionSuccess();
}

std::string CorruptData(const std::string &input) {
  // Replace a single char of input to a different random char.
  std::string output(input);
  output.at(base::RandomUint32() % input.size()) +=
      (base::RandomUint32() % 254) + 1;
  return output;
}

bool WriteFile(const fs::path &file, const std::string &content) {
  fs::fstream output_file(file.string().c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
  if (!output_file.good()) {
    output_file.close();
    return false;
  }
  output_file.write(content.data(), content.size());
  output_file.close();
  try {
    return fs::exists(file);
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "CryptoTest WriteFile: " << e.what() <<std::endl;
    return false;
  }
}

TEST(CryptoTest, BEH_BASE_SymmEncrypt) {
  // Set up data, temp test dir and files
  const std::string kKeyAndIv(base::DecodeFromHex("0a89927670e292af98080a3c3e2b"
      "dee4289b768de74570f9f470282756390fe392af98080a3c3e2bdee4289b768de7af"));
  const std::string kUnencrypted(base::DecodeFromHex("8b4a84c8f409d8c8b4a8e70f4"
      "9867c63661f2b31d6e4c984a6a01b2r15e48a47bc46af231d2b146e54a87db43f51c2a"
      "5"));
  const std::string kEncrypted(base::DecodeFromHex("441f907b71a14c2f482c4d1fef6"
      "1f3d7ffc0f14953f4f575601803feed5d10a3387c273f9a92b2ceb4d9236167d707"));
  const std::string kBadKeyAndIv(CorruptData(kKeyAndIv));
  const std::string kBadUnencrypted(CorruptData(kUnencrypted));
  const std::string kBadEncrypted(CorruptData(kEncrypted));
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(base::RandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  fs::path input_path(kTestDir / "Unencrypted.txt");
  const std::string kUnencryptedFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kUnencrypted));
  input_path = fs::path(kTestDir / "BadUnencrypted.txt");
  const std::string kBadUnencryptedFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kBadUnencrypted));
  input_path = fs::path(kTestDir / "Encrypted.txt");
  const std::string kEncryptedFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kEncrypted));
  input_path = fs::path(kTestDir / "BadEncrypted.txt");
  const std::string kBadEncryptedFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kBadEncrypted));
  Crypto test_crypto;

  // Check symmetric encryption type can be set correctly
  test_crypto.set_symm_algorithm(AES_256);
  EXPECT_EQ(test_crypto.symm_algorithm(), AES_256);

  // Encryption string to string
  EXPECT_EQ(kEncrypted, test_crypto.SymmEncrypt(kUnencrypted, "", STRING_STRING,
                                                kKeyAndIv));
  EXPECT_NE(kEncrypted, test_crypto.SymmEncrypt(kBadUnencrypted, "",
                                                STRING_STRING, kKeyAndIv));
  EXPECT_NE(kEncrypted, test_crypto.SymmEncrypt(kUnencrypted, "", STRING_STRING,
                                                kBadKeyAndIv));

  // Decryption string to string
  EXPECT_EQ(kUnencrypted, test_crypto.SymmDecrypt(kEncrypted, "", STRING_STRING,
                                                  kKeyAndIv));
  EXPECT_NE(kUnencrypted, test_crypto.SymmDecrypt(kBadEncrypted, "",
                                                  STRING_STRING, kKeyAndIv));
  EXPECT_NE(kUnencrypted, test_crypto.SymmDecrypt(kEncrypted, "", STRING_STRING,
                                                  kBadKeyAndIv));

  // Encryption file to string
  EXPECT_EQ(kEncrypted, test_crypto.SymmEncrypt(kUnencryptedFile, "",
                                                FILE_STRING, kKeyAndIv));
  EXPECT_NE(kEncrypted, test_crypto.SymmEncrypt(kBadUnencryptedFile, "",
                                                FILE_STRING, kKeyAndIv));
  EXPECT_NE(kEncrypted, test_crypto.SymmEncrypt(kUnencryptedFile, "",
                                                FILE_STRING, kBadKeyAndIv));

  // Decryption file to string
  EXPECT_EQ(kUnencrypted, test_crypto.SymmDecrypt(kEncryptedFile, "",
                                                  FILE_STRING, kKeyAndIv));
  EXPECT_NE(kUnencrypted, test_crypto.SymmDecrypt(kBadEncryptedFile, "",
                                                  FILE_STRING, kKeyAndIv));
  EXPECT_NE(kUnencrypted, test_crypto.SymmDecrypt(kEncryptedFile, "",
                                                  FILE_STRING, kBadKeyAndIv));

  // Encryption string to file
  fs::path output_path(kTestDir / "EncryptedOutput1.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kUnencrypted, output_path.string(),
                                    STRING_FILE, kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, kEncrypted));
  output_path = fs::path(kTestDir / "EncryptedOutput2.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kBadUnencrypted, output_path.string(),
                                    STRING_FILE, kKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kEncrypted));
  output_path = fs::path(kTestDir / "EncryptedOutput3.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kUnencrypted, output_path.string(),
                                    STRING_FILE, kBadKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kEncrypted));

  // Decryption string to file
  output_path = fs::path(kTestDir / "DecryptedOutput1.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kEncrypted, output_path.string(),
                                    STRING_FILE, kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, kUnencrypted));
  output_path = fs::path(kTestDir / "DecryptedOutput2.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kBadEncrypted, output_path.string(),
                                    STRING_FILE, kKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kUnencrypted));
  output_path = fs::path(kTestDir / "DecryptedOutput3.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kEncrypted, output_path.string(),
                                    STRING_FILE, kBadKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kUnencrypted));

  // Encryption file to file
  output_path = fs::path(kTestDir / "EncryptedOutput4.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kUnencryptedFile, output_path.string(),
                                    FILE_FILE, kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, kEncrypted));
  output_path = fs::path(kTestDir / "EncryptedOutput5.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kBadUnencryptedFile, output_path.string(),
                                    FILE_FILE, kKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kEncrypted));
  output_path = fs::path(kTestDir / "EncryptedOutput6.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt(kUnencryptedFile, output_path.string(),
                                    FILE_FILE, kBadKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kEncrypted));

  // Decryption file to file
  output_path = fs::path(kTestDir / "DecryptedOutput4.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kEncryptedFile, output_path.string(),
                                    FILE_FILE, kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, kUnencrypted));
  output_path = fs::path(kTestDir / "DecryptedOutput5.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kBadEncryptedFile, output_path.string(),
                                    FILE_FILE, kKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kUnencrypted));
  output_path = fs::path(kTestDir / "DecryptedOutput6.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt(kEncryptedFile, output_path.string(),
                                    FILE_FILE, kBadKeyAndIv));
  EXPECT_FALSE(ValidateOutputFile(output_path, kUnencrypted));

  // Check using empty string and invalid filename
  EXPECT_TRUE(test_crypto.SymmEncrypt("", "", STRING_STRING, kKeyAndIv).
                                      empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("", "", STRING_STRING, kKeyAndIv).
                                      empty());
  output_path = fs::path(kTestDir / "Output.txt");
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmEncrypt("", output_path.string(), STRING_FILE,
                                    kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, ""));
  EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
  EXPECT_EQ(output_path.string(),
            test_crypto.SymmDecrypt("", output_path.string(), STRING_FILE,
                                    kKeyAndIv));
  EXPECT_TRUE(ValidateOutputFile(output_path, ""));
  EXPECT_TRUE(test_crypto.SymmEncrypt("/", "", FILE_STRING, kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("/", "", FILE_STRING, kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt(kUnencrypted, "/", STRING_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt(kEncrypted, "/", STRING_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt("/", output_path.string(), FILE_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("/", output_path.string(), FILE_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt(kUnencryptedFile, "/", FILE_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt(kEncryptedFile, "/", FILE_FILE,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt("/", "/", FILE_FILE, kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("/", "/", FILE_FILE, kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt("NonExistent", "", FILE_STRING,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("NonExistent", "", FILE_STRING,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmEncrypt("NonExistent", output_path.string(),
                                      FILE_FILE, kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt("NonExistent", output_path.string(),
                                      FILE_FILE, kKeyAndIv).empty());

  // Use invalid operation type
  OperationType invalid_type(static_cast<OperationType>(999));
  EXPECT_TRUE(test_crypto.SymmEncrypt(kUnencrypted, "", invalid_type,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt(kEncrypted, "", invalid_type,
                                      kKeyAndIv).empty());

  // Use invalid symmetric encryption algorithm
  test_crypto.symm_algorithm_ = static_cast<SymmetricEncryptionType>(999);
  EXPECT_TRUE(test_crypto.SymmEncrypt(kUnencrypted, "", STRING_STRING,
                                      kKeyAndIv).empty());
  EXPECT_TRUE(test_crypto.SymmDecrypt(kEncrypted, "", STRING_STRING,
                                      kKeyAndIv).empty());

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

testing::AssertionResult FileContentsEqual(const fs::path &file1,
                                           const fs::path &file2) {
  try {
    if (!fs::exists(file1))
      return testing::AssertionFailure() << file1.string() << " doesn't exist.";
    if (!fs::exists(file2))
      return testing::AssertionFailure() << file2.string() << " doesn't exist.";
    if (fs::file_size(file1) != fs::file_size(file2))
      return testing::AssertionFailure() << file1.string() << " is " <<
          fs::file_size(file1) << " bytes.  " << file2.string() << " is " <<
          fs::file_size(file2) << " bytes.";
    fs::ifstream result1_filestream, result2_filestream;
    result1_filestream.open(file1.string().c_str(),
                            std::ios::in | std::ios::binary);
    result2_filestream.open(file2.string().c_str(),
                            std::ios::in | std::ios::binary);
    bool pass(true);
    while (pass) {
      pass = (result1_filestream.get() == result2_filestream.get());
      if (!result1_filestream.good() || !result2_filestream.good()) {
        pass = (!result1_filestream.good() && !result2_filestream.good());
        break;
      }
    }
    result1_filestream.close();
    result2_filestream.close();
    if (!pass)
      return testing::AssertionFailure() << file1.string() << " doesn't have"
          " the same contents as " << file2.string();
  }
  catch(const std::exception &e) {
    return testing::AssertionFailure() << e.what();
  }
  return testing::AssertionSuccess();
}

TEST(CryptoTest, BEH_BASE_AsymEncrypt) {
  // Set up data, temp test dir and files
  RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  const std::string kPublicKey(rsakp.public_key());
  const std::string kPrivateKey(rsakp.private_key());
  rsakp.GenerateKeys(4096);
  const std::string kAnotherPrivateKey(rsakp.private_key());
  ASSERT_NE(kPrivateKey, kAnotherPrivateKey);
  Crypto test_crypto;
  const std::string kUnencrypted(base::RandomString(470));
  const std::string kBadPublicKey(kPublicKey.substr(0, kPublicKey.size() - 1));
  const std::string kBadPrivateKey(
      kPrivateKey.substr(0, kPrivateKey.size() - 1));
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(base::RandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  fs::path input_path(kTestDir / "Unencrypted.txt");
  const std::string kUnencryptedFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kUnencrypted));

  // Encryption string to string
  std::string encrypted1(test_crypto.AsymEncrypt(kUnencrypted, "",
                                                 kPublicKey, STRING_STRING));
  EXPECT_FALSE(encrypted1.empty());
  std::string encrypted2(test_crypto.AsymEncrypt(kUnencrypted, "",
                                                 kPublicKey, STRING_STRING));
  EXPECT_FALSE(encrypted2.empty());
  EXPECT_NE(encrypted1, encrypted2);
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, "", kBadPublicKey,
                                      STRING_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, "", kPrivateKey,
                                      STRING_STRING).empty());

  // Decryption string to string
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(encrypted1, "",
                                                  kPrivateKey, STRING_STRING));
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(encrypted2, "",
                                                  kPrivateKey, STRING_STRING));
  EXPECT_NE(kUnencrypted, test_crypto.AsymDecrypt(encrypted1, "",
      kAnotherPrivateKey, STRING_STRING));
  EXPECT_NE(kUnencrypted, test_crypto.AsymDecrypt(encrypted1, "",
      kBadPrivateKey, STRING_STRING));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, "", kPublicKey,
                                      STRING_STRING).empty());

  // Encryption file to string
  encrypted1 = test_crypto.AsymEncrypt(kUnencryptedFile, "", kPublicKey,
                                       FILE_STRING);
  EXPECT_FALSE(encrypted1.empty());
  encrypted2 = test_crypto.AsymEncrypt(kUnencryptedFile, "", kPublicKey,
                                       FILE_STRING);
  EXPECT_FALSE(encrypted2.empty());
  EXPECT_NE(encrypted1, encrypted2);
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencryptedFile, "", kBadPublicKey,
                                      FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencryptedFile, "", kPrivateKey,
                                      FILE_STRING).empty());

  // Decryption string to file
  fs::path decrypted_path1(kTestDir / "DecryptedOutput1.txt");
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_EQ(decrypted_path1.string(),
            test_crypto.AsymDecrypt(encrypted1, decrypted_path1.string(),
                                    kPrivateKey, STRING_FILE));
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, kUnencrypted));
  fs::path decrypted_path2(kTestDir / "DecryptedOutput2.txt");
  EXPECT_TRUE(WriteFile(decrypted_path2, "Rubbish"));
  EXPECT_EQ(decrypted_path2.string(),
            test_crypto.AsymDecrypt(encrypted2, decrypted_path2.string(),
                                    kPrivateKey, STRING_FILE));
  EXPECT_TRUE(ValidateOutputFile(decrypted_path2, kUnencrypted));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, decrypted_path1.string(),
                                      kAnotherPrivateKey, STRING_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, ""));
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, decrypted_path1.string(),
                                      kBadPrivateKey, STRING_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, decrypted_path1.string(),
                                      kPublicKey, STRING_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, "Rubbish"));

  // Encryption string to file
  fs::path encrypted_path1(kTestDir / "EncryptedOutput1.txt");
  EXPECT_TRUE(WriteFile(encrypted_path1, "Rubbish"));
  EXPECT_EQ(encrypted_path1.string(),
            test_crypto.AsymEncrypt(kUnencrypted, encrypted_path1.string(),
                                    kPublicKey, STRING_FILE));
  EXPECT_FALSE(ValidateOutputFile(encrypted_path1, "Rubbish"));
  fs::path encrypted_path2(kTestDir / "EncryptedOutput2.txt");
  EXPECT_TRUE(WriteFile(encrypted_path2, "Rubbish"));
  EXPECT_EQ(encrypted_path2.string(),
            test_crypto.AsymEncrypt(kUnencrypted, encrypted_path2.string(),
                                    kPublicKey, STRING_FILE));
  EXPECT_FALSE(ValidateOutputFile(encrypted_path2, "Rubbish"));
  EXPECT_FALSE(FileContentsEqual(encrypted_path1, encrypted_path2));
  fs::path bad_encrypted_path(kTestDir / "BadEncryptedOutput.txt");
  EXPECT_TRUE(WriteFile(bad_encrypted_path, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, bad_encrypted_path.string(),
                                      kBadPublicKey, STRING_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(bad_encrypted_path, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, encrypted_path2.string(),
                                      kPrivateKey, STRING_FILE).empty());

  // Decryption file to string
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(encrypted_path1.string(), "",
                                                  kPrivateKey, FILE_STRING));
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(encrypted_path2.string(), "",
                                                  kPrivateKey, FILE_STRING));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(), "",
                                      kAnotherPrivateKey, FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(), "",
                                      kBadPrivateKey, FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(bad_encrypted_path.string(), "",
                                      kBadPrivateKey, FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(), "", kPublicKey,
                                      FILE_STRING).empty());

  // Encryption file to file
  EXPECT_TRUE(WriteFile(encrypted_path1, "Rubbish"));
  EXPECT_EQ(encrypted_path1.string(),
            test_crypto.AsymEncrypt(kUnencryptedFile, encrypted_path1.string(),
                                    kPublicKey, FILE_FILE));
  EXPECT_FALSE(ValidateOutputFile(encrypted_path1, "Rubbish"));
  EXPECT_TRUE(WriteFile(encrypted_path2, "Rubbish"));
  EXPECT_EQ(encrypted_path2.string(),
            test_crypto.AsymEncrypt(kUnencryptedFile, encrypted_path2.string(),
                                    kPublicKey, FILE_FILE));
  EXPECT_FALSE(ValidateOutputFile(encrypted_path2, "Rubbish"));
  EXPECT_FALSE(FileContentsEqual(encrypted_path1, encrypted_path2));
  EXPECT_TRUE(WriteFile(bad_encrypted_path, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencryptedFile,
                                      bad_encrypted_path.string(),
                                      kBadPublicKey, FILE_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(bad_encrypted_path, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencryptedFile,
                                      encrypted_path2.string(), kPrivateKey,
                                      FILE_FILE).empty());

  // Decryption file to file
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_EQ(decrypted_path1.string(),
            test_crypto.AsymDecrypt(encrypted_path1.string(),
                                    decrypted_path1.string(), kPrivateKey,
                                    FILE_FILE));
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, kUnencrypted));
  EXPECT_TRUE(WriteFile(decrypted_path2, "Rubbish"));
  EXPECT_EQ(decrypted_path2.string(),
            test_crypto.AsymDecrypt(encrypted_path2.string(),
                                    decrypted_path2.string(), kPrivateKey,
                                    FILE_FILE));
  EXPECT_TRUE(ValidateOutputFile(decrypted_path2, kUnencrypted));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(),
                                      decrypted_path1.string(),
                                      kAnotherPrivateKey, FILE_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, ""));
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(),
                                      decrypted_path1.string(),
                                      kBadPrivateKey, FILE_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymDecrypt(bad_encrypted_path.string(),
                                      decrypted_path1.string(),
                                      kBadPrivateKey, FILE_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(WriteFile(decrypted_path1, "Rubbish"));
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(),
                                      decrypted_path1.string(),
                                      kPublicKey, FILE_FILE).empty());
  EXPECT_TRUE(ValidateOutputFile(decrypted_path1, "Rubbish"));

  // Check using empty string and invalid filename
  EXPECT_TRUE(test_crypto.AsymDecrypt("", "", kPrivateKey, STRING_STRING).
                                      empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt("/", "", kPublicKey, FILE_STRING).
                                      empty());
//  EXPECT_TRUE(test_crypto.AsymDecrypt("/", "", kPrivateKey, FILE_STRING).
//                                      empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, "/", kPublicKey,
                                      STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, "/", kPrivateKey,
                                      STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt("", decrypted_path1.string(), kPrivateKey,
                                      STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt("/", decrypted_path1.string(), kPublicKey,
                                      FILE_FILE).empty());
//  EXPECT_TRUE(test_crypto.AsymDecrypt("/", decrypted_path1.string(),
//                                      kPrivateKey, FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencryptedFile, "/", kPublicKey,
                                      FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted_path1.string(), "/",
                                      kPrivateKey, FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt("/", "/", kPublicKey, FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt("/", "/", kPrivateKey, FILE_FILE).
                                      empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt("NonExistent", "", kPublicKey,
                                      FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt("NonExistent", "", kPrivateKey,
                                      FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt("NonExistent", decrypted_path1.string(),
                                      kPublicKey, FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt("NonExistent", decrypted_path1.string(),
                                      kPrivateKey, FILE_FILE).empty());

  // Check using invalid input data size (> 470 chars)
  const std::string kInvalidData(kUnencrypted + "A");
  input_path = fs::path(kTestDir / "InvalidData.txt");
  const std::string kInvalidDataFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kInvalidData));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kInvalidData, "", kPublicKey,
                                      STRING_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kInvalidDataFile, "", kPublicKey,
                                      FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kInvalidData, encrypted_path1.string(),
                                      kPublicKey, STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.AsymEncrypt(kInvalidDataFile,
                                      encrypted_path1.string(),
                                      kPublicKey, FILE_FILE).empty());

  // Use invalid operation type
  OperationType invalid_type(static_cast<OperationType>(999));
  EXPECT_TRUE(test_crypto.AsymEncrypt(kUnencrypted, "", kPublicKey,
                                      invalid_type).empty());
  EXPECT_TRUE(test_crypto.AsymDecrypt(encrypted1, "", kPrivateKey,
                                      invalid_type).empty());

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

TEST(CryptoTest, BEH_BASE_AsymSign) {
  // Set up data, temp test dir and files
  RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  const std::string kPublicKey(rsakp.public_key());
  const std::string kPrivateKey(rsakp.private_key());
  rsakp.GenerateKeys(4096);
  const std::string kAnotherPublicKey(rsakp.public_key());
  const std::string kAnotherPrivateKey(rsakp.private_key());
  ASSERT_NE(kPublicKey, kAnotherPublicKey);
  ASSERT_NE(kPrivateKey, kAnotherPrivateKey);
  Crypto test_crypto;
  const std::string kTestData(base::RandomString(99999));
  const std::string kBadPublicKey(kPublicKey.substr(0, kPublicKey.size() - 1));
  const std::string kBadPrivateKey(
      kPrivateKey.substr(0, kPrivateKey.size() - 1));
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(base::RandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  fs::path input_path(kTestDir / "TestData.txt");
  const std::string kTestDataFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kTestData));

  // Create signatures
  std::string signature_string(test_crypto.AsymSign(kTestData, "", kPrivateKey,
                                                    STRING_STRING));
  EXPECT_FALSE(signature_string.empty());
  std::string signature_file(test_crypto.AsymSign(kTestDataFile, "",
                                                  kPrivateKey, FILE_STRING));
  EXPECT_EQ(signature_string, signature_file);
  std::string another_signature_string(test_crypto.AsymSign(kTestData, "",
      kAnotherPrivateKey, STRING_STRING));
  EXPECT_FALSE(another_signature_string.empty());
  EXPECT_NE(signature_string, another_signature_string);
  std::string another_signature_file(test_crypto.AsymSign(kTestDataFile, "",
      kAnotherPrivateKey, FILE_STRING));
  EXPECT_FALSE(another_signature_string.empty());
  EXPECT_EQ(another_signature_string, another_signature_file);
  EXPECT_TRUE(test_crypto.AsymSign(kTestData, "", kBadPrivateKey,
                                   STRING_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymSign(kTestDataFile, "", kBadPrivateKey,
                                   FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.AsymSign(kTestData, "", kPublicKey, STRING_STRING).
                                   empty());
  EXPECT_TRUE(test_crypto.AsymSign(kTestDataFile, "", kPublicKey, FILE_STRING).
                                   empty());

  // Validate signatures
  EXPECT_TRUE(test_crypto.AsymCheckSig(kTestData, signature_string, kPublicKey,
                                       STRING_STRING));
  EXPECT_TRUE(test_crypto.AsymCheckSig(kTestDataFile, signature_file,
                                       kPublicKey, FILE_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestData, another_signature_string,
                                        kPublicKey, STRING_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestDataFile, another_signature_file,
                                        kPublicKey, FILE_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestData, signature_string,
                                        kAnotherPublicKey, STRING_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestDataFile, signature_file,
                                        kAnotherPublicKey, FILE_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestData, signature_string,
                                        kBadPublicKey, STRING_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestDataFile, signature_file,
                                        kBadPublicKey, FILE_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestData, signature_string,
                                        kPrivateKey, STRING_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestDataFile, signature_file,
                                        kPrivateKey, FILE_STRING));

  // Check using invalid operation types
  EXPECT_TRUE(test_crypto.AsymSign(kTestData, "", kPrivateKey, STRING_FILE).
                                   empty());
  EXPECT_TRUE(test_crypto.AsymSign(kTestDataFile, "", kPrivateKey, FILE_FILE).
                                   empty());
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestData, signature_string, kPublicKey,
                                        STRING_FILE));
  EXPECT_FALSE(test_crypto.AsymCheckSig(kTestDataFile, signature_file,
                                        kPublicKey, FILE_FILE));

  // Check using invalid filename
  EXPECT_TRUE(test_crypto.AsymSign("/", "", kPrivateKey, FILE_STRING).
                                   empty());
  EXPECT_TRUE(test_crypto.AsymSign("NonExistent", "", kPrivateKey, FILE_STRING).
                                   empty());
  EXPECT_FALSE(test_crypto.AsymCheckSig("/", another_signature_file,
                                        kPublicKey, FILE_STRING));
  EXPECT_FALSE(test_crypto.AsymCheckSig("NonExistent", another_signature_file,
                                        kPublicKey, FILE_STRING));

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

TEST(CryptoTest, BEH_BASE_Compress) {
  const size_t kTestDataSize(10000);
  const size_t kTolerance(kTestDataSize * 0.005);
  std::string initial_data(kTestDataSize, 'A');
  initial_data.replace(0, kTestDataSize / 2,
                       base::RandomString(kTestDataSize / 2));
  std::random_shuffle(initial_data.begin(), initial_data.end());
  const std::string kTestData(initial_data);
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(base::RandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  fs::path input_path(kTestDir / "TestData.txt");
  const std::string kTestDataFile(input_path.string());
  ASSERT_TRUE(WriteFile(input_path, kTestData));
  Crypto test_crypto;

  // Compress
  std::vector<std::string> compressed_strings, compressed_files;
  fs::path output_path;
  for (boost::uint16_t level = 0; level <= kMaxCompressionLevel; ++level) {
    compressed_strings.push_back(
        test_crypto.Compress(kTestData, "", level, STRING_STRING));
    if (level > 0) {
      EXPECT_GE(compressed_strings.at(level - 1).size() + kTolerance,
                compressed_strings.at(level).size());
    }
    EXPECT_EQ(compressed_strings.at(level),
              test_crypto.Compress(kTestDataFile, "", level, FILE_STRING));
    std::string output_name("Compressed" +
                            boost::lexical_cast<std::string>(level) + ".txt");
    output_path = fs::path(kTestDir / output_name);
    compressed_files.push_back(output_path.string());
    EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
    EXPECT_EQ(output_path.string(),
              test_crypto.Compress(kTestData, output_path.string(), level,
                                   STRING_FILE));
    EXPECT_TRUE(ValidateOutputFile(output_path, compressed_strings.at(level)));
    EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
    EXPECT_EQ(output_path.string(),
              test_crypto.Compress(kTestDataFile, output_path.string(), level,
                                   FILE_FILE));
    EXPECT_TRUE(ValidateOutputFile(output_path, compressed_strings.at(level)));
  }
  EXPECT_GT(kTestData.size(),
            compressed_strings.at(kMaxCompressionLevel).size());

  // Uncompress
  output_path = fs::path(kTestDir / "Uncompressed.txt");
  for (boost::uint16_t level = 0; level <= kMaxCompressionLevel; ++level) {
    EXPECT_EQ(kTestData, test_crypto.Uncompress(compressed_strings.at(level),
                                                "", STRING_STRING));
    EXPECT_EQ(kTestData, test_crypto.Uncompress(compressed_files.at(level), "",
                                                FILE_STRING));
    EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
    EXPECT_EQ(output_path.string(),
              test_crypto.Uncompress(compressed_strings.at(level),
                                     output_path.string(), STRING_FILE));
    EXPECT_TRUE(ValidateOutputFile(output_path, kTestData));
    EXPECT_TRUE(WriteFile(output_path, "Rubbish"));
    EXPECT_EQ(output_path.string(),
              test_crypto.Uncompress(compressed_files.at(level),
                                     output_path.string(), FILE_FILE));
    EXPECT_TRUE(ValidateOutputFile(output_path, kTestData));
  }

  // Try to compress with invalid compression level
  EXPECT_TRUE(test_crypto.Compress(kTestData, "", kMaxCompressionLevel + 1,
                                   STRING_STRING).empty());
  EXPECT_TRUE(test_crypto.Compress(kTestDataFile, "", kMaxCompressionLevel + 1,
                                   FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Compress(kTestData, output_path.string(),
      kMaxCompressionLevel + 1, STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.Compress(kTestDataFile, output_path.string(),
      kMaxCompressionLevel + 1, FILE_FILE).empty());

  // Try to compress and uncompress with invalid files
  EXPECT_TRUE(test_crypto.Compress("/", "", 0, FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Compress(kTestData, "/", 0, STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.Compress("/", output_path.string(), 0,
                                   FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.Compress(kTestDataFile, "/", 0, FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.Compress("NonExistent", "", 0, FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Compress("NonExistent", output_path.string(), 0,
                                   FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.Uncompress("/", "", FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Uncompress(compressed_strings.at(0), "/",
                                     STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.Uncompress("/", output_path.string(),
                                     FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.Uncompress(compressed_files.at(0), "/",
                                     FILE_FILE).empty());
  EXPECT_TRUE(test_crypto.Uncompress("NonExistent", "", FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Uncompress("NonExistent", output_path.string(),
                                     FILE_FILE).empty());

  // Try to compress and uncompress with invalid operation type
  OperationType invalid_type(static_cast<OperationType>(999));
  boost::uint16_t level(base::RandomUint32() % (kMaxCompressionLevel + 1));
  EXPECT_TRUE(test_crypto.Compress(kTestData, "", level, invalid_type).empty());
  EXPECT_TRUE(test_crypto.Uncompress(kTestData, "", invalid_type).empty());

  // Try to uncompress uncompressed data
  EXPECT_TRUE(test_crypto.Uncompress(kTestData, "", STRING_STRING).empty());
  EXPECT_TRUE(test_crypto.Uncompress(kTestDataFile, "", FILE_STRING).empty());
  EXPECT_TRUE(test_crypto.Uncompress(kTestData, output_path.string(),
                                     STRING_FILE).empty());
  EXPECT_TRUE(test_crypto.Uncompress(kTestDataFile, output_path.string(),
                                     FILE_FILE).empty());

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

TEST(RSAKeysTest, BEH_BASE_RsaKeyPair) {
  // Check setters and getters
  RsaKeyPair rsakp;
  EXPECT_TRUE(rsakp.public_key().empty());
  EXPECT_TRUE(rsakp.private_key().empty());
  std::string public_key = base::RandomString(100);
  rsakp.set_public_key(public_key);
  EXPECT_EQ(rsakp.public_key(), public_key);
  std::string private_key = base::RandomString(100);
  rsakp.set_private_key(private_key);
  EXPECT_EQ(rsakp.private_key(), private_key);

  // Check key generation
  rsakp.GenerateKeys(4096);
  EXPECT_NE(rsakp.public_key(), public_key);
  EXPECT_NE(rsakp.private_key(), private_key);
  public_key = rsakp.public_key();
  private_key = rsakp.private_key();
  EXPECT_FALSE(public_key.empty());
  EXPECT_FALSE(private_key.empty());

  // Use the first keys to encrypt and decrypt data
  const std::string kUnencrypted(base::RandomString(400));
  Crypto test_crypto;
  std::string encrypted(test_crypto.AsymEncrypt(kUnencrypted, "", public_key,
                                                STRING_STRING));
  EXPECT_FALSE(encrypted.empty());
  EXPECT_NE(kUnencrypted, encrypted);
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(encrypted, "", private_key,
                                                  STRING_STRING));

  // Generate new keys and check they cannot be interchanged with the originals
  rsakp.GenerateKeys(4096);
  EXPECT_NE(rsakp.public_key(), public_key);
  EXPECT_NE(rsakp.private_key(), private_key);
  std::string another_encrypted(test_crypto.AsymEncrypt(kUnencrypted, "",
      rsakp.public_key(), STRING_STRING));
  EXPECT_FALSE(another_encrypted.empty());
  EXPECT_NE(kUnencrypted, another_encrypted);
  EXPECT_NE(encrypted, another_encrypted);
  EXPECT_EQ(kUnencrypted, test_crypto.AsymDecrypt(another_encrypted, "",
      rsakp.private_key(), STRING_STRING));
  EXPECT_NE(kUnencrypted, test_crypto.AsymDecrypt(encrypted, "",
      rsakp.private_key(), STRING_STRING));
  EXPECT_NE(kUnencrypted, test_crypto.AsymDecrypt(another_encrypted, "",
      private_key, STRING_STRING));

  rsakp.ClearKeys();
  EXPECT_TRUE(rsakp.public_key().empty());
  EXPECT_TRUE(rsakp.private_key().empty());
}

}  // namespace test

}  // namespace crypto
