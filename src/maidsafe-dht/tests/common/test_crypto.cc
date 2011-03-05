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

#include <cstdlib>
#include "gtest/gtest.h"
#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/scoped_ptr.hpp"
#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/utils.h"
#include "maidsafe-dht/maidsafe-dht.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace crypto {

namespace test {

TEST(CryptoTest, BEH_COMMON_Obfuscation) {
  EXPECT_TRUE(XOR("A", "").empty());
  EXPECT_TRUE(XOR("", "B").empty());
  EXPECT_TRUE(XOR("A", "BB").empty());
  const size_t kStringSize(1024);
  std::string str1 = RandomString(kStringSize);
  std::string str2 = RandomString(kStringSize);
  std::string obfuscated = XOR(str1, str2);
  EXPECT_EQ(kStringSize, obfuscated.size());
  EXPECT_EQ(obfuscated, XOR(str2, str1));
  EXPECT_EQ(str1, XOR(obfuscated, str2));
  EXPECT_EQ(str2, XOR(obfuscated, str1));
  const std::string kZeros(kStringSize, 0);
  EXPECT_EQ(kZeros, XOR(str1, str1));
  EXPECT_EQ(str1, XOR(kZeros, str1));
  const std::string kKnown1("\xa5\x5a");
  const std::string kKnown2("\x5a\xa5");
  EXPECT_EQ(std::string("\xff\xff"), XOR(kKnown1, kKnown2));
}

TEST(CryptoTest, BEH_COMMON_SecurePasswordGeneration) {
  EXPECT_TRUE(SecurePassword("", "salt", 100).empty());
  EXPECT_TRUE(SecurePassword("password", "", 100).empty());
  EXPECT_TRUE(SecurePassword("password", "salt", 0).empty());
  const std::string kKnownPassword1(DecodeFromHex("70617373776f7264"));
  const std::string kKnownSalt1(DecodeFromHex("1234567878563412"));
  const boost::uint32_t kKnownIterations1(5);
  const std::string kKnownDerived1(DecodeFromHex("0a89927670e292af98080a3"
      "c3e2bdee4289b768de74570f9f470282756390fe36de6da2cbc407f4ecf6a9f62ef6249c"
      "c"));
  EXPECT_EQ(kKnownDerived1, SecurePassword(kKnownPassword1,
            kKnownSalt1, kKnownIterations1));
  const std::string kKnownPassword2(DecodeFromHex("416c6c206e2d656e746974"
      "696573206d75737420636f6d6d756e69636174652077697468206f74686572206e2d656e"
      "74697469657320766961206e2d3120656e746974656568656568656573"));
  const std::string kKnownSalt2(DecodeFromHex("1234567878563412"));
  const boost::uint32_t kKnownIterations2(500);
  const std::string kKnownDerived2(DecodeFromHex("ecae5ed132d15bac4c67cc5"
      "de7c4a5559ca448334bdf9dc8f2b9aa86a363ddaaf7b431a8456e51582508c74405dba27"
      "9"));
  EXPECT_EQ(kKnownDerived2, SecurePassword(kKnownPassword2,
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
        SHA1_raw_result(DecodeFromHex(SHA1_hex_res)),
        SHA256_raw_result(DecodeFromHex(SHA256_hex_res)),
        SHA384_raw_result(DecodeFromHex(SHA384_hex_res)),
        SHA512_raw_result(DecodeFromHex(SHA512_hex_res)) {}
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

TEST(CryptoTest, BEH_COMMON_Hash) {
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

  // Set up temp test dir and files
  const fs::path kTestDir(fs::path("temp") / std::string("crypto_test_" +
      boost::lexical_cast<std::string>(SRandomUint32()).substr(0, 8)));
  try {
    ASSERT_TRUE(fs::create_directories(kTestDir));
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
  std::vector<fs::path> input_files;
  for (size_t i = 0; i < test_data.size(); ++i) {
    fs::path input_path(kTestDir);
    input_path /= "Input" + boost::lexical_cast<std::string>(i) + ".txt";
    input_files.push_back(input_path);
    fs::fstream input_file(input_path.string().c_str(),
                           std::ios::out | std::ios::trunc | std::ios::binary);
    input_file << test_data.at(i).input;
    input_file.close();
  }

  // Run tests
  for (size_t j = 0; j < test_data.size(); ++j) {
    std::string input(test_data.at(j).input);
    if (!test_data.at(j).SHA1_hex_result.empty()) {
      EXPECT_EQ(test_data.at(j).SHA1_hex_result,
                EncodeToHex(Hash<crypto::SHA1>(input)));
      EXPECT_EQ(test_data.at(j).SHA1_raw_result, Hash<crypto::SHA1>(input));
      EXPECT_EQ(test_data.at(j).SHA1_hex_result,
                EncodeToHex(HashFile<crypto::SHA1>(input_files.at(j))));
      EXPECT_EQ(test_data.at(j).SHA1_raw_result,
                HashFile<crypto::SHA1>(input_files.at(j)));
    }

    if (!test_data.at(j).SHA256_hex_result.empty()) {
      EXPECT_EQ(test_data.at(j).SHA256_hex_result,
                EncodeToHex(Hash<crypto::SHA256>(input)));
      EXPECT_EQ(test_data.at(j).SHA256_raw_result, Hash<crypto::SHA256>(input));
      EXPECT_EQ(test_data.at(j).SHA256_hex_result,
                EncodeToHex(HashFile<crypto::SHA256>(input_files.at(j))));
      EXPECT_EQ(test_data.at(j).SHA256_raw_result,
                HashFile<crypto::SHA256>(input_files.at(j)));
    }

    if (!test_data.at(j).SHA384_hex_result.empty()) {
      EXPECT_EQ(test_data.at(j).SHA384_hex_result,
                EncodeToHex(Hash<crypto::SHA384>(input)));
      EXPECT_EQ(test_data.at(j).SHA384_raw_result, Hash<crypto::SHA384>(input));
      EXPECT_EQ(test_data.at(j).SHA384_hex_result,
                EncodeToHex(HashFile<crypto::SHA384>(input_files.at(j))));
      EXPECT_EQ(test_data.at(j).SHA384_raw_result,
                HashFile<crypto::SHA384>(input_files.at(j)));
    }

    if (!test_data.at(j).SHA512_hex_result.empty()) {
      EXPECT_EQ(test_data.at(j).SHA512_hex_result,
                EncodeToHex(Hash<crypto::SHA512>(input)));
      EXPECT_EQ(test_data.at(j).SHA512_raw_result, Hash<crypto::SHA512>(input));
      EXPECT_EQ(test_data.at(j).SHA512_hex_result,
                EncodeToHex(HashFile<crypto::SHA512>(input_files.at(j))));
      EXPECT_EQ(test_data.at(j).SHA512_raw_result,
                HashFile<crypto::SHA512>(input_files.at(j)));
    }
  }

  // Check using invalid filename
  EXPECT_TRUE(HashFile<crypto::SHA512>(fs::path("/")).empty());
  EXPECT_TRUE(HashFile<crypto::SHA512>(fs::path("NonExistent")).empty());

  try {
    EXPECT_GT(fs::remove_all(kTestDir), 0);
  }
  catch(const std::exception &e) {
    FAIL() << e.what();
  }
}

std::string CorruptData(const std::string &input) {
  // Replace a single char of input to a different random char.
  std::string output(input);
  output.at(SRandomUint32() % input.size()) +=
      (SRandomUint32() % 254) + 1;
  return output;
}

TEST(CryptoTest, BEH_COMMON_SymmEncrypt) {
  // Set up data
  const std::string kKey(DecodeFromHex("0a89927670e292af98080a3c3e2bdee4"
                                       "289b768de74570f9f470282756390fe3"));
  const std::string kIV(DecodeFromHex("92af98080a3c3e2bdee4289b768de7af"));
  const std::string kUnencrypted(DecodeFromHex("8b4a84c8f409d8c8b4a8e70f4"
      "9867c63661f2b31d6e4c984a6a01b2r15e48a47bc46af231d2b146e54a87db43f51c2a"
      "5"));
  const std::string kEncrypted(DecodeFromHex("441f907b71a14c2f482c4d1fef6"
      "1f3d7ffc0f14953f4f575601803feed5d10a3387c273f9a92b2ceb4d9236167d707"));
  const std::string kBadKey(CorruptData(kKey));
  const std::string kBadIV(CorruptData(kIV));
  const std::string kBadUnencrypted(CorruptData(kUnencrypted));
  const std::string kBadEncrypted(CorruptData(kEncrypted));

  // Encryption string to string
  EXPECT_EQ(kEncrypted, SymmEncrypt(kUnencrypted, kKey, kIV));
  EXPECT_NE(kEncrypted, SymmEncrypt(kBadUnencrypted, kKey, kIV));
  EXPECT_NE(kEncrypted, SymmEncrypt(kUnencrypted, kBadKey, kBadIV));

  // Decryption string to string
  EXPECT_EQ(kUnencrypted, SymmDecrypt(kEncrypted, kKey, kIV));
  EXPECT_NE(kUnencrypted, SymmDecrypt(kBadEncrypted, kKey, kIV));
  EXPECT_NE(kUnencrypted, SymmDecrypt(kEncrypted, kBadKey, kBadIV));

  // Check using empty string
  EXPECT_TRUE(SymmEncrypt("", kKey, kIV).empty());
  EXPECT_TRUE(SymmDecrypt("", kKey, kIV).empty());
}

TEST(CryptoTest, BEH_COMMON_AsymEncrypt) {
  // Set up data
  RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  const std::string kPublicKey(rsakp.public_key());
  const std::string kPrivateKey(rsakp.private_key());
  rsakp.GenerateKeys(4096);
  const std::string kAnotherPrivateKey(rsakp.private_key());
  ASSERT_NE(kPrivateKey, kAnotherPrivateKey);
  const std::string kUnencrypted(SRandomString(470));
  const std::string kBadPublicKey(kPublicKey.substr(0, kPublicKey.size() - 1));
  const std::string kBadPrivateKey(
      kPrivateKey.substr(0, kPrivateKey.size() - 1));

  // Encryption
  std::string encrypted1(AsymEncrypt(kUnencrypted, kPublicKey));
  EXPECT_FALSE(encrypted1.empty());
  std::string encrypted2(AsymEncrypt(kUnencrypted, kPublicKey));
  EXPECT_FALSE(encrypted2.empty());
  EXPECT_NE(encrypted1, encrypted2);
  EXPECT_TRUE(AsymEncrypt(kUnencrypted, kBadPublicKey).empty());
  EXPECT_TRUE(AsymEncrypt(kUnencrypted, kPrivateKey).empty());

  // Decryption
  EXPECT_EQ(kUnencrypted, AsymDecrypt(encrypted1, kPrivateKey));
  EXPECT_EQ(kUnencrypted, AsymDecrypt(encrypted2, kPrivateKey));
  EXPECT_NE(kUnencrypted, AsymDecrypt(encrypted1, kAnotherPrivateKey));
  EXPECT_NE(kUnencrypted, AsymDecrypt(encrypted1, kBadPrivateKey));
  EXPECT_TRUE(AsymDecrypt(encrypted1, kPublicKey).empty());

  // Check using empty string
  EXPECT_TRUE(AsymDecrypt("", kPrivateKey).empty());

  // Check using invalid input data size (> 470 chars)
  const std::string kInvalidData(kUnencrypted + "A");
  EXPECT_TRUE(AsymEncrypt(kInvalidData, kPublicKey).empty());
}

TEST(CryptoTest, BEH_COMMON_AsymSign) {
  // Set up data
  RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  const std::string kPublicKey(rsakp.public_key());
  const std::string kPrivateKey(rsakp.private_key());
  rsakp.GenerateKeys(4096);
  const std::string kAnotherPublicKey(rsakp.public_key());
  const std::string kAnotherPrivateKey(rsakp.private_key());
  ASSERT_NE(kPublicKey, kAnotherPublicKey);
  ASSERT_NE(kPrivateKey, kAnotherPrivateKey);
  const std::string kTestData(SRandomString(99999));
  const std::string kBadPublicKey(kPublicKey.substr(0, kPublicKey.size() - 1));
  const std::string kBadPrivateKey(
      kPrivateKey.substr(0, kPrivateKey.size() - 1));

  // Create signatures
  std::string signature_string(AsymSign(kTestData, kPrivateKey));
  EXPECT_FALSE(signature_string.empty());
  std::string another_signature_string(AsymSign(kTestData, kAnotherPrivateKey));
  EXPECT_FALSE(another_signature_string.empty());
  EXPECT_NE(signature_string, another_signature_string);
  EXPECT_TRUE(AsymSign(kTestData, kBadPrivateKey).empty());
  EXPECT_TRUE(AsymSign(kTestData, kPublicKey).empty());

  // Validate signatures
  EXPECT_TRUE(AsymCheckSig(kTestData, signature_string, kPublicKey));
  EXPECT_FALSE(AsymCheckSig(kTestData, another_signature_string, kPublicKey));
  EXPECT_FALSE(AsymCheckSig(kTestData, signature_string, kAnotherPublicKey));
  EXPECT_FALSE(AsymCheckSig(kTestData, signature_string, kBadPublicKey));
  EXPECT_FALSE(AsymCheckSig(kTestData, signature_string, kPrivateKey));
}

TEST(CryptoTest, BEH_COMMON_Compress) {
  const size_t kTestDataSize(10000);
  const size_t kTolerance(size_t(kTestDataSize * 0.005));
  std::string initial_data(kTestDataSize, 'A');
  initial_data.replace(0, kTestDataSize / 2, RandomString(kTestDataSize / 2));
  std::random_shuffle(initial_data.begin(), initial_data.end());
  const std::string kTestData(initial_data);

  // Compress
  std::vector<std::string> compressed_strings;
  for (boost::uint16_t level = 0; level <= kMaxCompressionLevel; ++level) {
    compressed_strings.push_back(Compress(kTestData, level));
    if (level > 0) {
      EXPECT_GE(compressed_strings.at(level - 1).size() + kTolerance,
                compressed_strings.at(level).size());
    }
  }
  EXPECT_GT(kTestData.size(),
            compressed_strings.at(kMaxCompressionLevel).size());

  // Uncompress
  for (boost::uint16_t level = 0; level <= kMaxCompressionLevel; ++level)
    EXPECT_EQ(kTestData, Uncompress(compressed_strings.at(level)));

  // Try to compress with invalid compression level
  EXPECT_TRUE(Compress(kTestData, kMaxCompressionLevel + 1).empty());

  // Try to uncompress uncompressed data
  EXPECT_TRUE(Uncompress(kTestData).empty());
}

TEST(RSAKeysTest, BEH_COMMON_RsaKeyPair) {
  // Check setters and getters
  RsaKeyPair rsakp;
  EXPECT_TRUE(rsakp.public_key().empty());
  EXPECT_TRUE(rsakp.private_key().empty());
  std::string public_key = SRandomString(100);
  rsakp.set_public_key(public_key);
  EXPECT_EQ(rsakp.public_key(), public_key);
  std::string private_key = SRandomString(100);
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
  const std::string kUnencrypted(RandomString(400));
  std::string encrypted(AsymEncrypt(kUnencrypted, public_key));
  EXPECT_FALSE(encrypted.empty());
  EXPECT_NE(kUnencrypted, encrypted);
  EXPECT_EQ(kUnencrypted, AsymDecrypt(encrypted, private_key));

  // Generate new keys and check they cannot be interchanged with the originals
  rsakp.GenerateKeys(4096);
  EXPECT_NE(rsakp.public_key(), public_key);
  EXPECT_NE(rsakp.private_key(), private_key);
  std::string another_encrypted(AsymEncrypt(kUnencrypted, rsakp.public_key()));
  EXPECT_FALSE(another_encrypted.empty());
  EXPECT_NE(kUnencrypted, another_encrypted);
  EXPECT_NE(encrypted, another_encrypted);
  EXPECT_EQ(kUnencrypted, AsymDecrypt(another_encrypted, rsakp.private_key()));
  EXPECT_NE(kUnencrypted, AsymDecrypt(encrypted, rsakp.private_key()));
  EXPECT_NE(kUnencrypted, AsymDecrypt(another_encrypted, private_key));

  rsakp.ClearKeys();
  EXPECT_TRUE(rsakp.public_key().empty());
  EXPECT_TRUE(rsakp.private_key().empty());
}

}  // namespace test

}  // namespace crypto

}  // namespace maidsafe
