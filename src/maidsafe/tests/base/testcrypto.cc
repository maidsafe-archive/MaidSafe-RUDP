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
#include <cstdlib>
#include "maidsafe/base/crypto.h"
#include "maidsafe/maidsafe-dht.h"
// Obfuscation tests
TEST(CryptoTest, BEH_BASE_ObfuscatDiffSizes) {
  crypto::Crypto ct;
  std::string obfuscated = ct.Obfuscate(base::RandomString(1024),
                           base::RandomString(1234), crypto::XOR);
  // To be checked, empty string means error = operation not performed because
  // otherwise it returns a non empty string
  ASSERT_EQ(obfuscated, "");
}

TEST(CryptoTest, BEH_BASE_Obfuscation) {
  crypto::Crypto ct;
  std::string str1 = base::RandomString(1024);
  std::string str2 = base::RandomString(1024);
  std::string obfuscated = ct.Obfuscate(str1, str2, crypto::XOR);
  std::string teststr2 = ct.Obfuscate(obfuscated, str1, crypto::XOR);
  std::string teststr1 = ct.Obfuscate(obfuscated, str2, crypto::XOR);
  ASSERT_EQ(teststr1, str1) << "First string not reformed correctly";
  ASSERT_EQ(teststr2, str2) << "Second string not reformed correctly";
}

//  Password generation
TEST(CryptoTest, BEH_BASE_SecurePasswordGeneration) {
  crypto::Crypto ct;
  ASSERT_EQ("", ct.SecurePassword("", 100));
  ASSERT_EQ("", ct.SecurePassword("abcdef", 0));
  ASSERT_NE(ct.SecurePassword("oreja80", 1000), "") << "Password empty";
  // TODO(Team#5#): 2009-06-30 - Include the test with industry standard data
}

//  Hashing
TEST(CryptoTest, BEH_BASE_SetGetAlgorithm) {
  crypto::Crypto ct;
  ct.set_hash_algorithm(crypto::SHA_1);
  ASSERT_EQ(ct.hash_algorithm(), crypto::SHA_1) << "Hash algorithm wrong";
  /*
  ct.set_hash_algorithm(crypto::SHA_224);
  ASSERT_EQ(ct.hash_algorithm(), crypto::SHA_224) << "Hash algorithm wrong";
  */
  ct.set_hash_algorithm(crypto::SHA_256);
  ASSERT_EQ(ct.hash_algorithm(), crypto::SHA_256) << "Hash algorithm wrong";
  ct.set_hash_algorithm(crypto::SHA_384);
  ASSERT_EQ(ct.hash_algorithm(), crypto::SHA_384) << "Hash algorithm wrong";
  ct.set_hash_algorithm(crypto::SHA_512);
  ASSERT_EQ(ct.hash_algorithm(), crypto::SHA_512) << "Hash algorithm wrong";
}

TEST(CryptoTest, BEH_BASE_Hash) {
  crypto::Crypto ct;
  // input files
  std::string input1("input1");
  input1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile1(input1.c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile1 << "abc";
  inputfile1.close();
  std::string input2("input2");
  input2 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile2(input2.c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile2 << "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  inputfile2.close();
  std::string input3("input3");
  input3 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile3(input3.c_str(),
                          std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile3 << "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijk"
                "lmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  inputfile3.close();

  // output file
  boost::filesystem::ifstream resfile;
  std::string random_string;
  random_string.reserve(10 * 1024 * 1024);
  std::string random_substring(base::RandomString(1024));
  for (int i = 0; i < 10 * 1024; ++i)
    random_string += random_substring;
//  ASSERT_EQ(ct.Hash(random_string, "",
//            crypto::STRING_STRING, true), "");
  ct.set_hash_algorithm(crypto::SHA_512);
  ASSERT_NE(ct.Hash(random_string, "",
            crypto::STRING_STRING, true), "") << "Output data empty";
  ASSERT_NE(ct.Hash(input1, "", crypto::FILE_STRING, true), "") <<
            "Output data empty";
  std::string result("result");
  result += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  ASSERT_EQ(result, ct.Hash(random_string,
                            result, crypto::STRING_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  std::string res;
  resfile >> res;
  resfile.close();
  ASSERT_NE("", res);
  boost::filesystem::remove(result);
  // Industry Standards
  ASSERT_EQ(ct.Hash("abc", "", crypto::STRING_STRING, true),
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
      "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(ct.Hash(input1, "", crypto::FILE_STRING, true),
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299"
      "2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  ASSERT_EQ(ct.Hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "",
      crypto::STRING_STRING, true),
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
      "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  ASSERT_EQ(ct.Hash(input3, "", crypto::FILE_STRING, true),
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28"
      "9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  ASSERT_EQ(result, ct.Hash("abc", result, crypto::STRING_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            , res);
  boost::filesystem::remove(result);

  ASSERT_EQ(result, ct.Hash(input1, result, crypto::FILE_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            , res);
  boost::filesystem::remove(result);

  ct.set_hash_algorithm(crypto::SHA_1);
  ASSERT_EQ(ct.Hash("abc", "", crypto::STRING_STRING, true),
      "a9993e364706816aba3e25717850c26c9cd0d89d");
  ASSERT_EQ(ct.Hash(input1.c_str(), "", crypto::FILE_STRING, true),
      "a9993e364706816aba3e25717850c26c9cd0d89d");
  ASSERT_EQ(ct.Hash("abcdbcdecdefdefgefghfghighijh"
            "ijkijkljklmklmnlmnomnopnopq", "", crypto::STRING_STRING, true),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  ASSERT_EQ(ct.Hash(input2.c_str(), "", crypto::FILE_STRING, true),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  ASSERT_EQ(result, ct.Hash("abc", result, crypto::STRING_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("a9993e364706816aba3e25717850c26c9cd0d89d", res);
  boost::filesystem::remove(result);
  ASSERT_EQ(result, ct.Hash(input1, result, crypto::FILE_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("a9993e364706816aba3e25717850c26c9cd0d89d", res);
  boost::filesystem::remove(result);

  ct.set_hash_algorithm(crypto::SHA_256);
  ASSERT_EQ(ct.Hash("abc", "", crypto::STRING_STRING, true),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ASSERT_EQ(ct.Hash(input1, "", crypto::FILE_STRING, true),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ASSERT_EQ(ct.Hash("abcdbcdecdefdefgefghfghighijhij"
            "kijkljklmklmnlmnomnopnopq", "", crypto::STRING_STRING, true),
            "248d6a61d20638b8e5c026930c3e6039a33ce459"
            "64ff2167f6ecedd419db06c1");
  ASSERT_EQ(ct.Hash(input2, "", crypto::FILE_STRING, true),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  ASSERT_EQ(result, ct.Hash("abc", result, crypto::STRING_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("ba7816bf8f01cfea414140de5dae2223b0036"
            "1a396177a9cb410ff61f20015ad", res);
  boost::filesystem::remove(result);
  ASSERT_EQ(result, ct.Hash(input1, result, crypto::FILE_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("ba7816bf8f01cfea414140de5dae2223b"
            "00361a396177a9cb410ff61f20015ad", res);
  boost::filesystem::remove(result);

  ct.set_hash_algorithm(crypto::SHA_384);
  ASSERT_EQ(ct.Hash("abc", "", crypto::STRING_STRING, true),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
            "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
  ASSERT_EQ(ct.Hash(input1, "", crypto::FILE_STRING, true),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
            "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
  ASSERT_EQ(ct.Hash("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "",
            crypto::STRING_STRING, true), "09330c33f71147e83d192fc782cd1b475311"
            "1b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
  ASSERT_EQ(ct.Hash(input3, "", crypto::FILE_STRING, true),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
            "fcc7c71a557e2db966c3e9fa91746039");
  ASSERT_EQ(result, ct.Hash("abc", result, crypto::STRING_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7", res);
  boost::filesystem::remove(result);
  ASSERT_EQ(result, ct.Hash(input1, result, crypto::FILE_FILE, true));
  ASSERT_TRUE(boost::filesystem::exists(result));
  if (!resfile.good()) {
    resfile.clear();
  }
  resfile.open(result.c_str(), std::ios::in |std::ios::binary);
  res.clear();
  resfile >> res;
  resfile.close();
  ASSERT_EQ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7", res);

  boost::filesystem::remove(result);

  boost::filesystem::remove(input1);
  boost::filesystem::remove(input2);
  boost::filesystem::remove(input3);
}

//  Symmetric Encryption
TEST(CryptoTest, BEH_BASE_SetSymmAlgorithm) {
  crypto::Crypto ct;
  ct.set_symm_algorithm(crypto::AES_256);
  ASSERT_EQ(ct.symm_algorithm(), crypto::AES_256) << "GetSymmAlgorithm Failed";
}

TEST(CryptoTest, BEH_BASE_SymmEncrypt) {
  crypto::Crypto ct;
  std::string key = "some key";
  std::string data;
  data.reserve(10 * 1024 * 1024);
  std::string random_substring(base::RandomString(1024));
  for (int i = 0; i < 10 * 1024; ++i)
    data += random_substring;
  // input file
  std::string input1("input1");
  input1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile(input1.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile << data;
  inputfile.close();

  boost::filesystem::ifstream result_file;
  std::string result1("result1");
  result1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result2("result2");
  result2 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result3("result3");
  result3 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result4("result4");
  result4 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  /*ASSERT_EQ(ct.SymmEncrypt(data, "", crypto::STRING_STRING, key), "") <<
              "Output data empty";
  ASSERT_EQ(ct.SymmDecrypt(data, "", crypto::STRING_STRING, key), "") <<
              "Output data empty"; */
  ct.set_symm_algorithm(crypto::AES_256);
  EXPECT_EQ(ct.symm_algorithm(), crypto::AES_256);
  std::string cipher_data = ct.SymmEncrypt(data, "",
                                           crypto::STRING_STRING, key);
  ASSERT_EQ(result1,
            ct.SymmEncrypt(data, result1, crypto::STRING_FILE, key));
  std::string cipher_data1 = ct.SymmEncrypt(input1, "",
                                            crypto::FILE_STRING, key);
  ASSERT_EQ(result2, ct.SymmEncrypt(input1, result2,
                                    crypto::FILE_FILE, key));
  std::string str_from_file;
  ASSERT_NE(cipher_data, "") << "Output data empty";
  ASSERT_EQ(data, ct.SymmDecrypt(cipher_data, "",
            crypto::STRING_STRING, key)) << "Error decrypting data";
  ASSERT_NE(data,
            ct.SymmDecrypt(cipher_data, "", crypto::STRING_STRING, "bad key"));
  ASSERT_EQ(data,
            ct.SymmDecrypt(result1, "", crypto::FILE_STRING, key));
  ASSERT_EQ(result3,
            ct.SymmDecrypt(result2, result3, crypto::FILE_FILE, key));
  ASSERT_EQ(result4,
            ct.SymmDecrypt(cipher_data, result4, crypto::STRING_FILE, key));
  str_from_file = "";
  result_file.open(result4.c_str(), std::ios::in |std::ios::binary);
  result_file >> str_from_file;
  result_file.close();
  ASSERT_EQ(data, str_from_file);
  boost::filesystem::remove(result4);

  ASSERT_EQ(data, ct.SymmDecrypt(cipher_data1, "",
            crypto::STRING_STRING, key)) << "Error decrypting data";
  ASSERT_NE(data, ct.SymmDecrypt(cipher_data1, "", crypto::STRING_STRING,
                                 "bad key"));

  boost::filesystem::remove(input1);
  boost::filesystem::remove(result1);
  boost::filesystem::remove(result2);
  boost::filesystem::remove(result3);

  // TODO(Team#5#): 2009-06-30 - Include the test with industry standard data
}

//  Asymmetric Encryption
TEST(CryptoTest, BEH_BASE_AsymEncrypt) {
  crypto::Crypto ct;
  std::string data = base::RandomString(100);
  // input file
  std::string input1("input1");
  input1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result1("result1");
  result1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result2("result2");
  result2 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result3("result3");
  result3 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result4("result4");
  result4 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile(input1.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile << data;
  inputfile.close();
  boost::filesystem::ifstream result_file;
  ASSERT_EQ("", ct.AsymEncrypt(data, "", base::RandomString(2048),
            crypto::STRING_STRING)) << "Tried to encrypt with something "
            "that is not a public key";
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  std::string ciphertext = ct.AsymEncrypt(data, "", rsakp.public_key(),
                                          crypto::STRING_STRING);
  std::string ciphertext1 = ct.AsymEncrypt(input1, "",
                                           rsakp.public_key(),
                                           crypto::FILE_STRING);
  ASSERT_EQ(result1,
            ct.AsymEncrypt(data, result1,
            rsakp.public_key(), crypto::STRING_FILE));
  ASSERT_EQ(result2,
            ct.AsymEncrypt(input1, result2,
            rsakp.public_key(), crypto::FILE_FILE));
  ASSERT_NE("", ciphertext) << "Returned empty string";
  // trying to decrypt
  ASSERT_EQ(data, ct.AsymDecrypt(ciphertext, "",
                                 rsakp.private_key(), crypto::STRING_STRING))
            << "Failed to decrypt";
  ASSERT_EQ(data,
            ct.AsymDecrypt(ciphertext1, "",
                           rsakp.private_key(), crypto::STRING_STRING));
  ASSERT_EQ(result3,
            ct.AsymDecrypt(result2, result3,
                           rsakp.private_key(), crypto::FILE_FILE));
  std::string str_from_file;
  if (!result_file.good()) {
    result_file.clear();
  }
  result_file.open(result3.c_str(), std::ios::in |std::ios::binary);
  result_file >> str_from_file;
  result_file.close();
  ASSERT_EQ(data, str_from_file);
  ASSERT_EQ(result4,
            ct.AsymDecrypt(ciphertext, result4,
                           rsakp.private_key(), crypto::STRING_FILE));
  str_from_file = "";
  if (!result_file.good()) {
    result_file.clear();
  }
  result_file.open(result3.c_str(), std::ios::in |std::ios::binary);
  result_file >> str_from_file;
  result_file.close();
  ASSERT_EQ(data, str_from_file);
  // trying to decrypt with wrong private key
  rsakp.ClearKeys();
  rsakp.GenerateKeys(4096);
  ASSERT_EQ("", ct.AsymDecrypt(ciphertext, "",
                               rsakp.private_key(), crypto::STRING_STRING));

  boost::filesystem::remove(input1);
  boost::filesystem::remove(result1);
  boost::filesystem::remove(result2);
  boost::filesystem::remove(result3);
  boost::filesystem::remove(result4);

  // TODO(Team#5#): 2009-06-30 - Check maximum size of data we can encrypt
}

TEST(CryptoTest, BEH_BASE_AsymSign) {
  crypto::Crypto ct;
  std::string data = base::RandomString(10*1024);
  ASSERT_EQ("", ct.AsymSign(data , "", base::RandomString(2048),
            crypto::STRING_STRING)) << "Tried to sign with a string that "
            "is not a private key";
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  // input file
  std::string input1("input1");
  input1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile(input1.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile << data;
  inputfile.close();
  boost::filesystem::ifstream result_file;

  std::string signed_data = ct.AsymSign(data , "", rsakp.private_key(),
                                        crypto::STRING_STRING);
  std::string signed_data1 = ct.AsymSign(input1, "",
                                         rsakp.private_key(),
                                         crypto::FILE_STRING);
  ASSERT_NE("", signed_data);
  // Validating the signature
  ASSERT_TRUE(ct.AsymCheckSig(data, signed_data,
              rsakp.public_key(), crypto::STRING_STRING));
  ASSERT_TRUE(ct.AsymCheckSig(data, signed_data1,
              rsakp.public_key(), crypto::STRING_STRING));
  // Trying to validate with another public key
  rsakp.ClearKeys();
  rsakp.GenerateKeys(4096);
  ASSERT_FALSE(ct.AsymCheckSig(data, signed_data,
               rsakp.public_key(), crypto::STRING_STRING));

  boost::filesystem::remove(input1);
}

//  Compression
TEST(CryptoTest, BEH_BASE_Compress) {
  crypto::Crypto ct;
  std::string data = "Deep in the mists of time in a previous millennium, when "
      "life was simpler and people had time, compassion and warmth for each "
      "other; when courage, fortitude and strength were the watchwords of the "
      "day; a society was born in order to preserve these noble attributes; a "
      "society of virtue and valour... a society of Silly Buggers.";
  // input file
  std::string input1("input1");
  input1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result1("result1");
  result1 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result2("result2");
  result2 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result3("result3");
  result3 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  std::string result4("result4");
  result4 += boost::lexical_cast<std::string>(base::RandomUint32()) +
            std::string(".txt");
  boost::filesystem::fstream inputfile(input1.c_str(),
                         std::ios::out | std::ios::trunc | std::ios::binary);
  inputfile << data;
  inputfile.close();
  boost::filesystem::ifstream result_file;
  ASSERT_EQ("", ct.Compress(data, "", 10, crypto::STRING_STRING));
  ASSERT_EQ("", ct.Compress(data, "", -1, crypto::STRING_STRING));
  std::string compressedtext = ct.Compress(data, "", 9, crypto::STRING_STRING);
  std::string compressedtext1 = ct.Compress(input1, "", 9, crypto::FILE_STRING);
  ASSERT_NE("", compressedtext);
  ASSERT_NE("", compressedtext1);
  ASSERT_EQ(result1, ct.Compress(data, result1, 9, crypto::STRING_FILE));
  ASSERT_EQ(result2, ct.Compress(input1, result2, 9, crypto::FILE_FILE));
  std::string level[10];
  for (int i = 0; i <10; ++i) {
    level[i] = ct.Compress(data, "", i, crypto::STRING_STRING);
    if (i)
      ASSERT_LE(level[i].size(), level[i-1].size());
  }
  ASSERT_LT(level[9].size(), data.size());
  // trying to uncompress
  ASSERT_EQ(data, ct.Uncompress(compressedtext, "", crypto::STRING_STRING));
  ASSERT_EQ(data, ct.Uncompress(compressedtext1, "", crypto::STRING_STRING));
  ASSERT_EQ(result3, ct.Uncompress(result1, result3, crypto::FILE_FILE));


//      std::string this_chunklet_;
//      std::ostringstream this_chunklet_oss_(std::ostringstream::binary);
//      fin_.read(bufferlet_.get(), this_chunklet_size_);
//      this_chunklet_oss_.write(bufferlet_.get(), this_chunklet_size_);


  std::string str_from_file;
  boost::scoped_ptr<char> buffer1(new char[data.size()]);
  result_file.open(result3.c_str(), std::ios::in | std::ios::binary);
  std::ostringstream oss1(std::ostringstream::binary);
  result_file.read(buffer1.get(), data.size());
  oss1.write(buffer1.get(), data.size());
  str_from_file = oss1.str();
  result_file.close();
  ASSERT_EQ(data, str_from_file);
  ASSERT_EQ(result4, ct.Uncompress(compressedtext, result4,
            crypto::STRING_FILE));
  str_from_file = "";
  boost::scoped_ptr<char> buffer2(new char[data.size()]);
  result_file.open(result3.c_str(), std::ios::in | std::ios::binary);
  std::ostringstream oss2(std::ostringstream::binary);
  result_file.read(buffer2.get(), data.size());
  oss2.write(buffer2.get(), data.size());
  str_from_file = oss2.str();
  result_file.close();
  ASSERT_EQ(data, str_from_file);
  // trying to uncompress uncompressed data
  ASSERT_EQ("", ct.Uncompress(data, "", crypto::STRING_STRING));

  boost::filesystem::remove(input1);
  boost::filesystem::remove(result1);
  boost::filesystem::remove(result2);
  boost::filesystem::remove(result3);
  boost::filesystem::remove(result4);
}

//  RSA Key Pairs
TEST(RSAKeysTest, BEH_BASE_SetPublicKey) {
  crypto::RsaKeyPair rsakp;
  std::string pub_key = base::RandomString(4096);
  rsakp.set_public_key(pub_key);
  ASSERT_EQ(rsakp.public_key(), pub_key) << "GetPublicKey Failed";
}

TEST(RSAKeysTest, BEH_BASE_SetPrivateKey) {
  crypto::RsaKeyPair rsakp;
  std::string pri_key = base::RandomString(4096);
  rsakp.set_private_key(pri_key);
  ASSERT_EQ(rsakp.private_key(), pri_key) << "GetPrivateKey Failed";
}

TEST(RSAKeysTest, BEH_BASE_KeyGeneration) {
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  ASSERT_NE("", rsakp.private_key()) << "Key generation Failed";
  ASSERT_NE("", rsakp.public_key()) << "Key generation Failed";
}

TEST(RSAKeysTest, BEH_BASE_ClearKeys) {
  crypto::RsaKeyPair rsakp;
  rsakp.GenerateKeys(4096);
  EXPECT_NE("", rsakp.private_key());
  EXPECT_NE("", rsakp.public_key());
  rsakp.ClearKeys();
  ASSERT_EQ("", rsakp.private_key());
  ASSERT_EQ("", rsakp.public_key());
}
