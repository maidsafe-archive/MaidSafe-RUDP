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

#include "maidsafe/base/crypto.h"
#include <maidsafe/cryptopp/integer.h>
#include <maidsafe/cryptopp/pwdbased.h>
#include <maidsafe/cryptopp/sha.h>
#include <maidsafe/cryptopp/filters.h>
#include <maidsafe/cryptopp/files.h>
#include <maidsafe/cryptopp/gzip.h>
#include <maidsafe/cryptopp/hex.h>
#include <maidsafe/cryptopp/aes.h>
#include <maidsafe/cryptopp/modes.h>
#include <maidsafe/cryptopp/rsa.h>
#include <maidsafe/cryptopp/osrng.h>
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/base/log.h"

namespace crypto {

CryptoPP::RandomNumberGenerator & GlobalRNG() {
  // static CryptoPP::AutoSeededRandomPool rand_pool;
  static CryptoPP::AutoSeededX917RNG< CryptoPP::AES > rand_pool;
  return rand_pool;
}

std::string Crypto::XOROperation(const std::string &first,
                                 const std::string &second) {
  std::string result(first);
  for (size_t i = 0; i < result.length(); ++i) {
    result[i] = first[i] ^ second[i];
  }
  return result;
}

std::string Crypto::Obfuscate(const std::string &first,
                              const std::string &second,
                              const ObfuscationType &obfuscation_type) {
  std::string result;
  if ((first.length() != second.length()) || (first.length() == 0))
    return result;
  switch (obfuscation_type) {
    case XOR:
      result = XOROperation(first, second);
      break;
    default:
      return result;
  }
  return result;
}

std::string Crypto::SecurePassword(const std::string &password,
                                   const boost::uint32_t &pin) {
  if ((password.empty()) || (pin == 0))
    return "";
  byte purpose = 0;
  std::string derived_password;
  std::string salt = "maidsafe_salt";
  boost::uint16_t iter = (pin % 1000)+1000;
  CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf;
  CryptoPP::SecByteBlock derived(32);
  pbkdf.DeriveKey(derived, derived.size(), purpose,
      reinterpret_cast<const byte *>(password.data()),
      password.size(), reinterpret_cast<const byte *>(salt.data()),
      salt.size(), iter);
  CryptoPP::HexEncoder enc(new CryptoPP::StringSink(derived_password), false);
  enc.Put(derived, derived.size());
  return derived_password;
}

template <class T>
std::string Crypto::HashFunc(const std::string &input,
                             const std::string &output,
                             const OperationType &operation_type,
                             const bool &hex,
                             T *hash) {
  std::string result;
  switch (operation_type) {
    case STRING_STRING:
      if (hex) {
        CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(*hash,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(result), false)));
      } else {
        CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(*hash,
            new CryptoPP::StringSink(result)));
      }
      break;
    case STRING_FILE:
      result = output;
      try {
        if (hex) {
          CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(*hash,
              new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
              false)));
        } else {
          CryptoPP::StringSource(input, true, new CryptoPP::HashFilter(*hash,
              new CryptoPP::FileSink(output.c_str())));
        }
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
        result.clear();
      }
      break;
    case FILE_STRING:
      try {
        if (hex) {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::HashFilter(*hash,
              new CryptoPP::HexEncoder(new CryptoPP::StringSink(result),
              false)));
        } else {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::HashFilter(*hash,
              new CryptoPP::StringSink(result)));
        }
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
      result.clear();
      }
      break;
    case FILE_FILE:
      result = output;
      try {
        if (hex) {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::HashFilter(*hash,
              new CryptoPP::HexEncoder(new CryptoPP::FileSink(output.c_str()),
              false)));
        } else {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::HashFilter(*hash,
              new CryptoPP::FileSink(output.c_str())));
        }
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
      result.clear();
      }
      break;
  }
  return result;
}

std::string Crypto::Hash(const std::string &input,
                         const std::string &output,
                         const OperationType &operation_type,
                         const bool &hex) {
  switch (hash_algorithm_) {
    case SHA_512: {
      CryptoPP::SHA512 hash;
      return HashFunc(input, output, operation_type, hex, &hash);
    }
    case SHA_1: {
      CryptoPP::SHA1 hash;
      return HashFunc(input, output, operation_type, hex, &hash);
    }
//    case SHA_224: {
//      CryptoPP::SHA224 hash;
//      return HashFunc(input, output, operation_type, hex, &hash);
//    }
    case SHA_256: {
      CryptoPP::SHA256 hash;
      return HashFunc(input, output, operation_type, hex, &hash);
    }
    case SHA_384: {
      CryptoPP::SHA384 hash;
      return HashFunc(input, output, operation_type, hex, &hash);
    }
    default: {
      CryptoPP::SHA512 hash;
      return HashFunc(input, output, operation_type, hex, &hash);
    }
  }
}

std::string Crypto::SymmEncrypt(const std::string &input,
                                const std::string &output,
                                const OperationType &operation_type,
                                const std::string &key) {
  if (symm_algorithm_ != AES_256)
    return "";
  CryptoPP::SHA512 hash;
  std::string hashkey = HashFunc(key, "", STRING_STRING, true, &hash);
  byte byte_key[AES256_KeySize], byte_iv[AES256_IVSize];
  CryptoPP::StringSource(hashkey.substr(0, AES256_KeySize), true,
      new CryptoPP::ArraySink(byte_key, sizeof(byte_key)));
  CryptoPP::StringSource(hashkey.substr(AES256_KeySize, AES256_IVSize),
      true, new CryptoPP::ArraySink(byte_iv, sizeof(byte_iv)));
  std::string result;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(byte_key,
      sizeof(byte_key), byte_iv);
  switch (operation_type) {
    case STRING_STRING:
      CryptoPP::StringSource(input, true,
          new CryptoPP::StreamTransformationFilter(encryptor,
          new CryptoPP::StringSink(result)));
      break;
    case STRING_FILE:
      result = output;
      try {
        CryptoPP::StringSource(input, true,
            new CryptoPP::StreamTransformationFilter(encryptor,
            new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
        result = "";
      }
      break;
      case FILE_STRING:
        try {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::StreamTransformationFilter(encryptor,
              new CryptoPP::StringSink(result)));
        }
        catch(const CryptoPP::Exception &e) {
          DLOG(ERROR) << e.what() << std::endl;
          result = "";
        }
        break;
      case FILE_FILE:
        result = output;
        try {
          CryptoPP::FileSource(input.c_str(), true,
              new CryptoPP::StreamTransformationFilter(encryptor,
              new CryptoPP::FileSink(output.c_str())));
        }
        catch(const CryptoPP::Exception &e) {
          DLOG(ERROR) << e.what() << std::endl;
          result = "";
        }
        break;
    }
  return result;
}

std::string Crypto::SymmDecrypt(const std::string &input,
                                const std::string &output,
                                const OperationType &operation_type,
                                const std::string &key) {
  if (symm_algorithm_ != AES_256)
    return "";
  CryptoPP::SHA512 hash;
  std::string hashkey = HashFunc(key, "", STRING_STRING, true, &hash);
  byte byte_key[ AES256_KeySize ], byte_iv[ AES256_IVSize ];
  CryptoPP::StringSource(hashkey.substr(0, AES256_KeySize), true,
      new CryptoPP::ArraySink(byte_key, sizeof(byte_key)));
  CryptoPP::StringSource(hashkey.substr(AES256_KeySize, AES256_IVSize),
      true, new CryptoPP::ArraySink(byte_iv, sizeof(byte_iv)));
  std::string result;
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(byte_key,
      sizeof(byte_key), byte_iv);
  switch (operation_type) {
    case STRING_STRING:
      CryptoPP::StringSource(input, true,
          new CryptoPP::StreamTransformationFilter(decryptor,
          new CryptoPP::StringSink(result)));
      break;
    case STRING_FILE:
      result = output;
      try {
        CryptoPP::StringSource(reinterpret_cast<const byte *>(input.c_str()),
          input.length(), true,
          new CryptoPP::StreamTransformationFilter(decryptor,
          new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
        result = "";
      }
      break;
    case FILE_STRING:
      try {
        CryptoPP::FileSource(input.c_str(), true,
          new CryptoPP::StreamTransformationFilter(decryptor,
          new CryptoPP::StringSink(result)));
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
        result = "";
      }
      break;
    case FILE_FILE:
      result = output;
      try {
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::StreamTransformationFilter(decryptor,
            new CryptoPP::FileSink(output.c_str())));
      }
      catch(const CryptoPP::Exception &e) {
        DLOG(ERROR) << e.what() << std::endl;
        result = "";
      }
      break;
  }
  return result;
}

std::string Crypto::AsymEncrypt(const std::string &input,
                                const std::string &output,
                                const std::string &key,
                                const OperationType &operation_type) {
  try {
    CryptoPP::StringSource pubkey(key, true);
    CryptoPP::RSAES_OAEP_SHA_Encryptor pub(pubkey);
    CryptoPP::AutoSeededRandomPool rand_pool;
    std::string result;

    switch (operation_type) {
      case STRING_STRING:
        CryptoPP::StringSource(input, true,
            new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
            new CryptoPP::StringSink(result)));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(input, true,
            new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
            new CryptoPP::FileSink(output.c_str())));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
            new CryptoPP::StringSink(result)));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
           new CryptoPP::PK_EncryptorFilter(rand_pool, pub,
           new CryptoPP::FileSink(output.c_str())));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return "";
  }
}

std::string Crypto::AsymDecrypt(const std::string &input,
                                const std::string &output,
                                const std::string &key,
                                const OperationType &operation_type) {
  try {
    CryptoPP::StringSource privkey(key, true);
    CryptoPP::RSAES_OAEP_SHA_Decryptor priv(privkey);
    std::string result;
    switch (operation_type) {
      case STRING_STRING:
        CryptoPP::StringSource(input, true,
            new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv,
            new CryptoPP::StringSink(result)));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(input, true,
            new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv,
            new CryptoPP::FileSink(output.c_str())));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv,
            new CryptoPP::StringSink(result)));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::PK_DecryptorFilter(GlobalRNG(), priv,
            new CryptoPP::FileSink(output.c_str())));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return "";
  }
}

std::string Crypto::AsymSign(const std::string &input,
                             const std::string &output,
                             const std::string &key,
                             const OperationType &operation_type) {
  try {
    CryptoPP::StringSource privkey(key, true);
    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Signer
        signer(privkey);
    std::string result;
    switch (operation_type) {
      case STRING_STRING:
        CryptoPP::StringSource(input, true,
            new CryptoPP::SignerFilter(GlobalRNG(), signer,
            new CryptoPP::StringSink(result)));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(input , true,
            new CryptoPP::SignerFilter(GlobalRNG(), signer,
            new CryptoPP::FileSink(output.c_str())));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::SignerFilter(GlobalRNG(), signer,
            new CryptoPP::StringSink(result)));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true,
            new CryptoPP::SignerFilter(GlobalRNG(), signer,
            new CryptoPP::FileSink(output.c_str())));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return "";
  }
}

bool Crypto::AsymCheckSig(const std::string &input_data,
                          const std::string &input_signature,
                          const std::string &key,
                          const OperationType &operation_type) {
  try {
    CryptoPP::StringSource pubkey(key, true);

    CryptoPP::RSASS<CryptoPP::PKCS1v15, CryptoPP::SHA512>::Verifier
        verifier(pubkey);
    bool result = false;
    CryptoPP::SecByteBlock *signature;
    CryptoPP::SignatureVerificationFilter *verifierFilter;

    if ((operation_type == STRING_STRING) || (operation_type == STRING_FILE)) {
      CryptoPP::StringSource signatureString(input_signature, true);
      if (signatureString.MaxRetrievable() != verifier.SignatureLength())
        return result;
      signature = new CryptoPP::SecByteBlock(verifier.SignatureLength());
      signatureString.Get(*signature, signature->size());

      verifierFilter = new CryptoPP::SignatureVerificationFilter(verifier);
      verifierFilter->Put(*signature, verifier.SignatureLength());
      CryptoPP::StringSource ssource(input_data, true, verifierFilter);
      result = verifierFilter->GetLastResult();
      delete signature;
      return result;
    } else if ((operation_type == FILE_FILE) ||
               (operation_type == FILE_STRING)) {
      CryptoPP::FileSource signatureFile(input_signature.c_str(), true);
      if (signatureFile.MaxRetrievable() != verifier.SignatureLength())
        return false;
      signature = new CryptoPP::SecByteBlock(verifier.SignatureLength());
      signatureFile.Get(*signature, signature->size());

      verifierFilter = new CryptoPP::SignatureVerificationFilter(verifier);
      verifierFilter->Put(*signature, verifier.SignatureLength());
      CryptoPP::FileSource fsource(input_data.c_str(), true, verifierFilter);
      result = verifierFilter->GetLastResult();
      delete signature;
      return result;
    } else {
      return false;
    }
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return false;
  }
}

std::string Crypto::Compress(const std::string &input,
                             const std::string &output,
                             const boost::uint16_t &compression_level,
                             const OperationType &operation_type) {
  if (compression_level < 0 || compression_level > 9)
    return "";
  try {
    std::string result("");
    switch (operation_type) {
      case STRING_STRING:
        CryptoPP::StringSource(input, true, new CryptoPP::Gzip(
            new CryptoPP::StringSink(result), compression_level));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(input, true, new CryptoPP::Gzip(
            new CryptoPP::FileSink(output.c_str()), compression_level));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true, new CryptoPP::Gzip(
            new CryptoPP::StringSink(result), compression_level));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true, new CryptoPP::Gzip(
            new CryptoPP::FileSink(output.c_str()), compression_level));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return "";
  }
}

std::string Crypto::Uncompress(const std::string &input,
                               const std::string &output,
                               const OperationType &operation_type) {
  try {
    std::string result;
    switch (operation_type) {
      case STRING_STRING:
        CryptoPP::StringSource(input, true, new CryptoPP::Gunzip(
            new CryptoPP::StringSink(result)));
        break;
      case STRING_FILE:
        result = output;
        CryptoPP::StringSource(input, true, new CryptoPP::Gunzip(
            new CryptoPP::FileSink(output.c_str())));
        break;
      case FILE_STRING:
        CryptoPP::FileSource(input.c_str(), true, new CryptoPP::Gunzip(
            new CryptoPP::StringSink(result)));
        break;
      case FILE_FILE:
        result = output;
        CryptoPP::FileSource(input.c_str(), true, new CryptoPP::Gunzip(
            new CryptoPP::FileSink(output.c_str())));
        break;
    }
    return result;
  }
  catch(const CryptoPP::Exception &e) {
    DLOG(ERROR) << e.what() << std::endl;
    return "";
  }
}

void RsaKeyPair::GenerateKeys(const boost::uint16_t &keySize) {  //NOLINT
  // CryptoPP::AutoSeededRandomPool rand_pool;
  private_key_.clear();
  public_key_.clear();
  CryptoPP::RandomPool rand_pool;
  std::string seed = base::RandomString(keySize);
  rand_pool.IncorporateEntropy(reinterpret_cast<const byte *>(seed.c_str()),
                                                              seed.size());

  CryptoPP::RSAES_OAEP_SHA_Decryptor priv(rand_pool, keySize);  // 256 bytes
  CryptoPP::StringSink privKey(private_key_);
  priv.DEREncode(privKey);
  privKey.MessageEnd();

  CryptoPP::RSAES_OAEP_SHA_Encryptor pub(priv);
  CryptoPP::StringSink pubKey(public_key_);
  pub.DEREncode(pubKey);
  pubKey.MessageEnd();
}

}  // namespace crypto
