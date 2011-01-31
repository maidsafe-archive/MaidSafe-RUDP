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

#ifndef MAIDSAFE_DHT_COMMON_CRYPTO_H_
#define MAIDSAFE_DHT_COMMON_CRYPTO_H_

#include <string>
#include "boost/cstdint.hpp"
#include "boost/filesystem/v3/path.hpp"

namespace CryptoPP {
class SHA1;
class SHA256;
class SHA384;
class SHA512;
}  // namespace CryptoPP

namespace maidsafe {

namespace crypto {

typedef CryptoPP::SHA1 SHA1;
typedef CryptoPP::SHA256 SHA256;
typedef CryptoPP::SHA384 SHA384;
typedef CryptoPP::SHA512 SHA512;

const boost::uint16_t AES256_KeySize = 32;  /**< size in bytes. */
const boost::uint16_t  AES256_IVSize = 16;  /**< size in bytes. */
const boost::uint16_t  kMaxCompressionLevel = 9;

/** XOR one string with another.
 *  The function performs an bitwise XOR on each char of first with the
 *  corresponding char of second.  first and second must have identical size.
 *  @param first string to be obfuscated.
 *  @param second string used to obfuscate the first one.
 *  @return The obfuscated string. */
std::string XOR(const std::string &first, const std::string &second);

/** Creates a secure password.
 *  Creates a secure password using the Password-Based Key Derivation Function
 *  (PBKDF) version 2 algorithm.
 *  @param password password.
 *  @param salt salt.
 *  @param pin PIN from which the number of iterations is derived.
 *  @return The derived key. */
std::string SecurePassword(const std::string &password,
                           const std::string &salt,
                           const boost::uint32_t &pin);

/** Hash function operating on a string.
 *  @tparam HashType type of hash function to use (e.g. SHA512)
 *  @param input string that is to be hashed.
 *  @return the result of the hash function. */
template <typename HashType>
std::string Hash(const std::string &input);

/** Hash function operating on a file.
 *  @tparam HashType type of hash function to use (e.g. SHA512)
 *  @param file_path path to file that is to be hashed.
 *  @return the result of the hash function, or empty string if the file could
 *  not be read. */
template <typename HashType>
std::string HashFile(const boost::filesystem::path &file_path);

/** Symmetrically encrypt a string.
 *  Performs symmetric encrytion using AES256. It returns an empty string if the
 *  key size < AES256_KeySize or if initialisation_vector size < AES256_IVSize.
 *  @param input string to be encrypted.
 *  @param key key used to encrypt.  Size must be >= AES256_KeySize.
 *  @param initialisation_vector initialisation vector used to encrypt.  Size
 *  must be >= AES256_IVSize.
 *  @return the encrypted data or an empty string. */
std::string SymmEncrypt(const std::string &input,
                        const std::string &key,
                        const std::string &initialisation_vector);

/** Symmetrically decrypt a string.
 *  Performs symmetric decrytion using AES256. It returns an empty string if the
 *  key size < AES256_KeySize or if initialisation_vector size < AES256_IVSize.
 *  @param input string to be decrypted.
 *  @param key key used to encrypt.  Size must be >= AES256_KeySize.
 *  @param initialisation_vector initialisation vector used to encrypt.  Size
 *  must be >= AES256_IVSize.
 *  @return the decrypted data or an empty string. */
std::string SymmDecrypt(const std::string &input,
                        const std::string &key,
                        const std::string &initialisation_vector);

/** Asymmetrically encrypt a string.
 *  Performs asymmetric encryption with a public key using RSA.  It returns an
 *  empty string if the public key is not valid.
 *  @param input string to be encrypted.
 *  @param public_key public key used to encrypt.
 *  @return the encrypted data or an empty string. */
std::string AsymEncrypt(const std::string &input,
                        const std::string &public_key);

/** Asymmetrically decrypt a string.
 *  Performs asymmetric decryption with a private key using RSA.  It returns an
 *  empty string if the private key is not valid.
 *  @param input string to be decrypted.
 *  @param private_key private key used to encrypt.
 *  @return the decrypted data or an empty string. */
std::string AsymDecrypt(const std::string &input,
                        const std::string &private_key);

/** Asymmetrically sign a string.
 *  Signs data with a private key.  It returns the 512 bit signature or an empty
 *  string if the private key is not valid.
 *  @param input string to be signed.
 *  @param private_key private key used to sign.
 *  @return the signature of the data or an empty string. */
std::string AsymSign(const std::string &input, const std::string &private_key);

/** Asymmetrically verify the signature of a string.
 *  Verifies the signature of data signed with a private key by using the
 *  corresponding public key.
 *  @param input_data the original data that was signed.
 *  @param input_signature signature to be verified.
 *  @param public_key public key used to verify.
 *  @return True if the signature was successfully validated, false
 *  otherwise. */
bool AsymCheckSig(const std::string &input_data,
                  const std::string &input_signature,
                  const std::string &public_key);

/** Compress a string.
 *  Compress a string using gzip.  Compression level must be between 0 and 9
 *  inclusive or function returns an empty string.
 *  @param input string to be compressed.
 *  @param compression_level level of compression.
 *  @return the compressed data or an empty string. */
std::string Compress(const std::string &input,
                     const boost::uint16_t &compression_level);

/** Uncompress a string.
 *  Uncompress a string using gzip.
 *  @param input string to be uncompressed.
 *  @return the uncompressed data or an empty string. */
std::string Uncompress(const std::string &input);


/** Object for managing an RSA key pair.
 *  Object that generates and holds an RSA key pair (private and public keys) of
 *  length given by the user.
 *  @class RsaKeyPair */
class RsaKeyPair {
 public:

  /** Default constructor. */
  RsaKeyPair() : public_key_(), private_key_() {}

  /** Getter.
   *  @return The cryptographic public key. */
  std::string public_key() const { return public_key_; }

  /** Getter.
   *  @return The cryptographic private key. */
  std::string private_key() const { return private_key_; }

  /** Setter.
   *  @param publickey The cryptographic public key. */
  void set_public_key(const std::string &publickey) { public_key_ = publickey; }

  /** Setter.
   *  @param privatekey The cryptographic private key. */
  void set_private_key(const std::string &privatekey) {
    private_key_ = privatekey;
  }

  /** Sets the keys as empty strings. */
  void ClearKeys() {
    public_key_.clear();
    private_key_.clear();
  }

  /** Generates a pair of RSA keys of given size.
   *  @param key_size size in bits of the keys. */
  void GenerateKeys(const boost::uint16_t &key_size);

 private:
  std::string public_key_;
  std::string private_key_;
};

}   // namespace crypto

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_COMMON_CRYPTO_H_
