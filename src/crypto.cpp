#include "src/crypto.h"

#include <openssl/evp.h>

#include <memory>

#include "src/macros.h"

namespace {
using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
CipherContext GetNewCipherContext() {
  return CipherContext(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
}
}

bool DecryptAes128Ecb(const std::vector<uint8_t>& input,
                      const std::vector<uint8_t>& key,
                      std::vector<uint8_t>* decrypted_data) {
  CHECK(key.size() == 16);

  auto context = GetNewCipherContext();

  int result = EVP_DecryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr,
                                  key.data(), nullptr);
  if (!result) {
    return false;
  }

  // Recovered text contracts upto BLOCK_SIZE.
  std::vector<uint8_t> out(input.size());
  int out_length;
  result = EVP_DecryptUpdate(context.get(), out.data(), &out_length,
                             input.data(), input.size());
  if (!result) {
    return false;
  }

  int out_length2;
  result =
      EVP_DecryptFinal_ex(context.get(), out.data() + out_length, &out_length2);
  if (!result) {
    return false;
  }

  out.resize(out_length + out_length2);

  (*decrypted_data) = std::move(out);

  return true;
}
