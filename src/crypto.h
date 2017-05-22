#ifndef SRC_CRYPTO_H_
#define SRC_CRYPTO_H_

#include <cstdint>

#include <vector>

bool DecryptAes128Ecb(const std::vector<uint8_t>& input,
                      const std::vector<uint8_t>& key,
                      std::vector<uint8_t>* decrypted_data);

#endif  // SRC_CRYPTO_H_
