#ifndef SRC_SET1_H_
#define SRC_SET1_H_

#include <string>
#include <vector>

std::vector<uint8_t> ToBytes(const std::string& str);

std::vector<uint8_t> FromHex(const std::string& str);
std::string ToBase64(const std::vector<uint8_t>& data);
bool FromBase64(const std::string& input, std::vector<uint8_t>* decoded);

std::vector<uint8_t> FixedXor(const std::vector<uint8_t>& input_a,
                              const std::vector<uint8_t>& input_b);

std::vector<uint8_t> XorWithSingleByte(const std::vector<uint8_t>& input,
                                       uint8_t xor_byte);
uint8_t DetectSingleCharXor(const std::vector<uint8_t>& input);

std::vector<uint8_t> RepeatingKeyXor(const std::vector<uint8_t>& input,
                                     const std::vector<uint8_t>& key);

int BinaryHammingDistance(const std::vector<uint8_t>& input_a,
                          const std::vector<uint8_t>& input_b);
std::vector<uint8_t> GetEqualDistanceBytes(const std::vector<uint8_t>& data,
                                           int start, int step);
#endif  // SRC_SET1_H_
