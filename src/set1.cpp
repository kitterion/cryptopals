#include "src/set1.h"

#include <algorithm>
#include <limits>

#include "src/macros.h"

namespace internal {
uint8_t FromHexChar(char c) {
  if ('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  }
  if ('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  }
  if ('0' <= c && c <= '9') {
    return c - '0';
  }
  DCHECK(false);
}

static double english_frequencies[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074};

double ScoreData(const std::vector<uint8_t>& input) {
  double frequences[256] = {0.0};
  for (uint8_t element : input) {
    frequences[element] += 1;
  }
  for (double& f : frequences) {
    f /= input.size();
  }

  double score = 0.0;
  for (int i = 0; i < 256; ++i) {
    if ('A' <= i && i <= 'Z') {
      score += std::abs(frequences[i] - english_frequencies[i - 'A']);
    } else if ('a' <= i && i <= 'z') {
      score += std::abs(frequences[i] - english_frequencies[i - 'a']);
    } else {
      score += frequences[i];
    }
  }
  return score;
}
}

std::vector<uint8_t> ToBytes(const std::string& str) {
  return std::vector<uint8_t>(str.begin(), str.end());
}

std::vector<uint8_t> FromHex(const std::string& str) {
  DCHECK(str.size() % 2 == 0);
  std::vector<uint8_t> result(str.size() / 2);

  for (size_t i = 0; i < str.size(); i += 2) {
    uint8_t high = internal::FromHexChar(str[i]);
    uint8_t low = internal::FromHexChar(str[i + 1]);
    result[i / 2] = high * 16 + low;
  }

  return result;
}

std::string ToBase64(const std::vector<uint8_t>& data) {
  static char base64_set[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string result;
  result.reserve(data.size() * 4 / 3);
  for (size_t i = 0; i < data.size() / 3; ++i) {
    result.push_back(base64_set[data[3 * i] >> 2]);
    result.push_back(
        base64_set[(data[3 * i] << 4 | data[3 * i + 1] >> 4) & 077]);
    result.push_back(
        base64_set[(data[3 * i + 1] << 2 | data[3 * i + 2] >> 6) & 077]);
    result.push_back(base64_set[data[3 * i + 2] & 077]);
  }

  if (data.size() % 3 == 1) {
    uint8_t last = data[data.size() - 1];
    result.push_back(base64_set[last >> 2]);
    result.push_back(base64_set[(last << 4) & 077]);
    result.push_back('=');
    result.push_back('=');
  }
  if (data.size() % 3 == 2) {
    uint8_t second_to_last = data[data.size() - 2];
    uint8_t last = data[data.size() - 1];
    result.push_back(base64_set[second_to_last >> 2]);
    result.push_back(base64_set[(second_to_last << 4 | last >> 4) & 077]);
    result.push_back(base64_set[(last << 2) & 077]);
    result.push_back('=');
  }

  return result;
}

bool FromBase64(const std::string& input, std::vector<uint8_t>* decoded) {
  if (input.size() % 4 != 0) {
    return false;
  }

  static const std::vector<int> t = [] {
    std::vector<int> t(256, -1);
    for (int i = 0; i < 64; i++)
      t["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] =
          i;
      t['='] = 0;
    return t;
  }();

  std::vector<uint8_t> out;
  int val = 0, valb = -8;
  for (uint8_t c : input) {
    if (t[c] == -1) {
      return false;
    }
    if (c == '=') {
      if (out.back() == '\0') {
        out.erase(out.end() - 1);
      }
      break;
    }

    val = (val << 6) + t[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back((val >> valb) & 0xFF);
      valb -= 8;
    }
  }

  (*decoded) = std::move(out);

  return true;
}

std::vector<uint8_t> FixedXor(const std::vector<uint8_t>& input_a,
                              const std::vector<uint8_t>& input_b) {
  DCHECK(input_a.size() == input_b.size());
  std::vector<uint8_t> result(input_a.size());
  for (size_t i = 0; i < input_a.size(); ++i) {
    result[i] = input_a[i] ^ input_b[i];
  }

  return result;
}

std::vector<uint8_t> XorWithSingleByte(const std::vector<uint8_t>& input,
                                       uint8_t xor_byte) {
  std::vector<uint8_t> result(input.size());
  for (size_t i = 0; i < input.size(); ++i) {
    result[i] = input[i] ^ xor_byte;
  }

  return result;
}

uint8_t DetectSingleCharXor(const std::vector<uint8_t>& input) {
  int best_i = -1;
  double best_score = std::numeric_limits<double>::infinity();
  for (int i = 0; i < 256; ++i) {
    double score = internal::ScoreData(XorWithSingleByte(input, i));
    if (score < best_score) {
      best_score = score;
      best_i = i;
    }
  }

  return best_i;
}

std::vector<uint8_t> RepeatingKeyXor(const std::vector<uint8_t>& input,
                                     const std::vector<uint8_t>& key) {
  std::vector<uint8_t> result(input.size());

  int key_index = 0;
  for (size_t i = 0; i < input.size(); ++i) {
    result[i] = input[i] ^ key[key_index];
    key_index = (key_index + 1) % key.size();
  }

  return result;
}

int CountBitsInAByte(uint8_t byte) {
  static const uint8_t table[16] = {0, 1, 1, 2, 1, 2, 2, 3,
                                    1, 2, 2, 3, 2, 3, 3, 4};
  return table[byte & 0x0F] + table[byte >> 4];
}

int BinaryHammingDistance(const std::vector<uint8_t>& input_a,
                          const std::vector<uint8_t>& input_b) {
  DCHECK(input_a.size() == input_b.size());

  int count = 0;
  for (size_t i = 0; i < input_a.size(); ++i) {
    count += CountBitsInAByte(input_a[i] ^ input_b[i]);
  }
  return count;
}

std::vector<uint8_t> GetEqualDistanceBytes(const std::vector<uint8_t>& data,
                                           int start, int step) {
  std::vector<uint8_t> result;
  result.reserve((data.size() - start) / step);
  for (size_t i = start; i < data.size(); i += step) {
    result.push_back(data[i]);
  }
  return result;
}
