#include "src/set1.h"

#include <algorithm>
#include <unordered_map>

#include "gtest/gtest.h"

#include "src/crypto.h"
#include "src/util.h"

TEST(Set1, HexToBase64) {
  std::string hex =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e"
      "6f7573206d757368726f6f6d";
  std::string expected =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  EXPECT_EQ(expected, ToBase64(FromHex(hex)));
}

TEST(set1, FromBase64) {
  std::vector<uint8_t> result;
  ASSERT_TRUE(FromBase64("c3VyZS4=", &result));
  EXPECT_EQ(ToBytes("sure."), result);
}

TEST(Set1, FixedXor) {
  std::string input_a = "1c0111001f010100061a024b53535009181c";
  std::string input_b = "686974207468652062756c6c277320657965";

  std::string expected = "746865206b696420646f6e277420706c6179";

  EXPECT_EQ(FromHex(expected), FixedXor(FromHex(input_a), FromHex(input_b)));
}

TEST(Set1, DISABLED_DetectSingleCharXor) {
  std::string input =
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  uint8_t key = DetectSingleCharXor(FromHex(input));
  auto decoded_input = XorWithSingleByte(FromHex(input), key);
  FAIL() << std::string((const char*)decoded_input.data(),
                        decoded_input.size());
}

TEST(Set1, RepeatingKeyXor) {
  std::string input =
      "Burning 'em, if you ain't quick and nimble\n"
      "I go crazy when I hear a cymbal";
  std::string key = "ICE";

  std::string expected =
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765"
      "272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27"
      "282f";
  EXPECT_EQ(FromHex(expected), RepeatingKeyXor(ToBytes(input), ToBytes(key)));
}

TEST(Set1, HammingDistance) {
  std::string string_a = "this is a test";
  ;
  std::string string_b = "wokka wokka!!!";

  EXPECT_EQ(37, BinaryHammingDistance(ToBytes(string_a), ToBytes(string_b)));
}

TEST(set1, DISABLED_DetectRepeatingKey) {
  std::string content = ReadFileToString("data/6.txt");
  content.erase(std::remove(content.begin(), content.end(), '\n'),
                content.end());

  std::vector<uint8_t> data;
  ASSERT_TRUE(FromBase64(content, &data));
  std::vector<std::pair<int, double>> distances;
  for (int key_size = 2; key_size < 40; ++key_size) {
    int distance1 = BinaryHammingDistance(
        std::vector<uint8_t>{data.begin(), data.begin() + key_size},
        std::vector<uint8_t>{data.begin() + key_size,
                             data.begin() + 2 * key_size});
    int distance2 = BinaryHammingDistance(
        std::vector<uint8_t>{data.begin() + key_size,
                             data.begin() + 2 * key_size},
        std::vector<uint8_t>{data.begin() + 2 * key_size,
                             data.begin() + 3 * key_size});
    int distance3 = BinaryHammingDistance(
        std::vector<uint8_t>{data.begin() + 2 * key_size,
                             data.begin() + 3 * key_size},
        std::vector<uint8_t>{data.begin() + 3 * key_size,
                             data.begin() + 4 * key_size});
    double avg_distance =
        static_cast<double>(distance1 + distance2 + distance3) / 3;

    distances.emplace_back(key_size, avg_distance / key_size);
  }

  std::sort(
      distances.begin(), distances.end(),
      [](const std::pair<int, double>& a, const std::pair<int, double>& b) {
        return a.second < b.second;
      });

  // This index is chosen emprically by looking at the output of decoding.
  int index = 2;
  int best_key_size = distances[index].first;

  std::vector<uint8_t> key(best_key_size);
  for (int i = 0; i < best_key_size; ++i) {
    auto transposed_data = GetEqualDistanceBytes(data, i, best_key_size);
    key[i] = DetectSingleCharXor(transposed_data);
  }

  auto decoded_data = RepeatingKeyXor(data, key);

  FAIL() << best_key_size << '\n'
         << std::string(decoded_data.begin(), decoded_data.end());
}

TEST(set1, DISABLED_DecodeAes128Ecb) {
  std::string content = ReadFileToString("data/7.txt");
  content.erase(std::remove(content.begin(), content.end(), '\n'),
                content.end());

  std::vector<uint8_t> data;
  ASSERT_TRUE(FromBase64(content, &data));

  std::vector<uint8_t> decrypted_data;
  ASSERT_TRUE(
      DecryptAes128Ecb(data, ToBytes("YELLOW SUBMARINE"), &decrypted_data));

  FAIL() << std::string(decrypted_data.begin(), decrypted_data.end());
}

TEST(Set1, DISABLED_DetectAes128Ecb) {
  auto lines = Split(ReadFileToString("data/8.txt"), '\n', SkipEmpty());

  size_t index_of_max_frequency = -1;
  int max_frequency = -1;

  for (size_t i = 0; i < lines.size(); ++i) {
    const std::string& line = lines[i];
    // 32 symbols = (2 hex symbols per byte) * (16 bytes per AES128 block)
    ASSERT_TRUE(line.size() % 32 == 0);

    std::unordered_map<std::string, int> frequences;
    for (size_t i = 0; i < lines.size(); i += 32) {
      frequences[line.substr(i, 32)] += 1;
    }

    auto it = std::max_element(frequences.begin(), frequences.end(),
                               [](const auto& left, const auto& right) {
                                 return left.second < right.second;
                               });

    if (max_frequency < it->second) {
      max_frequency = it->second;
      index_of_max_frequency = i;
    }
  }

  FAIL() << "Line number " + std::to_string(index_of_max_frequency) +
                " with frequency of a block equal " +
                std::to_string(max_frequency) + ": " +
                lines[index_of_max_frequency];
}
