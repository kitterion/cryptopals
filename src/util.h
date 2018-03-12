#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

#include <string>
#include <vector>

std::string ReadFileToString(const std::string& filename);

struct AllowEmpty {
  bool operator()(const std::string &) const { return true; }
};

struct SkipEmpty {
  bool operator()(const std::string &s) const { return !s.empty(); }
};

// Split a string on a character using a predicate. Predicate is a functor
// that should return true if a string should be kept in the result.
template <typename Predicate>
std::vector<std::string> Split(const std::string &to_split, char delimiter,
                               Predicate p) {
  std::vector<std::string> ret;

  size_t start = 0;
  size_t end = to_split.find_first_of(delimiter);

  while (end != std::string::npos) {
    const std::string s = to_split.substr(start, end - start);
    if (p(s)) {
      ret.emplace_back(std::move(s));
    }
    start = end + 1;
    end = to_split.find_first_of(delimiter, start);
  }

  const std::string s = to_split.substr(start);
  if (p(s)) {
    ret.emplace_back(std::move(s));
  }

  return ret;
}

// Split by default keeps empty strings, so splitting "1,,2" on a comma will
// yield {"1", "", "2"}.
inline std::vector<std::string> Split(const std::string &to_split,
                                      char delimiter) {
  return Split(to_split, delimiter, AllowEmpty());
}

#endif  // SRC_UTIL_H_
