#include "src/util.h"

#include <fstream>
#include <streambuf>

std::string ReadFileToString(const std::string& filename) {
  std::ifstream t(filename);
  return std::string{std::istreambuf_iterator<char>(t),
                     std::istreambuf_iterator<char>()};
}
