#pragma once
// An in-memory filesystem with the parts of the ESP32 fs::FS API that MeshCore uses

#include <map>
#include <memory>
#include <string>
#include <vector>
#include "Stream.h"

namespace fs {

class File : public Stream {
  std::shared_ptr<std::vector<uint8_t>> _data;
  size_t _pos = 0;
public:
  File() { }
  explicit File(std::shared_ptr<std::vector<uint8_t>> data) : _data(data) { }
  explicit operator bool() const { return (bool) _data; }
  int available() override { return _data ? (int) (_data->size() - _pos) : 0; }
  int read() override { return available() > 0 ? (*_data)[_pos++] : -1; }
  int peek() override { return available() > 0 ? (*_data)[_pos] : -1; }
  size_t read(uint8_t* buf, size_t len) {
    size_t n = 0;
    while (n < len && available() > 0) buf[n++] = (*_data)[_pos++];
    return n;
  }
  size_t write(uint8_t b) override { if (!_data) return 0; _data->push_back(b); return 1; }
  size_t write(const uint8_t* buf, size_t len) override {
    if (!_data) return 0;
    _data->insert(_data->end(), buf, buf + len);
    return len;
  }
  size_t size() const { return _data ? _data->size() : 0; }
  void close() { _data.reset(); }
};

class FS {
  std::map<std::string, std::shared_ptr<std::vector<uint8_t>>> _files;
public:
  bool exists(const char* path) { return _files.count(path) > 0; }
  bool remove(const char* path) { return _files.erase(path) > 0; }
  bool mkdir(const char*) { return true; }
  File open(const char* path, const char* mode = "r", bool create = false) {
    if (mode[0] == 'w') {
      auto data = std::make_shared<std::vector<uint8_t>>();
      _files[path] = data;
      return File(data);
    }
    (void) create;
    auto it = _files.find(path);
    return it == _files.end() ? File() : File(it->second);
  }
};

}  // namespace fs

using fs::File;
