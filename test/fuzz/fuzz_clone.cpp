// Fuzzes copying a radio (src/helpers/CloneTransfer, CPace): a real sender and receiver talk while
// the input decides what happens to each frame in flight (deliver, drop, corrupt, repeat, cut, or
// inject the input's own bytes), and the bundle parser gets the input as a byte stream.
#include <helpers/CloneTransfer.h>
#include <deque>
#include <map>
#include <vector>
#include <string.h>

using namespace clonelink;

namespace {

struct Fuzz {
  const uint8_t* d; size_t n, i;
  uint8_t byte() { return i < n ? d[i++] : 0; }
  bool more() const { return i < n; }
};

struct Pipe : Io {
  std::deque<std::vector<uint8_t>>* out;
  uint32_t seed;
  bool send(const uint8_t* f, int len) override {
    if (out->size() < 256) out->push_back(std::vector<uint8_t>(f, f + len));
    return true;
  }
  void random(uint8_t* buf, int len) override {
    for (int i = 0; i < len; i++) { seed = seed * 1103515245u + 12345u; buf[i] = (uint8_t)(seed >> 16); }
  }
};

struct Files_ : Files {
  std::map<uint8_t, std::vector<uint8_t>> have, got;
  int32_t fileSize(uint8_t id) override { auto it = have.find(id); return it == have.end() ? -1 : (int32_t)it->second.size(); }
  int fileRead(uint8_t id, uint32_t off, uint8_t* buf, int len) override {
    auto& v = have[id];
    if (off + len > v.size()) return -1;
    memcpy(buf, v.data() + off, len);
    return len;
  }
  bool fileBegin(uint8_t id, int32_t) override { got[id].clear(); return true; }
  bool fileWrite(uint8_t id, const uint8_t* buf, int len) override {
    if (got[id].size() + len > 100000) return false;
    got[id].insert(got[id].end(), buf, buf + len);
    return true;
  }
  bool fileEnd(uint8_t) override { return true; }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // the bundle parser alone, on the raw input
  {
    Files_ f;
    BundleSink k;
    k.init(&f, 4096);
    k.write(data, (int)size);
  }

  Fuzz in = { data, size, 0 };
  std::deque<std::vector<uint8_t>> to_a, to_b;
  Pipe a, b;
  a.out = &to_b; a.seed = 7;
  b.out = &to_a; b.seed = 9;
  Files_ src_files, dst_files;
  src_files.have[1] = std::vector<uint8_t>(96, 0x11);
  src_files.have[2] = std::vector<uint8_t>(700, 0x22);
  src_files.have[3] = std::vector<uint8_t>(9000, 0x33);
  const uint8_t ids[] = { 1, 2, 3, 4 };
  BundleSource src;
  src.init(&src_files, ids, 4);
  BundleSink sink;
  sink.init(&dst_files, 1 << 16);
  static Session tx, rx;   // large: keep them off the stack
  const char* code = in.byte() & 1 ? "123456" : "654321";
  rx.startReceive(&b, &sink, "123456", 0, 60000);
  tx.startSend(&a, &src, code, 0);
  uint32_t now = 0;
  for (int step = 0; step < 3000 && (tx.active() || rx.active()); step++) {
    for (int side = 0; side < 2; side++) {
      auto& q = side ? to_a : to_b;
      Session& s = side ? tx : rx;
      if (q.empty()) continue;
      std::vector<uint8_t> f = q.front();
      q.pop_front();
      uint8_t op = in.more() ? in.byte() : 0;
      float rssi = -40;
      switch (op & 7) {
        case 1: continue;                                           // dropped
        case 2: if (!f.empty()) f[in.byte() % f.size()] ^= (uint8_t)(1 << (op >> 5)); break;
        case 3: q.push_front(f); break;                             // delivered twice
        case 4: f.resize(in.byte() % (f.size() + 1)); break;        // cut short
        case 5: {                                                   // the input's own bytes instead
          size_t len = in.byte();
          f.clear();
          while (len-- && in.more()) f.push_back(in.byte());
          break;
        }
        case 6: rssi = -60.0f - (in.byte() & 63); break;            // weak
        default: break;
      }
      s.onFrame(f.data(), (int)f.size(), rssi, now);
    }
    tx.tick(now);
    rx.tick(now);
    now += 1 + (in.more() ? in.byte() % 50 : 50);
  }
  if (tx.state() == DONE_OK && rx.state() == DONE_OK) {
    // whatever happened in flight, a finished copy must be exact
    if (dst_files.got[3] != src_files.have[3] || dst_files.got[2] != src_files.have[2]) __builtin_trap();
  }
  tx.reset();
  rx.reset();
  return 0;
}
