// Clone transfer (src/helpers/CloneTransfer): two sessions over a simulated link that loses frames.
#include <gtest/gtest.h>
#include <helpers/CloneTransfer.h>
#include <deque>
#include <map>
#include <vector>
#include <string.h>

using namespace clonelink;

struct Frame { std::vector<uint8_t> b; };

// One end of the link. Frames go into the other end's queue, unless the loss pattern drops them.
struct End : Io {
  uint32_t seed = 1;
  std::deque<Frame>* out = nullptr;
  int sent = 0;
  int drop_every = 0;       // drop every Nth frame sent (0 = none)
  int drop_type = 0;        // only frames of this type (0 = any)
  bool deaf = false;        // drop everything
  bool send(const uint8_t* f, int len) override {
    sent++;
    if (deaf) return true;
    if (drop_every && (drop_type == 0 || f[2] == drop_type) && sent % drop_every == 0) return true;
    out->push_back(Frame{ std::vector<uint8_t>(f, f + len) });
    return true;
  }
  void random(uint8_t* buf, int len) override {
    for (int i = 0; i < len; i++) { seed = seed * 1103515245u + 12345u; buf[i] = (uint8_t)(seed >> 16); }
  }
};

struct MemFiles : Files {
  std::map<uint8_t, std::vector<uint8_t>> have;        // sender's files
  std::map<uint8_t, std::vector<uint8_t>> got;         // receiver's
  std::map<uint8_t, bool> absent;                      // receiver: sender had none
  std::map<uint8_t, bool> open;
  int fail_write_after = -1;                           // fail the Nth write
  int writes = 0;
  int32_t fileSize(uint8_t id) override { auto it = have.find(id); return it == have.end() ? -1 : (int32_t)it->second.size(); }
  int fileRead(uint8_t id, uint32_t off, uint8_t* buf, int len) override {
    auto& v = have[id];
    if (off + len > v.size()) return -1;
    memcpy(buf, &v[off], len);
    return len;
  }
  bool fileBegin(uint8_t id, int32_t size) override {
    if (size < 0) absent[id] = true; else got[id].clear();
    open[id] = true;
    return true;
  }
  bool fileWrite(uint8_t id, const uint8_t* buf, int len) override {
    if (fail_write_after >= 0 && writes++ >= fail_write_after) return false;
    if (!open[id]) return false;
    got[id].insert(got[id].end(), buf, buf + len);
    return true;
  }
  bool fileEnd(uint8_t id) override { open[id] = false; return true; }
};

static std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
  std::vector<uint8_t> v(n);
  uint32_t x = seed * 2654435761u + 1;
  for (size_t i = 0; i < n; i++) { x = x * 1103515245u + 12345u; v[i] = (uint8_t)(x >> 16); }
  return v;
}

struct Rig {
  End a, b;                       // a sends, b receives
  std::deque<Frame> to_a, to_b;
  MemFiles src_files, dst_files;
  BundleSource src;
  BundleSink sink;
  Session tx, rx;
  float rssi_at_b = -40, rssi_at_a = -40;
  uint32_t now = 1000;

  Rig() {
    a.seed = 0xA1;
    b.seed = 0xB2;
    a.out = &to_b;
    b.out = &to_a;
  }
  void start(const char* tx_code = "123456", const char* rx_code = "123456") {
    const uint8_t ids[] = { 1, 2, 3, 4 };
    ASSERT_TRUE(src.init(&src_files, ids, 4));
    sink.init(&dst_files, 1 << 20);
    rx.startReceive(&b, &sink, rx_code, now, 60000);
    tx.startSend(&a, &src, tx_code, now);
  }
  // one frame at a time, until the receiver has written n bytes
  void runUntilBytes(uint32_t n) {
    for (int i = 0; i < 100000 && rx.done() < n && tx.active(); i++) {
      if (!to_b.empty()) { Frame f = to_b.front(); to_b.pop_front(); rx.onFrame(f.b.data(), f.b.size(), rssi_at_b, now); }
      else if (!to_a.empty()) { Frame f = to_a.front(); to_a.pop_front(); tx.onFrame(f.b.data(), f.b.size(), rssi_at_a, now); }
      else { tx.tick(now); rx.tick(now); now++; }
    }
  }
  // runs both ends, 1 ms a step, until both are done or limit_ms passes
  void run(uint32_t limit_ms = 60000) {
    uint32_t end = now + limit_ms;
    while ((int32_t)(now - end) < 0) {
      while (!to_b.empty()) { Frame f = to_b.front(); to_b.pop_front(); rx.onFrame(f.b.data(), f.b.size(), rssi_at_b, now); }
      while (!to_a.empty()) { Frame f = to_a.front(); to_a.pop_front(); tx.onFrame(f.b.data(), f.b.size(), rssi_at_a, now); }
      tx.tick(now);
      rx.tick(now);
      if (!tx.active() && !rx.active() && to_a.empty() && to_b.empty()) break;
      now++;
    }
  }
};

static void addFiles(MemFiles& f) {
  f.have[1] = pattern(96, 1);       // identity
  f.have[2] = pattern(2500, 2);     // prefs
  f.have[3] = pattern(52500, 3);    // contacts
  // 4: none
}

TEST(CloneTransfer, CopiesEverything) {
  Rig r;
  addFiles(r.src_files);
  r.start();
  r.run();
  EXPECT_EQ(r.tx.state(), DONE_OK);
  EXPECT_EQ(r.rx.state(), DONE_OK);
  EXPECT_TRUE(r.sink.complete());
  EXPECT_EQ(r.dst_files.got[1], r.src_files.have[1]);
  EXPECT_EQ(r.dst_files.got[2], r.src_files.have[2]);
  EXPECT_EQ(r.dst_files.got[3], r.src_files.have[3]);
  EXPECT_TRUE(r.dst_files.absent[4]);
  EXPECT_EQ(r.tx.resent(), 0u);
}

TEST(CloneTransfer, LossyLink) {
  Rig r;
  addFiles(r.src_files);
  r.a.drop_every = 7;     // every 7th frame from the sender, of any kind
  r.b.drop_every = 3;     // every 3rd answer
  r.start();
  r.run();
  EXPECT_EQ(r.tx.state(), DONE_OK);
  EXPECT_EQ(r.rx.state(), DONE_OK);
  EXPECT_EQ(r.dst_files.got[3], r.src_files.have[3]);
  EXPECT_GT(r.tx.resent(), 0u);
}

TEST(CloneTransfer, LostDoneAck) {
  Rig r;
  addFiles(r.src_files);
  r.b.drop_every = 1;
  r.b.drop_type = T_DONE_ACK;   // every DONE_ACK lost once...
  r.start();
  // ...so let the first ones go, then the link heals
  for (int i = 0; i < 5000 && r.rx.state() != DONE_OK; i++) {
    r.run(1);
  }
  r.b.drop_every = 0;
  r.run();
  EXPECT_EQ(r.rx.state(), DONE_OK);
  EXPECT_EQ(r.tx.state(), DONE_OK);
}

TEST(CloneTransfer, WrongCode) {
  Rig r;
  addFiles(r.src_files);
  r.start("111111", "123456");
  r.run();
  EXPECT_EQ(r.rx.state(), FAILED);
  EXPECT_EQ(r.rx.fail(), F_WRONG_CODE);
  EXPECT_EQ(r.tx.state(), FAILED);
  EXPECT_EQ(r.tx.fail(), F_WRONG_CODE);
  EXPECT_TRUE(r.dst_files.got.empty());
}

TEST(CloneTransfer, TooFar) {
  Rig r;
  addFiles(r.src_files);
  r.rssi_at_b = -85;
  r.rssi_at_a = -85;
  r.start();
  r.run(30000);
  EXPECT_EQ(r.tx.fail(), F_NO_PEER);  // the receiver never answered a sender that far
  EXPECT_EQ(r.rx.state(), WAITING);   // still waiting for one close enough
  r.run(40000);
  EXPECT_EQ(r.rx.fail(), F_TOO_FAR);  // and says why nobody came
  EXPECT_TRUE(r.dst_files.got.empty());
}

TEST(CloneTransfer, NobodyThere) {
  Rig r;
  addFiles(r.src_files);
  r.a.deaf = true;
  r.start();
  r.run(70000);
  EXPECT_EQ(r.tx.fail(), F_NO_PEER);
  EXPECT_EQ(r.rx.fail(), F_NO_PEER);
}

TEST(CloneTransfer, LinkDropsMidway) {
  Rig r;
  addFiles(r.src_files);
  r.start();
  r.runUntilBytes(10000);   // handshake and a few windows
  ASSERT_EQ(r.tx.state(), TRANSFER);
  r.a.deaf = true;
  r.b.deaf = true;
  r.run(30000);
  EXPECT_EQ(r.tx.fail(), F_LOST);
  EXPECT_EQ(r.rx.fail(), F_LOST);
}

TEST(CloneTransfer, ReceiverCantWrite) {
  Rig r;
  addFiles(r.src_files);
  r.dst_files.fail_write_after = 10;
  r.start();
  r.run();
  EXPECT_EQ(r.rx.fail(), F_WRITE);
  EXPECT_EQ(r.tx.fail(), F_WRITE);
}

TEST(CloneTransfer, StrangerIgnored) {
  // a third radio's frames (other sid, junk) don't disturb the transfer
  Rig r;
  addFiles(r.src_files);
  r.start();
  uint8_t junk[40];
  memset(junk, 0x55, sizeof(junk));
  junk[0] = 'C'; junk[1] = 'L'; junk[2] = T_DATA;
  for (int i = 0; i < 200; i++) {
    r.to_b.push_back(Frame{ std::vector<uint8_t>(junk, junk + sizeof(junk)) });
    r.to_a.push_back(Frame{ std::vector<uint8_t>(junk, junk + sizeof(junk)) });
    r.run(5);
  }
  r.run();
  EXPECT_EQ(r.tx.state(), DONE_OK);
  EXPECT_EQ(r.dst_files.got[3], r.src_files.have[3]);
}

TEST(CloneTransfer, TamperedDataRejected) {
  // a flipped bit in a DATA frame fails its tag; the chunk is sent again
  Rig r;
  addFiles(r.src_files);
  r.start();
  int flipped = 0;
  uint32_t end = r.now + 60000;
  while ((r.tx.active() || r.rx.active()) && (int32_t)(r.now - end) < 0) {
    while (!r.to_b.empty()) {
      Frame f = r.to_b.front(); r.to_b.pop_front();
      if (f.b[2] == T_DATA && flipped < 5 && f.b.size() > 30) { f.b[20] ^= 0x01; flipped++; }
      r.rx.onFrame(f.b.data(), f.b.size(), -40, r.now);
    }
    while (!r.to_a.empty()) { Frame f = r.to_a.front(); r.to_a.pop_front(); r.tx.onFrame(f.b.data(), f.b.size(), -40, r.now); }
    r.tx.tick(r.now); r.rx.tick(r.now);
    r.now++;
  }
  EXPECT_EQ(flipped, 5);
  EXPECT_EQ(r.tx.state(), DONE_OK);
  EXPECT_EQ(r.dst_files.got[3], r.src_files.have[3]);
  EXPECT_GE(r.tx.resent(), 5u);
}

TEST(CloneTransfer, AbortBySender) {
  Rig r;
  addFiles(r.src_files);
  r.start();
  r.runUntilBytes(10000);
  ASSERT_EQ(r.tx.state(), TRANSFER);
  r.tx.abort(r.now);
  r.run();
  EXPECT_EQ(r.tx.fail(), F_ABORTED);
  EXPECT_EQ(r.rx.fail(), F_ABORTED);
}

TEST(CloneBundle, SmallAndEmptyFiles) {
  MemFiles f;
  f.have[7] = {};               // empty
  f.have[9] = { 1, 2, 3 };
  BundleSource s;
  const uint8_t ids[] = { 7, 8, 9 };
  ASSERT_TRUE(s.init(&f, ids, 3));
  EXPECT_EQ(s.size(), 5u + 15u + 3u);
  std::vector<uint8_t> all(s.size());
  ASSERT_EQ(s.read(0, all.data(), all.size()), (int)all.size());
  MemFiles d;
  BundleSink k;
  k.init(&d, 100);
  for (size_t i = 0; i < all.size(); i++) ASSERT_TRUE(k.write(&all[i], 1));   // a byte at a time
  EXPECT_TRUE(k.complete());
  EXPECT_TRUE(d.got[7].empty());
  EXPECT_TRUE(d.absent[8]);
  EXPECT_EQ(d.got[9], f.have[9]);
  uint8_t extra = 0;
  EXPECT_FALSE(k.write(&extra, 1));
}

TEST(CloneBundle, RejectsBadHeaders) {
  MemFiles d;
  BundleSink k;
  k.init(&d, 100);
  const uint8_t bad_magic[] = { 'X', 'L', 'B', '1', 0 };
  EXPECT_FALSE(k.write(bad_magic, sizeof(bad_magic)));
  k.init(&d, 100);
  const uint8_t too_big[] = { 'C', 'L', 'B', '1', 1, 3, 0xE8, 0x03, 0, 0 };   // 1000 bytes > 100
  EXPECT_FALSE(k.write(too_big, sizeof(too_big)));
  k.init(&d, 100);
  const uint8_t dup[] = { 'C', 'L', 'B', '1', 2, 3, 1, 0, 0, 0, 3, 1, 0, 0, 0 };
  EXPECT_FALSE(k.write(dup, sizeof(dup)));
  k.init(&d, 100);
  const uint8_t many[] = { 'C', 'L', 'B', '1', MAX_FILES + 1 };
  EXPECT_FALSE(k.write(many, sizeof(many)));
}

TEST(CloneBundle, ReadOutOfRange) {
  MemFiles f;
  f.have[1] = pattern(10, 4);
  BundleSource s;
  const uint8_t ids[] = { 1 };
  ASSERT_TRUE(s.init(&f, ids, 1));
  uint8_t buf[32];
  EXPECT_EQ(s.read(s.size() - 2, buf, 4), -1);
  EXPECT_EQ(s.read(8, buf, 4), 4);   // header end into the file
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
