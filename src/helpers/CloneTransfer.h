#pragma once
// Copies one radio onto another nearby (key, contacts, channels, settings) over a fast point-to-point
// link away from the mesh: FLRC on the LR2021. See docs/clone_takeover.md.
//
// The receiving radio shows a 6-digit code; the user types it on the sending radio. The radios run
// CPace (draft-irtf-cfrg-cpace, X25519/SHA-512; helpers/CPace) with the code as the password, so a
// listener can't test guesses offline and an impostor gets one guess (either side gives up on a wrong
// one). Both confirm the key (CPace section 10.4 tags) before anything moves. Data is encrypted with
// ChaCha20-Poly1305 (RFC 8439) under a key from HKDF-SHA256 (RFC 5869) of CPace's ISK. Handshake
// frames heard weaker than MIN_RSSI are ignored: the radios must be next to each other.
//
//   sender (initiator)                     receiver (responder)
//   HELLO   (sid, Ya)                   ->
//                                       <- HELLO_ACK (Yb, Tb)
//   CONFIRM (Ta)                        ->
//   DATA x up to WINDOW, POLL           ->
//                                       <- ACK (next chunk needed, which of the window it has)
//   ... until every chunk is acknowledged ...
//   DONE (length, SHA-256 of it all)    ->
//                                       <- DONE_ACK (ok / bad)
//
// The receiver keeps a window of chunks in RAM and writes them out (Sink) when the POLL comes, so
// flash writes never overlap a burst. Plain logic: no radio, clock or file access, for host tests.

#include <stdint.h>
#include <stddef.h>
#include <SHA256.h>

namespace clonelink {

static const int CHUNK = 200;           // data bytes per DATA frame
static const int WINDOW = 32;           // chunks sent before each POLL
static const int TAG_LEN = 16;          // Poly1305 tag per encrypted frame
static const int HDR_LEN = 7;           // 'C' 'L' type sid[4]
static const int MAX_FRAME = HDR_LEN + 2 + CHUNK + TAG_LEN;
static const int SID_LEN = 16;          // CPace session id
static const int POINT_LEN = 32;        // CPace shares (X25519)
static const int CONFIRM_LEN = 16;      // CPace key-confirmation tags, truncated HMAC-SHA-512
static const int CODE_LEN = 6;          // digits
static const float MIN_RSSI = -70.0f;   // dBm: "next to each other" (default; setMinRssi)

enum Type : uint8_t { T_HELLO = 1, T_HELLO_ACK, T_DATA, T_POLL, T_ACK, T_DONE, T_DONE_ACK, T_ABORT, T_CONFIRM };

enum State : uint8_t { IDLE = 0, WAITING, TRANSFER, FINISHING, DONE_OK, FAILED };

enum Fail : uint8_t {
  F_NONE = 0,
  F_NO_PEER,       // nobody answered (or nobody came) in time
  F_TOO_FAR,       // only heard the other radio weakly
  F_WRONG_CODE,
  F_LOST,          // the link dropped mid-transfer
  F_READ,          // sender couldn't read its files
  F_WRITE,         // receiver couldn't store them
  F_BAD_DATA,      // the copy didn't check out at the end
  F_ABORTED,       // stopped by the user (either end)
};

const char* failText(Fail f);

struct Io {
  virtual bool send(const uint8_t* frame, int len) = 0;
  virtual void random(uint8_t* buf, int len) = 0;   // cryptographic randomness
  virtual ~Io() { }
};

struct Source {   // the sender's bytes
  virtual uint32_t size() = 0;
  virtual int read(uint32_t off, uint8_t* buf, int len) = 0;   // returns len, or < 0
  virtual ~Source() { }
};

struct Sink {     // where the receiver's bytes go, in order
  virtual bool write(const uint8_t* buf, int len) = 0;
  virtual ~Sink() { }
};

class Session {
public:
  Session() { reset(); }
  void reset();

  // code: the receiver's 6 digits
  void startSend(Io* io, Source* src, const char* code, uint32_t now);
  // code: shown to the user; waits up to wait_ms for a sender
  void startReceive(Io* io, Sink* sink, const char* code, uint32_t now, uint32_t wait_ms);
  void onFrame(const uint8_t* f, int len, float rssi, uint32_t now);
  void tick(uint32_t now);
  void abort(uint32_t now);
  void setMinRssi(float dbm) { _min_rssi = dbm; }   // after start*()

  State state() const { return _state; }
  Fail fail() const { return _fail; }
  bool sending() const { return _sender; }
  bool active() const { return _state == WAITING || _state == TRANSFER || _state == FINISHING; }
  uint32_t total() const { return _total; }       // bytes (receiver: once DONE checks out)
  uint32_t done() const { return _sender ? (uint32_t)_base * CHUNK : _written; }
  uint32_t resent() const { return _resent; }
  uint32_t startedAt() const { return _t_link; }   // when the handshake finished
  uint32_t finishedAt() const { return _t_done; }
  float weakest() const { return _weak_rssi; }     // the strongest frame heard below MIN_RSSI (0 = none)
  float peerRssi() const { return _peer_rssi; }

private:
  Io* _io;
  Source* _src;
  Sink* _sink;
  bool _sender;
  State _state;
  Fail _fail;
  char _code[CODE_LEN + 1];
  uint32_t _sid;              // first 4 bytes of _sid_full: in every frame's header
  uint8_t _sid_full[SID_LEN];
  uint8_t _y[32];             // our CPace scalar
  uint8_t _Ya[POINT_LEN], _Yb[POINT_LEN];
  uint8_t _isk[64];
  uint8_t _key[32];           // ChaCha20-Poly1305, sender to receiver
  bool _confirmed;            // receiver: the sender's CPace tag checked out
  uint32_t _t_start, _t_deadline, _t_last_tx, _t_last_rx, _t_link, _t_done;
  float _weak_rssi, _peer_rssi, _min_rssi;

  // sender
  uint32_t _total;
  uint16_t _chunks, _base;
  uint32_t _acked;            // bit i: chunk _base + i is at the receiver
  uint32_t _sent;             // bit i: chunk _base + i was sent at least once
  bool _need_burst;
  bool _got_ack;              // the receiver has answered a POLL: it has our CONFIRM
  uint8_t _tries;
  uint32_t _resent;

  // receiver
  uint16_t _rbase;
  uint32_t _written;
  uint32_t _have;             // bit i: slot for chunk _rbase + i is filled
  uint8_t _slot_len[WINDOW];
  uint8_t _slots[WINDOW][CHUNK];
  SHA256 _hash;               // of what was written
  uint8_t _done_ack;          // 0xFF = no DONE yet; else the status sent

  void failWith(Fail f, bool tell_peer);
  void header(uint8_t* f, uint8_t type) const;
  bool sendFrame(const uint8_t* f, int len);
  void sendHello();
  void sendHelloAck();
  void sendConfirm();
  bool sendData(uint16_t seq);
  void sendPoll();
  void sendAck();
  void sendDone();
  void sendDoneAck(uint8_t status);
  bool deriveKeys(const uint8_t* peer_Y);
  void tag(uint8_t* out, bool sender_side) const;
  void wipe();
  bool seal(uint8_t* f, int hdr_len, uint32_t seq, const uint8_t* plain, int n);   // ct + tag after hdr
  bool open(const uint8_t* f, int hdr_len, uint32_t seq, int ct_len, uint8_t* plain);
  void onSender(const uint8_t* f, int len, float rssi, uint32_t now);
  void onReceiver(const uint8_t* f, int len, float rssi, uint32_t now);
  bool flush();
};

// ---- bundle: several files in one byte stream ----
// "CLB1", count, then per file: id, size (u32 LE; 0xFFFFFFFF = this radio has none), then the files'
// bytes in that order.

static const int MAX_FILES = 12;
static const uint32_t ABSENT = 0xFFFFFFFFUL;

struct Files {
  virtual int32_t fileSize(uint8_t id) = 0;                     // -1 = none
  virtual int fileRead(uint8_t id, uint32_t off, uint8_t* buf, int len) = 0;
  virtual bool fileBegin(uint8_t id, int32_t size) = 0;         // -1: the sender has none
  virtual bool fileWrite(uint8_t id, const uint8_t* buf, int len) = 0;
  virtual bool fileEnd(uint8_t id) = 0;
  virtual ~Files() { }
};

class BundleSource : public Source {
public:
  bool init(Files* files, const uint8_t* ids, int n);   // false: too many
  uint32_t size() override { return _size; }
  int read(uint32_t off, uint8_t* buf, int len) override;
private:
  Files* _files;
  int _n;
  uint8_t _ids[MAX_FILES];
  uint32_t _sizes[MAX_FILES];
  uint8_t _head[5 + 5 * MAX_FILES];
  int _head_len;
  uint32_t _size;
};

class BundleSink : public Sink {
public:
  void init(Files* files, uint32_t max_file);
  bool write(const uint8_t* buf, int len) override;
  bool complete() const { return _phase == 3; }
private:
  Files* _files;
  uint32_t _max_file;
  uint8_t _phase;     // 0 header, 1 entries, 2 files, 3 complete
  uint8_t _head[5 + 5 * MAX_FILES];
  int _head_len, _need;
  int _n, _cur;
  uint8_t _ids[MAX_FILES];
  uint32_t _sizes[MAX_FILES];
  uint32_t _left;
  bool nextFile();
};

}  // namespace clonelink
