#include "CloneTransfer.h"
#include "CPace.h"
#include <ChaChaPoly.h>
#include <HKDF.h>
#include <string.h>

namespace clonelink {

static const uint32_t HELLO_EVERY_MS = 200;
static const uint32_t SEND_WAIT_MS = 20000;   // sender: how long to look for the receiver
static const uint32_t RETRY_MS = 400;         // POLL / DONE without an answer
static const uint8_t MAX_TRIES = 10;
static const uint32_t SILENCE_MS = 10000;     // receiver: nothing heard mid-transfer
static const uint32_t DONE_SEQ = 0xFFFFFFFFUL;

// CPace inputs: channel identifier and associated data (the protocol version, and who is who)
static const uint8_t CI[] = { 'M', 'e', 's', 'h', 'C', 'o', 'r', 'e', ' ', 'c', 'l', 'o', 'n', 'e' };
static const uint8_t AD_A[] = { 'v', '1', ' ', 's', 'e', 'n', 'd', 'e', 'r' };
static const uint8_t AD_B[] = { 'v', '1', ' ', 'r', 'e', 'c', 'e', 'i', 'v', 'e', 'r' };
static const uint8_t HKDF_INFO[] = { 'M', 'e', 's', 'h', 'C', 'o', 'r', 'e', ' ', 'c', 'l', 'o', 'n', 'e', ' ',
                                     'v', '1', ' ', 'd', 'a', 't', 'a' };

const char* failText(Fail f) {
  switch (f) {
    case F_NONE: return "ok";
    case F_NO_PEER: return "no answer: is the other radio waiting (clone receive) and right next to this one?";
    case F_TOO_FAR: return "the other radio is too far away: put them next to each other";
    case F_WRONG_CODE: return "wrong code";
    case F_LOST: return "the link dropped";
    case F_READ: return "couldn't read this radio's files";
    case F_WRITE: return "the receiving radio couldn't store the copy";
    case F_BAD_DATA: return "the copy didn't check out";
    case F_ABORTED: return "stopped";
  }
  return "failed";
}

static void putU16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t getU16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void putU32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint32_t getU32(const uint8_t* p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void Session::reset() {
  _io = NULL; _src = NULL; _sink = NULL;
  _sender = false;
  _state = IDLE;
  _fail = F_NONE;
  memset(_code, 0, sizeof(_code));
  _sid = 0;
  memset(_sid_full, 0, sizeof(_sid_full));
  wipe();
  _t_start = _t_deadline = _t_last_tx = _t_last_rx = _t_link = _t_done = 0;
  _weak_rssi = 0; _peer_rssi = 0; _min_rssi = MIN_RSSI;
  _total = 0; _chunks = 0; _base = 0; _acked = 0; _sent = 0; _need_burst = false; _tries = 0; _resent = 0;
  _got_ack = false;
  _rbase = 0; _written = 0; _have = 0;
  memset(_slot_len, 0, sizeof(_slot_len));
  _done_ack = 0xFF;
}

void Session::wipe() {
  memset(_y, 0, sizeof(_y));
  memset(_Ya, 0, sizeof(_Ya));
  memset(_Yb, 0, sizeof(_Yb));
  memset(_isk, 0, sizeof(_isk));
  memset(_key, 0, sizeof(_key));
  _confirmed = false;
}

// our scalar and share for this session's generator
static void makeShare(Io* io, const char* code, const uint8_t* sid, uint8_t* y, uint8_t* Y) {
  uint8_t g[32];
  cpace::generator(g, (const uint8_t*)code, strlen(code), CI, sizeof(CI), sid, SID_LEN);
  io->random(y, 32);
  cpace::share(Y, y, g);
}

void Session::startSend(Io* io, Source* src, const char* code, uint32_t now) {
  reset();
  _io = io; _src = src; _sender = true;
  strncpy(_code, code ? code : "", CODE_LEN);
  if (io) {
    io->random(_sid_full, SID_LEN);
    _sid = getU32(_sid_full);
    makeShare(io, _code, _sid_full, _y, _Ya);
  }
  _total = src ? src->size() : 0;
  _chunks = (uint16_t)((_total + CHUNK - 1) / CHUNK);
  _t_start = now;
  _t_deadline = now + SEND_WAIT_MS;
  if (!io || !src || _total == 0 || (_total + CHUNK - 1) / CHUNK > 0xFFFF) { _state = FAILED; _fail = F_READ; return; }
  _state = WAITING;
  sendHello();
}

void Session::startReceive(Io* io, Sink* sink, const char* code, uint32_t now, uint32_t wait_ms) {
  reset();
  _io = io; _sink = sink; _sender = false;
  strncpy(_code, code ? code : "", CODE_LEN);
  _t_start = now;
  _t_deadline = now + wait_ms;
  _hash.reset();
  _state = (io && sink) ? WAITING : FAILED;
  if (_state == FAILED) _fail = F_WRITE;
}

void Session::failWith(Fail f, bool tell_peer) {
  if (tell_peer && _io) {
    uint8_t fr[HDR_LEN + 1];
    header(fr, T_ABORT);
    fr[HDR_LEN] = f;
    sendFrame(fr, sizeof(fr));
  }
  _state = FAILED;
  _fail = f;
  wipe();
}

void Session::abort(uint32_t now) {
  if (active()) failWith(F_ABORTED, _state != WAITING || _sender);
}

void Session::header(uint8_t* f, uint8_t type) const {
  f[0] = 'C'; f[1] = 'L'; f[2] = type;
  putU32(&f[3], _sid);
}

bool Session::sendFrame(const uint8_t* f, int len) {
  return _io->send(f, len);
}

// CPace's ISK from our scalar and the peer's share; then the data key (HKDF-SHA256, salt = sid).
// false: the peer's share is a low-order point (CPace: abort).
bool Session::deriveKeys(const uint8_t* peer_Y) {
  if (!cpace::isk(_isk, _y, peer_Y, _sid_full, SID_LEN, _Ya, AD_A, sizeof(AD_A), _Yb, AD_B, sizeof(AD_B))) return false;
  hkdf<SHA256>(_key, sizeof(_key), _isk, sizeof(_isk), _sid_full, SID_LEN, HKDF_INFO, sizeof(HKDF_INFO));
  memset(_y, 0, sizeof(_y));
  return true;
}

// CPace key confirmation (draft section 10.4): Ta for the sender's side, Tb for the receiver's
void Session::tag(uint8_t* out, bool sender_side) const {
  uint8_t full[64];
  if (sender_side) cpace::confirmTag(full, _isk, _sid_full, SID_LEN, _Ya, AD_A, sizeof(AD_A));
  else cpace::confirmTag(full, _isk, _sid_full, SID_LEN, _Yb, AD_B, sizeof(AD_B));
  memcpy(out, full, CONFIRM_LEN);
}

static void makeIv(uint8_t* iv, uint32_t sid, uint32_t seq, bool from_sender) {
  memset(iv, 0, 12);
  putU32(iv, sid);
  putU32(&iv[4], seq);
  iv[8] = from_sender ? 1 : 2;
}

bool Session::seal(uint8_t* f, int hdr_len, uint32_t seq, const uint8_t* plain, int n) {
  ChaChaPoly c;
  uint8_t iv[12];
  makeIv(iv, _sid, seq, _sender);
  if (!c.setKey(_key, sizeof(_key)) || !c.setIV(iv, sizeof(iv))) return false;
  c.addAuthData(f, hdr_len);
  c.encrypt(&f[hdr_len], plain, n);
  c.computeTag(&f[hdr_len + n], TAG_LEN);
  c.clear();
  return true;
}

bool Session::open(const uint8_t* f, int hdr_len, uint32_t seq, int ct_len, uint8_t* plain) {
  ChaChaPoly c;
  uint8_t iv[12];
  makeIv(iv, _sid, seq, !_sender);
  if (!c.setKey(_key, sizeof(_key)) || !c.setIV(iv, sizeof(iv))) return false;
  c.addAuthData(f, hdr_len);
  c.decrypt(plain, &f[hdr_len], ct_len);
  bool ok = c.checkTag(&f[hdr_len + ct_len], TAG_LEN);
  c.clear();
  return ok;
}

// ---- sender ----

void Session::sendHello() {
  uint8_t f[HDR_LEN + SID_LEN + POINT_LEN];
  header(f, T_HELLO);
  memcpy(&f[HDR_LEN], _sid_full, SID_LEN);
  memcpy(&f[HDR_LEN + SID_LEN], _Ya, POINT_LEN);
  sendFrame(f, sizeof(f));
}

void Session::sendConfirm() {
  uint8_t f[HDR_LEN + CONFIRM_LEN];
  header(f, T_CONFIRM);
  tag(&f[HDR_LEN], true);
  sendFrame(f, sizeof(f));
}

bool Session::sendData(uint16_t seq) {
  uint8_t plain[CHUNK];
  uint32_t off = (uint32_t)seq * CHUNK;
  int n = _total - off < (uint32_t)CHUNK ? (int)(_total - off) : CHUNK;
  if (_src->read(off, plain, n) != n) return false;
  uint8_t f[MAX_FRAME];
  header(f, T_DATA);
  putU16(&f[HDR_LEN], seq);
  if (!seal(f, HDR_LEN + 2, seq, plain, n)) return false;
  sendFrame(f, HDR_LEN + 2 + n + TAG_LEN);
  return true;
}

void Session::sendPoll() {
  uint8_t f[HDR_LEN + 2];
  header(f, T_POLL);
  putU16(&f[HDR_LEN], _base);
  sendFrame(f, sizeof(f));
}

void Session::sendDone() {
  uint8_t plain[4 + 32];
  putU32(plain, _total);
  // the whole stream's hash, read back from the files: what the receiver must end up with
  SHA256 h;
  h.reset();
  uint8_t buf[CHUNK];
  for (uint32_t off = 0; off < _total; off += CHUNK) {
    int n = _total - off < (uint32_t)CHUNK ? (int)(_total - off) : CHUNK;
    if (_src->read(off, buf, n) != n) { failWith(F_READ, true); return; }
    h.update(buf, n);
  }
  h.finalize(&plain[4], 32);
  uint8_t f[HDR_LEN + sizeof(plain) + TAG_LEN];
  header(f, T_DONE);
  seal(f, HDR_LEN, DONE_SEQ, plain, sizeof(plain));
  sendFrame(f, sizeof(f));
}

void Session::onSender(const uint8_t* f, int len, float rssi, uint32_t now) {
  uint8_t type = f[2];
  if (_state == WAITING) {
    if (type == T_ABORT && len == HDR_LEN + 1) {   // eg. the receiver already took another radio's try
      failWith(f[HDR_LEN] == F_NONE ? F_ABORTED : (Fail)f[HDR_LEN], false);
      return;
    }
    if (type != T_HELLO_ACK || len != HDR_LEN + POINT_LEN + CONFIRM_LEN) return;
    if (rssi < _min_rssi) {
      if (_weak_rssi == 0 || rssi > _weak_rssi) _weak_rssi = rssi;
      return;
    }
    memcpy(_Yb, &f[HDR_LEN], POINT_LEN);
    uint8_t want[CONFIRM_LEN];
    if (!deriveKeys(_Yb)) { failWith(F_WRONG_CODE, true); return; }
    tag(want, false);
    // a wrong tag: the other radio has a different code (or isn't the one). One guess only.
    if (!cpace::equal(want, &f[HDR_LEN + POINT_LEN], CONFIRM_LEN)) { failWith(F_WRONG_CODE, true); return; }
    _peer_rssi = rssi;
    _state = TRANSFER;
    _t_link = now;
    _t_last_rx = now;
    _base = 0; _acked = 0; _sent = 0;
    _need_burst = true;
    return;
  }
  if (type == T_ABORT && len == HDR_LEN + 1) {
    Fail why = (Fail)f[HDR_LEN];
    failWith(why == F_NONE ? F_ABORTED : why, false);
    return;
  }
  if (_state == TRANSFER && type == T_ACK && len == HDR_LEN + 2 + 4) {
    uint16_t base = getU16(&f[HDR_LEN]);
    uint32_t bits = getU32(&f[HDR_LEN + 2]);
    if (base < _base || base > _chunks) return;   // old, or nonsense
    uint16_t shift = base - _base;
    _sent = shift >= 32 ? 0 : (_sent >> shift);
    _base = base;
    _acked = bits;
    _tries = 0;
    _got_ack = true;
    _t_last_rx = now;
    if (_base >= _chunks) {
      _state = FINISHING;
      _tries = 1;
      _t_last_tx = now;
      sendDone();
    } else {
      _need_burst = true;
    }
    return;
  }
  if (_state == FINISHING && type == T_DONE_ACK && len == HDR_LEN + 1) {
    if (f[HDR_LEN] == 0) {
      _state = DONE_OK;
      _t_done = now;
    } else {
      failWith(F_BAD_DATA, false);
    }
  }
}

// ---- receiver ----

void Session::sendHelloAck() {
  uint8_t f[HDR_LEN + POINT_LEN + CONFIRM_LEN];
  header(f, T_HELLO_ACK);
  memcpy(&f[HDR_LEN], _Yb, POINT_LEN);
  tag(&f[HDR_LEN + POINT_LEN], false);
  sendFrame(f, sizeof(f));
}

void Session::sendAck() {
  uint8_t f[HDR_LEN + 2 + 4];
  header(f, T_ACK);
  putU16(&f[HDR_LEN], _rbase);
  putU32(&f[HDR_LEN + 2], _have);
  sendFrame(f, sizeof(f));
}

void Session::sendDoneAck(uint8_t status) {
  uint8_t f[HDR_LEN + 1];
  header(f, T_DONE_ACK);
  f[HDR_LEN] = status;
  sendFrame(f, sizeof(f));
}

// writes out the chunks that follow on from what's written
bool Session::flush() {
  while (_have & 1) {
    int slot = _rbase % WINDOW;
    if (!_sink->write(_slots[slot], _slot_len[slot])) return false;
    _hash.update(_slots[slot], _slot_len[slot]);
    _written += _slot_len[slot];
    _rbase++;
    _have >>= 1;
  }
  return true;
}

void Session::onReceiver(const uint8_t* f, int len, float rssi, uint32_t now) {
  uint8_t type = f[2];
  uint32_t sid = getU32(&f[3]);
  if (_state == WAITING) {
    if (type != T_HELLO || len != HDR_LEN + SID_LEN + POINT_LEN) return;
    if (getU32(&f[HDR_LEN]) != sid) return;
    if (rssi < _min_rssi) {
      if (_weak_rssi == 0 || rssi > _weak_rssi) _weak_rssi = rssi;
      return;
    }
    // the first sender close enough gets this code's one try
    memcpy(_sid_full, &f[HDR_LEN], SID_LEN);
    _sid = sid;
    memcpy(_Ya, &f[HDR_LEN + SID_LEN], POINT_LEN);
    makeShare(_io, _code, _sid_full, _y, _Yb);
    if (!deriveKeys(_Ya)) { failWith(F_WRONG_CODE, true); return; }
    _peer_rssi = rssi;
    _state = TRANSFER;
    _t_link = now;
    _t_last_rx = now;
    sendHelloAck();
    return;
  }
  if (sid != _sid) return;   // someone else's
  _t_last_rx = now;
  if (type == T_ABORT && len == HDR_LEN + 1) {
    if (_state == TRANSFER) failWith(f[HDR_LEN] == F_WRONG_CODE ? F_WRONG_CODE : F_ABORTED, false);
    return;
  }
  if (_state == TRANSFER && type == T_HELLO) {   // it missed our answer
    if (!_confirmed) sendHelloAck();
    return;
  }
  if (_state == TRANSFER && type == T_CONFIRM && len == HDR_LEN + CONFIRM_LEN) {
    if (_confirmed) return;
    uint8_t want[CONFIRM_LEN];
    tag(want, true);
    if (!cpace::equal(want, &f[HDR_LEN], CONFIRM_LEN)) { failWith(F_WRONG_CODE, true); return; }
    _confirmed = true;
    return;
  }
  if (_state == TRANSFER && !_confirmed) return;   // nothing counts before the sender proved the code
  if (_state == TRANSFER && type == T_DATA && len > HDR_LEN + 2 + TAG_LEN && len <= MAX_FRAME) {
    uint16_t seq = getU16(&f[HDR_LEN]);
    if (seq < _rbase || seq >= _rbase + WINDOW) return;
    int i = seq - _rbase;
    if (_have & (1UL << i)) return;   // a repeat
    int n = len - HDR_LEN - 2 - TAG_LEN;
    int slot = seq % WINDOW;
    if (!open(f, HDR_LEN + 2, seq, n, _slots[slot])) return;
    _slot_len[slot] = (uint8_t)n;
    _have |= 1UL << i;
    return;
  }
  if (_state == TRANSFER && type == T_POLL && len == HDR_LEN + 2) {
    if (!flush()) { failWith(F_WRITE, true); return; }
    sendAck();
    return;
  }
  if (type == T_DONE && len == HDR_LEN + 36 + TAG_LEN) {
    if (_done_ack != 0xFF) { sendDoneAck(_done_ack); return; }   // our answer was lost
    if (_state != TRANSFER) return;
    uint8_t plain[36];
    if (!open(f, HDR_LEN, DONE_SEQ, 36, plain)) return;
    if (!flush()) { failWith(F_WRITE, true); return; }
    uint8_t got[32];
    _hash.finalize(got, sizeof(got));
    bool ok = getU32(plain) == _written && memcmp(got, &plain[4], 32) == 0;
    _done_ack = ok ? 0 : 1;
    sendDoneAck(_done_ack);
    _total = _written;
    _t_done = now;
    if (ok) _state = DONE_OK;
    else { _state = FAILED; _fail = F_BAD_DATA; }
  }
}

void Session::onFrame(const uint8_t* f, int len, float rssi, uint32_t now) {
  if (!f || len < HDR_LEN || f[0] != 'C' || f[1] != 'L') return;
  if (_state == IDLE || _state == FAILED) return;
  if (_sender) {
    if (getU32(&f[3]) != _sid) return;
    if (_state == DONE_OK) return;
    onSender(f, len, rssi, now);
  } else {
    onReceiver(f, len, rssi, now);   // DONE_OK still answers repeats of DONE
  }
}

void Session::tick(uint32_t now) {
  if (_state == WAITING) {
    if ((int32_t)(now - _t_deadline) >= 0) {
      failWith(_weak_rssi != 0 ? F_TOO_FAR : F_NO_PEER, false);
      return;
    }
    if (_sender && now - _t_last_tx >= HELLO_EVERY_MS) {
      _t_last_tx = now;
      sendHello();
    }
    return;
  }
  if (!_sender) {
    if (_state == TRANSFER && now - _t_last_rx >= SILENCE_MS) failWith(F_LOST, false);
    return;
  }
  if (_state == TRANSFER) {
    if (_need_burst) {
      _need_burst = false;
      if (!_got_ack) sendConfirm();
      for (int i = 0; i < WINDOW && _base + i < _chunks; i++) {
        uint32_t bit = 1UL << i;
        if (_acked & bit) continue;
        if (_sent & bit) _resent++;
        if (!sendData((uint16_t)(_base + i))) { failWith(F_READ, true); return; }
        _sent |= bit;
      }
      sendPoll();
      _tries = 1;
      _t_last_tx = now;
    } else if (now - _t_last_tx >= RETRY_MS) {
      if (_tries >= MAX_TRIES) { failWith(F_LOST, false); return; }
      _tries++;
      _t_last_tx = now;
      if (!_got_ack) sendConfirm();   // it may have been the CONFIRM that was lost
      sendPoll();
    }
    return;
  }
  if (_state == FINISHING && now - _t_last_tx >= RETRY_MS) {
    if (_tries >= MAX_TRIES) { failWith(F_LOST, false); return; }
    _tries++;
    _t_last_tx = now;
    sendDone();
  }
}

// ---- bundle ----

bool BundleSource::init(Files* files, const uint8_t* ids, int n) {
  if (!files || n < 0 || n > MAX_FILES) return false;
  _files = files;
  _n = n;
  memcpy(_head, "CLB1", 4);
  _head[4] = (uint8_t)n;
  _head_len = 5 + 5 * n;
  _size = _head_len;
  for (int i = 0; i < n; i++) {
    _ids[i] = ids[i];
    int32_t sz = files->fileSize(ids[i]);
    _sizes[i] = sz < 0 ? ABSENT : (uint32_t)sz;
    _head[5 + 5 * i] = ids[i];
    putU32(&_head[6 + 5 * i], _sizes[i]);
    if (sz > 0) _size += (uint32_t)sz;
  }
  return true;
}

int BundleSource::read(uint32_t off, uint8_t* buf, int len) {
  if (off + (uint32_t)len > _size) return -1;
  int done = 0;
  while (done < len) {
    uint32_t o = off + done;
    if (o < (uint32_t)_head_len) {
      int n = _head_len - (int)o;
      if (n > len - done) n = len - done;
      memcpy(&buf[done], &_head[o], n);
      done += n;
      continue;
    }
    uint32_t start = _head_len;
    int i = 0;
    for (; i < _n; i++) {
      uint32_t sz = _sizes[i] == ABSENT ? 0 : _sizes[i];
      if (o < start + sz) break;
      start += sz;
    }
    if (i == _n) return -1;
    uint32_t in = o - start;
    uint32_t left = _sizes[i] - in;
    int n = left < (uint32_t)(len - done) ? (int)left : len - done;
    if (_files->fileRead(_ids[i], in, &buf[done], n) != n) return -1;
    done += n;
  }
  return len;
}

void BundleSink::init(Files* files, uint32_t max_file) {
  _files = files;
  _max_file = max_file;
  _phase = 0;
  _head_len = 0;
  _need = 5;
  _n = 0; _cur = -1; _left = 0;
}

// starts the next file with bytes; files the sender has none of (or empty ones) are done at once
bool BundleSink::nextFile() {
  while (++_cur < _n) {
    int32_t sz = _sizes[_cur] == ABSENT ? -1 : (int32_t)_sizes[_cur];
    if (!_files->fileBegin(_ids[_cur], sz)) return false;
    if (sz > 0) { _left = (uint32_t)sz; return true; }
    if (!_files->fileEnd(_ids[_cur])) return false;
  }
  _phase = 3;
  return true;
}

bool BundleSink::write(const uint8_t* buf, int len) {
  int i = 0;
  while (i < len) {
    if (_phase < 2) {
      _head[_head_len++] = buf[i++];
      if (_head_len < _need) continue;
      if (_phase == 0) {
        if (memcmp(_head, "CLB1", 4) != 0 || _head[4] > MAX_FILES) return false;
        _n = _head[4];
        _phase = 1;
        _need = 5 + 5 * _n;
        if (_head_len < _need) continue;
      }
      for (int k = 0; k < _n; k++) {
        _ids[k] = _head[5 + 5 * k];
        _sizes[k] = getU32(&_head[6 + 5 * k]);
        if (_sizes[k] != ABSENT && _sizes[k] > _max_file) return false;
        for (int j = 0; j < k; j++) if (_ids[j] == _ids[k]) return false;
      }
      _phase = 2;
      _cur = -1;
      if (!nextFile()) return false;
      continue;
    }
    if (_phase == 3) return false;   // more bytes than the files hold
    int n = _left < (uint32_t)(len - i) ? (int)_left : len - i;
    if (!_files->fileWrite(_ids[_cur], &buf[i], n)) return false;
    i += n;
    _left -= n;
    if (_left == 0) {
      if (!_files->fileEnd(_ids[_cur])) return false;
      if (!nextFile()) return false;
    }
  }
  return true;
}

}  // namespace clonelink
