#pragma once

#include <stdint.h>
#include <string.h>

#define CLONE_ALERT_INTERVAL   (30UL*60*1000)

#define CLONE_ROLE_SOLO    0   // as if no other radio shares this key
#define CLONE_ROLE_MAIN    1   // answers messages
#define CLONE_ROLE_BACKUP  2   // shows messages but never answers them

#define CLONE_CLAIM_CODE   0xC1   // marks a takeover claim, in a datagram from our key to our key

/**
 * \brief  Coordinates radios that share one identity (the same private key).
 *
 * When a message arrives by flood, every radio with the key gets it and replies, so the sender gets
 * several replies and keeps the path of whichever came last. One radio can take over as main: it
 * floods a claim that only radios with the key can read, and those become backups. A backup still
 * shows every message it receives but sends no ACKs, paths or responses, so the sender only ever
 * hears from the main radio: "delivered" means the main radio has it.
 *
 * Plain logic with no radio or clock access, so it can be tested on the host. Times are millis().
 */
class CloneCoordinator {
  uint8_t _role;
  uint32_t _epoch;       // newest claim seen or made
  uint32_t _tag;         // random, tells this radio's claims apart
  bool _alerted;
  unsigned long _last_alert;
  bool _prompted;
  unsigned long _last_prompt;
  uint32_t _siblings;    // packets heard from another radio with this key
  uint32_t _silenced;    // replies not sent since this radio last became a backup

  static bool due(bool& done, unsigned long& last, unsigned long now) {
    if (done && (long)(now - (last + CLONE_ALERT_INTERVAL)) < 0) return false;
    done = true;
    last = now;
    return true;
  }

public:
  CloneCoordinator() : _role(CLONE_ROLE_SOLO), _epoch(0), _tag(0), _alerted(false), _last_alert(0),
                       _prompted(false), _last_prompt(0), _siblings(0), _silenced(0) { }

  void load(uint8_t role, uint32_t epoch, uint32_t tag) {
    _role = role <= CLONE_ROLE_BACKUP ? role : CLONE_ROLE_SOLO;
    _epoch = epoch;
    _tag = tag;
  }
  uint8_t  role() const { return _role; }
  uint32_t epoch() const { return _epoch; }
  uint32_t tag() const { return _tag; }
  bool isBackup() const { return _role == CLONE_ROLE_BACKUP; }
  void setSolo() { _role = CLONE_ROLE_SOLO; }

  /**
   * \brief  This radio takes over as main. \returns the claim's epoch: newer than any seen, and
   *         normally the clock time, so a radio that missed earlier claims still makes a newer one.
   */
  uint32_t takeover(uint32_t clock_now) {
    _epoch = clock_now > _epoch ? clock_now : _epoch + 1;
    _role = CLONE_ROLE_MAIN;
    _prompted = false;
    return _epoch;
  }

  /** \returns  the claim payload length written to dest (9 bytes) */
  int writeClaim(uint8_t* dest) const {
    memcpy(dest, &_epoch, 4);
    dest[4] = CLONE_CLAIM_CODE;
    memcpy(&dest[5], &_tag, 4);
    return 9;
  }

  /**
   * \brief  A datagram from our key to our key arrived.
   * \returns  true if it's a newer claim from another radio, so this one is now a backup.
   */
  bool onClaim(const uint8_t* data, size_t len) {
    if (len < 9 || data[4] != CLONE_CLAIM_CODE) return false;
    uint32_t epoch, tag;
    memcpy(&epoch, data, 4);
    memcpy(&tag, &data[5], 4);
    if (tag == _tag || epoch <= _epoch) return false;   // ours, or old (a replay, or already seen)
    _epoch = epoch;
    _role = CLONE_ROLE_BACKUP;
    _prompted = false;
    _silenced = 0;
    return true;
  }

  /** \brief  Another radio with our key sent a packet. */
  void onSibling() { _siblings++; }

  /** \returns  true if this radio may answer a message or request (false for a backup) */
  bool allowReply() {
    if (_role != CLONE_ROLE_BACKUP) return true;
    _silenced++;
    return false;
  }

  /** \returns  true if it's time to tell the user another radio with this key is active */
  bool alertDue(unsigned long now) { return due(_alerted, _last_alert, now); }

  /** \returns  true if it's time to offer a takeover, because the user sent a message from a backup */
  bool promptDue(unsigned long now) { return isBackup() && due(_prompted, _last_prompt, now); }

  uint32_t siblings() const { return _siblings; }
  uint32_t silenced() const { return _silenced; }
};
