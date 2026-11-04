#pragma once

#include <stdint.h>
#include <string.h>
#include <Packet.h>

#ifndef CLONE_HELD_SLOTS
  #define CLONE_HELD_SLOTS     4     // backup replies held back at once
#endif
#ifndef CLONE_RECENT_SLOTS
  #define CLONE_RECENT_SLOTS   4     // sibling replies remembered, for messages we haven't got yet
#endif
#define CLONE_RECENT_MS        30000
#define CLONE_ALERT_INTERVAL   (30UL*60*1000)
#define CLONE_DEFAULT_WAIT_MS  1500

#define CLONE_ROLE_SOLO    0   // as if no other radio shares this key
#define CLONE_ROLE_MAIN    1   // answers at once
#define CLONE_ROLE_BACKUP  2   // holds back flood replies, and drops them if the main radio answers

#define CLONE_CLAIM_CODE   0xC1   // marks a takeover claim, in a datagram from our key to our key

/**
 * \brief  Coordinates radios that share one identity (the same private key).
 *
 * When a message arrives by flood, every radio with the key gets it and would reply, so the sender
 * gets several replies and paths. One radio can take over as main: it floods a claim that only
 * radios with the key can read, and those become backups. A backup holds back each flood reply for
 * a moment, and drops it if it hears another radio with the key reply to the same message first.
 * If the main radio is off, the backup's reply goes out after the wait.
 *
 * Plain logic with no radio or clock access, so it can be tested on the host. Times are millis().
 */
class CloneCoordinator {
public:
  struct Stats {
    uint32_t held;        // replies held back (as a backup)
    uint32_t dropped;     // held replies dropped because another radio answered
    uint32_t siblings;    // packets heard from another radio with this key
  };

private:
  struct Held {
    uint8_t hash[MAX_HASH_SIZE];   // of our queued reply
    uint8_t contact[6];            // who it goes to
    uint8_t ack[4];
    bool has_ack;
    bool used;
    unsigned long until;
  };
  struct Recent {
    uint8_t contact[6];
    uint8_t ack[4];
    bool used;
    unsigned long when;
  };

  uint8_t _role;
  uint32_t _epoch;       // newest claim seen or made
  uint32_t _tag;         // random, tells this radio's claims apart
  uint16_t _wait_ms;
  Held _held[CLONE_HELD_SLOTS];
  Recent _recent[CLONE_RECENT_SLOTS];
  int _next_recent;
  bool _alerted;
  unsigned long _last_alert;
  Stats _stats;

  static bool timeReached(unsigned long now, unsigned long t) { return (long)(now - t) >= 0; }

public:
  CloneCoordinator() : _role(CLONE_ROLE_SOLO), _epoch(0), _tag(0), _wait_ms(CLONE_DEFAULT_WAIT_MS),
                       _next_recent(0), _alerted(false), _last_alert(0) {
    memset(_held, 0, sizeof(_held));
    memset(_recent, 0, sizeof(_recent));
    memset(&_stats, 0, sizeof(_stats));
  }

  void load(uint8_t role, uint32_t epoch, uint32_t tag, uint16_t wait_ms) {
    _role = role <= CLONE_ROLE_BACKUP ? role : CLONE_ROLE_SOLO;
    _epoch = epoch;
    _tag = tag;
    _wait_ms = wait_ms ? wait_ms : CLONE_DEFAULT_WAIT_MS;
  }
  uint8_t  role() const { return _role; }
  uint32_t epoch() const { return _epoch; }
  uint32_t tag() const { return _tag; }
  uint16_t waitMs() const { return _wait_ms; }
  bool isBackup() const { return _role == CLONE_ROLE_BACKUP; }
  void setWait(uint16_t ms) { _wait_ms = ms; }
  void setTag(uint32_t tag) { _tag = tag; }
  void setSolo() { _role = CLONE_ROLE_SOLO; }

  /**
   * \brief  This radio takes over as main. \returns the claim's epoch: newer than any seen, and
   *         normally the clock time, so a radio that missed earlier claims still makes a newer one.
   */
  uint32_t takeover(uint32_t clock_now) {
    _epoch = clock_now > _epoch ? clock_now : _epoch + 1;
    _role = CLONE_ROLE_MAIN;
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
    return true;
  }

  /**
   * \brief  Another radio with our key sent a packet to this contact.
   * \param  ack  first 4 ACK bytes if it was a reply carrying an ACK, else NULL
   * \param  cancel_hash  set to the hash of our held reply to drop, if this answers it
   * \returns  true if a held reply should be dropped
   */
  bool onSibling(const uint8_t* contact, const uint8_t* ack, unsigned long now, uint8_t* cancel_hash) {
    _stats.siblings++;
    if (ack) {   // remember it, in case the message itself hasn't reached us yet
      Recent* r = &_recent[_next_recent];
      _next_recent = (_next_recent + 1) % CLONE_RECENT_SLOTS;
      memcpy(r->contact, contact, 6);
      memcpy(r->ack, ack, 4);
      r->used = true;
      r->when = now;
    }
    for (int i = 0; i < CLONE_HELD_SLOTS; i++) {
      Held* h = &_held[i];
      if (!h->used || timeReached(now, h->until) || memcmp(h->contact, contact, 6) != 0) continue;
      if (ack ? (h->has_ack && memcmp(h->ack, ack, 4) == 0) : !h->has_ack) {
        memcpy(cancel_hash, h->hash, MAX_HASH_SIZE);
        h->used = false;
        _stats.dropped++;
        return true;
      }
    }
    return false;
  }

  /** \returns  true if another radio with our key already sent this ACK to this contact */
  bool alreadyAnswered(const uint8_t* contact, const uint8_t* ack, unsigned long now) const {
    if (ack == NULL) return false;
    for (int i = 0; i < CLONE_RECENT_SLOTS; i++) {
      const Recent* r = &_recent[i];
      if (r->used && !timeReached(now, r->when + CLONE_RECENT_MS)
          && memcmp(r->contact, contact, 6) == 0 && memcmp(r->ack, ack, 4) == 0) return true;
    }
    return false;
  }

  /** \brief  Remember a reply a backup is holding back, so it can be dropped. */
  void hold(const uint8_t* hash, const uint8_t* contact, const uint8_t* ack, unsigned long now) {
    _stats.held++;
    Held* h = NULL;
    for (int i = 0; i < CLONE_HELD_SLOTS; i++) {
      if (!_held[i].used || timeReached(now, _held[i].until)) { h = &_held[i]; break; }
    }
    if (h == NULL) return;   // full: it just goes out after the wait
    memcpy(h->hash, hash, MAX_HASH_SIZE);
    memcpy(h->contact, contact, 6);
    h->has_ack = ack != NULL;
    if (ack) memcpy(h->ack, ack, 4);
    h->until = now + _wait_ms + 5000;
    h->used = true;
  }

  /** \returns  true if it's time to tell the user another radio with this key is active */
  bool alertDue(unsigned long now) {
    if (_alerted && !timeReached(now, _last_alert + CLONE_ALERT_INTERVAL)) return false;
    _alerted = true;
    _last_alert = now;
    return true;
  }

  const Stats& getStats() const { return _stats; }
};
