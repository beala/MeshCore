#pragma once

#include <Packet.h>
#include <string.h>

#ifndef FLOOD_RETRY_SLOTS
  #define FLOOD_RETRY_SLOTS   4     // flood packets waiting for an echo at once
#endif

namespace mesh {

/**
 * \brief  Resends a packet when no other node is heard passing it on.
 *
 * After a packet goes out, listen for a copy of it that has travelled further than ours. A flood
 * copy that went further has more hops in its path. A direct copy has fewer, because each hop
 * removes itself from the path before forwarding. Hearing one means the next node received it.
 * If none is heard within the wait time, the exact same bytes are sent again. Nodes that already
 * have the packet drop the copy as a duplicate (the duplicate check ignores the path), so the
 * resend only reaches nodes that missed the first one.
 *
 * Some packets never produce an echo, so they are not tracked: direct packets sent with an empty
 * path (the hand-off to the final recipient, or zero-hop), TRACE (its duplicate check includes
 * the path), and MULTIPART (the next hop forwards it as a different packet).
 *
 * Keeps its own copy of each packet, so it never holds on to pool packets. Times are millis().
 */
class FloodRetry {
public:
  struct Stats {
    uint32_t tracked;        // packets watched for an echo
    uint32_t echoed;         // echo heard (with or without a resend)
    uint32_t retries;        // resends transmitted
    uint32_t echoed_after;   // echo heard only after a resend went out
    uint32_t gave_up;        // no echo after all resends
    uint32_t skipped;        // not watched, or resend not sent (no free slot, busy channel, ...)
  };

  enum { ECHO_NONE, ECHO_HEARD, ECHO_CANCEL_RESEND };

private:
  struct Slot {
    uint8_t  hash[MAX_HASH_SIZE];
    uint8_t  raw[MAX_TRANS_UNIT];
    uint8_t  raw_len;        // 0 = free
    uint8_t  sent_hops;      // hops in our copy; a flood echo has more, a direct echo fewer
    bool     direct;
    uint8_t  retries_left;
    uint8_t  resends_sent;
    uint32_t wait_ms;
    unsigned long deadline;  // waiting: when to give up on an echo. Else: safety net for the resend
    bool     waiting;        // false while a resend is queued or transmitting
    bool     echoed;         // echo heard while a resend was queued or transmitting
  };
  Slot _slots[FLOOD_RETRY_SLOTS];
  int _active;
  Stats _stats;

  static bool timeReached(unsigned long now, unsigned long t) { return (long)(now - t) >= 0; }

  Slot* find(const uint8_t* hash) {
    for (int i = 0; i < FLOOD_RETRY_SLOTS; i++) {
      if (_slots[i].raw_len && memcmp(_slots[i].hash, hash, MAX_HASH_SIZE) == 0) return &_slots[i];
    }
    return NULL;
  }
  void release(Slot* s) { s->raw_len = 0; _active--; }

public:
  FloodRetry() { memset(_slots, 0, sizeof(_slots)); _active = 0; memset(&_stats, 0, sizeof(_stats)); }

  /**
   * \brief  Call when a packet has finished transmitting.
   * \returns  true if it was one of our resends. Otherwise the caller decides whether to track() it.
   */
  bool onSent(const Packet* pkt, unsigned long now) {
    if (_active == 0) return false;
    uint8_t hash[MAX_HASH_SIZE];
    pkt->calculatePacketHash(hash);
    Slot* s = find(hash);
    if (s == NULL) return false;

    _stats.retries++;
    s->resends_sent++;
    if (s->echoed) {   // the echo came in while this was going out: done
      release(s);
    } else {
      s->waiting = true;
      s->deadline = now + s->wait_ms;
    }
    return true;
  }

  /** \returns  true if some node should pass this packet on, so an echo can be heard */
  static bool canEcho(const Packet* pkt) {
    uint8_t type = pkt->getPayloadType();
    if (type == PAYLOAD_TYPE_TRACE || type == PAYLOAD_TYPE_MULTIPART) return false;
    if (pkt->isRouteFlood()) return true;
    return pkt->isRouteDirect() && pkt->getPathHashCount() > 0;
  }

  /**
   * \brief  Start watching a packet that has just been sent for the first time.
   * \param  retries  how many times to resend it if no echo is heard (1 or more)
   * \param  wait_ms  how long to wait for an echo after each send
   * \returns  false if not tracked (no echo possible, or no free slot)
   */
  bool track(const Packet* pkt, unsigned long now, uint8_t retries, uint32_t wait_ms) {
    if (retries == 0 || !canEcho(pkt)) return false;
    Slot* s = NULL;
    for (int i = 0; i < FLOOD_RETRY_SLOTS; i++) {
      if (_slots[i].raw_len == 0) { s = &_slots[i]; break; }
    }
    if (s == NULL) { _stats.skipped++; return false; }

    s->raw_len = pkt->writeTo(s->raw);
    if (s->raw_len == 0) return false;
    pkt->calculatePacketHash(s->hash);
    s->sent_hops = pkt->getPathHashCount();
    s->direct = pkt->isRouteDirect();
    s->retries_left = retries;
    s->resends_sent = 0;
    s->wait_ms = wait_ms;
    s->deadline = now + wait_ms;
    s->waiting = true;
    s->echoed = false;
    _active++;
    _stats.tracked++;
    return true;
  }

  /**
   * \brief  Call for every received packet, before duplicate filtering.
   * \returns  ECHO_CANCEL_RESEND if this echo arrived while a resend was queued or transmitting.
   *           The caller should take the queued copy (same hash) off the send queue and, if it
   *           found it there, call resendCancelled().
   */
  int onHeard(const Packet* pkt) {
    if (_active == 0) return ECHO_NONE;
    uint8_t hash[MAX_HASH_SIZE];
    pkt->calculatePacketHash(hash);
    Slot* s = find(hash);
    if (s == NULL || s->echoed) return ECHO_NONE;
    bool further = s->direct ? pkt->isRouteDirect() && pkt->getPathHashCount() < s->sent_hops
                             : pkt->isRouteFlood() && pkt->getPathHashCount() > s->sent_hops;
    if (!further) return ECHO_NONE;

    _stats.echoed++;
    if (s->resends_sent) _stats.echoed_after++;
    if (s->waiting) {
      release(s);
      return ECHO_HEARD;
    }
    s->echoed = true;   // keep the slot until the resend is cancelled or goes out
    return ECHO_CANCEL_RESEND;
  }

  /** \brief  The queued resend for this hash was taken off the send queue unsent. */
  void resendCancelled(const uint8_t* hash) {
    Slot* s = find(hash);
    if (s) release(s);
  }

  /**
   * \brief  Call often. If a resend is due, points raw at the stored packet bytes (valid until the
   *         next call into this class) and returns the slot index (call skip() with it if the
   *         resend can't be queued). Returns -1 if none is due.
   */
  int nextDue(unsigned long now, const uint8_t*& raw, uint8_t& raw_len) {
    if (_active == 0) return -1;
    for (int i = 0; i < FLOOD_RETRY_SLOTS; i++) {
      Slot* s = &_slots[i];
      if (s->raw_len == 0 || !timeReached(now, s->deadline)) continue;
      if (!s->waiting || s->retries_left == 0) {
        // out of resends, or a resend that never went out (dropped by the dispatcher)
        if (!s->echoed) _stats.gave_up++;
        release(s);
        continue;
      }
      s->retries_left--;
      s->waiting = false;
      s->deadline = now + 4*s->wait_ms + 30000;   // safety net in case the resend never goes out
      raw = s->raw;
      raw_len = s->raw_len;
      return i;
    }
    return -1;
  }

  void skip(int idx) {   // the resend from nextDue() won't be sent
    _stats.skipped++;
    release(&_slots[idx]);
  }

  int  getActiveCount() const { return _active; }
  const Stats& getStats() const { return _stats; }
  void resetStats() { memset(&_stats, 0, sizeof(_stats)); }
};

}
