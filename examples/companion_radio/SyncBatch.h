#pragma once

#include <stdint.h>

// Batch message sync (CMD_SYNC_BATCH, docs/ble_sync.md): which of the queued messages at the
// front of the offline queue have gone to the app and wait for it to confirm them. They stay
// queued until it does, so a link that drops mid-batch loses nothing: they go again next time.
//
// No I/O here, so it can be tested on its own (test/test_sync_batch).
struct SyncBatch {
  uint16_t sent = 0;     // messages from the front of the queue sent and not yet confirmed
  uint16_t limit = 0;    // send until this many are out (this batch)
  bool sending = false;  // a batch is going out: the main loop sends the next one, then the end frame

  // The app has `ack` of the messages sent. How many to remove from the front of the queue:
  // never more than were sent. The rest of a batch the app didn't confirm stays queued.
  int confirm(int ack) {
    int n = ack < 0 ? 0 : (ack > sent ? sent : ack);
    sent = 0;
    sending = false;
    return n;
  }

  // A new batch of up to `max` messages, after confirm().
  void start(int max) {
    sent = 0;
    limit = max < 0 ? 0 : (max > 255 ? 255 : max);
    sending = true;
  }

  // The next message to send (an index into the queue), or -1 when the batch is done.
  int next(int queue_len) const {
    if (!sending || sent >= limit || sent >= queue_len) return -1;
    return sent;
  }

  void markSent() { sent++; }

  // The queue was full and the message at `pos` was dropped to make room. One already sent
  // isn't there for the app to confirm any more.
  void onRemoved(int pos) {
    if (pos >= 0 && pos < sent) sent--;
  }

  // The app went back to CMD_SYNC_NEXT_MESSAGE, or disconnected: forget the batch. What was
  // sent stays queued, so the app may get some twice but none are lost.
  void cancel() {
    sent = 0;
    limit = 0;
    sending = false;
  }
};
