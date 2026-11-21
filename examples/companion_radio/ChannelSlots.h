#pragma once

#include <stdint.h>

// Channel slot compaction for the companion (docs/ble_sync.md, "Channel slots").
//
// The app fetches channels one slot at a time, every connect, up to the count in the device info
// reply. So the radio keeps its channels in consecutive slots from 0, reports one empty slot after
// them (where the app adds a new channel), and puts the built-in channels (Meshtastic, Weather, ...)
// right after that, instead of reporting all MAX_GROUP_CHANNELS slots every time.
//
// Slots only move while no app is connected, so a connected app's view always stays right.

namespace channel_slots {

static const uint8_t GONE = 0xFF;

// used[i]: slot i holds a channel. Fills remap[i] with the slot it moves to (GONE: empty slot) and
// returns how many channels there are. Order is kept.
inline int plan(const bool* used, int n, uint8_t* remap) {
  int dest = 0;
  for (int i = 0; i < n; i++) {
    remap[i] = used[i] ? (uint8_t) dest++ : GONE;
  }
  return dest;
}

// Slots the app is told about for the regular channels: the channels plus one empty one to add
// into, never more than max.
inline int reportedSlots(int used, int max) {
  return used + 1 < max ? used + 1 : max;
}

// Where a slot number the radio already handed out (in a queued message, say) goes after a
// compaction. Below old_base it's a regular channel: remapped (-1 when that slot was empty, i.e.
// the channel was deleted). From old_base on it's a built-in channel: it keeps its place after the
// regular ones, so it shifts with the base.
// 0xFF (no channel) stays as it is.
inline int remapIdx(int idx, const uint8_t* remap, int old_base, int new_base) {
  if (idx == 0xFF) return idx;
  if (idx < old_base) return remap[idx] == GONE ? -1 : remap[idx];
  return idx - old_base + new_base;
}

}  // namespace channel_slots
