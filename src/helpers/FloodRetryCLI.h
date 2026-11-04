#pragma once

#include <FloodRetry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLOOD_RETRY_MAX        3
#define FLOOD_RETRY_WAIT_MIN   500
#define FLOOD_RETRY_WAIT_MAX   30000

/**
 * \brief  CLI for flood retry, shared by the companion and the repeater:
 *           get flood.retry                  resends per packet, and the echo wait
 *           set flood.retry <0-3>            0 turns it off
 *           set flood.retry.wait <ms>|auto   how long to wait for an echo
 *           get flood.retry.stats
 * \param  changed  set to true when a setting changed (caller saves its prefs)
 * \returns  true if the command was a flood retry command (reply is filled in)
 */
inline bool handleFloodRetryCommand(const char* command, uint8_t& count, uint16_t& wait_ms,
                                    mesh::FloodRetry& retry, char* reply, bool& changed) {
  changed = false;
  if (strcmp(command, "get flood.retry") == 0) {
    if (wait_ms) {
      sprintf(reply, "> %u, wait %u ms", (uint32_t)count, (uint32_t)wait_ms);
    } else {
      sprintf(reply, "> %u, wait auto", (uint32_t)count);
    }
    return true;
  }
  if (strcmp(command, "get flood.retry.stats") == 0) {
    const mesh::FloodRetry::Stats& s = retry.getStats();
    sprintf(reply, "> watched %u, echoed %u (%u after a resend), resends %u, no echo %u, skipped %u",
            s.tracked, s.echoed, s.echoed_after, s.retries, s.gave_up, s.skipped);
    return true;
  }
  if (memcmp(command, "set flood.retry.wait ", 21) == 0) {
    const char* arg = &command[21];
    if (strcmp(arg, "auto") == 0) {
      wait_ms = 0;
    } else {
      long ms = atol(arg);
      if (ms < FLOOD_RETRY_WAIT_MIN || ms > FLOOD_RETRY_WAIT_MAX) {
        sprintf(reply, "Error: wait must be auto or %d-%d ms", FLOOD_RETRY_WAIT_MIN, FLOOD_RETRY_WAIT_MAX);
        return true;
      }
      wait_ms = (uint16_t)ms;
    }
    changed = true;
    strcpy(reply, "OK");
    return true;
  }
  if (memcmp(command, "set flood.retry ", 16) == 0) {
    const char* arg = &command[16];
    if (strcmp(arg, "off") == 0) arg = "0";
    if (strcmp(arg, "on") == 0) arg = "1";
    if (arg[0] < '0' || arg[0] > '0' + FLOOD_RETRY_MAX || arg[1] != 0) {
      sprintf(reply, "Error: retries must be 0-%d", FLOOD_RETRY_MAX);
      return true;
    }
    count = arg[0] - '0';
    changed = true;
    strcpy(reply, "OK");
    return true;
  }
  return false;
}
