#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * \brief  Spots contact names that read as "Radio console", the companion's built-in command contact,
 *         so a node on the mesh can't pose as it.
 *
 * Only letters and digits count, in any case. Spaces, punctuation, emoji and invisible characters are
 * skipped, so "radio_console" or "📻 Radio  Console" still match. 0 and 1 count as o and i/l, and up to
 * four other non-ASCII characters can stand in for letters, for lookalikes such as a Cyrillic "о".
 */
class ConsoleName {
  // the next UTF-8 code point at *p (advancing p), or 0xFFFD for a malformed byte
  static uint32_t nextCodePoint(const uint8_t*& p) {
    uint8_t c = *p++;
    if (c < 0x80) return c;
    int extra = (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : 0;
    uint32_t cp = extra == 1 ? (c & 0x1F) : extra == 2 ? (c & 0x0F) : (c & 0x07);
    if (extra == 0) return 0xFFFD;
    for (int k = 0; k < extra; k++) {
      if ((*p & 0xC0) != 0x80) return 0xFFFD;
      cp = (cp << 6) | (*p++ & 0x3F);
    }
    return cp;
  }

  // emoji, symbols and invisible characters: decoration, not letters
  static bool skipped(uint32_t cp) {
    return (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x206F)
        || cp == 0xFEFF || (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0x2190 && cp <= 0x2BFF)
        || (cp >= 0x1F000 && cp <= 0x1FAFF) || (cp >= 0xE0000 && cp <= 0xE007F) || cp == 0x00A0 || cp == 0x00AD;
  }

public:
  static bool looksLikeConsole(const char* name) {
    static const char target[] = "radioconsole";
    const int tlen = sizeof(target) - 1;
    char norm[64];
    int n = 0;
    const uint8_t* p = (const uint8_t*) name;
    while (*p && n < (int) sizeof(norm)) {
      uint32_t cp = nextCodePoint(p);
      if (cp >= 'A' && cp <= 'Z') norm[n++] = (char)(cp + 32);
      else if ((cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9')) norm[n++] = (char) cp;
      else if (cp >= 0x80 && !skipped(cp)) norm[n++] = '?';   // maybe a lookalike letter
    }
    if (n != tlen) return false;
    int wild = 0;
    for (int k = 0; k < tlen; k++) {
      char c = norm[k], t = target[k];
      if (c == t) continue;
      if (c == '?') { wild++; continue; }
      if (c == '0' && t == 'o') continue;
      if (c == '1' && (t == 'i' || t == 'l')) continue;
      return false;
    }
    return wild <= 4;
  }

  /** \brief  Writes "(fake) <name>" to dest (size bytes), cutting the name on a character boundary. */
  static void markFake(char* dest, size_t size, const char* name) {
    static const char prefix[] = "(fake) ";
    size_t plen = sizeof(prefix) - 1;
    if (size <= plen) { if (size) dest[0] = 0; return; }
    memcpy(dest, prefix, plen);
    size_t room = size - 1 - plen, len = strlen(name);
    if (len > room) {
      len = room;
      while (len > 0 && (((uint8_t) name[len]) & 0xC0) == 0x80) len--;   // don't split a character
    }
    memcpy(&dest[plen], name, len);
    dest[plen + len] = 0;
  }
};
