#pragma once

// Reading what survives of a packet that failed the radio's CRC check (docs/damaged_packets.md).
//
// MeshCore encrypts a message in 16-byte pieces, each on its own (AES-128 in ECB mode). A few bad bits
// spoil only the pieces they land in: the other pieces still decrypt to the right text. The encrypted
// pieces always end at the end of the packet, so they can be found even when the header or path was
// hit. A piece is judged by what it decrypts to: message text, or for the first piece a timestamp and
// flags followed by text. A piece of noise passes the text test about once in 87,000 tries.
//
// None of this is authenticated: the 2-byte MAC failed (or was only matched after a repair). What it
// gives is for showing, never for acting on.

#include <stdint.h>
#include <stddef.h>

namespace damaged {

static const int PIECE = 16;
static const int MAX_PIECES = 11;           // the most that fit in a packet (184-byte payload)

enum Kind : uint8_t { KIND_NONE = 0, KIND_CHANNEL = 1, KIND_DIRECT = 2 };

// Payload types, as in the packet header (src/Packet.h)
static const uint8_t TYPE_TXT_MSG = 0x02;
static const uint8_t TYPE_GRP_TXT = 0x05;

// Whether p[0..n) reads as message text: printable ASCII, newlines and well-formed UTF-8, ending in
// zero padding. A UTF-8 character may run in from the piece before or out to the piece after.
bool isTextPiece(const uint8_t* p, int n);

// Whether a piece reads as the first piece of a message: a timestamp (after 2023, and no more than a
// year ahead of now when now is known), the flags byte, then text. Signed direct messages have 4
// bytes of the sender's key before the text.
bool isFirstPiece(const uint8_t* p, Kind kind, uint32_t now);

// The header and path as received: where the payload would start, if the bytes there came through.
struct Layout {
  bool ok;              // the header and path lengths fit the packet and its type has a known shape
  uint8_t type;         // payload type
  int payload_off;
  int payload_len;
};
Layout parseHeader(const uint8_t* raw, int len);

// Whether the payload's size fits the type the header claims (an ack is 4 bytes, an advert a key, a
// signature and up to 32 bytes of data, encrypted messages whole pieces...). A packet whose first byte
// was hit usually claims a type its size doesn't fit.
bool sizeFits(const Layout& l);

// The radio that sent us this packet, as its 1-byte hash: the last repeater in a flood packet's path,
// or the packet's originator when it has no hops yet (an advert's key, a flooded direct message's source).
// -1 when the packet doesn't say: a channel message straight from its sender (no source byte), a
// direct-routed packet (each hop takes itself off the path, so even with none left, the last repeater
// may have sent it), or a header that didn't come through.
int sender(const uint8_t* raw, int len);

// The same radio's ID with every byte the packet gives: a flood path's hash size (1 to 3 bytes), an
// advert's key (the first 4 bytes kept), a direct message's source (1 byte). n = 0 when unknown.
// A 1-byte ID is shared by 1 in 256 radios: name a contact only from 2 bytes up (NAME_MIN_BYTES).
struct RadioId {
  uint8_t n;
  uint8_t b[4];
};
static const int NAME_MIN_BYTES = 2;
void senderId(const uint8_t* raw, int len, RadioId& out);

// One key's reading of a damaged packet.
struct Result {
  uint8_t n;            // pieces from the start of the message to the end of the packet
  uint16_t good;        // bit i: piece i decrypted to text (piece 0: to a first piece if 'first')
  bool first;           // piece 0 is the message's first piece: it has the timestamp
  bool start_known;     // piece 0 is where the message starts (by its timestamp, or by the header)
  int ct_off;           // offset in the packet of piece 0
  uint8_t pt[MAX_PIECES * PIECE];
};

// Decrypts the pieces of raw with secret (16-byte AES key at its start) and judges each one. ct_hint is
// where the header says the encrypted part starts, or -1. Returns how many pieces read right (0: none).
int decode(const uint8_t* secret, const uint8_t* raw, int len, Kind kind, int ct_hint, uint32_t now, Result& out);

int countGood(uint16_t mask);

// Tries the MAC (2 bytes just before the encrypted part) with every single bit flipped in the one piece
// that read wrong, or in the MAC itself when every piece read right. secret is the full 32-byte
// secret. On a match, fixes raw and r, and returns true. Only for a packet with r.first set (so the
// MAC's place is known) and at most one bad piece.
bool repair(const uint8_t* secret, uint8_t* raw, int len, Result& r, Kind kind);

// The text of r as UTF-8 for showing: lost pieces become "▒▒▒▒", a character cut by a lost piece is
// dropped, and the timestamp and flags (and a signed message's key bytes) are left out. Returns the
// length written (always NUL-terminated, cap > 0).
int showText(const Result& r, Kind kind, char* out, int cap);

// The timestamp from piece 0 (0 when it was lost)
uint32_t timestampOf(const Result& r);

// A short fingerprint of each piece-aligned 16 bytes counted from the end of the packet, so a damaged
// copy can be matched to an intact one heard (or not) through another repeater: the pieces that came
// through are the same bytes in both.
struct Fingerprint {
  uint8_t n;
  uint16_t fp[MAX_PIECES];   // fp[0] is the last piece of the packet
  uint16_t payload_len;      // the same in every copy (paths differ); 0 if the header didn't read
};
void fingerprint(const uint8_t* raw, int len, Fingerprint& out);
// Whether the damaged packet's good pieces (by r) match an intact packet's print: the piece with the
// timestamp, or two pieces, or one when the payload is the same length too (a two-piece message that
// lost its first)
bool sameMessage(const Fingerprint& intact, const uint8_t* raw, int len, const Result& r);

// A message read from one or more damaged copies: its pieces as received and as decrypted, and the MAC
struct Copy {
  Result r;
  uint8_t ct[MAX_PIECES * PIECE];
  uint8_t mac[2];
  bool fixed;           // the MAC matched (after a repair or joining copies)
};
// Fills c from a reading of raw (after any repair)
void takeCopy(const uint8_t* raw, const Result& r, bool fixed, Copy& c);

// Whether in is another copy of the message in m (through another repeater), and if so, takes the
// pieces it has that m lost. Pieces line up from the end of the packet. The same message means: pieces
// read in both are the same, and there are enough of them (the timestamp piece, or two: under ECB a
// common ending like "lol" is the same in different messages), or else both start where the header
// says, with the same length and MAC. When m becomes whole, checks the MAC (secret: 32 bytes).
bool merge(Copy& m, const Copy& in, const uint8_t* secret);

}  // namespace damaged
