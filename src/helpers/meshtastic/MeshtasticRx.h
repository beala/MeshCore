#pragma once

// Reads Meshtastic channel traffic: the 16-byte header every packet carries in the clear, the
// channel's AES-CTR encryption, and the few protobuf fields needed for text messages and node names.
// Receive only. Written from the protocol's on-air format; no Meshtastic code is used.
//
// On-air packet: to (u32 LE), from (u32 LE), id (u32 LE), flags (hop_limit bits 2:0, want_ack 3,
// via_mqtt 4, hop_start 7:5), channel hash (u8), next hop (u8), relay node (u8), then the payload:
// a protobuf `Data` message, encrypted with AES-CTR under the channel key. The CTR block is
// id (u64 LE) | from (u32 LE) | 32-bit block counter (big endian, starting at 0).

#include <stdint.h>
#include <stddef.h>

namespace meshtastic {

static const int HEADER_LEN = 16;
static const uint32_t BROADCAST = 0xFFFFFFFF;
static const int MAX_KEY = 32;

enum PortNum { PORT_TEXT = 1, PORT_NODEINFO = 4 };

struct Header {
  uint32_t to, from, id;
  uint8_t flags, channel, next_hop, relay;
  uint8_t hopLimit() const { return flags & 0x07; }
  uint8_t hopStart() const { return flags >> 5; }
};

bool parseHeader(const uint8_t* pkt, int len, Header* h);

// Expands a channel key as Meshtastic stores it: 0 bytes = no encryption, 1 byte = the well-known
// default key (index 1) or a variant of it (index 2..10), 16 or 32 bytes = AES-128/256 key.
// Returns the key length (0 = no encryption), or -1 if the key isn't valid.
int expandKey(const uint8_t* psk, int psk_len, uint8_t key[MAX_KEY]);

// Parses a key as the Meshtastic apps show it (base64, eg. "AQ=="). Returns the number of bytes
// (1, 16 or 32), or -1 if it isn't one.
int parseKeyBase64(const char* text, uint8_t psk[MAX_KEY]);

// The 1-byte channel hash in the header: XOR of the channel name's bytes and the expanded key's bytes
uint8_t channelHash(const char* name, const uint8_t* key, int key_len);

// Encrypts or decrypts in place (CTR mode is its own inverse)
void ctrCrypt(const uint8_t* key, int key_len, uint32_t from, uint32_t id, uint8_t* data, int len);

// The default frequency of a preset's primary channel in the US band: slot = djb2(name) mod the
// number of channels (26 MHz / bandwidth), centred in that slot.
float usFrequency(const char* channel_name, float bw_khz);

struct Preset {
  const char* name;
  float bw_khz;
  uint8_t sf, cr;
};
// Modem presets by name (case-insensitive), eg. "LongFast"; NULL if unknown
const Preset* findPreset(const char* name);

// Protobuf `Data`: portnum (field 1), payload (field 2). Pointers point into the input.
struct Data {
  uint32_t portnum;
  const uint8_t* payload;
  int payload_len;
};
bool parseData(const uint8_t* p, int len, Data* d);

// Protobuf `User`: id (1), long_name (2), short_name (3). Strings are cut to fit and NUL-terminated.
struct User {
  char id[12];
  char long_name[40];
  char short_name[8];
};
bool parseUser(const uint8_t* p, int len, User* u);

// How many bytes of text[0..len) go in the next message of at most max bytes: cut at a space or
// line break in the second half if there is one, never inside a UTF-8 character. Always >= 1 when
// len > 0.
int nextPart(const char* text, int len, int max);

// What Receiver::handle() found in a packet
enum Kind { NONE, TEXT, NODEINFO, DUPLICATE, OTHER_CHANNEL, NOT_FOR_US, UNDECODABLE };

struct Message {
  Header hdr;
  const char* text;        // TEXT: not NUL-terminated, text_len bytes
  int text_len;
  const char* sender;      // TEXT: the sender's long name if known, else "!xxxxxxxx"
};

class Receiver {
public:
  static const int NAMES = 24;
  static const int SEEN = 32;
  static const int MAX_PACKET = 256;

  Receiver() { reset(); }
  void reset();
  // name is the channel name used for the hash (a preset's name for the primary channel)
  bool setChannel(const char* name, const uint8_t* psk, int psk_len);
  uint8_t getChannelHash() const { return _hash; }

  // Decodes one packet heard on the air. For TEXT, msg points into this object until the next call.
  Kind handle(const uint8_t* pkt, int len, Message* msg);

  const char* nameOf(uint32_t node);   // long name if known, else "!xxxxxxxx"

  struct Stats { uint32_t heard, text, nodeinfo, duplicate, other_channel, not_for_us, undecodable; };
  const Stats& stats() const { return _stats; }

private:
  struct Name { uint32_t node; char long_name[40]; };
  uint8_t _key[MAX_KEY];
  int _key_len;
  uint8_t _hash;
  bool _configured;
  uint32_t _seen[SEEN];
  uint8_t _seen_next;
  Name _names[NAMES];
  uint8_t _names_next;
  uint8_t _buf[MAX_PACKET];
  char _fallback[12];
  Stats _stats;

  bool seenBefore(uint32_t from, uint32_t id);
  void remember(uint32_t node, const char* long_name);
};

}  // namespace meshtastic
