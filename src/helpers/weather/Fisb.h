#pragma once
// FIS-B: weather text (METAR, TAF, ...) from FAA ground stations on 978 MHz (UAT uplink frames).
// Error correction, the UAT header, information frames, FIS-B APDUs and DLAC text (docs/airport_weather.md).
// Written from the published format as documented by dump978; no code copied.
// Integer only and no allocation, so it builds for the companion and for the PC tests.

#include <stdint.h>
#include <stddef.h>

namespace fisb {

// On air after the 36-bit sync word 0x153225B1D: 552 bytes, 6 Reed-Solomon (92,72) blocks
// interleaved byte by byte (byte i belongs to block i mod 6), 432 data bytes in all.
static const int FRAME_BYTES = 552;
static const int DATA_BYTES = 432;
static const int BLOCKS = 6, BLOCK_BYTES = 92, BLOCK_DATA = 72;
static const uint64_t SYNC_WORD = 0x153225B1DULL;
static const uint16_t PRODUCT_TEXT = 413;   // generic text in DLAC: METAR, SPECI, TAF, PIREP, WINDS, ...

// Deinterleaves and corrects frame (FRAME_BYTES) into data (DATA_BYTES). Returns true if every block
// corrected, with the bytes fixed in *fixed. data may not overlap frame.
bool correct(const uint8_t* frame, uint8_t* data, int* fixed);

// The UAT header: the station's position and slot
struct Header {
  int32_t lat_e5, lon_e5;   // degrees x 1e5
  bool pos_valid, utc_coupled, app_valid;
  uint8_t slot, tisb_site;
};
void header(const uint8_t* data, Header* h);

// DLAC (6-bit characters, 4 in 3 bytes) to text. Tab (28) then a count is that many spaces; ETX (0)
// and the record separator (29) come through as '\x03' and '\x1e'. Returns the length written (out is
// always 0-terminated, cut short if n is too small).
int dlac(const uint8_t* in, int len, char* out, int n);

// Text reports in a frame's data, one at a time (one APDU can hold several, separated by '\x1e')
struct Text {
  uint16_t product;
  uint8_t hours, minutes;   // product time (UTC)
  const char* text;         // not 0-terminated; valid until the next call
  int len;
};

static const int TEXT_MAX = 600;   // one APDU's text: at most 418 bytes of DLAC, plus spaces from tabs

class Reports {
public:
  Reports() { start(NULL, 0); }
  Reports(const uint8_t* data, int len) { start(data, len); }
  void start(const uint8_t* data, int len);   // read another frame's data (it holds 600 bytes: reuse one)
  bool next(Text* out);   // the next text report, false at the end
private:
  const uint8_t* _d;
  int _len, _pos;           // next information frame
  char _buf[TEXT_MAX];
  int _blen, _bpos;         // the current APDU's text and where the next report in it starts
  uint16_t _product;
  uint8_t _hours, _minutes;
};

// A report's first three words, eg. "METAR KLMO 052153Z ...": the kind, location and time. Each out is
// 0-terminated and cut to its size. Returns false if there aren't three words.
bool words(const char* text, int len, char* kind, int kn, char* where, int wn, char* when, int tn);

// The report on one line: newlines and runs of spaces to one space, and no trailing '=' or spaces.
int oneLine(const char* text, int len, char* out, int n);

}  // namespace fisb
