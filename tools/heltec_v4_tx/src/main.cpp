// Bench node for a Heltec V4 (ESP32-S3 + SX1262), with the same commands as lr2021-re's console:
//   set radio <MHz>,<BW kHz>,<SF>,<CR> | set sync <hex> | set preamble <n> | set tx <dBm>
//   loratx <hex>   -> "  -> OK <n> bytes"
//   hold off       receive with the current settings, one "RXSTAT len=.. st=.. data=<hex>" line per packet
//   hold on        stop receiving
//   cw <MHz> <ms>          unmodulated carrier (raw frequency word: works below RadioLib's 150 MHz floor)
//   cwid <MHz> <wpm> <text> Morse-keyed carrier, e.g. a callsign ID on a ham band
//   fsktx <MHz> <dev kHz> <hex>  one packet as a Fine Offset weather sensor sends it: FSK 17.24 kbit/s,
//                          preamble 0xAA.., sync word 0x2DD4, then the bytes (no CRC or whitening added)
//   fskraw <MHz> <kbps> <dev kHz> <sync hex> <hex>  the same with any bit rate and sync word (1-8 bytes),
//                          eg. La Crosse View: fskraw 915 9.6 35 d2aa2dd4 <11 bytes>
// Build and flash: cd tools/heltec_v4_tx && pio run -t upload
#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

#define PA_POWER 7      // FEM LDO
#define PA_EN    2      // GC1109 CSD / KCT8103L CSD
#define PA_TX_EN 46     // GC1109 CPS: low = bypass
#define VEXT     36

SPIClass spi(FSPI);
static volatile bool rx_flag = false;
static bool listening = false;
static void onRx() { rx_flag = true; }
SX1262 radio = new Module(8, 14, 12, 13, spi);
static float mhz = 908.0, bw = 62.5; static int sf = 7, cr = 5, dbm = 22, pre = 32; static uint8_t sync_word = 0x12;

static bool apply() {
  listening = false;
  int st = radio.begin(mhz, bw, sf, cr, sync_word, dbm, pre, 1.8);
  if (st == RADIOLIB_ERR_NONE) st = radio.setDio2AsRfSwitch(true);
  if (st == RADIOLIB_ERR_NONE) st = radio.setCurrentLimit(140);
  return st == RADIOLIB_ERR_NONE;
}

static uint32_t frf(float f) { return (uint32_t)((double)f * 1e6 * 33554432.0 / 32e6 + 0.5); }

static void keyed(float f, uint32_t ms) {
  radio.transmitDirect(frf(f));
  delay(ms);
  radio.standby();
}

static const char* morse(char c) {
  static const char* L[] = {".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--",
                            "-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--.."};
  static const char* D[] = {"-----",".----","..---","...--","....-",".....","-....","--...","---..","----."};
  if (c >= 'a' && c <= 'z') c -= 32;
  if (c >= 'A' && c <= 'Z') return L[c - 'A'];
  if (c >= '0' && c <= '9') return D[c - '0'];
  if (c == '/') return "-..-.";
  return NULL;
}

static void cwid(float f, int wpm, const char* text) {
  uint32_t dot = 1200 / (wpm > 0 ? wpm : 20);
  for (const char* p = text; *p; p++) {
    if (*p == ' ') { delay(dot * 4); continue; }
    const char* m = morse(*p);
    if (!m) continue;
    for (; *m; m++) { keyed(f, *m == '.' ? dot : dot * 3); delay(dot); }
    delay(dot * 2);
  }
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void handle(char* cmd) {
  if (!strncmp(cmd, "set radio ", 10)) {
    float f, b; int s, c;
    if (sscanf(cmd + 10, "%f,%f,%d,%d", &f, &b, &s, &c) == 4) { mhz = f; bw = b; sf = s; cr = c; }
    Serial.println(apply() ? "  -> OK" : "  -> ERR init");
  } else if (!strncmp(cmd, "set sync ", 9)) {
    sync_word = strtoul(cmd + 9, NULL, 16);
    Serial.println(apply() ? "  -> OK" : "  -> ERR init");
  } else if (!strncmp(cmd, "set preamble ", 13)) {
    pre = atoi(cmd + 13);
    Serial.println(apply() ? "  -> OK" : "  -> ERR init");
  } else if (!strncmp(cmd, "set tx ", 7)) {
    dbm = atoi(cmd + 7);
    Serial.println(apply() ? "  -> OK" : "  -> ERR init");
  } else if (!strcmp(cmd, "hold off")) {   // receive with the current settings, print each packet
    listening = true;
    radio.setPacketReceivedAction(onRx);
    radio.startReceive();
    Serial.println("hold st=0");
  } else if (!strncmp(cmd, "hold", 4)) {
    listening = false;
    radio.standby();
    Serial.println("hold st=0");
  } else if (!strncmp(cmd, "loratx ", 7)) {
    static uint8_t buf[255];
    size_t n = 0;
    for (const char* p = cmd + 7; p[0] && p[1] && n < sizeof(buf); p += 2) {
      int h = hexval(p[0]), l = hexval(p[1]);
      if (h < 0 || l < 0) break;
      buf[n++] = (uint8_t)(h << 4 | l);
    }
    radio.clearPacketReceivedAction();
    int st = radio.transmit(buf, n);
    if (listening) { radio.setPacketReceivedAction(onRx); radio.startReceive(); }
    if (st == RADIOLIB_ERR_NONE) Serial.printf("  -> OK %u bytes\r\n", (unsigned)n);
    else Serial.printf("  -> ERR %d\r\n", st);
  } else if (!strncmp(cmd, "fsktx ", 6) || !strncmp(cmd, "fskraw ", 7)) {
    bool raw = cmd[3] == 'r';
    float f, kbps = 17.24f, dev; int off = 0;
    static uint8_t buf[64];
    uint8_t sync[8] = { 0x2D, 0xD4 };   // fsktx: Fine Offset's sync word, every time
    size_t n = 0, slen = 2;
    const char* p = NULL;
    if (raw) {
      char sh[20];
      if (sscanf(cmd + 7, "%f %f %f %19s %n", &f, &kbps, &dev, sh, &off) >= 4 && off) {
        slen = 0;
        for (const char* q = sh; q[0] && q[1] && slen < sizeof(sync); q += 2) {
          int h = hexval(q[0]), l = hexval(q[1]);
          if (h < 0 || l < 0) break;
          sync[slen++] = (uint8_t)(h << 4 | l);
        }
        p = cmd + 7 + off;
      }
    } else if (sscanf(cmd + 6, "%f %f %n", &f, &dev, &off) >= 2 && off) {
      p = cmd + 6 + off;
    }
    for (; p && p[0] && p[1] && n < sizeof(buf); p += 2) {
      int h = hexval(p[0]), l = hexval(p[1]);
      if (h < 0 || l < 0) break;
      buf[n++] = (uint8_t)(h << 4 | l);
    }
    if (n == 0 || slen == 0) { Serial.println("  -> ERR args"); return; }
    listening = false;
    int st = radio.beginFSK(f, kbps, dev, 156.2, dbm, 40, 1.8);
    if (st == RADIOLIB_ERR_NONE) st = radio.setDio2AsRfSwitch(true);
    if (st == RADIOLIB_ERR_NONE) st = radio.setSyncWord(sync, slen);
    if (st == RADIOLIB_ERR_NONE) st = radio.setCRC(0);
    if (st == RADIOLIB_ERR_NONE) st = radio.setWhitening(false);
    if (st == RADIOLIB_ERR_NONE) st = radio.setDataShaping(RADIOLIB_SHAPING_NONE);
    if (st == RADIOLIB_ERR_NONE) st = radio.fixedPacketLengthMode(n);
    if (st == RADIOLIB_ERR_NONE) st = radio.transmit(buf, n);
    apply();   // back to LoRa
    if (st == RADIOLIB_ERR_NONE) Serial.printf("  -> OK %u bytes\r\n", (unsigned)n);
    else Serial.printf("  -> ERR %d\r\n", st);
  } else if (!strncmp(cmd, "cwid ", 5)) {
    float f; int wpm, off = 0;
    if (sscanf(cmd + 5, "%f %d %n", &f, &wpm, &off) >= 2 && off) {
      radio.setOutputPower(dbm);
      cwid(f, wpm, cmd + 5 + off);
      apply();
      Serial.println("  -> OK");
    } else Serial.println("  -> ERR args");
  } else if (!strncmp(cmd, "cw ", 3)) {
    float f; unsigned ms;
    if (sscanf(cmd + 3, "%f %u", &f, &ms) == 2) {
      radio.setOutputPower(dbm);
      keyed(f, ms);
      apply();
      Serial.println("  -> OK");
    } else Serial.println("  -> ERR args");
  } else if (cmd[0]) {
    Serial.println("  -> ERR unknown");
  }
}

void setup() {
  Serial.setRxBufferSize(1024);   // a loratx line with 255 bytes is 517 characters
  Serial.begin(115200);
  pinMode(VEXT, OUTPUT); digitalWrite(VEXT, HIGH);
  pinMode(PA_POWER, OUTPUT); digitalWrite(PA_POWER, HIGH);
  delay(2);
  pinMode(PA_EN, OUTPUT); digitalWrite(PA_EN, HIGH);
  pinMode(PA_TX_EN, OUTPUT); digitalWrite(PA_TX_EN, LOW);   // bypass: the SX1262's own power
  spi.begin(9, 11, 10, 8);
  apply();
}

void loop() {
  if (rx_flag) {
    rx_flag = false;
    static uint8_t buf[256];
    size_t n = radio.getPacketLength();
    int st = radio.readData(buf, n);
    Serial.printf("RXSTAT len=%u st=%d rssi=%.1f snr=%.1f data=", (unsigned)n, st, radio.getRSSI(), radio.getSNR());
    for (size_t i = 0; i < n; i++) Serial.printf("%02X", buf[i]);
    Serial.println();
    radio.startReceive();
  }
  static char line[600];
  static size_t n = 0;
  while (Serial.available()) {
    int ch = Serial.read();
    if (ch == '\r' || ch == '\n') { line[n] = 0; handle(line); n = 0; }
    else if (n < sizeof(line) - 1) line[n++] = (char)ch;
  }
}
