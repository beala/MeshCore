// Bench node for a Heltec V4 (ESP32-S3 + SX1262), with the same commands as lr2021-re's console:
//   set radio <MHz>,<BW kHz>,<SF>,<CR> | set sync <hex> | set preamble <n> | set tx <dBm>
//   loratx <hex>   -> "  -> OK <n> bytes"
//   hold off       receive with the current settings, one "RXSTAT len=.. st=.. data=<hex>" line per packet
//   hold on        stop receiving
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
