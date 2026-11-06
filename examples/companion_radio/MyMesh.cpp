#include "MyMesh.h"
#include <helpers/ConsoleName.h>
#include <AesSiv.h>
#include <helpers/EntropyPool.h>

#include <Arduino.h> // needed for PlatformIO
#ifdef ENABLE_WIFI_INTERFACE
#include <WiFi.h>
#endif
#include <Mesh.h>
#include <helpers/FloodRetryCLI.h>

#define CMD_APP_START                 1
#define CMD_SEND_TXT_MSG              2
#define CMD_SEND_CHANNEL_TXT_MSG      3
#define CMD_GET_CONTACTS              4 // with optional 'since' (for efficient sync)
#define CMD_GET_DEVICE_TIME           5
#define CMD_SET_DEVICE_TIME           6
#define CMD_SEND_SELF_ADVERT          7
#define CMD_SET_ADVERT_NAME           8
#define CMD_ADD_UPDATE_CONTACT        9
#define CMD_SYNC_NEXT_MESSAGE         10
#define CMD_SET_RADIO_PARAMS          11
#define CMD_SET_RADIO_TX_POWER        12
#define CMD_RESET_PATH                13
#define CMD_SET_ADVERT_LATLON         14
#define CMD_REMOVE_CONTACT            15
#define CMD_SHARE_CONTACT             16
#define CMD_EXPORT_CONTACT            17
#define CMD_IMPORT_CONTACT            18
#define CMD_REBOOT                    19
#define CMD_GET_BATT_AND_STORAGE      20   // was CMD_GET_BATTERY_VOLTAGE
#define CMD_SET_TUNING_PARAMS         21
#define CMD_DEVICE_QUERY              22
#define CMD_EXPORT_PRIVATE_KEY        23
#define CMD_IMPORT_PRIVATE_KEY        24
#define CMD_SEND_RAW_DATA             25
#define CMD_SEND_LOGIN                26
#define CMD_SEND_STATUS_REQ           27
#define CMD_HAS_CONNECTION            28
#define CMD_LOGOUT                    29 // 'Disconnect'
#define CMD_GET_CONTACT_BY_KEY        30
#define CMD_GET_CHANNEL               31
#define CMD_SET_CHANNEL               32
#define CMD_SIGN_START                33
#define CMD_SIGN_DATA                 34
#define CMD_SIGN_FINISH               35
#define CMD_SEND_TRACE_PATH           36
#define CMD_SET_DEVICE_PIN            37
#define CMD_SET_OTHER_PARAMS          38
#define CMD_SEND_TELEMETRY_REQ        39  // can deprecate this
#define CMD_GET_CUSTOM_VARS           40
#define CMD_SET_CUSTOM_VAR            41
#define CMD_GET_ADVERT_PATH           42
#define CMD_GET_TUNING_PARAMS         43
// NOTE: CMD range 44..49 parked, potentially for WiFi operations
#define CMD_SEND_BINARY_REQ           50
#define CMD_FACTORY_RESET             51
#define CMD_SEND_PATH_DISCOVERY_REQ   52
#define CMD_SET_FLOOD_SCOPE_KEY       54   // v8+
#define CMD_SEND_CONTROL_DATA         55   // v8+
#define CMD_GET_STATS                 56   // v8+, second byte is stats type
#define CMD_SEND_ANON_REQ             57
#define CMD_SET_AUTOADD_CONFIG        58
#define CMD_GET_AUTOADD_CONFIG        59
#define CMD_GET_ALLOWED_REPEAT_FREQ   60
#define CMD_SET_PATH_HASH_MODE        61
#define CMD_SEND_CHANNEL_DATA         62
#define CMD_SET_DEFAULT_FLOOD_SCOPE   63
#define CMD_GET_DEFAULT_FLOOD_SCOPE   64
#define CMD_SEND_RAW_PACKET           65
#define CMD_RUN_CLI_COMMAND           66  // v14+

// Stats sub-types for CMD_GET_STATS
#define STATS_TYPE_CORE               0
#define STATS_TYPE_RADIO              1
#define STATS_TYPE_PACKETS             2

#define RESP_CODE_OK                  0
#define RESP_CODE_ERR                 1
#define RESP_CODE_CONTACTS_START      2  // first reply to CMD_GET_CONTACTS
#define RESP_CODE_CONTACT             3  // multiple of these (after CMD_GET_CONTACTS)
#define RESP_CODE_END_OF_CONTACTS     4  // last reply to CMD_GET_CONTACTS
#define RESP_CODE_SELF_INFO           5  // reply to CMD_APP_START
#define RESP_CODE_SENT                6  // reply to CMD_SEND_TXT_MSG
#define RESP_CODE_CONTACT_MSG_RECV    7  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
#define RESP_CODE_CHANNEL_MSG_RECV    8  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
#define RESP_CODE_CURR_TIME           9  // a reply to CMD_GET_DEVICE_TIME
#define RESP_CODE_NO_MORE_MESSAGES    10 // a reply to CMD_SYNC_NEXT_MESSAGE
#define RESP_CODE_EXPORT_CONTACT      11
#define RESP_CODE_BATT_AND_STORAGE    12 // a reply to a CMD_GET_BATT_AND_STORAGE
#define RESP_CODE_DEVICE_INFO         13 // a reply to CMD_DEVICE_QUERY
#define RESP_CODE_PRIVATE_KEY         14 // a reply to CMD_EXPORT_PRIVATE_KEY
#define RESP_CODE_DISABLED            15
#define RESP_CODE_CONTACT_MSG_RECV_V3 16 // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
#define RESP_CODE_CHANNEL_MSG_RECV_V3 17 // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
#define RESP_CODE_CHANNEL_INFO        18 // a reply to CMD_GET_CHANNEL
#define RESP_CODE_SIGN_START          19
#define RESP_CODE_SIGNATURE           20
#define RESP_CODE_CUSTOM_VARS         21
#define RESP_CODE_ADVERT_PATH         22
#define RESP_CODE_TUNING_PARAMS       23
#define RESP_CODE_STATS               24   // v8+, second byte is stats type
#define RESP_CODE_AUTOADD_CONFIG      25
#define RESP_ALLOWED_REPEAT_FREQ      26
#define RESP_CODE_CHANNEL_DATA_RECV   27
#define RESP_CODE_DEFAULT_FLOOD_SCOPE 28
#define RESP_CODE_CLI_REPLY           29  // v14+, a reply to CMD_RUN_CLI_COMMAND

#define MAX_CHANNEL_DATA_LENGTH       (MAX_FRAME_SIZE - 9)

#define SEND_TIMEOUT_BASE_MILLIS        500
#define FLOOD_SEND_TIMEOUT_FACTOR       16.0f
#define DIRECT_SEND_PERHOP_FACTOR       6.0f
#define DIRECT_SEND_PERHOP_EXTRA_MILLIS 250
#define LAZY_CONTACTS_WRITE_DELAY       5000

#define PUBLIC_GROUP_PSK                "izOH6cXN6mrJ5e26oRXNcg=="

// these are _pushed_ to client app at any time
#define PUSH_CODE_ADVERT                0x80
#define PUSH_CODE_PATH_UPDATED          0x81
#define PUSH_CODE_SEND_CONFIRMED        0x82
#define PUSH_CODE_MSG_WAITING           0x83
#define PUSH_CODE_RAW_DATA              0x84
#define PUSH_CODE_LOGIN_SUCCESS         0x85
#define PUSH_CODE_LOGIN_FAIL            0x86
#define PUSH_CODE_STATUS_RESPONSE       0x87
#define PUSH_CODE_LOG_RX_DATA           0x88
#define PUSH_CODE_TRACE_DATA            0x89
#define PUSH_CODE_NEW_ADVERT            0x8A
#define PUSH_CODE_TELEMETRY_RESPONSE    0x8B
#define PUSH_CODE_BINARY_RESPONSE       0x8C
#define PUSH_CODE_PATH_DISCOVERY_RESPONSE 0x8D
#define PUSH_CODE_CONTROL_DATA          0x8E   // v8+
#define PUSH_CODE_CONTACT_DELETED       0x8F // used to notify client app of deleted contact when overwriting oldest
#define PUSH_CODE_CONTACTS_FULL         0x90 // used to notify client app that contacts storage is full

#define ERR_CODE_UNSUPPORTED_CMD        1
#define ERR_CODE_NOT_FOUND              2
#define ERR_CODE_TABLE_FULL             3
#define ERR_CODE_BAD_STATE              4
#define ERR_CODE_FILE_IO_ERROR          5
#define ERR_CODE_ILLEGAL_ARG            6

#define MAX_SIGN_DATA_LEN               (8 * 1024) // 8K

// Auto-add config bitmask
// Bit 0: If set, overwrite oldest non-favourite contact when contacts file is full
// Bits 1-4: these indicate which contact types to auto-add when manual_contact_mode = 0x01
#define AUTO_ADD_OVERWRITE_OLDEST (1 << 0)  // 0x01 - overwrite oldest non-favourite when full
#define AUTO_ADD_CHAT             (1 << 1)  // 0x02 - auto-add Chat (Companion) (ADV_TYPE_CHAT)
#define AUTO_ADD_REPEATER         (1 << 2)  // 0x04 - auto-add Repeater (ADV_TYPE_REPEATER)
#define AUTO_ADD_ROOM_SERVER      (1 << 3)  // 0x08 - auto-add Room Server (ADV_TYPE_ROOM)
#define AUTO_ADD_SENSOR           (1 << 4)  // 0x10 - auto-add Sensor (ADV_TYPE_SENSOR)

void MyMesh::writeOKFrame() {
  uint8_t buf[1];
  buf[0] = RESP_CODE_OK;
  _serial->writeFrame(buf, 1);
}
void MyMesh::writeErrFrame(uint8_t err_code) {
  uint8_t buf[2];
  buf[0] = RESP_CODE_ERR;
  buf[1] = err_code;
  _serial->writeFrame(buf, 2);
}

void MyMesh::writeDisabledFrame() {
  uint8_t buf[1];
  buf[0] = RESP_CODE_DISABLED;
  _serial->writeFrame(buf, 1);
}

void MyMesh::writeContactRespFrame(uint8_t code, const ContactInfo &contact) {
  int i = 0;
  out_frame[i++] = code;
  memcpy(&out_frame[i], contact.id.pub_key, PUB_KEY_SIZE);
  i += PUB_KEY_SIZE;
  out_frame[i++] = contact.type;
  out_frame[i++] = contact.flags;
  out_frame[i++] = contact.out_path_len;
  memcpy(&out_frame[i], contact.out_path, MAX_PATH_SIZE);
  i += MAX_PATH_SIZE;
  if (!isConsoleKey(contact.id.pub_key) && ConsoleName::looksLikeConsole(contact.name)) {
    // a node posing as the Radio console contact: show it as fake, so it can't be mistaken for it
    ConsoleName::markFake((char *)&out_frame[i], 32, contact.name);
  } else {
    StrHelper::strzcpy((char *)&out_frame[i], contact.name, 32);
  }
  i += 32;
  memcpy(&out_frame[i], &contact.last_advert_timestamp, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.gps_lat, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.gps_lon, 4);
  i += 4;
  memcpy(&out_frame[i], &contact.lastmod, 4);
  i += 4;
  _serial->writeFrame(out_frame, i);
}

void MyMesh::updateContactFromFrame(ContactInfo &contact, uint32_t& last_mod, const uint8_t *frame, int len) {
  int i = 0;
  i++; // skip the command code, eg. CMD_ADD_UPDATE_CONTACT
  memcpy(contact.id.pub_key, &frame[i], PUB_KEY_SIZE);
  i += PUB_KEY_SIZE;
  contact.type = frame[i++];
  contact.flags = frame[i++];
  contact.out_path_len = frame[i++];
  memcpy(contact.out_path, &frame[i], MAX_PATH_SIZE);
  i += MAX_PATH_SIZE;
  memcpy(contact.name, &frame[i], 32);
  i += 32;
  memcpy(&contact.last_advert_timestamp, &frame[i], 4);
  i += 4;
  if (len >= i + 8) { // optional fields
    memcpy(&contact.gps_lat, &frame[i], 4);
    i += 4;
    memcpy(&contact.gps_lon, &frame[i], 4);
    i += 4;
    if (len >= i + 4) {
      memcpy(&last_mod, &frame[i], 4);
    }
  }
}

bool MyMesh::Frame::isChannelMsg() const {
  return buf[0] == RESP_CODE_CHANNEL_MSG_RECV || buf[0] == RESP_CODE_CHANNEL_MSG_RECV_V3 ||
         buf[0] == RESP_CODE_CHANNEL_DATA_RECV;
}

void MyMesh::addToOfflineQueue(const uint8_t frame[], int len) {
  if (offline_queue_len >= OFFLINE_QUEUE_SIZE) {
    MESH_DEBUG_PRINTLN("WARN: offline_queue is full!");
    int pos = 0;
    while (pos < offline_queue_len) {
      if (offline_queue[pos].isChannelMsg()) {
        for (int i = pos; i < offline_queue_len - 1; i++) { // delete oldest channel msg from queue
          offline_queue[i] = offline_queue[i + 1];
        }
        MESH_DEBUG_PRINTLN("INFO: removed oldest channel message from queue.");
        offline_queue[offline_queue_len - 1].len = len;
        memcpy(offline_queue[offline_queue_len - 1].buf, frame, len);
        return;
      }
      pos++;
    }
    MESH_DEBUG_PRINTLN("INFO: no channel messages to remove from queue.");
  } else {
    offline_queue[offline_queue_len].len = len;
    memcpy(offline_queue[offline_queue_len].buf, frame, len);
    offline_queue_len++;
  }
}

int MyMesh::getFromOfflineQueue(uint8_t frame[]) {
  if (offline_queue_len > 0) {         // check offline queue
    size_t len = offline_queue[0].len; // take from top of queue
    memcpy(frame, offline_queue[0].buf, len);

    offline_queue_len--;
    for (int i = 0; i < offline_queue_len; i++) { // delete top item from queue
      offline_queue[i] = offline_queue[i + 1];
    }
    return len;
  }
  return 0; // queue is empty
}

float MyMesh::getAirtimeBudgetFactor() const {
  return _prefs.airtime_factor;
}

int MyMesh::getInterferenceThreshold() const {
  return _prefs.interference_threshold;
}
bool MyMesh::getCADEnabled() const {
  return _prefs.cad_enabled;
}

int MyMesh::calcRxDelay(float score, uint32_t air_time) const {
  if (_prefs.rx_delay_base <= 0.0f) return 0;
  return (int)((pow(_prefs.rx_delay_base, 0.85f - score) - 1.0) * air_time);
}

uint32_t MyMesh::getRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}
uint32_t MyMesh::getDirectRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.direct_tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}

uint8_t MyMesh::getFloodRetries(const mesh::Packet* packet) {
  // only asked for packets some node should pass on (see FloodRetry::canEcho)
  if (packet->isRouteDirect()) return _prefs.flood_retry.count;   // a repeater is next on the path
  if (packet->getPathHashCount() == 0 && packet->getPayloadType() != PAYLOAD_TYPE_ADVERT) {
    return _prefs.flood_retry.count;   // a flood packet we started (adverts repeat on a timer anyway)
  }
  return 0;
}

uint32_t MyMesh::getFloodRetryWait(const mesh::Packet* packet) {
  return _prefs.flood_retry.wait_ms ? _prefs.flood_retry.wait_ms : mesh::Mesh::getFloodRetryWait(packet);
}

// ---------- radios sharing this identity (see CloneCoordinator) ----------

bool MyMesh::allowReplyTo(const ContactInfo& to) {
  return _clone.allowReply();   // a backup leaves all answers to the main radio
}

void MyMesh::onSiblingPacket(const ContactInfo& to, mesh::Packet* pkt, uint8_t type) {
  unsigned long now = _ms->getMillis();
  _clone.onSibling();
  StrHelper::strncpy(_sibling_name, to.name, sizeof(_sibling_name));
  _sibling_heard = now;

  // normal: any packet shows another radio uses this key. Main: only a reply (a flood reply carries a
  // path), since backups never send one; that radio must have missed the takeover.
  bool reply = type == PAYLOAD_TYPE_PATH;
  bool alert = _clone.role() == CLONE_ROLE_SOLO || (_clone.role() == CLONE_ROLE_MAIN && reply);
  if (alert && _clone.alertDue(now)) {
    char msg[200];
    if (_clone.role() == CLONE_ROLE_MAIN) {
      snprintf(msg, sizeof(msg), "Another radio with this key also replied to %s, so it missed the takeover. "
               "Send the takeover again? Reply \"yes\".", to.name);
    } else {
      snprintf(msg, sizeof(msg), "Another radio with this key is active: it sent to %s. Make this the main "
               "radio, so the others stay quiet? Reply \"yes\".", to.name);
    }
    consoleNote(msg);
    _takeover_offered = true;
  }
}

void MyMesh::onSelfDataRecv(mesh::Packet* packet, uint8_t type, const uint8_t* data, size_t len) {
  if (type == PAYLOAD_TYPE_REQ && _clone.onClaim(data, len)) {
    saveCloneState();
    consoleNote("Another radio with this key took over. This one is now a backup: it shows the messages it "
                "hears, but doesn't answer them.");
  }
}

void MyMesh::saveCloneState() {
  _prefs.clone.role = _clone.role();
  _prefs.clone.epoch = _clone.epoch();
  savePrefs();
}

bool MyMesh::sendClaim() {
  uint8_t data[16];
  int len = _clone.writeClaim(data);
  mesh::Packet* pkt = createSelfDatagram(PAYLOAD_TYPE_REQ, data, len);
  if (pkt == NULL) return false;
  if (send_unscoped) {
    sendFlood(pkt, (uint32_t) 0, _prefs.path_hash_mode + 1);
  } else {
    TransportKey default_scope;
    memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));
    sendFloodScoped(send_scope.isNull() ? default_scope : send_scope, pkt, 0);
  }
  return true;
}

void MyMesh::takeover(char* reply) {
  _clone.takeover(getRTCClock()->getCurrentTime());
  saveCloneState();
  if (sendClaim()) {
    strcpy(reply, "This is now the main radio. Other radios with this key go quiet when they hear it.");
  } else {
    strcpy(reply, "This is now the main radio, but the claim couldn't be sent (no free packet). Try again.");
  }
}

bool MyMesh::handleCloneCommand(const char* command, char* reply) {
  if (handleCloneTransferCommand(command, reply)) return true;
  if (_xfer_on && strcmp(command, "takeover") == 0) {
    strcpy(reply, "Error: a copy is running ('clone stop' ends it).");
    return true;
  }
  if (strcmp(command, "takeover") == 0) {
    takeover(reply);
    return true;
  }
  if (strcmp(command, "clone off") == 0) {
    _clone.setSolo();
    saveCloneState();
    strcpy(reply, "OK, this radio answers as normal again.");
    return true;
  }
  if (strcmp(command, "clone") == 0 || strcmp(command, "get clone") == 0) {
    static const char* roles[] = { "normal", "main", "backup" };
    int n = snprintf(reply, 160, "Role: %s.", roles[_clone.role()]);
    if (_clone.isBackup()) {
      n += snprintf(&reply[n], 160 - n, " Messages left unanswered: %u.", (unsigned)_clone.silenced());
    }
    if (_sibling_heard) {
      snprintf(&reply[n], 160 - n, " Other radio heard %lu min ago, to %s.",
               (unsigned long)((_ms->getMillis() - _sibling_heard) / 60000), _sibling_name);
    } else {
      snprintf(&reply[n], 160 - n, " No other radio heard yet.");
    }
    return true;
  }
  return false;
}

// ---------- console contact ----------

#define CONSOLE_NAME  "Radio console"
#define CONSOLE_CONFIRM_DELAY  300   // ms: give the app time to note the ACK code before it's confirmed

void MyMesh::fillConsoleContact(ContactInfo& c) {
  memset((void*) &c, 0, sizeof(c));
  // stable, and can't be a real node: a hash of our own key
  mesh::Utils::sha256(c.id.pub_key, PUB_KEY_SIZE, (const uint8_t *) CONSOLE_NAME, strlen(CONSOLE_NAME),
                      self_id.pub_key, PUB_KEY_SIZE);
  StrHelper::strncpy(c.name, CONSOLE_NAME, sizeof(c.name));
  c.type = ADV_TYPE_CHAT;
  c.out_path_len = 0;   // shows as a direct contact
  c.lastmod = _console_lastmod;
}

bool MyMesh::isConsoleKey(const uint8_t* prefix) {
  ContactInfo c;
  fillConsoleContact(c);
  return memcmp(c.id.pub_key, prefix, 6) == 0;
}

void MyMesh::consoleNote(const char* text) {
  ContactInfo c;
  fillConsoleContact(c);
  mesh::Packet pkt;   // stands in for a received packet: direct, no path
  pkt.header = ROUTE_TYPE_DIRECT;
  pkt.path_len = 0;
  pkt._snr = 0;
  uint32_t ts = getRTCClock()->getCurrentTimeUnique();
  _console_lastmod = ts;
  queueMessage(c, TXT_TYPE_PLAIN, &pkt, ts, NULL, 0, text);
}

void MyMesh::checkConsole() {
  if (_serial->isWriteBusy()) return;
  if (!_console_pending) {
    if (_console_offer_pending) {   // the user sent a message from a backup
      _console_offer_pending = false;
      consoleNote("This radio is a backup, so it doesn't answer messages, and replies to you may go to the "
                  "main radio. Make this the main radio? Reply \"yes\".");
      _takeover_offered = true;
    }
    return;
  }
  if (!millisHasNowPassed(_console_due)) return;
  _console_pending = false;

  if (_console_from.kind != CHAT_CHANNEL) {   // channel messages have no "delivered"
    out_frame[0] = PUSH_CODE_SEND_CONFIRMED;
    memcpy(&out_frame[1], &_console_ack, 4);
    uint32_t trip_time = 0;
    memcpy(&out_frame[5], &trip_time, 4);
    _serial->writeFrame(out_frame, 9);
  }
  if (_console_cmd[0] == 0) return;   // the app sent the last command again: already run

  char* cmd = _console_cmd;
  while (*cmd == ' ') cmd++;
  bool console = _console_from.kind == CHAT_CONSOLE;
  if (console && *cmd == '/') cmd++;   // "/help" works in the console too
  // phones capitalise the first letter: match the command word in lower case (all of a '/'
  // command, which has no names in it)
  for (char* c = cmd; *c && (!console || *c != ' '); c++) *c = tolower(*c);

  char reply[256];   // more than handleCommand() needs, so the console's own texts have room
  reply[0] = 0;
  _find_started = false;
  if (!console) {
    handleSlashCommand(_console_from, cmd, reply);
  } else {
    bool offered = _takeover_offered;
    _takeover_offered = false;
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
      strcpy(reply, "takeover: make this the main radio\n"
                    "clone: status\n"
                    "clone off: answer as normal\n"
                    "In a chat, send /help for its commands\n"
                    "Every CLI command works here too, e.g. uptime");
    } else if (strcmp(cmd, "yes") == 0) {
      if (offered) takeover(reply);
      else strcpy(reply, "Nothing to confirm. Send \"help\".");
    } else if (!handleCommand(cmd, 0, reply)) {
      strcpy(reply, "Unknown command. Send \"help\".");
    }
  }
  if (_find_started) {   // a find request went out: its answer shows in this chat
    _find_chat = _console_from;
    ContactInfo* c = lookupContactByPubKey(_find_peer, PUB_KEY_SIZE);
    sprintf(reply, "Asked %s, the answer will show here.", c ? c->name : "them");
  }
  if (reply[0]) postToChat(_console_from, reply);
}

// A message the user typed: -1 if it's a '/' command (a '/' then a letter), else its length,
// with "//" at the start turned into "/" so text starting with '/' can still be sent
int MyMesh::takeSlashCommand(char* text, int len) {
  if (len >= 2 && text[0] == '/' && isalpha((unsigned char) text[1])) return -1;
  if (len >= 2 && text[0] == '/' && text[1] == '/') {
    memmove(text, &text[1], len - 1);
    return len - 1;
  }
  return len;
}

// Take a command typed in a chat (the console, a DM or a channel): tell the app it's sent, and
// checkConsole() runs it shortly after, replying in the same chat
void MyMesh::queueChatCommand(const ChatRef& from, uint32_t ts, const char* text, int len) {
  if (_console_pending) {
    writeErrFrame(ERR_CODE_TABLE_FULL);   // still running the last one
    return;
  }
  if (ts != 0 && ts == _console_last_ts) {
    _console_cmd[0] = 0;   // the app is resending a command it sent: confirm it, but don't run it again
  } else {
    if (len < 0) len = 0;
    if (len > (int) sizeof(_console_cmd) - 1) len = sizeof(_console_cmd) - 1;
    memcpy(_console_cmd, text, len);
    _console_cmd[len] = 0;
  }
  _console_last_ts = ts;
  _console_from = from;
  _console_pending = true;
  _console_due = futureMillis(CONSOLE_CONFIRM_DELAY);

  if (from.kind == CHAT_CHANNEL) {
    writeOKFrame();
    return;
  }
  do { getRNG()->random((uint8_t *) &_console_ack, 4); } while (_console_ack == 0);
  out_frame[0] = RESP_CODE_SENT;
  out_frame[1] = 0;   // direct
  memcpy(&out_frame[2], &_console_ack, 4);
  uint32_t est_timeout = 3000;
  memcpy(&out_frame[6], &est_timeout, 4);
  _serial->writeFrame(out_frame, 10);
}

// Show a reply in a chat, as a message received there. In a DM or channel it starts with a gear,
// so it doesn't read as something the contact wrote. It stays on this radio and phone.
void MyMesh::postToChat(const ChatRef& to, const char* text) {
  // A message holds about 150 bytes of text: send a longer reply as several, split at a line
  // break or space where there is one
  const int max_part = 140;
  char part[max_part + 1];
  while ((int) strlen(text) > max_part) {
    int cut = max_part;
    for (int k = max_part; k > max_part / 2; k--) {   // a line break if there's one, else a space
      if (text[k] == '\n') { cut = k; break; }
    }
    if (cut == max_part) {
      for (int k = max_part; k > max_part / 2; k--) {
        if (text[k] == ' ') { cut = k; break; }
      }
    }
    while (cut > 0 && (((uint8_t) text[cut]) & 0xC0) == 0x80) cut--;   // don't split a character
    memcpy(part, text, cut);
    part[cut] = 0;
    postPart(to, part);
    text += cut;
    if (*text == '\n' || *text == ' ') text++;
  }
  postPart(to, text);
}

void MyMesh::postPart(const ChatRef& to, const char* text) {
  if (to.kind == CHAT_CONSOLE) {
    consoleNote(text);
    return;
  }
  mesh::Packet pkt;   // stands in for a received packet: direct, no path
  pkt.header = ROUTE_TYPE_DIRECT;
  pkt.path_len = 0;
  pkt._snr = 0;
  uint32_t ts = getRTCClock()->getCurrentTimeUnique();
  char msg[MAX_FRAME_SIZE + 1];
  if (to.kind == CHAT_CONTACT) {
    ContactInfo* c = lookupContactByPubKey(to.pub_key, PUB_KEY_SIZE);
    if (c == NULL) return;
    snprintf(msg, sizeof(msg), "\xE2\x9A\x99 %s", text);
    queueMessage(*c, TXT_TYPE_PLAIN, &pkt, ts, NULL, 0, msg);
  } else if (to.kind == CHAT_CHANNEL) {
    snprintf(msg, sizeof(msg), "\xE2\x9A\x99 Radio: %s", text);   // channel texts are "sender: text"
    pushChannelText(to.channel_idx, ts, 0, 0xFF, msg, strlen(msg));
  }
}

// Shows a text in a channel as if received there; it stays on this radio and phone.
// path_len 0xFF = direct.
void MyMesh::pushChannelText(uint8_t channel_idx, uint32_t ts, int8_t snr_x4, uint8_t path_len, const char* text, int len) {
  int i = 0;
  if (app_target_ver >= 3) {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV_V3;
    out_frame[i++] = (uint8_t) snr_x4;
    out_frame[i++] = 0;
    out_frame[i++] = 0;
  } else {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV;
  }
  out_frame[i++] = channel_idx;
  out_frame[i++] = path_len;
  out_frame[i++] = TXT_TYPE_PLAIN;
  memcpy(&out_frame[i], &ts, 4);
  i += 4;
  int tlen = len;
  if (tlen < 0) tlen = 0;
  if (i + tlen > MAX_FRAME_SIZE) tlen = MAX_FRAME_SIZE - i;
  memcpy(&out_frame[i], text, tlen);
  i += tlen;
  addToOfflineQueue(out_frame, i);
  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING;
    _serial->writeFrame(frame, 1);
  }
}

// A '/' command typed in a DM or channel, in lower case without the '/'. It applies to that chat.
void MyMesh::handleSlashCommand(const ChatRef& from, char* cmd, char* reply) {
  char* arg = strchr(cmd, ' ');
  if (arg) {
    *arg++ = 0;
    while (*arg == ' ') arg++;
    for (char* e = arg + strlen(arg); e > arg && e[-1] == ' '; ) *--e = 0;
  } else {
    arg = cmd + strlen(cmd);
  }
  bool help = strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0;
  const char* unknown = "Unknown command. Send /help. To send text starting with /, type //";

  if (from.kind == CHAT_CHANNEL) {
#ifdef MAX_GROUP_CHANNELS
    ChannelDetails ch;
    if (!getChannel(from.channel_idx, ch)) {
      strcpy(reply, "Error: channel not found");
    } else if (help) {
      strcpy(reply, "Commands here run on your radio, nothing is sent:\n"
                    "/crypto: this channel's encryption\n"
                    "/crypto legacy|v2|v2only: change it\n"
                    "//text: send text starting with /");
    } else if (strcmp(cmd, "crypto") == 0 && *arg == 0) {
      sprintf(reply, "> %s: %s", ch.name, CryptoPolicyTable::name(getCryptoPolicy(ch.channel.secret)));
    } else if (strcmp(cmd, "crypto") == 0) {
      int p = CryptoPolicyTable::parse(arg);
      if (p < 0) {
        strcpy(reply, "Error: use /crypto legacy, v2 or v2only");
      } else if (setCryptoPolicy(ch.channel.secret, p, reply)) {
        sprintf(reply, "OK - %s: %s", ch.name, CryptoPolicyTable::name(p));
      }
    } else {
      strcpy(reply, unknown);
    }
#else
    strcpy(reply, unknown);
#endif
    return;
  }

  ContactInfo* c = lookupContactByPubKey(from.pub_key, PUB_KEY_SIZE);
  if (c == NULL) {
    strcpy(reply, "Error: contact not found");
  } else if (help) {   // too long for one message
    postToChat(from, "Commands here run on your radio, nothing is sent:\n"
                     "/range: distance to them\n"
                     "/beep, /beep stop: make their radio beep");
    strcpy(reply, "/crypto: encryption with them\n"
                  "/crypto legacy|v2|v2only: change it\n"
                  "/path, /path reset: route to them\n"
                  "//text: send text starting with /");
  } else if (strcmp(cmd, "range") == 0 && *arg == 0) {
    startFind(c, _prefs.find.ext ? "find range ext" : "find range", reply);
  } else if (strcmp(cmd, "beep") == 0 && (*arg == 0 || strcmp(arg, "stop") == 0)) {
    startFind(c, *arg ? "find me stop" : "find me", reply);
  } else if (strcmp(cmd, "crypto") == 0 && *arg == 0) {
    sprintf(reply, "> %s: %s", c->name, CryptoPolicyTable::name(getCryptoPolicy(c->getSharedSecret(self_id))));
  } else if (strcmp(cmd, "crypto") == 0) {
    int p = CryptoPolicyTable::parse(arg);
    if (p < 0) {
      strcpy(reply, "Error: use /crypto legacy, v2 or v2only");
    } else if (setCryptoPolicy(c->getSharedSecret(self_id), p, reply)) {
      sprintf(reply, "OK - %s: %s", c->name, CryptoPolicyTable::name(p));
    }
  } else if (strcmp(cmd, "path") == 0 && *arg == 0) {
    if (c->out_path_len == OUT_PATH_UNKNOWN) {
      sprintf(reply, "> No route to %s yet: messages go by flood", c->name);
    } else {
      int sz = (c->out_path_len >> 6) + 1, n = c->out_path_len & 63;
      if (n == 0) {
        sprintf(reply, "> Direct to %s, no repeaters", c->name);
      } else {
        int k = sprintf(reply, "> %d hop%s:", n, n == 1 ? "" : "s");
        for (int h = 0; h < n && k < 150; h++) {
          reply[k++] = h == 0 ? ' ' : ',';
          mesh::Utils::toHex(&reply[k], &c->out_path[h * sz], sz);
          k += sz * 2;
        }
        reply[k] = 0;
      }
    }
  } else if (strcmp(cmd, "path") == 0 && strcmp(arg, "reset") == 0) {
    c->out_path_len = OUT_PATH_UNKNOWN;
    onContactPathUpdated(*c);   // tells the app, and saves the contacts
    sprintf(reply, "OK - the next message to %s goes by flood and finds a new route", c->name);
  } else {
    strcpy(reply, unknown);
  }
}

uint8_t MyMesh::getExtraAckTransmitCount() const {
  return _prefs.multi_acks;
}

void MyMesh::logRxRaw(float snr, float rssi, const uint8_t raw[], int len) {
  // Apps only understand v1: show them v2 packets we can decrypt in their v1 form, so they still
  // recognise echoes of their own messages ("heard N repeats").
  uint8_t legacy[MAX_TRANS_UNIT];
  int legacy_len;
  if (_serial->isConnected() && toLegacyForm(raw, len, legacy, legacy_len)) {
    raw = legacy;
    len = legacy_len;
  }
  if (_serial->isConnected() && len + 3 <= MAX_FRAME_SIZE) {
    int i = 0;
    out_frame[i++] = PUSH_CODE_LOG_RX_DATA;
    out_frame[i++] = (int8_t)(snr * 4);
    out_frame[i++] = (int8_t)(rssi);
    memcpy(&out_frame[i], raw, len);
    i += len;

    _serial->writeFrame(out_frame, i);
  }
}

bool MyMesh::isAutoAddEnabled() const {
  return (_prefs.manual_add_contacts & 1) == 0;
}

bool MyMesh::shouldAutoAddContactType(uint8_t contact_type) const {
  if ((_prefs.manual_add_contacts & 1) == 0) {
    return true;
  }

  uint8_t type_bit = 0;
  switch (contact_type) {
    case ADV_TYPE_CHAT:
      type_bit = AUTO_ADD_CHAT;
      break;
    case ADV_TYPE_REPEATER:
      type_bit = AUTO_ADD_REPEATER;
      break;
    case ADV_TYPE_ROOM:
      type_bit = AUTO_ADD_ROOM_SERVER;
      break;
    case ADV_TYPE_SENSOR:
      type_bit = AUTO_ADD_SENSOR;
      break;
    default:
      return false;  // Unknown type, don't auto-add
  }

  return (_prefs.autoadd_config & type_bit) != 0;
}

bool MyMesh::shouldOverwriteWhenFull() const {
  return (_prefs.autoadd_config & AUTO_ADD_OVERWRITE_OLDEST) != 0;
}

uint8_t MyMesh::getAutoAddMaxHops() const {
  return _prefs.autoadd_max_hops;
}

void MyMesh::onContactOverwrite(const uint8_t* pub_key) {
    _store->deleteBlobByKey(pub_key, PUB_KEY_SIZE); // delete from storage
  if (_serial->isConnected()) {
    out_frame[0] = PUSH_CODE_CONTACT_DELETED;
    memcpy(&out_frame[1], pub_key, PUB_KEY_SIZE);
    _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE);
  }
}

void MyMesh::onContactsFull() {
  if (_serial->isConnected()) {
    out_frame[0] = PUSH_CODE_CONTACTS_FULL;
    _serial->writeFrame(out_frame, 1);
  }
}

void MyMesh::onDiscoveredContact(ContactInfo &contact, bool is_new, uint8_t path_len, const uint8_t* path) {
  if (_serial->isConnected()) {
    if (is_new) {
      writeContactRespFrame(PUSH_CODE_NEW_ADVERT, contact);
    } else {
      out_frame[0] = PUSH_CODE_ADVERT;
      memcpy(&out_frame[1], contact.id.pub_key, PUB_KEY_SIZE);
      _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE);
    }
  }

  // add inbound-path to mem cache
  if (path && mesh::Packet::isValidPathLen(path_len)) {  // check path is valid
    AdvertPath* p = advert_paths;
    uint32_t oldest = 0xFFFFFFFF;
    for (int i = 0; i < ADVERT_PATH_TABLE_SIZE; i++) {   // check if already in table, otherwise evict oldest
      if (memcmp(advert_paths[i].pubkey_prefix, contact.id.pub_key, sizeof(AdvertPath::pubkey_prefix)) == 0) {
        p = &advert_paths[i];   // found
        break;
      }
      if (advert_paths[i].recv_timestamp < oldest) {
        oldest = advert_paths[i].recv_timestamp;
        p = &advert_paths[i];
      }
    }

    memcpy(p->pubkey_prefix, contact.id.pub_key, sizeof(p->pubkey_prefix));
    strcpy(p->name, contact.name);
    p->recv_timestamp = getRTCClock()->getCurrentTime();
    p->path_len = mesh::Packet::copyPath(p->path, path, path_len);
  }

  if (_listener) _listener->onDiscoveredContact(contact, is_new, path_len, path);

  if (!is_new) dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY); // only schedule lazy write for contacts that are in contacts[]
}

static int sort_by_recent(const void *a, const void *b) {
  return ((AdvertPath *) b)->recv_timestamp - ((AdvertPath *) a)->recv_timestamp;
}

int MyMesh::getRecentlyHeard(AdvertPath dest[], int max_num) {
  if (max_num > ADVERT_PATH_TABLE_SIZE) max_num = ADVERT_PATH_TABLE_SIZE;
  qsort(advert_paths, ADVERT_PATH_TABLE_SIZE, sizeof(advert_paths[0]), sort_by_recent);

  for (int i = 0; i < max_num; i++) {
    dest[i] = advert_paths[i];
  }
  return max_num;
}

void MyMesh::onContactPathUpdated(const ContactInfo &contact) {
  out_frame[0] = PUSH_CODE_PATH_UPDATED;
  memcpy(&out_frame[1], contact.id.pub_key, PUB_KEY_SIZE);
  _serial->writeFrame(out_frame, 1 + PUB_KEY_SIZE); // NOTE: app may not be connected

  dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
}

ContactInfo*  MyMesh::processAck(const uint8_t *data) {
  if (_listener) {
    uint32_t ack_crc;
    memcpy(&ack_crc, data, 4);
    _listener->onACKRecv(ack_crc);
  }
  // see if matches any in a table
  for (int i = 0; i < EXPECTED_ACK_TABLE_SIZE; i++) {
    if (memcmp(data, &expected_ack_table[i].ack, 4) == 0) { // got an ACK from recipient
      out_frame[0] = PUSH_CODE_SEND_CONFIRMED;
      memcpy(&out_frame[1], data, 4);
      uint32_t trip_time = _ms->getMillis() - expected_ack_table[i].msg_sent;
      memcpy(&out_frame[5], &trip_time, 4);
      _serial->writeFrame(out_frame, 9);

      // NOTE: the same ACK can be received multiple times!
      expected_ack_table[i].ack = 0; // clear expected hash, now that we have received ACK
      return expected_ack_table[i].contact;
    }
  }
  return checkConnectionsAck(data);
}

void MyMesh::queueMessage(const ContactInfo &from, uint8_t txt_type, mesh::Packet *pkt,
                          uint32_t sender_timestamp, const uint8_t *extra, int extra_len, const char *text) {
  int i = 0;
  if (app_target_ver >= 3) {
    out_frame[i++] = RESP_CODE_CONTACT_MSG_RECV_V3;
    out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
    out_frame[i++] = 0; // reserved1
    out_frame[i++] = 0; // reserved2
  } else {
    out_frame[i++] = RESP_CODE_CONTACT_MSG_RECV;
  }
  memcpy(&out_frame[i], from.id.pub_key, 6);
  i += 6; // just 6-byte prefix
  out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;   // path length
  out_frame[i++] = txt_type;
  memcpy(&out_frame[i], &sender_timestamp, 4);
  i += 4;
  if (extra_len > 0) {
    memcpy(&out_frame[i], extra, extra_len);
    i += extra_len;
  }
  int tlen = strlen(text); // TODO: UTF-8 ??
  if (i + tlen > MAX_FRAME_SIZE) {
    tlen = MAX_FRAME_SIZE - i;
  }
  memcpy(&out_frame[i], text, tlen);
  i += tlen;
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }

  if (_listener) {
    _listener->onMessageRecv(pkt, from, txt_type, sender_timestamp, text);
    _listener->onQueueSizeChanged(offline_queue_len);
  }
}

bool MyMesh::filterRecvFloodPacket(mesh::Packet* packet) {
  // REVISIT: try to determine which Region (from transport_codes[1]) that Sender is indicating for replies/responses
  //    if unknown, fallback to finding Region from transport_codes[0], the 'scope' used by Sender
  return false;
}

bool MyMesh::allowPacketForward(const mesh::Packet* packet) {
  return _prefs.isRepeatEn();
}

void MyMesh::sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis) {
  if (scope.isNull()) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);
  } else {
    uint16_t codes[2];
    codes[0] = scope.calcTransportCode(pkt);
    codes[1] = 0;  // REVISIT: set to 'home' Region, for sender/return region?
    sendFlood(pkt, codes, delay_millis, _prefs.path_hash_mode + 1);
  }
}

void MyMesh::sendFloodScoped(const ContactInfo& recipient, mesh::Packet* pkt, uint32_t delay_millis) {
  // TODO: dynamic send_scope, depending on recipient and current 'home' Region
  if (send_unscoped) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);  // app has explicitly requested un-scoped
  } else {
    TransportKey default_scope;
    memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));

    auto scope = send_scope.isNull() ? &default_scope : &send_scope;
    sendFloodScoped(*scope, pkt, delay_millis);
  }
}
void MyMesh::sendFloodScoped(const mesh::GroupChannel& channel, mesh::Packet* pkt, uint32_t delay_millis) {
  // TODO: have per-channel send_scope
  if (send_unscoped) {
    sendFlood(pkt, delay_millis, _prefs.path_hash_mode + 1);  // app has explicitly requested un-scoped
  } else {
    TransportKey default_scope;
    memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));

    auto scope = send_scope.isNull() ? &default_scope : &send_scope;
    sendFloodScoped(*scope, pkt, delay_millis);
  }
}

void MyMesh::onMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                           const char *text) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  queueMessage(from, TXT_TYPE_PLAIN, pkt, sender_timestamp, NULL, 0, text);
}

void MyMesh::onCommandDataRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp, const char *text) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  // an answer to 'find beep/stop/range'? Already shown in the chat the request was typed in, so not again
  if (onFindReply(from, text)) return;
  queueMessage(from, TXT_TYPE_CLI_DATA, pkt, sender_timestamp, NULL, 0, text);
}

void MyMesh::onCLICommandRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                               const char *text, char* reply) {
  markConnectionActive(from); // in case this is from a server, and we have a connection
  if (isFindRequest(text)) {  // another companion looking for this radio (MyMeshFind.cpp)
    handleFindRequest(from, sender_timestamp, text, reply);
    return;
  }
  if (from.isRemoteCLIAllowed()) {
    _cli_remote = true;
    if (!handleCommand(text, sender_timestamp, reply)) {
      strcat(reply, "Unknown command");   // reply may have cmd prefix from 'text'
    }
    _cli_remote = false;
  } else {
    queueMessage(from, TXT_TYPE_CLI_COMMAND, pkt, sender_timestamp, NULL, 0, text);
  }
}

void MyMesh::onSignedMessageRecv(const ContactInfo &from, mesh::Packet *pkt, uint32_t sender_timestamp,
                                 const uint8_t *sender_prefix, const char *text) {
  markConnectionActive(from);
  // from.sync_since change needs to be persisted
  dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
  queueMessage(from, TXT_TYPE_SIGNED_PLAIN, pkt, sender_timestamp, sender_prefix, 4, text);
}

void MyMesh::onChannelMessageRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint32_t timestamp,
                                  const char *text) {
  int i = 0;
  if (app_target_ver >= 3) {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV_V3;
    out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
    out_frame[i++] = 0; // reserved1
    out_frame[i++] = 0; // reserved2
  } else {
    out_frame[i++] = RESP_CODE_CHANNEL_MSG_RECV;
  }

  uint8_t channel_idx = findChannelIdx(channel);
  out_frame[i++] = channel_idx;
  out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;   // path length

  out_frame[i++] = TXT_TYPE_PLAIN;
  memcpy(&out_frame[i], &timestamp, 4);
  i += 4;
  int tlen = strlen(text); // TODO: UTF-8 ??
  if (i + tlen > MAX_FRAME_SIZE) {
    tlen = MAX_FRAME_SIZE - i;
  }
  memcpy(&out_frame[i], text, tlen);
  i += tlen;
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }
  if (_listener) {
    // Get the channel name from the channel index
    ChannelDetails channel_details;
    if (!getChannel(channel_idx, channel_details)) {
      strcpy(channel_details.name, "Unknown");
    }
    _listener->onChannelMessageRecv(pkt, channel_details, text);
    _listener->onQueueSizeChanged(offline_queue_len);
  }
}

void MyMesh::onChannelDataRecv(const mesh::GroupChannel &channel, mesh::Packet *pkt, uint16_t data_type,
                               const uint8_t *data, size_t data_len) {
  if (data_len > MAX_CHANNEL_DATA_LENGTH) {
    MESH_DEBUG_PRINTLN("onChannelDataRecv: dropping payload_len=%d exceeds frame limit=%d",
                       (uint32_t)data_len, (uint32_t)MAX_CHANNEL_DATA_LENGTH);
    return;
  }

  int i = 0;
  out_frame[i++] = RESP_CODE_CHANNEL_DATA_RECV;
  out_frame[i++] = (int8_t)(pkt->getSNR() * 4);
  out_frame[i++] = 0; // reserved1
  out_frame[i++] = 0; // reserved2

  uint8_t channel_idx = findChannelIdx(channel);
  out_frame[i++] = channel_idx;
  out_frame[i++] = pkt->isRouteFlood() ? pkt->path_len : 0xFF;
  out_frame[i++] = (uint8_t)(data_type & 0xFF);
  out_frame[i++] = (uint8_t)(data_type >> 8);
  out_frame[i++] = (uint8_t)data_len;

  int copy_len = (int)data_len;
  if (copy_len > 0) {
    memcpy(&out_frame[i], data, copy_len);
    i += copy_len;
  }
  addToOfflineQueue(out_frame, i);

  if (_serial->isConnected()) {
    uint8_t frame[1];
    frame[0] = PUSH_CODE_MSG_WAITING; // send push 'tickle'
    _serial->writeFrame(frame, 1);
  }
  if (_listener) {
    _listener->onChannelDataRecv(pkt, channel, data_type, data, data_len);
  }
}

uint8_t MyMesh::onContactRequest(const ContactInfo &contact, uint32_t sender_timestamp, const uint8_t *data,
                                 uint8_t len, uint8_t *reply) {
  if (data[0] == REQ_TYPE_GET_TELEMETRY_DATA) {
    uint8_t permissions = 0;
    uint8_t cp = contact.flags >> 1; // LSB used as 'favourite' bit (so only use upper bits)

    if (_prefs.telemetry_mode_base == TELEM_MODE_ALLOW_ALL) {
      permissions = TELEM_PERM_BASE;
    } else if (_prefs.telemetry_mode_base == TELEM_MODE_ALLOW_FLAGS) {
      permissions = cp & TELEM_PERM_BASE;
    }

    if (_prefs.telemetry_mode_loc == TELEM_MODE_ALLOW_ALL) {
      permissions |= TELEM_PERM_LOCATION;
    } else if (_prefs.telemetry_mode_loc == TELEM_MODE_ALLOW_FLAGS) {
      permissions |= cp & TELEM_PERM_LOCATION;
    }

    if (_prefs.telemetry_mode_env == TELEM_MODE_ALLOW_ALL) {
      permissions |= TELEM_PERM_ENVIRONMENT;
    } else if (_prefs.telemetry_mode_env == TELEM_MODE_ALLOW_FLAGS) {
      permissions |= cp & TELEM_PERM_ENVIRONMENT;
    }

    uint8_t perm_mask = ~(data[1]);    // NEW: first reserved byte (of 4), is now inverse mask to apply to permissions
    permissions &= perm_mask;

    if (permissions & TELEM_PERM_BASE) { // only respond if base permission bit is set
      telemetry.reset();
      telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);
      // query other sensors -- target specific
      sensors.querySensors(permissions, telemetry);

      float temperature = board.getMCUTemperature();
      if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
        telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
      }

      memcpy(reply, &sender_timestamp,
             4); // reflect sender_timestamp back in response packet (kind of like a 'tag')

      uint8_t tlen = telemetry.getSize();
      memcpy(&reply[4], telemetry.getBuffer(), tlen);
      return 4 + tlen;
    }
  } else if (_listener) {
    return _listener->onUnhandledRequest(contact, sender_timestamp, data, len, reply);
  }
  return 0; // unknown
}

void MyMesh::onContactResponse(const ContactInfo &contact, const uint8_t *data, uint8_t len) {
  uint32_t tag;
  memcpy(&tag, data, 4);

  if (pending_login && memcmp(&pending_login, contact.id.pub_key, 4) == 0) { // check for login response
    // yes, is response to pending sendLogin()
    pending_login = 0;

    int i = 0;
    if (memcmp(&data[4], "OK", 2) == 0) { // legacy Repeater login OK response
      out_frame[i++] = PUSH_CODE_LOGIN_SUCCESS;
      out_frame[i++] = 0; // legacy: is_admin = false
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6;                                     // pub_key_prefix
    } else if (data[4] == RESP_SERVER_LOGIN_OK) { // new login response
      uint16_t keep_alive_secs = ((uint16_t)data[5]) * 16;
      if (keep_alive_secs > 0) {
        startConnection(contact, keep_alive_secs);
      }
      out_frame[i++] = PUSH_CODE_LOGIN_SUCCESS;
      out_frame[i++] = data[6]; // permissions (eg. is_admin)
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6; // pub_key_prefix
      memcpy(&out_frame[i], &tag, 4);
      i += 4; // NEW: include server timestamp
      out_frame[i++] = data[7]; // NEW (v7): ACL permissions
      out_frame[i++] = data[12]; // FIRMWARE_VER_LEVEL
    } else {
      out_frame[i++] = PUSH_CODE_LOGIN_FAIL;
      out_frame[i++] = 0; // reserved
      memcpy(&out_frame[i], contact.id.pub_key, 6);
      i += 6; // pub_key_prefix
    }
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && // check for status response
             pending_status &&
             memcmp(&pending_status, contact.id.pub_key, 4) == 0 // legacy matching scheme
                                                                 // FUTURE: tag == pending_status
  ) {
    pending_status = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_STATUS_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], contact.id.pub_key, 6);
    i += 6; // pub_key_prefix
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && tag == pending_telemetry) {  // check for matching response tag
    pending_telemetry = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_TELEMETRY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], contact.id.pub_key, 6);
    i += 6; // pub_key_prefix
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else if (len > 4 && tag == pending_req) {  // check for matching response tag
    pending_req = 0;

    int i = 0;
    out_frame[i++] = PUSH_CODE_BINARY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], &tag, 4);   // app needs to match this to RESP_CODE_SENT.tag
    i += 4;
    memcpy(&out_frame[i], &data[4], len - 4);
    i += (len - 4);
    _serial->writeFrame(out_frame, i);
  } else {
    bool handled;
    if (_listener && len > 4) {
      handled = _listener->onUnhandledResponse(contact, tag, &data[4], len - 4);
    } else {
      handled = false;
    }
    if (!handled) {   // let the app know about unknown/unhandled responses (eg. push telemetry packets)
      int i = 0;
      out_frame[i++] = PUSH_CODE_BINARY_RESPONSE;
      out_frame[i++] = 0; // reserved
      memcpy(&out_frame[i], data, len);
      i += len;
      _serial->writeFrame(out_frame, i);
    }
  }
}

bool MyMesh::onContactPathRecv(ContactInfo& contact, uint8_t* in_path, uint8_t in_path_len, uint8_t* out_path, uint8_t out_path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) {
  if (extra_type == PAYLOAD_TYPE_RESPONSE && extra_len > 4) {
    uint32_t tag;
    memcpy(&tag, extra, 4);

    if (tag == pending_discovery) {  // check for matching response tag)
      pending_discovery = 0;

      if (!mesh::Packet::isValidPathLen(in_path_len) || !mesh::Packet::isValidPathLen(out_path_len)) {
        MESH_DEBUG_PRINTLN("onContactPathRecv, invalid path sizes: %d, %d", in_path_len, out_path_len);
      } else {
        int i = 0;
        out_frame[i++] = PUSH_CODE_PATH_DISCOVERY_RESPONSE;
        out_frame[i++] = 0; // reserved
        memcpy(&out_frame[i], contact.id.pub_key, 6);
        i += 6; // pub_key_prefix
        out_frame[i++] = out_path_len;
        i += mesh::Packet::writePath(&out_frame[i], out_path, out_path_len);
        out_frame[i++] = in_path_len;
        i += mesh::Packet::writePath(&out_frame[i], in_path, in_path_len);
        // NOTE: telemetry data in 'extra' is discarded at present

        _serial->writeFrame(out_frame, i);
      }
      return false;  // DON'T send reciprocal path!
    }
  }
  // let base class handle received path and data
  bool reciprocal = BaseChatMesh::onContactPathRecv(contact, in_path, in_path_len, out_path, out_path_len, extra_type, extra, extra_len);
  // a backup leaves the reciprocal path to the main radio, so the contact learns one path to this key
  return reciprocal && !_clone.isBackup();
}

void MyMesh::onControlDataRecv(mesh::Packet *packet) {
  if (packet->payload_len + 4 > (int) sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onControlDataRecv(), payload_len too long: %d", packet->payload_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_CONTROL_DATA;
  out_frame[i++] = (int8_t)(_radio->getLastSNR() * 4);
  out_frame[i++] = (int8_t)(_radio->getLastRSSI());
  out_frame[i++] = packet->path_len;
  memcpy(&out_frame[i], packet->payload, packet->payload_len);
  i += packet->payload_len;

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onControlDataRecv(), data received while app offline");
  }

  if (_listener) _listener->onControlDataRecv(packet);
}

void MyMesh::onRawDataRecv(mesh::Packet *packet) {
  if (packet->payload_len + 4 > (int) sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onRawDataRecv(), payload_len too long: %d", packet->payload_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_RAW_DATA;
  out_frame[i++] = (int8_t)(_radio->getLastSNR() * 4);
  out_frame[i++] = (int8_t)(_radio->getLastRSSI());
  out_frame[i++] = 0xFF; // reserved (possibly path_len in future)
  memcpy(&out_frame[i], packet->payload, packet->payload_len);
  i += packet->payload_len;

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onRawDataRecv(), data received while app offline");
  }
  if (_listener) {
    _listener->onRawDataRecv(packet);
  }
}

void MyMesh::onTraceRecv(mesh::Packet *packet, uint32_t tag, uint32_t auth_code, uint8_t flags,
                         const uint8_t *path_snrs, const uint8_t *path_hashes, uint8_t path_len) {
  uint8_t path_sz = flags & 0x03;  // NEW v1.11+
  if (12 + path_len + (path_len >> path_sz) + 1 > (int) sizeof(out_frame)) {
    MESH_DEBUG_PRINTLN("onTraceRecv(), path_len is too long: %d", (uint32_t)path_len);
    return;
  }
  int i = 0;
  out_frame[i++] = PUSH_CODE_TRACE_DATA;
  out_frame[i++] = 0; // reserved
  out_frame[i++] = path_len;
  out_frame[i++] = flags;
  memcpy(&out_frame[i], &tag, 4);
  i += 4;
  memcpy(&out_frame[i], &auth_code, 4);
  i += 4;
  memcpy(&out_frame[i], path_hashes, path_len);
  i += path_len;

  memcpy(&out_frame[i], path_snrs, path_len >> path_sz);
  i += path_len >> path_sz;
  out_frame[i++] = (int8_t)(packet->getSNR() * 4); // extra/final SNR (to this node)

  if (_serial->isConnected()) {
    _serial->writeFrame(out_frame, i);
  } else {
    MESH_DEBUG_PRINTLN("onTraceRecv(), data received while app offline");
  }
  if (_listener) {
    _listener->onTraceRecv(packet, tag, auth_code, flags, path_snrs, path_hashes, path_len);
  }
}

uint32_t MyMesh::calcFloodTimeoutMillisFor(uint32_t pkt_airtime_millis) const {
  return SEND_TIMEOUT_BASE_MILLIS + (FLOOD_SEND_TIMEOUT_FACTOR * pkt_airtime_millis);
}
uint32_t MyMesh::calcDirectTimeoutMillisFor(uint32_t pkt_airtime_millis, uint8_t path_len) const {
  uint8_t path_hash_count = path_len & 63;
  return SEND_TIMEOUT_BASE_MILLIS +
         ((pkt_airtime_millis * DIRECT_SEND_PERHOP_FACTOR + DIRECT_SEND_PERHOP_EXTRA_MILLIS) *
          (path_hash_count + 1));
}

void MyMesh::onSendTimeout() {}

MyMesh::MyMesh(mesh::Radio &radio, mesh::RNG &rng, mesh::RTCClock &rtc, SimpleMeshTables &tables, DataStore& store)
    : BaseChatMesh(radio, *new ArduinoMillis(), rng, rtc, *new StaticPoolPacketManager(16), tables),
      _store(&store), _serial(NULL), _listener(NULL), _iter(0), telemetry(MAX_PACKET_PAYLOAD - 4) {
  _iter_started = false;
  _iter_console_pending = false;
  _console_pending = false;
  _console_ack = 0;
  _console_lastmod = 0;
  _console_cmd[0] = 0;
  _console_last_ts = 0;
  _console_due = 0;
  _console_offer_pending = false;
  _takeover_offered = false;
  _sibling_name[0] = 0;
  memset(&_console_from, 0, sizeof(_console_from));
  _console_from.kind = CHAT_CONSOLE;
  memset(&_find_chat, 0, sizeof(_find_chat));
  _find_started = false;
  _sibling_heard = 0;
  _cli_rescue = false;
  cli_command[0] = 0;
  offline_queue_len = 0;
  app_target_ver = 0;
  clearPendingReqs();
  next_ack_idx = 0;
  sign_data = NULL;
  dirty_contacts_expiry = 0;
  memset(advert_paths, 0, sizeof(advert_paths));
  memset(send_scope.key, 0, sizeof(send_scope.key));
  send_unscoped = false;

  // defaults
  _prefs.airtime_factor = 1.0;
  _prefs.tx_delay_factor = 0.5f;
  _prefs.direct_tx_delay_factor = 0.2f;
  strcpy(_prefs.node_name, "NONAME");
  _prefs.freq = LORA_FREQ;
  _prefs.sf = LORA_SF;
  _prefs.bw = LORA_BW;
  _prefs.cr = LORA_CR;
  _prefs.tx_power_dbm = LORA_TX_POWER;
  _prefs.gps_enabled = 0;       // GPS disabled by default
  _prefs.gps_interval = 0;      // No automatic GPS updates by default
  _prefs.radio_fem_rxgain = 1;
#ifdef RADIO_FEM_TXGAIN
  _prefs.radio_fem_txgain = RADIO_FEM_TXGAIN;   // board-specific default for PA
#else
  _prefs.radio_fem_txgain = 0;
#endif
  //_prefs.rx_delay_base = 10.0f;  enable once new algo fixed
  _prefs.setRepeatEn(false);
#if defined(USE_SX1262) || defined(USE_SX1268)
#ifdef SX126X_RX_BOOSTED_GAIN
  _prefs.rx_boosted_gain = SX126X_RX_BOOSTED_GAIN;
#else
  _prefs.rx_boosted_gain = 1; // enabled by default
#endif
#endif
}

void MyMesh::begin() {
  BaseChatMesh::begin();

  if (!_store->loadMainIdentity(self_id)) {
    self_id = radio_new_identity(); // create new random identity
    int count = 0;
    while (count < 10 && (self_id.pub_key[0] == 0x00 || self_id.pub_key[0] == 0xFF)) { // reserved id hashes
      self_id = radio_new_identity();
      count++;
    }
    if (EntropyPool::readyForKeys()) {
      _store->saveMainIdentity(self_id);
      _identity_state = 1;
    } else {
      _identity_state = 2;
      // not enough trusted entropy: use this key for now but don't keep it, try again next boot
      MESH_DEBUG_PRINTLN("WARNING: not enough entropy for a permanent key (%d bits), identity not saved",
                         EntropyPool::creditedBits());
    }
  }

// if name is provided as a build flag, use that as default node name instead
#ifdef ADVERT_NAME
  strcpy(_prefs.node_name, ADVERT_NAME);
#else
  // use hex of first 4 bytes of identity public key as default node name
  char pub_key_hex[10];
  mesh::Utils::toHex(pub_key_hex, self_id.pub_key, 4);
  strcpy(_prefs.node_name, pub_key_hex);
#endif

  // if build provides default-scope, init with that
#ifdef DEFAULT_FLOOD_SCOPE_NAME
  strcpy(_prefs.default_scope_name, DEFAULT_FLOOD_SCOPE_NAME);
  {
    TransportKeyStore temp;
    TransportKey key;
    temp.getAutoKeyFor(0, "#" DEFAULT_FLOOD_SCOPE_NAME, key);
    memcpy(_prefs.default_scope_key, key.key, sizeof(key.key));
  }
#endif

  // load persisted prefs
  _prefs.led_off = 0xFF;   // marks "not saved yet", see below
  _store->loadPrefs(_prefs);
  if (_prefs.led_off == 0xFF) {
    // a new device, or the first boot of a firmware with this setting: apply this build's defaults
#ifdef STATUS_LED_DEFAULT_OFF
    _prefs.led_off = 1;
#else
    _prefs.led_off = 0;
#endif
#ifdef BUZZER_DEFAULT_OFF
    _prefs.buzzer_quiet = 1;
#endif
#ifdef VIBE_DEFAULT_OFF
    _prefs.vibe_quiet = 1;
#endif
  }
  sensors.node_lat = _prefs.node_lat;
  sensors.node_lon = _prefs.node_lon;

  // sanitise bad pref values
  _prefs.rx_delay_base = constrain(_prefs.rx_delay_base, 0, 20.0f);
  _prefs.tx_delay_factor = constrain(_prefs.tx_delay_factor, 0, 2.0f);
  _prefs.direct_tx_delay_factor = constrain(_prefs.direct_tx_delay_factor, 0, 2.0f);
  _prefs.airtime_factor = constrain(_prefs.airtime_factor, 0, 9.0f);
  _prefs.freq = constrain(_prefs.freq, 150.0f, 2500.0f);
  _prefs.bw = constrain(_prefs.bw, 7.8f, 500.0f);
  _prefs.sf = constrain(_prefs.sf, 5, 12);
  _prefs.cr = constrain(_prefs.cr, 5, 8);
  _prefs.tx_power_dbm = constrain(_prefs.tx_power_dbm, -9, MAX_LORA_TX_POWER);
  _prefs.gps_enabled = constrain(_prefs.gps_enabled, 0, 1);  // Ensure boolean 0 or 1
  _prefs.gps_interval = constrain(_prefs.gps_interval, 0, 86400);  // Max 24 hours

  // pick a random tag for our takeover claims, on first boot. Kept below 2^31: prefs read numbers
  // back with atol(), which stops at 0x7FFFFFFF, so bigger tags would all load as the same value.
  if (_prefs.clone.tag == 0 || _prefs.clone.tag >= 0x7FFFFFFF) {
    do {
      getRNG()->random((uint8_t *) &_prefs.clone.tag, 4);
      _prefs.clone.tag &= 0x7FFFFFFF;
    } while (_prefs.clone.tag == 0 || _prefs.clone.tag == 0x7FFFFFFF);
    savePrefs();
  }
  _clone.load(_prefs.clone.role, _prefs.clone.epoch, _prefs.clone.tag);
  _console_lastmod = getRTCClock()->getCurrentTime();

  _active_ble_pin = _prefs.ble_pin;

  resetContacts();
  _store->loadContacts(this);
  bootstrapRTCfromContacts();
  addChannel("Public", PUBLIC_GROUP_PSK); // pre-configure public channel
  _store->loadChannels(this);
  _store->loadCryptoPolicies(crypto_policies, _crypto_seq);
  if (_prefs.crypto_seq > _crypto_seq) {
    // prefs say a newer policy file was saved than the one we could load: it was lost or rolled back.
    // Don't silently fall back to accepting v1 (see 'set crypto.recover').
    _crypto_lost = true;
    MESH_DEBUG_PRINTLN("encryption policies lost (have seq %u, expected %u): v2 only until recovered",
                       _crypto_seq, _prefs.crypto_seq);
  }

  applyMeshtastic();   // may load the on-chip scanner, which restarts the radio: settings come next
  applyRadioPrefs();
  applyWeather();
  applyAircraft();
  radio_driver.setTxLedEnabled(!_prefs.led_off);
  loadFindAllow();

  board.attachDynamicPrefs(_prefs.getCustom());
  sensors.attachDynamicPrefs(_prefs.getCustom());

  MESH_DEBUG_PRINTLN("RX Boosted Gain Mode: %s",
                     radio_driver.getRxBoostedGainMode() ? "Enabled" : "Disabled");
}

const char *MyMesh::getNodeName() {
  return _prefs.node_name;
}
NodePrefs *MyMesh::getNodePrefs() {
  return &_prefs;
}
uint32_t MyMesh::getBLEPin() {
  return _active_ble_pin;
}
void MyMesh::setBLEPin(uint32_t active_pin) {
  _active_ble_pin = active_pin;
}

struct FreqRange {
  uint32_t lower_freq, upper_freq;
};

static FreqRange repeat_freq_ranges[] = {
  #ifdef ALLOWED_REPEAT_FREQ_RANGE
  ALLOWED_REPEAT_FREQ_RANGE
  #else
  { 433000, 433000 },
  { 869495, 869495 },
  { 918000, 918000 }
  #endif
};

bool MyMesh::isValidClientRepeatFreq(uint32_t f) const {
  for (size_t i = 0; i < sizeof(repeat_freq_ranges)/sizeof(repeat_freq_ranges[0]); i++) {
    auto r = &repeat_freq_ranges[i];
    if (f >= r->lower_freq && f <= r->upper_freq) return true;
  }
  return false;
}

void MyMesh::startInterface(BaseSerialInterface &serial) {
  _serial = &serial;
  serial.enable();
}

void MyMesh::handleCmdFrame(size_t len) {
  if (cmd_frame[0] == CMD_DEVICE_QUERY && len >= 2) { // sent when app establishes connection
    app_target_ver = cmd_frame[1];                    // which version of protocol does app understand

    int i = 0;
    out_frame[i++] = RESP_CODE_DEVICE_INFO;
    out_frame[i++] = FIRMWARE_VER_CODE;
    out_frame[i++] = MAX_CONTACTS / 2;   // v3+
    out_frame[i++] = MAX_GROUP_CHANNELS + virtualChannelCount(); // v3+; then the fixed synthetic slots (Meshtastic, Weather, Aircraft)
    memcpy(&out_frame[i], &_prefs.ble_pin, 4);
    i += 4;
    memset(&out_frame[i], 0, 12);
    strcpy((char *)&out_frame[i], FIRMWARE_BUILD_DATE);
    i += 12;
    StrHelper::strzcpy((char *)&out_frame[i], board.getManufacturerName(), 40);
    i += 40;
    StrHelper::strzcpy((char *)&out_frame[i], FIRMWARE_VERSION, 20);
    i += 20;
    out_frame[i++] = _prefs.isRepeatEn() ? 1 : 0;   // v9+
    out_frame[i++] = _prefs.path_hash_mode;  // v10+
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_APP_START &&
             len >= 8) { // sent when app establishes connection, respond with node ID
    //  cmd_frame[1..7]  reserved future
    char *app_name = (char *)&cmd_frame[8];
    cmd_frame[len] = 0; // make app_name null terminated
    MESH_DEBUG_PRINTLN("App %s connected", app_name);

    _iter_started = false; // stop any left-over ContactsIterator
    int i = 0;
    out_frame[i++] = RESP_CODE_SELF_INFO;
    out_frame[i++] = ADV_TYPE_CHAT; // what this node Advert identifies as (maybe node's pronouns too?? :-)
    out_frame[i++] = _prefs.tx_power_dbm;
    out_frame[i++] = MAX_LORA_TX_POWER;
    memcpy(&out_frame[i], self_id.pub_key, PUB_KEY_SIZE);
    i += PUB_KEY_SIZE;

    int32_t lat, lon;
    lat = (sensors.node_lat * 1000000.0);
    lon = (sensors.node_lon * 1000000.0);
    memcpy(&out_frame[i], &lat, 4);
    i += 4;
    memcpy(&out_frame[i], &lon, 4);
    i += 4;
    out_frame[i++] = _prefs.multi_acks; // new v7+
    out_frame[i++] = _prefs.advert_loc_policy;
    out_frame[i++] = (_prefs.telemetry_mode_env << 4) | (_prefs.telemetry_mode_loc << 2) |
                     (_prefs.telemetry_mode_base); // v5+
    out_frame[i++] = _prefs.manual_add_contacts;

    uint32_t freq = _prefs.freq * 1000;
    memcpy(&out_frame[i], &freq, 4);
    i += 4;
    uint32_t bw = _prefs.bw * 1000;
    memcpy(&out_frame[i], &bw, 4);
    i += 4;
    out_frame[i++] = _prefs.sf;
    out_frame[i++] = _prefs.cr;

    int tlen = strlen(_prefs.node_name); // revisit: UTF_8 ??
    memcpy(&out_frame[i], _prefs.node_name, tlen);
    i += tlen;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_RUN_CLI_COMMAND && len >= 3) { // V14+
    int i = 1;
    char *text = (char *)&cmd_frame[i];
    int tlen = len - i;
    text[tlen] = 0; // ensure null

    reply_buf[0] = 0;
    if (!handleCommand(text, 0, reply_buf)) {
      strcat(reply_buf, "Unknown command");   // reply_buf may have cmd prefix from 'text'
    }
    out_frame[0] = RESP_CODE_CLI_REPLY;
    int rlen = strlen(reply_buf);
    memcpy(&out_frame[1], reply_buf, rlen);
    _serial->writeFrame(out_frame, 1 + rlen);
  } else if (cmd_frame[0] == CMD_SEND_TXT_MSG && len >= 14 && isConsoleKey(&cmd_frame[7])) {
    // a message to the console contact: run it here, never send it
    uint32_t ts;
    memcpy(&ts, &cmd_frame[3], 4);
    ChatRef from;
    memset(&from, 0, sizeof(from));
    from.kind = CHAT_CONSOLE;
    queueChatCommand(from, ts, (const char*) &cmd_frame[13], len - 13);
  } else if (cmd_frame[0] == CMD_SEND_TXT_MSG && len >= 14) {
    int i = 1;
    uint8_t txt_type = cmd_frame[i++];
    uint8_t attempt = cmd_frame[i++];
    uint32_t msg_timestamp;
    memcpy(&msg_timestamp, &cmd_frame[i], 4);
    i += 4;
    uint8_t *pub_key_prefix = &cmd_frame[i];
    i += 6;
    ContactInfo *recipient = lookupContactByPubKey(pub_key_prefix, 6);
    if (recipient && (txt_type == TXT_TYPE_PLAIN || txt_type == TXT_TYPE_CLI_DATA || txt_type == TXT_TYPE_CLI_COMMAND)) {
      char *text = (char *)&cmd_frame[i];
      int tlen = len - i;
      uint32_t est_timeout;
      text[tlen] = 0; // ensure null
      if (txt_type == TXT_TYPE_PLAIN) {
        int n = takeSlashCommand(text, tlen);
        if (n < 0) {   // a '/' command for this chat: run it here, don't send it
          ChatRef from;
          memset(&from, 0, sizeof(from));
          from.kind = CHAT_CONTACT;
          memcpy(from.pub_key, recipient->id.pub_key, PUB_KEY_SIZE);
          queueChatCommand(from, msg_timestamp, &text[1], tlen - 1);
          return;
        }
        tlen = n;
        text[tlen] = 0;
      }
      int result;
      uint32_t expected_ack;
      if (txt_type == TXT_TYPE_CLI_DATA || txt_type == TXT_TYPE_CLI_COMMAND) {
        msg_timestamp = getRTCClock()->getCurrentTimeUnique(); // Use node's RTC instead of app timestamp to avoid tripping replay protection
        result = sendCommandData(*recipient, msg_timestamp, attempt, txt_type, text, est_timeout);
        expected_ack = 0; // no Ack expected
      } else {
        result = sendMessage(*recipient, msg_timestamp, attempt, text, expected_ack, est_timeout);
      }
      // TODO: add expected ACK to table
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        if (expected_ack) {
          expected_ack_table[next_ack_idx].msg_sent = _ms->getMillis(); // add to circular table
          expected_ack_table[next_ack_idx].ack = expected_ack;
          expected_ack_table[next_ack_idx].contact = recipient;
          next_ack_idx = (next_ack_idx + 1) % EXPECTED_ACK_TABLE_SIZE;
        }

        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &expected_ack, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);

        // the user is writing from a backup, which doesn't answer: offer to make it main
        if (txt_type == TXT_TYPE_PLAIN && _clone.promptDue(_ms->getMillis())) _console_offer_pending = true;
      }
    } else {
      writeErrFrame(recipient == NULL
                        ? ERR_CODE_NOT_FOUND
                        : ERR_CODE_UNSUPPORTED_CMD); // unknown recipient, or unsupported TXT_TYPE_*
    }
  } else if (cmd_frame[0] == CMD_SEND_CHANNEL_TXT_MSG && len >= 7) { // send GroupChannel text msg
    // 7 = code, txt_type, channel_idx and the 4 byte timestamp; the text may be empty.
    // Without this the text length below is computed as len - 7 and turns negative.
    int i = 1;
    uint8_t txt_type = cmd_frame[i++]; // should be TXT_TYPE_PLAIN
    uint8_t channel_idx = cmd_frame[i++];
    uint32_t msg_timestamp;
    memcpy(&msg_timestamp, &cmd_frame[i], 4);
    i += 4;
    const char *text = (char *)&cmd_frame[i];

    if (txt_type != TXT_TYPE_PLAIN) {
      writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);
    } else if (isMeshtasticChannel(channel_idx) || isWeatherChannel(channel_idx) || isAircraftChannel(channel_idx)) {   // receive only
      writeOKFrame();
      ChatRef to;
      memset(&to, 0, sizeof(to));
      to.kind = CHAT_CHANNEL;
      to.channel_idx = channel_idx;
      postToChat(to, isWeatherChannel(channel_idx) ? "Not sent: the Weather channel is receive-only"
                     : isAircraftChannel(channel_idx) ? "Not sent: the Aircraft channel is receive-only"
                                                      : "Not sent: the Meshtastic channel is receive-only");
    } else {
      ChannelDetails channel;
      bool success = getChannel(channel_idx, channel);
      int tlen = len - i;
      if (success) tlen = takeSlashCommand((char*) text, tlen);
      if (tlen < 0) {   // a '/' command for this channel: run it here, don't send it
        ChatRef from;
        memset(&from, 0, sizeof(from));
        from.kind = CHAT_CHANNEL;
        from.channel_idx = channel_idx;
        queueChatCommand(from, msg_timestamp, &text[1], len - i - 1);
      } else if (success && sendGroupMessage(msg_timestamp, channel.channel, _prefs.node_name, text, tlen)) {
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
      }
    }
  } else if (cmd_frame[0] == CMD_SEND_CHANNEL_DATA) { // send GroupChannel datagram
    if (len < 4) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      return;
    }
    int i = 1;
    uint8_t channel_idx = cmd_frame[i++];
    uint8_t path_len = cmd_frame[i++];

    // validate path len, allowing 0xFF for flood
    if (!mesh::Packet::isValidPathLen(path_len) && path_len != OUT_PATH_UNKNOWN) {
      MESH_DEBUG_PRINTLN("CMD_SEND_CHANNEL_DATA invalid path size: %d", path_len);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      return;
    }

    // parse provided path if not flood
    uint8_t path[MAX_PATH_SIZE];
    if (path_len != OUT_PATH_UNKNOWN) {
      i += mesh::Packet::writePath(path, &cmd_frame[i], path_len);
    }

    uint16_t data_type = ((uint16_t)cmd_frame[i]) | (((uint16_t)cmd_frame[i + 1]) << 8);
    i += 2;
    const uint8_t *payload = &cmd_frame[i];
    int payload_len = (len > (size_t)i) ? (int)(len - i) : 0;

    ChannelDetails channel;
    if (!getChannel(channel_idx, channel)) {
      writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
    } else if (data_type == DATA_TYPE_RESERVED) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (payload_len > MAX_GROUP_DATA_LENGTH) {
      MESH_DEBUG_PRINTLN("CMD_SEND_CHANNEL_DATA payload too long: %d > %d", payload_len, MAX_GROUP_DATA_LENGTH);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (sendGroupData(channel.channel, path, path_len, data_type, payload, payload_len)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
  } else if (cmd_frame[0] == CMD_GET_CONTACTS) { // get Contact list
    if (_iter_started) {
      writeErrFrame(ERR_CODE_BAD_STATE); // iterator is currently busy
    } else {
      if (len >= 5) { // has optional 'since' param
        memcpy(&_iter_filter_since, &cmd_frame[1], 4);
      } else {
        _iter_filter_since = 0;
      }

      uint8_t reply[5];
      reply[0] = RESP_CODE_CONTACTS_START;
      uint32_t count = getNumContacts() + 1; // total, NOT filtered count (+1: the console contact)
      memcpy(&reply[1], &count, 4);
      _serial->writeFrame(reply, 5);

      // start iterator
      _iter = startContactsIterator();
      _iter_started = true;
      _iter_console_pending = true;
      _most_recent_lastmod = 0;
    }
  } else if (cmd_frame[0] == CMD_SET_ADVERT_NAME && len >= 2) {
    int nlen = len - 1;
    if (nlen > (int) sizeof(_prefs.node_name) - 1) nlen = sizeof(_prefs.node_name) - 1; // max len
    memcpy(_prefs.node_name, &cmd_frame[1], nlen);
    _prefs.node_name[nlen] = 0; // null terminator
    savePrefs();
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_ADVERT_LATLON && len >= 9) {
    int32_t lat, lon, alt = 0;
    memcpy(&lat, &cmd_frame[1], 4);
    memcpy(&lon, &cmd_frame[5], 4);
    if (len >= 13) {
      memcpy(&alt, &cmd_frame[9], 4); // for FUTURE support
    }
    if (lat <= 90 * 1E6 && lat >= -90 * 1E6 && lon <= 180 * 1E6 && lon >= -180 * 1E6) {
      sensors.node_lat = ((double)lat) / 1000000.0;
      sensors.node_lon = ((double)lon) / 1000000.0;
      savePrefs();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid geo coordinate
    }
  } else if (cmd_frame[0] == CMD_GET_DEVICE_TIME) {
    uint8_t reply[5];
    reply[0] = RESP_CODE_CURR_TIME;
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply[1], &now, 4);
    _serial->writeFrame(reply, 5);
  } else if (cmd_frame[0] == CMD_SET_DEVICE_TIME && len >= 5) {
    uint32_t secs;
    memcpy(&secs, &cmd_frame[1], 4);
    uint32_t curr = getRTCClock()->getCurrentTime();
    if (secs >= curr) {
      getRTCClock()->setCurrentTime(secs);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_SEND_SELF_ADVERT) {
    mesh::Packet* pkt;
    if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
      pkt = createSelfAdvert(_prefs.node_name);
    } else {
      pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
    }
    if (pkt) {
      if (len >= 2 && cmd_frame[1] == 1) { // optional param (1 = flood, 0 = zero hop)
        unsigned long delay_millis = 0;
        TransportKey default_scope;
        memcpy(&default_scope.key, _prefs.default_scope_key, sizeof(default_scope.key));
        sendFloodScoped(default_scope, pkt, delay_millis);
      } else {
        sendZeroHop(pkt);
      }
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
  } else if (cmd_frame[0] == CMD_RESET_PATH && len >= 1 + 32) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      recipient->out_path_len = OUT_PATH_UNKNOWN;
      // recipient->lastmod = ??   shouldn't be needed, app already has this version of contact
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // unknown contact
    }
  } else if (cmd_frame[0] == CMD_ADD_UPDATE_CONTACT && len >= 1 + 32 + 2 + 1) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    uint32_t last_mod = getRTCClock()->getCurrentTime();  // fallback value if not present in cmd_frame
    if (recipient) {
      updateContactFromFrame(*recipient, last_mod, cmd_frame, len);
      recipient->lastmod = last_mod;
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      ContactInfo contact;
      updateContactFromFrame(contact, last_mod, cmd_frame, len);
      contact.lastmod = last_mod;
      contact.sync_since = 0;
      if (addContact(contact)) {
        dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      }
    }
  } else if (cmd_frame[0] == CMD_REMOVE_CONTACT) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient && removeContact(*recipient)) {
      _store->deleteBlobByKey(pub_key, PUB_KEY_SIZE);
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // not found, or unable to remove
    }
  } else if (cmd_frame[0] == CMD_SHARE_CONTACT) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      if (shareContactZeroHop(*recipient)) {
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL); // unable to send
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_GET_CONTACT_BY_KEY) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *contact = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (contact) {
      writeContactRespFrame(RESP_CODE_CONTACT, *contact);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // not found
    }
  } else if (cmd_frame[0] == CMD_EXPORT_CONTACT) {
    if (len < 1 + PUB_KEY_SIZE) {
      // export SELF
      mesh::Packet* pkt;
      if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
        pkt = createSelfAdvert(_prefs.node_name);
      } else {
        pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
      }
      if (pkt) {
        pkt->header |= ROUTE_TYPE_FLOOD; // would normally be sent in this mode

        out_frame[0] = RESP_CODE_EXPORT_CONTACT;
        uint8_t out_len = pkt->writeTo(&out_frame[1]);
        releasePacket(pkt); // undo the obtainNewPacket()
        _serial->writeFrame(out_frame, out_len + 1);
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL); // Error
      }
    } else {
      uint8_t *pub_key = &cmd_frame[1];
      ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
      uint8_t out_len;
      if (recipient && (out_len = exportContact(*recipient, &out_frame[1])) > 0) {
        out_frame[0] = RESP_CODE_EXPORT_CONTACT;
        _serial->writeFrame(out_frame, out_len + 1);
      } else {
        writeErrFrame(ERR_CODE_NOT_FOUND); // not found
      }
    }
  } else if (cmd_frame[0] == CMD_IMPORT_CONTACT && len > 2 + 32 + 64) {
    if (importContact(&cmd_frame[1], len - 1)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_SYNC_NEXT_MESSAGE) {
    int out_len;
    if ((out_len = getFromOfflineQueue(out_frame)) > 0) {
      _serial->writeFrame(out_frame, out_len);
      if (_listener) _listener->onQueueSizeChanged(offline_queue_len);
    } else {
      out_frame[0] = RESP_CODE_NO_MORE_MESSAGES;
      _serial->writeFrame(out_frame, 1);
    }
  } else if (cmd_frame[0] == CMD_SET_RADIO_PARAMS) {
    int i = 1;
    uint32_t freq;
    memcpy(&freq, &cmd_frame[i], 4);
    i += 4;
    uint32_t bw;
    memcpy(&bw, &cmd_frame[i], 4);
    i += 4;
    uint8_t sf = cmd_frame[i++];
    uint8_t cr = cmd_frame[i++];
    uint8_t repeat = 0;  // default - false
    if ((int) len > i) {
      repeat = cmd_frame[i++];   // FIRMWARE_VER_CODE  9+
    }

    if (repeat && !isValidClientRepeatFreq(freq)) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else if (freq >= 150000 && freq <= 2500000 && sf >= 5 && sf <= 12 && cr >= 5 && cr <= 8 && bw >= 7000 &&
        bw <= 500000) {
      _prefs.sf = sf;
      _prefs.cr = cr;
      _prefs.freq = (float)freq / 1000.0;
      _prefs.bw = (float)bw / 1000.0;
      _prefs.setRepeatEn(repeat != 0);
      savePrefs();

      radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
      MESH_DEBUG_PRINTLN("OK: CMD_SET_RADIO_PARAMS: f=%d, bw=%d, sf=%d, cr=%d", freq, bw, (uint32_t)sf,
                         (uint32_t)cr);

      writeOKFrame();
    } else {
      MESH_DEBUG_PRINTLN("Error: CMD_SET_RADIO_PARAMS: f=%d, bw=%d, sf=%d, cr=%d", freq, bw, (uint32_t)sf,
                         (uint32_t)cr);
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_SET_RADIO_TX_POWER) {
    int8_t power = (int8_t)cmd_frame[1];
    if (power < -9 || power > MAX_LORA_TX_POWER) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      _prefs.tx_power_dbm = power;
      savePrefs();
      radio_driver.setTxPower(_prefs.tx_power_dbm);
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_SET_TUNING_PARAMS) {
    int i = 1;
    uint32_t rx, af;
    memcpy(&rx, &cmd_frame[i], 4);
    i += 4;
    memcpy(&af, &cmd_frame[i], 4);
    i += 4;
    _prefs.rx_delay_base = ((float)rx) / 1000.0f;
    _prefs.airtime_factor = ((float)af) / 1000.0f;
    savePrefs();
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_GET_TUNING_PARAMS) {
    uint32_t rx = _prefs.rx_delay_base * 1000, af = _prefs.airtime_factor * 1000;
    int i = 0;
    out_frame[i++] = RESP_CODE_TUNING_PARAMS;
    memcpy(&out_frame[i], &rx, 4); i += 4;
    memcpy(&out_frame[i], &af, 4); i += 4;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SET_OTHER_PARAMS) {
    _prefs.manual_add_contacts = cmd_frame[1];
    if (len >= 3) {
      _prefs.telemetry_mode_base = cmd_frame[2] & 0x03; // v5+
      _prefs.telemetry_mode_loc = (cmd_frame[2] >> 2) & 0x03;
      _prefs.telemetry_mode_env = (cmd_frame[2] >> 4) & 0x03;

      if (len >= 4) {
        _prefs.advert_loc_policy = cmd_frame[3];
        if (len >= 5) {
          _prefs.multi_acks = cmd_frame[4];
        }
      }
    }
    savePrefs();
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_PATH_HASH_MODE && cmd_frame[1] == 0 && len >= 3) {
    if (cmd_frame[2] >= 3) {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      _prefs.path_hash_mode = cmd_frame[2];
      savePrefs();
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_REBOOT && memcmp(&cmd_frame[1], "reboot", 6) == 0) {
    if (dirty_contacts_expiry) { // is there are pending dirty contacts write needed?
      saveContacts();
    }
    board.reboot();
  } else if (cmd_frame[0] == CMD_GET_BATT_AND_STORAGE) {
    uint8_t reply[11];
    int i = 0;
    reply[i++] = RESP_CODE_BATT_AND_STORAGE;
    uint16_t battery_millivolts = board.getBattMilliVolts();
    uint32_t used = _store->getStorageUsedKb();
    uint32_t total = _store->getStorageTotalKb();
    memcpy(&reply[i], &battery_millivolts, 2); i += 2;
    memcpy(&reply[i], &used, 4); i += 4;
    memcpy(&reply[i], &total, 4); i += 4;
    _serial->writeFrame(reply, i);
  } else if (cmd_frame[0] == CMD_EXPORT_PRIVATE_KEY) {
#if ENABLE_PRIVATE_KEY_EXPORT
    uint8_t reply[65];
    reply[0] = RESP_CODE_PRIVATE_KEY;
    self_id.writeTo(&reply[1], 64);
    _serial->writeFrame(reply, 65);
#else
    writeDisabledFrame();
#endif
  } else if (cmd_frame[0] == CMD_IMPORT_PRIVATE_KEY && len >= 65) {
#if ENABLE_PRIVATE_KEY_IMPORT
    if (!mesh::LocalIdentity::validatePrivateKey(&cmd_frame[1])) {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid key
    } else {
        mesh::LocalIdentity identity;
        identity.readFrom(&cmd_frame[1], 64);
        if (_store->saveMainIdentity(identity)) {
          self_id = identity;
          writeOKFrame();
          // re-load contacts, to invalidate ecdh shared_secrets
          resetContacts();
          _store->loadContacts(this);
        } else {
          writeErrFrame(ERR_CODE_FILE_IO_ERROR);
        }
    }
#else
    writeDisabledFrame();
#endif
  } else if (cmd_frame[0] == CMD_SEND_RAW_DATA && len >= 6) {
    int i = 1;
    uint8_t path_len = cmd_frame[i++];
    if (path_len >= 0 && mesh::Packet::isValidPathLen(path_len)) {
      uint8_t path[MAX_PATH_SIZE];
      i += mesh::Packet::writePath(path, &cmd_frame[i], path_len);
      if (i + 4 > (int) len) {  // min payload 4 bytes
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      } else {
        auto pkt = createRawData(&cmd_frame[i], len - i);
        if (pkt) {
          sendDirect(pkt, path, path_len);
          writeOKFrame();
        } else {
          writeErrFrame(ERR_CODE_TABLE_FULL);
        }
      }
    } else {
      writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); // flood, not supported (yet)
    }
  } else if (cmd_frame[0] == CMD_SEND_LOGIN && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    char *password = (char *)&cmd_frame[1 + PUB_KEY_SIZE];
    cmd_frame[len] = 0; // ensure null terminator in password
    if (recipient) {
      uint32_t est_timeout;
      int result = sendLogin(*recipient, password, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        memcpy(&pending_login, recipient->id.pub_key, 4); // match this to onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &pending_login, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
  } else if (cmd_frame[0] == CMD_SEND_ANON_REQ && len > 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    ContactInfo anon;
    if (recipient == NULL) { // FIRMWARE_VER_CODE 13+,  allow non-contact requests
      memset((void*) &anon, 0, sizeof(anon));
      memcpy(anon.id.pub_key, pub_key, PUB_KEY_SIZE);
      anon.out_path_len = 0;   // default to zero-hop direct
      anon.type = ADV_TYPE_NONE;  // unknown
      anon.lastmod = getRTCClock()->getCurrentTime();

      if (addContact(anon)) recipient = &anon;
    }
    uint8_t *data = &cmd_frame[1 + PUB_KEY_SIZE];
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendAnonReq(*recipient, data, len - (1 + PUB_KEY_SIZE), tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_req = tag; // match this to onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL); // contacts full
    }
  } else if (cmd_frame[0] == CMD_SEND_STATUS_REQ && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, REQ_TYPE_GET_STATUS, tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        // FUTURE:  pending_status = tag;  // match this in onContactResponse()
        memcpy(&pending_status, recipient->id.pub_key, 4); // legacy matching scheme
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
  } else if (cmd_frame[0] == CMD_SEND_PATH_DISCOVERY_REQ && cmd_frame[1] == 0 && len >= 2 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[2];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      // 'Path Discovery' is just a special case of flood + Telemetry req
      uint8_t req_data[9];
      req_data[0] = REQ_TYPE_GET_TELEMETRY_DATA;
      req_data[1] = ~(TELEM_PERM_BASE);  // NEW: inverse permissions mask (ie. we only want BASE telemetry)
      memset(&req_data[2], 0, 3);  // reserved
      getRNG()->random(&req_data[5], 4);   // random blob to help make packet-hash unique
      auto save = recipient->out_path_len;    // temporarily force sendRequest() to flood
      recipient->out_path_len = OUT_PATH_UNKNOWN;
      int result = sendRequest(*recipient, req_data, sizeof(req_data), tag, est_timeout);
      recipient->out_path_len = save;
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_discovery = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
  } else if (cmd_frame[0] == CMD_SEND_TELEMETRY_REQ && len >= 4 + PUB_KEY_SIZE) {  // can deprecate, in favour of CMD_SEND_BINARY_REQ
    uint8_t *pub_key = &cmd_frame[4];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, REQ_TYPE_GET_TELEMETRY_DATA, tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_telemetry = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
  } else if (cmd_frame[0] == CMD_SEND_TELEMETRY_REQ && len == 4) {  // 'self' telemetry request
    telemetry.reset();
    telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);
    float temperature = board.getMCUTemperature();
    if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
      telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
    }

    // query other sensors -- target specific
    sensors.querySensors(0xFF, telemetry);

    int i = 0;
    out_frame[i++] = PUSH_CODE_TELEMETRY_RESPONSE;
    out_frame[i++] = 0; // reserved
    memcpy(&out_frame[i], self_id.pub_key, 6);
    i += 6; // pub_key_prefix
    uint8_t tlen = telemetry.getSize();
    memcpy(&out_frame[i], telemetry.getBuffer(), tlen);
    i += tlen;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SEND_BINARY_REQ && len >= 2 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    ContactInfo *recipient = lookupContactByPubKey(pub_key, PUB_KEY_SIZE);
    if (recipient) {
      uint8_t *req_data = &cmd_frame[1 + PUB_KEY_SIZE];
      uint32_t tag, est_timeout;
      int result = sendRequest(*recipient, req_data, len - (1 + PUB_KEY_SIZE), tag, est_timeout);
      if (result == MSG_SEND_FAILED) {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      } else {
        clearPendingReqs();
        pending_req = tag; // match this in onContactResponse()
        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = (result == MSG_SEND_SENT_FLOOD) ? 1 : 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      }
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // contact not found
    }
  } else if (cmd_frame[0] == CMD_HAS_CONNECTION && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    if (hasConnectionTo(pub_key)) {
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_LOGOUT && len >= 1 + PUB_KEY_SIZE) {
    uint8_t *pub_key = &cmd_frame[1];
    stopConnection(pub_key);
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_GET_CHANNEL && len >= 2) {
    uint8_t channel_idx = cmd_frame[1];
    ChannelDetails channel;
    bool found = isVirtualChannelSlot(channel_idx);
    if (isMeshtasticChannel(channel_idx)) {
      getMeshtasticChannel(channel);
    } else if (isWeatherChannel(channel_idx)) {
      getWeatherChannel(channel);
    } else if (isAircraftChannel(channel_idx)) {
      memset(&channel, 0, sizeof(channel));
      strcpy(channel.name, "Aircraft");
      uint8_t h[32];
      const char* tag = "aircraft channel";
      mesh::Utils::sha256(h, sizeof(h), (const uint8_t*) tag, strlen(tag));
      memcpy(channel.channel.secret, h, 16);
    } else if (found) {
      memset(&channel, 0, sizeof(channel));   // a synthetic slot whose feature is off: empty
    } else {
      found = getChannel(channel_idx, channel);
    }
    if (found) {
      int i = 0;
      out_frame[i++] = RESP_CODE_CHANNEL_INFO;
      out_frame[i++] = channel_idx;
      memset(&out_frame[i], 0, 32);
      StrHelper::strncpy((char *)&out_frame[i], channel.name, 32);
      i += 32;
      memcpy(&out_frame[i], channel.channel.secret, 16);
      i += 16; // NOTE: only 128-bit supported
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_SET_CHANNEL && len >= 2 + 32 + 32) {
    writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); // not supported (yet)
  } else if (cmd_frame[0] == CMD_SET_CHANNEL && len >= 2 + 32 + 16 &&
             isVirtualChannelSlot(cmd_frame[1])) {
    writeErrFrame(ERR_CODE_ILLEGAL_ARG);   // set with 'set mt.*' / 'set wx.*' instead
  } else if (cmd_frame[0] == CMD_SET_CHANNEL && len >= 2 + 32 + 16) {
    uint8_t channel_idx = cmd_frame[1];
    ChannelDetails channel;
    StrHelper::strncpy(channel.name, (char *)&cmd_frame[2], 32);
    memset(channel.channel.secret, 0, sizeof(channel.channel.secret));
    memcpy(channel.channel.secret, &cmd_frame[2 + 32], 16); // NOTE: only 128-bit supported
    if (setChannel(channel_idx, channel)) {
      saveChannels();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND); // bad channel_idx
    }
  } else if (cmd_frame[0] == CMD_SIGN_START) {
    out_frame[0] = RESP_CODE_SIGN_START;
    out_frame[1] = 0; // reserved
    uint32_t len = MAX_SIGN_DATA_LEN;
    memcpy(&out_frame[2], &len, 4);
    _serial->writeFrame(out_frame, 6);

    if (sign_data) {
      free(sign_data);
    }
    sign_data = (uint8_t *)malloc(MAX_SIGN_DATA_LEN);
    sign_data_len = 0;
  } else if (cmd_frame[0] == CMD_SIGN_DATA && len > 1) {
    if (sign_data == NULL || sign_data_len + (len - 1) > MAX_SIGN_DATA_LEN) {
      writeErrFrame(sign_data == NULL ? ERR_CODE_BAD_STATE : ERR_CODE_TABLE_FULL); // error: too long
    } else {
      memcpy(&sign_data[sign_data_len], &cmd_frame[1], len - 1);
      sign_data_len += (len - 1);
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_SIGN_FINISH) {
    if (sign_data) {
      self_id.sign(&out_frame[1], sign_data, sign_data_len);

      free(sign_data); // don't need sign_data now
      sign_data = NULL;

      out_frame[0] = RESP_CODE_SIGNATURE;
      _serial->writeFrame(out_frame, 1 + SIGNATURE_SIZE);
    } else {
      writeErrFrame(ERR_CODE_BAD_STATE);
    }
  } else if (cmd_frame[0] == CMD_SEND_TRACE_PATH && len > 10 && len - 10 < MAX_PACKET_PAYLOAD-5) {
    uint8_t path_len = len - 10;
    uint8_t flags = cmd_frame[9];
    uint8_t path_sz = flags & 0x03;  // NEW v1.11+
    if ((path_len >> path_sz) > MAX_PATH_SIZE || (path_len % (1 << path_sz)) != 0) { // make sure is multiple of path_sz
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    } else {
      uint32_t tag, auth;
      memcpy(&tag, &cmd_frame[1], 4);
      memcpy(&auth, &cmd_frame[5], 4);
      auto pkt = createTrace(tag, auth, flags);
      if (pkt) {
        sendDirect(pkt, &cmd_frame[10], path_len);

        uint32_t t = _radio->getEstAirtimeFor(pkt->payload_len + pkt->path_len + 2);
        uint32_t est_timeout = calcDirectTimeoutMillisFor(t, path_len >> path_sz);

        out_frame[0] = RESP_CODE_SENT;
        out_frame[1] = 0;
        memcpy(&out_frame[2], &tag, 4);
        memcpy(&out_frame[6], &est_timeout, 4);
        _serial->writeFrame(out_frame, 10);
      } else {
        writeErrFrame(ERR_CODE_TABLE_FULL);
      }
    }
  } else if (cmd_frame[0] == CMD_SET_DEVICE_PIN && len >= 5) {

    // get pin from command frame
    uint32_t pin;
    memcpy(&pin, &cmd_frame[1], 4);

    // ensure pin is zero, or a valid 6 digit pin
    if (pin == 0 || (pin >= 100000 && pin <= 999999)) {
      _prefs.ble_pin = pin;
      savePrefs();
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_GET_CUSTOM_VARS) {
    out_frame[0] = RESP_CODE_CUSTOM_VARS;
    char *dp = (char *)&out_frame[1];
    for (int i = 0; i < sensors.getNumSettings() && dp - (char *)&out_frame[1] < 140; i++) {
      if (i > 0) {
        *dp++ = ',';
      }
      strcpy(dp, sensors.getSettingName(i));
      dp = strchr(dp, 0);
      *dp++ = ':';
      strcpy(dp, sensors.getSettingValue(i));
      dp = strchr(dp, 0);
    }
    _serial->writeFrame(out_frame, dp - (char *)out_frame);
  } else if (cmd_frame[0] == CMD_SET_CUSTOM_VAR && len >= 4) {
    cmd_frame[len] = 0;
    char *sp = (char *)&cmd_frame[1];
    char *np = strchr(sp, ':'); // look for separator char
    if (np) {
      *np++ = 0; // modify 'cmd_frame', replace ':' with null
      bool success = sensors.setSettingValue(sp, np);
      if (success) {
        if (_prefs.isDirty()) savePrefs();
        #if ENV_INCLUDE_GPS == 1
        // Update node preferences for GPS settings
        if (strcmp(sp, "gps") == 0) {
          _prefs.gps_enabled = (np[0] == '1') ? 1 : 0;
          savePrefs();
        } else if (strcmp(sp, "gps_interval") == 0) {
          uint32_t interval_seconds = atoi(np);
          _prefs.gps_interval = constrain(interval_seconds, 0, 86400);
          savePrefs();
        }
        #endif
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG);
    }
  } else if (cmd_frame[0] == CMD_GET_ADVERT_PATH && len >= PUB_KEY_SIZE+2) {
    // FUTURE use:  uint8_t reserved = cmd_frame[1];
    uint8_t *pub_key = &cmd_frame[2];
    AdvertPath* found = NULL;
    for (int i = 0; i < ADVERT_PATH_TABLE_SIZE; i++) {
      auto p = &advert_paths[i];
      if (memcmp(p->pubkey_prefix, pub_key, sizeof(p->pubkey_prefix)) == 0) {
        found = p;
        break;
      }
    }
    if (found) {
      int i = 0;
      out_frame[i++] = RESP_CODE_ADVERT_PATH;
      memcpy(&out_frame[i], &found->recv_timestamp, 4); i += 4;
      out_frame[i++] = found->path_len;
      i += mesh::Packet::writePath(&out_frame[i], found->path, found->path_len);
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_NOT_FOUND);
    }
  } else if (cmd_frame[0] == CMD_GET_STATS && len >= 2) {
    uint8_t stats_type = cmd_frame[1];
    if (stats_type == STATS_TYPE_CORE) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_CORE;
      uint16_t battery_mv = board.getBattMilliVolts();
      uint32_t uptime_secs = _ms->getMillis() / 1000;
      uint8_t queue_len = (uint8_t)_mgr->getOutboundTotal();
      memcpy(&out_frame[i], &battery_mv, 2); i += 2;
      memcpy(&out_frame[i], &uptime_secs, 4); i += 4;
      memcpy(&out_frame[i], &_err_flags, 2); i += 2;
      out_frame[i++] = queue_len;
      _serial->writeFrame(out_frame, i);
    } else if (stats_type == STATS_TYPE_RADIO) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_RADIO;
      int16_t noise_floor = (int16_t)_radio->getNoiseFloor();
      int8_t last_rssi = (int8_t)radio_driver.getLastRSSI();
      int8_t last_snr = (int8_t)(radio_driver.getLastSNR() * 4); // scaled by 4 for 0.25 dB precision
      uint32_t tx_air_secs = getTotalAirTime() / 1000;
      uint32_t rx_air_secs = getReceiveAirTime() / 1000;
      memcpy(&out_frame[i], &noise_floor, 2); i += 2;
      out_frame[i++] = last_rssi;
      out_frame[i++] = last_snr;
      memcpy(&out_frame[i], &tx_air_secs, 4); i += 4;
      memcpy(&out_frame[i], &rx_air_secs, 4); i += 4;
      _serial->writeFrame(out_frame, i);
    } else if (stats_type == STATS_TYPE_PACKETS) {
      int i = 0;
      out_frame[i++] = RESP_CODE_STATS;
      out_frame[i++] = STATS_TYPE_PACKETS;
      uint32_t recv = radio_driver.getPacketsRecv();
      uint32_t sent = radio_driver.getPacketsSent();
      uint32_t n_sent_flood = getNumSentFlood();
      uint32_t n_sent_direct = getNumSentDirect();
      uint32_t n_recv_flood = getNumRecvFlood();
      uint32_t n_recv_direct = getNumRecvDirect();
      uint32_t n_recv_errors = radio_driver.getPacketsRecvErrors();
      memcpy(&out_frame[i], &recv, 4); i += 4;
      memcpy(&out_frame[i], &sent, 4); i += 4;
      memcpy(&out_frame[i], &n_sent_flood, 4); i += 4;
      memcpy(&out_frame[i], &n_sent_direct, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_flood, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_direct, 4); i += 4;
      memcpy(&out_frame[i], &n_recv_errors, 4); i += 4;
      _serial->writeFrame(out_frame, i);
    } else {
      writeErrFrame(ERR_CODE_ILLEGAL_ARG); // invalid stats sub-type
    }
  } else if (cmd_frame[0] == CMD_FACTORY_RESET && memcmp(&cmd_frame[1], "reset", 5) == 0) {
    if (_serial) {
      MESH_DEBUG_PRINTLN("Factory reset: disabling serial interface to prevent reconnects (BLE/WiFi)");
      _serial->disable(); // Phone app disconnects before we can send OK frame so it's safe here
    }
    bool success = _store->formatFileSystem();
    if (success) {
      writeOKFrame();
      delay(1000);
      board.reboot();  // doesn't return
    } else {
      writeErrFrame(ERR_CODE_FILE_IO_ERROR);
    }
  } else if (cmd_frame[0] == CMD_SET_FLOOD_SCOPE_KEY && len >= 2 && cmd_frame[1] == 0) {
    if (len >= 2 + 16) {
      memcpy(send_scope.key, &cmd_frame[2], sizeof(send_scope.key));  // set scope override TransportKey
    } else {
      memset(send_scope.key, 0, sizeof(send_scope.key));  // reset scope override
    }
    send_unscoped = false;
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_FLOOD_SCOPE_KEY && len >= 2 && cmd_frame[1] == 1) {  // ver 12+
    send_unscoped = true;
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_SET_DEFAULT_FLOOD_SCOPE && len >= 1) {
    if (len >= 1+31+16) {
      int n = strlen((char *) &cmd_frame[1]);
      if (n > 0 && n < 31) {
        strcpy(_prefs.default_scope_name, (char *) &cmd_frame[1]);
        memcpy(_prefs.default_scope_key, &cmd_frame[1+31], 16);
        savePrefs();
        writeOKFrame();
      } else {
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      memset(_prefs.default_scope_name, 0, sizeof(_prefs.default_scope_name));  // set default scope to null
      memset(_prefs.default_scope_key, 0, sizeof(_prefs.default_scope_key));
      savePrefs();
      writeOKFrame();
    }
  } else if (cmd_frame[0] == CMD_GET_DEFAULT_FLOOD_SCOPE) {
    out_frame[0] = RESP_CODE_DEFAULT_FLOOD_SCOPE;
    if (strlen(_prefs.default_scope_name) > 0) {
      memcpy(&out_frame[1], _prefs.default_scope_name, 31);
      memcpy(&out_frame[1+31], _prefs.default_scope_key, 16);
      _serial->writeFrame(out_frame, 1+31+16);
    } else {
      _serial->writeFrame(out_frame, 1);   // no name or key means null
    }
  } else if (cmd_frame[0] == CMD_SEND_CONTROL_DATA && len >= 2 && (cmd_frame[1] & 0x80) != 0) {
    auto resp = createControlData(&cmd_frame[1], len - 1);
    if (resp) {
      sendZeroHop(resp);
      writeOKFrame();
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
  } else if (cmd_frame[0] == CMD_SET_AUTOADD_CONFIG) {
    _prefs.autoadd_config = cmd_frame[1];
    if (len >= 3) {
      _prefs.autoadd_max_hops = min(cmd_frame[2], (uint8_t)64);
    }
    savePrefs();
    writeOKFrame();
  } else if (cmd_frame[0] == CMD_GET_AUTOADD_CONFIG) {
    int i = 0;
    out_frame[i++] = RESP_CODE_AUTOADD_CONFIG;
    out_frame[i++] = _prefs.autoadd_config;
    out_frame[i++] = _prefs.autoadd_max_hops;
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_GET_ALLOWED_REPEAT_FREQ) {
    int i = 0;
    out_frame[i++] = RESP_ALLOWED_REPEAT_FREQ;
    for (size_t k = 0; k < sizeof(repeat_freq_ranges)/sizeof(repeat_freq_ranges[0]) && i + 8 < (int) sizeof(out_frame); k++) {
      auto r = &repeat_freq_ranges[k];
      memcpy(&out_frame[i], &r->lower_freq, 4); i += 4;
      memcpy(&out_frame[i], &r->upper_freq, 4); i += 4;
    }
    _serial->writeFrame(out_frame, i);
  } else if (cmd_frame[0] == CMD_SEND_RAW_PACKET && len >= 4) {
    auto pkt = obtainNewPacket();
    if (pkt) {
      uint8_t priority = cmd_frame[1];
      if (tryParsePacket(pkt, &cmd_frame[2], len - 2)) {
        sendPacket(pkt, priority, 0);
        writeOKFrame();
      } else {
        releasePacket(pkt);
        writeErrFrame(ERR_CODE_ILLEGAL_ARG);
      }
    } else {
      writeErrFrame(ERR_CODE_TABLE_FULL);
    }
  } else {
    writeErrFrame(ERR_CODE_UNSUPPORTED_CMD);
    MESH_DEBUG_PRINTLN("ERROR: unknown command: %02X", cmd_frame[0]);
  }
}

static bool save_filter(const ContactInfo& c) {
  return c.type != ADV_TYPE_NONE;   // don't save the transient/anon entries
}

void MyMesh::saveContacts() {
  _store->saveContacts(this, save_filter);
}

void MyMesh::enterCLIRescue() {
  _cli_rescue = true;
  cli_command[0] = 0;
  Serial.println("========= CLI Rescue =========");
}

// A contact named exactly 'arg' (case-insensitive), or else one whose public key starts with hex 'arg'
ContactInfo* MyMesh::findContactForCLI(const char* arg) {
  while (*arg == ' ') arg++;
  if (*arg == 0) return NULL;

  ContactsIterator iter = startContactsIterator();
  ContactInfo c;
  while (iter.hasNext(this, c)) {
    if (strcasecmp(c.name, arg) == 0) {
      return lookupContactByPubKey(c.id.pub_key, PUB_KEY_SIZE);
    }
  }

  int len = strlen(arg);
  if (len >= 4 && len <= 2*PUB_KEY_SIZE && (len % 2) == 0) {
    uint8_t prefix[PUB_KEY_SIZE];
    if (mesh::Utils::fromHex(prefix, len / 2, arg)) {
      return lookupContactByPubKey(prefix, len / 2);
    }
  }
  return NULL;
}

// "contact not found", pointing at crypto.ch when the name is a channel's (mode NULL = a 'get')
void MyMesh::contactNotFound(const char* name, const char* mode, char* reply) {
  ChannelDetails ch;
  while (*name == ' ') name++;
  bool numeric = *name != 0;
  for (const char* q = name; *q; q++) if (*q < '0' || *q > '9') numeric = false;
  if (!numeric && findChannelForCLI(name, ch) >= 0) {
    if (mode) {
      sprintf(reply, "Error: %.31s is a channel, use: set crypto.ch %s %.31s", ch.name, mode, ch.name);
    } else {
      sprintf(reply, "Error: %.31s is a channel, use: get crypto.ch %.31s", ch.name, ch.name);
    }
  } else {
    strcpy(reply, "Error: contact not found");
  }
}

// A channel named exactly 'arg' (case-insensitive), or else channel number 'arg'
int MyMesh::findChannelForCLI(const char* arg, ChannelDetails& ch) {
#ifdef MAX_GROUP_CHANNELS
  while (*arg == ' ') arg++;
  if (*arg == 0) return -1;
  for (int i = 0; i < MAX_GROUP_CHANNELS; i++) {
    if (getChannel(i, ch) && ch.name[0] != 0 && strcasecmp(ch.name, arg) == 0) return i;
  }
  bool numeric = true;
  for (const char* p = arg; *p; p++) if (*p < '0' || *p > '9') numeric = false;
  if (numeric) {
    int i = atoi(arg);
    if (i >= 0 && i < MAX_GROUP_CHANNELS && getChannel(i, ch) && ch.name[0] != 0) return i;
  }
#endif
  return -1;
}

// a known contact sent us a verified v2 packet, so it can receive v2 too: start sending it v2.
// This only ever raises the policy, never lowers it.
void MyMesh::onPeerCryptoV2Recv(int sender_idx, const uint8_t* secret) {
  if (_crypto_lost) return;
  if (crypto_policies.get(secret) == CRYPTO_POLICY_LEGACY) {
    if (crypto_policies.set(secret, CRYPTO_POLICY_V2)) {
      // Applies right away. The flash write waits a few seconds, so it doesn't hold up this
      // packet or its ACK. If it's lost (reboot first, or the write fails) the contact is back on
      // legacy, which still accepts v2, and the upgrade is relearned from its next v2 packet.
      _crypto_save_pending = true;
      _crypto_save_at = millis() + 5000;
      MESH_DEBUG_PRINTLN("contact upgraded to v2 encryption");
    }
  }
}

// Saves the policy table to a new file, then records its seq in prefs. A later boot that can only
// load an older file (or none) sees the seq gap and fails closed.
bool MyMesh::saveCryptoPolicies() {
  uint32_t seq = (_crypto_seq > _prefs.crypto_seq ? _crypto_seq : _prefs.crypto_seq) + 1;
  if (!_store->saveCryptoPolicies(crypto_policies, seq)) return false;
  _crypto_seq = seq;
  _prefs.crypto_seq = seq;
  savePrefs();
  return true;
}

// Sets and saves a policy. If the save fails, the old policy is restored and an error returned.
bool MyMesh::setCryptoPolicy(const uint8_t* secret, uint8_t policy, char* reply) {
  if (_cli_remote) {
    strcpy(reply, "Error: encryption policies can only be changed on this device");
    return false;
  }
  if (_crypto_lost) {
    strcpy(reply, "Error: saved policies were lost. Run set crypto.recover first");
    return false;
  }
  uint8_t old = crypto_policies.get(secret);
  if (!crypto_policies.set(secret, policy)) {
    strcpy(reply, "Error: policy table full");
    return false;
  }
  if (!saveCryptoPolicies()) {
    crypto_policies.set(secret, old);
    strcpy(reply, "Error: couldn't save, policy unchanged");
    return false;
  }
  return true;
}

bool MyMesh::handleCommand(const char* command, uint32_t sender_timestamp, char* reply) {
  while (*command == ' ') command++; // skip leading spaces

  if (strlen(command) > 4 && command[2] == '|') { // optional prefix (for companion radio CLI)
    memcpy(reply, command, 3);                    // reflect the prefix back
    reply += 3;
    *reply = 0;
    command += 3;
  }

  if (_prefs.getRadioPrefs()->handleCommand(command, sender_timestamp, reply)) {  // is radio CLI command?
    if (_prefs.getRadioPrefs()->isDirty()) { savePrefs(); }
    return true;
  }

  bool retry_changed;
  if (handleFloodRetryCommand(command, _prefs.flood_retry.count, _prefs.flood_retry.wait_ms, getFloodRetry(), reply, retry_changed)) {
    if (retry_changed) savePrefs();
    return true;
  }

  if (handleCloneCommand(command, reply)) return true;
  if (handleMeshtasticCommand(command, reply)) return true;
  if (handleWeatherCommand(command, reply)) return true;
  if (handleAircraftCommand(command, reply)) return true;
  if (handleRadarCommand(command, reply)) return true;

  // hook for variant-specific CLI processing
  if (board.handleCommand(command, sender_timestamp, reply)) {
    if (_prefs.isDirty()) { savePrefs(); }
    return true;
  }

  // hook for radio-specific CLI processing
  if (_radio->handleCommand(command, sender_timestamp, reply)) {
    return true;
  }

#ifdef CRASH_TEST   // test builds only: check the crash reporting
  if (strcmp(command, "crashtest fault") == 0) {
    *(volatile uint32_t*) 0xFFFFFFF0 = 1;   // a write to no memory: bus fault, then hard fault
  }
  if (strcmp(command, "crashtest hang") == 0) {
    while (true) { }
  }
#endif
  if (strcmp(command, "reboot") == 0) {
    board.reboot(); // doesn't return
    return true;
  }

  if (strcmp(command, "poweroff") == 0 || strcmp(command, "shutdown") == 0) {
    board.powerOff(); // doesn't return
    return true;
  }

  if (memcmp(command, "set name ", 9) == 0) {
    if (AdvertDataParser::isValidName(&command[9])) {
      StrHelper::strncpy(_prefs.node_name, &command[9], sizeof(_prefs.node_name));
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error, bad chars");
    }
    return true;
  }
  if (memcmp(command, "sensor get ", 11) == 0) {
    const char* val = sensors.getSettingByKey(&command[11]);
    if (val) sprintf(reply, "> %s", val); else strcpy(reply, "null");
    return true;
  }
  if (memcmp(command, "sensor set ", 11) == 0) {
    char key[24];
    const char* sp = strchr(&command[11], ' ');
    int klen = sp ? sp - &command[11] : 0;
    if (klen > 0 && klen < (int)sizeof(key)) {
      memcpy(key, &command[11], klen);
      key[klen] = 0;
      if (sensors.setSettingValue(key, sp + 1)) {
        if (_prefs.isDirty()) savePrefs();
        strcpy(reply, "OK");
        return true;
      }
    }
    strcpy(reply, "Error, unknown setting or bad value");
    return true;
  }
  if (strcmp(command, "sensor list") == 0) {
    char* dp = reply;
    *dp = 0;
    for (int i = 0; i < sensors.getNumSettings() && dp - reply < 100; i++) {
      dp += sprintf(dp, "%s%s=%s", i ? "\n" : "", sensors.getSettingName(i), sensors.getSettingValue(i));
    }
    if (dp == reply) strcpy(reply, "no custom var");
    return true;
  }
  if (strcmp(command, "get name") == 0) {
    sprintf(reply, "> %s", _prefs.node_name);
    return true;
  }
  if (strcmp(command, "get entropy") == 0) {
    // Nothing is collected at boot when the key is just loaded, so test the hardware RNG now if it
    // hasn't been (cheap). The radio isn't sampled here: that would stop it receiving.
    if (EntropyPool::hardwareStatus() == 0) EntropyPool::addHardware();
    static const char* hw[] = { "failed/untrusted", "not tried", "ok" };
    static const char* key[] = { "loaded from flash", "made this boot, saved", "made this boot, NOT saved" };
    const char* radio = EntropyPool::radioSamples() == 0 ? "not sampled this boot"
                      : EntropyPool::radioStatus() == 1 ? "ok" : "failed health tests";
    sprintf(reply, "> hardware RNG: %s; radio noise: %s; %d bits, %s; key: %s",
            hw[EntropyPool::hardwareStatus() + 1], radio, EntropyPool::creditedBits(),
            EntropyPool::readyForKeys() ? "enough for new keys" : "NOT enough for new keys",
            key[_identity_state]);
    return true;
  }

  // encryption policy: legacy | v2 | v2only  (see docs/crypto_v2.md)
  if (strcmp(command, "set crypto.recover") == 0) {
    if (_cli_remote) {
      strcpy(reply, "Error: encryption policies can only be changed on this device");
    } else if (!_crypto_lost) {
      strcpy(reply, "OK - nothing to recover");
    } else {
      _crypto_lost = false;   // accept the policies that did load (possibly older, possibly none)
      if (saveCryptoPolicies()) {
        sprintf(reply, "OK - using the %d saved policies that loaded. Check v2only contacts and channels", crypto_policies.count());
      } else {
        _crypto_lost = true;
        strcpy(reply, "Error: couldn't save");
      }
    }
    return true;
  }
  // timings of v2 decryption with a fixed test key (nothing secret), in microseconds per call
  if (strcmp(command, "get crypto.bench") == 0) {
    uint8_t secret[PUB_KEY_SIZE], ctx[3] = { PAYLOAD_TYPE_TXT_MSG, 0x11, 0x22 };
    uint8_t p[170], env[MAX_PACKET_PAYLOAD], out[MAX_PACKET_PAYLOAD], key[32];
    for (int i = 0; i < PUB_KEY_SIZE; i++) secret[i] = (uint8_t)i;
    for (int i = 0; i < (int)sizeof(p); i++) p[i] = (uint8_t)(i * 7);
    const int N = 8;
    auto timeOpen = [&](int env_len) -> uint32_t {
      uint32_t t0 = micros();
      for (int k = 0; k < N; k++) mesh::CryptoV2::open(secret, out, env, env_len, ctx, sizeof(ctx));
      return (micros() - t0) / N;
    };
    uint32_t ok[3];
    const int lens[3] = { 20, 80, 160 };
    for (int j = 0; j < 3; j++) {
      ok[j] = timeOpen(mesh::CryptoV2::seal(secret, env, p, lens[j], ctx, sizeof(ctx)));
    }
    int n = mesh::CryptoV2::seal(secret, env, p, 160, ctx, sizeof(ctx));
    env[0] ^= 1;  uint32_t bad0 = timeOpen(n);  env[0] ^= 1;     // tag wrong in its first byte
    env[15] ^= 1; uint32_t bad15 = timeOpen(n); env[15] ^= 1;    // ... or only in its last byte
    n = mesh::CryptoV2::seal(secret, env, p, 162, ctx, sizeof(ctx));   // padded: a bad tag costs 2 attempts
    env[3] ^= 1;  uint32_t pad = timeOpen(n);
    uint32_t t0 = micros();
    for (int k = 0; k < N; k++) mesh::CryptoV2::deriveKey(secret, key);
    uint32_t kdf = (micros() - t0) / N;
    n = mesh::Utils::encryptThenMAC(secret, env, p, 160);
    env[0] ^= 1;
    t0 = micros();
    for (int k = 0; k < N; k++) mesh::Utils::MACThenDecrypt(secret, out, env, n);
    uint32_t v1bad = (micros() - t0) / N;
    sprintf(reply, "> aes=%s us: ok20/80/160 %u/%u/%u bad@0 %u bad@15 %u padretry %u kdf %u v1bad %u",
            mesh::AesSiv::usingHardwareAes() ? "hw" : "sw", (unsigned)ok[0], (unsigned)ok[1], (unsigned)ok[2],
            (unsigned)bad0, (unsigned)bad15, (unsigned)pad, (unsigned)kdf, (unsigned)v1bad);
    return true;
  }
  if (strcmp(command, "get crypto") == 0) {
    int n_ch = 0, n_v2 = 0, n_only = 0;
    char* dp = reply;
    if (_crypto_lost) {
      strcpy(reply, "> WARNING: saved policies were lost, everything is v2only until: set crypto.recover");
      return true;
    }
    dp += sprintf(dp, ">");
#ifdef MAX_GROUP_CHANNELS
    for (int i = 0; i < MAX_GROUP_CHANNELS; i++) {
      ChannelDetails ch;
      if (!getChannel(i, ch) || ch.name[0] == 0) continue;
      uint8_t p = crypto_policies.get(ch.channel.secret);
      if (p == CRYPTO_POLICY_LEGACY) continue;
      n_ch++;
      if (dp - reply < 100) dp += sprintf(dp, " ch%d %.16s: %s,", i, ch.name, CryptoPolicyTable::name(p));
    }
#endif
    for (int i = 0; i < crypto_policies.count(); i++) {
      if (crypto_policies.entry(i).policy == CRYPTO_POLICY_V2_ONLY) n_only++; else n_v2++;
    }
    // channel entries are in the table too, but only contacts are counted here
    int contacts_on = n_v2 + n_only - n_ch;
    if (contacts_on < 0) contacts_on = 0;
    sprintf(dp, " %d contact(s) on v2 or v2only (others legacy)", contacts_on);
    return true;
  }
  if (memcmp(command, "get crypto ", 11) == 0) {
    ContactInfo* c = findContactForCLI(&command[11]);
    if (c) {
      sprintf(reply, "> %s: %s", c->name, CryptoPolicyTable::name(getCryptoPolicy(c->getSharedSecret(self_id))));
    } else {
      contactNotFound(&command[11], NULL, reply);
    }
    return true;
  }
  if (memcmp(command, "set crypto ", 11) == 0) {
    char mode[8];
    const char* sp = strchr(&command[11], ' ');
    int ml = sp ? (int)(sp - &command[11]) : 0;
    if (ml <= 0 || ml >= (int)sizeof(mode)) {
      strcpy(reply, "Error: use set crypto <legacy|v2|v2only> <contact>");
      return true;
    }
    memcpy(mode, &command[11], ml);
    mode[ml] = 0;
    int p = CryptoPolicyTable::parse(mode);
    ContactInfo* c = findContactForCLI(sp + 1);
    if (p < 0) {
      strcpy(reply, "Error: mode must be legacy, v2 or v2only");
    } else if (c == NULL) {
      contactNotFound(sp + 1, mode, reply);
    } else if (setCryptoPolicy(c->getSharedSecret(self_id), p, reply)) {
      sprintf(reply, "OK - %s: %s", c->name, CryptoPolicyTable::name(p));
    }
    return true;
  }
#ifdef MAX_GROUP_CHANNELS
  if (memcmp(command, "get crypto.ch ", 14) == 0) {
    ChannelDetails ch;
    int idx = findChannelForCLI(&command[14], ch);
    if (idx >= 0) {
      sprintf(reply, "> ch%d %s: %s", idx, ch.name, CryptoPolicyTable::name(getCryptoPolicy(ch.channel.secret)));
    } else {
      strcpy(reply, "Error: channel not found");
    }
    return true;
  }
  if (memcmp(command, "set crypto.ch ", 14) == 0) {
    char mode[8];
    const char* sp = strchr(&command[14], ' ');
    int ml = sp ? (int)(sp - &command[14]) : 0;
    if (ml <= 0 || ml >= (int)sizeof(mode)) {
      strcpy(reply, "Error: use set crypto.ch <legacy|v2|v2only> <channel>");
      return true;
    }
    memcpy(mode, &command[14], ml);
    mode[ml] = 0;
    int p = CryptoPolicyTable::parse(mode);
    ChannelDetails ch;
    int idx = findChannelForCLI(sp + 1, ch);
    if (p < 0) {
      strcpy(reply, "Error: mode must be legacy, v2 or v2only");
    } else if (idx < 0) {
      strcpy(reply, "Error: channel not found");
    } else if (setCryptoPolicy(ch.channel.secret, p, reply)) {
      sprintf(reply, "OK - ch%d %s: %s", idx, ch.name, CryptoPolicyTable::name(p));
    }
    return true;
  }
#endif

#ifdef PIN_BUZZER
  if (strcmp(command, "get buzzer") == 0) {
    sprintf(reply, "> %s", _prefs.buzzer_quiet ? "off" : "on");
    return true;
  }
  if (memcmp(command, "set buzzer ", 11) == 0) {
    if (strcmp(&command[11], "on") == 0 || strcmp(&command[11], "off") == 0) {
      _prefs.buzzer_quiet = strcmp(&command[11], "off") == 0;
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error: state must be on or off");
    }
    return true;
  }
#endif

#ifdef HAS_DRV2605
  if (strcmp(command, "get vibe") == 0) {
    sprintf(reply, "> %s", _prefs.vibe_quiet ? "off" : "on");
    return true;
  }
  if (memcmp(command, "set vibe ", 9) == 0) {
    if (strcmp(&command[9], "on") == 0 || strcmp(&command[9], "off") == 0) {
      _prefs.vibe_quiet = strcmp(&command[9], "off") == 0;
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error: state must be on or off");
    }
    return true;
  }
#endif

#if defined(PIN_STATUS_LED) || defined(PIN_STATUS_LED_R) || defined(P_LORA_TX_LED)
  if (strcmp(command, "get led") == 0) {
    sprintf(reply, "> %s", _prefs.led_off ? "off" : "on");
    return true;
  }
  if (memcmp(command, "set led ", 8) == 0) {
    if (strcmp(&command[8], "on") == 0 || strcmp(&command[8], "off") == 0) {
      _prefs.led_off = strcmp(&command[8], "off") == 0;
      radio_driver.setTxLedEnabled(!_prefs.led_off);
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error: state must be on or off");
    }
    return true;
  }
#endif

  if (strcmp(command, "uptime") == 0 || strcmp(command, "get uptime") == 0) {
    unsigned long secs = _ms->getMillis() / 1000;
    int n = sprintf(reply, "> up ");
    if (secs >= 86400) n += sprintf(&reply[n], "%lud ", secs / 86400);
    if (secs >= 3600) n += sprintf(&reply[n], "%luh ", (secs / 3600) % 24);
    n += sprintf(&reply[n], "%lum %lus", (secs / 60) % 60, secs % 60);
    if (board.isPwrMgtInitialised()) {   // why it last started, where the board can tell
      n += sprintf(&reply[n], ", started by: %s", board.getResetReasonString(board.getResetReason()));
    }
    const char* crash = board.getLastCrash();
    if (crash) sprintf(&reply[n], ". The run before crashed: %s", crash);
    return true;
  }

#ifdef NRF52_PLATFORM
  if (strcmp(command, "get charger.wake") == 0) {
    sprintf(reply, "> %s", _prefs.charger_wake ? "on" : "off");
    return true;
  }
  if (memcmp(command, "set charger.wake ", 17) == 0) {
    if (strcmp(&command[17], "on") == 0 || strcmp(&command[17], "off") == 0) {
      _prefs.charger_wake = strcmp(&command[17], "on") == 0;
      savePrefs();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Error: state must be on or off");
    }
    return true;
  }
#endif

  if (handleFindCommand(command, reply)) return true;   // find beep/stop/range, get/set find.* (MyMeshFind.cpp)

  // find me: beep (and vibrate) so a lost radio can be found, even if the buzzer is turned off
  if (strcmp(command, "find me") == 0 || memcmp(command, "find me ", 8) == 0) {
    const char* arg = command[7] ? &command[8] : "";
    if (strcmp(arg, "stop") == 0) {
      strcpy(reply, (_listener && _listener->stopFindMe()) ? "OK, stopped" : "> not running");
      return true;
    }
    int secs = *arg ? atoi(arg) : 120;
    if (secs < 1 || secs > 600) {
      strcpy(reply, "Error: seconds must be 1 to 600");
    } else if (_listener && _listener->startFindMe(secs)) {
      sprintf(reply, "OK, beeping for %d s. Stop: press the button, or: find me stop", secs);
    } else {
      strcpy(reply, "Error: this radio has no buzzer or vibration motor");
    }
    return true;
  }

  if (memcmp(command, "set pin ", 8) == 0) {
    _prefs.ble_pin = atoi(&command[8]);
    savePrefs();
    sprintf(reply, "> pin is now %06lu", (unsigned long)_prefs.ble_pin);
    return true;
  }

#ifdef ENABLE_WIFI_INTERFACE
  if (memcmp(command, "set wifi.ssid ", 14) == 0) {
    StrHelper::strncpy(_prefs.wifi_ssid, &command[14], sizeof(_prefs.wifi_ssid));
    savePrefs();
    sprintf(reply, "> wifi.ssid is now %s (set wifi.pwd too, then reboot)", _prefs.wifi_ssid);
    return true;
  }
  if (memcmp(command, "set wifi.pwd ", 13) == 0) {
    StrHelper::strncpy(_prefs.wifi_pwd, &command[13], sizeof(_prefs.wifi_pwd));
    savePrefs();
    strcpy(reply, "> wifi.pwd updated (reboot to apply)");
    return true;
  }
  if (strcmp(command, "get wifi.pwd") == 0) {
    sprintf(reply, "> %s", _prefs.wifi_pwd);
    return true;
  }
  if (strcmp(command, "set wifi.clear") == 0) {
    _prefs.wifi_ssid[0] = 0;
    _prefs.wifi_pwd[0] = 0;
    savePrefs();
    strcpy(reply, "> wifi config cleared (reboot to apply)");
    return true;
  }
  if (strcmp(command, "get wifi.ssid") == 0) {
    sprintf(reply, "> %s", _prefs.getWifiSSID()[0] ? _prefs.getWifiSSID() : "(not set)");
    return true;
  }
  if (memcmp(command, "set wifi.enabled ", 17) == 0) {
    _prefs.wifi_enabled = atoi(&command[17]) ? 1 : 0;
    savePrefs();
    sprintf(reply, "> wifi.enabled is now %d (reboot to apply)", _prefs.wifi_enabled);
    return true;
  }
  if (strcmp(command, "get wifi.enabled") == 0) {
    sprintf(reply, "> %d", _prefs.wifi_enabled);
    return true;
  }
  if (strcmp(command, "get wifi.status") == 0) {
    strcpy(reply, WiFi.status() == WL_CONNECTED ? "> connected" : "> disconnected");
    return true;
  }
  if (strcmp(command, "get wifi.ip") == 0) {
    if (WiFi.status() == WL_CONNECTED) {
      sprintf(reply, "> %s", WiFi.localIP().toString().c_str());
    } else {
      strcpy(reply, "> (not connected)");
    }
    return true;
  }
#endif

  if (strcmp(command, "board") == 0) {
    strcpy(reply, board.getManufacturerName());
    return true;
  }

  if (strcmp(command, "ver") == 0) {
    sprintf(reply, "%s (Build: %s)", FIRMWARE_VERSION, FIRMWARE_BUILD_DATE);
    return true;
  }

  if (strcmp(command, "get tz.offset") == 0) {
    float q = _prefs.tz_offset * 4;
    sprintf(reply, (q == (int)q && ((int)q & 1)) ? "> %.2f" : "> %.1f", _prefs.tz_offset);
    return true;
  }
  if (memcmp(command, "set tz.offset ", 14) == 0) {
    float tz = atof(&command[14]);
    if (tz < -12 || tz > 14) {
      strcpy(reply, "Error, must be from -12 to +14");
    } else {
      _prefs.tz_offset = tz;
      savePrefs();
      strcpy(reply, "OK");
    }
    return true;
  }
#ifdef DISPLAY_CLASS
  if (memcmp(command, "set ui.show_clock", 17) == 0) {
    _prefs.ui_show_clock = atoi(&command[17]) ? 1 : 0;
    savePrefs();
    sprintf(reply, "> now %d", _prefs.ui_show_clock);
    return true;
  }
  if (memcmp(command, "set ui.auto_off_delay", 21) == 0) {
    _prefs.ui_auto_off_delay = atoi(&command[21]);
    savePrefs();
    sprintf(reply, "> now %lu seconds", (unsigned long)_prefs.ui_auto_off_delay);
    return true;
  }
  if (memcmp(command, "set ui.backlight_delay", 22) == 0) {
    _prefs.ui_backlight_delay = atoi(&command[22]);
    savePrefs();
    if (_prefs.ui_backlight_delay >= 0)    
      sprintf(reply, "> now %ld seconds", (long)_prefs.ui_backlight_delay);
    else if (_prefs.ui_backlight_delay == -1)
      sprintf(reply, "> now always on (-1)");
    else
      sprintf(reply, "> now disabled (<-1)");
    return true;
  }
  if (memcmp(command, "set ui.backlight_on_keys", 24) == 0) {
    _prefs.ui_backlight_on_keys = atoi(&command[24]);
    savePrefs();
    sprintf(reply, "> now %d", _prefs.ui_backlight_on_keys);
    return true;
  }
  if (memcmp(command, "set ui.backlight_on_msgs", 24) == 0) {
    _prefs.ui_backlight_on_msgs = atoi(&command[24]);
    savePrefs();
    sprintf(reply, "> now %d", _prefs.ui_backlight_on_msgs);
    return true;
  }
  if (memcmp(command, "set ui.auto_off_blank", 21) == 0) {
    _prefs.ui_auto_off_blank = atoi(&command[21]);
    savePrefs();
    sprintf(reply, "> now %d", _prefs.ui_auto_off_blank);
    return true;
  }
  if (memcmp(command, "set ui.auto_off_keep_msgs", 25) == 0) {
    _prefs.ui_auto_off_keep_msgs = atoi(&command[25]);
    savePrefs();
    sprintf(reply, "> now %d", _prefs.ui_auto_off_keep_msgs);
    return true;
  }
  if (memcmp(command, "set ui.max_partial", 18) == 0) {
    _prefs.ui_max_partial = atoi(&command[18]);
    savePrefs();
    sprintf(reply, "> now %d (applied at next screen wakeup)", _prefs.ui_max_partial);
    return true;
  }
  if (memcmp(command, "set ui.nd_name", 14) == 0) {
    _prefs.ui_nd_name = atoi(&command[14]);
    savePrefs();
    sprintf(reply, "> ui.nd_name is now %d", _prefs.ui_nd_name);
    return true;
  }
  if (memcmp(command, "get ui.show_clock", 17) == 0) {
    sprintf(reply, "> %d", _prefs.ui_show_clock);
    return true;
  }
  if (memcmp(command, "get ui.auto_off_delay", 21) == 0) {
    sprintf(reply, "> %lu seconds", (unsigned long)_prefs.ui_auto_off_delay);
    return true;
  }
  if (memcmp(command, "get ui.backlight_delay", 22) == 0) {
    if (_prefs.ui_backlight_delay >= 0)    
      sprintf(reply, "> %ld seconds", (long)_prefs.ui_backlight_delay);
    else if (_prefs.ui_backlight_delay == -1)
      sprintf(reply, "> always on (-1)");
    else
      sprintf(reply, "> disabled (<-1)");
    return true;
  }
  if (memcmp(command, "get ui.backlight_on_keys", 24) == 0) {
    sprintf(reply, "> %d", _prefs.ui_backlight_on_keys);
    return true;
  }
  if (memcmp(command, "get ui.backlight_on_msgs", 24) == 0) {
    sprintf(reply, "> %d", _prefs.ui_backlight_on_msgs);
    return true;
  }
  if (memcmp(command, "get ui.auto_off_blank", 21) == 0) {
    sprintf(reply, "> %d", _prefs.ui_auto_off_blank);
    return true;
  }
  if (memcmp(command, "get ui.auto_off_keep_msgs", 25) == 0) {
    sprintf(reply, "> %d", _prefs.ui_auto_off_keep_msgs);
    return true;
  }
  if (memcmp(command, "get ui.max_partial", 18) == 0) {
    sprintf(reply, "> %d", _prefs.ui_max_partial);
    return true;
  }
  if (memcmp(command, "get ui.nd_name", 14) == 0) {
    sprintf(reply, "> %d", _prefs.ui_nd_name);
    return true;
  }
#endif

  return false;  // not handled
}

void MyMesh::checkCLIRescueCmd() {
  int len = strlen(cli_command);
  // `cli_command` must stay NUL-terminated within its bounds. If it ever isn't,
  // strlen() above can return >= sizeof(cli_command) and the loop below would
  // then index past the buffer, so clamp defensively.
  if (len >= (int)sizeof(cli_command)) {
    cli_command[0] = 0;
    len = 0;
  }
  while (Serial.available() && len < (int) sizeof(cli_command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      cli_command[len++] = c;
      cli_command[len] = 0;
    }
    Serial.print(c);  // echo
  }
  if (len == sizeof(cli_command)-1) {  // buffer full: treat as a completed line
    cli_command[sizeof(cli_command)-2] = '\r';  // place end-of-line marker inside the buffer
    cli_command[sizeof(cli_command)-1] = 0;     // keep the buffer NUL-terminated
  }

  if (len > 0 && cli_command[len - 1] == '\r') {  // received complete line
    cli_command[len - 1] = 0;  // replace newline with C string null terminator

    reply_buf[0] = 0;
    if (handleCommand(cli_command, 0, reply_buf)) {
      // command was handled, print reply output
      Serial.print("  "); Serial.print(reply_buf); Serial.println();
    } else if (strcmp(cli_command, "rebuild") == 0) {
      bool success = _store->formatFileSystem();
      if (success) {
        _store->saveMainIdentity(self_id);
        savePrefs();
        saveContacts();
        saveChannels();
        Serial.println("  > erase and rebuild done");
      } else {
        Serial.println("  Error: erase failed");
      }
    } else if (strcmp(cli_command, "erase") == 0) {
      bool success = _store->formatFileSystem();
      if (success) {
        Serial.println("  > erase done");
      } else {
        Serial.println("  Error: erase failed");
      }
    } else if (memcmp(cli_command, "ls", 2) == 0) {

      // get path from command e.g: "ls /adafruit"
      const char *path = &cli_command[3];

      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      }
      Serial.printf("Listing files in %s\n", path);

      // log each file and directory
      File root = _store->openRead(path);
      if (is_fs2 == false) {
        if (root) {
          File file = root.openNextFile();
          while (file) {
            if (file.isDirectory()) {
              Serial.printf("[dir]  UserData%s/%s\n", path, file.name());
            } else {
              Serial.printf("[file] UserData%s/%s (%d bytes)\n", path, file.name(), file.size());
            }
            // move to next file
            file = root.openNextFile();
          }
          root.close();
        }
      }

      if (is_fs2 == true || strlen(path) == 0 || strcmp(path, "/") == 0) {
        if (_store->getSecondaryFS() != nullptr) {
          File root2 = _store->openRead(_store->getSecondaryFS(), path);
          File file = root2.openNextFile();
          while (file) {
            if (file.isDirectory()) {
              Serial.printf("[dir]  ExtraFS%s/%s\n", path, file.name());
            } else {
              Serial.printf("[file] ExtraFS%s/%s (%d bytes)\n", path, file.name(), file.size());
            }
            // move to next file
            file = root2.openNextFile();
          }
          root2.close();
        }
      }
    } else if (memcmp(cli_command, "cat", 3) == 0) {

      // get path from command e.g: "cat /contacts3"
      const char *path = &cli_command[4];

      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      } else {
        Serial.println("Invalid path provided, must start with UserData/ or ExtraFS/");
        cli_command[0] = 0;
        return;
      }

      // log file content as hex
      File file = _store->openRead(path);
      if (is_fs2 == true) {
        file = _store->openRead(_store->getSecondaryFS(), path);
      }
      if(file){

        // get file content
        int file_size = file.available();
        uint8_t buffer[file_size];
        file.read(buffer, file_size);

        // print hex
        mesh::Utils::printHex(Serial, buffer, file_size);
        Serial.print("\n");

        file.close();

      }

    } else if (memcmp(cli_command, "rm ", 3) == 0) {
      // get path from command e.g: "rm /adv_blobs"
      const char *path = &cli_command[3];
      MESH_DEBUG_PRINTLN("Removing file: %s", path);
      // ensure path is not empty, or root dir
      if(!path || strlen(path) == 0 || strcmp(path, "/") == 0){
        Serial.println("Invalid path provided");
      } else {
      bool is_fs2 = false;
      if (memcmp(path, "UserData/", 9) == 0) {
        path += 8; // skip "UserData"
      } else if (memcmp(path, "ExtraFS/", 8) == 0) {
        path += 7; // skip "ExtraFS"
        is_fs2 = true;
      }

        // remove file
        bool removed;
        if (is_fs2) {
          MESH_DEBUG_PRINTLN("Removing file from ExtraFS: %s", path);
          removed = _store->removeFile(_store->getSecondaryFS(), path);
        } else {
          MESH_DEBUG_PRINTLN("Removing file from UserData: %s", path);
          removed = _store->removeFile(path);
        }
        if(removed){
          Serial.println("File removed");
        } else {
          Serial.println("Failed to remove file");
        }

      }

    } else if (strcmp(cli_command, "reboot") == 0) {
      board.reboot();  // doesn't return
    } else {
      Serial.println("  Error: unknown command");
    }

    cli_command[0] = 0;  // reset command buffer
  }
}

void MyMesh::checkSerialInterface() {
  size_t len = _serial->checkRecvFrame(cmd_frame);
  if (len > 0) {
    handleCmdFrame(len);
  } else if (_iter_started              // check if our ContactsIterator is 'running'
             && !_serial->isWriteBusy() // don't spam the Serial Interface too quickly!
  ) {
    ContactInfo contact;
    if (_iter.hasNext(this, contact)) {
      if (contact.lastmod > _iter_filter_since) { // apply the 'since' filter
        writeContactRespFrame(RESP_CODE_CONTACT, contact);
        if (contact.lastmod > _most_recent_lastmod) {
          _most_recent_lastmod = contact.lastmod; // save for the RESP_CODE_END_OF_CONTACTS frame
        }
      }
    } else if (_iter_console_pending) {   // always sent, whatever the 'since' filter
      _iter_console_pending = false;
      ContactInfo console;
      fillConsoleContact(console);
      writeContactRespFrame(RESP_CODE_CONTACT, console);
    } else { // EOF
      out_frame[0] = RESP_CODE_END_OF_CONTACTS;
      memcpy(&out_frame[1], &_most_recent_lastmod,
             4); // include the most recent lastmod, so app can update their 'since'
      _serial->writeFrame(out_frame, 5);
      _iter_started = false;
    }
  //} else if (!_serial->isWriteBusy()) {
  //  checkConnections();    // TODO - deprecate the 'Connections' stuff
  }
}

void MyMesh::loop() {
  if (_xfer_on) {        // copying this radio: the clone link has the radio to itself
    cloneLoop();
  } else {
    BaseChatMesh::loop();
    findLoop();
    meshtasticLoop();
    if (_radar_active) {   // the radar listen has the radio to itself
      radarLoop();
    } else {
      weatherLoop();
      aircraftLoop();
    }
  }

  if (_crypto_save_pending && (long)(millis() - _crypto_save_at) >= 0) {
    _crypto_save_pending = false;
    if (!_crypto_lost) saveCryptoPolicies();
  }

  if (_cli_rescue) {
    checkCLIRescueCmd();
  } else {
    checkSerialInterface();
    checkConsole();
#if defined(ENABLE_WIFI_INTERFACE) && defined(RP2040_PLATFORM) && !defined(ENABLE_USB_INTERFACE)
    // RP2040 WiFi builds are headless and have no way into the rescue CLI (that needs a
    // display + long-press), so serve config commands on the otherwise unused USB serial
    checkCLIRescueCmd();
#endif
  }

  // is there are pending dirty contacts write needed? (not while a copy may replace them)
  if (dirty_contacts_expiry && !_xfer_on && millisHasNowPassed(dirty_contacts_expiry)) {
    saveContacts();
    dirty_contacts_expiry = 0;
  }
}

bool MyMesh::advert() {
  mesh::Packet* pkt;
  if (_prefs.advert_loc_policy == ADVERT_LOC_NONE) {
    pkt = createSelfAdvert(_prefs.node_name);
  } else {
    pkt = createSelfAdvert(_prefs.node_name, sensors.node_lat, sensors.node_lon);
  }
  if (pkt) {
    sendZeroHop(pkt);
    return true;
  } else {
    return false;
  }
}

// To check if there is pending work
bool MyMesh::hasPendingWork() const {
  return _mgr->getOutboundTotal() > 0 || dirty_contacts_expiry != 0;
}
