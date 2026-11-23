#include "MyMesh.h"
#include <algorithm>
#include <helpers/FloodRetryCLI.h>
#include <helpers/sensors/LPPDataHelpers.h>

/* ------------------------------ Config -------------------------------- */

#ifndef LORA_FREQ
  #define LORA_FREQ 915.0
#endif
#ifndef LORA_BW
  #define LORA_BW 250
#endif
#ifndef LORA_SF
  #define LORA_SF 10
#endif
#ifndef LORA_CR
  #define LORA_CR 5
#endif
#ifndef LORA_TX_POWER
  #define LORA_TX_POWER 20
#endif

#ifndef ADVERT_NAME
  #define ADVERT_NAME "repeater"
#endif
#ifndef ADVERT_LAT
  #define ADVERT_LAT 0.0
#endif
#ifndef ADVERT_LON
  #define ADVERT_LON 0.0
#endif

#ifndef ADMIN_PASSWORD
  #define ADMIN_PASSWORD "password"
#endif

#ifndef SERVER_RESPONSE_DELAY
  #define SERVER_RESPONSE_DELAY 300
#endif

#ifndef TXT_ACK_DELAY
  #define TXT_ACK_DELAY 200
#endif

#ifndef SENSOR_READ_INTERVAL_SECS
  #define SENSOR_READ_INTERVAL_SECS  60
#endif

#ifndef TELEM_SUBSCRIBE_MAX_SECS
  #define TELEM_SUBSCRIBE_MAX_SECS  3600
#endif

#define FIRMWARE_VER_LEVEL       2

#define REQ_TYPE_GET_STATUS         0x01 // same as _GET_STATS
#define REQ_TYPE_KEEP_ALIVE         0x02
#define REQ_TYPE_GET_TELEMETRY_DATA 0x03
#define REQ_TYPE_GET_ACCESS_LIST    0x05
#define REQ_TYPE_GET_NEIGHBOURS     0x06
#define REQ_TYPE_GET_OWNER_INFO     0x07     // FIRMWARE_VER_LEVEL >= 2

#define REQ_TYPE_SUBSCRIBE           0x08
#define REQ_TYPE_UNSUBSCRIBE         0x09

#define RESP_SERVER_LOGIN_OK        0 // response to ANON_REQ

#define ANON_REQ_TYPE_REGIONS      0x01
#define ANON_REQ_TYPE_OWNER        0x02
#define ANON_REQ_TYPE_BASIC        0x03   // just remote clock

#define CLI_REPLY_DELAY_MILLIS      600

#define LAZY_CONTACTS_WRITE_DELAY    5000

void MyMesh::putNeighbour(const mesh::Identity &id, uint32_t timestamp, float snr) {
#if MAX_NEIGHBOURS // check if neighbours enabled
  // find existing neighbour, else use least recently updated
  uint32_t oldest_timestamp = 0xFFFFFFFF;
  NeighbourInfo *neighbour = &neighbours[0];
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    // if neighbour already known, we should update it
    if (id.matches(neighbours[i].id)) {
      neighbour = &neighbours[i];
      break;
    }

    // otherwise we should update the least recently updated neighbour
    if (neighbours[i].heard_timestamp < oldest_timestamp) {
      neighbour = &neighbours[i];
      oldest_timestamp = neighbour->heard_timestamp;
    }
  }

  // update neighbour info
  neighbour->id = id;
  neighbour->advert_timestamp = timestamp;
  neighbour->heard_timestamp = getRTCClock()->getCurrentTime();
  neighbour->snr = (int8_t)(snr * 4);
#endif
}

uint8_t MyMesh::handleLoginReq(const mesh::Identity& sender, const uint8_t* secret, uint32_t sender_timestamp, const uint8_t* data, bool is_flood) {
  ClientInfo* client = NULL;
  if (data[0] == 0) {   // blank password, just check if sender is in ACL
    client = acl.getClient(sender.pub_key, PUB_KEY_SIZE);
    if (client == NULL) {
    #if MESH_DEBUG
      MESH_DEBUG_PRINTLN("Login, sender not in ACL");
    #endif
    }
  }
  if (client == NULL) {
    uint8_t perms;
    if (strcmp((char *)data, _prefs.password) == 0) { // check for valid admin password
      perms = PERM_ACL_ADMIN;
    } else if (strcmp((char *)data, _prefs.guest_password) == 0) { // check guest password
      perms = PERM_ACL_GUEST;
    } else {
#if MESH_DEBUG
      MESH_DEBUG_PRINTLN("Invalid password: %s", data);
#endif
      return 0;
    }

    client = acl.putClient(sender, 0);  // add to contacts (if not already known)
    if (sender_timestamp <= client->last_timestamp) {
      MESH_DEBUG_PRINTLN("Possible login replay attack!");
      return 0;  // FATAL: client table is full -OR- replay attack
    }

    MESH_DEBUG_PRINTLN("Login success!");
    client->last_timestamp = sender_timestamp;
    client->last_activity = getRTCClock()->getCurrentTime();
    client->permissions &= ~0x03;
    client->permissions |= perms;
    memcpy(client->shared_secret, secret, PUB_KEY_SIZE);

    if (perms != PERM_ACL_GUEST) {   // keep number of FS writes to a minimum
      dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);
    }
  }

  if (is_flood) {
    client->out_path_len = OUT_PATH_UNKNOWN;  // need to rediscover out_path
  }

  uint32_t now = getRTCClock()->getCurrentTimeUnique();
  memcpy(reply_data, &now, 4);   // response packets always prefixed with timestamp
  reply_data[4] = RESP_SERVER_LOGIN_OK;
  reply_data[5] = 0;  // Legacy: was recommended keep-alive interval (secs / 16)
  reply_data[6] = client->isAdmin() ? 1 : 0;
  reply_data[7] = client->permissions;
  getRNG()->random(&reply_data[8], 4);   // random blob to help packet-hash uniqueness
  reply_data[12] = FIRMWARE_VER_LEVEL;  // New field

  return 13;  // reply length
}

uint8_t MyMesh::handleAnonRegionsReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data,
                                     size_t data_len) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    if (data == nullptr || data_len == 0 || !mesh::Packet::isValidPathLen(data[0])) return 0;
    const size_t path_byte_len = (data[0] & 63) * ((data[0] >> 6) + 1);
    if (path_byte_len > data_len - 1) return 0;
    reply_path_len = *data++;

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)

    return 8 + region_map.exportNamesTo((char *) &reply_data[8], sizeof(reply_data) - 12, REGION_DENY_FLOOD);   // reply length
  }
  return 0;
}

uint8_t MyMesh::handleAnonOwnerReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data,
                                   size_t data_len) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    if (data == nullptr || data_len == 0 || !mesh::Packet::isValidPathLen(data[0])) return 0;
    const size_t path_byte_len = (data[0] & 63) * ((data[0] >> 6) + 1);
    if (path_byte_len > data_len - 1) return 0;
    reply_path_len = *data++;

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)
    sprintf((char *) &reply_data[8], "%s\n%s", _prefs.node_name, _prefs.owner_info);

    return 8 + strlen((char *) &reply_data[8]);   // reply length
  }
  return 0;
}

uint8_t MyMesh::handleAnonClockReq(const mesh::Identity& sender, uint32_t sender_timestamp, const uint8_t* data,
                                   size_t data_len) {
  if (anon_limiter.allow(rtc_clock.getCurrentTime())) {
    // request data has: {reply-path-len}{reply-path}
    if (data == nullptr || data_len == 0 || !mesh::Packet::isValidPathLen(data[0])) return 0;
    const size_t path_byte_len = (data[0] & 63) * ((data[0] >> 6) + 1);
    if (path_byte_len > data_len - 1) return 0;
    reply_path_len = *data++;

    mesh::Packet::writePath(reply_path, data, reply_path_len);
    // data += (uint8_t)reply_path_len * reply_path_hash_size;

    memcpy(reply_data, &sender_timestamp, 4);   // prefix with sender_timestamp, like a tag
    uint32_t now = getRTCClock()->getCurrentTime();
    memcpy(&reply_data[4], &now, 4);     // include our clock (for easy clock sync, and packet hash uniqueness)
    reply_data[8] = 0;  // features
#ifdef WITH_RS232_BRIDGE
    reply_data[8] |= 0x01;  // is bridge, type UART
#elif WITH_ESPNOW_BRIDGE
    reply_data[8] |= 0x03;  // is bridge, type ESP-NOW
#endif
    if (_prefs.disable_fwd) {   // is this repeater currently disabled
      reply_data[8] |= 0x80;  // is disabled
    }
    // TODO:  add some kind of moving-window utilisation metric, so can query 'how busy' is this repeater
    return 9;   // reply length
  }
  return 0;
}

/* --------------------- Cayenne LPP helpers ----------------------------*/

static float findTelemValue(const uint8_t* buf, uint8_t size, uint8_t channel, uint8_t type, float def_value) {
  uint8_t i = 0;

  while (i + 2 < size) {
    // Get channel #
    uint8_t ch = buf[i++];
    // Get data type
    uint8_t t = buf[i++];
    uint8_t sz = LPPData::getDataSize(t);

    if (ch == channel && t == type) {
      return LPPData::getFloat(&buf[i], sz, LPPData::getMultiplier(t), LPPData::isSigned(t));
    }
    i += sz;  // skip
  }
  return def_value;   // not found
}

/* ------------------ end Cayenne LPP helpers ----------------------*/

bool MyMesh::telemHasChanged(ClientInfo* c) {
  auto buf = telemetry.getBuffer();
  uint8_t size = telemetry.getSize();
  uint8_t i = 0;
  bool changed = false;

  while (i + 2 < c->extra.sensor.min_deltas_len) {
    uint8_t ch = c->extra.sensor.min_deltas[i];    // Get channel #
    uint8_t t = c->extra.sensor.min_deltas[i + 1];     // Get data type
    uint8_t sz = LPPData::getDataSize(t);

    float min_delta = LPPData::getFloat(&c->extra.sensor.min_deltas[i + 2], sz, LPPData::getMultiplier(t), LPPData::isSigned(t));
    float pv = LPPData::getFloat(&c->extra.sensor.prev_telem[i + 2], sz, LPPData::getMultiplier(t), LPPData::isSigned(t));

    float v = findTelemValue(buf, size, ch, t, 0.0f);
    if (abs(v - pv) > min_delta) changed = true;   // Yes, has changed

    i += 2 + sz;  // skip
  }
  if (changed) {
    // take snapshot of all _monitored_ telem values, for next cycle
    i = 0;
    while (i + 2 < c->extra.sensor.min_deltas_len) {
      uint8_t ch = c->extra.sensor.min_deltas[i];    // Get channel #
      uint8_t t = c->extra.sensor.min_deltas[i + 1];     // Get data type
      uint8_t sz = LPPData::getDataSize(t);

      c->extra.sensor.prev_telem[i] = ch;
      c->extra.sensor.prev_telem[i + 1] = t;

      float v = findTelemValue(buf, size, ch, t, 0.0f);
      LPPData::putFloat(&c->extra.sensor.prev_telem[i + 2], v, sz, LPPData::getMultiplier(t), LPPData::isSigned(t));

      i += 2 + sz;  // skip
    }
  }
  return changed;
}

int MyMesh::handleRequest(ClientInfo *sender, uint32_t sender_timestamp, uint8_t *payload, size_t payload_len) {
  // uint32_t now = getRTCClock()->getCurrentTimeUnique();
  // memcpy(reply_data, &now, 4);   // response packets always prefixed with timestamp
  memcpy(reply_data, &sender_timestamp, 4); // reflect sender_timestamp back in response packet (kind of like a 'tag')

  if (payload[0] == REQ_TYPE_GET_STATUS) {  // guests can also access this now
    RepeaterStats stats;
    stats.batt_milli_volts = board.getBattMilliVolts();
    stats.curr_tx_queue_len = _mgr->getOutboundTotal();
    stats.noise_floor = (int16_t)_radio->getNoiseFloor();
    stats.last_rssi = (int16_t)radio_driver.getLastRSSI();
    stats.n_packets_recv = radio_driver.getPacketsRecv();
    stats.n_packets_sent = radio_driver.getPacketsSent();
    stats.total_air_time_secs = getTotalAirTime() / 1000;
    stats.total_up_time_secs = uptime_millis / 1000;
    stats.n_sent_flood = getNumSentFlood();
    stats.n_sent_direct = getNumSentDirect();
    stats.n_recv_flood = getNumRecvFlood();
    stats.n_recv_direct = getNumRecvDirect();
    stats.err_events = _err_flags;
    stats.last_snr = (int16_t)(radio_driver.getLastSNR() * 4);
    stats.n_direct_dups = std::min<uint32_t>(((SimpleMeshTables *)getTables())->getNumDirectDups(), 0xFFFF);
    stats.n_flood_dups = std::min<uint32_t>(((SimpleMeshTables *)getTables())->getNumFloodDups(), 0xFFFF);
    stats.total_rx_air_time_secs = getReceiveAirTime() / 1000;
    stats.n_recv_errors = radio_driver.getPacketsRecvErrors();
    memcpy(&reply_data[4], &stats, sizeof(stats));

    return 4 + sizeof(stats); //  reply_len
  }
  if (payload[0] == REQ_TYPE_GET_TELEMETRY_DATA) {
    uint8_t perm_mask = ~(payload[1]); // NEW: first reserved byte (of 4), is now inverse mask to apply to permissions

    telemetry.reset();
    telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);

    // query other sensors -- target specific
    if ((sender->permissions & PERM_ACL_ROLE_MASK) == PERM_ACL_GUEST) {
      perm_mask = 0x00;  // just base telemetry allowed
    }
    sensors.querySensors(perm_mask, telemetry);

	// This default temperature will be overridden by external sensors (if any)
    float temperature = board.getMCUTemperature();
    if(!isnan(temperature)) { // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
      telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature); // Built-in MCU Temperature
    }

    uint8_t tlen = telemetry.getSize();
    memcpy(&reply_data[4], telemetry.getBuffer(), tlen);
    return 4 + tlen; // reply_len
  }
  if (payload[0] == REQ_TYPE_GET_ACCESS_LIST && sender->isAdmin()) {
    uint8_t res1 = payload[1];   // reserved for future  (extra query params)
    uint8_t res2 = payload[2];
    if (res1 == 0 && res2 == 0) {
      uint8_t ofs = 4;
      for (int i = 0; i < acl.getNumClients() && ofs + 7 <= (int) sizeof(reply_data) - 4; i++) {
        auto c = acl.getClientByIdx(i);
        if (c->permissions == 0) continue;  // skip deleted entries
        memcpy(&reply_data[ofs], c->id.pub_key, 6); ofs += 6;  // just 6-byte pub_key prefix
        reply_data[ofs++] = c->permissions;
      }
      return ofs;
    }
  }
  if (payload[0] == REQ_TYPE_GET_NEIGHBOURS) {
    uint8_t request_version = payload[1];
    if (request_version == 0) {

      // reply data offset (after response sender_timestamp/tag)
      int reply_offset = 4;

      // get request params
      uint8_t count = payload[2]; // how many neighbours to fetch (0-255)
      uint16_t offset;
      memcpy(&offset, &payload[3], 2); // offset from start of neighbours list (0-65535)
      uint8_t order_by = payload[5]; // how to order neighbours. 0=newest_to_oldest, 1=oldest_to_newest, 2=strongest_to_weakest, 3=weakest_to_strongest
      uint8_t pubkey_prefix_length = payload[6]; // how many bytes of neighbour pub key we want
      // we also send a 4 byte random blob in payload[7...10] to help packet uniqueness

      MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS count=%d, offset=%d, order_by=%d, pubkey_prefix_length=%d", count, offset, order_by, pubkey_prefix_length);

      // clamp pub key prefix length to max pub key length
      if(pubkey_prefix_length > PUB_KEY_SIZE){
        pubkey_prefix_length = PUB_KEY_SIZE;
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS invalid pubkey_prefix_length=%d clamping to %d", pubkey_prefix_length, PUB_KEY_SIZE);
      }

      // create copy of neighbours list, skipping empty entries so we can sort it separately from main list
      int16_t neighbours_count = 0;
#if MAX_NEIGHBOURS
      NeighbourInfo* sorted_neighbours[MAX_NEIGHBOURS];
      for (int i = 0; i < MAX_NEIGHBOURS; i++) {
        auto neighbour = &neighbours[i];
        if (neighbour->heard_timestamp > 0) {
          sorted_neighbours[neighbours_count] = neighbour;
          neighbours_count++;
        }
      }

      // sort neighbours based on order
      if (order_by == 0) {
        // sort by newest to oldest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting newest to oldest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->heard_timestamp > b->heard_timestamp; // desc
        });
      } else if (order_by == 1) {
        // sort by oldest to newest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting oldest to newest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->heard_timestamp < b->heard_timestamp; // asc
        });
      } else if (order_by == 2) {
        // sort by strongest to weakest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting strongest to weakest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->snr > b->snr; // desc
        });
      } else if (order_by == 3) {
        // sort by weakest to strongest
        MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS sorting weakest to strongest");
        std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
          return a->snr < b->snr; // asc
        });
      }
#endif

      // build results buffer
      int results_count = 0;
      int results_offset = 0;
      uint8_t results_buffer[130];
      for(int index = 0; index < count && index + offset < neighbours_count; index++){

        // stop if we can't fit another entry in results
        int entry_size = pubkey_prefix_length + 4 + 1;
        if(results_offset + entry_size > (int) sizeof(results_buffer)){
          MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS no more entries can fit in results buffer");
          break;
        }

#if MAX_NEIGHBOURS
        // add next neighbour to results
        auto neighbour = sorted_neighbours[index + offset];
        uint32_t heard_seconds_ago = getRTCClock()->getCurrentTime() - neighbour->heard_timestamp;
        memcpy(&results_buffer[results_offset], neighbour->id.pub_key, pubkey_prefix_length); results_offset += pubkey_prefix_length;
        memcpy(&results_buffer[results_offset], &heard_seconds_ago, 4); results_offset += 4;
        memcpy(&results_buffer[results_offset], &neighbour->snr, 1); results_offset += 1;
        results_count++;
#endif

      }

      // build reply
      MESH_DEBUG_PRINTLN("REQ_TYPE_GET_NEIGHBOURS neighbours_count=%d results_count=%d", neighbours_count, results_count);
      memcpy(&reply_data[reply_offset], &neighbours_count, 2); reply_offset += 2;
      memcpy(&reply_data[reply_offset], &results_count, 2); reply_offset += 2;
      memcpy(&reply_data[reply_offset], &results_buffer, results_offset); reply_offset += results_offset;

      return reply_offset;
    }
  } else if (payload[0] == REQ_TYPE_GET_OWNER_INFO) {
    sprintf((char *) &reply_data[4], "%s\n%s\n%s", FIRMWARE_VERSION, _prefs.node_name, _prefs.owner_info);
    return 4 + strlen((char *) &reply_data[4]);
  }

  return payload_len > 0 ? handleRequest(sender, sender_timestamp, payload[0], &payload[1], payload_len - 1) : 0;
}

int MyMesh::handleRequest(ClientInfo *from, uint32_t sender_timestamp, uint8_t req_type, uint8_t *payload, size_t payload_len) {
  uint8_t perms = from->isAdmin() ? 0xFF : from->permissions;

  if (req_type == REQ_TYPE_SUBSCRIBE && payload_len >= 8 && (perms & PERM_ACL_ROLE_MASK) >= PERM_ACL_READ_ONLY) {
    memcpy(&from->extra.sensor.push_tag, &payload[0], 4);
    uint16_t timeout_secs;
    memcpy(&timeout_secs, &payload[4], 2);
    // payload[6] is reserved
    uint8_t  min_deltas_len = payload[7];
    RegionEntry* r;
    if (recv_pkt_region && !recv_pkt_region->isWildcard()) {   // use request scope
      r = recv_pkt_region;
    } else {   // use default scope
      r = region_map.getDefaultRegion();
    }
    uint8_t reply_len;
    if (r && min_deltas_len >= 3 && min_deltas_len <= sizeof(from->extra.sensor.min_deltas)) {
      if (timeout_secs > TELEM_SUBSCRIBE_MAX_SECS) timeout_secs = TELEM_SUBSCRIBE_MAX_SECS;  // impose max
      from->extra.sensor.scope_region_id = r->id;
      from->extra.sensor.expiry_timestamp = getRTCClock()->getCurrentTime() + timeout_secs;
      from->extra.sensor.min_deltas_len = min_deltas_len;
      memcpy(from->extra.sensor.min_deltas, &payload[8], min_deltas_len);
      // reply with actual expiry seconds (we could modify/impose restriction)
      memcpy(&reply_data[4], &timeout_secs, 2);
      memset(&reply_data[6], 0, 2);  // reserved
      strcpy((char *)&reply_data[8], r ? r->name : "");  // reply with name of scope that will be used
      reply_len = 8 + strlen((char *)&reply_data[8]);
    } else {
      memset(&reply_data[4], 0, 4);  // expiry secs (0 for error)
      reply_len = 8;
    }
    return reply_len;
  }
  if (req_type == REQ_TYPE_UNSUBSCRIBE && (perms & PERM_ACL_ROLE_MASK) >= PERM_ACL_READ_ONLY) {
    from->extra.sensor.scope_region_id = 0;
    from->extra.sensor.push_tag = 0;
    from->extra.sensor.expiry_timestamp = 0;
    from->extra.sensor.min_deltas_len = 0;
    // REVISIT: maybe return some stats, eg total number of telemetry pushes since SUBSCRIBE?
    memset(&reply_data[4], 0, 8);  // success
    getRNG()->random(&reply_data[12], 2);   // just some entropy for better packet-hash uniqueness
    return 12 + 2;
  }
  return 0; // unknown command
}

mesh::Packet *MyMesh::createSelfAdvert() {
  uint8_t app_data[MAX_ADVERT_DATA_SIZE];
  uint8_t app_data_len = _cli.buildAdvertData(ADV_TYPE_REPEATER, app_data);

  return createAdvert(self_id, app_data, app_data_len);
}

File MyMesh::openAppend(const char *fname) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return _fs->open(fname, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return _fs->open(fname, "a");
#else
  return _fs->open(fname, "a", true);
#endif
}

static uint8_t max_loop_minimal[] =  { 0, /* 1-byte */  4, /* 2-byte */  2, /* 3-byte */  1 };
static uint8_t max_loop_moderate[] = { 0, /* 1-byte */  2, /* 2-byte */  1, /* 3-byte */  1 };
static uint8_t max_loop_strict[] =   { 0, /* 1-byte */  1, /* 2-byte */  1, /* 3-byte */  1 };

bool MyMesh::isLooped(const mesh::Packet* packet, const uint8_t max_counters[]) {
  uint8_t hash_size = packet->getPathHashSize();
  uint8_t hash_count = packet->getPathHashCount();
  uint8_t n = 0;
  const uint8_t* path = packet->path;
  while (hash_count > 0) {      // count how many times this node is already in the path
    if (self_id.isHashMatch(path, hash_size)) n++;
    hash_count--;
    path += hash_size;
  }
  return n >= max_counters[hash_size];
}

void MyMesh::sendFloodReply(mesh::Packet* packet, unsigned long delay_millis, uint8_t path_hash_size) {
  TransportKey req_scope;
  bool is_wildcard = recv_pkt_region != NULL && recv_pkt_region->isWildcard();
  bool req_scope_known = recv_pkt_region != NULL && !is_wildcard
                      && region_map.getTransportKeysFor(*recv_pkt_region, &req_scope, 1) > 0;

  switch (mesh::chooseReplyScope(req_scope_known, is_wildcard, !default_scope.isNull())) {
    case mesh::REPLY_SCOPE_REQUEST:
      sendFloodScoped(req_scope, packet, delay_millis, path_hash_size);   // reply with same scope as request
      break;
    case mesh::REPLY_SCOPE_DEFAULT:
      // requester's scope is unknown: DIRECT request (no transport codes), or code matched no Region.
      // un-scoped would be dropped at hop 0 by repeaters running flood.max.unscoped=0
      sendFloodScoped(default_scope, packet, delay_millis, path_hash_size);
      break;
    case mesh::REPLY_SCOPE_NONE:
      sendFlood(packet, delay_millis, path_hash_size);  // send un-scoped
      break;
  }
}

bool MyMesh::allowPacketForward(const mesh::Packet *packet) {
  if (_prefs.disable_fwd) return false;
  if (packet->isRouteFlood()
      && mesh::isFloodHopLimitExceeded(packet, _prefs.flood_max, _prefs.flood_max_unscoped, _prefs.flood_max_advert)) {
    return false;
  }
  if (packet->isRouteFlood() && recv_pkt_region == NULL) {
    MESH_DEBUG_PRINTLN("allowPacketForward: unknown transport code, or wildcard not allowed for FLOOD packet");
    return false;
  }
  if (packet->isRouteFlood() && _prefs.loop_detect != LOOP_DETECT_OFF) {
    const uint8_t* maximums;
    if (_prefs.loop_detect == LOOP_DETECT_MINIMAL) {
      maximums = max_loop_minimal;
    } else if (_prefs.loop_detect == LOOP_DETECT_MODERATE) {
      maximums = max_loop_moderate;
    } else {
      maximums = max_loop_strict;
    }
    if (isLooped(packet, maximums)) {
      MESH_DEBUG_PRINTLN("allowPacketForward: FLOOD packet loop detected!");
      return false;
    }
  }
  return true;
}

const char *MyMesh::getLogDateTime() {
  static char tmp[32];
  uint32_t now = getRTCClock()->getCurrentTime();
  DateTime dt = DateTime(now);
  sprintf(tmp, "%02d:%02d:%02d - %d/%d/%d U", dt.hour(), dt.minute(), dt.second(), dt.day(), dt.month(),
          dt.year());
  return tmp;
}

void MyMesh::logRxRaw(float snr, float rssi, const uint8_t raw[], int len) {
#if MESH_PACKET_LOGGING
  Serial.print(getLogDateTime());
  Serial.print(" RAW: ");
  mesh::Utils::printHex(Serial, raw, len);
  Serial.println();
#endif
}

void MyMesh::logRx(mesh::Packet *pkt, int len, float score) {
#ifdef WITH_BRIDGE
  if (_prefs.bridge_pkt_src == 1) {
    bridge.sendPacket(pkt);
  }
#endif

  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": RX, len=%d (type=%d, route=%s, payload_len=%d) SNR=%d RSSI=%d score=%d", len,
               pkt->getPayloadType(), pkt->isRouteDirect() ? "D" : "F", pkt->payload_len,
               (int)_radio->getLastSNR(), (int)_radio->getLastRSSI(), (int)(score * 1000));

      if (pkt->payload_len >= 2 &&
          (pkt->getPayloadType() == PAYLOAD_TYPE_PATH || pkt->getPayloadType() == PAYLOAD_TYPE_REQ ||
           pkt->getPayloadType() == PAYLOAD_TYPE_RESPONSE || pkt->getPayloadType() == PAYLOAD_TYPE_TXT_MSG)) {
        f.printf(" [%02X -> %02X]\n", (uint32_t)pkt->payload[1], (uint32_t)pkt->payload[0]);
      } else {
        f.printf("\n");
      }
      f.close();
    }
  }
}

void MyMesh::logTx(mesh::Packet *pkt, int len) {
#ifdef WITH_BRIDGE
  if (_prefs.bridge_pkt_src == 0) {
    bridge.sendPacket(pkt);
  }
#endif

  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": TX, len=%d (type=%d, route=%s, payload_len=%d)", len, pkt->getPayloadType(),
               pkt->isRouteDirect() ? "D" : "F", pkt->payload_len);

      if (pkt->payload_len >= 2 &&
          (pkt->getPayloadType() == PAYLOAD_TYPE_PATH || pkt->getPayloadType() == PAYLOAD_TYPE_REQ ||
           pkt->getPayloadType() == PAYLOAD_TYPE_RESPONSE || pkt->getPayloadType() == PAYLOAD_TYPE_TXT_MSG)) {
        f.printf(" [%02X -> %02X]\n", (uint32_t)pkt->payload[1], (uint32_t)pkt->payload[0]);
      } else {
        f.printf("\n");
      }
      f.close();
    }
  }
}

void MyMesh::logTxFail(mesh::Packet *pkt, int len) {
  if (_logging) {
    File f = openAppend(PACKET_LOG_FILE);
    if (f) {
      f.print(getLogDateTime());
      f.printf(": TX FAIL!, len=%d (type=%d, route=%s, payload_len=%d)\n", len, pkt->getPayloadType(),
               pkt->isRouteDirect() ? "D" : "F", pkt->payload_len);
      f.close();
    }
  }
}

int MyMesh::calcRxDelay(float score, uint32_t air_time) const {
  if (_prefs.rx_delay_base <= 0.0f) return 0;
  return (int)((pow(_prefs.rx_delay_base, 0.85f - score) - 1.0) * air_time);
}

uint8_t MyMesh::getFloodRetries(const mesh::Packet* packet) {
  // only asked for packets some node should pass on (see FloodRetry::canEcho)
  if (packet->getPayloadType() == PAYLOAD_TYPE_ADVERT) return 0;   // most of the flood traffic, and losing one is cheap
  return _prefs.flood_retry.count;
}

uint32_t MyMesh::getFloodRetryWait(const mesh::Packet* packet) {
  return _prefs.flood_retry.wait_ms ? _prefs.flood_retry.wait_ms : mesh::Mesh::getFloodRetryWait(packet);
}

#ifndef FLOOD_RETRY_BUSY_QUEUE
  #define FLOOD_RETRY_BUSY_QUEUE  2   // skip a resend if this many packets are already waiting to go out
#endif

bool MyMesh::allowFloodRetryNow(const mesh::Packet* packet) {
  return _mgr->getOutboundTotal() < FLOOD_RETRY_BUSY_QUEUE;
}

uint32_t MyMesh::getRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}
uint32_t MyMesh::getDirectRetransmitDelay(const mesh::Packet *packet) {
  uint32_t t = (_radio->getEstAirtimeFor(packet->getPathByteLen() + packet->payload_len + 2) * _prefs.direct_tx_delay_factor);
  return getRNG()->nextInt(0, 5*t + 1);
}

mesh::DispatcherAction MyMesh::onRecvPacket(mesh::Packet* pkt) {
  if (pkt->getRouteType() == ROUTE_TYPE_TRANSPORT_FLOOD) {
    recv_pkt_region = region_map.findMatch(pkt, REGION_DENY_FLOOD);
  } else if (pkt->getRouteType() == ROUTE_TYPE_FLOOD) {
    if (region_map.getWildcard().flags & REGION_DENY_FLOOD) {
      recv_pkt_region = NULL;
    } else {
      recv_pkt_region =  &region_map.getWildcard();
    }
  } else {
    recv_pkt_region = NULL;
  }
  return Mesh::onRecvPacket(pkt);
}

void MyMesh::onAnonDataRecv(mesh::Packet *packet, const uint8_t *secret, const mesh::Identity &sender,
                            uint8_t *data, size_t len) {
  if (packet->getPayloadType() == PAYLOAD_TYPE_ANON_REQ) { // received an initial request by a possible admin
                                                           // client (unknown at this stage)
    if (len < 5 || len >= MAX_PACKET_PAYLOAD) return;

    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    data[len] = 0;  // ensure null terminator
    uint8_t reply_len;

    reply_path_len = 0xFF;
    if (data[4] == 0 || data[4] >= ' ') {   // is password, ie. a login request
      reply_len = handleLoginReq(sender, secret, timestamp, &data[4], packet->isRouteFlood());
    } else if (data[4] == ANON_REQ_TYPE_REGIONS && packet->isRouteDirect()) {
      reply_len = handleAnonRegionsReq(sender, timestamp, &data[5], len - 5);
    } else if (data[4] == ANON_REQ_TYPE_OWNER && packet->isRouteDirect()) {
      reply_len = handleAnonOwnerReq(sender, timestamp, &data[5], len - 5);
    } else if (data[4] == ANON_REQ_TYPE_BASIC && packet->isRouteDirect()) {
      reply_len = handleAnonClockReq(sender, timestamp, &data[5], len - 5);
    } else {
      reply_len = 0;  // unknown/invalid request type
    }

    if (reply_len == 0) return;   // invalid request

    // a DIRECT login can reply via the stored out_path, as onPeerDataRecv() does for REQ
    ClientInfo* client = acl.getClient(sender.pub_key, PUB_KEY_SIZE);
    bool have_out_path = client != NULL && client->out_path_len != OUT_PATH_UNKNOWN;

    auto route = mesh::chooseReplyRoute(packet->isRouteFlood(), reply_path_len != 0xFF, have_out_path);

    if (route == mesh::REPLY_ROUTE_PATH_RETURN) {
      // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the response
      mesh::Packet* path = createPathReturn(sender, secret, packet->path, packet->path_len,
                                            PAYLOAD_TYPE_RESPONSE, reply_data, reply_len);
      if (path) sendFloodReply(path, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
      return;
    }

    mesh::Packet* reply = createDatagram(PAYLOAD_TYPE_RESPONSE, sender, secret, reply_data, reply_len);
    if (reply == NULL) return;

    if (route == mesh::REPLY_ROUTE_DIRECT_SUPPLIED) {
      sendDirect(reply, reply_path, reply_path_len, SERVER_RESPONSE_DELAY);
    } else if (route == mesh::REPLY_ROUTE_DIRECT_OUT_PATH) {
      sendDirect(reply, client->out_path, client->out_path_len, SERVER_RESPONSE_DELAY);
    } else {
      sendFloodReply(reply, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
    }
  }
}

int MyMesh::searchPeersByHash(const uint8_t *hash) {
  int n = 0;
  for (int i = 0; i < acl.getNumClients(); i++) {
    if (acl.getClientByIdx(i)->id.isHashMatch(hash)) {
      matching_peer_indexes[n++] = i; // store the INDEXES of matching contacts (for subsequent 'peer' methods)
    }
  }
  return n;
}

void MyMesh::getPeerSharedSecret(uint8_t *dest_secret, int peer_idx) {
  int i = matching_peer_indexes[peer_idx];
  if (i >= 0 && i < acl.getNumClients()) {
    // lookup pre-calculated shared_secret
    memcpy(dest_secret, acl.getClientByIdx(i)->shared_secret, PUB_KEY_SIZE);
  } else {
    MESH_DEBUG_PRINTLN("getPeerSharedSecret: Invalid peer idx: %d", i);
  }
}

static bool isShare(const mesh::Packet *packet) {
  if (packet->hasTransportCodes()) {
    return packet->transport_codes[0] == 0 && packet->transport_codes[1] == 0;  // codes { 0, 0 } means 'send to nowhere'
  }
  return false;
}

void MyMesh::onAdvertRecv(mesh::Packet *packet, const mesh::Identity &id, uint32_t timestamp,
                          const uint8_t *app_data, size_t app_data_len) {
  mesh::Mesh::onAdvertRecv(packet, id, timestamp, app_data, app_data_len); // chain to super impl

  // if this a zero hop advert (and not via 'Share'), add it to neighbours
  if (packet->getPathHashCount() == 0 && !isShare(packet)) {
    AdvertDataParser parser(app_data, app_data_len);
    if (parser.isValid() && parser.getType() == ADV_TYPE_REPEATER) { // just keep neigbouring Repeaters
      putNeighbour(id, timestamp, packet->getSNR());
    }
  }
}

void MyMesh::onPeerDataRecv(mesh::Packet *packet, uint8_t type, int sender_idx, const uint8_t *secret,
                            uint8_t *data, size_t len) {
  int i = matching_peer_indexes[sender_idx];
  if (i < 0 || i >= acl.getNumClients()) { // get from our known_clients table (sender SHOULD already be known in this context)
    MESH_DEBUG_PRINTLN("onPeerDataRecv: invalid peer idx: %d", i);
    return;
  }
  ClientInfo* client = acl.getClientByIdx(i);

  if (type == PAYLOAD_TYPE_REQ) { // request (from a Known admin client!)
    uint32_t timestamp;
    memcpy(&timestamp, data, 4);

    if (timestamp > client->last_timestamp) { // prevent replay attacks
      int reply_len = handleRequest(client, timestamp, &data[4], len - 4);
      if (reply_len == 0) return; // invalid command

      client->last_timestamp = timestamp;
      client->last_activity = getRTCClock()->getCurrentTime();

      if (packet->isRouteFlood()) {
        // let this sender know path TO here, so they can use sendDirect(), and ALSO encode the response
        mesh::Packet *path = createPathReturn(client->id, secret, packet->path, packet->path_len,
                                              PAYLOAD_TYPE_RESPONSE, reply_data, reply_len);
        if (path) sendFloodReply(path, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
      } else {
        mesh::Packet *reply =
            createDatagram(PAYLOAD_TYPE_RESPONSE, client->id, secret, reply_data, reply_len);
        if (reply) {
          if (client->out_path_len != OUT_PATH_UNKNOWN) { // we have an out_path, so send DIRECT
            sendDirect(reply, client->out_path, client->out_path_len, SERVER_RESPONSE_DELAY);
          } else {
            sendFloodReply(reply, SERVER_RESPONSE_DELAY, packet->getPathHashSize());
          }
        }
      }
    } else {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: possible replay attack detected");
    }
  } else if (type == PAYLOAD_TYPE_TXT_MSG && len > 5 && client->isAdmin()) { // a CLI command
    uint32_t sender_timestamp;
    memcpy(&sender_timestamp, data, 4); // timestamp (by sender's RTC clock - which could be wrong)
    uint8_t flags = (data[4] >> 2);        // message attempt number, and other flags

    if (!(flags == TXT_TYPE_PLAIN || flags == TXT_TYPE_CLI_DATA || flags == TXT_TYPE_CLI_COMMAND)) {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: unsupported text type received: flags=%02x", (uint32_t)flags);
    } else if (sender_timestamp >= client->last_timestamp) { // prevent replay attacks
      bool is_retry = (sender_timestamp == client->last_timestamp);
      client->last_timestamp = sender_timestamp;
      client->last_activity = getRTCClock()->getCurrentTime();

      // len can be > original length, but 'text' will be padded with zeroes
      data[len] = 0; // need to make a C string again, with null terminator

      if (flags == TXT_TYPE_PLAIN) { // for legacy CLI, send Acks
        uint32_t ack_hash; // calc truncated hash of the message timestamp + text + sender pub_key, to prove
                           // to sender that we got it
        mesh::Utils::sha256((uint8_t *)&ack_hash, 4, data, 5 + strlen((char *)&data[5]), client->id.pub_key,
                            PUB_KEY_SIZE);

        mesh::Packet *ack = createAck(ack_hash);
        if (ack) {
          if (client->out_path_len == OUT_PATH_UNKNOWN) {
            sendFloodReply(ack, TXT_ACK_DELAY, packet->getPathHashSize());
          } else {
            sendDirect(ack, client->out_path, client->out_path_len, TXT_ACK_DELAY);
          }
        }
      }

      // 5-byte datagram header + 3-byte reflected CLI prefix + 160-byte reply text + NUL
      uint8_t temp[169];
      char *command = (char *)&data[5];
      char *reply = (char *)&temp[5];
      if (is_retry) {
        *reply = 0;
      } else {
        handleCommand(sender_timestamp, command, reply);
      }
      int text_len = strlen(reply);
      if (text_len > 0) {
        uint32_t timestamp = getRTCClock()->getCurrentTimeUnique();
        if (timestamp == sender_timestamp) {
          // WORKAROUND: the two timestamps need to be different, in the CLI view
          timestamp++;
        }
        memcpy(temp, &timestamp, 4);        // mostly an extra blob to help make packet_hash unique
        temp[4] = (TXT_TYPE_CLI_DATA << 2); // NOTE: legacy was: TXT_TYPE_PLAIN

        auto reply = createDatagram(PAYLOAD_TYPE_TXT_MSG, client->id, secret, temp, 5 + text_len);
        if (reply) {
          if (client->out_path_len == OUT_PATH_UNKNOWN) {
            sendFloodReply(reply, CLI_REPLY_DELAY_MILLIS, packet->getPathHashSize());
          } else {
            sendDirect(reply, client->out_path, client->out_path_len, CLI_REPLY_DELAY_MILLIS);
          }
        }
      }
    } else {
      MESH_DEBUG_PRINTLN("onPeerDataRecv: possible replay attack detected");
    }
  }
}

bool MyMesh::onPeerPathRecv(mesh::Packet *packet, int sender_idx, const uint8_t *secret, uint8_t *path,
                            uint8_t path_len, uint8_t extra_type, uint8_t *extra, uint8_t extra_len) {
  // TODO: prevent replay attacks
  int i = matching_peer_indexes[sender_idx];

  if (i >= 0 && i < acl.getNumClients()) { // get from our known_clients table (sender SHOULD already be known in this context)
    MESH_DEBUG_PRINTLN("PATH to client, path_len=%d", (uint32_t)path_len);
    auto client = acl.getClientByIdx(i);

    // store a copy of path, for sendDirect()
    client->out_path_len = mesh::Packet::copyPath(client->out_path, path, path_len);
    client->last_activity = getRTCClock()->getCurrentTime();
  } else {
    MESH_DEBUG_PRINTLN("onPeerPathRecv: invalid peer idx: %d", i);
  }

  // NOTE: no reciprocal path send!!
  return false;
}

#define CTL_TYPE_NODE_DISCOVER_REQ   0x80
#define CTL_TYPE_NODE_DISCOVER_RESP  0x90

void MyMesh::onControlDataRecv(mesh::Packet* packet) {
  uint8_t type = packet->payload[0] & 0xF0;    // just test upper 4 bits
  if (type == CTL_TYPE_NODE_DISCOVER_REQ && packet->payload_len >= 6
      && !_prefs.disable_fwd && discover_limiter.allow(rtc_clock.getCurrentTime())
      && !isHiddenNode()   // this node wishes to NOT be discoverable
  ) {
    int i = 1;
    uint8_t  filter = packet->payload[i++];
    uint32_t tag;
    memcpy(&tag, &packet->payload[i], 4); i += 4;
    uint32_t since;
    if (packet->payload_len >= i+4) {   // optional since field
      memcpy(&since, &packet->payload[i], 4); i += 4;
    } else {
      since = 0;
    }

    if ((filter & (1 << ADV_TYPE_REPEATER)) != 0 && _prefs.discovery_mod_timestamp >= since) {
      bool prefix_only = packet->payload[0] & 1;
      uint8_t data[6 + PUB_KEY_SIZE];
      data[0] = CTL_TYPE_NODE_DISCOVER_RESP | ADV_TYPE_REPEATER;   // low 4-bits for node type
      data[1] = packet->_snr;   // let sender know the inbound SNR ( x 4)
      memcpy(&data[2], &tag, 4);     // include tag from request, for client to match to
      memcpy(&data[6], self_id.pub_key, PUB_KEY_SIZE);
      auto resp = createControlData(data, prefix_only ? 6 + 8 : 6 + PUB_KEY_SIZE);
      if (resp) {
        sendZeroHop(resp, getRetransmitDelay(resp)*4);  // apply random delay (widened x4), as multiple nodes can respond to this
      }
    }
  } else if (type == CTL_TYPE_NODE_DISCOVER_RESP && packet->payload_len >= 6) {
    uint8_t node_type = packet->payload[0] & 0x0F;
    if (node_type != ADV_TYPE_REPEATER) {
      return;
    }
    if (packet->payload_len < 6 + PUB_KEY_SIZE) {
      MESH_DEBUG_PRINTLN("onControlDataRecv: DISCOVER_RESP pubkey too short: %d", (uint32_t)packet->payload_len);
      return;
    }

    if (pending_discover_tag == 0 || millisHasNowPassed(pending_discover_until)) {
      pending_discover_tag = 0;
      return;
    }
    uint32_t tag;
    memcpy(&tag, &packet->payload[2], 4);
    if (tag != pending_discover_tag) {
      return;
    }

    mesh::Identity id(&packet->payload[6]);
    if (id.matches(self_id)) {
      return;
    }
    putNeighbour(id, rtc_clock.getCurrentTime(), packet->getSNR());
  }
}

void MyMesh::sendNodeDiscoverReq() {
  uint8_t data[10];
  data[0] = CTL_TYPE_NODE_DISCOVER_REQ; // prefix_only=0
  data[1] = (1 << ADV_TYPE_REPEATER);
  getRNG()->random(&data[2], 4); // tag
  memcpy(&pending_discover_tag, &data[2], 4);
  pending_discover_until = futureMillis(60000);
  uint32_t since = 0;
  memcpy(&data[6], &since, 4);

  auto pkt = createControlData(data, sizeof(data));
  if (pkt) {
    sendZeroHop(pkt);
  }
}

MyMesh::MyMesh(mesh::MainBoard &board, mesh::Radio &radio, mesh::MillisecondClock &ms, mesh::RNG &rng,
               mesh::RTCClock &rtc, mesh::MeshTables &tables)
    : mesh::Mesh(radio, ms, rng, rtc, *new StaticPoolPacketManager(32), tables),
      _cli(board, rtc, sensors, region_map, acl, &_prefs, this),
      region_map(key_store), temp_map(key_store),
      discover_limiter(4, 120),  // max 4 every 2 minutes
      anon_limiter(4, 180),  // max 4 every 3 minutes
      telemetry(MAX_PACKET_PAYLOAD - 4)
#if defined(WITH_RS232_BRIDGE)
      , bridge(&_prefs, WITH_RS232_BRIDGE, _mgr, &rtc)
#endif
#if defined(WITH_ESPNOW_BRIDGE)
      , bridge(&_prefs, _mgr, &rtc)
#endif
{
  last_millis = 0;
  uptime_millis = 0;
  next_local_advert = next_flood_advert = 0;
  dirty_contacts_expiry = 0;
  last_read_time = 0;
  set_radio_at = revert_radio_at = 0;
  _logging = false;
  region_load_active = false;
  recv_pkt_region = NULL;

#if MAX_NEIGHBOURS
  memset((void*) neighbours, 0, sizeof(neighbours));
#endif

  // defaults
  _prefs.airtime_factor = 1.0;
  _prefs.rx_delay_base = 0.0f;   // turn off by default, was 10.0;
  _prefs.tx_delay_factor = 0.5f; // was 0.25f
  _prefs.direct_tx_delay_factor = 0.3f; // was 0.2
  StrHelper::strncpy(_prefs.node_name, ADVERT_NAME, sizeof(_prefs.node_name));
  _prefs.node_lat = ADVERT_LAT;
  _prefs.node_lon = ADVERT_LON;
  StrHelper::strncpy(_prefs.password, ADMIN_PASSWORD, sizeof(_prefs.password));
  _prefs.freq = LORA_FREQ;
  _prefs.sf = LORA_SF;
  _prefs.bw = LORA_BW;
  _prefs.cr = LORA_CR;
  _prefs.tx_power_dbm = LORA_TX_POWER;
  _prefs.advert_interval = 1;        // default to 2 minutes for NEW installs
  _prefs.flood_advert_interval = 47; // 47 hours
  _prefs.flood_max = 64;
  _prefs.flood_max_unscoped = 64;
  _prefs.flood_max_advert = 8;
  _prefs.interference_threshold = 0; // disabled
  _prefs.cad_enabled = 0;            // hardware CAD before TX (off by default; 'set cad on')
  _prefs.loop_detect = LOOP_DETECT_MINIMAL;

  // bridge defaults
  _prefs.bridge_enabled = 1;    // enabled
  _prefs.bridge_delay   = 500;  // milliseconds
  _prefs.bridge_pkt_src = 0;    // logTx
  _prefs.bridge_baud = 115200;  // baud rate
  _prefs.bridge_channel = 1;    // channel 1

  StrHelper::strncpy(_prefs.bridge_secret, "LVSITANOS", sizeof(_prefs.bridge_secret));

  // GPS defaults
  _prefs.gps_enabled = 0;
  _prefs.gps_interval = 0;
  _prefs.advert_loc_policy = ADVERT_LOC_PREFS;

  _prefs.adc_multiplier = 0.0f; // 0.0f means use default board multiplier

#if defined(USE_SX1262) || defined(USE_SX1268)
#ifdef SX126X_RX_BOOSTED_GAIN
  _prefs.rx_boosted_gain = SX126X_RX_BOOSTED_GAIN;
#else
  _prefs.rx_boosted_gain = 1; // enabled by default;
#endif
#endif
  _prefs.radio_fem_rxgain = 1;
  _prefs.radio_fem_txgain = 0;

  pending_discover_tag = 0;
  pending_discover_until = 0;

  memset(default_scope.key, 0, sizeof(default_scope.key));
}

void MyMesh::begin(FILESYSTEM *fs) {
  mesh::Mesh::begin();
  _fs = fs;
  // load persisted prefs
  _cli.loadPrefs(_fs);
  acl.load(_fs, self_id);
  // TODO: key_store.begin();
  region_map.load(_fs);
#if defined(GEOFENCE_WIFI)
  geoBegin();
#endif

  // establish default-scope
  {
    RegionEntry* r = region_map.getDefaultRegion();
    if (r) {
      region_map.getTransportKeysFor(*r, &default_scope, 1);
    } else {
#ifdef DEFAULT_FLOOD_SCOPE_NAME
      r = region_map.findByName(DEFAULT_FLOOD_SCOPE_NAME);
      if (r == NULL) {
        r = region_map.putRegion(DEFAULT_FLOOD_SCOPE_NAME, 0);  // auto-create the default scope region
        if (r) { r->flags = 0; }   // Allow-flood
      }
      if (r) {
        region_map.setDefaultRegion(r);
        region_map.getTransportKeysFor(*r, &default_scope, 1);
      }
#endif
    }
  }

#if defined(WITH_BRIDGE)
  if (_prefs.bridge_enabled) {
    bridge.begin();
  }
#endif

  radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setTxPower(_prefs.tx_power_dbm);

  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
  MESH_DEBUG_PRINTLN("RX Boosted Gain Mode: %s",
                     radio_driver.getRxBoostedGainMode() ? "Enabled" : "Disabled");

  board.attachDynamicPrefs(_prefs.getCustom());
  sensors.attachDynamicPrefs(_prefs.getCustom());

  updateAdvertTimer();
  updateFloodAdvertTimer();

  board.setAdcMultiplier(_prefs.adc_multiplier);

#if ENV_INCLUDE_GPS == 1
  applyGpsPrefs();
#endif
}

void MyMesh::sendFloodScoped(const TransportKey& scope, mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size) {
  if (scope.isNull()) {
    sendFlood(pkt, delay_millis, path_hash_size);
  } else {
    uint16_t codes[2];
    codes[0] = scope.calcTransportCode(pkt);
    codes[1] = 0;  // REVISIT: set to 'home' Region, for sender/return region?
    sendFlood(pkt, codes, delay_millis, path_hash_size);
  }
}

void MyMesh::applyTempRadioParams(float freq, float bw, uint8_t sf, uint8_t cr, int timeout_mins) {
  set_radio_at = futureMillis(2000); // give CLI reply some time to be sent back, before applying temp radio params
  pending_freq = freq;
  pending_bw = bw;
  pending_sf = sf;
  pending_cr = cr;

  revert_radio_at = futureMillis(2000 + timeout_mins * 60 * 1000); // schedule when to revert radio params
}

bool MyMesh::formatFileSystem() {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  return InternalFS.format();
#elif defined(RP2040_PLATFORM)
  return LittleFS.format();
#elif defined(ESP32)
  return SPIFFS.format();
#else
#error "need to implement file system erase"
  return false;
#endif
}

void MyMesh::sendSelfAdvertisement(int delay_millis, bool flood) {
  mesh::Packet *pkt = createSelfAdvert();
  if (pkt) {
    if (flood) {
      sendFloodScoped(default_scope, pkt, delay_millis, _prefs.path_hash_mode + 1);
    } else {
      sendZeroHop(pkt, delay_millis);
    }
  } else {
    MESH_DEBUG_PRINTLN("ERROR: unable to create advertisement packet!");
  }
}

void MyMesh::updateAdvertTimer() {
  if (_prefs.advert_interval > 0) { // schedule local advert timer
    next_local_advert = futureMillis(((uint32_t)_prefs.advert_interval) * 2 * 60 * 1000);
  } else {
    next_local_advert = 0; // stop the timer
  }
}

void MyMesh::updateFloodAdvertTimer() {
  if (_prefs.flood_advert_interval > 0) { // schedule flood advert timer
    next_flood_advert = futureMillis(((uint32_t)_prefs.flood_advert_interval) * 60 * 60 * 1000);
  } else {
    next_flood_advert = 0; // stop the timer
  }
}

void MyMesh::dumpLogFile() {
#if defined(RP2040_PLATFORM)
  File f = _fs->open(PACKET_LOG_FILE, "r");
#else
  File f = _fs->open(PACKET_LOG_FILE);
#endif
  if (f) {
    while (f.available()) {
      int c = f.read();
      if (c < 0) break;
      Serial.print((char)c);
    }
    f.close();
  }
}

void MyMesh::setTxPower(int8_t power_dbm) {
  radio_driver.setTxPower(power_dbm);
}

bool MyMesh::setRxBoostedGain(bool enable) {
  return radio_driver.setRxBoostedGainMode(enable);
}

#if defined(USE_LR2021)
bool MyMesh::configSideDetectors(const uint8_t sideDetSFs[], uint8_t num, float bw) {
  return radio_driver.configSideDetectors(sideDetSFs, num, bw);
}
#endif

void MyMesh::formatNeighborsReply(char *reply) {
  char *dp = reply;

#if MAX_NEIGHBOURS
  // create copy of neighbours list, skipping empty entries so we can sort it separately from main list
  int16_t neighbours_count = 0;
  NeighbourInfo* sorted_neighbours[MAX_NEIGHBOURS];
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    auto neighbour = &neighbours[i];
    if (neighbour->heard_timestamp > 0) {
      sorted_neighbours[neighbours_count] = neighbour;
      neighbours_count++;
    }
  }

  // sort neighbours newest to oldest
  std::sort(sorted_neighbours, sorted_neighbours + neighbours_count, [](const NeighbourInfo* a, const NeighbourInfo* b) {
    return a->heard_timestamp > b->heard_timestamp; // desc
  });

  for (int i = 0; i < neighbours_count && dp - reply < 134; i++) {
    NeighbourInfo *neighbour = sorted_neighbours[i];

    // add new line if not first item
    if (i > 0) *dp++ = '\n';

    char hex[10];
    // get 4 bytes of neighbour id as hex
    mesh::Utils::toHex(hex, neighbour->id.pub_key, 4);

    // add next neighbour
    uint32_t secs_ago = getRTCClock()->getCurrentTime() - neighbour->heard_timestamp;
    sprintf(dp, "%s:%lu:%d", hex, (unsigned long)secs_ago, neighbour->snr);
    while (*dp)
      dp++; // find end of string
  }
#endif
  if (dp == reply) { // no neighbours, need empty response
    strcpy(dp, "-none-");
    dp += 6;
  }
  *dp = 0; // null terminator
}

void MyMesh::removeNeighbor(const uint8_t *pubkey, int key_len) {
#if MAX_NEIGHBOURS
  for (int i = 0; i < MAX_NEIGHBOURS; i++) {
    NeighbourInfo *neighbour = &neighbours[i];
    if (memcmp(neighbour->id.pub_key, pubkey, key_len) == 0) {
      neighbours[i] = NeighbourInfo(); // clear neighbour entry
    }
  }
#endif
}

void MyMesh::startRegionsLoad() {
  temp_map.resetFrom(region_map);   // rebuild regions in a temp instance
  memset(load_stack, 0, sizeof(load_stack));
  load_stack[0] = &temp_map.getWildcard();
  region_load_active = true;
}

bool MyMesh::saveRegions() {
  return region_map.save(_fs);
}

void MyMesh::onDefaultRegionChanged(const RegionEntry* r) {
  if (r) {
    region_map.getTransportKeysFor(*r, &default_scope, 1);
  } else {
    memset(default_scope.key, 0, sizeof(default_scope.key));
  }
}

void MyMesh::formatStatsReply(char *reply) {
  StatsFormatHelper::formatCoreStats(reply, board, *_ms, _err_flags, _mgr);
}

void MyMesh::formatRadioStatsReply(char *reply) {
  StatsFormatHelper::formatRadioStats(reply, _radio, radio_driver, getTotalAirTime(), getReceiveAirTime());
}

void MyMesh::formatPacketStatsReply(char *reply) {
  StatsFormatHelper::formatPacketStats(reply, radio_driver, getNumSentFlood(), getNumSentDirect(),
                                       getNumRecvFlood(), getNumRecvDirect());
}

void MyMesh::saveIdentity(const mesh::LocalIdentity &new_id) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  IdentityStore store(*_fs, "");
#elif defined(ESP32)
  IdentityStore store(*_fs, "/identity");
#elif defined(RP2040_PLATFORM)
  IdentityStore store(*_fs, "/identity");
#else
#error "need to define saveIdentity()"
#endif
  store.save("_main", new_id);
}

void MyMesh::clearStats() {
  radio_driver.resetStats();
  resetStats();
  ((SimpleMeshTables *)getTables())->resetStats();
}

#if defined(USE_LR1110)
// "wifi scan [ms_per_channel] [type b|g|*] [mode 1|2|4|5]": passive scan of 2.4 GHz channels 1-11
// with the LR1110, listening ms_per_channel on each (beacons come every ~102 ms). Types (Semtech
// lr11xx_wifi_types.h): b = 802.11b, g = 802.11g and n (mixed mode) together, * = b then g/n.
// Modes: 1 beacons, 2 beacons and some packets, 4 full beacon (802.11b only), 5 up to the SSID
// (LR1110 firmware 0x0306+), which names the networks. Over USB every result is printed; the
// reply lists the strongest (MAC, RSSI, channel) as far as 160 characters allow.
static CustomLR1110::WifiResult wifi_results[RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS];   // static: ~1.4 KB

// One Wi-Fi scan of channels 1-11, then LoRa put back as begin() does (the scan changes the
// packet type), and back to sleep if the geofence has the radio asleep. fw_*: the LR1110 Wi-Fi
// firmware, read while the radio is awake. Returns as CustomLR1110Wrapper::wifiScan().
int MyMesh::wifiScanRestore(char type, uint8_t mode, uint16_t ms, CustomLR1110::WifiResult* out, int max,
                            uint8_t* fw_major, uint8_t* fw_minor) {
  const uint16_t CHANNELS_1_TO_11 = 0x07FF;
  int n = radio_driver.wifiScan(type, mode, CHANNELS_1_TO_11, ms, out, max);
  if (n == CustomLR1110Wrapper::WIFI_SCAN_BUSY) return n;
  radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
  radio_driver.setTxPower(_prefs.tx_power_dbm);
  radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
  if (fw_major && fw_minor && !radio_driver.getWifiFirmware(*fw_major, *fw_minor)) *fw_major = *fw_minor = 0;
#if defined(GEOFENCE_WIFI)
  if (_geo_asleep) radio_driver.sleepRadio();
#endif
  return n;
}

void MyMesh::handleWifiScan(uint32_t sender_timestamp, const char* args, char* reply) {
  unsigned long ms = 120;
  char* end;
  while (*args == ' ') args++;
  if (*args >= '0' && *args <= '9') {
    ms = strtoul(args, &end, 10);
    args = end;
  }
  char type = '*';
  unsigned long mode = 5;
  while (*args == ' ') args++;
  if (*args == 'b' || *args == 'g' || *args == 'n' || *args == '*') {
    type = *args++;
    while (*args == ' ') args++;
    if (*args >= '0' && *args <= '9') {
      mode = strtoul(args, &end, 10);
      args = end;
    }
  }
  while (*args == ' ') args++;
  // one pass blocks the loop for 11 x ms: keep it under ~2.3 s, past which USB output was lost
  if (*args != 0 || ms < 20 || ms > 190 || mode < 1 || mode > 5 || mode == 3) {
    strcpy(reply, "Err - wifi scan [ms 20-190] [b|g|*] [mode 1|2|4|5]");
    return;
  }

  const unsigned long started = millis();
  CustomLR1110::WifiResult* results = wifi_results;
  uint8_t fw_major = 0, fw_minor = 0;
  int n = wifiScanRestore(type, (uint8_t)mode, (uint16_t)ms, results, RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS,
                          &fw_major, &fw_minor);
  const unsigned long took = millis() - started;
  if (n == CustomLR1110Wrapper::WIFI_SCAN_BUSY) {
    strcpy(reply, "Err - radio busy, try again");
    return;
  }
  if (n < 0) {
    sprintf(reply, "Err - scan failed (%d) wifi fw %u.%u", n, fw_major, fw_minor);
    return;
  }

  // unique access points, strongest first
  struct Ap { uint8_t mac[6]; int8_t rssi; uint8_t ch; };
  Ap aps[RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS];
  int num_aps = 0;
  for (int i = 0; i < n; i++) {
    const CustomLR1110::WifiResult& r = results[i];
    const int ch = r.channel;
    if (sender_timestamp == 0) {   // local USB: everything
      Serial.printf("wifi %02X:%02X:%02X:%02X:%02X:%02X %4d dBm%s ch%-2d %c '%s'\n",
                    r.mac[0], r.mac[1], r.mac[2], r.mac[3], r.mac[4], r.mac[5], (int)r.rssi,
                    r.rssi_valid ? "" : "?", ch, r.type, r.ssid);
    }
    int j = 0;
    while (j < num_aps && memcmp(aps[j].mac, r.mac, 6) != 0) j++;
    if (j == num_aps) {
      memcpy(aps[num_aps].mac, r.mac, 6);
      aps[num_aps].rssi = (int8_t)r.rssi;
      aps[num_aps].ch = (uint8_t)ch;
      num_aps++;
    } else if ((int8_t)r.rssi > aps[j].rssi) {
      aps[j].rssi = (int8_t)r.rssi;
    }
  }
  for (int i = 1; i < num_aps; i++) {   // insertion sort by RSSI, strongest first
    Ap a = aps[i];
    int j = i - 1;
    while (j >= 0 && aps[j].rssi < a.rssi) { aps[j + 1] = aps[j]; j--; }
    aps[j + 1] = a;
  }

  int len = snprintf(reply, 160, "fw%u.%u pt%u/%d %d/%d %lums", fw_major, fw_minor,
                     radio_driver._wifi_pkt_type, radio_driver._wifi_restore_err, num_aps, n, took);
  for (int i = 0; i < num_aps; i++) {
    char item[24];
    int il = snprintf(item, sizeof(item), " %02X%02X%02X%02X%02X%02X %d c%u",
                      aps[i].mac[0], aps[i].mac[1], aps[i].mac[2], aps[i].mac[3], aps[i].mac[4],
                      aps[i].mac[5], aps[i].rssi, aps[i].ch);
    if (len + il >= 160) break;
    memcpy(reply + len, item, il + 1);
    len += il;
  }
}
#endif

void MyMesh::handleCommand(uint32_t sender_timestamp, char *command, char *reply) {
  if (region_load_active) {
    if (StrHelper::isBlank(command)) {  // empty/blank line, signal to terminate 'load' operation
      region_map = temp_map;  // copy over the temp instance as new current map
      region_load_active = false;

      sprintf(reply, "OK - loaded %d regions", region_map.getCount());
    } else {
      char *np = command;
      while (*np == ' ') np++;   // skip indent
      int indent = np - command;

      char *ep = np;
      while (RegionMap::is_name_char(*ep)) ep++;
      if (*ep) { *ep++ = 0; }  // set null terminator for end of name

      while (*ep && *ep != 'F') ep++;  // look for (optional) flags

      if (indent > 0 && indent < 8 && strlen(np) > 0) {
        auto parent = load_stack[indent - 1];
        if (parent) {
          auto old = region_map.findByName(np);
          auto nw = temp_map.putRegion(np, parent->id, old ? old->id : 0);  // carry-over the current ID (if name already exists)
          if (nw) {
            nw->flags = old ? old->flags : (*ep == 'F' ? 0 : REGION_DENY_FLOOD);   // carry-over flags from curr

            load_stack[indent] = nw;  // keep pointers to parent regions, to resolve parent_id's
          }
        }
      }
      reply[0] = 0;
    }
    return;
  }

  while (*command == ' ') command++; // skip leading spaces

  if (strlen(command) > 4 && command[2] == '|') { // optional prefix (for companion radio CLI)
    memcpy(reply, command, 3);                    // reflect the prefix back
    reply += 3;
    command += 3;
  }

  bool retry_changed;
  if (handleFloodRetryCommand(command, _prefs.flood_retry.count, _prefs.flood_retry.wait_ms, getFloodRetry(), reply, retry_changed)) {
    if (retry_changed) savePrefs();
    return;
  }

  // handle ACL related commands
  if (memcmp(command, "setperm ", 8) == 0) {   // format:  setperm {pubkey-hex} {permissions-int8}
    char* hex = &command[8];
    char* sp = strchr(hex, ' ');   // look for separator char
    if (sp == NULL) {
      strcpy(reply, "Err - bad params");
    } else {
      *sp++ = 0;   // replace space with null terminator

      uint8_t pubkey[PUB_KEY_SIZE];
      int hex_len = min(sp - hex, PUB_KEY_SIZE*2);
      if (mesh::Utils::fromHex(pubkey, hex_len / 2, hex)) {
        uint8_t perms = atoi(sp);
        if (acl.applyPermissions(self_id, pubkey, hex_len / 2, perms)) {
          dirty_contacts_expiry = futureMillis(LAZY_CONTACTS_WRITE_DELAY);   // trigger acl.save()
          strcpy(reply, "OK");
        } else {
          strcpy(reply, "Err - invalid params");
        }
      } else {
        strcpy(reply, "Err - bad pubkey");
      }
    }
  } else if (sender_timestamp == 0 && strcmp(command, "get acl") == 0) {
    Serial.println("ACL:");
    for (int i = 0; i < acl.getNumClients(); i++) {
      auto c = acl.getClientByIdx(i);
      if (c->permissions == 0) continue;  // skip deleted (or guest) entries

      Serial.printf("%02X ", c->permissions);
      mesh::Utils::printHex(Serial, c->id.pub_key, PUB_KEY_SIZE);
      Serial.printf("\n");
    }
    reply[0] = 0;
  } else if (memcmp(command, "discover.neighbors", 18) == 0) {
    const char* sub = command + 18;
    while (*sub == ' ') sub++;
    if (*sub != 0) {
      strcpy(reply, "Err - discover.neighbors has no options");
    } else {
      sendNodeDiscoverReq();
      strcpy(reply, "OK - Discover sent");
    }
#if defined(MOTION_WAKE_QMA6100P)
  } else if (strcmp(command, "motion") == 0) {
    if (!motion_state.ok) {
      sprintf(reply, "Err - accelerometer: %s", motion.probeInfo());
    } else {
      char last[16] = "never";
      if (motion_state.events > 0) snprintf(last, sizeof(last), "%lus ago", (unsigned long)((millis() - motion_state.last_ms) / 1000));
      sprintf(reply, "> addr %02X th %u n %u irq %lu ev %lu last %s st %02X", motion.address(), motion_state.threshold,
              motion_state.samples, (unsigned long)motion_state.irqs, (unsigned long)motion_state.events, last, motion_state.last_st0);
    }
  } else if (strcmp(command, "motion init") == 0) {
    motion_begin();
    sprintf(reply, "%s - %s", motion_state.ok ? "OK" : "Err", motion.probeInfo());
  } else if (memcmp(command, "motion th ", 10) == 0 || memcmp(command, "motion n ", 9) == 0) {
    const bool is_th = command[7] == 't';
    char* end;
    unsigned long v = strtoul(command + (is_th ? 10 : 9), &end, 10);
    if (*end != 0 || (is_th ? (v < 1 || v > 255) : (v < 1 || v > 4))) {
      strcpy(reply, is_th ? "Err - motion th 1-255" : "Err - motion n 1-4");
    } else if (!(is_th ? motion.setThreshold((uint8_t)v) : motion.setSamples((uint8_t)v))) {
      strcpy(reply, "Err - accelerometer write failed");
    } else {
      if (is_th) motion_state.threshold = (uint8_t)v; else motion_state.samples = (uint8_t)v;
      strcpy(reply, "OK");
    }
#endif
#if defined(GEOFENCE_WIFI)
  } else if (handleGeoCommand(sender_timestamp, command, reply)) {
    // done
#endif
#if defined(USE_LR1110)
  } else if (memcmp(command, "wifi scan", 9) == 0 && (command[9] == 0 || command[9] == ' ')) {
    handleWifiScan(sender_timestamp, command + 9, reply);
#endif
  } else{
    _cli.handleCommand(sender_timestamp, command, reply);  // common CLI commands
  }
}

void MyMesh::loop() {
#ifdef WITH_BRIDGE
  bridge.loop();
#endif

#if defined(GEOFENCE_WIFI)
  geoLoop();
  if (_geo_asleep) {   // parked at home: no receive, no repeating, no adverts
    uint32_t now = millis();
    uptime_millis += now - last_millis;
    last_millis = now;
    return;
  }
#endif

  mesh::Mesh::loop();

  if (next_flood_advert && millisHasNowPassed(next_flood_advert)) {
    mesh::Packet *pkt = createSelfAdvert();
    uint32_t delay_millis = 0;
    if (pkt) sendFloodScoped(default_scope, pkt, delay_millis, _prefs.path_hash_mode + 1);

    updateFloodAdvertTimer(); // schedule next flood advert
    updateAdvertTimer();      // also schedule local advert (so they don't overlap)
  } else if (next_local_advert && millisHasNowPassed(next_local_advert)) {
    mesh::Packet *pkt = createSelfAdvert();
    if (pkt) sendZeroHop(pkt);

    updateAdvertTimer(); // schedule next local advert
  }

  if (set_radio_at && millisHasNowPassed(set_radio_at)) { // apply pending (temporary) radio params
    set_radio_at = 0;                                     // clear timer
    radio_driver.setParams(pending_freq, pending_bw, pending_sf, pending_cr);
    MESH_DEBUG_PRINTLN("Temp radio params");
  }

  if (revert_radio_at && millisHasNowPassed(revert_radio_at)) { // revert radio params to orig
    revert_radio_at = 0;                                        // clear timer
    radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
    MESH_DEBUG_PRINTLN("Radio params restored");
  }

  uint32_t curr = getRTCClock()->getCurrentTime();
  if (curr >= last_read_time + SENSOR_READ_INTERVAL_SECS) {
    telemetry.reset();
    telemetry.addVoltage(TELEM_CHANNEL_SELF, (float)board.getBattMilliVolts() / 1000.0f);
    // query other sensors -- target specific
    sensors.querySensors(0xFF, telemetry);  // allow all telemetry permissions
  	// This MCU temperature will be overridden by external sensors (if any)
    float temperature = board.getMCUTemperature();
    if (!isnan(temperature)) {   // Supported boards with built-in temperature sensor. ESP32-C3 may return NAN
      telemetry.addTemperature(TELEM_CHANNEL_SELF, temperature);    // Built-in MCU Temperature
    }

    // compare with previous telemetry, check if any deltas are greater than subscriber minimums
    for (int i = 0; i < acl.getNumClients(); i++) {
      auto c = acl.getClientByIdx(i);
      if (c->permissions == 0 || c->extra.sensor.scope_region_id == 0 || c->extra.sensor.min_deltas_len == 0) continue;  // skip deleted entries, or Not subscribed to deltas
      RegionEntry* r = region_map.findById(c->extra.sensor.scope_region_id);
      if (r == NULL) continue;   // unknown region scope
      if (curr > c->extra.sensor.expiry_timestamp) continue;  // subscription now expired
      if (telemHasChanged(c)) {
        TransportKey scope;
        if (region_map.getTransportKeysFor(*r, &scope, 1) > 0) {
          uint8_t tlen = telemetry.getSize();
          memcpy(reply_data, &c->extra.sensor.push_tag, 4);
          uint32_t timestamp = getRTCClock()->getCurrentTimeUnique();
          memcpy(&reply_data[4], &timestamp, 4);
          memcpy(&reply_data[8], telemetry.getBuffer(), tlen);

          mesh::Packet* reply = createDatagram(PAYLOAD_TYPE_RESPONSE, c->id, c->shared_secret, reply_data, 8 + tlen);
          if (reply) {
            if (c->out_path_len != OUT_PATH_UNKNOWN) {  // we have an out_path, so send DIRECT
              sendDirect(reply, c->out_path, c->out_path_len, 0);
            } else {
              sendFloodScoped(scope, reply, 0, _prefs.path_hash_mode + 1);
            }
          }
        }
      }
    }

    last_read_time = curr;
  }

  // is pending dirty contacts write needed?
  if (dirty_contacts_expiry && millisHasNowPassed(dirty_contacts_expiry)) {
    acl.save(_fs);
    dirty_contacts_expiry = 0;
  }

  // update uptime
  uint32_t now = millis();
  uptime_millis += now - last_millis;
  last_millis = now;
}

// To check if there is pending work
bool MyMesh::hasPendingWork() const {
#if defined(WITH_BRIDGE)
  if (bridge.isRunning()) return true;  // bridge needs WiFi radio, can't sleep
#endif
  return _mgr->getOutboundTotal() > 0;
}

#if defined(GEOFENCE_WIFI)
#define GEOFENCE_FILE "/geofence"

void MyMesh::geoBegin() {
  _geo_prefs.setDefaults();
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  File f = _fs->open(GEOFENCE_FILE, FILE_O_READ);
#else
  File f = _fs->open(GEOFENCE_FILE, "r");
#endif
  if (f) {
    GeoFencePrefs p;
    if (f.read((uint8_t *)&p, sizeof(p)) == (int)sizeof(p) && p.isValid()) _geo_prefs = p;
    f.close();
  }
  geoRestart();
}

void MyMesh::geoSave() {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  _fs->remove(GEOFENCE_FILE);
  File f = _fs->open(GEOFENCE_FILE, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  File f = _fs->open(GEOFENCE_FILE, "w");
#else
  File f = _fs->open(GEOFENCE_FILE, "w", true);
#endif
  if (f) {
    f.write((const uint8_t *)&_geo_prefs, sizeof(_geo_prefs));
    f.close();
  }
}

// After boot or "geo on/off": the accelerometer is powered only while the geofence is on
void MyMesh::geoRestart() {
  const uint32_t now = millis();
  if (_geo_prefs.enabled && _geo_prefs.num_home > 0) {
    if (!motion_state.ok) motion_begin();
  } else {
    motion_end();
  }
  _geo_motion_seen = motion_events();
  _geo_btn_seen = button_presses();
  _geo.begin(now);
  _geo_sleep_wait = false;
  if (_geo_asleep) geoSetAsleep(false);
  geoLog('S');
}

void MyMesh::geoLog(char what, int8_t rssi, int16_t err) {
  GeoLogEntry e;
  e.err = err;
  e.up_s = millis() / 1000;
  e.what = what;
  e.state = _geo.state();
  e.rssi = rssi;
  e.mv = board.getBattMilliVolts();
  _geo_log.add(e);
}

// b pass first: every home AP seen on the bench beacons at 802.11b rates (120 ms per channel
// saw home 25/25); a g/n pass only when b did not see home.
GeoFence::ScanResult MyMesh::geoScan(int8_t& best_rssi) {
  best_rssi = 0;
  const char types[2] = { 'b', 'g' };
  for (char type : types) {
    int n = wifiScanRestore(type, 1, 120, wifi_results, RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS);
    if (n < 0) {   // busy (a packet in flight) or a radio error: retried
      _geo_last_err = (int16_t)n;
      return GeoFence::FAILED;
    }
    bool saw = false;
    for (int i = 0; i < n; i++) {
      if (_geo.isHome(wifi_results[i].mac)) {
        if (!saw || wifi_results[i].rssi > best_rssi) best_rssi = wifi_results[i].rssi;
        saw = true;
      }
    }
    if (saw) return GeoFence::SAW_HOME;
  }
  return GeoFence::MISSED;
}

void MyMesh::geoSetAsleep(bool asleep) {
  if (asleep) {
    radio_driver.sleepRadio();
    const char* gps = sensors.getSettingByKey("gps");
    _geo_gps_was_on = gps && strcmp(gps, "1") == 0;
    if (_geo_gps_was_on) sensors.setSettingValue("gps", "0");
    // the GPS driver powers the GPS off but leaves its UART receiving (opened at boot): close it.
    // Turning the GPS on opens it again.
    gps_serial_end();
    const uint32_t now = millis();
    _geo_resleep_at = now + 5 * 60000UL;
    _geo_battery_at = now + 30 * 60000UL;
  } else {
    radio_driver.wakeRadio();
    radio_driver.setParams(_prefs.freq, _prefs.bw, _prefs.sf, _prefs.cr);
    radio_driver.setTxPower(_prefs.tx_power_dbm);
    radio_driver.setRxBoostedGainMode(_prefs.rx_boosted_gain);
    if (_geo_gps_was_on) sensors.setSettingValue("gps", "1");
    _geo_gps_was_on = false;
  }
  _geo_asleep = asleep;
  _geo_sleep_wait = false;
}

void MyMesh::geoLoop() {
  const uint32_t now = millis();
  const GeoFence::State before = _geo.state();

  const uint32_t motion = motion_events();
  if (motion != _geo_motion_seen) {
    _geo_motion_seen = motion;
    if (before != GeoFence::OFF) _geo.onMotion(now);
  }
  const uint32_t presses = button_presses();
  if (presses != _geo_btn_seen) {
    _geo_btn_seen = presses;
    if (before != GeoFence::OFF) {
      _geo.onButton(now);
      geoLog('B');
    }
  }
  if (_geo.scanDue(now)) {
    int8_t best;
    GeoFence::ScanResult r = geoScan(best);
    _geo.onScan(millis(), r);
    geoLog(r == GeoFence::SAW_HOME ? 'H' : r == GeoFence::MISSED ? 'M' : 'F', best,
           r == GeoFence::FAILED ? _geo_last_err : 0);
  }
  if (_geo.state() != before) geoLog('S');

  if (_geo_asleep && (int32_t)(now - _geo_resleep_at) >= 0) {
    radio_driver.sleepRadio();   // harmless if asleep; back to sleep if a command woke it to standby
    _geo_resleep_at = now + 5 * 60000UL;
  }
  if (_geo_asleep && (int32_t)(now - _geo_battery_at) >= 0) {
    geoLog('P');
    _geo_battery_at = now + 30 * 60000UL;
  }

  if (!_geo.radioOn(now)) {
    if (!_geo_asleep) {
      if (!_geo_sleep_wait) {
        _geo_sleep_wait = true;
        _geo_sleep_since = now;
      }
      // let queued packets go out first (30 s at most), and never stop a send halfway
      if (radio_driver.isInRecvMode() && (!hasPendingWork() || now - _geo_sleep_since > 30000)) {
        geoSetAsleep(true);
      }
    }
  } else {
    _geo_sleep_wait = false;
    if (_geo_asleep) geoSetAsleep(false);
  }
}

// geo commands that need the radio or the board; the rest are in helpers/GeoFence.h.
//   geo home set [min dBm]   save the APs heard now (park at home first), default -75
//   geo home add [min dBm]   the same, keeping the APs already saved
//   geo scan                 one geofence scan now: does it see home?
//   geo log                  recent scans and state changes (USB prints all)
bool MyMesh::handleGeoCommand(uint32_t sender_timestamp, const char* command, char* reply) {
  const uint32_t now = millis();
  const bool home_add = strncmp(command, "geo home add", 12) == 0;
  if ((home_add || strncmp(command, "geo home set", 12) == 0) && (command[12] == 0 || command[12] == ' ')) {
    long min_rssi = -75;   // the 3 home APs: -47..-74 from the bench; neighbours -80 and weaker
    if (command[12] == ' ') {
      char* end;
      min_rssi = strtol(command + 13, &end, 10);
      if (*end != 0 || min_rssi < -100 || min_rssi > -20) {
        strcpy(reply, "Err - geo home set|add [min dBm -100..-20]");
        return true;
      }
    }
    // one scan does not hear every AP (bench: 1 of 3 sometimes): merge three, best RSSI per BSSID
    const int SCANS = 3, MAX_APS = 64;
    GeoScanAp aps[MAX_APS];
    int n = 0;
    for (int s = 0; s < SCANS; s++) {
      int got = wifiScanRestore(s == SCANS - 1 ? '*' : 'b', 1, 120, wifi_results, RADIOLIB_LR11X0_WIFI_MAX_NUM_RESULTS);
      if (got < 0) {
        sprintf(reply, "Err - scan %s, try again", got == CustomLR1110Wrapper::WIFI_SCAN_BUSY ? "busy" : "failed");
        return true;
      }
      for (int i = 0; i < got; i++) {
        int j = 0;
        while (j < n && memcmp(aps[j].mac, wifi_results[i].mac, 6) != 0) j++;
        if (j == n) {
          if (n == MAX_APS) continue;
          memcpy(aps[n].mac, wifi_results[i].mac, 6);
          aps[n++].rssi = wifi_results[i].rssi;
        } else if (wifi_results[i].rssi > aps[j].rssi) {
          aps[j].rssi = wifi_results[i].rssi;
        }
      }
    }
    int saved = _geo.setHome(aps, n, (int8_t)min_rssi, home_add);
    if (saved == 0) {
      sprintf(reply, "Err - no %sAP at %ld dBm or better (%d heard)", home_add ? "new " : "", min_rssi, n);
      return true;
    }
    geoSave();
    if (_geo_prefs.enabled) geoRestart();
    int len = snprintf(reply, 160, "OK - %d home APs:", saved);
    for (int i = 0; i < _geo_prefs.num_home && len < 140; i++) {
      const uint8_t* m = _geo_prefs.home[i];
      len += snprintf(reply + len, 160 - len, " ??%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4]);
    }
    return true;
  }
  if (strcmp(command, "geo scan") == 0) {
    if (_geo_prefs.num_home == 0) {
      strcpy(reply, "Err - no home APs: geo home set");
      return true;
    }
    const uint32_t t0 = millis();
    int8_t best;
    GeoFence::ScanResult r = geoScan(best);
    if (r == GeoFence::SAW_HOME) sprintf(reply, "> home seen, best %d dBm, %lu ms", best, (unsigned long)(millis() - t0));
    else if (r == GeoFence::MISSED) sprintf(reply, "> home not seen, %lu ms", (unsigned long)(millis() - t0));
    else strcpy(reply, "Err - scan busy or failed, try again");
    return true;
  }
  if (strcmp(command, "geo log") == 0) {
    int len = snprintf(reply, 160, "> %lu:", (unsigned long)_geo_log.total());
    for (int i = _geo_log.count() - 1; i >= 0; i--) {   // oldest first
      const GeoLogEntry& e = _geo_log.get(i);
      if (sender_timestamp == 0) {
        Serial.printf("geo %6lus %c %-7s %4d dBm %4u mV", (unsigned long)e.up_s, e.what,
                      GeoFence::stateName((GeoFence::State)e.state), (int)e.rssi, (unsigned)e.mv);
        if (e.what == 'F') Serial.printf(" err %d", (int)e.err);
        Serial.println();
      }
    }
    for (int i = 0; i < _geo_log.count() && len < 140; i++) {   // reply: newest first, as many as fit
      const GeoLogEntry& e = _geo_log.get(i);
      len += snprintf(reply + len, 160 - len, " %lu%c%d/%u", (unsigned long)e.up_s, e.what,
                      (int)(e.what == 'F' ? e.err : e.rssi), (unsigned)e.mv);
    }
    return true;
  }

  bool changed, restart;
  const GeoFence::State before = _geo.state();
  if (!::handleGeoCommand(_geo, _geo_prefs, command, now, reply, changed, restart)) return false;
  if (changed) geoSave();
  if (restart) geoRestart();
  else if (_geo.state() != before) geoLog('S');   // geo force
  if (strcmp(command, "geo") == 0 && _geo_prefs.enabled && !motion_state.ok) {
    int len = strlen(reply);
    snprintf(reply + len, 160 - len, ", no accelerometer");
  }
  return true;
}
#endif
