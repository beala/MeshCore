#include "Mesh.h"
//#include <Arduino.h>

namespace mesh {

void Mesh::begin() {
  Dispatcher::begin();
}

bool Mesh::cancelQueued(const uint8_t* hash) {
  uint8_t h[MAX_HASH_SIZE];
  for (int i = 0; i < _mgr->getOutboundTotal(); i++) {
    Packet* q = _mgr->getOutboundByIdx(i);
    q->calculatePacketHash(h);
    if (memcmp(h, hash, MAX_HASH_SIZE) == 0) {
      releasePacket(_mgr->removeOutboundByIdx(i));
      return true;
    }
  }
  return false;
}

Packet* Mesh::createSelfDatagram(uint8_t type, const uint8_t* data, size_t len) {
  uint8_t secret[PUB_KEY_SIZE];
  self_id.calcSharedSecret(secret, self_id);
  return createDatagram(type, self_id, secret, data, len);
}

void Mesh::loop() {
  Dispatcher::loop();

  const uint8_t* raw;   // no copy here: this frame is live under every receive path
  uint8_t len;
  int idx = _flood_retry.nextDue(_ms->getMillis(), raw, len);
  if (idx >= 0) {
    Packet* pkt = obtainNewPacket();
    if (pkt == NULL || !pkt->readFrom(raw, len) || !allowFloodRetryNow(pkt)) {
      if (pkt) releasePacket(pkt);
      _flood_retry.skip(idx);
    } else {
      MESH_DEBUG_PRINTLN("%s Mesh::loop(): no echo heard, resending flood packet", getLogDateTime());
      // same bytes and path as before, so nodes that have it drop it. Direct packets go first, as
      // when they are forwarded; flood packets further from the source get lower priority.
      uint8_t hops = pkt->getPathHashCount();
      sendPacket(pkt, pkt->isRouteDirect() ? 0 : (hops ? hops : 1));
    }
  }
}

uint32_t Mesh::getFloodRetryWait(const Packet* packet) {
  // neighbours wait up to a few airtimes before they forward (tx_delay_factor), then transmit
  return 1000 + 8 * _radio->getEstAirtimeFor(packet->getRawLength() + packet->getPathHashSize());
}

void Mesh::onPacketSent(Packet* packet) {
  if (_flood_retry.onSent(packet, _ms->getMillis())) return;   // one of our resends
  if (!FloodRetry::canEcho(packet)) return;

  uint8_t n = getFloodRetries(packet);
  if (n > 0) _flood_retry.track(packet, _ms->getMillis(), n, getFloodRetryWait(packet));
}

void Mesh::onPacketHeard(Packet* packet) {
  if (_flood_retry.onHeard(packet) == FloodRetry::ECHO_CANCEL_RESEND) {
    // the echo arrived after all, so take our queued resend (same hash) off the send queue
    uint8_t heard[MAX_HASH_SIZE], h[MAX_HASH_SIZE];
    packet->calculatePacketHash(heard);
    for (int i = 0; i < _mgr->getOutboundTotal(); i++) {
      Packet* q = _mgr->getOutboundByIdx(i);
      q->calculatePacketHash(h);
      if (memcmp(h, heard, MAX_HASH_SIZE) == 0) {
        releasePacket(_mgr->removeOutboundByIdx(i));
        _flood_retry.resendCancelled(heard);
        break;
      }
    }
    // if it wasn't queued, it's transmitting now, and onSent() closes it
  }
}

int Mesh::encryptPayload(const uint8_t* secret, uint8_t* dest, const uint8_t* data, int data_len, const uint8_t* ctx, int ctx_len) {
  if (getCryptoPolicy(secret) != CRYPTO_POLICY_LEGACY) {
    return CryptoV2::seal(secret, dest, data, data_len, ctx, ctx_len);
  }
  return Utils::encryptThenMAC(secret, dest, data, data_len);
}

// dest must be MAX_PACKET_PAYLOAD bytes. Everything after the plaintext is zeroed, so parsers that
// read a little past the end (as v1's block padding used to allow) see zeroes, never stale stack data.
int Mesh::decryptPayload(const uint8_t* secret, uint8_t* dest, const uint8_t* env, int env_len, const uint8_t* ctx, int ctx_len, bool& was_v2) {
  int len;
  // v1 and v2 are told apart by length: v1 is always a 2-byte MAC plus whole AES blocks
  if (CryptoV2::isLegacyEnvelope(env_len)) {
    was_v2 = false;
    if (getCryptoPolicy(secret) == CRYPTO_POLICY_V2_ONLY) {
      len = 0;   // v1 not accepted for this contact/channel
    } else {
      len = env_len - CIPHER_MAC_SIZE <= MAX_PACKET_PAYLOAD ? Utils::MACThenDecrypt(secret, dest, env, env_len) : 0;
    }
  } else {
    was_v2 = true;
    len = CryptoV2::open(secret, dest, env, env_len, ctx, ctx_len);
  }
  if (len < 0 || len > MAX_PACKET_PAYLOAD) len = 0;
  memset(&dest[len], 0, MAX_PACKET_PAYLOAD - len);
  return len;
}

bool Mesh::toLegacyForm(const uint8_t* raw, int len, uint8_t* out, int& out_len) {
  if (len <= 0 || len > MAX_TRANS_UNIT) return false;
  Packet pkt;
  if (!pkt.readFrom(raw, (uint8_t)len)) return false;

  uint8_t type = pkt.getPayloadType();
  uint8_t data[MAX_PACKET_PAYLOAD];
  int hdr;                      // bytes before the encrypted envelope
  uint8_t ctx[3];
  int ctx_len;
  if (type == PAYLOAD_TYPE_GRP_TXT || type == PAYLOAD_TYPE_GRP_DATA) {
    hdr = PATH_HASH_SIZE;
    ctx[0] = type; ctx[1] = pkt.payload[0]; ctx_len = 2;
  } else if (type == PAYLOAD_TYPE_TXT_MSG || type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE || type == PAYLOAD_TYPE_PATH) {
    hdr = 2 * PATH_HASH_SIZE;
    ctx[0] = type; ctx[1] = pkt.payload[0]; ctx[2] = pkt.payload[1]; ctx_len = 3;
  } else {
    return false;
  }
  int env_len = pkt.payload_len - hdr;
  if (env_len <= 0 || CryptoV2::isLegacyEnvelope(env_len)) return false;   // not v2
  const uint8_t* env = &pkt.payload[hdr];

  uint8_t secret[PUB_KEY_SIZE];
  int plen = 0;
  if (hdr == PATH_HASH_SIZE) {
    GroupChannel channels[4];
    int num = searchChannelsByHash(&pkt.payload[0], channels, 4);
    for (int j = 0; j < num && plen <= 0; j++) {
      plen = CryptoV2::open(channels[j].secret, data, env, env_len, ctx, ctx_len);
      if (plen > 0) memcpy(secret, channels[j].secret, PUB_KEY_SIZE);
    }
  } else {
    // to us: the sender is a contact; from us (our own packet, heard again): the recipient is
    const uint8_t* peer_hash = self_id.isHashMatch(&pkt.payload[0]) ? &pkt.payload[1]
                             : self_id.isHashMatch(&pkt.payload[1]) ? &pkt.payload[0] : NULL;
    if (peer_hash == NULL) return false;
    int num = searchPeersByHash(peer_hash);
    for (int j = 0; j < num && plen <= 0; j++) {
      getPeerSharedSecret(secret, j);
      plen = CryptoV2::open(secret, data, env, env_len, ctx, ctx_len);
    }
  }
  if (plen <= 0) return false;

  if (hdr + CIPHER_MAC_SIZE + ((plen + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE > MAX_PACKET_PAYLOAD) {
    memset(data, 0, sizeof(data));
    return false;
  }
  pkt.payload_len = hdr + Utils::encryptThenMAC(secret, &pkt.payload[hdr], data, plen);
  memset(data, 0, sizeof(data));
  memset(secret, 0, sizeof(secret));
  out_len = pkt.writeTo(out);
  return true;
}

bool Mesh::fitsPayload(const uint8_t* secret, int header_len, int data_len) {
  if (getCryptoPolicy(secret) == CRYPTO_POLICY_LEGACY) return true;   // v1 callers keep their existing checks
  return header_len + data_len + CryptoV2::OVERHEAD_MAX <= MAX_PACKET_PAYLOAD;
}

bool Mesh::allowPacketForward(const mesh::Packet* packet) { 
  return false;  // by default, Transport NOT enabled
}
uint32_t Mesh::getRetransmitDelay(const mesh::Packet* packet) { 
  uint32_t t = (_radio->getEstAirtimeFor(packet->getRawLength()) * 52 / 50) / 2;

  return _rng->nextInt(0, 5)*t;
}
uint32_t Mesh::getDirectRetransmitDelay(const Packet* packet) {
  return 0;  // by default, no delay
}
uint8_t Mesh::getExtraAckTransmitCount() const {
  return 0;
}

uint32_t Mesh::getCADFailRetryDelay() const {
  return _rng->nextInt(1, 4)*120;
}

int Mesh::searchPeersByHash(const uint8_t* hash) {
  return 0;  // not found
}

int Mesh::searchChannelsByHash(const uint8_t* hash, GroupChannel channels[], int max_matches) {
  return 0;  // not found
}

DispatcherAction Mesh::onRecvPacket(Packet* pkt) {
  if (pkt->isRouteDirect() && pkt->getPayloadType() == PAYLOAD_TYPE_TRACE) {
    if (pkt->path_len < MAX_PATH_SIZE && pkt->payload_len >= 9) {
      uint8_t i = 0;
      uint32_t trace_tag;
      memcpy(&trace_tag, &pkt->payload[i], 4); i += 4;
      uint32_t auth_code;
      memcpy(&auth_code, &pkt->payload[i], 4); i += 4;
      uint8_t flags = pkt->payload[i++];
      uint8_t path_sz = flags & 0x03;  // NEW v1.11+: lower 2 bits is path hash size

      uint8_t len = pkt->payload_len - i;
      // path_len*entry_size can exceed 255 (path_len up to 63, entry_size up to 8);
      // a uint8_t offset would wrap and steer the isHashMatch() read to the wrong place.
      uint16_t offset = (uint16_t)pkt->path_len << path_sz;
      uint8_t hash_size = 1 << path_sz;
      if (offset >= len) {   // TRACE has reached end of given path
        onTraceRecv(pkt, trace_tag, auth_code, flags, pkt->path, &pkt->payload[i], len);
      } else if (offset + hash_size <= len && self_id.isHashMatch(&pkt->payload[i + offset], hash_size) && allowPacketForward(pkt) && !_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        // append SNR (Not hash!)
        pkt->path[pkt->path_len++] = (int8_t) (pkt->getSNR()*4);

        uint32_t d = getDirectRetransmitDelay(pkt);
        return ACTION_RETRANSMIT_DELAYED(5, d);  // schedule with priority 5 (for now), maybe make configurable?
      }
    }
    return ACTION_RELEASE;
  }

  if (pkt->isRouteDirect() && pkt->getPayloadType() == PAYLOAD_TYPE_CONTROL &&
      pkt->payload_len > 0 && (pkt->payload[0] & 0x80) != 0) {
    if (pkt->getPathHashCount() == 0) {
      onControlDataRecv(pkt);
    }
    // just zero-hop control packets allowed (for this subset of payloads)
    return ACTION_RELEASE;
  }

  if (pkt->isRouteDirect() && pkt->getPathHashCount() > 0) {
    // check for 'early received' ACK
    if (pkt->getPayloadType() == PAYLOAD_TYPE_ACK) {
      if (pkt->payload_len >= sizeof(uint32_t)) {
        uint32_t ack_crc;
        memcpy(&ack_crc, pkt->payload, sizeof(ack_crc));
        onAckRecv(pkt, ack_crc);
      }
    }

    if (self_id.isHashMatch(pkt->path, pkt->getPathHashSize()) && allowPacketForward(pkt)) {
      uint32_t d = getDirectRetransmitDelay(pkt);
      if (pkt->getPayloadType() == PAYLOAD_TYPE_MULTIPART) {
        return forwardMultipartDirect(pkt, d);
      } else if (pkt->getPayloadType() == PAYLOAD_TYPE_ACK) {
        if (!_tables->wasSeen(pkt)) {  // don't retransmit!
          _tables->markSeen(pkt);
          removeSelfFromPath(pkt);
          routeDirectRecvAcks(pkt, d);
        }
        return ACTION_RELEASE;
      }

      if (!_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        removeSelfFromPath(pkt);

        return ACTION_RETRANSMIT_DELAYED(0, d);  // Routed traffic is HIGHEST priority 
      }
    }
    return ACTION_RELEASE;   // this node is NOT the next hop (OR this packet has already been forwarded), so discard.
  }

  if (pkt->isRouteFlood() && filterRecvFloodPacket(pkt)) return ACTION_RELEASE;

  DispatcherAction action = ACTION_RELEASE;

  switch (pkt->getPayloadType()) {
    case PAYLOAD_TYPE_ACK: {
      if (pkt->payload_len < sizeof(uint32_t)) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): incomplete ACK packet", getLogDateTime());
      } else if (!_tables->wasSeen(pkt)) {
        uint32_t ack_crc;
        memcpy(&ack_crc, pkt->payload, sizeof(ack_crc));
        _tables->markSeen(pkt);
        onAckRecv(pkt, ack_crc);
        action = routeRecvPacket(pkt);
      }
      break;
    }
    case PAYLOAD_TYPE_PATH:
    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_TXT_MSG: {
      if (pkt->payload_len < 2) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): incomplete data packet", getLogDateTime());
        break;
      }

      int i = 0;
      uint8_t dest_hash = pkt->payload[i++];
      uint8_t src_hash = pkt->payload[i++];

      uint8_t* macAndData = &pkt->payload[i];   // MAC + encrypted data 
      if (!_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        // NOTE: this is a 'first packet wins' impl. When receiving from multiple paths, the first to arrive wins.
        //       For flood mode, the path may not be the 'best' in terms of hops.
        // FUTURE: could send back multiple paths, using createPathReturn(), and let sender choose which to use(?)

        if (self_id.isHashMatch(&dest_hash)) {
          // scan contacts DB, for all matching hashes of 'src_hash' (max 4 matches supported ATM)
          int num = searchPeersByHash(&src_hash);
          // for each matching contact, try to decrypt data
          bool found = false;
          for (int j = 0; j < num; j++) {
            uint8_t secret[PUB_KEY_SIZE];
            getPeerSharedSecret(secret, j);

            // decrypt, checking MAC is valid
            uint8_t data[MAX_PACKET_PAYLOAD];
            uint8_t ctx[3] = { pkt->getPayloadType(), dest_hash, src_hash };
            bool was_v2;
            int len = decryptPayload(secret, data, macAndData, pkt->payload_len - i, ctx, sizeof(ctx), was_v2);
            if (len > 0) {  // success!
              if (was_v2) onPeerCryptoV2Recv(j, secret);
              if (pkt->getPayloadType() == PAYLOAD_TYPE_PATH) {
                if (len < 2 || !Packet::isValidPathLen(data[0])) {
                  MESH_DEBUG_PRINTLN("%s PAYLOAD_TYPE_PATH, truncated path or missing extra type", getLogDateTime());
                  break;
                }
                int k = 0;
                uint8_t path_len = data[k++];
                uint8_t hash_size = (path_len >> 6) + 1;
                uint8_t hash_count = path_len & 63;
                if ((size_t)hash_size * hash_count >= (size_t)len - k) {
                  MESH_DEBUG_PRINTLN("%s PAYLOAD_TYPE_PATH, truncated path or missing extra type", getLogDateTime());
                  break;
                }
                uint8_t* path = &data[k]; k += hash_size*hash_count;
                if (k + 1 > len) {
                  MESH_DEBUG_PRINTLN("%s PAYLOAD_TYPE_PATH, path longer than payload", getLogDateTime());
                  break;   // declared path doesn't fit in the plaintext
                }
                uint8_t extra_type = data[k++] & 0x0F;   // upper 4 bits reserved for future use
                uint8_t* extra = &data[k];
                uint8_t extra_len = len - k;   // remainder of packet (may be padded with zeroes!)
                if (onPeerPathRecv(pkt, j, secret, path, path_len, extra_type, extra, extra_len)) {
                  if (pkt->isRouteFlood()) {
                    // send a reciprocal return path to sender, but send DIRECTLY!
                    mesh::Packet* rpath = createPathReturn(&src_hash, secret, pkt->path, pkt->path_len, 0, NULL, 0);
                    if (rpath) sendDirect(rpath, path, path_len, 500);
                  }
                }
              } else {
                onPeerDataRecv(pkt, pkt->getPayloadType(), j, secret, data, len);
              }
              found = true;
              break;
            }
          }
          if (!found && self_id.isHashMatch(&src_hash)) {
            // from our own key to our own key: another radio sharing this identity
            uint8_t secret[PUB_KEY_SIZE];
            self_id.calcSharedSecret(secret, self_id);
            uint8_t data[MAX_PACKET_PAYLOAD];
            int len = Utils::MACThenDecrypt(secret, data, macAndData, pkt->payload_len - i);
            if (len > 0) {
              onSelfDataRecv(pkt, pkt->getPayloadType(), data, len);   // keeps flooding, for the other copies
              found = true;
            }
          } else if (found) {
            pkt->markDoNotRetransmit();  // packet was for this node, so don't retransmit
          }
          if (!found) {
            MESH_DEBUG_PRINTLN("%s recv matches no peers, src_hash=%02X", getLogDateTime(), (uint32_t)src_hash);
          }
        } else if (self_id.isHashMatch(&src_hash)) {
          // from our key to someone else, and not sent by this radio (our own sends are marked seen):
          // maybe another radio sharing this identity
          onSiblingDatagram(pkt, pkt->getPayloadType(), dest_hash, macAndData, pkt->payload_len - i);
        }
        action = routeRecvPacket(pkt);
      }
      break;
    }
    case PAYLOAD_TYPE_ANON_REQ: {
      if (pkt->payload_len < 1 + PUB_KEY_SIZE) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): incomplete data packet", getLogDateTime());
        break;
      }

      int i = 0;
      uint8_t dest_hash = pkt->payload[i++];
      uint8_t* sender_pub_key = &pkt->payload[i]; i += PUB_KEY_SIZE;

      uint8_t* macAndData = &pkt->payload[i];   // MAC + encrypted data 
      if (!_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        if (self_id.isHashMatch(&dest_hash)) {
          Identity sender(sender_pub_key);

          uint8_t secret[PUB_KEY_SIZE];
          self_id.calcSharedSecret(secret, sender);

          // decrypt, checking MAC is valid
          uint8_t data[MAX_PACKET_PAYLOAD];
          uint8_t ctx[2 + PUB_KEY_SIZE];
          ctx[0] = pkt->getPayloadType();
          ctx[1] = dest_hash;
          memcpy(&ctx[2], sender_pub_key, PUB_KEY_SIZE);
          bool was_v2;
          int len = decryptPayload(secret, data, macAndData, pkt->payload_len - i, ctx, sizeof(ctx), was_v2);
          if (len > 0) {  // success!
            onAnonDataRecv(pkt, secret, sender, data, len);
            pkt->markDoNotRetransmit();
          }
        }
        action = routeRecvPacket(pkt);
      }
      break;
    }
    case PAYLOAD_TYPE_GRP_DATA: 
    case PAYLOAD_TYPE_GRP_TXT: {
      if (pkt->payload_len < 1) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): incomplete data packet", getLogDateTime());
        break;
      }

      int i = 0;
      uint8_t channel_hash = pkt->payload[i++];

      uint8_t* macAndData = &pkt->payload[i];   // MAC + encrypted data 
      if (!_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        // scan channels DB, for all matching hashes of 'channel_hash' (max 4 matches supported ATM)
        GroupChannel channels[4];
        int num = searchChannelsByHash(&channel_hash, channels, 4);
        // for each matching channel, try to decrypt data
        for (int j = 0; j < num; j++) {
          // decrypt, checking MAC is valid
          uint8_t data[MAX_PACKET_PAYLOAD];
          uint8_t ctx[2] = { pkt->getPayloadType(), channel_hash };
          bool was_v2;
          int len = decryptPayload(channels[j].secret, data, macAndData, pkt->payload_len - i, ctx, sizeof(ctx), was_v2);
          if (len > 0) {  // success!
            onGroupDataRecv(pkt, pkt->getPayloadType(), channels[j], data, len);
            break;
          }
        }
        action = routeRecvPacket(pkt);
      }
      break;
    }
    case PAYLOAD_TYPE_ADVERT: {
      const size_t required_len = PUB_KEY_SIZE + sizeof(uint32_t) + SIGNATURE_SIZE;
      if (pkt->payload_len < required_len) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): incomplete advertisement packet", getLogDateTime());
        break;
      }

      int i = 0;
      Identity id;
      memcpy(id.pub_key, &pkt->payload[i], PUB_KEY_SIZE); i += PUB_KEY_SIZE;

      uint32_t timestamp;
      memcpy(&timestamp, &pkt->payload[i], 4); i += 4;
      const uint8_t* signature = &pkt->payload[i]; i += SIGNATURE_SIZE;

      if (self_id.matches(id.pub_key)) {
        MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): receiving SELF advert packet", getLogDateTime());
      } else if (!_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        uint8_t* app_data = &pkt->payload[i];
        int app_data_len = pkt->payload_len - i;
        if (app_data_len > MAX_ADVERT_DATA_SIZE) { app_data_len = MAX_ADVERT_DATA_SIZE; }

        // check that signature is valid
        bool is_ok;
        {
          uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
          int msg_len = 0;
          memcpy(&message[msg_len], id.pub_key, PUB_KEY_SIZE); msg_len += PUB_KEY_SIZE;
          memcpy(&message[msg_len], &timestamp, 4); msg_len += 4;
          memcpy(&message[msg_len], app_data, app_data_len); msg_len += app_data_len;

          is_ok = id.verify(signature, message, msg_len);
        }
        if (is_ok) {
          MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): valid advertisement received!", getLogDateTime());
          onAdvertRecv(pkt, id, timestamp, app_data, app_data_len);
          action = routeRecvPacket(pkt);
        } else {
          MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): received advertisement with forged signature! (app_data_len=%d)", getLogDateTime(), app_data_len);
        }
      }
      break;
    }
    case PAYLOAD_TYPE_RAW_CUSTOM: {
      if (pkt->isRouteDirect() && !_tables->wasSeen(pkt)) {
        _tables->markSeen(pkt);
        onRawDataRecv(pkt);
        //action = routeRecvPacket(pkt);    don't flood route these (yet)
      }
      break;
    }
    case PAYLOAD_TYPE_MULTIPART:
      if (pkt->payload_len > 2) {
        uint8_t remaining = pkt->payload[0] >> 4;  // num of packets in this multipart sequence still to be sent
        uint8_t type = pkt->payload[0] & 0x0F;

        if (type == PAYLOAD_TYPE_ACK && pkt->payload_len >= 5) {    // a multipart ACK
          Packet tmp;
          tmp.header = pkt->header;
          tmp.path_len = Packet::copyPath(tmp.path, pkt->path, pkt->path_len);
          tmp.payload_len = pkt->payload_len - 1;
          memcpy(tmp.payload, &pkt->payload[1], tmp.payload_len);

          if (!_tables->wasSeen(&tmp)) {
            _tables->markSeen(&tmp);
            uint32_t ack_crc;
            memcpy(&ack_crc, tmp.payload, 4);

            onAckRecv(&tmp, ack_crc);
            //action = routeRecvPacket(&tmp);  // NOTE: currently not needed, as multipart ACKs not sent Flood
          }
        } else {
          // FUTURE: other multipart types??
        }
      }
      break;

    default:
      MESH_DEBUG_PRINTLN("%s Mesh::onRecvPacket(): unknown payload type, header: %d", getLogDateTime(), (int) pkt->header);
      // Don't flood route unknown packet types!   action = routeRecvPacket(pkt);
      break;
  }
  return action;
}

void Mesh::removeSelfFromPath(Packet* pkt) {
  // remove our hash from 'path'
  pkt->setPathHashCount(pkt->getPathHashCount() - 1);  // decrement the count

  uint8_t sz = pkt->getPathHashSize();
  for (int k = 0; k < pkt->getPathHashCount()*sz; k += sz) {  // shuffle path by 1 'entry'
    memcpy(&pkt->path[k], &pkt->path[k + sz], sz);
  }
}

DispatcherAction Mesh::routeRecvPacket(Packet* packet) {
  uint8_t n = packet->getPathHashCount();
  if (packet->isRouteFlood() && !packet->isMarkedDoNotRetransmit()
    && (n + 1)*packet->getPathHashSize() <= MAX_PATH_SIZE && allowPacketForward(packet)) {
    // append this node's hash to 'path'
    self_id.copyHashTo(&packet->path[n * packet->getPathHashSize()], packet->getPathHashSize());
    packet->setPathHashCount(n + 1);

    uint32_t d = getRetransmitDelay(packet);
    // as this propagates outwards, give it lower and lower priority
    return ACTION_RETRANSMIT_DELAYED(packet->getPathHashCount(), d);   // give priority to closer sources, than ones further away
  }
  return ACTION_RELEASE;
}

DispatcherAction Mesh::forwardMultipartDirect(Packet* pkt, uint32_t delay_millis) {
  if (pkt->payload_len == 0) return ACTION_RELEASE;

  uint8_t remaining = pkt->payload[0] >> 4;  // num of packets in this multipart sequence still to be sent
  uint8_t type = pkt->payload[0] & 0x0F;

  if (type == PAYLOAD_TYPE_ACK && pkt->payload_len >= 5) {    // a multipart ACK
    Packet tmp;
    tmp.header = pkt->header;
    tmp.path_len = Packet::copyPath(tmp.path, pkt->path, pkt->path_len);
    tmp.payload_len = pkt->payload_len - 1;
    memcpy(tmp.payload, &pkt->payload[1], tmp.payload_len);

    if (!_tables->wasSeen(&tmp)) {   // don't retransmit!
      _tables->markSeen(&tmp);
      removeSelfFromPath(&tmp);
      routeDirectRecvAcks(&tmp, delay_millis + ((uint32_t)remaining + 1) * 300);  // expect multipart ACKs 300ms apart (x2)
    }
  }
  return ACTION_RELEASE;
}

void Mesh::routeDirectRecvAcks(Packet* packet, uint32_t delay_millis) {
  if (!packet->isMarkedDoNotRetransmit()) {
    uint8_t extra = getExtraAckTransmitCount();
    while (extra > 0) {
      auto a1 = createMultiAck(packet->payload, packet->payload_len, extra);
      if (a1) {
        a1->path_len = Packet::copyPath(a1->path, packet->path, packet->path_len);
        a1->header &= ~PH_ROUTE_MASK;
        a1->header |= ROUTE_TYPE_DIRECT;
        sendPacket(a1, 0, delay_millis);
        delay_millis += 300;
      }
      extra--;
    }

    auto a2 = createAck(packet->payload, packet->payload_len);
    if (a2) {
      a2->path_len = Packet::copyPath(a2->path, packet->path, packet->path_len);
      a2->header &= ~PH_ROUTE_MASK;
      a2->header |= ROUTE_TYPE_DIRECT;
      sendPacket(a2, 0, delay_millis);
    }
  }
}

Packet* Mesh::createAdvert(const LocalIdentity& id, const uint8_t* app_data, size_t app_data_len) {
  if (app_data_len > MAX_ADVERT_DATA_SIZE) return NULL;

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createAdvert(): error, packet pool empty", getLogDateTime());
    return NULL;
  }

  packet->header = (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT);  // ROUTE_TYPE_* is set later

  int len = 0;
  memcpy(&packet->payload[len], id.pub_key, PUB_KEY_SIZE); len += PUB_KEY_SIZE;

  uint32_t emitted_timestamp = _rtc->getCurrentTime();
  memcpy(&packet->payload[len], &emitted_timestamp, 4); len += 4;

  uint8_t* signature = &packet->payload[len]; len += SIGNATURE_SIZE;  // will fill this in later

  memcpy(&packet->payload[len], app_data, app_data_len); len += app_data_len;

  packet->payload_len = len;

  {
    uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
    int msg_len = 0;
    memcpy(&message[msg_len], id.pub_key, PUB_KEY_SIZE); msg_len += PUB_KEY_SIZE;
    memcpy(&message[msg_len], &emitted_timestamp, 4); msg_len += 4;
    memcpy(&message[msg_len], app_data, app_data_len); msg_len += app_data_len;

    id.sign(signature, message, msg_len);
  }

  return packet;
}

#define MAX_COMBINED_PATH  (MAX_PACKET_PAYLOAD - 2 - CIPHER_BLOCK_SIZE)

Packet* Mesh::createPathReturn(const Identity& dest, const uint8_t* secret, const uint8_t* path, uint8_t path_len, uint8_t extra_type, const uint8_t*extra, size_t extra_len) {
  uint8_t dest_hash[PATH_HASH_SIZE];
  dest.copyHashTo(dest_hash);
  return createPathReturn(dest_hash, secret, path, path_len, extra_type, extra, extra_len);
}

Packet* Mesh::createPathReturn(const uint8_t* dest_hash, const uint8_t* secret, const uint8_t* path, uint8_t path_len, uint8_t extra_type, const uint8_t*extra, size_t extra_len) {
  uint8_t path_hash_size = (path_len >> 6) + 1;
  uint8_t path_hash_count = path_len & 63;

  if (path_hash_count*path_hash_size + extra_len + 5 > MAX_COMBINED_PATH) return NULL;  // too long!!
  if (!fitsPayload(secret, 2*PATH_HASH_SIZE, 1 + path_hash_count*path_hash_size + (extra_len > 0 ? 1 + extra_len : 5))) return NULL;

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createPathReturn(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_PATH << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  int len = 0;
  memcpy(&packet->payload[len], dest_hash, PATH_HASH_SIZE); len += PATH_HASH_SIZE;  // dest hash
  len += self_id.copyHashTo(&packet->payload[len]);  // src hash

  {
    int data_len = 0;
    uint8_t data[MAX_PACKET_PAYLOAD];

    data[data_len++] = path_len;
    memcpy(&data[data_len], path, path_hash_count*path_hash_size); data_len += path_hash_count*path_hash_size;
    if (extra_len > 0) {
      data[data_len++] = extra_type;
      memcpy(&data[data_len], extra, extra_len); data_len += extra_len;
    } else {
      // append a timestamp, or random blob (to make packet_hash unique)
      data[data_len++] = 0xFF;  // dummy payload type
      getRNG()->random(&data[data_len], 4); data_len += 4;
    }

    uint8_t ctx[3] = { PAYLOAD_TYPE_PATH, packet->payload[0], packet->payload[1] };
    len += encryptPayload(secret, &packet->payload[len], data, data_len, ctx, sizeof(ctx));
  }

  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createDatagram(uint8_t type, const Identity& dest, const uint8_t* secret, const uint8_t* data, size_t data_len) {
  if (type == PAYLOAD_TYPE_TXT_MSG || type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE) {
    if (data_len + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE-1 > MAX_PACKET_PAYLOAD) return NULL;
    if (!fitsPayload(secret, 2*PATH_HASH_SIZE, data_len)) return NULL;
  } else {
    return NULL;  // invalid type
  }

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createDatagram(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (type << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  int len = 0;
  len += dest.copyHashTo(&packet->payload[len]);  // dest hash
  len += self_id.copyHashTo(&packet->payload[len]);  // src hash
  uint8_t ctx[3] = { type, packet->payload[0], packet->payload[1] };
  len += encryptPayload(secret, &packet->payload[len], data, data_len, ctx, sizeof(ctx));

  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createAnonDatagram(uint8_t type, const LocalIdentity& sender, const Identity& dest, const uint8_t* secret, const uint8_t* data, size_t data_len) {
  if (type == PAYLOAD_TYPE_ANON_REQ) {
    if (data_len + 1 + PUB_KEY_SIZE + CIPHER_BLOCK_SIZE-1 > MAX_PACKET_PAYLOAD) return NULL;
    if (!fitsPayload(secret, PATH_HASH_SIZE + PUB_KEY_SIZE, data_len)) return NULL;
  } else {
    return NULL;  // invalid type
  }

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createAnonDatagram(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (type << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  int len = 0;
  if (type == PAYLOAD_TYPE_ANON_REQ) {
    len += dest.copyHashTo(&packet->payload[len]);  // dest hash
    memcpy(&packet->payload[len], sender.pub_key, PUB_KEY_SIZE); len += PUB_KEY_SIZE;  // sender pub_key
  } else {
    // FUTURE:
  }
  uint8_t ctx[2 + PUB_KEY_SIZE];
  ctx[0] = type;
  ctx[1] = packet->payload[0];
  memcpy(&ctx[2], sender.pub_key, PUB_KEY_SIZE);
  len += encryptPayload(secret, &packet->payload[len], data, data_len, ctx, sizeof(ctx));

  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createGroupDatagram(uint8_t type, const GroupChannel& channel, const uint8_t* data, size_t data_len) {
  if (!(type == PAYLOAD_TYPE_GRP_TXT || type == PAYLOAD_TYPE_GRP_DATA)) return NULL;   // invalid type
  if (data_len + 1 + CIPHER_BLOCK_SIZE-1 > MAX_PACKET_PAYLOAD) return NULL; // too long
  if (!fitsPayload(channel.secret, PATH_HASH_SIZE, data_len)) return NULL;

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createGroupDatagram(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (type << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  int len = 0;
  memcpy(&packet->payload[len], channel.hash, PATH_HASH_SIZE); len += PATH_HASH_SIZE;
  uint8_t ctx[2] = { type, channel.hash[0] };
  len += encryptPayload(channel.secret, &packet->payload[len], data, data_len, ctx, sizeof(ctx));

  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createAck(const uint8_t* ack, uint8_t len) {
  if (ack == NULL || len < MIN_ACK_PAYLOAD_SIZE || len > MAX_ACK_PAYLOAD_SIZE ||
      len > sizeof(Packet::payload)) {
    return NULL;
  }

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createAck(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  memcpy(packet->payload, ack, len);
  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createMultiAck(const uint8_t* ack, uint8_t len, uint8_t remaining) {
  if (ack == NULL || len < MIN_ACK_PAYLOAD_SIZE || len > MAX_ACK_PAYLOAD_SIZE ||
      len > sizeof(Packet::payload) - 1) {
    return NULL;
  }

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createMultiAck(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_MULTIPART << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  packet->payload[0] = (remaining << 4) | PAYLOAD_TYPE_ACK;
  memcpy(&packet->payload[1], ack, len);
  packet->payload_len = 1 + len;

  return packet;
}

Packet* Mesh::createRawData(const uint8_t* data, size_t len) {
  if (len > sizeof(Packet::payload)) return NULL;  // invalid arg

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createRawData(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  memcpy(packet->payload, data, len);
  packet->payload_len = len;

  return packet;
}

Packet* Mesh::createTrace(uint32_t tag, uint32_t auth_code, uint8_t flags) {
  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createTrace(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  memcpy(packet->payload, &tag, 4);
  memcpy(&packet->payload[4], &auth_code, 4);
  packet->payload[8] = flags;
  packet->payload_len = 9;  // NOTE: path will be appended to payload[] later

  return packet;
}

Packet* Mesh::createControlData(const uint8_t* data, size_t len) {
  if (len > sizeof(Packet::payload)) return NULL;  // invalid arg

  Packet* packet = obtainNewPacket();
  if (packet == NULL) {
    MESH_DEBUG_PRINTLN("%s Mesh::createControlData(): error, packet pool empty", getLogDateTime());
    return NULL;
  }
  packet->header = (PAYLOAD_TYPE_CONTROL << PH_TYPE_SHIFT);  // ROUTE_TYPE_* set later

  memcpy(packet->payload, data, len);
  packet->payload_len = len;

  return packet;
}

void Mesh::sendFlood(Packet* packet, uint32_t delay_millis, uint8_t path_hash_size) {
  if (packet->getPayloadType() == PAYLOAD_TYPE_TRACE) {
    MESH_DEBUG_PRINTLN("%s Mesh::sendFlood(): TRACE type not suspported", getLogDateTime());
    return;
  }
  if (path_hash_size == 0 || path_hash_size > 3) {
    MESH_DEBUG_PRINTLN("%s Mesh::sendFlood(): invalid path_hash_size", getLogDateTime());
    return;
  }

  packet->header &= ~PH_ROUTE_MASK;
  packet->header |= ROUTE_TYPE_FLOOD;
  packet->setPathHashSizeAndCount(path_hash_size, 0);

  _tables->markSeen(packet); // mark this packet as already sent in case it is rebroadcast back to us

  uint8_t pri;
  if (packet->getPayloadType() == PAYLOAD_TYPE_PATH) {
    pri = 2;
  } else if (packet->getPayloadType() == PAYLOAD_TYPE_ADVERT) {
    pri = 3;   // de-prioritie these
  } else {
    pri = 1;
  }
  sendPacket(packet, pri, delay_millis);
}

void Mesh::sendFlood(Packet* packet, uint16_t* transport_codes, uint32_t delay_millis, uint8_t path_hash_size) {
  if (packet->getPayloadType() == PAYLOAD_TYPE_TRACE) {
    MESH_DEBUG_PRINTLN("%s Mesh::sendFlood(): TRACE type not suspported", getLogDateTime());
    return;
  }
  if (path_hash_size == 0 || path_hash_size > 3) {
    MESH_DEBUG_PRINTLN("%s Mesh::sendFlood(): invalid path_hash_size", getLogDateTime());
    return;
  }

  packet->header &= ~PH_ROUTE_MASK;
  packet->header |= ROUTE_TYPE_TRANSPORT_FLOOD;
  packet->transport_codes[0] = transport_codes[0];
  packet->transport_codes[1] = transport_codes[1];
  packet->setPathHashSizeAndCount(path_hash_size, 0);

  _tables->markSeen(packet); // mark this packet as already sent in case it is rebroadcast back to us

  uint8_t pri;
  if (packet->getPayloadType() == PAYLOAD_TYPE_PATH) {
    pri = 2;
  } else if (packet->getPayloadType() == PAYLOAD_TYPE_ADVERT) {
    pri = 3;   // de-prioritie these
  } else {
    pri = 1;
  }
  sendPacket(packet, pri, delay_millis);
}

void Mesh::sendDirect(Packet* packet, const uint8_t* path, uint8_t path_len, uint32_t delay_millis) {
  packet->header &= ~PH_ROUTE_MASK;
  packet->header |= ROUTE_TYPE_DIRECT;

  uint8_t pri;
  if (packet->getPayloadType() == PAYLOAD_TYPE_TRACE) {   // TRACE packets are different
    // for TRACE packets, path is appended to end of PAYLOAD. (path is used for SNR's)
    memcpy(&packet->payload[packet->payload_len], path, path_len);  // NOTE: path_len here can be > 64, and NOT in the new scheme
    packet->payload_len += path_len;

    packet->path_len = 0;
    pri = 5;   // maybe make this configurable
  } else {
    packet->path_len = Packet::copyPath(packet->path, path, path_len);
    if (packet->getPayloadType() == PAYLOAD_TYPE_PATH) {
      pri = 1;   // slightly less priority
    } else {
      pri = 0;
    }
  }
  _tables->markSeen(packet); // mark this packet as already sent in case it is rebroadcast back to us
  sendPacket(packet, pri, delay_millis);
}

void Mesh::sendZeroHop(Packet* packet, uint32_t delay_millis) {
  packet->header &= ~PH_ROUTE_MASK;
  packet->header |= ROUTE_TYPE_DIRECT;

  packet->path_len = 0;  // path_len of zero means Zero Hop

  _tables->markSeen(packet); // mark this packet as already sent in case it is rebroadcast back to us

  sendPacket(packet, 0, delay_millis);
}

void Mesh::sendZeroHop(Packet* packet, uint16_t* transport_codes, uint32_t delay_millis) {
  packet->header &= ~PH_ROUTE_MASK;
  packet->header |= ROUTE_TYPE_TRANSPORT_DIRECT;
  packet->transport_codes[0] = transport_codes[0];
  packet->transport_codes[1] = transport_codes[1];

  packet->path_len = 0;  // path_len of zero means Zero Hop

  _tables->markSeen(packet); // mark this packet as already sent in case it is rebroadcast back to us

  sendPacket(packet, 0, delay_millis);
}

}
