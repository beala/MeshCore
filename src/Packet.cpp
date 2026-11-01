#include "Packet.h"
#include <string.h>
#include <SHA256.h>

namespace mesh {

Packet::Packet() {
  header = 0;
  path_len = 0;
  payload_len = 0;
}

bool Packet::isValidPathLen(uint8_t path_len) {
  uint8_t hash_count = path_len & 63;
  uint8_t hash_size = (path_len >> 6) + 1;
  if (hash_size == 4) return false;  // Reserved for future
  return hash_count*hash_size <= MAX_PATH_SIZE;
}

size_t Packet::writePath(uint8_t* dest, const uint8_t* src, uint8_t path_len) {
  uint8_t hash_count = path_len & 63;
  uint8_t hash_size = (path_len >> 6) + 1;
  size_t len = hash_count*hash_size;
  if (len > MAX_PATH_SIZE) {
    MESH_DEBUG_PRINTLN("Packet::copyPath, invalid path_len=%d", (uint32_t)path_len);
    return 0;   // Error
  }
  memcpy(dest, src, len);
  return len;
}

uint8_t Packet::copyPath(uint8_t* dest, const uint8_t* src, uint8_t path_len) {
  writePath(dest, src, path_len);
  return path_len;
}

int Packet::getRawLength() const {
  return 2 + getPathByteLen() + payload_len + (hasTransportCodes() ? 4 : 0);
}

void Packet::calculatePacketHash(uint8_t* hash) const {
  SHA256 sha;
  uint8_t t = getPayloadType();
  sha.update(&t, 1);
  if (t == PAYLOAD_TYPE_TRACE) {
    sha.update(&path_len, sizeof(path_len));   // CAVEAT: TRACE packets can revisit same node on return path
  }
  sha.update(payload, payload_len);
  sha.finalize(hash, MAX_HASH_SIZE);
}

uint8_t Packet::writeTo(uint8_t dest[]) const {
  uint8_t i = 0;
  dest[i++] = header;
  if (hasTransportCodes()) {
    memcpy(&dest[i], &transport_codes[0], 2); i += 2;
    memcpy(&dest[i], &transport_codes[1], 2); i += 2;
  }
  dest[i++] = path_len;
  i += writePath(&dest[i], path, path_len);
  memcpy(&dest[i], payload, payload_len); i += payload_len;
  return i;
}

bool Packet::readFrom(const uint8_t src[], uint8_t len) {
  if (src == nullptr || len < 2) return false;

  // Validate the complete frame before reading optional fields or modifying this packet.
  const uint8_t route = src[0] & PH_ROUTE_MASK;
  const bool has_transport = route == ROUTE_TYPE_TRANSPORT_FLOOD || route == ROUTE_TYPE_TRANSPORT_DIRECT;
  const size_t path_offset = has_transport ? 5 : 1;
  if (len <= path_offset) return false;

  const uint8_t encoded_path_len = src[path_offset];
  if (!isValidPathLen(encoded_path_len)) return false;
  const size_t path_bytes = (encoded_path_len & 63) * ((encoded_path_len >> 6) + 1);
  const size_t payload_offset = path_offset + 1 + path_bytes;
  if (payload_offset >= len || len - payload_offset > sizeof(payload)) return false;

  header = src[0];
  if (has_transport) {
    memcpy(transport_codes, &src[1], sizeof(transport_codes));
  } else {
    transport_codes[0] = transport_codes[1] = 0;
  }
  path_len = encoded_path_len;
  memcpy(path, &src[path_offset + 1], path_bytes);
  payload_len = len - payload_offset;
  memcpy(payload, &src[payload_offset], payload_len);
  return true;
}

}
