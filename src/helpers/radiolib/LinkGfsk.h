#pragma once
// The GFSK settings of the point-to-point link (copying a radio, mesh::Radio::linkStart), the same on
// every chip so they hear each other: the LR2021's packet handler has SX126x-compatible length,
// CRC and whitening modes (LR2021 datasheet 11.3).

#include <stdint.h>

#define LINK_GFSK_KBPS      250.0f
#define LINK_GFSK_DEV_KHZ   62.5f
#define LINK_GFSK_RXBW_KHZ  467.0f      // the SX126x's setting; the LR2021 takes 476.2
#define LINK_GFSK_PBL_BITS  64
#define LINK_GFSK_WHITEN    0x01FF      // SX126x whitening seed
#define LINK_GFSK_CRC_POLY  0x1021      // CRC-16 CCITT, inverted
#define LINK_GFSK_CRC_INIT  0x1D0F

static const uint8_t LINK_SYNC_BYTES[4] = { 'M', 'C', 'C', 'L' };   // sent first byte first, MSB first
