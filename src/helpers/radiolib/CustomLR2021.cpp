#ifdef USE_LR2021

#include "CustomLR2021.h"
#include "lr20xx_pram_lr2021.h"

// Values from Semtech's LR20xx driver (lr20xx_pram_load.c, lr20xx_patch.c)
#define PRAM_BASE_ADDR       0x801000
#define PRAM_MAGIC_ADDR      0x800FF8
#define PRAM_VERSION_ADDR    0x800FFC
#define PRAM_MAGIC           0x600DB002
// Writes are limited to 32 words per SPI transaction (RADIOLIB_LRXXXX_SPI_MAX_READ_WRITE_LEN = 128 bytes)
#define PRAM_BLOCK_WORDS     32

int16_t CustomLR2021::readWord(uint32_t addr, uint32_t* out) {
  uint8_t req[4] = { (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr, 1 };
  uint8_t rpl[4] = { 0 };
  int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_READ_REG_MEM_32, false, rpl, sizeof(rpl), req, sizeof(req));
  if (state == RADIOLIB_ERR_NONE) {
    *out = ((uint32_t)rpl[0] << 24) | ((uint32_t)rpl[1] << 16) | ((uint32_t)rpl[2] << 8) | (uint32_t)rpl[3];
  }
  return state;
}

// Uploads Semtech's patch image to PRAM and activates it, following
// lr20xx_pram_load_pram_lr2021() from Semtech's LR20xx driver.
int16_t CustomLR2021::loadPram() {
  for (uint32_t i = 0; i < pram_lr2021_size; i += PRAM_BLOCK_WORDS) {
    size_t len = pram_lr2021_size - i;
    if (len > PRAM_BLOCK_WORDS) len = PRAM_BLOCK_WORDS;
    int16_t state = writeCommon(RADIOLIB_LR2021_CMD_WRITE_REG_MEM_32, PRAM_BASE_ADDR + i * 4, &pram_lr2021[i], len, false);
    if (state != RADIOLIB_ERR_NONE) return state;
  }

  uint8_t arg[] = { 0 };
  int16_t state = SPIcommand(RADIOLIB_LR2021_CMD_ACTIVATE_PRAM, true, arg, sizeof(arg));
  if (state != RADIOLIB_ERR_NONE) return state;

  // confirm the chip reports the patch as loaded
  uint32_t magic = 0;
  state = readWord(PRAM_MAGIC_ADDR, &magic);
  if (state != RADIOLIB_ERR_NONE) return state;
  if (magic != PRAM_MAGIC) return RADIOLIB_ERR_UNKNOWN;

  return readWord(PRAM_VERSION_ADDR, &_pram_info);
}

#endif
