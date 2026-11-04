#ifdef USE_LR2021

#include "CustomLR2021.h"
#include "lr20xx_pram_lr2021.h"

// PRAM write window, from Semtech's LR20xx driver (LR20XX_PRAM_BASE_ADDRESS).
// RadioLib has the same value in LR2021_registers.h, which LR2021.h doesn't include.
#define PRAM_BASE_ADDR    0x801000
// WriteRegMem32 takes at most 32 words per call, as in Semtech's lr20xx_patch_load_pram()
#define PRAM_BLOCK_WORDS  32

// Uploads Semtech's patch image to PRAM and activates it, following
// lr20xx_pram_load_pram_lr2021() from Semtech's LR20xx driver, then checks
// that the chip reports it as loaded.
int16_t CustomLR2021::loadPram() {
  for (uint32_t i = 0; i < pram_lr2021_size; i += PRAM_BLOCK_WORDS) {
    size_t len = pram_lr2021_size - i;
    if (len > PRAM_BLOCK_WORDS) len = PRAM_BLOCK_WORDS;
    int16_t state = writeRegMem32(PRAM_BASE_ADDR + i * 4, &pram_lr2021[i], len);
    if (state != RADIOLIB_ERR_NONE) return state;
  }

  int16_t state = activatePram();
  if (state != RADIOLIB_ERR_NONE) return state;

  bool loaded = false;
  state = checkPramLoaded(&loaded);
  if (state != RADIOLIB_ERR_NONE) return state;
  if (!loaded) return RADIOLIB_ERR_UNKNOWN;

  return getPramVersion(&_pram_version);
}

#endif
