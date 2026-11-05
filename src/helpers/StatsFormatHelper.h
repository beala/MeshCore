#pragma once

#include "Mesh.h"

class StatsFormatHelper {
public:
  static void formatCoreStats(char* reply, 
                             mesh::MainBoard& board, 
                             mesh::MillisecondClock& ms, 
                             uint16_t err_flags,
                             mesh::PacketManager* mgr) {
    sprintf(reply, 
      "{\"battery_mv\":%u,\"uptime_secs\":%lu,\"errors\":%u,\"queue_len\":%d}",
      (unsigned)board.getBattMilliVolts(),
      (unsigned long)(ms.getMillis() / 1000),
      (unsigned)err_flags,
      (int)mgr->getOutboundTotal()
    );
  }

  template<typename RadioDriverType>
  static void formatRadioStats(char* reply,
                              mesh::Radio* radio,
                              RadioDriverType& driver,
                              uint32_t total_air_time_ms,
                              uint32_t total_rx_air_time_ms) {
    int n = sprintf(reply, 
      "{\"noise_floor\":%d,\"last_rssi\":%d,\"last_snr\":%.2f,\"tx_air_secs\":%lu,\"rx_air_secs\":%lu",
      (int16_t)radio->getNoiseFloor(),
      (int16_t)driver.getLastRSSI(),
      driver.getLastSNR(),
      (unsigned long)(total_air_time_ms / 1000),
      (unsigned long)(total_rx_air_time_ms / 1000)
    );
    // only radios that report it (currently LR2021) add the gain step
    int gain = driver.getLastGainStep();
    if (gain >= 0) n += sprintf(&reply[n], ",\"last_gain\":%d", gain);
    strcpy(&reply[n], "}");
  }

  template<typename RadioDriverType>
  static void formatPacketStats(char* reply,
                               RadioDriverType& driver,
                               uint32_t n_sent_flood,
                               uint32_t n_sent_direct,
                               uint32_t n_recv_flood,
                               uint32_t n_recv_direct) {
    sprintf(reply, 
      "{\"recv\":%lu,\"sent\":%lu,\"flood_tx\":%lu,\"direct_tx\":%lu,\"flood_rx\":%lu,\"direct_rx\":%lu,\"recv_errors\":%lu}",
      (unsigned long)driver.getPacketsRecv(),
      (unsigned long)driver.getPacketsSent(),
      (unsigned long)n_sent_flood,
      (unsigned long)n_sent_direct,
      (unsigned long)n_recv_flood,
      (unsigned long)n_recv_direct,
      (unsigned long)driver.getPacketsRecvErrors()
    );
  }
};
