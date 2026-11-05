#pragma once
// The DateTime part of RTClib that the CLI uses to print the clock

#include <cstdint>
#include <ctime>

class DateTime {
  struct tm _tm;
public:
  explicit DateTime(uint32_t t) { time_t tt = t; gmtime_r(&tt, &_tm); }
  uint16_t year() const { return _tm.tm_year + 1900; }
  uint8_t month() const { return _tm.tm_mon + 1; }
  uint8_t day() const { return _tm.tm_mday; }
  uint8_t hour() const { return _tm.tm_hour; }
  uint8_t minute() const { return _tm.tm_min; }
  uint8_t second() const { return _tm.tm_sec; }
};
