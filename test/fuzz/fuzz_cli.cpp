// libFuzzer: random command lines into the repeater/room CLI (CommonCLI, regions, radio settings).
// Each input is split on newlines and run as a sequence of commands on one radio, so commands that
// build up state (region put, then region list) get exercised too. See build.sh.

#include "cli_rig.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Rig* rig = new Rig();   // a fresh radio for every input, so any finding replays from its input alone

  std::string text((const char*) data, size);
  size_t start = 0;
  while (start <= text.size()) {
    size_t end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    std::string command = text.substr(start, end - start);
    command = command.substr(0, strnlen(command.c_str(), command.size()));   // stop at a zero byte
    if (!command.empty()) rig->run(command);
    start = end + 1;
  }
  delete rig;
  return 0;
}
