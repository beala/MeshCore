#!/bin/bash
# Builds and runs every fuzzer for SECONDS each (default 60). Stops with an error on the first finding;
# the input that caused it is saved in .pio/fuzz/findings/ and replays with: .pio/fuzz/fuzz_<name> <file>
#
#   test/fuzz/run.sh          # a minute each
#   test/fuzz/run.sh 3600     # an hour each
set -e
cd "$(dirname "$0")/../.."
SECONDS_EACH=${1:-60}
test/fuzz/build.sh
mkdir -p .pio/fuzz/findings .pio/fuzz/corpus_cli .pio/fuzz/corpus_mesh .pio/fuzz/seeds_mesh \
  .pio/fuzz/corpus_meshtastic .pio/fuzz/seeds_meshtastic \
  .pio/fuzz/corpus_wxsensor .pio/fuzz/corpus_uat
FUZZ_WRITE_SEEDS=.pio/fuzz/seeds_mesh .pio/fuzz/fuzz_mesh
FUZZ_WRITE_SEEDS=.pio/fuzz/seeds_meshtastic .pio/fuzz/fuzz_meshtastic

run() {
  local name=$1; shift
  echo "== fuzz_$name for ${SECONDS_EACH}s"
  if ! .pio/fuzz/fuzz_$name -max_total_time=$SECONDS_EACH -print_final_stats=1 \
       -artifact_prefix=.pio/fuzz/findings/${name}- "$@" > .pio/fuzz/$name.log 2>&1; then
    grep -E "ERROR|SUMMARY|runtime error|lost|#[0-9]+ 0x|Test unit" .pio/fuzz/$name.log | head -40
    echo "fuzz_$name found a problem: full log in .pio/fuzz/$name.log"
    exit 1
  fi
  grep -E "DONE|stat::number_of_executed_units" .pio/fuzz/$name.log | tail -1
}
run cli -dict=test/fuzz/cli.dict -max_len=600 .pio/fuzz/corpus_cli
run mesh -max_len=1200 .pio/fuzz/corpus_mesh .pio/fuzz/seeds_mesh
run meshtastic -max_len=1200 .pio/fuzz/corpus_meshtastic .pio/fuzz/seeds_meshtastic
run wxsensor -max_len=400 .pio/fuzz/corpus_wxsensor
run uat -max_len=300 .pio/fuzz/corpus_uat
echo "no findings"
