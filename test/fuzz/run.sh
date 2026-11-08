#!/bin/bash
# Builds and runs every fuzzer for SECONDS each (default 60), one per CPU core at a time. Exits with an
# error if any finds a problem;
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
  .pio/fuzz/corpus_wxsensor .pio/fuzz/corpus_uat .pio/fuzz/corpus_fisb .pio/fuzz/corpus_meters .pio/fuzz/corpus_clone .pio/fuzz/corpus_damaged
FUZZ_WRITE_SEEDS=.pio/fuzz/seeds_mesh .pio/fuzz/fuzz_mesh
FUZZ_WRITE_SEEDS=.pio/fuzz/seeds_meshtastic .pio/fuzz/fuzz_meshtastic

# Several at a time, one per CPU core (FUZZ_JOBS to change), each for the full SECONDS_EACH
JOBS=${FUZZ_JOBS:-$(nproc)}
rm -f .pio/fuzz/*.status

fuzz() {
  local name=$1; shift
  if .pio/fuzz/fuzz_$name -max_total_time=$SECONDS_EACH -print_final_stats=1 \
       -artifact_prefix=.pio/fuzz/findings/${name}- "$@" > .pio/fuzz/$name.log 2>&1; then
    echo ok > .pio/fuzz/$name.status
  else
    echo failed > .pio/fuzz/$name.status
  fi
}

NAMES=()
run() {
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n || true; done
  echo "== fuzz_$1 for ${SECONDS_EACH}s"
  NAMES+=("$1")
  fuzz "$@" &
}
run cli -dict=test/fuzz/cli.dict -max_len=600 .pio/fuzz/corpus_cli
run mesh -max_len=1200 .pio/fuzz/corpus_mesh .pio/fuzz/seeds_mesh
run meshtastic -max_len=1200 .pio/fuzz/corpus_meshtastic .pio/fuzz/seeds_meshtastic
run wxsensor -max_len=400 .pio/fuzz/corpus_wxsensor
run uat -max_len=300 .pio/fuzz/corpus_uat
run fisb -max_len=600 .pio/fuzz/corpus_fisb
run meters -max_len=64 .pio/fuzz/corpus_meters
run clone -max_len=2000 .pio/fuzz/corpus_clone
run damaged -max_len=300 .pio/fuzz/corpus_damaged test/fuzz/regress/damaged   # inputs that found bugs: replayed first
wait

found=0
for name in "${NAMES[@]}"; do
  if [ "$(cat .pio/fuzz/$name.status 2>/dev/null)" != ok ]; then
    grep -E "ERROR|SUMMARY|runtime error|lost|#[0-9]+ 0x|Test unit" .pio/fuzz/$name.log | head -40
    echo "fuzz_$name found a problem: full log in .pio/fuzz/$name.log"
    found=1
  else
    echo "fuzz_$name: $(grep -E "DONE" .pio/fuzz/$name.log | tail -1)"
  fi
done
[ $found = 0 ] || exit 1
echo "no findings"
