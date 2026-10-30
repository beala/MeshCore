#!/bin/bash
# Host-side helpers: portd.py keeps a serial port logged and takes commands from a FIFO,
# campaign.sh runs the step 2/3 cases (needs dut.fifo/tx.fifo from portd.py), analyze.py
# summarises results/<case>.tx + .dut.
# Runs the step 2/3 cases back to back. Each case: DUT command, TX burst, stop DUT, save both logs.
cd "$(dirname "$0")"
case_run() {  # name, setup cmds for both boards (;-separated), dut mode cmd, tx args
  local name=$1 setup=$2 mode=$3 txargs=$4
  IFS=';' read -ra cmds <<< "$setup"
  for c in "${cmds[@]}"; do [ -n "$c" ] && { echo "$c" > dut.fifo; sleep 0.5; }; done
  local L=$(wc -l < dut.log) T=$(wc -l < tx.log)
  echo "$(date +%T) start $name" >> results/progress.txt
  echo "$mode" > dut.fifo; sleep 1.5
  echo "tx $txargs" > tx.fifo
  timeout 3600 bash -c "until sed -n '$((T+1)),\$p' tx.log | grep -q 'tx done'; do sleep 2; done"
  sleep 2; echo x > dut.fifo
  timeout 20 bash -c "until sed -n '$((L+1)),\$p' dut.log | grep -q 'SUM,B'; do sleep 0.5; done"
  sleep 1
  sed -n "$((L+1)),\$p" dut.log > results/$name.dut
  sed -n "$((T+1)),\$p" tx.log > results/$name.tx
  echo "$(date +%T) done  $name: $(grep SUM results/$name.dut | tr '\n' ' ')" >> results/progress.txt
}
STD="10 160"
case_run b2_A "rxpre 32" "rx A" "A 1000 100 1000 32 $STD"
case_run b2_B "rxpre 32" "rx B" "B 1000 100 1000 32 $STD"
case_run s3_A "rxpre 32" "scan" "A 500 100 1000 32 $STD"
case_run s3_B "rxpre 32" "scan" "B 500 100 1000 32 $STD"
case_run s3_AB_low  "rxpre 32" "scan" "AB 400 500 2000 32 $STD"
case_run s3_AB_med  "rxpre 32" "scan" "AB 600 100 1000 32 $STD"
case_run s3_AB_high "rxpre 32" "scan" "AB 600 0 200 32 $STD"
for p in 24 16 12 10 8; do
  case_run s3_pre$p "rxpre $p" "scan" "A 300 100 1000 $p $STD"
done
case_run b2_A_pre8 "rxpre 8" "rx A" "A 300 100 1000 8 $STD"
echo "rxpre 32" > dut.fifo
echo "$(date +%T) ALL DONE" >> results/progress.txt
