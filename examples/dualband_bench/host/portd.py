# Keep a serial port open: append every line to <log> (prefixed with host time),
# and forward lines written to <fifo> as commands.
import sys, os, time, serial, threading
port, log, fifo = sys.argv[1:4]
if not os.path.exists(fifo): os.mkfifo(fifo)
while True:
    try:
        s = serial.Serial(port, 115200, timeout=0.2); break
    except Exception: time.sleep(0.5)
lf = open(log, 'a', buffering=1)
def cmds():
    while True:
        with open(fifo) as f:
            for line in f:
                lf.write(f"{time.time():.3f} >> {line.strip()}\n")
                s.write((line.strip() + "\n").encode())
threading.Thread(target=cmds, daemon=True).start()
buf = b''
while True:
    d = s.read(4096)
    if d:
        buf += d
        while b'\n' in buf:
            l, buf = buf.split(b'\n', 1)
            lf.write(f"{time.time():.3f} {l.decode(errors='replace').rstrip()}\n")
