#!/usr/bin/env python3
"""Bench test: does a companion hear the repeats of what it sends, whatever listen mode is on?

The companion under test (an LR2021 companion, USB build) sends a channel message; the Heltec V4
(tools/heltec_v4_tx) hears it and plays it back as a repeater would (one more hash on the path)
after a set delay; the companion's 'get radio.counts' says whether it heard it. On a miss it prints
the companion's 'get radio.log'. Both radios on 908 MHz, 62.5 kHz, SF7, CR 5 (the bench settings).

  repeat_test.py <label> [trials per delay] [delays,comma,separated] [options]
    --setup "cmd;cmd"      companion CLI commands first, eg. "set air on"
    --incoming N           then N packets from the Heltec at random moments (no transmit before)
    --chain d1,d2,.. N     N sends, each followed by repeats at d1, d2, .. s (each one hop further)
    --sensor SECS          a WH65 weather station on 915 MHz every 16 s; wait SECS for 'wx' to learn it

  eg. repeat_test.py air 3 0.5,1.5,3.3,6,12 --setup "set air on" --incoming 10 --chain 0.6,2,3.6,5 6

Ports: X (companion) and H (Heltec) below. Repeats at exactly the flood-retry wait (about 3 s for a
50-byte message) collide with the companion's own resend: pick delays off it."""
import sys, time, struct, re, threading, random, serial

X = '/dev/serial/by-id/usb-Seeed_Studio_XIAO_nRF52840_1AE2A6FD3E022354-if00'
H = '/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_8C:FD:49:B3:D7:3C-if00'


def frame(p): return b'<' + struct.pack('<H', len(p)) + p


class Comp:
    def __init__(self, port):
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.buf = b''
        self.notes = []
        self.s.write(frame(bytes([1, 3]) + bytes(6) + b'rpt'))
        self.frames(1.0)

    def frames(self, secs):
        out, end = [], time.time() + secs
        while time.time() < end:
            self.buf += self.s.read(4096)
            while True:
                i = self.buf.find(b'>')
                if i < 0 or len(self.buf) < i + 3: break
                n = struct.unpack('<H', self.buf[i + 1:i + 3])[0]
                if len(self.buf) < i + 3 + n: break
                f = self.buf[i + 3:i + 3 + n]
                self.buf = self.buf[i + 3 + n:]
                if f[0] == 0x83: self.s.write(frame(bytes([10])))   # messages waiting: fetch
                elif f[0] in (7, 16, 8, 17):
                    self.notes.append(f)
                out.append(f)
            if out and secs < 0: break
        return out

    def cli(self, cmd, t=2.0):
        self.s.write(frame(bytes([66]) + cmd.encode()))
        end = time.time() + t
        while time.time() < end:
            for f in self.frames(0.05):
                if f[0] == 29: return f[1:].decode(errors='replace')
        return None

    def rx(self):
        r = self.cli('get radio.counts')
        m = re.search(r'rx (\d+) ok (\d+) errors, tx (\d+)', r or '')
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None

    def send_chan(self, text, ch=0):
        self.s.write(frame(bytes([3, 0, ch]) + struct.pack('<I', int(time.time())) + text.encode()))


class Heltec:
    def __init__(self, port):
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.lock = threading.Lock()
        self.cmd_lock = threading.RLock()
        self.rx = []      # (time, hex)
        self.replies = []
        self.stop = False
        threading.Thread(target=self._reader, daemon=True).start()
        for c in ['hold on', 'set radio 908,62.5,7,5', 'set sync 12', 'set tx 22', 'hold off']:
            self.cmd(c)

    def _reader(self):
        buf = b''
        while not self.stop:
            buf += self.s.read(4096)
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                line = line.decode(errors='replace').strip()
                if line.startswith('RXSTAT'):
                    m = re.search(r'st=(-?\d+).*data=([0-9A-F]*)', line)
                    if m and m.group(1) == '0':
                        with self.lock: self.rx.append((time.time(), m.group(2)))
                elif line:
                    with self.lock: self.replies.append(line)

    def cmd(self, c, t=3.0):
        with self.cmd_lock:
            return self._cmd(c, t)

    def _cmd(self, c, t):
        with self.lock: self.replies.clear()
        self.s.write((c + '\n').encode())
        end = time.time() + t
        while time.time() < end:
            with self.lock:
                for r in self.replies:
                    if '->' in r or 'hold st' in r: return r
            time.sleep(0.005)
        return None

    def sensor(self, period=16.0):
        """A WH65 weather station on 915 MHz, every period seconds (then back to listening for LoRa)."""
        pkt = '24BF0AE2064E0802004A00010000008F07' + '55' * 15
        def run():
            while not self.stop:
                with self.cmd_lock:
                    self._cmd('fsktx 915 35 ' + pkt, 3.0)
                    self._cmd('hold off', 3.0)
                    self.sent_sensor = getattr(self, 'sent_sensor', 0) + 1
                time.sleep(period)
        threading.Thread(target=run, daemon=True).start()

    def wait_rx(self, since, t):
        end = time.time() + t
        while time.time() < end:
            with self.lock:
                for ts, h in self.rx:   # a channel message from the XIAO (flood, group text)
                    if ts >= since and len(h) >= 40 and h[:2] == '15': return ts, h
            time.sleep(0.005)
        return None


def as_repeat(hx):
    """The packet as a repeater passes it on: one more 1-byte hash on the path (flood, no transport codes)."""
    b = bytes.fromhex(hx)
    if b[0] & 3 != 1 or (b[1] >> 6) != 0: return hx
    n = b[1] & 63
    return (bytes([b[0], n + 1]) + b[2:2 + n] + bytes([0x5A + n]) + b[2 + n:]).hex().upper()


def main():
    a = sys.argv[1:]
    label = a.pop(0)
    trials = int(a.pop(0)) if a and not a[0].startswith('-') else 4
    delays = [float(v) for v in a.pop(0).split(',')] if a and not a[0].startswith('-') else [0.5, 1.5, 3, 4.5, 6, 8, 12]
    setup, incoming, chain, chain_n = [], 0, [], 0
    sensor_wait = None
    while a:
        k = a.pop(0)
        if k == '--setup': setup = [c.strip() for c in a.pop(0).split(';') if c.strip()]
        elif k == '--incoming': incoming = int(a.pop(0))
        elif k == '--sensor': sensor_wait = float(a.pop(0))
        elif k == '--chain': chain = [float(v) for v in a.pop(0).split(',')]; chain_n = int(a.pop(0))
    x = Comp(X)
    h = Heltec(H)
    for c in setup:
        print('setup', c, '=>', x.cli(c, 4.0), flush=True)
    if sensor_wait is not None:
        h.sensor()
        end = time.time() + sensor_wait   # let the weather tracker learn the sensor first
        while time.time() < end:
            time.sleep(15)
            print('  learning:', x.cli('get wx.sensors'), flush=True)
    print('state:', x.cli('get radio.fsk'), flush=True)
    res = {d: [0, 0] for d in delays}
    lat = []
    order = [d for d in delays for _ in range(trials)]
    random.shuffle(order)
    for k, d in enumerate(order):
        before = x.rx()
        t_send = time.time()
        x.send_chan('rpt %s %d d=%.1f' % (label, k, d))
        got = h.wait_rx(t_send, 8.0)
        if not got:
            print('  trial %d: heltec heard nothing from the XIAO' % k, flush=True)
            res[d][1] += 1
            continue
        t0, hx = got
        lat.append(t0 - t_send)
        while time.time() < t0 + d: time.sleep(0.002)
        r = h.cmd('loratx ' + as_repeat(hx))
        t1 = time.time()
        time.sleep(0.8)
        after = x.rx()
        heard = after[0] - before[0] >= 1 if before and after else None
        res[d][0] += 1 if heard else 0
        res[d][1] += 1
        print('  trial %2d d=%5.1f send->air %.2fs heard=%s %s' % (k, d, t0 - t_send, heard, '' if r and 'OK' in r else r), flush=True)
        if not heard: print('     log:', x.cli('get radio.log'), '| chip:', x.cli('get radio.chip'), flush=True)
        time.sleep(random.uniform(0.2, 1.5))
    if chain:   # one send, then a repeat at each delay in the chain
        got_all = [0, 0]
        for k in range(chain_n):
            before = x.rx()
            t_send = time.time()
            x.send_chan('chain %s %d' % (label, k))
            got = h.wait_rx(t_send, 8.0)
            if not got: print('  chain %d: heltec heard nothing' % k); continue
            t0, hx = got
            rep = as_repeat(hx)
            for i, d in enumerate(chain):
                while time.time() < t0 + d: time.sleep(0.002)
                # each later repeat one hop further: another hash on the path
                h.cmd('loratx ' + rep)
                rep = as_repeat(rep)
            time.sleep(0.8)
            after = x.rx()
            n = after[0] - before[0] if after and before else -1
            got_all[0] += n; got_all[1] += len(chain)
            print('  chain %2d: heard %d of %d' % (k, n, len(chain)), flush=True)
            if n < len(chain): print('     log:', x.cli('get radio.log'), flush=True)
            time.sleep(random.uniform(1, 3))
        print('CHAIN %s %s: %d/%d' % (label, chain, got_all[0], got_all[1]), flush=True)
    inc = [0, 0]
    for k in range(incoming):
        time.sleep(random.uniform(2, 9))
        before = x.rx()
        h.cmd('loratx 1100' + '%02X' % (k & 255) + 'AB' * 40)  # a junk flood packet
        time.sleep(0.8)
        after = x.rx()
        inc[1] += 1
        inc[0] += 1 if after and before and after[0] > before[0] else 0
    print('RESULT %s:' % label, '  '.join('%g s %d/%d' % (d, res[d][0], res[d][1]) for d in delays),
          ('| incoming %d/%d' % tuple(inc)) if incoming else '',
          '| send->air median %.2f s max %.2f' % (sorted(lat)[len(lat) // 2], max(lat)) if lat else '', flush=True)
    if sensor_wait is not None:
        print('sensor: sent %d, XIAO:' % getattr(h, 'sent_sensor', 0), x.cli('get wx.sensors'), '|', x.cli('get wx.stats'), flush=True)
    print('after:', x.cli('get radio.fsk'), '|', x.cli('get flood.retry.stats'), '|', x.cli('get radio.faults'), flush=True)
    h.stop = True


if __name__ == '__main__':
    main()
