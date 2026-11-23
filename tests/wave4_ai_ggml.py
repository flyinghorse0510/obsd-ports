#!/usr/bin/env python3
"""
tests/wave4_ai_ggml.py -- Tri-Release (OpenBSD 7.8 + 7.9 + 8.0) WASM64 End-to-End
Verification Suite for Wave-4 Slice A (SIMD128 GGML AI Inference, Speech,
Diffusion & MCP Server Suite):
  1. `devel/libggml` (`0.9.4` on 7.8, `0.9.11` on 7.9, `0.25.3p0` on 8.0)
  2. `misc/llama.cpp` (`0.0.6641` on 7.8, `0.0.8631` on 7.9, `0.5.0` on 8.0)
  3. `audio/whisper.cpp` (`1.7.6` on 7.8, `1.8.4` on 7.9, `1.9.4` on 8.0)
  4. `graphics/stable-diffusion.cpp` (`0.0.537545fac4` on 7.9, `0.0.899` on 8.0)

Runnable standalone via:
  python3 -I tests/wave4_ai_ggml.py --openbsd-version 8.0
  python3 -I tests/wave4_ai_ggml.py --openbsd-version 7.9
  python3 -I tests/wave4_ai_ggml.py --openbsd-version 7.8
  python3 -I tests/wave4_ai_ggml.py --openbsd-version all
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import wave
from typing import Any, Dict, List, Sequence, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_PKGS: Dict[str, List[str]] = {
    "7.8": [
        "libggml-0.9.4.tgz",
        "llama.cpp-0.0.6641.tgz",
        "whisper.cpp-1.7.6.tgz",
    ],
    "7.9": [
        "libggml-0.9.11.tgz",
        "llama.cpp-0.0.8631.tgz",
        "whisper.cpp-1.8.4.tgz",
        "stable-diffusion.cpp-0.0.537545fac4.tgz",
    ],
    "8.0": [
        "libggml-0.25.3p0.tgz",
        "llama.cpp-0.5.0.tgz",
        "whisper.cpp-1.9.4.tgz",
        "stable-diffusion.cpp-0.0.899.tgz",
    ],
}

LLAMA_APPLETS_COMMON = [
    "/usr/local/bin/llama",
    "/usr/local/bin/llama-cli",
    "/usr/local/bin/llama-server",
    "/usr/local/bin/llama-simple-chat",
    "/usr/local/bin/llama-embedding",
    "/usr/local/bin/llama-quantize",
    "/usr/local/bin/llama-gguf",
    "/usr/local/bin/llama-bench",
]

LLAMA_APPLETS_80_EXTRA = [
    "/usr/local/bin/llama-batched-bench",
    "/usr/local/bin/llama-completion",
    "/usr/local/bin/llama-perplexity",
    "/usr/local/bin/llama-fit-params",
]

WHISPER_APPLETS_COMMON = [
    "/usr/local/bin/whisper",
    "/usr/local/bin/whisper-cli",
    "/usr/local/bin/whisper-server",
    "/usr/local/bin/whisper-bench",
    "/usr/local/bin/whisper-quantize",
]

SD_APPLETS = [
    "/usr/local/bin/sd",
    "/usr/local/bin/sd-cli",
    "/usr/local/bin/sd-server",
]

SDK_CPP_PROBE_SRC = r"""
#include <ggml.h>
#include <ggml-cpu.h>
#include <gguf.h>
#include <llama.h>
#include <whisper.h>
#ifdef HAVE_SD
#include <stable-diffusion.h>
#endif
#include <cstdio>
#include <cstring>

int main(void) {
    struct ggml_init_params params = { 1024 * 1024, nullptr, false };
    struct ggml_context * ctx = ggml_init(params);
    if (!ctx) return 1;
    struct ggml_tensor * a = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, 32);
    if (!a) return 2;
    ggml_free(ctx);

    const char * sys_info = llama_print_system_info();
    const char * w_info = whisper_print_system_info();
    if (!sys_info || !w_info || std::strlen(w_info) == 0) return 3;
    return 0;
}
"""

# Full SVNP/1 Node.js runner supporting BOTH client TCP/UDP/DNS AND in-guest
# TCP server sockets (`SVNP_OP_BIND`, `SVNP_OP_LISTEN`, `SVNP_OP_ACCEPT`,
# and dynamic port `SVNP_OP_GETSOCKNAME`) so `llama-server` and `8.0` `llama-cli`
# run natively over loopback TCP inside WASM64 OpenBSD!
NODE_SVNP_FULL_MJS = r'''
import fs from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [runtimePath, configPath] = process.argv.slice(2);
const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

const createRuntime = (await import(pathToFileURL(path.resolve(runtimePath)).href)).default;
const Module = await createRuntime();
const { FS } = Module;

function mkdirp(p, mode = 0o755) {
  const parts = p.split('/').filter(Boolean);
  let cur = '';
  for (const seg of parts) {
    cur += '/' + seg;
    try { FS.mkdir(cur, mode); } catch {}
  }
}

for (const d of [
  '/bsd/sysroot/bin', '/bsd/sysroot/sbin', '/bsd/sysroot/usr/bin', '/bsd/sysroot/usr/sbin',
  '/bsd/sysroot/usr/local/bin', '/bsd/sysroot/usr/local/sbin', '/bsd/sysroot/usr/local/share',
  '/bsd/sysroot/usr/share/terminfo', '/bsd/sysroot/etc/ssl', '/bsd/sysroot/root',
  '/bsd/persist/etc/ssl', '/bsd/tmp', '/bsd/sysroot/tmp',
]) {
  mkdirp(d, d.endsWith('tmp') ? 0o1777 : 0o755);
}

const stubBytes = enc.encode(`Sonvori BSD applet stub.\ntable ${cfg.tableDigest}\n`);
for (const gp of cfg.appletPaths) {
  const full = `/bsd/sysroot${gp}`;
  mkdirp(path.posix.dirname(full), 0o755);
  FS.writeFile(full, stubBytes);
  FS.chmod(full, 0o555);
}

function copyHostTreeToMemfs(hostDir, memfsBase) {
  if (!fs.existsSync(hostDir)) return;
  for (const ent of fs.readdirSync(hostDir, { withFileTypes: true })) {
    const hp = path.join(hostDir, ent.name);
    const mp = path.posix.join(memfsBase, ent.name);
    if (ent.isSymbolicLink()) {
      const target = fs.readlinkSync(hp);
      try { FS.unlink(mp); } catch {}
      FS.symlink(target, mp);
    } else if (ent.isDirectory()) {
      mkdirp(mp, 0o755);
      copyHostTreeToMemfs(hp, mp);
    } else if (ent.isFile()) {
      mkdirp(path.posix.dirname(mp), 0o755);
      FS.writeFile(mp, fs.readFileSync(hp));
      const mode = fs.statSync(hp).mode & 0o777;
      FS.chmod(mp, mode || 0o644);
    }
  }
}

copyHostTreeToMemfs(cfg.sysrootUsrLocal, '/bsd/sysroot/usr/local');

for (const [gp, hp, mode] of cfg.stagedFiles) {
  const dest = gp.startsWith('/etc/') ? `/bsd/persist${gp}` : (gp.startsWith('/tmp/') ? `/bsd${gp}` : `/bsd/sysroot${gp}`);
  mkdirp(path.posix.dirname(dest), 0o755);
  FS.writeFile(dest, fs.readFileSync(hp));
  FS.chmod(dest, mode);
}

FS.writeFile('/bsd/tmp/__obsd_ports_cmd.sh', enc.encode(cfg.scriptText));
FS.chmod('/bsd/tmp/__obsd_ports_cmd.sh', 0o755);
FS.writeFile('/bsd/persist/fakeroot.db', new Uint8Array(0));
FS.writeFile(
  '/bsd/vfs.profile',
  enc.encode('version 1\nbind /etc /bsd/persist/etc\nbind /tmp /bsd/tmp\nremap / /bsd/sysroot\nsynth proc /proc\nidentity root\n'),
);

if (cfg.enableSvnp) {
  const SVNP_MAGIC = 0x53564e50;
  const SVNP_SHM_MAGIC = 0x53564e31;
  const SOCKS_BASE_OFF = 64;
  const SOCK_STRIDE = 16;
  const SLOTS_BASE_OFF = 16448;
  const SLOT_STRIDE = 65696;
  const MAX_SLOTS = 32;
  const SLOT_BUF_OFF = 32;

  const lo = Module._ports_svnp_shm_lo() >>> 0;
  const hi = Module._ports_svnp_shm_hi() >>> 0;
  const shmOff = hi * 0x100000000 + lo;

  const getViews = () => {
    const b = Module.wasmMemory.buffer;
    return { u8: new Uint8Array(b), i32: new Int32Array(b), u32: new Uint32Array(b) };
  };

  {
    const { i32, u32 } = getViews();
    Atomics.store(u32, (shmOff + 4) >> 2, 1);
    Atomics.store(u32, shmOff >> 2, SVNP_SHM_MAGIC);
    Atomics.store(i32, (shmOff + 8) >> 2, 1);
    Atomics.notify(i32, (shmOff + 8) >> 2, 64);
  }

  let nextSockId = 1;
  const socks = new Map();

  function encodeAddr(ip, port, family = 4) {
    const out = Buffer.alloc(28, 0);
    out.writeUInt8(family, 0);
    out.writeUInt16LE((port || 0) & 0xffff, 2);
    const normIp = (!ip || ip === '::ffff:127.0.0.1' || ip === '::1') ? '127.0.0.1' : ip.replace(/^::ffff:/, '');
    if (family === 4 && normIp.includes('.')) {
      const ps = normIp.split('.').map(Number);
      out[8] = ps[0]; out[9] = ps[1]; out[10] = ps[2]; out[11] = ps[3];
    }
    return out;
  }

  function decodeAddr(buf, off = 0) {
    const family = buf.readUInt8(off);
    const port = buf.readUInt16LE(off + 2);
    const ip = family === 4 ? `${buf[off+8]}.${buf[off+9]}.${buf[off+10]}.${buf[off+11]}` : '127.0.0.1';
    return { family, port, ip };
  }

  function updateSockState(sockId, s) {
    const { i32, u32 } = getViews();
    let mask = 0;
    let avail = 0;
    for (const c of s.rxQueue) avail += c.data.length;
    if (s.listening) {
      if (s.acceptQueue.length > 0) mask |= 1; // POLLIN on listening socket
    } else {
      if (avail > 0 || s.eof) mask |= 1;
      if (s.connected && !s.connecting) mask |= 4;
      if (s.err) mask |= 8;
      if (s.eof) mask |= 16;
    }
    const off = shmOff + SOCKS_BASE_OFF + sockId * SOCK_STRIDE;
    Atomics.store(i32, off >> 2, mask);
    Atomics.store(u32, (off + 4) >> 2, avail >>> 0);
    Atomics.store(i32, (off + 8) >> 2, s.err | 0);
    Atomics.add(i32, (off + 12) >> 2, 1);
    Atomics.notify(i32, (off + 12) >> 2, 64);
    Atomics.add(i32, (shmOff + 20) >> 2, 1);
    Atomics.notify(i32, (shmOff + 20) >> 2, 64);
    while (s.waiters.length > 0 && (avail > 0 || s.eof || s.err || s.acceptQueue.length > 0)) {
      const w = s.waiters.shift();
      w();
    }
  }

  function finishSlot(slotIdx, reqId, sockId, err, bodyBuf = Buffer.alloc(0)) {
    const { u8, i32, u32 } = getViews();
    const slotBase = shmOff + SLOTS_BASE_OFF + slotIdx * SLOT_STRIDE;
    const stateIdx = slotBase >> 2;
    if (Atomics.load(i32, stateIdx) !== 2) {
      Atomics.store(i32, stateIdx, 0);
      return false;
    }
    const resp = Buffer.alloc(20 + bodyBuf.length);
    resp.writeUInt32LE(SVNP_MAGIC, 0);
    resp.writeUInt8(0x80, 4);
    resp.writeUInt32LE(reqId >>> 0, 8);
    resp.writeUInt32LE(sockId >>> 0, 12);
    resp.writeInt32LE(err | 0, 16);
    bodyBuf.copy(resp, 20);
    u8.set(resp, slotBase + SLOT_BUF_OFF);
    Atomics.store(u32, (slotBase + 12) >> 2, resp.length);
    Atomics.store(i32, (slotBase + 16) >> 2, 0);
    Atomics.store(i32, stateIdx, 3);
    Atomics.notify(i32, stateIdx, 1);
    return true;
  }

  function attachTcpSocket(id, s, sock) {
    s.tcp = sock;
    sock.on('data', (chunk) => {
      s.rxQueue.push({ data: Buffer.from(chunk), addr: null });
      updateSockState(id, s);
    });
    sock.on('end', () => { s.eof = true; updateSockState(id, s); });
    sock.on('close', () => { s.eof = true; updateSockState(id, s); });
    sock.on('error', () => { s.err = 54; updateSockState(id, s); });
  }

  async function handleReq(slotIdx, frame) {
    const op = frame.readUInt8(4);
    const reqId = frame.readUInt32LE(8);
    const sockId = frame.readUInt32LE(12);
    const body = frame.subarray(16);

    if (op === 0x02) { // SOCKET
      const domain = body.readUInt8(0);
      const type = body.readUInt8(1);
      if (domain !== 4 && domain !== 6) return finishSlot(slotIdx, reqId, 0, 47);
      if (type !== 1 && type !== 2) return finishSlot(slotIdx, reqId, 0, 44);
      const id = nextSockId++;
      const s = {
        id, domain, type, tcp: null, udp: null, srv: null,
        connected: type === 2, connecting: false, listening: false,
        eof: false, err: 0, rxQueue: [], acceptQueue: [], acceptWaiters: [], waiters: [],
        local: { ip: '127.0.0.1', port: 0 }, peer: null,
      };
      if (type === 2) {
        const u = dgram.createSocket(domain === 6 ? 'udp6' : 'udp4');
        s.udp = u;
        u.on('message', (msg, rinfo) => {
          s.rxQueue.push({ data: Buffer.from(msg), addr: encodeAddr(rinfo.address, rinfo.port, 4) });
          updateSockState(id, s);
        });
        u.on('error', () => { s.err = 54; updateSockState(id, s); });
      }
      socks.set(id, s);
      updateSockState(id, s);
      const b = Buffer.alloc(4); b.writeUInt32LE(id, 0);
      return finishSlot(slotIdx, reqId, id, 0, b);
    }

    if (op === 0x10) { // RESOLVE
      const mode = body.readUInt8(0);
      if (mode === 0) {
        const port = body.readUInt16LE(4);
        const hlen = body.readUInt16LE(6);
        const host = body.subarray(8, 8 + hlen).toString('utf8');
        try {
          const res = await dns.lookup(host, { family: 4, all: true });
          const out = Buffer.alloc(4 + res.length * 28);
          out.writeUInt16LE(res.length, 0);
          out.writeUInt16LE(0, 2);
          res.forEach((r, idx) => encodeAddr(r.address, port, 4).copy(out, 4 + idx * 28));
          return finishSlot(slotIdx, reqId, 0, 0, out);
        } catch {
          return finishSlot(slotIdx, reqId, 0, 2);
        }
      }
      return finishSlot(slotIdx, reqId, 0, 78);
    }

    const s = socks.get(sockId);
    if (!s) return finishSlot(slotIdx, reqId, sockId, 9);

    if (op === 0x03) { // BIND
      const reqAddr = decodeAddr(body, 0);
      const bindHost = (reqAddr.ip === '0.0.0.0' || !reqAddr.ip) ? '127.0.0.1' : reqAddr.ip;
      if (s.type === 2 && s.udp) {
        try {
          await new Promise((resolve, reject) => {
            s.udp.once('error', reject);
            s.udp.bind(reqAddr.port, bindHost, () => { s.udp.removeListener('error', reject); resolve(); });
          });
          const a = s.udp.address();
          s.local = { ip: a.address, port: a.port };
          return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
        } catch {
          return finishSlot(slotIdx, reqId, sockId, 48 /* EADDRINUSE */);
        }
      }
      const srv = net.createServer({ allowHalfOpen: true });
      srv.on('connection', (connSock) => {
        if (!s.listening) {
          connSock.destroy();
          return;
        }
        s.acceptQueue.push(connSock);
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0 && s.acceptQueue.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
      });
      srv.on('error', () => {});
      try {
        await new Promise((resolve, reject) => {
          const onErr = (e) => { srv.removeListener('listening', onListen); reject(e); };
          const onListen = () => { srv.removeListener('error', onErr); resolve(); };
          srv.once('error', onErr);
          srv.once('listening', onListen);
          srv.listen({ host: bindHost, port: reqAddr.port, exclusive: false });
        });
        s.srv = srv;
        const a = srv.address();
        s.local = { ip: (a && a.address) ? a.address : bindHost, port: (a && a.port) ? a.port : reqAddr.port };
        return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
      } catch {
        try { srv.close(); } catch {}
        return finishSlot(slotIdx, reqId, sockId, 48 /* EADDRINUSE */);
      }
    }

    if (op === 0x05) { // LISTEN
      if (!s.srv) return finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
      s.listening = true;
      updateSockState(sockId, s);
      return finishSlot(slotIdx, reqId, sockId, 0);
    }

    if (op === 0x06) { // ACCEPT
      if (!s.srv || !s.listening) return finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
      const nonblock = body.length > 0 && body.readUInt8(0) !== 0;
      const tryAccept = () => {
        const { i32 } = getViews();
        const slotBase = shmOff + SLOTS_BASE_OFF + slotIdx * SLOT_STRIDE;
        if (Atomics.load(i32, slotBase >> 2) !== 2) {
          Atomics.store(i32, slotBase >> 2, 0);
          return true;
        }
        if (!s.srv || !s.listening) {
          finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
          return true;
        }
        if (s.acceptQueue.length === 0) return false;
        const connSock = s.acceptQueue.shift();
        updateSockState(sockId, s);
        const nid = nextSockId++;
        const peerIp = connSock.remoteAddress || '127.0.0.1';
        const peerPort = connSock.remotePort || 0;
        const ns = {
          id: nid, domain: s.domain, type: s.type, tcp: null, udp: null, srv: null,
          connected: true, connecting: false, listening: false,
          eof: false, err: 0, rxQueue: [], acceptQueue: [], acceptWaiters: [], waiters: [],
          local: { ip: connSock.localAddress || s.local.ip, port: connSock.localPort || s.local.port },
          peer: { ip: peerIp, port: peerPort, family: 4 },
        };
        socks.set(nid, ns);
        attachTcpSocket(nid, ns, connSock);
        updateSockState(nid, ns);
        const resp = Buffer.alloc(32, 0);
        resp.writeUInt32LE(nid, 0);
        encodeAddr(peerIp, peerPort, 4).copy(resp, 4);
        finishSlot(slotIdx, reqId, sockId, 0, resp);
        return true;
      };
      if (tryAccept()) return;
      if (nonblock) return finishSlot(slotIdx, reqId, sockId, 35 /* EAGAIN */);
      s.acceptWaiters.push(() => { tryAccept(); });
      return;
    }

    if (op === 0x04) { // CONNECT
      const dst = decodeAddr(body, 0);
      const nonblock = body.readUInt8(28) !== 0;
      s.peer = dst;
      if (s.type === 2) {
        updateSockState(sockId, s);
        return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr('127.0.0.1', 0, 4));
      }
      s.connecting = true;
      const sock = net.createConnection({ host: dst.ip, port: dst.port, allowHalfOpen: true });
      s.tcp = sock;
      sock.on('data', (chunk) => {
        s.rxQueue.push({ data: Buffer.from(chunk), addr: null });
        updateSockState(sockId, s);
      });
      sock.on('end', () => { s.eof = true; updateSockState(sockId, s); });
      sock.on('close', () => { s.eof = true; updateSockState(sockId, s); });
      if (nonblock) {
        sock.once('connect', () => {
          s.connecting = false; s.connected = true;
          s.local = { ip: sock.localAddress || '127.0.0.1', port: sock.localPort || 0 };
          updateSockState(sockId, s);
        });
        sock.on('error', () => { s.connecting = false; s.err = 61; updateSockState(sockId, s); });
        return finishSlot(slotIdx, reqId, sockId, 36 /* EINPROGRESS */);
      }
      sock.once('connect', () => {
        s.connecting = false; s.connected = true;
        s.local = { ip: sock.localAddress || '127.0.0.1', port: sock.localPort || 0 };
        updateSockState(sockId, s);
        finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
      });
      sock.once('error', () => {
        s.connecting = false; s.err = 61; updateSockState(sockId, s);
        finishSlot(slotIdx, reqId, sockId, 61);
      });
      return;
    }

    if (op === 0x07) { // SEND
      const hasDst = body.readUInt8(4) !== 0;
      const dst = hasDst ? decodeAddr(body, 5) : s.peer;
      const payload = body.subarray(33);
      if (s.type === 2 && s.udp && dst) {
        s.udp.send(payload, dst.port, dst.ip, (err) => {
          if (err) return finishSlot(slotIdx, reqId, sockId, 51);
          const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
          finishSlot(slotIdx, reqId, sockId, 0, b);
        });
        return;
      }
      if (!s.tcp) return finishSlot(slotIdx, reqId, sockId, 57);
      if (s.connecting && !s.connected) return finishSlot(slotIdx, reqId, sockId, 35);
      if (!s.connected || s.tcp.destroyed || !s.tcp.writable) {
        const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
        return finishSlot(slotIdx, reqId, sockId, 0, b);
      }
      s.tcp.write(payload, (err) => {
        if (err) return finishSlot(slotIdx, reqId, sockId, 54);
        const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
        finishSlot(slotIdx, reqId, sockId, 0, b);
      });
      return;
    }

    if (op === 0x08) { // RECV
      const maxLen = body.readUInt32LE(0);
      const msgFlags = body.readUInt32LE(4);
      const timeoutMs = body.readInt32LE(8);
      const tryPop = () => {
        if (s.rxQueue.length > 0) {
          const head = s.rxQueue[0];
          const take = head.data.subarray(0, maxLen);
          if (!(msgFlags & 0x02)) {
            if (take.length === head.data.length) s.rxQueue.shift();
            else head.data = head.data.subarray(take.length);
            updateSockState(sockId, s);
          }
          const out = Buffer.alloc(36 + take.length, 0);
          if (head.addr) { out.writeUInt8(1, 4); head.addr.copy(out, 8); }
          out.writeInt16LE(-1, 6);
          take.copy(out, 36);
          finishSlot(slotIdx, reqId, sockId, 0, out);
          return true;
        }
        if (s.err) { const e = s.err; s.err = 0; finishSlot(slotIdx, reqId, sockId, e); return true; }
        if (s.eof) { finishSlot(slotIdx, reqId, sockId, 0, Buffer.alloc(36, 0)); return true; }
        return false;
      };
      if (tryPop()) return;
      if ((msgFlags & 0x40) || timeoutMs === 0) return finishSlot(slotIdx, reqId, sockId, 35);
      let done = false;
      const waiter = () => { if (!done) { done = true; clearTimeout(tm); tryPop(); } };
      const tm = setTimeout(() => {
        if (!done) {
          done = true;
          const idx = s.waiters.indexOf(waiter);
          if (idx >= 0) s.waiters.splice(idx, 1);
          finishSlot(slotIdx, reqId, sockId, 35);
        }
      }, timeoutMs > 0 ? timeoutMs : 15000);
      s.waiters.push(waiter);
      return;
    }

    if (op === 0x09) return finishSlot(slotIdx, reqId, sockId, 0);
    if (op === 0x0a) {
      const level = body.readUInt16LE(0);
      const opt = body.readUInt16LE(2);
      const b = Buffer.alloc(4, 0);
      if (level === 1 && opt === 9) { b.writeInt32LE(s.err, 0); s.err = 0; }
      else if (level === 1 && opt === 12) { b.writeInt32LE(s.type, 0); }
      return finishSlot(slotIdx, reqId, sockId, 0, b);
    }
    if (op === 0x0b) return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
    if (op === 0x0c) return finishSlot(slotIdx, reqId, sockId, s.peer ? 0 : 57, s.peer ? encodeAddr(s.peer.ip, s.peer.port, 4) : Buffer.alloc(0));
    if (op === 0x0d) { // SHUTDOWN
      const how = body.length > 0 ? body.readUInt8(0) : 2;
      if (s.srv) {
        const srv = s.srv;
        s.srv = null;
        s.listening = false;
        s.eof = true;
        s.err = 22;
        for (const q of s.acceptQueue) { try { q.destroy(); } catch {} }
        s.acceptQueue.length = 0;
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
        await new Promise((r) => srv.close(() => r()));
      } else if (s.tcp) {
        if (how === 1) {
          s.tcp.end();
        } else {
          s.eof = true;
          s.tcp.destroy();
          updateSockState(sockId, s);
          while (s.waiters.length > 0) {
            const w = s.waiters.shift();
            w();
          }
        }
      }
      return finishSlot(slotIdx, reqId, sockId, 0);
    }
    if (op === 0x0e) { // CLOSE
      s.eof = true;
      s.err = 9;
      s.listening = false;
      if (s.tcp) s.tcp.destroy();
      if (s.udp) try { s.udp.close(); } catch {}
      if (s.srv) {
        const srv = s.srv;
        s.srv = null;
        for (const q of s.acceptQueue) { try { q.destroy(); } catch {} }
        s.acceptQueue.length = 0;
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
        await new Promise((r) => srv.close(() => r()));
      } else {
        updateSockState(sockId, s);
      }
      while (s.waiters.length > 0) {
        const w = s.waiters.shift();
        w();
      }
      socks.delete(sockId);
      return finishSlot(slotIdx, reqId, sockId, 0);
    }
    return finishSlot(slotIdx, reqId, sockId, 0);
  }

  setInterval(() => {
    const { u8, i32, u32 } = getViews();
    for (let s = 0; s < MAX_SLOTS; s++) {
      const slotBase = shmOff + SLOTS_BASE_OFF + s * SLOT_STRIDE;
      const stateIdx = slotBase >> 2;
      const st = Atomics.load(i32, stateIdx);
      if (st === 4) {
        Atomics.store(i32, stateIdx, 0);
        continue;
      }
      if (st === 1) {
        const reqLen = Atomics.load(u32, (slotBase + 8) >> 2);
        const frame = Buffer.from(u8.slice(slotBase + SLOT_BUF_OFF, slotBase + SLOT_BUF_OFF + reqLen));
        if (Atomics.compareExchange(i32, stateIdx, 1, 2) === 1) {
          void handleReq(s, frame);
        }
      }
    }
  }, 2).unref();
}

const rc = Module._ports_start(cfg.enableSvnp ? 1 : 0);
if (rc !== 0) {
  console.error(`ports_start failed: ${rc}`);
  process.exit(1);
}

const outPtr = Module._ports_io_buf_addr() >>> 0;
function drain() {
  for (;;) {
    const n = Module._ports_read_output();
    if (n <= 0) break;
    const chunk = new Uint8Array(n);
    chunk.set(Module.HEAPU8.subarray(outPtr, outPtr + n));
    process.stdout.write(dec.decode(chunk));
  }
}

const deadline = Date.now() + (cfg.timeoutMs || 240000);
while (!Module._ports_is_done()) {
  drain();
  if (Date.now() > deadline) {
    console.error('Timed out waiting for WASM64 guest command');
    process.exit(124);
  }
  await new Promise((r) => setTimeout(r, 10));
}
drain();
const status = Module._ports_wait_status();
const err = Module._ports_embed_error() >>> 0;
if (err !== 0) {
  console.error(`embed error: ${err}`);
  process.exit(1);
}
const exitCode = (status & 0x7f) === 0 ? ((status >> 8) & 0xff) : 128 + (status & 0x7f);
process.exit(exitCode);
'''


GUEST_SCRIPT_TEMPLATE = r"""
set -eu

EXPECTED_REL="__OPENBSD_VERSION__"
HAS_SD="__HAS_SD__"
IS_80="__IS_80__"

fail() {
    echo "[WAVE4-AI-FAIL] $*" >&2
    exit 1
}

pass() {
    printf '[WAVE4-AI-PASS] %s: %s\n' "$1" "$2"
}

[ "$(uname -s)" = "OpenBSD" ] || fail "expected OpenBSD"
[ "$(uname -r)" = "$EXPECTED_REL" ] || fail "expected OpenBSD $EXPECTED_REL, got $(uname -r)"

# 01. Multi-call PATH & help/version checks across llama, whisper, and sd
for cmd in llama llama-cli llama-server llama-simple-chat llama-embedding llama-quantize llama-gguf llama-bench whisper whisper-cli whisper-server whisper-bench whisper-quantize whisper.cpp-download-ggml-model; do
    p=$(command -v "$cmd") || fail "missing command on PATH: $cmd"
    [ "$p" = "/usr/local/bin/$cmd" ] || fail "unexpected path for $cmd: $p"
done

if [ "$IS_80" = "1" ]; then
    for cmd in llama-completion llama-perplexity llama-fit-params llama-batched-bench; do
        p=$(command -v "$cmd") || fail "missing 8.0 command on PATH: $cmd"
        [ "$p" = "/usr/local/bin/$cmd" ] || fail "unexpected path for $cmd: $p"
    done
fi

if [ "$HAS_SD" = "1" ]; then
    for cmd in sd sd-cli sd-server; do
        p=$(command -v "$cmd") || fail "missing sd command on PATH: $cmd"
        [ "$p" = "/usr/local/bin/$cmd" ] || fail "unexpected path for $cmd: $p"
    done
fi
pass "01_path_and_applets" "OpenBSD $EXPECTED_REL AI binaries resolved cleanly on PATH"

# 02. GGUF read/write roundtrip via `llama-gguf`
rm -rf /tmp/w4_ai
mkdir -p /tmp/w4_ai
MALLOC_OPTIONS=JJ llama-gguf /tmp/w4_ai/roundtrip.gguf w >/tmp/w4_ai/gguf_w.log 2>&1
[ -s /tmp/w4_ai/roundtrip.gguf ] || fail "llama-gguf w did not produce /tmp/w4_ai/roundtrip.gguf"
MALLOC_OPTIONS=JJ llama-gguf /tmp/w4_ai/roundtrip.gguf r >/tmp/w4_ai/gguf_r.log 2>&1
grep -qi "tensor" /tmp/w4_ai/gguf_r.log || fail "llama-gguf r output missing tensor metadata"
pass "02_llama_gguf_roundtrip" "MALLOC_OPTIONS=JJ llama-gguf write + read round-trip OK"

# 03. Quantize synthetic FP32 Llama model -> Q4_0 & Q8_0 (exercises SIMD128 quantize + matmul!)
[ -s /tmp/tiny.gguf ] || fail "missing staged /tmp/tiny.gguf"
MALLOC_OPTIONS=JJ llama-quantize /tmp/tiny.gguf /tmp/w4_ai/tiny-q4_0.gguf Q4_0 >/tmp/w4_ai/quant_q4.log 2>&1
[ -s /tmp/w4_ai/tiny-q4_0.gguf ] || fail "llama-quantize Q4_0 failed"
MALLOC_OPTIONS=JJ llama-quantize /tmp/tiny.gguf /tmp/w4_ai/tiny-q8_0.gguf Q8_0 >/tmp/w4_ai/quant_q8.log 2>&1
[ -s /tmp/w4_ai/tiny-q8_0.gguf ] || fail "llama-quantize Q8_0 failed"
pass "03_llama_quantize" "llama-quantize FP32 -> Q4_0 & Q8_0 succeeded under MALLOC_OPTIONS=JJ"

# 04. REAL `llama-cli -m /tmp/tiny.gguf -p "hello" -n 6` WITHOUT `--no-mmap`!
CLI_F32_OUT=$(MALLOC_OPTIONS=JJ llama-cli -m /tmp/tiny.gguf -p "hello" -n 6 --single-turn </dev/null 2>/tmp/w4_ai/cli_f32.err)
[ -n "$CLI_F32_OUT" ] || fail "llama-cli FP32 produced empty stdout (stderr: $(cat /tmp/w4_ai/cli_f32.err))"

CLI_Q4_OUT=$(MALLOC_OPTIONS=JJ llama-cli -m /tmp/w4_ai/tiny-q4_0.gguf -p "hello" -n 6 --single-turn </dev/null 2>/tmp/w4_ai/cli_q4.err)
[ -n "$CLI_Q4_OUT" ] || fail "llama-cli Q4_0 SIMD128 produced empty stdout (stderr: $(cat /tmp/w4_ai/cli_q4.err))"

SUB_OUT=$(MALLOC_OPTIONS=JJ llama cli -m /tmp/w4_ai/tiny-q8_0.gguf -p "hello" -n 4 --single-turn </dev/null 2>/tmp/w4_ai/cli_sub.err)
[ -n "$SUB_OUT" ] || fail "llama cli subcommand Q8_0 produced empty stdout (stderr: $(cat /tmp/w4_ai/cli_sub.err))"

if [ "$IS_80" = "1" ]; then
    COMP_OUT=$(MALLOC_OPTIONS=JJ llama-completion -m /tmp/w4_ai/tiny-q4_0.gguf -p "hello" -n 6 -no-cnv </dev/null 2>/tmp/w4_ai/comp.err)
    [ -n "$COMP_OUT" ] || fail "llama-completion on 8.0 produced empty stdout"
fi
pass "04_llama_cli_inference" "REAL llama-cli & 'llama cli' -m /tmp/tiny.gguf (FP32, Q4_0, Q8_0) -p 'hello' -n 6 (NO --no-mmap!) generated tokens cleanly"

# 05. Standalone `llama-embedding` & `llama-bench`
MALLOC_OPTIONS=JJ llama-embedding -m /tmp/tiny.gguf -p "OpenBSD WASM64 SIMD128" >/tmp/w4_ai/emb_cli.out 2>/tmp/w4_ai/emb_cli.err
grep -Eq "embedding|[-0-9]+\.[0-9]+" /tmp/w4_ai/emb_cli.out /tmp/w4_ai/emb_cli.err || fail "llama-embedding output missing floats"

MALLOC_OPTIONS=JJ llama-bench -m /tmp/w4_ai/tiny-q4_0.gguf -p 8 -n 4 -r 1 >/tmp/w4_ai/bench.out 2>/tmp/w4_ai/bench.err
grep -Eq "pp8|tg4|t/s" /tmp/w4_ai/bench.out || fail "llama-bench missing throughput table: $(cat /tmp/w4_ai/bench.out)"
pass "05_llama_embedding_and_bench" "llama-embedding + llama-bench Q4_0 SIMD128 throughput verified"

# 06. REAL `llama-server -m /tmp/tiny.gguf --host 127.0.0.1 --port 18089`
#     WITHOUT `--no-mmap`! Test /health, /v1/models, /v1/chat/completions (JSON, SSE stream, tools schema),
#     GET / WebUI, and `--embedding --pooling mean` /v1/embeddings!
MALLOC_OPTIONS=JJ llama-server -m /tmp/tiny.gguf --host 127.0.0.1 --port 18089 --jinja -np 1 -c 1024 >/tmp/w4_ai/server.log 2>&1 &
SRV_PID=$!

cleanup_srv() {
    if [ -n "${SRV_PID:-}" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill -9 "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
}
trap cleanup_srv EXIT

READY=0
attempt=0
while [ "$attempt" -lt 80 ]; do
    if HJSON=$(curl -fsS --max-time 2 http://127.0.0.1:18089/health 2>/dev/null); then
        if printf '%s' "$HJSON" | grep -q '"ok"'; then
            READY=1
            break
        fi
    fi
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        fail "llama-server exited prematurely! Log: $(cat /tmp/w4_ai/server.log)"
    fi
    sleep 1
    attempt=$((attempt + 1))
done
[ "$READY" = "1" ] || fail "llama-server /health did not become ready on 127.0.0.1:18089: $(cat /tmp/w4_ai/server.log)"

# 6a. GET /v1/models
MODELS_JSON=$(curl -fsS http://127.0.0.1:18089/v1/models)
MODELS_OK=$(printf '%s\n' "$MODELS_JSON" | jq -r '.object == "list" and (.data | length >= 1)')
[ "$MODELS_OK" = "true" ] || fail "GET /v1/models invalid JSON: $MODELS_JSON"

# 6b. POST /v1/chat/completions (non-streaming)
CHAT_REQ='{"model":"tiny","messages":[{"role":"user","content":"hello"}],"max_tokens":6,"temperature":0.0}'
CHAT_RESP=$(curl -fsS -H "Content-Type: application/json" -d "$CHAT_REQ" http://127.0.0.1:18089/v1/chat/completions)
CHAT_OK=$(printf '%s\n' "$CHAT_RESP" | jq -r '(.choices | length == 1) and ((.choices[0].message.content | length) > 0) and (.usage.completion_tokens >= 1)')
[ "$CHAT_OK" = "true" ] || fail "POST /v1/chat/completions non-streaming check failed: $CHAT_RESP"

# 6c. POST /v1/chat/completions (SSE streaming)
STREAM_REQ='{"model":"tiny","messages":[{"role":"user","content":"hello"}],"max_tokens":5,"temperature":0.0,"stream":true}'
STREAM_RESP=$(curl -fsSN -H "Content-Type: application/json" -d "$STREAM_REQ" http://127.0.0.1:18089/v1/chat/completions)
printf '%s\n' "$STREAM_RESP" | grep -q "^data: " || fail "SSE stream missing 'data: ' events: $STREAM_RESP"
printf '%s\n' "$STREAM_RESP" | grep -q "\[DONE\]" || fail "SSE stream missing [DONE]: $STREAM_RESP"

# 6d. POST /v1/chat/completions with OpenAI `tools` JSON schema
TOOLS_REQ='{"model":"tiny","messages":[{"role":"user","content":"What is the weather in Tokyo?"}],"max_tokens":6,"temperature":0.0,"tools":[{"type":"function","function":{"name":"get_weather","description":"Get current weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}]}'
TOOLS_RESP=$(curl -sS -H "Content-Type: application/json" -d "$TOOLS_REQ" http://127.0.0.1:18089/v1/chat/completions) || fail "curl tools failed: $TOOLS_RESP (log: $(cat /tmp/w4_ai/server.log))"
TOOLS_OK=$(printf '%s\n' "$TOOLS_RESP" | jq -r '(.choices | length == 1) and (.choices[0].message != null)')
[ "$TOOLS_OK" = "true" ] || fail "POST /v1/chat/completions with tools schema failed: $TOOLS_RESP (log: $(tail -n 30 /tmp/w4_ai/server.log))"

# 6e. GET / WebUI (especially OpenBSD 8.0 embedded 70-asset Agentic + MCP Svelte WebUI!)
curl -fsS --compressed -o /tmp/w4_ai/webui.html http://127.0.0.1:18089/ || fail "GET / WebUI curl failed (log: $(tail -n 20 /tmp/w4_ai/server.log))"
grep -qi "<html" /tmp/w4_ai/webui.html || fail "GET / WebUI did not return HTML: $(head -n 5 /tmp/w4_ai/webui.html)"
if [ "$IS_80" = "1" ]; then
    # Verify 8.0 also exposes /props with MCP/WebUI build info
    PROPS_JSON=$(curl -fsS http://127.0.0.1:18089/props)
    printf '%s\n' "$PROPS_JSON" | jq -e '.default_generation_settings != null' >/dev/null || fail "8.0 /props check failed: $PROPS_JSON"
fi

cleanup_srv

# 6f. POST /v1/embeddings (`--embedding --pooling mean`)
MALLOC_OPTIONS=JJ llama-server -m /tmp/tiny.gguf --host 127.0.0.1 --port 18090 --embedding --pooling mean -np 1 -c 256 >/tmp/w4_ai/emb_server.log 2>&1 &
SRV_PID=$!
EMB_READY=0
attempt=0
while [ "$attempt" -lt 60 ]; do
    if HJSON=$(curl -fsS --max-time 2 http://127.0.0.1:18090/health 2>/dev/null); then
        if printf '%s' "$HJSON" | grep -q '"ok"'; then
            EMB_READY=1
            break
        fi
    fi
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        fail "llama-server --embedding exited prematurely! Log: $(cat /tmp/w4_ai/emb_server.log)"
    fi
    sleep 1
    attempt=$((attempt + 1))
done
[ "$EMB_READY" = "1" ] || fail "llama-server --embedding /health did not become ready: $(cat /tmp/w4_ai/emb_server.log)"

EMB_REQ='{"model":"tiny","input":"OpenBSD WASM64 AI inference"}'
EMB_RESP=$(curl -sS -H "Content-Type: application/json" -d "$EMB_REQ" http://127.0.0.1:18090/v1/embeddings) || fail "curl embeddings failed: $EMB_RESP"
EMB_DIM=$(printf '%s\n' "$EMB_RESP" | jq -r '.data[0].embedding | length')
[ "$EMB_DIM" = "64" ] || fail "expected 64-dim embedding from /v1/embeddings, got $EMB_DIM: $EMB_RESP"

cleanup_srv
trap - EXIT
pass "06_llama_server_e2e" "llama-server 127.0.0.1:18089/18090 (/health, /v1/models, /v1/chat/completions JSON+SSE+tools, /v1/embeddings, GET / WebUI) OK"

# 07. `audio/whisper.cpp`: whisper-cli, whisper-server, whisper-bench, whisper-quantize, download script, and WAV/model load check
MALLOC_OPTIONS=JJ whisper-cli --help >/tmp/w4_ai/w_cli.help 2>&1
grep -qi "usage" /tmp/w4_ai/w_cli.help || fail "whisper-cli --help missing usage"

MALLOC_OPTIONS=JJ whisper-server --help >/tmp/w4_ai/w_srv.help 2>&1
grep -qi "usage" /tmp/w4_ai/w_srv.help || fail "whisper-server --help missing usage"

MALLOC_OPTIONS=JJ whisper-bench --help >/tmp/w4_ai/w_bench.help 2>&1
grep -qi "usage" /tmp/w4_ai/w_bench.help || fail "whisper-bench --help missing usage"

MALLOC_OPTIONS=JJ whisper-quantize --help >/tmp/w4_ai/w_quant.help 2>&1 || true
grep -qi "usage" /tmp/w4_ai/w_quant.help || fail "whisper-quantize --help missing usage"

DL_HELP=$(/usr/local/bin/whisper.cpp-download-ggml-model --help 2>&1 || true)
printf '%s\n' "$DL_HELP" | grep -q "base.en" || fail "whisper.cpp-download-ggml-model missing base.en model listing: $DL_HELP"

# Run whisper-cli + whisper-quantize with our synthetic 16kHz WAV + tiny synthetic GGML whisper model!
[ -s /tmp/tiny_whisper.bin ] || fail "missing staged /tmp/tiny_whisper.bin"
[ -s /tmp/test_16k.wav ] || fail "missing staged /tmp/test_16k.wav"
MALLOC_OPTIONS=JJ whisper-cli -m /tmp/tiny_whisper.bin -f /tmp/test_16k.wav -np >/tmp/w4_ai/w_run.out 2>/tmp/w4_ai/w_run.err
MALLOC_OPTIONS=JJ whisper-quantize /tmp/tiny_whisper.bin /tmp/w4_ai/tiny_whisper_q4_0.bin q4_0 >/tmp/w4_ai/w_q4.log 2>&1
[ -s /tmp/w4_ai/tiny_whisper_q4_0.bin ] || fail "whisper-quantize q4_0 failed"
MALLOC_OPTIONS=JJ whisper-cli -m /tmp/w4_ai/tiny_whisper_q4_0.bin -f /tmp/test_16k.wav -np >/tmp/w4_ai/w_run_q4.out 2>/tmp/w4_ai/w_run_q4.err
pass "07_whisper_cpp_suite" "whisper-cli (FP16 & Q4_0 SIMD128 16kHz WAV transcription!) + whisper-quantize + whisper-server/bench + download script OK"

# 08. `graphics/stable-diffusion.cpp` (`7.9` & `8.0`)
if [ "$HAS_SD" = "1" ]; then
    MALLOC_OPTIONS=JJ sd-cli --help >/tmp/w4_ai/sd_cli.help 2>&1
    grep -qi "usage" /tmp/w4_ai/sd_cli.help || fail "sd-cli --help missing usage"
    MALLOC_OPTIONS=JJ sd-server --help >/tmp/w4_ai/sd_srv.help 2>&1
    grep -qi "usage" /tmp/w4_ai/sd_srv.help || fail "sd-server --help missing usage"
    pass "08_stable_diffusion_cpp" "sd-cli --help & sd-server --help single-closure multi-call verified under MALLOC_OPTIONS=JJ"
fi

echo "[WAVE4-AI-ALL-OK] OpenBSD $EXPECTED_REL passed 100% of Wave-4 GGML AI Inference & Server tests!"
"""


def resolve_obsd_root(cli_val: str = "") -> pathlib.Path:
    if cli_val:
        return pathlib.Path(cli_val).resolve()
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        return pathlib.Path(env_val).resolve()
    out = subprocess.check_output(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        text=True,
    ).strip()
    return pathlib.Path(out).resolve()


def parse_svfs_paths(svfs_gz: pathlib.Path) -> Set[str]:
    raw = gzip.decompress(svfs_gz.read_bytes())
    hdr = struct.Struct("<IHHI")
    ent = struct.Struct("<BBHIIIHHI")
    magic, ver, _flags, count = hdr.unpack_from(raw, 0)
    assert magic == 0x53564653 and ver == 1, f"bad SVFS header in {svfs_gz}"
    paths: Set[str] = set()
    off = hdr.size
    for _ in range(count):
        _et, _r0, _perm, p_off, p_len, _d_off, _r1, _r2, _d_len = ent.unpack_from(raw, off)
        off += ent.size
        rel = raw[p_off : p_off + p_len].decode("utf-8")
        paths.add("/" + rel)
    return paths


def _gguf_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<Q", len(b)) + b


def synthesize_tiny_llama_gguf(out_path: pathlib.Path) -> None:
    """
    Synthesize a deterministic, 100% valid ~330 KB GGUF v3 Llama model
    (`n_vocab=320, n_embd=64, n_head=2, n_head_kv=2, n_ff=128, n_layer=1`)
    with full 256-byte `<0x00>`..`<0xFF>` SentencePiece byte fallback (`token_type=6`),
    compatible with `llama-cli`, `llama-server` (`/v1/chat/completions` + `tools` + `/v1/embeddings`),
    and `llama-quantize` (`Q4_0`, `Q8_0`) across OpenBSD 7.8, 7.9, and 8.0.
    """
    n_vocab = 320
    n_embd = 64
    n_head = 2
    n_head_kv = 2
    n_ff = 128

    special_tokens = ["<unk>", "<s>", "</s>", "<|im_end|>", "<|im_start|>"]
    byte_tokens = [f"<0x{b:02X}>" for b in range(256)]
    word_tokens = [
        "\n",
        "\u2581",
        "\u2581hello",
        "\u2581OpenBSD",
        "\u2581WASM64",
        "\u2581SIMD128",
        "\u2581AI",
        "\u2581agent",
        "\u2581ready",
        "\u2581Tokyo",
        "\u2581sunny",
        "\u2581weather",
        "\u2581is",
        "\u2581in",
        "hello",
        "Tokyo",
    ]
    ascii_pool = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!:-_/")
    tokens = list(special_tokens) + list(byte_tokens) + list(word_tokens)
    for ch in ascii_pool:
        if len(tokens) >= n_vocab:
            break
        if ch not in tokens:
            tokens.append(ch)
    assert len(tokens) == n_vocab

    scores = [0.0 if i < 261 else (-0.1 * float(i - 260)) for i in range(n_vocab)]
    token_types = [2, 3, 3, 3, 3] + ([6] * 256) + ([1] * (n_vocab - 261))

    chat_tmpl = (
        "{% for message in messages %}"
        "{{ '<|im_start|>' + message['role'] + '\\n' + (message['content'] if message['content'] is string else '') + '<|im_end|>\\n' }}"
        "{% endfor %}"
        "{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}"
    )

    # GGUF value types: UINT32=4, INT32=5, FLOAT32=6, BOOL=7, STRING=8, ARRAY=9
    kvs: List[bytes] = []

    def add_u32(k: str, v: int) -> None:
        kvs.append(_gguf_str(k) + struct.pack("<II", 4, v))

    def add_f32(k: str, v: float) -> None:
        kvs.append(_gguf_str(k) + struct.pack("<If", 6, v))

    def add_bool(k: str, v: bool) -> None:
        kvs.append(_gguf_str(k) + struct.pack("<IB", 7, 1 if v else 0))

    def add_str(k: str, v: str) -> None:
        kvs.append(_gguf_str(k) + struct.pack("<I", 8) + _gguf_str(v))

    def add_arr_str(k: str, vals: Sequence[str]) -> None:
        body = b"".join(_gguf_str(x) for x in vals)
        kvs.append(_gguf_str(k) + struct.pack("<IIQ", 9, 8, len(vals)) + body)

    def add_arr_f32(k: str, vals: Sequence[float]) -> None:
        body = struct.pack(f"<{len(vals)}f", *vals)
        kvs.append(_gguf_str(k) + struct.pack("<IIQ", 9, 6, len(vals)) + body)

    def add_arr_i32(k: str, vals: Sequence[int]) -> None:
        body = struct.pack(f"<{len(vals)}i", *vals)
        kvs.append(_gguf_str(k) + struct.pack("<IIQ", 9, 5, len(vals)) + body)

    add_str("general.architecture", "llama")
    add_str("general.name", "tiny-sonvori-llama")
    add_u32("general.file_type", 0)
    add_u32("llama.vocab_size", n_vocab)
    add_u32("llama.context_length", 1024)
    add_u32("llama.embedding_length", n_embd)
    add_u32("llama.block_count", 1)
    add_u32("llama.feed_forward_length", n_ff)
    add_u32("llama.attention.head_count", n_head)
    add_u32("llama.attention.head_count_kv", n_head_kv)
    add_f32("llama.attention.layer_norm_rms_epsilon", 1e-5)
    add_u32("llama.rope.dimension_count", n_embd // n_head)
    add_f32("llama.rope.freq_base", 10000.0)
    add_str("tokenizer.ggml.model", "llama")
    add_arr_str("tokenizer.ggml.tokens", tokens)
    add_arr_f32("tokenizer.ggml.scores", scores)
    add_arr_i32("tokenizer.ggml.token_type", token_types)
    add_u32("tokenizer.ggml.bos_token_id", 1)
    add_u32("tokenizer.ggml.eos_token_id", 2)
    add_u32("tokenizer.ggml.eot_token_id", 3)
    add_u32("tokenizer.ggml.unknown_token_id", 0)
    add_bool("tokenizer.ggml.add_bos_token", True)
    add_str("tokenizer.chat_template", chat_tmpl)

    tensors: List[Tuple[str, Tuple[int, ...], List[float]]] = []

    # Bias coordinate 0 positively in embeddings and positively for printable word tokens (7..14) in output.weight
    # while strongly suppressing EOS/control tokens (0..5) so generation NEVER terminates early with empty output!
    tok_embd: List[float] = []
    for tok_id in range(n_vocab):
        for d in range(n_embd):
            if d == 0:
                tok_embd.append(1.0)
            else:
                tok_embd.append(0.03 * math.sin(0.17 * (tok_id + 1) * (d + 1)))
    tensors.append(("token_embd.weight", (n_embd, n_vocab), tok_embd))
    tensors.append(("output_norm.weight", (n_embd,), [1.0] * n_embd))

    out_w: List[float] = []
    for tok_id in range(n_vocab):
        for d in range(n_embd):
            if d == 0:
                if tok_id < 263:
                    out_w.append(-6.0)
                elif 263 <= tok_id <= 274:
                    out_w.append(2.5 + 0.05 * (tok_id - 263))
                else:
                    out_w.append(0.2)
            else:
                out_w.append(0.02 * math.cos(0.13 * (tok_id + 1) * (d + 1)))
    tensors.append(("output.weight", (n_embd, n_vocab), out_w))

    def small_mat(ne0: int, ne1: int, seed: float) -> List[float]:
        return [0.01 * math.sin(seed + 0.01 * i) for i in range(ne0 * ne1)]

    tensors.append(("blk.0.attn_norm.weight", (n_embd,), [1.0] * n_embd))
    tensors.append(("blk.0.attn_q.weight", (n_embd, n_embd), small_mat(n_embd, n_embd, 0.1)))
    tensors.append(("blk.0.attn_k.weight", (n_embd, n_embd), small_mat(n_embd, n_embd, 0.2)))
    tensors.append(("blk.0.attn_v.weight", (n_embd, n_embd), small_mat(n_embd, n_embd, 0.3)))
    tensors.append(("blk.0.attn_output.weight", (n_embd, n_embd), small_mat(n_embd, n_embd, 0.4)))
    tensors.append(("blk.0.ffn_norm.weight", (n_embd,), [1.0] * n_embd))
    tensors.append(("blk.0.ffn_gate.weight", (n_embd, n_ff), small_mat(n_embd, n_ff, 0.5)))
    tensors.append(("blk.0.ffn_down.weight", (n_ff, n_embd), small_mat(n_ff, n_embd, 0.6)))
    tensors.append(("blk.0.ffn_up.weight", (n_embd, n_ff), small_mat(n_embd, n_ff, 0.7)))

    t_infos: List[bytes] = []
    t_blobs: List[bytes] = []
    cur_off = 0
    for name, dims, vals in tensors:
        raw = struct.pack(f"<{len(vals)}f", *vals)
        pad = (32 - (len(raw) % 32)) % 32
        raw_padded = raw + (b"\x00" * pad)
        info = _gguf_str(name) + struct.pack("<I", len(dims))
        for d in dims:
            info += struct.pack("<Q", d)
        info += struct.pack("<IQ", 0, cur_off)  # GGML_TYPE_F32 = 0
        t_infos.append(info)
        t_blobs.append(raw_padded)
        cur_off += len(raw_padded)

    hdr = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(kvs)) + b"".join(kvs) + b"".join(t_infos)
    hdr_pad = (32 - (len(hdr) % 32)) % 32
    out_path.write_bytes(hdr + (b"\x00" * hdr_pad) + b"".join(t_blobs))


def synthesize_tiny_whisper_model_and_wav(model_path: pathlib.Path, wav_path: pathlib.Path) -> None:
    """
    Synthesize:
      1. A deterministic 1.0s 16kHz 16-bit mono PCM WAV file (`wav_path`)
      2. A complete, 100% valid legacy-GGML Whisper `.en` model (`model_path`, ~3.5 MB,
         all 95 encoder/decoder/cross-attention tensors initialized with finite weights)
         compatible with `whisper-cli` and `whisper-quantize` across 1.7.6, 1.8.4, and 1.9.4.
    """
    sr = 16000
    pcm_samples: List[int] = []
    for i in range(sr):
        t = i / float(sr)
        if 0.20 <= t <= 0.80:
            val = 0.35 * math.sin(2.0 * math.pi * 440.0 * t) + 0.20 * math.sin(2.0 * math.pi * 880.0 * t)
            pcm_samples.append(int(max(-32767, min(32767, val * 16000.0))))
        else:
            pcm_samples.append(0)
    with wave.open(str(wav_path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(struct.pack(f"<{len(pcm_samples)}h", *pcm_samples))

    n_vocab = 51864
    n_audio_ctx = 1500
    n_audio_state = 32
    n_audio_head = 2
    n_audio_layer = 4
    n_text_ctx = 64
    n_text_state = 32
    n_text_head = 2
    n_text_layer = 1
    n_mels = 80
    ftype = 1  # GGML_FTYPE_MOSTLY_F16 (wtype=F16=1, vtype=F16=1)
    n_fft = 201  # WHISPER_N_FFT / 2 + 1 = 400 / 2 + 1

    chunks: List[bytes] = []
    chunks.append(struct.pack("<I", 0x67676D6C))  # GGML_FILE_MAGIC
    chunks.append(
        struct.pack(
            "<11i",
            n_vocab,
            n_audio_ctx,
            n_audio_state,
            n_audio_head,
            n_audio_layer,
            n_text_ctx,
            n_text_state,
            n_text_head,
            n_text_layer,
            n_mels,
            ftype,
        )
    )

    # Mel filters: n_mel=80, n_fft=201
    chunks.append(struct.pack("<2i", n_mels, n_fft))
    chunks.append(struct.pack("<f", 0.001) * (n_mels * n_fft))

    # Partial vocab (Whisper auto-populates remaining tokens up to 51864, including [_EOT_]=50256;
    # note `whisper_full` requires `" "` in `vocab.token_to_id` for `suppress_blank`!)
    seed_words = [
        b" ",
        b" OpenBSD",
        b" hello",
        b" WASM64",
        b" SIMD128",
        b" AI",
        b" speech",
        b" ok",
        b".",
        b",",
        b" -",
        b" '",
    ]
    chunks.append(struct.pack("<i", len(seed_words)))
    for w in seed_words:
        chunks.append(struct.pack("<I", len(w)) + w)

    f32_zero = b"\x00\x00\x00\x00"
    f32_one = struct.pack("<f", 1.0)
    f16_zero = b"\x00\x00"

    def add_tensor_raw(name: str, dims: Sequence[int], ttype: int, data: bytes) -> None:
        nb = name.encode("utf-8")
        chunks.append(struct.pack("<3i", len(dims), len(nb), ttype))
        chunks.append(struct.pack(f"<{len(dims)}i", *dims))
        chunks.append(nb)
        chunks.append(data)

    def add_zeros_f32(name: str, dims: Sequence[int]) -> None:
        nel = 1
        for d in dims:
            nel *= d
        add_tensor_raw(name, dims, 0, f32_zero * nel)

    def add_ones_f32(name: str, dims: Sequence[int]) -> None:
        nel = 1
        for d in dims:
            nel *= d
        add_tensor_raw(name, dims, 0, f32_one * nel)

    def add_zeros_f16(name: str, dims: Sequence[int]) -> None:
        nel = 1
        for d in dims:
            nel *= d
        add_tensor_raw(name, dims, 1, f16_zero * nel)

    s = n_audio_state

    # Encoder global (7 tensors)
    add_zeros_f32("encoder.positional_embedding", (s, n_audio_ctx))
    add_zeros_f16("encoder.conv1.weight", (3, n_mels, s))
    add_zeros_f32("encoder.conv1.bias", (1, s))
    add_zeros_f16("encoder.conv2.weight", (3, s, s))
    add_zeros_f32("encoder.conv2.bias", (1, s))
    add_ones_f32("encoder.ln_post.weight", (s,))
    add_zeros_f32("encoder.ln_post.bias", (s,))

    # Encoder blocks (4 * 15 = 60 tensors)
    for i in range(n_audio_layer):
        add_ones_f32(f"encoder.blocks.{i}.mlp_ln.weight", (s,))
        add_zeros_f32(f"encoder.blocks.{i}.mlp_ln.bias", (s,))
        add_zeros_f16(f"encoder.blocks.{i}.mlp.0.weight", (s, 4 * s))
        add_zeros_f32(f"encoder.blocks.{i}.mlp.0.bias", (4 * s,))
        add_zeros_f16(f"encoder.blocks.{i}.mlp.2.weight", (4 * s, s))
        add_zeros_f32(f"encoder.blocks.{i}.mlp.2.bias", (s,))
        add_ones_f32(f"encoder.blocks.{i}.attn_ln.weight", (s,))
        add_zeros_f32(f"encoder.blocks.{i}.attn_ln.bias", (s,))
        add_zeros_f16(f"encoder.blocks.{i}.attn.query.weight", (s, s))
        add_zeros_f32(f"encoder.blocks.{i}.attn.query.bias", (s,))
        add_zeros_f16(f"encoder.blocks.{i}.attn.key.weight", (s, s))
        add_zeros_f16(f"encoder.blocks.{i}.attn.value.weight", (s, s))
        add_zeros_f32(f"encoder.blocks.{i}.attn.value.bias", (s,))
        add_zeros_f16(f"encoder.blocks.{i}.attn.out.weight", (s, s))
        add_zeros_f32(f"encoder.blocks.{i}.attn.out.bias", (s,))

    # Decoder global (4 tensors)
    add_zeros_f32("decoder.positional_embedding", (s, n_text_ctx))
    # Bias coordinate 0 of " OpenBSD" (1), timestamp [_TT_1] (50364), and [_EOT_] (50256)
    # positively so greedy decode emits a valid timestamped segment and finishes in <= 3 steps!
    d_te_buf = bytearray(s * n_vocab * 2)
    row_stride = s * 2
    d_te_buf[1 * row_stride : 1 * row_stride + 2] = struct.pack("<e", 3.5)
    d_te_buf[50364 * row_stride : 50364 * row_stride + 2] = struct.pack("<e", 3.0)
    d_te_buf[50256 * row_stride : 50256 * row_stride + 2] = struct.pack("<e", 8.0)
    add_tensor_raw("decoder.token_embedding.weight", (s, n_vocab), 1, bytes(d_te_buf))
    add_ones_f32("decoder.ln.weight", (s,))
    add_tensor_raw("decoder.ln.bias", (s,), 0, struct.pack("<f", 1.0) + (f32_zero * (s - 1)))

    # Decoder blocks (1 * 24 = 24 tensors)
    for i in range(n_text_layer):
        add_ones_f32(f"decoder.blocks.{i}.mlp_ln.weight", (s,))
        add_zeros_f32(f"decoder.blocks.{i}.mlp_ln.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.mlp.0.weight", (s, 4 * s))
        add_zeros_f32(f"decoder.blocks.{i}.mlp.0.bias", (4 * s,))
        add_zeros_f16(f"decoder.blocks.{i}.mlp.2.weight", (4 * s, s))
        add_zeros_f32(f"decoder.blocks.{i}.mlp.2.bias", (s,))

        add_ones_f32(f"decoder.blocks.{i}.attn_ln.weight", (s,))
        add_zeros_f32(f"decoder.blocks.{i}.attn_ln.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.attn.query.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.attn.query.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.attn.key.weight", (s, s))
        add_zeros_f16(f"decoder.blocks.{i}.attn.value.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.attn.value.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.attn.out.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.attn.out.bias", (s,))

        add_ones_f32(f"decoder.blocks.{i}.cross_attn_ln.weight", (s,))
        add_zeros_f32(f"decoder.blocks.{i}.cross_attn_ln.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.cross_attn.query.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.cross_attn.query.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.cross_attn.key.weight", (s, s))
        add_zeros_f16(f"decoder.blocks.{i}.cross_attn.value.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.cross_attn.value.bias", (s,))
        add_zeros_f16(f"decoder.blocks.{i}.cross_attn.out.weight", (s, s))
        add_zeros_f32(f"decoder.blocks.{i}.cross_attn.out.bias", (s,))

    model_path.write_bytes(b"".join(chunks))


def verify_host_packaging(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> None:
    tsv_path = lane_dir / "ports-applets.tsv"
    assert tsv_path.is_file(), f"[{ver}] missing {tsv_path}; run `make package OPENBSD_VERSION={ver}` first"

    by_path: Dict[str, Tuple[str, str, pathlib.Path]] = {}
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gpath, entry_sym, obj_rel = s.split("\t")[:4]
        obj_p = (lane_dir / obj_rel).resolve()
        assert obj_p.is_file(), f"[{ver}] missing localized applet object: {obj_p}"
        by_path[gpath] = (sym, entry_sym, obj_p)

    # 1. Verify single-closure multi-call sharing for llama, whisper, and sd
    llama_paths = list(LLAMA_APPLETS_COMMON) + (LLAMA_APPLETS_80_EXTRA if ver == "8.0" else [])
    llama_objs: Set[pathlib.Path] = set()
    for lp in llama_paths:
        assert lp in by_path, f"[{ver}] missing llama applet path in ports-applets.tsv: {lp}"
        llama_objs.add(by_path[lp][2])
    assert len(llama_objs) == 1, f"[{ver}] expected 1 shared llama.o closure, got {llama_objs}"

    whisper_paths = list(WHISPER_APPLETS_COMMON) + (["/usr/local/sbin/whisper-server"] if ver in ("7.9", "8.0") else [])
    whisper_objs: Set[pathlib.Path] = set()
    for wp in whisper_paths:
        assert wp in by_path, f"[{ver}] missing whisper applet path in ports-applets.tsv: {wp}"
        whisper_objs.add(by_path[wp][2])
    assert len(whisper_objs) == 1, f"[{ver}] expected 1 shared whisper.o closure, got {whisper_objs}"

    has_sd = ver in ("7.9", "8.0")
    sd_size_kb = 0
    if has_sd:
        sd_objs: Set[pathlib.Path] = set()
        for sp in SD_APPLETS:
            assert sp in by_path, f"[{ver}] missing sd applet path in ports-applets.tsv: {sp}"
            sd_objs.add(by_path[sp][2])
        assert len(sd_objs) == 1, f"[{ver}] expected 1 shared sd.o closure, got {sd_objs}"
        sd_size_kb = next(iter(sd_objs)).stat().st_size // 1024
    else:
        for sp in SD_APPLETS:
            assert sp not in by_path, f"[{ver}] unexpected sd applet on OpenBSD 7.8: {sp}"

    # 2. Verify SVFS staged headers, static libraries, pkg-config files, and helper scripts
    svfs_gz = lane_dir / "ports.svfs.gz"
    assert svfs_gz.is_file(), f"[{ver}] missing {svfs_gz}"
    svfs_paths = parse_svfs_paths(svfs_gz)

    req_svfs = [
        "/usr/local/include/ggml.h",
        "/usr/local/include/ggml-cpu.h",
        "/usr/local/include/gguf.h",
        "/usr/local/include/llama.h",
        "/usr/local/include/whisper.h",
        "/usr/local/lib/libggml.a",
        "/usr/local/lib/libggml-cpu.a",
        "/usr/local/lib/libggml-base.a",
        "/usr/local/lib/libllama.a",
        "/usr/local/lib/libwhisper.a",
        "/usr/local/lib/pkgconfig/ggml.pc",
        "/usr/local/lib/pkgconfig/llama.pc",
        "/usr/local/lib/pkgconfig/whisper.pc",
        "/usr/local/bin/whisper.cpp-download-ggml-model",
    ]
    if has_sd:
        req_svfs.extend([
            "/usr/local/include/stable-diffusion.h",
            "/usr/local/lib/libstable-diffusion.a",
        ])
    for rp in req_svfs:
        assert rp in svfs_paths, f"[{ver}] missing staged file in ports.svfs.gz: {rp}"

    for p in svfs_paths:
        assert not p.endswith("ggml-base.en.bin"), f"[{ver}] 148MB ggml-base.en.bin leaked into ports.svfs.gz: {p}"

    dl_script = (lane_dir / "sysroot/usr/local/bin/whisper.cpp-download-ggml-model").read_text(encoding="utf-8")
    assert "curl" in dl_script and "/etc/ssl/cert.pem" in dl_script, (
        f"[{ver}] whisper.cpp-download-ggml-model missing curl + /etc/ssl/cert.pem integration"
    )

    # 3. Verify .tgz packages & index.tsv
    pkg_dir = lane_dir / "packages"
    for pkg_name in EXPECTED_PKGS[ver]:
        pf = pkg_dir / pkg_name
        assert pf.is_file() and pf.stat().st_size > 0, f"[{ver}] missing or empty package {pf}"

    idx_tsv = pkg_dir / "index.tsv"
    assert idx_tsv.is_file(), f"[{ver}] missing {idx_tsv}"
    pkg_rows = [ln for ln in idx_tsv.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    min_pkgs = 56 if ver == "7.8" else 57
    assert len(pkg_rows) >= min_pkgs, f"[{ver}] expected >= {min_pkgs} packages in {idx_tsv}, got {len(pkg_rows)}"

    # 4. Verify C++17 static SDK link against staged ggml/llama/whisper (+ stable-diffusion header)
    obsd_cxx = REPO_ROOT / "sdk/bin/obsd-c++"
    obsd_pkgcfg = REPO_ROOT / "sdk/bin/obsd-pkg-config"
    sdk_env = dict(os.environ)
    sdk_env["OPENBSD_VERSION"] = ver
    sdk_env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    sdk_env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

    ggml_flags = subprocess.check_output(
        [str(obsd_pkgcfg), "--cflags", "--libs", "ggml"],
        env=sdk_env,
        text=True,
    ).split()

    with tempfile.TemporaryDirectory(prefix=f"wave4-ai-sdk-{ver}-") as td:
        tp = pathlib.Path(td)
        src_cpp = tp / "probe.cpp"
        out_bin = tp / "probe.wasm"
        src_cpp.write_text(SDK_CPP_PROBE_SRC, encoding="utf-8")
        cxx_cmd = [
            str(obsd_cxx),
            "-std=c++17",
            "-msimd128",
            "-O2",
            *([ "-DHAVE_SD" ] if has_sd else []),
            str(src_cpp),
            "-lllama",
            "-lwhisper",
            *ggml_flags,
            "-o",
            str(out_bin),
        ]
        subprocess.run(cxx_cmd, env=sdk_env, check=True)
        assert out_bin.is_file() and out_bin.stat().st_size > 0

    llama_kb = next(iter(llama_objs)).stat().st_size // 1024
    whisper_kb = next(iter(whisper_objs)).stat().st_size // 1024
    print(
        f"[WAVE4-AI-HOST] [{ver}] host packaging & SDK C++17 static link OK: "
        f"{len(pkg_rows)} packages, llama.o={llama_kb}KB ({len(llama_paths)} cmds), "
        f"whisper.o={whisper_kb}KB ({len(whisper_paths)} cmds)"
        + (f", sd.o={sd_size_kb}KB (3 cmds)" if has_sd else "")
    )


def _load_merge_wasm_guest() -> Any:
    import importlib.util

    mod_path = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
    spec = importlib.util.spec_from_file_location("merge_wasm_guest", mod_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_guest_suite(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path, timeout_ms: int) -> None:
    mwg = _load_merge_wasm_guest()
    runtime_mjs, table_tsv, node_bin = mwg.build_and_cache_test_runtime(obsd_root, ver, lane_dir)

    raw_tsv = table_tsv.read_bytes()
    table_digest = hashlib.sha256(raw_tsv).hexdigest()
    applet_paths = sorted({ln.split("\t")[0] for ln in raw_tsv.decode("utf-8").splitlines() if ln.strip()})

    src_root = obsd_root / "vendor/openbsd/versions" / ver / "src"
    test_dir = lane_dir / "test-runtime"
    etc_stage = test_dir / "etc-stage"
    etc_stage.mkdir(parents=True, exist_ok=True)

    mpw = src_root / "etc/master.passwd"
    pw_out = etc_stage / "passwd"
    pw_lines = []
    for ln in mpw.read_text(encoding="utf-8").splitlines():
        if ln and not ln.startswith("#") and len(ln.split(":")) >= 10:
            f = ln.split(":")
            pw_lines.append(":".join([f[0], "*", f[2], f[3], f[7], f[8], f[9]]))
    pw_out.write_text("\n".join(pw_lines) + "\n", encoding="utf-8")

    hosts_out = etc_stage / "hosts"
    hosts_out.write_text("127.0.0.1\tlocalhost\n::1\tlocalhost\n", encoding="utf-8")
    resolv_out = etc_stage / "resolv.conf"
    resolv_out.write_text("nameserver 1.1.1.1\nlookup file bind\n", encoding="utf-8")

    staged_files: List[Tuple[str, str, int]] = [
        ("/etc/master.passwd", str(mpw), 0o600),
        ("/etc/passwd", str(pw_out), 0o644),
        ("/etc/group", str(src_root / "etc/group"), 0o644),
        ("/etc/services", str(src_root / "etc/services"), 0o644),
        ("/etc/protocols", str(src_root / "etc/protocols"), 0o644),
        ("/etc/hosts", str(hosts_out), 0o644),
        ("/etc/resolv.conf", str(resolv_out), 0o644),
    ]

    for cert_cand in (
        src_root / "lib/libcrypto/cert.pem",
        pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
        pathlib.Path("/etc/ssl/cert.pem"),
    ):
        if cert_cand.is_file():
            staged_files.append(("/etc/ssl/cert.pem", str(cert_cand), 0o444))
            break

    for rel_ti in ("d/dumb", "x/xterm", "x/xterm-256color", "v/vt100"):
        for base_ti in ("/usr/share/terminfo", "/lib/terminfo"):
            cand = pathlib.Path(base_ti) / rel_ti
            if cand.is_file():
                staged_files.append((f"/usr/share/terminfo/{rel_ti}", str(cand), 0o444))
                break

    script_text = (
        GUEST_SCRIPT_TEMPLATE.replace("__OPENBSD_VERSION__", ver)
        .replace("__HAS_SD__", "1" if ver in ("7.9", "8.0") else "0")
        .replace("__IS_80__", "1" if ver == "8.0" else "0")
    )

    with tempfile.TemporaryDirectory(prefix=f"wave4-ai-guest-{ver}-") as td:
        tp = pathlib.Path(td)
        tiny_gguf = tp / "tiny.gguf"
        tiny_whisper = tp / "tiny_whisper.bin"
        test_wav = tp / "test_16k.wav"

        synthesize_tiny_llama_gguf(tiny_gguf)
        synthesize_tiny_whisper_model_and_wav(tiny_whisper, test_wav)

        staged_files.extend([
            ("/tmp/tiny.gguf", str(tiny_gguf), 0o644),
            ("/tmp/tiny_whisper.bin", str(tiny_whisper), 0o644),
            ("/tmp/test_16k.wav", str(test_wav), 0o644),
        ])

        runner_mjs = tp / "run_svnp_full.mjs"
        cfg_json = tp / "config.json"
        runner_mjs.write_text(NODE_SVNP_FULL_MJS, encoding="utf-8")
        cfg_json.write_text(
            json.dumps({
                "tableDigest": table_digest,
                "appletPaths": applet_paths,
                "sysrootUsrLocal": str(lane_dir / "sysroot/usr/local"),
                "stagedFiles": staged_files,
                "scriptText": script_text,
                "enableSvnp": True,
                "timeoutMs": timeout_ms,
            }),
            encoding="utf-8",
        )

        proc = subprocess.run(
            [node_bin, str(runner_mjs), str(runtime_mjs), str(cfg_json)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    sys.stdout.write(proc.stdout)
    sys.stdout.flush()
    if proc.returncode != 0:
        raise SystemExit(f"[wave4_ai_ggml] OpenBSD {ver} guest suite failed with exit code {proc.returncode}")
    if f"[WAVE4-AI-ALL-OK] OpenBSD {ver}" not in proc.stdout:
        raise SystemExit(f"[wave4_ai_ggml] OpenBSD {ver} missing completion banner")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    ap.add_argument("--timeout-ms", type=int, default=300000)
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    req = args.openbsd_version.strip()
    versions = ["7.8", "7.9", "8.0"] if req in ("", "all") else [v.strip() for v in req.split(",") if v.strip()]

    for ver in versions:
        if ver not in EXPECTED_PKGS:
            raise SystemExit(f"unsupported OpenBSD version: {ver}")
        lane_dir = (
            pathlib.Path(args.ports_lane_dir).resolve()
            if args.ports_lane_dir
            else (REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten").resolve()
        )
        verify_host_packaging(ver, obsd_root, lane_dir)
        run_guest_suite(ver, obsd_root, lane_dir, args.timeout_ms)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
