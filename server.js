const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');
const express = require('express');
const multer = require('multer');
const { WebSocketServer } = require('ws');
const { Client: SSHClient } = require('ssh2');

const PORT = Number(process.env.PORT || 3022);
const TOOL_ACCESS_PIN = String(process.env.TOOL_ACCESS_PIN || '050507').trim();
const SESSION_SECRET = String(process.env.SESSION_SECRET || 'arthur-admin-token-v1').trim();
const ADMIN_AUTH_TOKEN = crypto.createHmac('sha256', SESSION_SECRET).update(TOOL_ACCESS_PIN).digest('hex');
const LEGACY_ADMIN_TOKEN = String(process.env.ADMIN_AUTH_TOKEN || 'arthur_admin_v1').trim();
const HOST_VPS_IP = process.env.HOST_VPS_IP || '172.17.0.1';
const HOST_VPS_PORT = Number(process.env.HOST_VPS_PORT || 22);
const INTERNAL_SSH_KEY_PATH = path.join(__dirname, 'keys', 'id_ed25519');

const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }
});

// Strip /ssh prefix if Nginx passes full URI
app.use((req, _res, next) => {
  if (req.url === '/ssh') {
    req.url = '/';
  } else if (req.url.startsWith('/ssh/')) {
    req.url = req.url.slice(4) || '/';
  } else if (req.url.startsWith('/ssh?')) {
    req.url = '/' + req.url.slice(4);
  }
  next();
});

function parseCookies(req) {
  const raw = req.headers?.cookie || '';
  if (!raw) return {};
  return raw.split(';').reduce((acc, part) => {
    const idx = part.indexOf('=');
    if (idx <= 0) return acc;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    acc[key] = val;
    return acc;
  }, {});
}

// Active Mabar / SSH Rooms
const rooms = new Map();

function getQueryParam(req, name) {
  if (req.query && req.query[name] !== undefined) return req.query[name];
  try {
    const u = new URL(req.url || '/', `http://${req.headers?.host || 'localhost'}`);
    return u.searchParams.get(name) || '';
  } catch {
    return '';
  }
}

function getHeaderVal(req, name) {
  if (typeof req.get === 'function') return req.get(name) || '';
  return req.headers?.[name.toLowerCase()] || '';
}

function isValidAdminToken(token) {
  const t = String(token || '').trim();
  return Boolean(t) && (t === ADMIN_AUTH_TOKEN || t === LEGACY_ADMIN_TOKEN);
}

function setAdminAuthCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `arthur_admin_token=${encodeURIComponent(ADMIN_AUTH_TOKEN)}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax`
  );
}

function hasOwnerAuth(req) {
  const cookies = parseCookies(req);
  const headerToken = String(getHeaderVal(req, 'x-admin-token') || getQueryParam(req, 'adminToken') || '').trim();
  const headerPin = String(getHeaderVal(req, 'x-admin-pin') || getQueryParam(req, 'pin') || '').trim();
  if (
    isValidAdminToken(cookies.arthur_admin_token) ||
    isValidAdminToken(headerToken) ||
    (headerPin && headerPin === TOOL_ACCESS_PIN)
  ) {
    return true;
  }
  return false;
}

function hasRoomInviteAuth(req, roomId) {
  const targetId = String(roomId || getQueryParam(req, 'room') || getQueryParam(req, 'roomId') || req.body?.roomId || '').trim();
  const invite = String(getHeaderVal(req, 'x-room-invite') || getQueryParam(req, 'invite') || req.body?.invite || '').trim();
  if (!targetId || !invite) return false;
  const room = rooms.get(targetId);
  if (!room) return false;
  return room.inviteToken === invite;
}

// Real-time CPU & Network delta trackers
let prevCpu = null;
let prevNet = null;

function readCpuPercent() {
  try {
    const statPath = fs.existsSync('/host/proc/stat') ? '/host/proc/stat' : '/proc/stat';
    const line = fs.readFileSync(statPath, 'utf-8').split('\n')[0];
    const parts = line.trim().split(/\s+/).slice(1).map(Number);
    const idle = parts[3] + (parts[4] || 0);
    const total = parts.reduce((a, b) => a + b, 0);
    if (!prevCpu) {
      prevCpu = { idle, total };
      return 8;
    }
    const diffIdle = idle - prevCpu.idle;
    const diffTotal = total - prevCpu.total;
    prevCpu = { idle, total };
    if (diffTotal <= 0) return 0;
    return Math.max(1, Math.min(100, Math.round(((diffTotal - diffIdle) / diffTotal) * 100)));
  } catch {
    const load = os.loadavg()[0] || 0;
    const cores = os.cpus()?.length || 1;
    return Math.min(100, Math.round((load / cores) * 100));
  }
}

function readMemoryStats() {
  try {
    const memPath = fs.existsSync('/host/proc/meminfo') ? '/host/proc/meminfo' : '/proc/meminfo';
    const raw = fs.readFileSync(memPath, 'utf-8');
    const getKb = key => {
      const m = raw.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'));
      return m ? Number(m[1]) * 1024 : 0;
    };
    const total = getKb('MemTotal') || os.totalmem();
    const avail = getKb('MemAvailable') || os.freemem();
    const used = Math.max(0, total - avail);
    const swapTotal = getKb('SwapTotal');
    const swapFree = getKb('SwapFree');
    const swapUsed = Math.max(0, swapTotal - swapFree);
    return {
      totalBytes: total,
      usedBytes: used,
      freeBytes: avail,
      percent: total > 0 ? Math.round((used / total) * 100) : 0,
      swapTotalBytes: swapTotal,
      swapUsedBytes: swapUsed
    };
  } catch {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    return {
      totalBytes: total,
      usedBytes: used,
      freeBytes: free,
      percent: Math.round((used / total) * 100),
      swapTotalBytes: 0,
      swapUsedBytes: 0
    };
  }
}

function readDiskStats() {
  try {
    const out = execSync('df -kP / | tail -n 1', { encoding: 'utf-8' }).trim();
    const cols = out.split(/\s+/);
    const totalBytes = Number(cols[1] || 0) * 1024;
    const usedBytes = Number(cols[2] || 0) * 1024;
    const freeBytes = Number(cols[3] || 0) * 1024;
    const percent = totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 100) : 0;
    return { totalBytes, usedBytes, freeBytes, percent };
  } catch {
    return { totalBytes: 0, usedBytes: 0, freeBytes: 0, percent: 0 };
  }
}

function readNetworkStats() {
  try {
    const netPath = fs.existsSync('/host/proc/net/dev') ? '/host/proc/net/dev' : '/proc/net/dev';
    const lines = fs.readFileSync(netPath, 'utf-8').split('\n').slice(2);
    let rxBytes = 0;
    let txBytes = 0;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('lo:')) continue;
      const parts = trimmed.replace(':', ' ').trim().split(/\s+/);
      rxBytes += Number(parts[1] || 0);
      txBytes += Number(parts[9] || 0);
    }
    const now = Date.now();
    let rxRatePerSec = 0;
    let txRatePerSec = 0;
    if (prevNet && now > prevNet.at) {
      const dt = (now - prevNet.at) / 1000;
      rxRatePerSec = Math.max(0, Math.round((rxBytes - prevNet.rxBytes) / dt));
      txRatePerSec = Math.max(0, Math.round((txBytes - prevNet.txBytes) / dt));
    }
    prevNet = { rxBytes, txBytes, at: now };
    return { rxBytes, txBytes, rxRatePerSec, txRatePerSec };
  } catch {
    return { rxBytes: 0, txBytes: 0, rxRatePerSec: 0, txRatePerSec: 0 };
  }
}

function getSystemTelemetry() {
  const cpuPercent = readCpuPercent();
  const mem = readMemoryStats();
  const disk = readDiskStats();
  const net = readNetworkStats();
  const load = os.loadavg();
  return {
    hostname: process.env.HOST_HOSTNAME || 'arthurg-vps',
    containerId: os.hostname(),
    uptimeSec: Math.floor(os.uptime()),
    cpu: {
      percent: cpuPercent,
      cores: os.cpus()?.length || 1,
      model: os.cpus()?.[0]?.model || 'Virtual CPU',
      load1: Number(load[0] || 0).toFixed(2),
      load5: Number(load[1] || 0).toFixed(2),
      load15: Number(load[2] || 0).toFixed(2)
    },
    memory: mem,
    disk,
    network: net,
    activeRooms: rooms.size,
    timestamp: Date.now()
  };
}

function serializeRoom(room, includeToken = false) {
  const participants = Array.from(room.participants.values()).map(p => ({
    id: p.id,
    nickname: p.nickname,
    role: p.role,
    color: p.color
  }));
  const payload = {
    id: room.id,
    name: room.name,
    mode: room.mode,
    targetLabel: room.targetLabel,
    connected: room.connected,
    guestWrite: room.guestWrite,
    createdAt: room.createdAt,
    participantCount: participants.length,
    participants
  };
  if (includeToken) {
    payload.inviteToken = room.inviteToken;
  }
  return payload;
}

function broadcastToRoom(room, messageObj) {
  const raw = JSON.stringify(messageObj);
  for (const client of room.participants.keys()) {
    if (client.readyState === 1) {
      try {
        client.send(raw);
      } catch {}
    }
  }
}

function connectRoomSsh(room) {
  return new Promise((resolve, reject) => {
    const ssh = new SSHClient();
    room.sshClient = ssh;
    let settled = false;

    const connConfig = {
      readyTimeout: 12000,
      keepaliveInterval: 10000
    };

    if (room.mode === 'host-vps' || room.mode !== 'custom') {
      room.mode = 'host-vps';
      connConfig.host = HOST_VPS_IP;
      connConfig.port = HOST_VPS_PORT;
      connConfig.username = 'root';
      connConfig.privateKey = fs.readFileSync(INTERNAL_SSH_KEY_PATH);
      room.targetLabel = `root@arthurg.my.id:${HOST_VPS_PORT}`;
    } else {
      connConfig.host = room.customConfig.host;
      connConfig.port = Number(room.customConfig.port || 22);
      connConfig.username = room.customConfig.username || 'root';
      if (room.customConfig.privateKey) {
        connConfig.privateKey = room.customConfig.privateKey;
      } else {
        connConfig.password = room.customConfig.password || '';
      }
      room.targetLabel = `${connConfig.username}@${connConfig.host}:${connConfig.port}`;
    }

    ssh.on('ready', () => {
      ssh.shell(
        {
          term: 'xterm-256color',
          cols: room.cols || 110,
          rows: room.rows || 32
        },
        (err, stream) => {
          if (err) {
            if (!settled) {
              settled = true;
              reject(err);
            }
            return;
          }
          room.connected = true;
          room.ptyStream = stream;
          if (!settled) {
            settled = true;
            resolve(room);
          }

          stream.on('data', chunk => {
            const text = chunk.toString('utf-8');
            room.scrollback += text;
            if (room.scrollback.length > 65536) {
              room.scrollback = room.scrollback.slice(-65536);
            }
            broadcastToRoom(room, { type: 'output', data: text });
          });

          stream.on('close', () => {
            room.connected = false;
            broadcastToRoom(room, {
              type: 'output',
              data: '\r\n\x1b[1;33m[Session Closed]\x1b[0m\r\n'
            });
            broadcastToRoom(room, { type: 'room_state', room: serializeRoom(room, false) });
          });
        }
      );
    });

    ssh.on('error', err => {
      room.connected = false;
      const msg = err?.message || 'SSH connection failed';
      broadcastToRoom(room, {
        type: 'output',
        data: `\r\n\x1b[1;31m[SSH Error: ${msg}]\x1b[0m\r\n`
      });
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    ssh.on('close', () => {
      room.connected = false;
    });

    try {
      ssh.connect(connConfig);
    } catch (e) {
      if (!settled) {
        settled = true;
        reject(e);
      }
    }
  });
}

function getSftp(room) {
  return new Promise((resolve, reject) => {
    if (!room || !room.sshClient || !room.connected) {
      return reject(new Error('Sesi SSH belum terhubung.'));
    }
    room.sshClient.sftp((err, sftp) => {
      if (err) return reject(err);
      resolve(sftp);
    });
  });
}

function formatModePerm(mode) {
  const isDir = (mode & 0o170000) === 0o040000;
  const isLink = (mode & 0o170000) === 0o120000;
  const prefix = isDir ? 'd' : isLink ? 'l' : '-';
  const chars = ['r', 'w', 'x'];
  let out = prefix;
  for (let i = 2; i >= 0; i--) {
    const bits = (mode >> (i * 3)) & 7;
    out += (bits & 4) ? chars[0] : '-';
    out += (bits & 2) ? chars[1] : '-';
    out += (bits & 1) ? chars[2] : '-';
  }
  const octal = (mode & 0o777).toString(8).padStart(3, '0');
  return { symbolic: out, octal, isDir, isLink };
}

// --- API ROUTES ---

app.get('/api/auth/status', (req, res) => {
  const isOwner = hasOwnerAuth(req);
  if (isOwner) {
    setAdminAuthCookie(res);
  }
  const roomId = String(req.query?.room || '').trim();
  const isInvite = roomId ? hasRoomInviteAuth(req, roomId) : false;
  return res.json({
    authenticated: isOwner || isInvite,
    role: isOwner ? 'owner' : (isInvite ? 'guest' : 'none'),
    token: isOwner ? ADMIN_AUTH_TOKEN : null,
    roomId: isInvite ? roomId : null
  });
});

app.post('/api/auth/login', (req, res) => {
  const pin = String(req.body?.pin || '').trim();
  const token = String(req.body?.token || '').trim();
  if (pin !== TOOL_ACCESS_PIN && !isValidAdminToken(token)) {
    return res.status(401).json({ status: false, message: 'PIN Owner tidak sesuai.' });
  }
  setAdminAuthCookie(res);
  return res.json({
    status: true,
    token: ADMIN_AUTH_TOKEN,
    message: 'Akses Web SSH & SFTP terbuka.'
  });
});

app.post('/api/auth/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'arthur_admin_token=; Path=/; Max-Age=0; SameSite=Lax');
  return res.json({ status: true });
});

app.get('/api/telemetry', (req, res) => {
  const roomId = String(req.query?.room || '').trim();
  if (!hasOwnerAuth(req) && !hasRoomInviteAuth(req, roomId)) {
    return res.status(401).json({ status: false, message: 'PIN diperlukan.' });
  }
  return res.json({
    status: true,
    telemetry: getSystemTelemetry(),
    rooms: Array.from(rooms.values()).map(r => serializeRoom(r, hasOwnerAuth(req)))
  });
});

app.get('/api/rooms', (req, res) => {
  const roomId = String(req.query?.room || '').trim();
  const isOwner = hasOwnerAuth(req);
  if (!isOwner && !hasRoomInviteAuth(req, roomId)) {
    return res.status(401).json({ status: false, message: 'PIN diperlukan.' });
  }
  const list = Array.from(rooms.values())
    .filter(r => isOwner || r.id === roomId)
    .map(r => serializeRoom(r, isOwner));
  return res.json({ status: true, rooms: list });
});

app.post('/api/rooms', async (req, res) => {
  if (!hasOwnerAuth(req)) {
    return res.status(401).json({ status: false, message: 'Hanya Owner yang dapat membuat sesi SSH baru.' });
  }
  try {
    const rawMode = String(req.body?.mode || 'host-vps').trim();
    const mode = rawMode === 'custom' ? 'custom' : 'host-vps';
    const id = 'mabar-' + crypto.randomBytes(3).toString('hex');
    const inviteToken = crypto.randomBytes(10).toString('hex');
    const defaultName = mode === 'custom'
      ? `${req.body?.username || 'root'}@${req.body?.host || 'remote'}`
      : 'Arthur Main VPS (Root)';

    const room = {
      id,
      name: String(req.body?.name || defaultName).trim().slice(0, 48),
      mode,
      targetLabel: '',
      inviteToken,
      guestWrite: req.body?.guestWrite !== false,
      connected: false,
      createdAt: Date.now(),
      cols: Number(req.body?.cols || 110),
      rows: Number(req.body?.rows || 32),
      scrollback: '',
      participants: new Map(),
      sshClient: null,
      ptyStream: null,
      customConfig: {
        host: String(req.body?.host || '').trim(),
        port: Number(req.body?.port || 22),
        username: String(req.body?.username || 'root').trim(),
        password: String(req.body?.password || ''),
        privateKey: String(req.body?.privateKey || '')
      }
    };

    rooms.set(id, room);
    await connectRoomSsh(room);

    return res.json({
      status: true,
      room: serializeRoom(room, true)
    });
  } catch (err) {
    return res.status(500).json({
      status: false,
      message: `Gagal membuka koneksi SSH: ${err?.message || err}`
    });
  }
});

app.post('/api/rooms/:id/permission', (req, res) => {
  if (!hasOwnerAuth(req)) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }
  const room = rooms.get(req.params.id);
  if (!room) return res.status(404).json({ status: false, message: 'Room tidak ditemukan.' });
  room.guestWrite = Boolean(req.body?.guestWrite);
  broadcastToRoom(room, { type: 'room_state', room: serializeRoom(room, false) });
  return res.json({ status: true, room: serializeRoom(room, true) });
});

app.delete('/api/rooms/:id', (req, res) => {
  if (!hasOwnerAuth(req)) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }
  const room = rooms.get(req.params.id);
  if (!room) return res.status(404).json({ status: false, message: 'Room tidak ditemukan.' });
  broadcastToRoom(room, { type: 'room_deleted', roomId: room.id, message: `Sesi "${room.name}" telah dihapus oleh Owner.` });
  try { room.ptyStream?.end(); } catch {}
  try { room.sshClient?.end(); } catch {}
  rooms.delete(room.id);
  const remaining = Array.from(rooms.values()).map(r => serializeRoom(r, true));
  return res.json({ status: true, deletedId: room.id, rooms: remaining, message: `Sesi "${room.name}" berhasil dihapus.` });
});

// --- SFTP ENDPOINTS ---

app.get('/api/sftp/list', async (req, res) => {
  const roomId = String(req.query?.roomId || '').trim();
  if (!hasOwnerAuth(req) && !hasRoomInviteAuth(req, roomId)) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }
  const room = rooms.get(roomId);
  if (!room) return res.status(404).json({ status: false, message: 'Pilih atau buat sesi SSH terlebih dahulu.' });

  const dirPath = String(req.query?.path || '/root').trim() || '/root';
  try {
    const sftp = await getSftp(room);
    sftp.readdir(dirPath, (err, list) => {
      sftp.end();
      if (err) {
        return res.status(400).json({ status: false, message: err.message });
      }
      const items = (list || []).map(entry => {
        const perm = formatModePerm(entry.attrs?.mode || 0);
        return {
          name: entry.filename,
          path: path.posix.join(dirPath, entry.filename),
          size: Number(entry.attrs?.size || 0),
          mtime: Number(entry.attrs?.mtime || 0) * 1000,
          isDir: perm.isDir,
          isLink: perm.isLink,
          permSymbolic: perm.symbolic,
          permOctal: perm.octal
        };
      }).sort((a, b) => {
        if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
        return a.name.localeCompare(b.name);
      });
      return res.json({ status: true, path: dirPath, items });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.get('/api/sftp/read', async (req, res) => {
  const roomId = String(req.query?.roomId || '').trim();
  if (!hasOwnerAuth(req) && !hasRoomInviteAuth(req, roomId)) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }
  const room = rooms.get(roomId);
  const filePath = String(req.query?.path || '').trim();
  if (!room || !filePath) return res.status(400).json({ status: false, message: 'Parameter tidak lengkap.' });

  try {
    const sftp = await getSftp(room);
    const chunks = [];
    let total = 0;
    const stream = sftp.createReadStream(filePath, { start: 0, end: 512 * 1024 });
    stream.on('data', chunk => {
      total += chunk.length;
      chunks.push(chunk);
    });
    stream.on('error', err => {
      sftp.end();
      res.status(400).json({ status: false, message: err.message });
    });
    stream.on('end', () => {
      sftp.end();
      const buf = Buffer.concat(chunks);
      res.json({
        status: true,
        path: filePath,
        size: total,
        content: buf.toString('utf-8')
      });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.post('/api/sftp/write', async (req, res) => {
  const roomId = String(req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req) && !(hasRoomInviteAuth(req, roomId) && rooms.get(roomId)?.guestWrite)) {
    return res.status(401).json({ status: false, message: 'Unauthorized.' });
  }
  const room = rooms.get(roomId);
  const filePath = String(req.body?.path || '').trim();
  const content = String(req.body?.content ?? '');
  if (!room || !filePath) return res.status(400).json({ status: false, message: 'Parameter tidak lengkap.' });

  try {
    const sftp = await getSftp(room);
    const stream = sftp.createWriteStream(filePath);
    stream.on('error', err => {
      sftp.end();
      res.status(400).json({ status: false, message: err.message });
    });
    stream.on('close', () => {
      sftp.end();
      res.json({ status: true, message: `File ${path.posix.basename(filePath)} berhasil disimpan.` });
    });
    stream.end(Buffer.from(content, 'utf-8'));
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.post('/api/sftp/mkdir', async (req, res) => {
  const roomId = String(req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req)) return res.status(401).json({ status: false, message: 'Unauthorized.' });
  const room = rooms.get(roomId);
  const targetPath = String(req.body?.path || '').trim();
  if (!room || !targetPath) return res.status(400).json({ status: false, message: 'Path tidak valid.' });

  try {
    const sftp = await getSftp(room);
    sftp.mkdir(targetPath, err => {
      sftp.end();
      if (err) return res.status(400).json({ status: false, message: err.message });
      return res.json({ status: true, message: 'Folder berhasil dibuat.' });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.post('/api/sftp/rename', async (req, res) => {
  const roomId = String(req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req)) return res.status(401).json({ status: false, message: 'Unauthorized.' });
  const room = rooms.get(roomId);
  const oldPath = String(req.body?.oldPath || '').trim();
  const newPath = String(req.body?.newPath || '').trim();
  if (!room || !oldPath || !newPath) return res.status(400).json({ status: false, message: 'Parameter tidak lengkap.' });

  try {
    const sftp = await getSftp(room);
    sftp.rename(oldPath, newPath, err => {
      sftp.end();
      if (err) return res.status(400).json({ status: false, message: err.message });
      return res.json({ status: true, message: 'Berhasil mengubah nama.' });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.post('/api/sftp/chmod', async (req, res) => {
  const roomId = String(req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req)) return res.status(401).json({ status: false, message: 'Unauthorized.' });
  const room = rooms.get(roomId);
  const targetPath = String(req.body?.path || '').trim();
  const modeStr = String(req.body?.mode || '644').trim();
  if (!room || !targetPath) return res.status(400).json({ status: false, message: 'Parameter tidak lengkap.' });

  try {
    const sftp = await getSftp(room);
    const modeOctal = parseInt(modeStr, 8);
    sftp.chmod(targetPath, modeOctal, err => {
      sftp.end();
      if (err) return res.status(400).json({ status: false, message: err.message });
      return res.json({ status: true, message: `Permission diubah ke ${modeStr}.` });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.post('/api/sftp/delete', async (req, res) => {
  const roomId = String(req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req)) return res.status(401).json({ status: false, message: 'Unauthorized.' });
  const room = rooms.get(roomId);
  const targetPath = String(req.body?.path || '').trim();
  const isDir = Boolean(req.body?.isDir);
  if (!room || !targetPath) return res.status(400).json({ status: false, message: 'Parameter tidak lengkap.' });

  try {
    const sftp = await getSftp(room);
    const fn = isDir ? sftp.rmdir.bind(sftp) : sftp.unlink.bind(sftp);
    fn(targetPath, err => {
      sftp.end();
      if (err) return res.status(400).json({ status: false, message: err.message });
      return res.json({ status: true, message: 'Item berhasil dihapus.' });
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

app.get('/api/sftp/download', async (req, res) => {
  const roomId = String(req.query?.roomId || '').trim();
  if (!hasOwnerAuth(req) && !hasRoomInviteAuth(req, roomId)) {
    return res.status(401).send('Unauthorized');
  }
  const room = rooms.get(roomId);
  const filePath = String(req.query?.path || '').trim();
  if (!room || !filePath) return res.status(400).send('Invalid path');

  try {
    const sftp = await getSftp(room);
    const filename = path.posix.basename(filePath);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    const stream = sftp.createReadStream(filePath);
    stream.on('error', () => {
      sftp.end();
      if (!res.headersSent) res.status(404).end('File not found');
    });
    stream.on('close', () => sftp.end());
    stream.pipe(res);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post('/api/sftp/upload', upload.array('files', 20), async (req, res) => {
  const roomId = String(req.query?.roomId || req.body?.roomId || '').trim();
  if (!hasOwnerAuth(req)) return res.status(401).json({ status: false, message: 'Unauthorized.' });
  const room = rooms.get(roomId);
  const targetDir = String(req.query?.path || req.body?.path || '/root').trim();
  if (!room) return res.status(404).json({ status: false, message: 'Room SSH tidak ditemukan.' });

  const files = req.files || [];
  if (!files.length) return res.status(400).json({ status: false, message: 'Tidak ada file yang dipilih.' });

  try {
    const sftp = await getSftp(room);
    for (const file of files) {
      const destPath = path.posix.join(targetDir, file.originalname);
      await new Promise((resolve, reject) => {
        const ws = sftp.createWriteStream(destPath);
        ws.on('error', reject);
        ws.on('close', resolve);
        ws.end(file.buffer);
      });
    }
    sftp.end();
    return res.json({
      status: true,
      message: `${files.length} file berhasil diunggah ke ${targetDir}.`
    });
  } catch (err) {
    return res.status(500).json({ status: false, message: err.message });
  }
});

// Serve Static PWA & UI Assets
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-cache');
  }
}));

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const PARTICIPANT_COLORS = ['#22c55e', '#38bdf8', '#f59e0b', '#a855f7', '#ec4899', '#14b8a6'];

server.on('upgrade', (req, socket, head) => {
  const parsed = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const roomId = String(parsed.searchParams.get('roomId') || '').trim();
  const isOwner = hasOwnerAuth(req);
  const isInvite = hasRoomInviteAuth(req, roomId);

  if (!isOwner && !isInvite) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, ws => {
    ws.authRole = isOwner ? 'owner' : 'guest';
    ws.roomId = roomId;
    ws.nickname = String(parsed.searchParams.get('nick') || (isOwner ? 'Arthur (Owner)' : 'Mabar Guest')).slice(0, 24);
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', ws => {
  const room = rooms.get(ws.roomId);
  if (!room) {
    ws.send(JSON.stringify({ type: 'error', message: 'Sesi terminal tidak ditemukan atau sudah ditutup.' }));
    ws.close();
    return;
  }

  const pId = crypto.randomBytes(3).toString('hex');
  const participant = {
    id: pId,
    nickname: ws.nickname,
    role: ws.authRole,
    color: PARTICIPANT_COLORS[room.participants.size % PARTICIPANT_COLORS.length]
  };
  room.participants.set(ws, participant);

  // Send initial scrollback & room state
  ws.send(JSON.stringify({
    type: 'init',
    participant,
    room: serializeRoom(room, ws.authRole === 'owner'),
    scrollback: room.scrollback
  }));

  broadcastToRoom(room, {
    type: 'room_state',
    room: serializeRoom(room, false),
    event: `${participant.nickname} bergabung ke sesi Mabar SSH`
  });

  ws.on('message', raw => {
    try {
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'input') {
        if (ws.authRole !== 'owner' && !room.guestWrite) {
          return;
        }
        if (room.ptyStream && room.connected && typeof msg.data === 'string') {
          room.ptyStream.write(msg.data);
          broadcastToRoom(room, {
            type: 'typing',
            participantId: participant.id,
            nickname: participant.nickname,
            color: participant.color
          });
        }
      } else if (msg.type === 'resize') {
        const cols = Math.max(20, Math.min(400, Number(msg.cols || 100)));
        const rows = Math.max(8, Math.min(200, Number(msg.rows || 30)));
        room.cols = cols;
        room.rows = rows;
        if (room.ptyStream && room.connected) {
          try { room.ptyStream.setWindow(rows, cols, 0, 0); } catch {}
        }
      } else if (msg.type === 'set_nick' && msg.nickname) {
        participant.nickname = String(msg.nickname).trim().slice(0, 24) || participant.nickname;
        broadcastToRoom(room, { type: 'room_state', room: serializeRoom(room, false) });
      }
    } catch {}
  });

  ws.on('close', () => {
    room.participants.delete(ws);
    broadcastToRoom(room, {
      type: 'room_state',
      room: serializeRoom(room, false)
    });
  });
});

// Automatically create a default Main VPS room on startup
setTimeout(async () => {
  try {
    const defaultRoom = {
      id: 'mabar-main',
      name: 'Arthur Main VPS (Root)',
      mode: 'host-vps',
      targetLabel: `root@arthurg.my.id:${HOST_VPS_PORT}`,
      inviteToken: crypto.randomBytes(10).toString('hex'),
      guestWrite: true,
      connected: false,
      createdAt: Date.now(),
      cols: 110,
      rows: 32,
      scrollback: '',
      participants: new Map(),
      sshClient: null,
      ptyStream: null,
      customConfig: {}
    };
    rooms.set(defaultRoom.id, defaultRoom);
    await connectRoomSsh(defaultRoom);
    console.log('[Arthur SSH Web] Default Main VPS Room initialized.');
  } catch (e) {
    console.error('[Arthur SSH Web] Default room init warning:', e.message);
  }
}, 1200);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Arthur SSH Web] Running on http://0.0.0.0:${PORT}`);
});
