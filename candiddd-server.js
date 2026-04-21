#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// CANDIDDD.live — Backend v2.2
// PostgreSQL persistente + sicurezza + rate limiting
// ═══════════════════════════════════════════════════════════════

const { AccessToken, RoomServiceClient } = require('livekit-server-sdk');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const http   = require('http');
const crypto = require('crypto');

// ─── CONFIG ──────────────────────────────────────────────────
function requireEnv(name) {
  const val = process.env[name];
  if (!val) { console.error(`ERRORE: variabile ${name} mancante`); process.exit(1); }
  return val;
}

const CONFIG = {
  PORT:               parseInt(process.env.PORT || '3000'),
  LIVEKIT_API_KEY:    requireEnv('LIVEKIT_API_KEY'),
  LIVEKIT_API_SECRET: requireEnv('LIVEKIT_API_SECRET'),
  LIVEKIT_URL:        requireEnv('LIVEKIT_URL'),
  ADMIN_KEY:          requireEnv('ADMIN_KEY'),
  ALLOWED_ORIGIN:     process.env.ALLOWED_ORIGIN || 'https://candiddd.live',
  WORKER_URL:         process.env.WORKER_URL || 'http://localhost:4000',
  JWT_SECRET:         process.env.JWT_SECRET || 'candiddd-jwt-fallback',
};

// ─── POSTGRESQL ───────────────────────────────────────────────
let pool = null;

async function getDb() {
  if (!pool) {
    if (!process.env.DATABASE_URL) {
      console.warn('[DB] DATABASE_URL non configurata — uso RAM');
      return null;
    }
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
    });
    try {
      await pool.query('SELECT 1');
      console.log('[DB] ✅ PostgreSQL connesso');
    } catch (e) {
      console.error('[DB] Errore connessione:', e.message);
      pool = null;
      return null;
    }
  }
  return pool;
}

// ─── IN-MEMORY FALLBACK ───────────────────────────────────────
const db = {
  sessions:  new Map(),
  donations: new Map(),
  reports:   new Map(),
  mod_logs:  new Map(),
  fraud:     new Map(),
};

// ─── RATE LIMITING ────────────────────────────────────────────
const rateLimitMap = new Map();

function checkRateLimit(ip, max = 5, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count <= max;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of rateLimitMap) if (now > e.resetAt) rateLimitMap.delete(ip);
}, 5 * 60 * 1000);

// ─── LIVEKIT ──────────────────────────────────────────────────
const livekit = {
  async publisherToken(creatorId, roomName) {
    const at = new AccessToken(CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET, { identity: creatorId, ttl: '4h' });
    at.addGrant({ room: roomName, roomJoin: true, canPublish: true, canSubscribe: false, canPublishData: true });
    return await at.toJwt();
  },
  async viewerToken(roomName) {
    const identity = `viewer-${crypto.randomUUID().substring(0, 8)}`;
    const at = new AccessToken(CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET, { identity, ttl: '4h' });
    at.addGrant({ room: roomName, roomJoin: true, canPublish: false, canSubscribe: true });
    return await at.toJwt();
  },
};

// ─── AUTH HELPERS ─────────────────────────────────────────────
function generateToken(creator) {
  return jwt.sign(
    { id: creator.id, email: creator.email, name: creator.name },
    CONFIG.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

async function verifyToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  try { return jwt.verify(token, CONFIG.JWT_SECRET); }
  catch { return null; }
}

// ─── WEBSOCKET ────────────────────────────────────────────────
const wsRooms = new Map();

function getRoom(sid) {
  if (!wsRooms.has(sid)) wsRooms.set(sid, { viewers: new Set(), admins: new Set() });
  return wsRooms.get(sid);
}

function wsEmit(socket, data) {
  try {
    const msgBuf = Buffer.from(JSON.stringify(data), 'utf8');
    const len = msgBuf.length;
    let header;
    if (len < 126)      { header = Buffer.alloc(2); header[0] = 0x81; header[1] = len; }
    else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2); }
    else                  { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2); }
    socket.write(Buffer.concat([header, msgBuf]));
  } catch {}
}

function emitToSet(set, evt) { for (const s of set) wsEmit(s, evt); }
function emitToViewers(sid, evt) { emitToSet(getRoom(sid).viewers, evt); }
function emitToAdmins(sid, evt)  { emitToSet(getRoom(sid).admins, evt); }
function emitToAll(sid, evt)     { emitToViewers(sid, evt); emitToAdmins(sid, evt); }

// ─── ANTI-FRODE ───────────────────────────────────────────────
function fraudCheck(userId, amount) {
  const now = Date.now();
  const data = db.fraud.get(userId) || { total: 0, timestamps: [] };
  const recent = data.timestamps.filter(ts => now - ts < 60_000);
  if (recent.length >= 5)        return { ok: false, reason: 'rate_limit', message: 'Max 5 donazioni/minuto' };
  if (data.total + amount > 200) return { ok: false, reason: 'daily_limit', message: 'Limite giornaliero EUR 200' };
  if (amount > 100)              return { ok: false, reason: 'amount_too_high', message: 'Max EUR 100' };
  if (amount <= 0)               return { ok: false, reason: 'invalid_amount', message: 'Importo non valido' };
  recent.push(now);
  db.fraud.set(userId, { total: data.total + amount, timestamps: recent });
  const flagged = amount > 50 || recent.length >= 4;
  return { ok: true, flagged, flag_reason: flagged ? (amount > 50 ? 'high_amount' : 'high_velocity') : null };
}

// ─── HTTP HELPERS ─────────────────────────────────────────────
function getCorsHeaders(origin) {
  const allowed = [CONFIG.ALLOWED_ORIGIN, 'https://candiddd.pages.dev'];
  const isOk = allowed.includes(origin) || (origin && origin.endsWith('.candiddd.pages.dev'));
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': isOk ? origin : CONFIG.ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Creator-Id,X-User-Id,X-Viewer-Id,X-Admin-Key,X-Admin-Id',
    'Vary': 'Origin',
  };
}

function respond(res, origin, data, status = 200) {
  res.writeHead(status, getCorsHeaders(origin));
  res.end(JSON.stringify(data));
}

async function readBody(req, maxBytes = 65536) {
  return new Promise((resolve) => {
    let data = '', size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) { req.destroy(); resolve({}); return; }
      data += chunk;
    });
    req.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve({}); } });
  });
}

// ─── SERVER ───────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url    = new URL(req.url, 'http://localhost');
  const path   = url.pathname;
  const method = req.method;
  const origin = req.headers['origin'] || CONFIG.ALLOWED_ORIGIN;

  if (method === 'OPTIONS') {
    res.writeHead(204, getCorsHeaders(origin));
    res.end();
    return;
  }

  const body     = ['POST','PATCH','PUT'].includes(method) ? await readBody(req) : {};
  const creatorId = req.headers['x-creator-id'] || 'demo-creator';
  const userId    = req.headers['x-user-id']    || 'anon-' + Date.now();
  const viewerId  = req.headers['x-viewer-id']  || 'viewer-' + Date.now();
  const isAdmin   = (req.headers['x-admin-key'] || '') === CONFIG.ADMIN_KEY;

  // POST /api/auth/register
  if (method === 'POST' && path === '/api/auth/register') {
    const { name, email, password, city } = body;
    if (!name || !email || !password) return respond(res, origin, { error: 'Nome, email e password obbligatori' }, 400);
    if (password.length < 6) return respond(res, origin, { error: 'Password minimo 6 caratteri' }, 400);

    const dbConn = await getDb();
    if (!dbConn) return respond(res, origin, { error: 'Database non disponibile' }, 500);

    try {
      // Controlla se email già usata
      const existing = await dbConn.query('SELECT id FROM creators WHERE email=$1', [email.toLowerCase()]);
      if (existing.rows.length > 0) return respond(res, origin, { error: 'Email già registrata' }, 409);

      const hash = await bcrypt.hash(password, 10);
      const result = await dbConn.query(
        'INSERT INTO creators (name, email, password_hash, city, level, status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, email, city, level',
        [name.trim(), email.toLowerCase(), hash, city || '', 'BASE', 'ACTIVE']
      );
      const creator = result.rows[0];
      const token = generateToken(creator);
      console.log('[AUTH] Nuovo creator:', creator.email);
      return respond(res, origin, { ok: true, token, creator: { id: creator.id, name: creator.name, email: creator.email, city: creator.city, level: creator.level } }, 201);
    } catch(e) {
      console.error('[AUTH] Register error:', e.message);
      return respond(res, origin, { error: 'Errore registrazione' }, 500);
    }
  }

  // POST /api/auth/login
  if (method === 'POST' && path === '/api/auth/login') {
    const { email, password } = body;
    if (!email || !password) return respond(res, origin, { error: 'Email e password obbligatori' }, 400);

    const dbConn = await getDb();
    if (!dbConn) return respond(res, origin, { error: 'Database non disponibile' }, 500);

    try {
      const result = await dbConn.query('SELECT * FROM creators WHERE email=$1 AND status=$2', [email.toLowerCase(), 'ACTIVE']);
      if (result.rows.length === 0) return respond(res, origin, { error: 'Credenziali non valide' }, 401);

      const creator = result.rows[0];
      const valid = await bcrypt.compare(password, creator.password_hash);
      if (!valid) return respond(res, origin, { error: 'Credenziali non valide' }, 401);

      const token = generateToken(creator);
      console.log('[AUTH] Login:', creator.email);
      return respond(res, origin, { ok: true, token, creator: { id: creator.id, name: creator.name, email: creator.email, city: creator.city, level: creator.level } });
    } catch(e) {
      console.error('[AUTH] Login error:', e.message);
      return respond(res, origin, { error: 'Errore login' }, 500);
    }
  }

  // GET /api/auth/me
  if (method === 'GET' && path === '/api/auth/me') {
    const decoded = await verifyToken(req);
    if (!decoded) return respond(res, origin, { error: 'Non autorizzato' }, 401);
    return respond(res, origin, { ok: true, creator: decoded });
  }

  // GET /api/health
  if (method === 'GET' && path === '/api/health') {
    const dbOk = !!(await getDb().catch(() => null));
    return respond(res, origin, {
      ok: true,
      ts: new Date().toISOString(),
      active_sessions: [...db.sessions.values()].filter(s => s.status === 'LIVE').length,
      db: dbOk ? 'postgresql' : 'ram',
    });
  }

  // POST /api/creator/live-sessions
  if (method === 'POST' && path === '/api/creator/live-sessions') {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(ip)) return respond(res, origin, { error: 'Troppo richieste. Riprova tra un minuto.' }, 429);

    // Verifica JWT se presente, altrimenti usa X-Creator-Id (retrocompatibilità)
    const decoded = await verifyToken(req);
    const { level = 'CASA', geo_lat, geo_lng, creator_name, creator_city } = body;
    const authCreatorName = decoded?.name || creator_name;
    const authCreatorCity = decoded?.city || creator_city;
    const authCreatorId   = decoded?.id   || req.headers['x-creator-id'] || 'demo-creator';
    const validLevels = ['CASA','ROUTINE','SOCIALE','LOCALE','CITTADINO','REGIONALE','NAZIONALE','GLOBALE'];
    if (!validLevels.includes(level)) return respond(res, origin, { error: 'Level non valido' }, 400);

    const id  = crypto.randomUUID();
    const now = new Date().toISOString();

    let livekitToken;
    try { livekitToken = await livekit.publisherToken(authCreatorId, id); }
    catch (e) { return respond(res, origin, { error: 'Errore token LiveKit: ' + e.message }, 500); }

    const session = {
      id, creator_id: authCreatorId, status: 'LIVE', level,
      creator_name: authCreatorName || 'Creator',
      creator_city: authCreatorCity || '',
      stream_key:   `sk_${creatorId.substring(0,8)}_${Date.now()}`,
      playback_url: `https://candiddd.live/live/${id}`,
      geo_lat: geo_lat || null, geo_lng: geo_lng || null,
      start_time: now, end_time: null, viewer_count: 0, earnings_eur: 0,
    };
    db.sessions.set(id, session);

    // Salva su PostgreSQL
    try {
      const dbConn = await getDb();
      if (dbConn) {
        await dbConn.query(
          `INSERT INTO live_sessions (id, creator_name, creator_city, status, level, livekit_room, playback_url, geo_lat, geo_lng, start_time)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [id, session.creator_name, session.creator_city, 'LIVE', level, id, session.playback_url, geo_lat||null, geo_lng||null, now]
        );
        console.log('[DB] Sessione salvata:', id.substring(0,8));
      }
    } catch(e) { console.error('[DB] Insert error:', e.message); }

    emitToAll(id, { type: 'live_started', payload: { session_id: id, start_time: now, level } });
    console.log(`[SESSION] Created: ${id.substring(0,8)} by ${session.creator_name}`);

    return respond(res, origin, {
      live_session_id: id, livekit_token: livekitToken,
      livekit_url: CONFIG.LIVEKIT_URL, stream_key: session.stream_key,
      playback_url: session.playback_url, status: 'LIVE', level,
    }, 201);
  }

  // PATCH /api/creator/live-sessions/:id/end
  const endMatch = path.match(/^\/api\/creator\/live-sessions\/([^/]+)\/end$/);
  if (method === 'PATCH' && endMatch) {
    const session = db.sessions.get(endMatch[1]);
    if (!session) return respond(res, origin, { error: 'Sessione non trovata' }, 404);
    if (session.status === 'ENDED') return respond(res, origin, { session_id: endMatch[1], status: 'ENDED', already_ended: true });

    const now = new Date().toISOString();
    const durationSec = Math.round((new Date(now) - new Date(session.start_time)) / 1000);
    session.status = 'ENDED'; session.end_time = now;

    // Aggiorna DB
    try {
      const dbConn = await getDb();
      if (dbConn) {
        await dbConn.query(
          'UPDATE live_sessions SET status=$1, end_time=$2, viewer_count=$3 WHERE id=$4',
          ['ENDED', now, session.viewer_count, endMatch[1]]
        );
      }
    } catch(e) { console.error('[DB] Update error:', e.message); }

    emitToAll(endMatch[1], { type: 'live_ended', payload: { session_id: endMatch[1], end_time: now, duration_seconds: durationSec } });
    return respond(res, origin, { live_session_id: endMatch[1], status: 'ENDED', end_time: now, duration_seconds: durationSec });
  }

  // GET /api/live-sessions/:id/viewers
  const viewersMatch = path.match(/^\/api\/live-sessions\/([^/]+)\/viewers$/);
  if (method === 'GET' && viewersMatch) {
    const session = db.sessions.get(viewersMatch[1]);
    if (!session) return respond(res, origin, { error: 'Sessione non trovata' }, 404);
    try {
      const svc = new RoomServiceClient(CONFIG.LIVEKIT_URL.replace('wss://', 'https://'), CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET);
      const rooms = await svc.listRooms([viewersMatch[1]]);
      const room = rooms.find(r => r.name === viewersMatch[1]);
      const count = room ? Math.max(0, (room.numParticipants || 0) - 1) : 0;
      session.viewer_count = count;
      return respond(res, origin, { viewer_count: count, session_id: viewersMatch[1] });
    } catch { return respond(res, origin, { viewer_count: session.viewer_count || 0 }); }
  }

  // GET /api/live-sessions/:id
  const sessionMatch = path.match(/^\/api\/live-sessions\/([^/]+)$/);
  if (method === 'GET' && sessionMatch) {
    let session = db.sessions.get(sessionMatch[1]);

    // Se non in RAM, cerca nel DB
    if (!session) {
      try {
        const dbConn = await getDb();
        if (dbConn) {
          const r = await dbConn.query('SELECT * FROM live_sessions WHERE id=$1', [sessionMatch[1]]);
          if (r.rows[0]) {
            session = { ...r.rows[0], creator_id: 'db-restored', earnings_eur: 0 };
            db.sessions.set(session.id, session);
          }
        }
      } catch(e) { console.error('[DB] Fetch error:', e.message); }
    }

    if (!session) return respond(res, origin, { error: 'Sessione non trovata' }, 404);

    let viewerToken = null;
    if (session.status === 'LIVE') {
      try { viewerToken = await livekit.viewerToken(session.id); } catch {}
    }
    return respond(res, origin, {
      id: session.id, status: session.status, level: session.level,
      playback_url: session.playback_url,
      livekit_token: viewerToken, livekit_url: CONFIG.LIVEKIT_URL,
      creator: { id: session.creator_id, username: session.creator_name || 'Creator CANDIDDD' },
      viewer_count: session.viewer_count,
      start_time: session.start_time, end_time: session.end_time,
    });
  }

  // GET /api/live-sessions
  if (method === 'GET' && path === '/api/live-sessions') {
    try {
      const dbConn = await getDb();
      if (dbConn) {
        const result = await dbConn.query(
          "SELECT id, creator_name, creator_city, level, playback_url, viewer_count, start_time FROM live_sessions WHERE status='LIVE' ORDER BY start_time DESC"
        );
        // Ripristina in RAM
        for (const row of result.rows) {
          if (!db.sessions.has(row.id)) {
            db.sessions.set(row.id, { ...row, status: 'LIVE', creator_id: 'db-restored', end_time: null, earnings_eur: 0 });
          }
        }
        return respond(res, origin, { live_sessions: result.rows, total: result.rows.length });
      }
    } catch(e) { console.error('[DB] List error:', e.message); }

    // Fallback RAM
    const active = [...db.sessions.values()]
      .filter(s => s.status === 'LIVE')
      .map(s => ({ id: s.id, creator_name: s.creator_name || 'Creator', creator_city: s.creator_city || '', level: s.level, playback_url: s.playback_url, viewer_count: s.viewer_count, start_time: s.start_time }));
    return respond(res, origin, { live_sessions: active, total: active.length });
  }

  // POST /api/live-sessions/:id/donations
  const donMatch = path.match(/^\/api\/live-sessions\/([^/]+)\/donations$/);
  if (method === 'POST' && donMatch) {
    const session = db.sessions.get(donMatch[1]);
    if (!session || session.status !== 'LIVE') return respond(res, origin, { error: 'Live non attiva' }, 400);
    const amount = parseFloat(body.amount);
    const fraud = fraudCheck(userId, amount);
    if (!fraud.ok) return respond(res, origin, { error: fraud.message, reason: fraud.reason }, 400);
    const don = { id: crypto.randomUUID(), live_session_id: donMatch[1], user_id: userId, from: String(body.from || 'Anonimo').substring(0,30), amount, message: String(body.message || '').substring(0,100), flagged: fraud.flagged, flag_reason: fraud.flag_reason, created_at: new Date().toISOString() };
    db.donations.set(don.id, don);
    session.earnings_eur = (session.earnings_eur || 0) + amount;
    emitToAll(donMatch[1], { type: 'donation', payload: { from: don.from, amount, message: don.message, ts: don.created_at } });
    return respond(res, origin, { ok: true, donation_id: don.id, flagged: fraud.flagged }, 201);
  }

  // POST /api/live-sessions/:id/report
  const repMatch = path.match(/^\/api\/live-sessions\/([^/]+)\/report$/);
  if (method === 'POST' && repMatch) {
    const session = db.sessions.get(repMatch[1]);
    if (!session) return respond(res, origin, { error: 'Sessione non trovata' }, 404);
    const report = { id: crypto.randomUUID(), live_session_id: repMatch[1], viewer_id: viewerId, reason: String(body.reason || '').substring(0,200), resolution: 'PENDING', created_at: new Date().toISOString() };
    db.reports.set(report.id, report);
    const total = [...db.reports.values()].filter(r => r.live_session_id === repMatch[1]).length;
    emitToAdmins(repMatch[1], { type: 'report_received', payload: { report_id: report.id, reason: report.reason, total } });
    return respond(res, origin, { ok: true, report_id: report.id, total_reports: total });
  }

  // POST /api/admin/live-sessions/:id/actions
  const modMatch = path.match(/^\/api\/admin\/live-sessions\/([^/]+)\/actions$/);
  if (method === 'POST' && modMatch) {
    if (!isAdmin) return respond(res, origin, { error: 'Non autorizzato' }, 401);
    const session = db.sessions.get(modMatch[1]);
    if (!session) return respond(res, origin, { error: 'Sessione non trovata' }, 404);
    const allowed = ['BLUR_ON','BLUR_OFF','MUTE_AUDIO','END_LIVE','FREEZE_STREAM','WARNING','BAN_CREATOR'];
    if (!allowed.includes(body.action)) return respond(res, origin, { error: 'Azione non valida', allowed }, 400);
    const log = { id: crypto.randomUUID(), live_session_id: modMatch[1], action: body.action, admin_id: req.headers['x-admin-id'] || 'admin', reason: body.reason || null, created_at: new Date().toISOString() };
    db.mod_logs.set(log.id, log);
    emitToViewers(modMatch[1], { type: 'moderation_action', payload: { action: body.action, ts: log.created_at } });
    if (body.action === 'END_LIVE') { session.status = 'ENDED'; session.end_time = log.created_at; }
    return respond(res, origin, { ok: true, action: body.action, log_id: log.id });
  }

  // GET /api/admin/live-sessions
  if (method === 'GET' && path === '/api/admin/live-sessions') {
    if (!isAdmin) return respond(res, origin, { error: 'Non autorizzato' }, 401);
    const all = [...db.sessions.values()].map(s => ({
      ...s,
      report_count: [...db.reports.values()].filter(r => r.live_session_id === s.id).length,
      total_donations: [...db.donations.values()].filter(d => d.live_session_id === s.id).reduce((a,d) => a + d.amount, 0),
    }));
    return respond(res, origin, { sessions: all, total: all.length });
  }

  respond(res, origin, { error: 'Not found', path }, 404);
});

// ─── WEBSOCKET UPGRADE ────────────────────────────────────────
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://localhost');
  const sid  = url.searchParams.get('sessionId');
  const role = url.searchParams.get('role') || 'viewer';
  const aKey = url.searchParams.get('adminKey') || req.headers['x-admin-key'] || '';

  if (!sid) { socket.destroy(); return; }
  if (role === 'admin' && aKey !== CONFIG.ADMIN_KEY) { socket.destroy(); return; }

  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const acceptKey = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${acceptKey}`, '\r\n'].join('\r\n'));

  socket.clientId = crypto.randomUUID().substring(0,8);
  socket.sessionId = sid;
  socket.role = role;

  const room = getRoom(sid);
  if (role === 'admin') {
    room.admins.add(socket);
  } else {
    room.viewers.add(socket);
    const session = db.sessions.get(sid);
    if (session) session.viewer_count = room.viewers.size;
    emitToAll(sid, { type: 'viewer_count', payload: { count: room.viewers.size } });
  }

  socket.on('data', buffer => {
    try {
      const msg = decodeWSFrame(buffer);
      if (!msg) return;
      const data = JSON.parse(msg);
      if (data.type === 'chat_message') {
        emitToAll(sid, { type: 'chat_message', payload: { from: String(data.payload?.from || 'Anonimo').substring(0,30), message: String(data.payload?.message || '').substring(0,200), ts: new Date().toISOString() } });
      }
    } catch {}
  });

  socket.on('close', () => {
    room.viewers.delete(socket);
    room.admins.delete(socket);
    const session = db.sessions.get(sid);
    if (session && role === 'viewer') session.viewer_count = room.viewers.size;
  });
  socket.on('error', () => socket.destroy());
});

function decodeWSFrame(buffer) {
  if (buffer.length < 2) return null;
  const masked = !!(buffer[1] & 0x80);
  let payloadLen = buffer[1] & 0x7f;
  let offset = 2;
  if (payloadLen === 126)      { payloadLen = buffer.readUInt16BE(2); offset = 4; }
  else if (payloadLen === 127) { payloadLen = Number(buffer.readBigUInt64BE(2)); offset = 10; }
  if (masked) {
    const mask = buffer.slice(offset, offset+4); offset += 4;
    const payload = Buffer.from(buffer.slice(offset, offset+payloadLen));
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i%4];
    return payload.toString('utf8');
  }
  return buffer.slice(offset, offset+payloadLen).toString('utf8');
}

// ─── PULIZIA AUTOMATICA ───────────────────────────────────────
async function cleanupSessions() {
  const liveSessions = [...db.sessions.values()].filter(s => s.status === 'LIVE');
  if (liveSessions.length === 0) return;
  try {
    const svc = new RoomServiceClient(CONFIG.LIVEKIT_URL.replace('wss://', 'https://'), CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET);
    const rooms = await svc.listRooms(liveSessions.map(s => s.id));
    const activeNames = new Set(rooms.map(r => r.name));
    for (const session of liveSessions) {
      const room = rooms.find(r => r.name === session.id);
      const participants = room ? (room.numParticipants || 0) : 0;
      if (!activeNames.has(session.id) || participants === 0) {
        session.status = 'ENDED'; session.end_time = new Date().toISOString();
        const dbConn = await getDb();
        if (dbConn) dbConn.query('UPDATE live_sessions SET status=$1, end_time=$2 WHERE id=$3', ['ENDED', session.end_time, session.id]).catch(() => {});
        console.log('[CLEANUP] Sessione chiusa:', session.id.substring(0,8));
      } else {
        session.viewer_count = Math.max(0, participants - 1);
      }
    }
  } catch(e) { console.log('[CLEANUP] Errore:', e.message); }
}

setInterval(cleanupSessions, 5 * 60 * 1000);
setTimeout(cleanupSessions, 60 * 1000);

// ─── START ────────────────────────────────────────────────────
server.timeout = 30000;
server.requestTimeout = 15000;

server.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log(`\n🚀 CANDIDDD Backend v2.2 — porta ${CONFIG.PORT}`);
  console.log(`   LiveKit: ${CONFIG.LIVEKIT_URL}`);
  console.log(`   CORS: ${CONFIG.ALLOWED_ORIGIN}`);
  console.log(`   DB: ${process.env.DATABASE_URL ? 'PostgreSQL (Neon)' : 'RAM (fallback)'}\n`);
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 10000).unref(); });
process.on('SIGINT',  () => { server.close(() => process.exit(0)); });
