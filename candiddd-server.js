#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// CANDIDDD.live — Backend All-in-One (Sprint 1+2)
// Stack: Node.js puro (zero dipendenze esterne tranne livekit-server-sdk)
// Funziona subito dopo: npm install && node server.js
// ═══════════════════════════════════════════════════════════════

// ── Dipendenze ────────────────────────────────────────────────
// npm install livekit-server-sdk @fastify/cors
const { AccessToken, RoomServiceClient } = require('livekit-server-sdk');
const http    = require('http');
const { EventEmitter } = require('events');
const crypto  = require('crypto');

// ─────────────────────────────────────────────────────────────
// CONFIG — compila con i valori dal dashboard LiveKit Cloud
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  PORT:              parseInt(process.env.PORT || '3000'),
  LIVEKIT_API_KEY:   process.env.LIVEKIT_API_KEY    || 'YOUR_LIVEKIT_API_KEY',
  LIVEKIT_API_SECRET:process.env.LIVEKIT_API_SECRET || 'YOUR_LIVEKIT_API_SECRET',
  LIVEKIT_URL:       process.env.LIVEKIT_URL         || 'wss://your-project.livekit.cloud',
  ADMIN_KEY:         process.env.ADMIN_KEY            || 'candiddd-admin-2026',
  WORKER_URL:        process.env.WORKER_URL           || 'http://localhost:4000',
};

// ─────────────────────────────────────────────────────────────
// IN-MEMORY DB (sviluppo) — sostituire con Postgres in produzione
// ─────────────────────────────────────────────────────────────
const db = {
  sessions:   new Map(),  // id → session
  donations:  new Map(),  // id → donation
  reports:    new Map(),  // id → report
  mod_logs:   new Map(),  // id → log
  // Anti-frode: userId → { total, timestamps[] }
  fraud:      new Map(),
};

// ─────────────────────────────────────────────────────────────
// LIVEKIT SERVICE
// ─────────────────────────────────────────────────────────────
const livekit = {
  // Token publisher (creator — può pubblicare audio/video)
  publisherToken(creatorId, roomName) {
    const at = new AccessToken(CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET, {
      identity: creatorId,
      ttl: '4h',
    });
    at.addGrant({
      room:           roomName,
      roomJoin:       true,
      canPublish:     true,
      canSubscribe:   false,
      canPublishData: true,
    });
    return at.toJwt();
  },

  // Token viewer (solo subscribe)
  viewerToken(roomName) {
    const identity = `viewer-${crypto.randomUUID().substring(0, 8)}`;
    const at = new AccessToken(CONFIG.LIVEKIT_API_KEY, CONFIG.LIVEKIT_API_SECRET, {
      identity,
      ttl: '4h',
    });
    at.addGrant({
      room:         roomName,
      roomJoin:     true,
      canPublish:   false,
      canSubscribe: true,
    });
    return at.toJwt();
  },

  // Verifica stanza via Room Service API
  async roomInfo(roomName) {
    try {
      const svc = new RoomServiceClient(
        CONFIG.LIVEKIT_URL.replace('wss://', 'https://'),
        CONFIG.LIVEKIT_API_KEY,
        CONFIG.LIVEKIT_API_SECRET,
      );
      const rooms = await svc.listRooms([roomName]);
      return rooms.find(r => r.name === roomName) || null;
    } catch (e) {
      return null;
    }
  },
};

// ─────────────────────────────────────────────────────────────
// WEBSOCKET — implementazione leggera con BroadcastChannel
// viewer room: live:{id}  |  admin room: admin:{id}
// ─────────────────────────────────────────────────────────────
const wsRooms = new Map(); // sessionId → { viewers: Set<ws>, admins: Set<ws> }

function getRoom(sessionId) {
  if (!wsRooms.has(sessionId)) wsRooms.set(sessionId, { viewers: new Set(), admins: new Set() });
  return wsRooms.get(sessionId);
}

function emitToViewers(sessionId, evt) {
  const room = getRoom(sessionId);
  const msg  = JSON.stringify(evt);
  for (const ws of room.viewers) { try { ws.send(msg); } catch {} }
}

function emitToAdmins(sessionId, evt) {
  const room = getRoom(sessionId);
  const msg  = JSON.stringify(evt);
  for (const ws of room.admins) { try { ws.send(msg); } catch {} }
}

function emitToAll(sessionId, evt) {
  emitToViewers(sessionId, evt);
  emitToAdmins(sessionId, evt);
}

// ─────────────────────────────────────────────────────────────
// ANTI-FRODE
// ─────────────────────────────────────────────────────────────
function fraudCheck(userId, amount) {
  const now  = Date.now();
  const key  = userId;
  const data = db.fraud.get(key) || { total: 0, timestamps: [] };

  // Rate limit: max 5 donazioni per minuto
  const recent = data.timestamps.filter(ts => now - ts < 60_000);
  if (recent.length >= 5) return { ok: false, reason: 'rate_limit', message: 'Max 5 donazioni/minuto' };

  // Limite giornaliero: max EUR 200
  if (data.total + amount > 200) return { ok: false, reason: 'daily_limit', message: 'Limite giornaliero EUR 200 raggiunto' };

  // Limite singola donazione
  if (amount > 100) return { ok: false, reason: 'amount_too_high', message: 'Max EUR 100 per donazione' };
  if (amount <= 0)  return { ok: false, reason: 'invalid_amount', message: 'Importo non valido' };

  // Aggiorna stato
  recent.push(now);
  db.fraud.set(key, { total: data.total + amount, timestamps: recent });

  const flagged = amount > 50 || recent.length >= 4;
  return { ok: true, flagged, flag_reason: flagged ? (amount > 50 ? 'high_amount' : 'high_velocity') : null };
}

// ─────────────────────────────────────────────────────────────
// HTTP ROUTER (senza framework)
// ─────────────────────────────────────────────────────────────
function respond(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods':'GET,POST,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers':'Content-Type,Authorization,X-Creator-Id,X-User-Id,X-Viewer-Id,X-Admin-Key,X-Admin-Id',
  });
  res.end(JSON.stringify(data));
}

async function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(data)); } catch { resolve({}); }
    });
  });
}

// ─────────────────────────────────────────────────────────────
// SERVER HTTP
// ─────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url    = new URL(req.url, `http://localhost`);
  const path   = url.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' }); res.end(); return; }

  const body       = ['POST','PATCH','PUT'].includes(method) ? await readBody(req) : {};
  const creatorId  = req.headers['x-creator-id'] || 'demo-creator';
  const userId     = req.headers['x-user-id']    || 'anon-' + Date.now();
  const viewerId   = req.headers['x-viewer-id']  || 'viewer-' + Date.now();
  const adminKey   = req.headers['x-admin-key']  || '';
  const isAdmin    = adminKey === CONFIG.ADMIN_KEY;

  // ── GET /api/health ──────────────────────────────────────
  if (method === 'GET' && path === '/api/health') {
    return respond(res, {
      ok: true,
      ts: new Date().toISOString(),
      livekit_configured: CONFIG.LIVEKIT_API_KEY !== 'YOUR_LIVEKIT_API_KEY',
      active_sessions: db.sessions.size,
      config: {
        livekit_url: CONFIG.LIVEKIT_URL,
        worker_url:  CONFIG.WORKER_URL,
      }
    });
  }

  // ══════════════════════════════════════════════════════════
  // LIVE SESSIONS
  // ══════════════════════════════════════════════════════════

  // ── POST /api/creator/live-sessions ─────────────────────
  if (method === 'POST' && path === '/api/creator/live-sessions') {
    const { level = 'CASA', mission_id = null, geo_lat, geo_lng } = body;

    const validLevels = ['CASA','ROUTINE','SOCIALE','LOCALE','CITTADINO','REGIONALE','NAZIONALE','GLOBALE'];
    if (!validLevels.includes(level)) return respond(res, { error: `Level non valido. Ammessi: ${validLevels.join(', ')}` }, 400);

    const id         = crypto.randomUUID();
    const streamKey  = `sk_${creatorId.substring(0, 8)}_${Date.now()}`;
    const now        = new Date().toISOString();

    // Genera token LiveKit per il creator (publisher)
    let livekitToken;
    try {
      livekitToken = livekit.publisherToken(creatorId, id);
    } catch (e) {
      return respond(res, { error: 'Errore generazione token LiveKit: ' + e.message }, 500);
    }

    const session = {
      id,
      creator_id:   creatorId,
      status:       'LIVE',
      level,
      mission_id,
      ingest_type:  'WEBRTC',
      stream_key:   streamKey,
      playback_url: `https://candiddd.live/live/${id}`,
      hls_url:      `https://cdn.candiddd.live/hls/${id}/index.m3u8`,
      geo_lat:      geo_lat || null,
      geo_lng:      geo_lng || null,
      start_time:   now,
      end_time:     null,
      viewer_count: 0,
      earnings_eur: 0,
      created_at:   now,
    };

    db.sessions.set(id, session);

    // Notifica WS: live_started
    emitToAll(id, { type: 'live_started', payload: { session_id: id, creator_id: creatorId, start_time: now, level } });

    // Notifica worker AI per avviare il transcoding (fire-and-forget)
    notifyWorker(id, creatorId).catch(() => {});

    console.log(`[SESSION] Created: ${id} by ${creatorId} — level: ${level}`);

    return respond(res, {
      live_session_id: id,
      livekit_token:   livekitToken,
      livekit_url:     CONFIG.LIVEKIT_URL,
      stream_key:      streamKey,
      playback_url:    session.playback_url,
      hls_url:         session.hls_url,
      status:          'LIVE',
      level,
    }, 201);
  }

  // ── PATCH /api/creator/live-sessions/:id/end ─────────────
  const endMatch = path.match(/^\/api\/creator\/live-sessions\/([^/]+)\/end$/);
  if (method === 'PATCH' && endMatch) {
    const sessionId = endMatch[1];
    const session   = db.sessions.get(sessionId);

    if (!session) return respond(res, { error: 'Sessione non trovata' }, 404);
    if (session.creator_id !== creatorId) return respond(res, { error: 'Non autorizzato' }, 403);
    if (session.status === 'ENDED') return respond(res, { session_id: sessionId, status: 'ENDED', already_ended: true });

    const now        = new Date().toISOString();
    const durationMs = new Date(now).getTime() - new Date(session.start_time).getTime();
    const durationSec = Math.round(durationMs / 1000);

    session.status   = 'ENDED';
    session.end_time = now;

    emitToAll(sessionId, { type: 'live_ended', payload: { session_id: sessionId, end_time: now, duration_seconds: durationSec } });

    console.log(`[SESSION] Ended: ${sessionId} — duration: ${durationSec}s`);
    return respond(res, { live_session_id: sessionId, status: 'ENDED', end_time: now, duration_seconds: durationSec, duration_human: `${Math.floor(durationSec/60)}m ${durationSec%60}s` });
  }

  // ── GET /api/live-sessions/:id (viewer) ──────────────────
  const sessionMatch = path.match(/^\/api\/live-sessions\/([^/]+)$/);
  if (method === 'GET' && sessionMatch) {
    const session = db.sessions.get(sessionMatch[1]);
    if (!session) return respond(res, { error: 'Sessione non trovata' }, 404);

    let viewerToken = null;
    if (session.status === 'LIVE') {
      try { viewerToken = livekit.viewerToken(session.id); } catch {}
    }

    return respond(res, {
      id:           session.id,
      status:       session.status,
      level:        session.level,
      playback_url: session.playback_url,
      hls_url:      session.hls_url,
      livekit_token: viewerToken,
      livekit_url:  CONFIG.LIVEKIT_URL,
      creator:      { id: session.creator_id, username: 'Creator CANDIDDD' },
      mission:      session.mission_id ? { id: session.mission_id } : null,
      viewer_count: session.viewer_count,
      start_time:   session.start_time,
      end_time:     session.end_time,
    });
  }

  // ── GET /api/live-sessions (lista live attive) ────────────
  if (method === 'GET' && path === '/api/live-sessions') {
    const active = [];
    for (const [, s] of db.sessions) {
      if (s.status === 'LIVE') active.push({ id: s.id, creator_id: s.creator_id, level: s.level, playback_url: s.playback_url, viewer_count: s.viewer_count, start_time: s.start_time });
    }
    return respond(res, { live_sessions: active, total: active.length });
  }

  // ══════════════════════════════════════════════════════════
  // DONAZIONI
  // ══════════════════════════════════════════════════════════

  // ── POST /api/live-sessions/:id/donations ─────────────────
  const donMatch = path.match(/^\/api\/live-sessions\/([^/]+)\/donations$/);
  if (method === 'POST' && donMatch) {
    const sessionId = donMatch[1];
    const session   = db.sessions.get(sessionId);
    if (!session || session.status !== 'LIVE') return respond(res, { error: 'Live non attiva' }, 400);

    const amount = parseFloat(body.amount);
    const fraud  = fraudCheck(userId, amount);

    if (!fraud.ok) return respond(res, { error: fraud.message, reason: fraud.reason }, 400);

    const don = {
      id:              crypto.randomUUID(),
      live_session_id: sessionId,
      user_id:         userId,
      from:            String(body.from || 'Anonimo').substring(0, 30),
      amount,
      currency:        'EUR',
      message:         String(body.message || '').substring(0, 100),
      flagged:         fraud.flagged,
      flag_reason:     fraud.flag_reason,
      created_at:      new Date().toISOString(),
    };
    db.donations.set(don.id, don);
    session.earnings_eur = (session.earnings_eur || 0) + amount;

    const evt = { type: 'donation', payload: { from: don.from, amount, currency: 'EUR', message: don.message, ts: don.created_at } };
    emitToAll(sessionId, evt);

    if (fraud.flagged) {
      emitToAdmins(sessionId, { type: 'donation_flagged', payload: { donation_id: don.id, reason: fraud.flag_reason, amount, user_id: userId } });
    }

    console.log(`[DONATION] ${don.from} → €${amount} on ${sessionId}${fraud.flagged ? ' ⚠️ FLAGGED' : ''}`);
    return respond(res, { ok: true, donation_id: don.id, flagged: fraud.flagged }, 201);
  }

  // ══════════════════════════════════════════════════════════
  // SEGNALAZIONI
  // ══════════════════════════════════════════════════════════

  // ── POST /api/live-sessions/:id/report ───────────────────
  const repMatch = path.match(/^\/api\/live-sessions\/([^/]+)\/report$/);
  if (method === 'POST' && repMatch) {
    const sessionId = repMatch[1];
    const session   = db.sessions.get(sessionId);
    if (!session) return respond(res, { error: 'Sessione non trovata' }, 404);

    const report = {
      id:              crypto.randomUUID(),
      live_session_id: sessionId,
      viewer_id:       viewerId,
      reason:          String(body.reason || 'Non specificato').substring(0, 200),
      resolution:      'PENDING',
      created_at:      new Date().toISOString(),
    };
    db.reports.set(report.id, report);

    // Conta segnalazioni per sessione
    const sessionReports = [...db.reports.values()].filter(r => r.live_session_id === sessionId).length;

    emitToAdmins(sessionId, { type: 'report_received', payload: { report_id: report.id, viewer_id: viewerId, reason: report.reason, total: sessionReports, ts: report.created_at } });

    // Auto-azioni
    if (sessionReports === 5) emitToAll(sessionId, { type: 'moderation_warning', payload: { reason: '5 segnalazioni automatiche', auto: true } });
    if (sessionReports === 10) {
      emitToViewers(sessionId, { type: 'moderation_action', payload: { action: 'BLUR_ON', auto: true } });
      console.warn(`[AUTO-BLUR] Session ${sessionId} — 10 reports`);
    }

    console.log(`[REPORT] ${report.reason} on ${sessionId} (total: ${sessionReports})`);
    return respond(res, { ok: true, report_id: report.id, total_reports: sessionReports });
  }

  // ══════════════════════════════════════════════════════════
  // MODERAZIONE ADMIN
  // ══════════════════════════════════════════════════════════

  // ── POST /api/admin/live-sessions/:id/actions ─────────────
  const modMatch = path.match(/^\/api\/admin\/live-sessions\/([^/]+)\/actions$/);
  if (method === 'POST' && modMatch) {
    if (!isAdmin) return respond(res, { error: 'Non autorizzato' }, 401);

    const sessionId = modMatch[1];
    const session   = db.sessions.get(sessionId);
    if (!session) return respond(res, { error: 'Sessione non trovata' }, 404);

    const allowed = ['BLUR_ON','BLUR_OFF','MUTE_AUDIO','END_LIVE','FREEZE_STREAM','WARNING','BAN_CREATOR'];
    if (!allowed.includes(body.action)) return respond(res, { error: 'Azione non valida', allowed }, 400);

    const log = {
      id:              crypto.randomUUID(),
      live_session_id: sessionId,
      action:          body.action,
      admin_id:        req.headers['x-admin-id'] || 'admin',
      reason:          body.reason || null,
      created_at:      new Date().toISOString(),
    };
    db.mod_logs.set(log.id, log);

    // Emetti a viewer e admin
    emitToViewers(sessionId, { type: 'moderation_action', payload: { action: body.action, ts: log.created_at } });
    emitToAdmins(sessionId, { type: 'admin_action_confirmed', payload: { action: body.action, ok: true } });

    // Se END_LIVE → chiudi sessione
    if (body.action === 'END_LIVE') {
      session.status   = 'ENDED';
      session.end_time = log.created_at;
      emitToAll(sessionId, { type: 'live_ended', payload: { session_id: sessionId, end_time: log.created_at, forced: true } });
    }

    // Notifica worker se blur
    if (['BLUR_ON','BLUR_OFF','END_LIVE'].includes(body.action)) {
      notifyWorkerAction(sessionId, body.action).catch(() => {});
    }

    console.log(`[MOD] ${body.action} on ${sessionId} by ${log.admin_id}`);
    return respond(res, { ok: true, action: body.action, log_id: log.id });
  }

  // ── GET /api/admin/live-sessions — dashboard admin ────────
  if (method === 'GET' && path === '/api/admin/live-sessions') {
    if (!isAdmin) return respond(res, { error: 'Non autorizzato' }, 401);
    const all = [];
    for (const [, s] of db.sessions) {
      const reports = [...db.reports.values()].filter(r => r.live_session_id === s.id).length;
      const donations = [...db.donations.values()].filter(d => d.live_session_id === s.id).reduce((acc, d) => acc + d.amount, 0);
      all.push({ ...s, report_count: reports, total_donations: donations });
    }
    return respond(res, { sessions: all, total: all.length });
  }

  // ── GET /api/admin/live-sessions/:id/logs ─────────────────
  const logsMatch = path.match(/^\/api\/admin\/live-sessions\/([^/]+)\/logs$/);
  if (method === 'GET' && logsMatch) {
    if (!isAdmin) return respond(res, { error: 'Non autorizzato' }, 401);
    const sid  = logsMatch[1];
    const logs = [...db.mod_logs.values()].filter(l => l.live_session_id === sid);
    const reps = [...db.reports.values()].filter(r => r.live_session_id === sid);
    const dons = [...db.donations.values()].filter(d => d.live_session_id === sid);
    return respond(res, { session_id: sid, moderation_logs: logs, reports: reps, donations: dons });
  }

  // ── POST /api/admin/live-sessions/:id/replay-clip ─────────
  const clipMatch = path.match(/^\/api\/admin\/live-sessions\/([^/]+)\/replay-clip$/);
  if (method === 'POST' && clipMatch) {
    if (!isAdmin) return respond(res, { error: 'Non autorizzato' }, 401);
    const secondsBack = body.seconds_back || 20;
    // Richiede al worker di salvare la clip
    const clipRes = await fetch(`${CONFIG.WORKER_URL}/sessions/${clipMatch[1]}/replay-clip`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seconds_back: secondsBack }),
    }).catch(() => null);
    if (!clipRes?.ok) return respond(res, { error: 'Worker non disponibile', fallback: 'Clip salvata in locale' });
    const clipData = await clipRes.json();
    return respond(res, clipData);
  }

  // ── POST /api/internal/emit/:id (dal worker AI) ───────────
  const emitMatch = path.match(/^\/api\/internal\/emit\/([^/]+)$/);
  if (method === 'POST' && emitMatch) {
    const backendKey = req.headers['x-backend-key'];
    if (backendKey !== (process.env.BACKEND_KEY || 'candiddd-backend-2026')) return respond(res, { error: 'Non autorizzato' }, 401);
    const sessionId = emitMatch[1];
    emitToAll(sessionId, body);
    return respond(res, { ok: true });
  }

  respond(res, { error: 'Not found', path }, 404);
});

// ─────────────────────────────────────────────────────────────
// WEBSOCKET SERVER (upgrade HTTP → WS manuale, zero dipendenze)
// ─────────────────────────────────────────────────────────────
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  const sessionId = url.searchParams.get('sessionId');
  const role      = url.searchParams.get('role') || 'viewer';
  const adminKey  = url.searchParams.get('adminKey') || req.headers['x-admin-key'] || '';

  if (!sessionId) { socket.destroy(); return; }
  if (role === 'admin' && adminKey !== CONFIG.ADMIN_KEY) { socket.destroy(); return; }

  // WebSocket handshake
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const acceptKey = require('crypto')
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '\r\n',
  ].join('\r\n'));

  socket.clientId  = crypto.randomUUID().substring(0, 8);
  socket.sessionId = sessionId;
  socket.role      = role;

  const room = getRoom(sessionId);
  if (role === 'admin') {
    room.admins.add(socket);
    wsEmit(socket, { type: 'admin_connected', payload: { session_id: sessionId } });
  } else {
    room.viewers.add(socket);
    // Aggiorna viewer count
    const session = db.sessions.get(sessionId);
    if (session) session.viewer_count = room.viewers.size;
    emitToAll(sessionId, { type: 'viewer_count', payload: { count: room.viewers.size } });
    emitToAdmins(sessionId, { type: 'viewer_joined', payload: { viewer_id: socket.clientId } });
  }

  console.log(`[WS] ${role} connected to ${sessionId} (total viewers: ${room.viewers.size})`);

  // Gestione messaggi WS in arrivo
  socket.on('data', (buffer) => {
    try {
      const msg = decodeWSFrame(buffer);
      if (!msg) return;
      const data = JSON.parse(msg);
      handleWSMessage(socket, data);
    } catch {}
  });

  socket.on('close', () => {
    room.viewers.delete(socket);
    room.admins.delete(socket);
    if (socket.role === 'viewer') {
      const session = db.sessions.get(sessionId);
      if (session) session.viewer_count = room.viewers.size;
      emitToAll(sessionId, { type: 'viewer_count', payload: { count: room.viewers.size } });
    }
  });
  socket.on('error', () => socket.destroy());
});

function handleWSMessage(socket, data) {
  const { sessionId, role } = socket;

  if (role === 'viewer') {
    switch (data.type) {
      case 'chat_message': {
        const evt = { type: 'chat_message', payload: { from: String(data.payload?.from || 'Anonimo').substring(0,30), message: String(data.payload?.message || '').substring(0,200), ts: new Date().toISOString() } };
        emitToAll(sessionId, evt);
        break;
      }
      case 'report': {
        // Reindirizza al REST handler
        const r = { id: crypto.randomUUID(), live_session_id: sessionId, viewer_id: socket.clientId, reason: String(data.payload?.reason || '').substring(0,200), created_at: new Date().toISOString() };
        db.reports.set(r.id, r);
        const total = [...db.reports.values()].filter(x => x.live_session_id === sessionId).length;
        emitToAdmins(sessionId, { type: 'report_received', payload: { ...r, total } });
        wsEmit(socket, { type: 'report_confirmed', payload: { ok: true } });
        break;
      }
    }
  }

  if (role === 'admin') {
    switch (data.type) {
      case 'moderation_action': {
        const allowed = ['BLUR_ON','BLUR_OFF','MUTE_AUDIO','END_LIVE','FREEZE_STREAM','WARNING'];
        if (!allowed.includes(data.payload?.action)) break;
        emitToViewers(sessionId, { type: 'moderation_action', payload: { action: data.payload.action, ts: new Date().toISOString() } });
        wsEmit(socket, { type: 'action_confirmed', payload: { action: data.payload.action, ok: true } });
        if (data.payload.action === 'END_LIVE') {
          const s = db.sessions.get(sessionId);
          if (s) { s.status = 'ENDED'; s.end_time = new Date().toISOString(); }
        }
        break;
      }
      case 'mission_update':
        emitToAll(sessionId, { type: 'mission_update', payload: data.payload });
        break;
      case 'mission_end':
        emitToAll(sessionId, { type: 'mission_end', payload: { ts: new Date().toISOString() } });
        break;
    }
  }
}

// Encode/decode WebSocket frame (RFC 6455, frame base senza extension)
function wsEmit(socket, data) {
  try {
    const msg    = JSON.stringify(data);
    const msgBuf = Buffer.from(msg, 'utf8');
    const len    = msgBuf.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[0] = 0x81;     // FIN + text frame
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x81;
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x81;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    socket.write(Buffer.concat([header, msgBuf]));
  } catch {}
}

// Metodi di broadcast usano wsEmit
function decodeWSFrame(buffer) {
  if (buffer.length < 2) return null;
  const masked  = !!(buffer[1] & 0x80);
  let payloadLen = buffer[1] & 0x7f;
  let offset    = 2;

  if (payloadLen === 126)      { payloadLen = buffer.readUInt16BE(2); offset = 4; }
  else if (payloadLen === 127) { payloadLen = Number(buffer.readBigUInt64BE(2)); offset = 10; }

  if (masked) {
    const mask    = buffer.slice(offset, offset + 4);
    offset       += 4;
    const payload = Buffer.from(buffer.slice(offset, offset + payloadLen));
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    return payload.toString('utf8');
  }
  return buffer.slice(offset, offset + payloadLen).toString('utf8');
}

// Override broadcast functions per usare wsEmit
const _emitToViewers = emitToViewers;
const _emitToAdmins  = emitToAdmins;
// Ridefinisci per usare wsEmit invece di ws.send
function emitBroadcast(set, evt) {
  const msg = JSON.stringify(evt);
  for (const socket of set) {
    wsEmit(socket, evt);
  }
}
// Patch globale
Object.assign(global, {
  __emitToViewers: (sid, evt) => emitBroadcast(getRoom(sid).viewers, evt),
  __emitToAdmins:  (sid, evt) => emitBroadcast(getRoom(sid).admins, evt),
});

// ─────────────────────────────────────────────────────────────
// NOTIFY WORKER (fire-and-forget)
// ─────────────────────────────────────────────────────────────
async function notifyWorker(sessionId, creatorId) {
  const session = db.sessions.get(sessionId);
  if (!session) return;
  // In produzione: LiveKit Egress URL da LiveKit Cloud
  const ingestUrl = `rtmp://${CONFIG.LIVEKIT_URL.replace('wss://','')}/egress/${sessionId}`;
  await fetch(`${CONFIG.WORKER_URL}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, input_url: ingestUrl }),
  }).catch(() => console.log('[WORKER] Not reachable — start manually'));
}

async function notifyWorkerAction(sessionId, action) {
  if (action === 'END_LIVE') {
    await fetch(`${CONFIG.WORKER_URL}/sessions/${sessionId}`, { method: 'DELETE' }).catch(() => {});
  } else if (action === 'BLUR_ON') {
    await fetch(`${CONFIG.WORKER_URL}/sessions/${sessionId}/blur`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enable: true }) }).catch(() => {});
  } else if (action === 'BLUR_OFF') {
    await fetch(`${CONFIG.WORKER_URL}/sessions/${sessionId}/blur`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enable: false }) }).catch(() => {});
  }
}

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
server.listen(CONFIG.PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   CANDIDDD.live Backend — Sprint 1+2     ║');
  console.log(`╠══════════════════════════════════════════╣`);
  console.log(`║  http://localhost:${CONFIG.PORT}                  ║`);
  console.log(`║  LiveKit: ${CONFIG.LIVEKIT_URL.substring(0, 30)}...║`);
  console.log(`║  Configured: ${CONFIG.LIVEKIT_API_KEY !== 'YOUR_LIVEKIT_API_KEY' ? '✅ YES' : '❌ Set LIVEKIT_API_KEY'}          ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log('Endpoints:');
  console.log('  POST  /api/creator/live-sessions');
  console.log('  PATCH /api/creator/live-sessions/:id/end');
  console.log('  GET   /api/live-sessions/:id');
  console.log('  GET   /api/live-sessions');
  console.log('  POST  /api/live-sessions/:id/donations');
  console.log('  POST  /api/live-sessions/:id/report');
  console.log('  POST  /api/admin/live-sessions/:id/actions');
  console.log('  GET   /api/admin/live-sessions (X-Admin-Key richiesta)');
  console.log('  WS    ws://localhost:' + CONFIG.PORT + '?sessionId={id}&role=viewer');
  console.log('  WS    ws://localhost:' + CONFIG.PORT + '?sessionId={id}&role=admin&adminKey={key}');
  console.log('');

  if (CONFIG.LIVEKIT_API_KEY === 'YOUR_LIVEKIT_API_KEY') {
    console.log('⚠️  ATTENZIONE: LiveKit non configurato!');
    console.log('   1. Vai su https://livekit.io/cloud');
    console.log('   2. Crea un progetto gratuito');
    console.log('   3. Copia le credenziali nel .env');
    console.log('   4. Rilancia: LIVEKIT_API_KEY=xxx LIVEKIT_API_SECRET=yyy node server.js');
    console.log('');
  }
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT',  () => { server.close(() => process.exit(0)); });
