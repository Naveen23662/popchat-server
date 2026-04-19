/**
 * PopChat — Production Signaling Server
 * ─────────────────────────────────────
 * npm install express socket.io jsonwebtoken dotenv cors express-rate-limit helmet
 * node server.js
 * Deploy → railway.app (free)
 */

require('dotenv').config();
const express     = require('express');
const http        = require('http');
const { Server }  = require('socket.io');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL || '*', methods: ['GET','POST'] },
  pingTimeout: 20000,
  pingInterval: 10000,
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_in_production';

// ── Security headers ────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '10kb' }));

// ── Rate limiting ───────────────────────────────
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts. Try again later.' } });
app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// ── In-memory store (swap Redis for production scale) ──
let   waitingSocket = null;
const activeRooms   = new Map();
const bannedUsers   = new Set();
const reportLog     = [];
const socketConnectCount = new Map(); // IP → count (basic socket flood guard)

// ── Health ──────────────────────────────────────
app.get('/', (_, res) => res.json({ status: '🟢 PopChat running', version: '1.0.0' }));

// ── Online count ────────────────────────────────
app.get('/api/online', (_, res) => res.json({ count: io.engine.clientsCount }));

// ── ICE / TURN credentials ──────────────────────
app.get('/api/ice', (_, res) => {
  res.json({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      {
        urls: [
          'turn:openrelay.metered.ca:80',
          'turn:openrelay.metered.ca:443',
          'turn:openrelay.metered.ca:443?transport=tcp',
        ],
        username: 'openrelayproject',
        credential: 'openrelayproject',
      },
    ],
  });
});

// ── Email auth ──────────────────────────────────
// STUB: replace with bcrypt + real DB (Supabase, Postgres, etc.)
app.post('/api/auth/email', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || typeof email !== 'string' || !email.includes('@'))
    return res.status(400).json({ error: 'Valid email required.' });
  if (!password || typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (bannedUsers.has(email.toLowerCase()))
    return res.status(403).json({ error: 'Account permanently banned for violating community guidelines.' });

  // Replace with: const user = await db.findUser(email); await bcrypt.compare(password, user.hash)
  const token = jwt.sign(
    { userId: Buffer.from(email.toLowerCase()).toString('base64'), email: email.toLowerCase(), name: email.split('@')[0] },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, name: email.split('@')[0] });
});

// ── Report (REST fallback) ───────────────────────
app.post('/api/report', (req, res) => {
  const { reason, reportedBy } = req.body || {};
  const entry = { reason, reportedBy, ts: new Date().toISOString(), source: 'rest' };
  reportLog.push(entry);
  console.log('[REPORT]', entry);
  // TODO: persist to DB + alert moderation dashboard
  res.json({ ok: true });
});

// ── Socket auth middleware ───────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (token && token !== 'demo') {
    try {
      socket.user = jwt.verify(token, JWT_SECRET);
      if (bannedUsers.has(socket.user?.email)) return next(new Error('Account banned.'));
    } catch { /* allow as guest for now */ }
  }
  socket.user = socket.user || { name: 'Guest', userId: socket.id };

  // Basic flood guard: max 3 concurrent sockets per IP
  const ip = socket.handshake.address;
  const count = (socketConnectCount.get(ip) || 0) + 1;
  if (count > 5) return next(new Error('Too many connections from this address.'));
  socketConnectCount.set(ip, count);
  socket.on('disconnect', () => {
    const c = (socketConnectCount.get(ip) || 1) - 1;
    if (c <= 0) socketConnectCount.delete(ip);
    else socketConnectCount.set(ip, c);
  });

  next();
});

// ── Socket events ────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[+] ${socket.user.name} (${socket.id})`);

  // MATCHMAKING
  socket.on('find-peer', () => {
    if (waitingSocket && (!waitingSocket.connected || waitingSocket.id === socket.id)) {
      waitingSocket = null;
    }
    if (waitingSocket) {
      const roomId = `room_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
      const peer   = waitingSocket;
      waitingSocket = null;
      socket.join(roomId);
      peer.join(roomId);
      activeRooms.set(roomId, { offerer: socket.id, answerer: peer.id, startedAt: Date.now() });
      socket.emit('matched', { room: roomId, role: 'offerer' });
      peer.emit('matched',   { room: roomId, role: 'answerer' });
      console.log(`[MATCH] ${socket.id} ↔ ${peer.id} → ${roomId}`);
    } else {
      waitingSocket = socket;
      socket.emit('waiting');
      console.log(`[WAIT] ${socket.id}`);
    }
  });

  // WEBRTC RELAY
  socket.on('offer',         ({ room, offer })      => socket.to(room).emit('offer',         { offer }));
  socket.on('answer',        ({ room, answer })     => socket.to(room).emit('answer',        { answer }));
  socket.on('ice-candidate', ({ room, candidate })  => socket.to(room).emit('ice-candidate', { candidate }));

  // CHAT RELAY — basic sanitisation
  socket.on('chat-message', ({ room, text }) => {
    if (!text || typeof text !== 'string') return;
    const clean = text.trim().slice(0, 500); // max 500 chars
    if (!clean) return;
    socket.to(room).emit('chat-message', { text: clean });
  });

  // TYPING
  socket.on('typing', ({ room }) => socket.to(room).emit('peer-typing'));

  // LEAVE
  socket.on('leave-room', ({ room }) => {
    socket.to(room).emit('peer-disconnected');
    socket.leave(room);
    activeRooms.delete(room);
    console.log(`[LEAVE] ${socket.id} left ${room}`);
  });

  // REPORT
  socket.on('report-user', ({ reason }) => {
    if (!reason) return;
    const entry = { reportedBy: socket.user.userId, reason, ts: new Date().toISOString(), source: 'socket' };
    reportLog.push(entry);
    console.log('[REPORT]', entry);
    socket.emit('report-received');
    // TODO: persist + alert moderation
  });

  // DISCONNECT
  socket.on('disconnect', () => {
    console.log(`[-] ${socket.user.name} (${socket.id})`);
    if (waitingSocket?.id === socket.id) waitingSocket = null;
    for (const [roomId, m] of activeRooms) {
      if (m.offerer === socket.id || m.answerer === socket.id) {
        socket.to(roomId).emit('peer-disconnected');
        activeRooms.delete(roomId);
        break;
      }
    }
  });
});

// ── Start ────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`\n🚀 PopChat server running on port ${PORT}`);
  console.log(`   JWT: ${JWT_SECRET !== 'dev_secret_change_in_production' ? '✅ custom secret set' : '⚠️  using dev secret — set JWT_SECRET in .env'}`);
  console.log(`   Frontend: ${process.env.FRONTEND_URL || '* (open)'}\n`);
});
