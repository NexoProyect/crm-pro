const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

function hash(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

const IS_VERCEL   = !!process.env.VERCEL;
const DB_DIR      = path.join(__dirname, 'db');
const ADMIN_PASS  = hash(process.env.ADMIN_PASSWORD || 'admin123');
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'crmpro-secret-2024-nexo';
const MONGODB_URI  = process.env.MONGODB_URI;

// ── Tokens ────────────────────────────────────────────────────────────────────
function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(data, 'base64url').toString());
  } catch { return null; }
}

// ── DB layer ──────────────────────────────────────────────────────────────────
// MongoDB: one document per collection key, shape: { _id: key, data: [...] }
// Local:   JSON files in db/

let _clientPromise = null;

async function getDb() {
  if (!_clientPromise) {
    const client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 10000,
    });
    _clientPromise = client.connect().then(c => c.db('crmpro'));
  }
  try {
    const db = await _clientPromise;
    // Ping to detect stale connection and reconnect if needed
    await db.command({ ping: 1 });
    return db;
  } catch {
    _clientPromise = null;
    const client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 10000,
    });
    _clientPromise = client.connect().then(c => c.db('crmpro'));
    return await _clientPromise;
  }
}

const adminUser = {
  id: 1,
  nombre: 'Johangel',
  email: 'sm8contact@gmail.com',
  password: ADMIN_PASS,
  rol: 'admin',
  activo: true,
  avatar: 'JG',
  creado: new Date().toISOString(),
};

async function read(key) {
  if (MONGODB_URI) {
    const db  = await getDb();
    const doc = await db.collection('store').findOne({ _id: key });
    // Seed admin on first read of usuarios if collection is empty
    if (key === 'usuarios' && (!doc || !doc.data || doc.data.length === 0)) {
      await db.collection('store').updateOne(
        { _id: 'usuarios' },
        { $set: { data: [adminUser] } },
        { upsert: true }
      );
      return [adminUser];
    }
    return doc ? doc.data : [];
  }
  // Local filesystem
  try { return JSON.parse(fs.readFileSync(path.join(DB_DIR, key + '.json'), 'utf8')); }
  catch { return []; }
}

async function write(key, data) {
  if (MONGODB_URI) {
    const db = await getDb();
    await db.collection('store').updateOne(
      { _id: key },
      { $set: { data } },
      { upsert: true }
    );
    return;
  }
  fs.writeFileSync(path.join(DB_DIR, key + '.json'), JSON.stringify(data, null, 2));
}

// Local-only: init JSON files if missing
function initLocalStore() {
  if (MONGODB_URI) return;
  const defaults = {
    'clientes.json': [], 'cotizaciones.json': [], 'proyectos.json': [],
    'usuarios.json': [adminUser],
  };
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  Object.entries(defaults).forEach(([f, d]) => {
    const p = path.join(DB_DIR, f);
    if (!fs.existsSync(p)) fs.writeFileSync(p, JSON.stringify(d, null, 2));
  });
}
initLocalStore();

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(roles = []) {
  return async (req, res, next) => {
    const raw = req.headers['x-token'];
    if (!raw) return res.status(401).json({ error: 'No autenticado' });
    const payload = verifyToken(raw);
    if (!payload) return res.status(401).json({ error: 'Token inválido' });
    const usuarios = await read('usuarios');
    const user = usuarios.find(u => u.id === payload.id && u.activo);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (roles.length && !roles.includes(user.rol)) return res.status(403).json({ error: 'Sin permiso' });
    req.user = user;
    next();
  };
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const usuarios = await read('usuarios');
  const user = usuarios.find(u => u.email === email && u.password === hash(password) && u.activo);
  if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
  const token = signToken({ id: user.id, rol: user.rol });
  res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, avatar: user.avatar } });
});

app.post('/api/logout', (req, res) => res.json({ ok: true }));

app.get('/api/me', auth(), async (req, res) => {
  const { password, ...safe } = req.user;
  res.json(safe);
});

// ── CLIENTES ──────────────────────────────────────────────────────────────────
app.get('/api/clientes', auth(), async (req, res) => res.json(await read('clientes')));

app.post('/api/clientes', auth(['admin', 'vendedor']), async (req, res) => {
  await write('clientes', req.body);
  res.json({ ok: true });
});

// ── USUARIOS ──────────────────────────────────────────────────────────────────
app.get('/api/usuarios', auth(['admin']), async (req, res) => {
  res.json((await read('usuarios')).map(({ password, ...u }) => u));
});

app.post('/api/usuarios', auth(['admin']), async (req, res) => {
  const usuarios = await read('usuarios');
  const { nombre, email, password, rol, avatar } = req.body;
  if (usuarios.find(u => u.email === email)) return res.status(400).json({ error: 'Email ya registrado' });
  const nuevo = { id: Date.now(), nombre, email, password: hash(password), rol, activo: true, avatar: avatar || nombre.slice(0, 2).toUpperCase(), creado: new Date().toISOString() };
  usuarios.push(nuevo);
  await write('usuarios', usuarios);
  const { password: _, ...safe } = nuevo;
  res.json(safe);
});

app.put('/api/usuarios/:id', auth(['admin']), async (req, res) => {
  const usuarios = await read('usuarios');
  const idx = usuarios.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  const { password, ...rest } = req.body;
  usuarios[idx] = { ...usuarios[idx], ...rest };
  if (password) usuarios[idx].password = hash(password);
  await write('usuarios', usuarios);
  res.json({ ok: true });
});

app.delete('/api/usuarios/:id', auth(['admin']), async (req, res) => {
  const uid = parseInt(req.params.id);
  if (uid === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const usuarios = (await read('usuarios')).map(u => u.id === uid ? { ...u, activo: false } : u);
  await write('usuarios', usuarios);
  res.json({ ok: true });
});

// ── COTIZACIONES ──────────────────────────────────────────────────────────────
app.get('/api/cotizaciones', auth(), async (req, res) => res.json(await read('cotizaciones')));

app.post('/api/cotizaciones', auth(['admin', 'vendedor']), async (req, res) => {
  const cots = await read('cotizaciones');
  const nueva = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, fecha: new Date().toISOString(), estado: req.body.estado || 'borrador' };
  cots.push(nueva);
  await write('cotizaciones', cots);
  res.json(nueva);
});

app.put('/api/cotizaciones/:id', auth(['admin', 'vendedor']), async (req, res) => {
  const cots = await read('cotizaciones');
  const idx = cots.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrada' });
  cots[idx] = { ...cots[idx], ...req.body, actualizadoEn: new Date().toISOString() };
  await write('cotizaciones', cots);
  res.json({ ok: true });
});

app.delete('/api/cotizaciones/:id', auth(['admin']), async (req, res) => {
  await write('cotizaciones', (await read('cotizaciones')).filter(c => c.id !== parseInt(req.params.id)));
  res.json({ ok: true });
});

// ── PROYECTOS ─────────────────────────────────────────────────────────────────
app.get('/api/proyectos', auth(), async (req, res) => res.json(await read('proyectos')));

app.post('/api/proyectos', auth(['admin', 'vendedor']), async (req, res) => {
  const proyectos = await read('proyectos');
  const nuevo = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, fecha: new Date().toISOString(), mensajes: [], estado: 'pendiente', progreso: 0 };
  proyectos.push(nuevo);
  await write('proyectos', proyectos);
  res.json(nuevo);
});

app.put('/api/proyectos/:id', auth(['admin', 'vendedor', 'desarrollador']), async (req, res) => {
  const proyectos = await read('proyectos');
  const idx = proyectos.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  if (req.user.rol === 'desarrollador') {
    ['estado', 'devAsignado', 'progreso'].forEach(k => { if (req.body[k] !== undefined) proyectos[idx][k] = req.body[k]; });
  } else {
    proyectos[idx] = { ...proyectos[idx], ...req.body };
  }
  proyectos[idx].actualizadoEn = new Date().toISOString();
  await write('proyectos', proyectos);
  res.json({ ok: true });
});

app.post('/api/proyectos/:id/mensaje', auth(), async (req, res) => {
  const proyectos = await read('proyectos');
  const idx = proyectos.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  if (!proyectos[idx].mensajes) proyectos[idx].mensajes = [];
  const msg = { id: Date.now(), texto: req.body.texto, tipo: req.body.tipo || 'mensaje', autor: req.user.nombre, autorRol: req.user.rol, fecha: new Date().toISOString() };
  proyectos[idx].mensajes.push(msg);
  await write('proyectos', proyectos);
  res.json(msg);
});

app.delete('/api/proyectos/:id', auth(['admin']), async (req, res) => {
  await write('proyectos', (await read('proyectos')).filter(p => p.id !== parseInt(req.params.id)));
  res.json({ ok: true });
});

// ── CAMPAÑAS ──────────────────────────────────────────────────────────────────
app.get('/api/campanas', auth(['admin', 'vendedor', 'soporte']), async (req, res) => {
  res.json(await read('campanas'));
});

app.post('/api/campanas', auth(['admin']), async (req, res) => {
  const campanas = await read('campanas');
  const { campana, prospectos } = req.body;
  if (!campana || !prospectos) return res.status(400).json({ error: 'JSON inválido: falta campana o prospectos' });
  const existente = campanas.findIndex(c => c.campana.id === campana.id);
  const nueva = { id: campana.id, campana, prospectos: prospectos.map(p => ({ ...p, _estado: p.outreach?.estado || 'pendiente' })), importadoEn: new Date().toISOString(), importadoPor: req.user.nombre };
  if (existente >= 0) { campanas[existente] = nueva; }
  else { campanas.push(nueva); }
  await write('campanas', campanas);
  res.json({ ok: true, total: prospectos.length });
});

// Actualizar estado de un prospecto dentro de una campaña
app.put('/api/campanas/:id/prospecto/:pid', auth(['admin', 'vendedor', 'soporte']), async (req, res) => {
  const campanas = await read('campanas');
  const idx = campanas.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Campaña no encontrada' });
  const pidx = campanas[idx].prospectos.findIndex(p => p.id === parseInt(req.params.pid));
  if (pidx === -1) return res.status(404).json({ error: 'Prospecto no encontrado' });
  campanas[idx].prospectos[pidx] = { ...campanas[idx].prospectos[pidx], ...req.body };
  await write('campanas', campanas);
  res.json({ ok: true });
});

app.delete('/api/campanas/:id', auth(['admin']), async (req, res) => {
  await write('campanas', (await read('campanas')).filter(c => c.id !== req.params.id));
  res.json({ ok: true });
});

// ── Static ────────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!IS_VERCEL) {
  app.listen(3000, () => console.log('CRM Pro → http://localhost:3000'));
}

module.exports = app;
