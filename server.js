const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app = express();
app.use(express.json());

function hash(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

const IS_VERCEL = !!process.env.VERCEL;
const DB_DIR    = path.join(__dirname, 'db');
const ADMIN_PASS = hash(process.env.ADMIN_PASSWORD || 'admin123');
// Secret for signing stateless tokens — stable across all Vercel instances
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'crmpro-secret-2024-nexo';

// ── Stateless signed tokens (work across all serverless instances) ────────────
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

// ── In-memory store ────────────────────────────────────────────────────────────
let _store = { clientes: null, usuarios: null, cotizaciones: null, proyectos: null };

function readJsonFile(filename, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(DB_DIR, filename), 'utf8')); }
  catch { return fallback; }
}

function initStore() {
  const adminUser = { id: 1, nombre: 'Johangel', email: 'sm8contact@gmail.com', password: ADMIN_PASS, rol: 'admin', activo: true, avatar: 'JG', creado: new Date().toISOString() };
  if (IS_VERCEL) {
    _store.clientes     = readJsonFile('clientes.json', []);
    _store.cotizaciones = readJsonFile('cotizaciones.json', []);
    _store.proyectos    = readJsonFile('proyectos.json', []);
    _store.usuarios     = [adminUser];
  } else {
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
}
initStore();

function read(key) {
  if (IS_VERCEL) return _store[key];
  return JSON.parse(fs.readFileSync(path.join(DB_DIR, key + '.json'), 'utf8'));
}
function write(key, data) {
  if (IS_VERCEL) { _store[key] = data; return; }
  fs.writeFileSync(path.join(DB_DIR, key + '.json'), JSON.stringify(data, null, 2));
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(roles = []) {
  return (req, res, next) => {
    const raw = req.headers['x-token'];
    if (!raw) return res.status(401).json({ error: 'No autenticado' });
    const payload = verifyToken(raw);
    if (!payload) return res.status(401).json({ error: 'Token inválido' });
    const usuarios = read('usuarios');
    const user = usuarios.find(u => u.id === payload.id && u.activo);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (roles.length && !roles.includes(user.rol)) return res.status(403).json({ error: 'Sin permiso' });
    req.user = user;
    next();
  };
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const usuarios = read('usuarios');
  const user = usuarios.find(u => u.email === email && u.password === hash(password) && u.activo);
  if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });
  const token = signToken({ id: user.id, rol: user.rol });
  res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, avatar: user.avatar } });
});

app.post('/api/logout', (req, res) => {
  // Stateless tokens: logout is handled client-side by deleting the token
  res.json({ ok: true });
});

app.get('/api/me', auth(), (req, res) => {
  const { password, ...safe } = req.user;
  res.json(safe);
});

// ── CLIENTES ─────────────────────────────────────────────────────────────────
app.get('/api/clientes', auth(), (req, res) => res.json(read('clientes')));
app.post('/api/clientes', auth(['admin', 'vendedor']), (req, res) => {
  write('clientes', req.body);
  res.json({ ok: true });
});

// ── USUARIOS ─────────────────────────────────────────────────────────────────
app.get('/api/usuarios', auth(['admin']), (req, res) => {
  res.json(read('usuarios').map(({ password, ...u }) => u));
});

app.post('/api/usuarios', auth(['admin']), (req, res) => {
  const usuarios = read('usuarios');
  const { nombre, email, password, rol, avatar } = req.body;
  if (usuarios.find(u => u.email === email)) return res.status(400).json({ error: 'Email ya registrado' });
  const nuevo = { id: Date.now(), nombre, email, password: hash(password), rol, activo: true, avatar: avatar || nombre.slice(0, 2).toUpperCase(), creado: new Date().toISOString() };
  usuarios.push(nuevo);
  write('usuarios', usuarios);
  const { password: _, ...safe } = nuevo;
  res.json(safe);
});

app.put('/api/usuarios/:id', auth(['admin']), (req, res) => {
  const usuarios = read('usuarios');
  const idx = usuarios.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  const { password, ...rest } = req.body;
  usuarios[idx] = { ...usuarios[idx], ...rest };
  if (password) usuarios[idx].password = hash(password);
  write('usuarios', usuarios);
  res.json({ ok: true });
});

app.delete('/api/usuarios/:id', auth(['admin']), (req, res) => {
  const uid = parseInt(req.params.id);
  if (uid === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const usuarios = read('usuarios').map(u => u.id === uid ? { ...u, activo: false } : u);
  write('usuarios', usuarios);
  res.json({ ok: true });
});

// ── COTIZACIONES ─────────────────────────────────────────────────────────────
app.get('/api/cotizaciones', auth(), (req, res) => res.json(read('cotizaciones')));

app.post('/api/cotizaciones', auth(['admin', 'vendedor']), (req, res) => {
  const cots = read('cotizaciones');
  const nueva = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, fecha: new Date().toISOString(), estado: req.body.estado || 'borrador' };
  cots.push(nueva);
  write('cotizaciones', cots);
  res.json(nueva);
});

app.put('/api/cotizaciones/:id', auth(['admin', 'vendedor']), (req, res) => {
  const cots = read('cotizaciones');
  const idx = cots.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrada' });
  cots[idx] = { ...cots[idx], ...req.body, actualizadoEn: new Date().toISOString() };
  write('cotizaciones', cots);
  res.json({ ok: true });
});

app.delete('/api/cotizaciones/:id', auth(['admin']), (req, res) => {
  write('cotizaciones', read('cotizaciones').filter(c => c.id !== parseInt(req.params.id)));
  res.json({ ok: true });
});

// ── PROYECTOS ─────────────────────────────────────────────────────────────────
app.get('/api/proyectos', auth(), (req, res) => res.json(read('proyectos')));

app.post('/api/proyectos', auth(['admin', 'vendedor']), (req, res) => {
  const proyectos = read('proyectos');
  const nuevo = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, fecha: new Date().toISOString(), mensajes: [], estado: 'pendiente', progreso: 0 };
  proyectos.push(nuevo);
  write('proyectos', proyectos);
  res.json(nuevo);
});

app.put('/api/proyectos/:id', auth(['admin', 'vendedor', 'desarrollador']), (req, res) => {
  const proyectos = read('proyectos');
  const idx = proyectos.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  if (req.user.rol === 'desarrollador') {
    ['estado', 'devAsignado', 'progreso'].forEach(k => { if (req.body[k] !== undefined) proyectos[idx][k] = req.body[k]; });
  } else {
    proyectos[idx] = { ...proyectos[idx], ...req.body };
  }
  proyectos[idx].actualizadoEn = new Date().toISOString();
  write('proyectos', proyectos);
  res.json({ ok: true });
});

app.post('/api/proyectos/:id/mensaje', auth(), (req, res) => {
  const proyectos = read('proyectos');
  const idx = proyectos.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  if (!proyectos[idx].mensajes) proyectos[idx].mensajes = [];
  const msg = { id: Date.now(), texto: req.body.texto, tipo: req.body.tipo || 'mensaje', autor: req.user.nombre, autorRol: req.user.rol, fecha: new Date().toISOString() };
  proyectos[idx].mensajes.push(msg);
  write('proyectos', proyectos);
  res.json(msg);
});

app.delete('/api/proyectos/:id', auth(['admin']), (req, res) => {
  write('proyectos', read('proyectos').filter(p => p.id !== parseInt(req.params.id)));
  res.json({ ok: true });
});

// Static files AFTER all API routes
app.use(express.static(path.join(__dirname, 'public')));

// Catch-all: serve index.html for any non-API route (Express 5 syntax)
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Local dev server (not used by Vercel)
if (!IS_VERCEL) {
  app.listen(3000, () => console.log('CRM Pro → http://localhost:3000'));
}

module.exports = app;
