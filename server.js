const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const crypto       = require('crypto');
const bcrypt       = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());
app.use(cookieParser());

const IS_VERCEL    = !!process.env.VERCEL;
const DB_DIR       = path.join(__dirname, 'db');
const TOKEN_SECRET = process.env.TOKEN_SECRET || (() => {
  if (!IS_VERCEL) console.warn('[WARN] TOKEN_SECRET no definido — usando clave insegura. Setea la variable de entorno.');
  return 'crmpro-dev-only-' + crypto.randomBytes(16).toString('hex');
})();
const MONGODB_URI  = process.env.MONGODB_URI;
const COOKIE_NAME  = 'crm_session';
const TOKEN_TTL_S  = 8 * 60 * 60; // 8 horas

// ── Tokens (HMAC-SHA256, con expiración) ──────────────────────────────────────
function signToken(payload) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_S };
  const data = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig  = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expirado
    return payload;
  } catch { return null; }
}

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,                        // JS no puede leerla
    secure: IS_VERCEL || process.env.NODE_ENV === 'production', // HTTPS en prod
    sameSite: 'strict',                    // bloquea CSRF cross-site
    maxAge: TOKEN_TTL_S * 1000,
    path: '/',
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// ── Passwords (bcrypt) ────────────────────────────────────────────────────────
const BCRYPT_ROUNDS = 12;

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function checkPassword(plain, stored) {
  // Soporta hashes SHA-256 legacy durante migración
  if (/^[a-f0-9]{64}$/.test(stored)) {
    const sha = crypto.createHash('sha256').update(plain).digest('hex');
    return sha === stored;
  }
  return bcrypt.compare(plain, stored);
}

// ── DB layer ──────────────────────────────────────────────────────────────────
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

async function read(key) {
  if (MONGODB_URI) {
    const db  = await getDb();
    const doc = await db.collection('store').findOne({ _id: key });
    if (key === 'usuarios' && (!doc || !doc.data || doc.data.length === 0)) {
      const adminPass = await hashPassword(process.env.ADMIN_PASSWORD || 'admin123');
      const adminUser = {
        id: 1, nombre: 'Johangel', email: 'sm8contact@gmail.com',
        password: adminPass, rol: 'admin', activo: true,
        avatar: 'JG', creado: new Date().toISOString(),
      };
      await db.collection('store').updateOne(
        { _id: 'usuarios' },
        { $set: { data: [adminUser] } },
        { upsert: true }
      );
      return [adminUser];
    }
    return doc ? doc.data : [];
  }
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

async function initLocalStore() {
  if (MONGODB_URI) return;
  const adminPass = await hashPassword(process.env.ADMIN_PASSWORD || 'admin123');
  const adminUser = {
    id: 1, nombre: 'Johangel', email: 'sm8contact@gmail.com',
    password: adminPass, rol: 'admin', activo: true,
    avatar: 'JG', creado: new Date().toISOString(),
  };
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

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(roles = []) {
  return async (req, res, next) => {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'No autenticado' });
    const payload = verifyToken(token);
    if (!payload) return res.status(401).json({ error: 'Sesión expirada' });
    const usuarios = await read('usuarios');
    const user = usuarios.find(u => u.id === payload.id && u.activo);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (roles.length && !roles.includes(user.rol)) return res.status(403).json({ error: 'Sin permiso' });
    req.user = user;
    // Renovar cookie si queda menos de 2 horas de vida
    if (payload.exp - Math.floor(Date.now() / 1000) < 2 * 60 * 60) {
      setSessionCookie(res, signToken({ id: user.id, rol: user.rol }));
    }
    next();
  };
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Credenciales requeridas' });
  const usuarios = await read('usuarios');
  const user = usuarios.find(u => u.email === email && u.activo);
  if (!user || !(await checkPassword(password, user.password)))
    return res.status(401).json({ error: 'Credenciales incorrectas' });

  // Migrar hash SHA-256 a bcrypt si aún no lo está
  if (/^[a-f0-9]{64}$/.test(user.password)) {
    const idx = usuarios.findIndex(u => u.id === user.id);
    usuarios[idx].password = await hashPassword(password);
    await write('usuarios', usuarios);
  }

  const token = signToken({ id: user.id, rol: user.rol });
  setSessionCookie(res, token);
  res.json({ user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, avatar: user.avatar } });
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

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

app.get('/api/usuarios/desarrolladores', auth(), async (req, res) => {
  res.json((await read('usuarios'))
    .filter(u => u.rol === 'desarrollador' && u.activo !== false)
    .map(({ password, ...u }) => u));
});

app.post('/api/usuarios', auth(['admin']), async (req, res) => {
  const usuarios = await read('usuarios');
  const { nombre, email, password, rol, avatar } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Contraseña mínima 6 caracteres' });
  if (usuarios.find(u => u.email === email)) return res.status(400).json({ error: 'Email ya registrado' });
  const nuevo = {
    id: Date.now(), nombre, email,
    password: await hashPassword(password),
    rol, activo: true,
    avatar: avatar || nombre.slice(0, 2).toUpperCase(),
    creado: new Date().toISOString(),
  };
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
  if (password && password.length >= 6) usuarios[idx].password = await hashPassword(password);
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

// Cambiar contraseña propia
app.put('/api/me/password', auth(), async (req, res) => {
  const { actual, nueva } = req.body;
  if (!actual || !nueva || nueva.length < 6)
    return res.status(400).json({ error: 'Contraseña nueva mínima 6 caracteres' });
  const usuarios = await read('usuarios');
  const idx = usuarios.findIndex(u => u.id === req.user.id);
  if (!(await checkPassword(actual, usuarios[idx].password)))
    return res.status(401).json({ error: 'Contraseña actual incorrecta' });
  usuarios[idx].password = await hashPassword(nueva);
  await write('usuarios', usuarios);
  res.json({ ok: true });
});

// ── COTIZACIONES ──────────────────────────────────────────────────────────────
app.get('/api/cotizaciones', auth(), async (req, res) => res.json(await read('cotizaciones')));

app.post('/api/cotizaciones', auth(['admin', 'vendedor', 'soporte']), async (req, res) => {
  const cots = await read('cotizaciones');
  const nueva = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, creadoPorId: req.user.id, fecha: new Date().toISOString(), estado: req.body.estado || 'borrador' };
  cots.push(nueva);
  await write('cotizaciones', cots);
  res.json(nueva);
});

app.put('/api/cotizaciones/:id', auth(['admin', 'vendedor', 'soporte']), async (req, res) => {
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

app.post('/api/proyectos', auth(['admin', 'vendedor', 'soporte']), async (req, res) => {
  const proyectos = await read('proyectos');
  const nuevo = { ...req.body, id: Date.now(), creadoPor: req.user.id, creadoPorNombre: req.user.nombre, fecha: new Date().toISOString(), mensajes: [], estado: 'pendiente', progreso: 0 };
  proyectos.push(nuevo);
  await write('proyectos', proyectos);
  res.json(nuevo);
});

app.put('/api/proyectos/:id', auth(['admin', 'vendedor', 'soporte', 'desarrollador']), async (req, res) => {
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

// ── TICKETS ───────────────────────────────────────────────────────────────────
app.get('/api/tickets', auth(), async (req, res) => {
  // Todos ven todos los tickets — gestión restringida por rol en PUT/DELETE
  res.json(await read('tickets'));
});

app.post('/api/tickets', auth(), async (req, res) => {
  const tickets = await read('tickets');
  const { titulo, descripcion, tipo, prioridad, clienteId, clienteNombre } = req.body;
  if (!titulo || !descripcion) return res.status(400).json({ error: 'Título y descripción requeridos' });
  const nuevo = {
    id: Date.now(), titulo, descripcion,
    tipo: tipo || 'general', prioridad: prioridad || 'media',
    estado: 'abierto', clienteId: clienteId || null,
    clienteNombre: clienteNombre || null,
    autorId: req.user.id, autorNombre: req.user.nombre, autorRol: req.user.rol,
    creadoEn: new Date().toISOString(), actualizadoEn: new Date().toISOString(),
    respuestas: [],
  };
  tickets.push(nuevo);
  await write('tickets', tickets);
  res.json(nuevo);
});

app.put('/api/tickets/:id', auth(), async (req, res) => {
  const tickets = await read('tickets');
  const idx = tickets.findIndex(t => t.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  const t = tickets[idx];
  if (req.user.rol !== 'admin' && t.autorId !== req.user.id)
    return res.status(403).json({ error: 'Sin permiso' });
  const { estado, prioridad, titulo, descripcion } = req.body;
  if (estado)      t.estado = estado;
  if (prioridad)   t.prioridad = prioridad;
  if (titulo)      t.titulo = titulo;
  if (descripcion) t.descripcion = descripcion;
  t.actualizadoEn = new Date().toISOString();
  await write('tickets', tickets);
  res.json({ ok: true });
});

app.post('/api/tickets/:id/respuesta', auth(), async (req, res) => {
  const tickets = await read('tickets');
  const idx = tickets.findIndex(t => t.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'No encontrado' });
  const { texto } = req.body;
  if (!texto) return res.status(400).json({ error: 'Texto requerido' });
  const resp = {
    id: Date.now(), texto,
    autorId: req.user.id, autorNombre: req.user.nombre, autorRol: req.user.rol,
    fecha: new Date().toISOString(),
  };
  tickets[idx].respuestas.push(resp);
  tickets[idx].actualizadoEn = new Date().toISOString();
  if (req.user.rol !== 'admin' && tickets[idx].estado === 'cerrado') {
    tickets[idx].estado = 'abierto';
  }
  await write('tickets', tickets);
  res.json(resp);
});

app.delete('/api/tickets/:id', auth(), async (req, res) => {
  const tickets = await read('tickets');
  const t = tickets.find(x => x.id === parseInt(req.params.id));
  if (!t) return res.status(404).json({ error: 'No encontrado' });
  if (req.user.rol !== 'admin' && t.autorId !== req.user.id)
    return res.status(403).json({ error: 'Sin permiso' });
  await write('tickets', tickets.filter(x => x.id !== parseInt(req.params.id)));
  res.json({ ok: true });
});

// ── EVENTOS (Calendario) ──────────────────────────────────────────────────────
app.get('/api/eventos', auth(), async (req, res) => {
  res.json(await read('eventos'));
});

app.post('/api/eventos', auth(['admin', 'vendedor']), async (req, res) => {
  const eventos = await read('eventos');
  const { titulo, fecha, hora, tipo, clienteId, descripcion } = req.body;
  if (!titulo || !fecha) return res.status(400).json({ error: 'titulo y fecha requeridos' });
  const nuevo = {
    _id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    titulo, fecha, hora: hora || null, tipo: tipo || 'reunion',
    clienteId: clienteId || null, descripcion: descripcion || null,
    autorId: req.user.id, autorNombre: req.user.nombre,
    creado: new Date().toISOString(),
  };
  eventos.push(nuevo);
  await write('eventos', eventos);
  res.json(nuevo);
});

app.put('/api/eventos/:id', auth(['admin', 'vendedor']), async (req, res) => {
  const eventos = await read('eventos');
  const idx = eventos.findIndex(e => e._id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'no encontrado' });
  const { titulo, fecha, hora, tipo, clienteId, descripcion } = req.body;
  eventos[idx] = { ...eventos[idx], titulo, fecha, hora: hora || null, tipo: tipo || 'reunion', clienteId: clienteId || null, descripcion: descripcion || null };
  await write('eventos', eventos);
  res.json(eventos[idx]);
});

app.delete('/api/eventos/:id', auth(['admin', 'vendedor']), async (req, res) => {
  await write('eventos', (await read('eventos')).filter(e => e._id !== req.params.id));
  res.json({ ok: true });
});

// ── Static ────────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!IS_VERCEL) {
  initLocalStore().then(() => {
    app.listen(3000, () => console.log('CRM Pro → http://localhost:3000'));
  });
} else {
  initLocalStore();
}

module.exports = app;
