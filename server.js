// API dos dados do dashboard (Render + Postgres).
// Login e perfis continuam no Supabase: esta API só confia no token do Supabase
// e consulta o papel (admin/viewer) do usuário. Admin escreve; viewer só lê.
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const { DATABASE_URL, SUPABASE_URL, SUPABASE_ANON_KEY, ALLOWED_ORIGIN = '*', PORT = 3000 } = process.env;
for (const k of ['DATABASE_URL', 'SUPABASE_URL', 'SUPABASE_ANON_KEY'])
  if (!process.env[k]) { console.error(`Variável ${k} não definida.`); process.exit(1); }

const SB = SUPABASE_URL.replace(/\/$/, '');
const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false });
const app = express();
const err = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => fn(req, res).catch(next);

app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN.split(',').map(s => s.trim()) }));
app.use(express.json({ limit: '100kb' }));

// ---- autenticação via Supabase (cache de 30 s por token) ----
const cache = new Map();
setInterval(() => { for (const [k, v] of cache) if (v.exp < Date.now()) cache.delete(k); }, 60000).unref();

async function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!t) throw err(401, 'Não autenticado.');
    const hit = cache.get(t);
    if (hit && hit.exp > Date.now()) { req.user = hit.u; return next(); }
    const H = { apikey: SUPABASE_ANON_KEY, Authorization: 'Bearer ' + t };
    const ru = await fetch(`${SB}/auth/v1/user`, { headers: H });
    if (!ru.ok) throw err(401, 'Sessão inválida.');
    const u = await ru.json();
    const rp = await fetch(`${SB}/rest/v1/profiles?id=eq.${encodeURIComponent(u.id)}&select=role`, { headers: H });
    const p = rp.ok ? await rp.json() : [];
    if (!p[0]) throw err(403, 'Perfil não encontrado.');
    req.user = { id: u.id, role: p[0].role };
    cache.set(t, { u: req.user, exp: Date.now() + 30000 });
    next();
  } catch (e) { next(e); }
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : next(err(403, 'Apenas administradores podem alterar dados.'));

// ---- validação ----
const STATUS = ['novo', 'andamento', 'aguardando', 'concluido'];
function clean(b = {}) {
  const nome = String(b.nome || '').trim().slice(0, 200);
  if (!nome) throw err(400, 'Nome obrigatório.');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b.prazo || '')) throw err(400, 'Prazo inválido.');
  const status = STATUS.includes(b.status) ? b.status : 'novo';
  const prog = status === 'concluido' ? 100 : Math.min(100, Math.max(0, parseInt(b.prog) || 0));
  return {
    nome, status, prog, prazo: b.prazo,
    resp: String(b.resp || '—').slice(0, 120),
    tipo: String(b.tipo || 'Processo').slice(0, 120),
    hora: /^\d{2}:\d{2}/.test(b.hora || '') ? b.hora.slice(0, 5) : '09:00'
  };
}
const COLS = `id, nome, resp, tipo, status, to_char(prazo,'YYYY-MM-DD') AS prazo, to_char(hora,'HH24:MI') AS hora, prog`;
const idOf = req => { if (!/^\d+$/.test(req.params.id)) throw err(400, 'ID inválido.'); return req.params.id; };

// ---- rotas ----
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/processos', auth, wrap(async (req, res) => {
  res.json((await pool.query(`SELECT ${COLS} FROM processos ORDER BY prazo, hora`)).rows);
}));

app.post('/processos', auth, admin, wrap(async (req, res) => {
  const d = clean(req.body);
  const r = await pool.query(
    `INSERT INTO processos (nome,resp,tipo,status,prazo,hora,prog,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING ${COLS}`,
    [d.nome, d.resp, d.tipo, d.status, d.prazo, d.hora, d.prog, req.user.id]);
  res.status(201).json(r.rows[0]);
}));

app.put('/processos/:id', auth, admin, wrap(async (req, res) => {
  const d = clean(req.body);
  const r = await pool.query(
    `UPDATE processos SET nome=$1,resp=$2,tipo=$3,status=$4,prazo=$5,hora=$6,prog=$7,updated_at=now() WHERE id=$8 RETURNING ${COLS}`,
    [d.nome, d.resp, d.tipo, d.status, d.prazo, d.hora, d.prog, idOf(req)]);
  if (!r.rowCount) throw err(404, 'Processo não encontrado.');
  res.json(r.rows[0]);
}));

app.delete('/processos/:id', auth, admin, wrap(async (req, res) => {
  const r = await pool.query('DELETE FROM processos WHERE id=$1', [idOf(req)]);
  if (!r.rowCount) throw err(404, 'Processo não encontrado.');
  res.json({ ok: true });
}));

app.use((e, req, res, next) => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : 'Erro interno.' });
});

// ---- cria a tabela se não existir e inicia ----
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS processos (
      id         BIGSERIAL PRIMARY KEY,
      nome       TEXT NOT NULL,
      resp       TEXT NOT NULL DEFAULT '—',
      tipo       TEXT NOT NULL DEFAULT 'Processo',
      status     TEXT NOT NULL DEFAULT 'novo' CHECK (status IN ('novo','andamento','aguardando','concluido')),
      prazo      DATE NOT NULL,
      hora       TIME NOT NULL DEFAULT '09:00',
      prog       INT  NOT NULL DEFAULT 0 CHECK (prog BETWEEN 0 AND 100),
      created_by UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS processos_prazo_idx ON processos (prazo);`);
  app.listen(PORT, () => console.log('API rodando na porta ' + PORT));
})().catch(e => { console.error(e); process.exit(1); });
