const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ============== 数据库层（支持 SQLite 和 内存模式） ==============
let db;
let useSqlite = false;

// Vercel 环境强制使用内存模式
if (process.env.VERCEL) {
  db = createMemoryDB();
  useSqlite = false;
  console.log('📦 Vercel 模式：使用内存存储');
} else {
  try {
    const Database = require('better-sqlite3');
    db = new Database('/data/kidshield.db');
    db.pragma('journal_mode=WAL');
    useSqlite = true;
    initSqliteTables();
    console.log('✅ 使用 SQLite 存储');
  } catch (e) {
    // 内存模式（适用于 Vercel serverless）
    db = createMemoryDB();
    console.log('📦 使用内存存储（数据不持久化）');
  }
}

function initSqliteTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('parent','child')),
      nickname TEXT DEFAULT '',
      parent_code TEXT,
      parent_id TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS whitelist_apps (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      package_name TEXT NOT NULL,
      app_name TEXT DEFAULT '',
      added_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS missions (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      parent_id TEXT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      type TEXT DEFAULT 'parent_assign',
      status TEXT DEFAULT 'pending',
      reward_minutes INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS time_requests (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      reason TEXT DEFAULT '',
      requested_minutes INTEGER DEFAULT 30,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS usage_stats (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      date TEXT NOT NULL,
      total_minutes INTEGER DEFAULT 0,
      app_stats TEXT DEFAULT '{}',
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS notifications_cache (
      id TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      package_name TEXT DEFAULT '',
      title TEXT DEFAULT '',
      text TEXT DEFAULT '',
      posted_at TEXT DEFAULT (datetime('now'))
    );
  `);
}

function createMemoryDB() {
  const data = {
    users: [], whitelist_apps: [], missions: [],
    time_requests: [], usage_stats: [], notifications_cache: []
  };
  return {
    get: (table) => data[table] || [],
    find: (table, predicate) => (data[table] || []).find(predicate),
    filter: (table, predicate) => (data[table] || []).filter(predicate),
    insert: (table, item) => { data[table].push(item); return item; },
    update: (table, predicate, updates) => {
      const items = data[table] || [];
      for (let i = 0; i < items.length; i++) {
        if (predicate(items[i])) { Object.assign(items[i], updates); return items[i]; }
      }
      return null;
    },
    delete: (table, predicate) => {
      const items = data[table] || [];
      const idx = items.findIndex(predicate);
      if (idx >= 0) { items.splice(idx, 1); return true; }
      return false;
    }
  };
}

// ============== SQLite 查询辅助 ==============
function sqlRun(sql, params = {}) {
  if (useSqlite) {
    // 兼容：如果传的是对象，转成数组（按?占位符顺序取值）
    let execParams = params;
    if (typeof params === 'object' && !Array.isArray(params)) {
      const keys = Object.keys(params);
      if (keys.length > 0 && sql.includes('?')) {
        execParams = keys.map(k => params[k]);
      } else {
        execParams = params;
      }
    }
    const stmt = db.prepare(sql);
    if (sql.trim().toUpperCase().startsWith('SELECT')) {
      return Array.isArray(execParams) && execParams.length > 0 ? stmt.all(...execParams) : stmt.all();
    } else {
      return Array.isArray(execParams) ? stmt.run(...execParams) : stmt.run(execParams);
    }
  }
  return null;
}

function sqlGet(sql, params = {}) {
  if (useSqlite) {
    let execParams = params;
    if (typeof params === 'object' && !Array.isArray(params)) {
      const keys = Object.keys(params);
      if (keys.length > 0 && sql.includes('?')) {
        execParams = keys.map(k => params[k]);
      }
    }
    const stmt = db.prepare(sql);
    return Array.isArray(execParams) ? stmt.get(...execParams) : stmt.get(execParams);
  }
  return null;
}

// ============== 工具函数 ==============
const JWT_SECRET = process.env.JWT_SECRET || 'kidshield_jwt_secret_change_me_2024';
const tokenBlacklist = new Set();

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录' });
  }
  const token = authHeader.substring(7);
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token已失效' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token无效或已过期' });
  }
}

function generateParentCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ============== 健康检查 ==============
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'KidShield API', version: '1.0.0' });
});

// ============== 用户注册 ==============
app.post('/api/register', async (req, res) => {
  try {
    let { email, password, role, nickname } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ error: '邮箱、密码、角色为必填项' });
    }
    if (role === '家长' || role === 'parent') role = 'parent';
  else if (role === '孩子' || role === 'child') role = 'child';
  else return res.status(400).json({ error: '角色必须是 parent 或 child' });

    // 检查邮箱是否已注册
    const existing = useSqlite
      ? sqlGet('SELECT * FROM users WHERE email = ?', [email])
      : db.find('users', u => u.email === email);

    if (existing) {
      return res.status(400).json({ error: '该邮箱已被注册' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      email,
      password: hashedPassword,
      role,
      nickname: nickname || '',
      parent_code: role === 'parent' ? generateParentCode() : null,
      parent_id: null,
      created_at: new Date().toISOString()
    };

    if (useSqlite) {
      sqlRun(`INSERT INTO users (id, email, password, role, nickname, parent_code, created_at)
              VALUES (@id, @email, @password, @role, @nickname, @parent_code, @created_at)`, user);
    } else {
      db.insert('users', user);
    }

    const token = generateToken(user);
    res.json({
      token,
      uid: user.id,
      user: { id: user.id, email: user.email, role: user.role, nickname: user.nickname, parent_code: user.parent_code }
    });
  } catch (e) {
    console.error('注册失败:', e);
    res.status(500).json({ error: '注册失败: ' + e.message });
  }
});

// ============== 用户登录 ==============
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: '邮箱和密码为必填项' });
    }

    const user = useSqlite
      ? sqlGet('SELECT * FROM users WHERE email = ?', [email])
      : db.find('users', u => u.email === email);

    if (!user) {
      return res.status(400).json({ error: '邮箱或密码错误' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: '邮箱或密码错误' });
    }

    const token = generateToken(user);
    res.json({
      token,
      uid: user.id,
      user: { id: user.id, email: user.email, role: user.role, nickname: user.nickname, parent_code: user.parent_code }
    });
  } catch (e) {
    console.error('登录失败:', e);
    res.status(500).json({ error: '登录失败: ' + e.message });
  }
});

// ============== 获取用户信息 ==============
app.get('/api/user/me', authMiddleware, (req, res) => {
  const user = useSqlite
    ? sqlGet('SELECT id, email, role, nickname, parent_code, parent_id, created_at FROM users WHERE id = ?', [req.user.id])
    : db.find('users', u => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({ user });
});

// ============== 修改用户角色（需验证原密码） ==============
app.post('/api/user/change-role', authMiddleware, async (req, res) => {
  try {
    const { password, new_role } = req.body;
    if (!password || !new_role) {
      return res.status(400).json({ error: '密码和新角色为必填项' });
    }
    if (!['parent', 'child'].includes(new_role)) {
      return res.status(400).json({ error: '角色必须是 parent 或 child' });
    }

    const user = useSqlite
      ? sqlGet('SELECT * FROM users WHERE id = ?', [req.user.id])
      : db.find('users', u => u.id === req.user.id);

    if (!user) return res.status(404).json({ error: '用户不存在' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(403).json({ error: '密码错误，无法修改角色' });
    }

    // 生成新的 parent_code
    const parent_code = new_role === 'parent' ? generateParentCode() : null;

    if (useSqlite) {
      sqlRun('UPDATE users SET role = ?, parent_code = ? WHERE id = ?', [new_role, parent_code, req.user.id]);
    } else {
      db.update('users', u => u.id === req.user.id, { role: new_role, parent_code });
    }

    // 生成新 token
    const updatedUser = { ...user, role: new_role, parent_code };
    const newToken = generateToken(updatedUser);
    // 将旧 token 加入黑名单
    const authHeader = req.headers.authorization;
    if (authHeader) tokenBlacklist.add(authHeader.substring(7));

    res.json({
      success: true,
      token: newToken,
      uid: user.id,
      user: { id: user.id, email: user.email, role: new_role, nickname: user.nickname, parent_code }
    });
  } catch (e) {
    console.error('修改角色失败:', e);
    res.status(500).json({ error: '修改角色失败: ' + e.message });
  }
});


// ============== 家长绑定孩子（由家长端调用） ==============
app.post('/api/parent/bind', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'parent') {
      return res.status(403).json({ error: '仅家长账号可绑定孩子' });
    }
    const { child_email, parent_code } = req.body;
    if (!child_email || !parent_code) {
      return res.status(400).json({ error: '孩子邮箱和家长码为必填项' });
    }
    // 从数据库获取当前家长的完整信息（含parent_code）
    const parentInfo = useSqlite
      ? sqlGet('SELECT id, email, parent_code FROM users WHERE id = ? AND role = ?', [req.user.id, 'parent'])
      : db.find('users', u => u.id === req.user.id && u.role === 'parent');
    if (!parentInfo) {
      return res.status(403).json({ error: '账户异常，请重新登录' });
    }
    // 验证家长码是否匹配
    if (parent_code !== parentInfo.parent_code) {
      return res.status(400).json({ error: '家长码错误' });
    }
    // 查找孩子用户
    const child = useSqlite
      ? sqlGet('SELECT id, email, nickname FROM users WHERE email = ? AND role = ?', [child_email, 'child'])
      : db.find('users', u => u.email === child_email && u.role === 'child');
    if (!child) {
      return res.status(400).json({ error: '未找到该孩子账号，请确认邮箱正确且角色为孩子' });
    }
    // 更新孩子的 parent_id
    if (useSqlite) {
      sqlRun('UPDATE users SET parent_id = ? WHERE id = ?', [req.user.id, child.id]);
    } else {
      db.update('users', u => u.id === child.id, { parent_id: req.user.id });
    }
    res.json({ success: true, child: { id: child.id, email: child.email, nickname: child.nickname } });
  } catch (e) {
    console.error('家长绑定孩子失败:', e);
    res.status(500).json({ error: '绑定失败: ' + e.message });
  }
});

// ============== 孩子绑定家长码 ==============
app.post('/api/child/bind', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'child') {
      return res.status(403).json({ error: '仅孩子账号可绑定家长' });
    }
    const { parent_code } = req.body;
    if (!parent_code) return res.status(400).json({ error: '请输入家长码' });

    const parent = useSqlite
      ? sqlGet('SELECT id, email, nickname FROM users WHERE role = ? AND parent_code = ?', ['parent', parent_code])
      : db.find('users', u => u.role === 'parent' && u.parent_code === parent_code);

    if (!parent) return res.status(400).json({ error: '家长码无效' });

    if (useSqlite) {
      sqlRun('UPDATE users SET parent_id = ? WHERE id = ?', [parent.id, req.user.id]);
    } else {
      db.update('users', u => u.id === req.user.id, { parent_id: parent.id });
    }

    res.json({ success: true, parent: { id: parent.id, nickname: parent.nickname, email: parent.email } });
  } catch (e) {
    res.status(500).json({ error: '绑定失败: ' + e.message });
  }
});

// ============== 家长获取绑定的孩子列表 ==============
app.get('/api/parent/children', authMiddleware, (req, res) => {
  if (req.user.role !== 'parent') return res.status(403).json({ error: '仅家长可查看' });

  const children = useSqlite
    ? sqlRun('SELECT id, email, nickname, created_at FROM users WHERE parent_id = ?', [req.user.id])
    : db.filter('users', u => u.parent_id === req.user.id);

  res.json({ children: children.map(c => ({ id: c.id, email: c.email, nickname: c.nickname })) });
});

// ============== 白名单管理 ==============
app.post('/api/whitelist/add', authMiddleware, (req, res) => {
  const { child_id, package_name, app_name } = req.body;
  if (!child_id || !package_name) return res.status(400).json({ error: '参数不完整' });

  const item = { id: uuidv4(), child_id, package_name, app_name: app_name || '', added_at: new Date().toISOString() };
  if (useSqlite) {
    sqlRun(`INSERT INTO whitelist_apps (id, child_id, package_name, app_name, added_at) VALUES (?, ?, ?, ?, ?)`,
      [item.id, item.child_id, item.package_name, item.app_name, item.added_at]);
  } else {
    db.insert('whitelist_apps', item);
  }
  res.json({ success: true, item });
});

app.get('/api/whitelist/:childId', authMiddleware, (req, res) => {
  const items = useSqlite
    ? sqlRun('SELECT * FROM whitelist_apps WHERE child_id = ?', [req.params.childId])
    : db.filter('whitelist_apps', w => w.child_id === req.params.childId);
  res.json({ apps: items });
});

app.delete('/api/whitelist/:id', authMiddleware, (req, res) => {
  if (useSqlite) {
    sqlRun('DELETE FROM whitelist_apps WHERE id = @id', [req.params.id]);
  } else {
    db.delete('whitelist_apps', w => w.id === req.params.id);
  }
  res.json({ success: true });
});

// ============== 任务管理 ==============
app.post('/api/missions/create', authMiddleware, (req, res) => {
  const { child_id, title, description, reward_minutes } = req.body;
  if (!child_id || !title) return res.status(400).json({ error: '参数不完整' });

  const mission = {
    id: uuidv4(), child_id, parent_id: req.user.id,
    title, description: description || '',
    type: 'parent_assign', status: 'pending',
    reward_minutes: reward_minutes || 0,
    created_at: new Date().toISOString(), completed_at: null
  };

  if (useSqlite) {
    sqlRun(`INSERT INTO missions (id, child_id, parent_id, title, description, type, status, reward_minutes, created_at)
            VALUES (@id, @child_id, @parent_id, @title, @description, @type, @status, @reward_minutes, @created_at)`, mission);
  } else {
    db.insert('missions', mission);
  }
  res.json({ success: true, mission });
});

app.get('/api/missions/:childId', authMiddleware, (req, res) => {
  const missions = useSqlite
    ? sqlRun('SELECT * FROM missions WHERE child_id = ? ORDER BY created_at DESC', [req.params.childId])
    : db.filter('missions', m => m.child_id === req.params.childId).sort((a,b) => b.created_at.localeCompare(a.created_at));
  res.json({ missions });
});

app.post('/api/missions/:id/complete', authMiddleware, (req, res) => {
  const now = new Date().toISOString();
  if (useSqlite) {
    sqlRun('UPDATE missions SET status = ?, completed_at = ? WHERE id = ?', ['completed', now, req.params.id]);
  } else {
    db.update('missions', m => m.id === req.params.id, { status: 'completed', completed_at: now });
  }
  res.json({ success: true });
});

app.post('/api/missions/:id/approve', authMiddleware, (req, res) => {
  if (useSqlite) {
    sqlRun('UPDATE missions SET status = ? WHERE id = ?', ['approved', req.params.id]);
  } else {
    db.update('missions', m => m.id === req.params.id, { status: 'approved' });
  }
  res.json({ success: true });
});

// ============== 加时长申请 ==============
app.post('/api/time-request/create', authMiddleware, (req, res) => {
  const { child_id, reason, requested_minutes } = req.body;
  const request = {
    id: uuidv4(), child_id,
    reason: reason || '', requested_minutes: requested_minutes || 30,
    status: 'pending', created_at: new Date().toISOString()
  };

  if (useSqlite) {
    sqlRun(`INSERT INTO time_requests (id, child_id, reason, requested_minutes, status, created_at)
            VALUES (@id, @child_id, @reason, @requested_minutes, @status, @created_at)`, request);
  } else {
    db.insert('time_requests', request);
  }
  res.json({ success: true, request });
});

app.get('/api/time-requests/:childId', authMiddleware, (req, res) => {
  const requests = useSqlite
    ? sqlRun('SELECT * FROM time_requests WHERE child_id = ? ORDER BY created_at DESC', [req.params.childId])
    : db.filter('time_requests', r => r.child_id === req.params.childId).sort((a,b) => b.created_at.localeCompare(a.created_at));
  res.json({ requests });
});

app.post('/api/time-requests/:id/approve', authMiddleware, (req, res) => {
  if (useSqlite) {
    sqlRun('UPDATE time_requests SET status = ? WHERE id = ?', ['approved', req.params.id]);
  } else {
    db.update('time_requests', r => r.id === req.params.id, { status: 'approved' });
  }
  res.json({ success: true });
});

app.post('/api/time-requests/:id/reject', authMiddleware, (req, res) => {
  if (useSqlite) {
    sqlRun('UPDATE time_requests SET status = ? WHERE id = ?', ['rejected', req.params.id]);
  } else {
    db.update('time_requests', r => r.id === req.params.id, { status: 'rejected' });
  }
  res.json({ success: true });
});

// ============== 使用统计上报 ==============
app.post('/api/usage/report', authMiddleware, (req, res) => {
  const { child_id, date, total_minutes, app_stats } = req.body;
  const item = {
    id: uuidv4(), child_id, date: date || new Date().toISOString().split('T')[0],
    total_minutes: total_minutes || 0, app_stats: JSON.stringify(app_stats || {}),
    updated_at: new Date().toISOString()
  };

  if (useSqlite) {
    const existing = sqlGet('SELECT * FROM usage_stats WHERE child_id = ? AND date = ?', [child_id, item.date]);
    if (existing) {
      sqlRun('UPDATE usage_stats SET total_minutes = ?, app_stats = ?, updated_at = ? WHERE id = ?', [item.total_minutes, item.app_stats, item.updated_at, existing.id]);
    } else {
      sqlRun(`INSERT INTO usage_stats (id, child_id, date, total_minutes, app_stats, updated_at)
              VALUES (@id, @child_id, @date, @total_minutes, @app_stats, @updated_at)`, item);
    }
  } else {
    const existing = db.find('usage_stats', u => u.child_id === child_id && u.date === item.date);
    if (existing) {
      Object.assign(existing, item);
    } else {
      db.insert('usage_stats', item);
    }
  }
  res.json({ success: true });
});

app.get('/api/usage/:childId', authMiddleware, (req, res) => {
  const stats = useSqlite
    ? sqlRun('SELECT * FROM usage_stats WHERE child_id = @child_id ORDER BY date DESC LIMIT 30', { child_id: req.params.childId })
    : db.filter('usage_stats', u => u.child_id === req.params.childId).sort((a,b) => b.date.localeCompare(a.date)).slice(0, 30);
  res.json({ stats: stats.map(s => ({ ...s, app_stats: typeof s.app_stats === 'string' ? JSON.parse(s.app_stats) : s.app_stats })) });
});

// ============== 通知缓存同步 ==============
app.post('/api/notifications/sync', authMiddleware, (req, res) => {
  const { child_id, notifications } = req.body;
  if (!child_id || !notifications) return res.status(400).json({ error: '参数不完整' });

  if (useSqlite) {
    sqlRun('DELETE FROM notifications_cache WHERE child_id = ?', [child_id]);
    const insert = db.prepare(`INSERT INTO notifications_cache (id, child_id, package_name, title, text, posted_at) VALUES (?, ?, ?, ?, ?, ?)`);
    const tx = db.transaction((items) => {
      for (const n of items) {
        insert.run(uuidv4(), child_id, n.package_name || '', n.title || '', n.text || '', n.posted_at || new Date().toISOString());
      }
    });
    tx(notifications.slice(0, 100));
  } else {
    db.delete('notifications_cache', n => n.child_id === child_id);
    for (const n of notifications.slice(0, 100)) {
      db.insert('notifications_cache', { id: uuidv4(), child_id, package_name: n.package_name || '', title: n.title || '', text: n.text || '', posted_at: n.posted_at || new Date().toISOString() });
    }
  }
  res.json({ success: true, count: Math.min(notifications.length, 100) });
});

app.get('/api/notifications/:childId', authMiddleware, (req, res) => {
  const items = useSqlite
    ? sqlRun('SELECT * FROM notifications_cache WHERE child_id = @child_id ORDER BY posted_at DESC LIMIT 200', { child_id: req.params.childId })
    : db.filter('notifications_cache', n => n.child_id === req.params.childId).sort((a,b) => b.posted_at.localeCompare(a.posted_at)).slice(0, 200);
  res.json({ notifications: items });
});

// ============== 启动服务器 ==============
const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'vercel') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 KidShield API 运行在 http://0.0.0.0:${PORT}`);
    console.log(`📝 注册: POST /api/register`);
    console.log(`🔑 登录: POST /api/login`);
  });
}

// Vercel 导出
module.exports = app;
