const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const PLAYER_DIR = path.join(DATA_DIR, 'playerdata');
const CACHE_DIR = path.join(__dirname, 'cache');

if (!fs.existsSync(PLAYER_DIR)) {
  fs.mkdirSync(PLAYER_DIR, { recursive: true });
}
if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}
// 生成空进度数据
function createEmptyProgress(username, deviceId) {
  const now = new Date().toISOString();
  return {
    username: username,
    deviceId: deviceId ? encodeDeviceId(deviceId) : '',
    createdAt: now,
    lastLogin: now,
    completedLevels: [],
    gushiCompletedLevels: [],
    caiziCompletedLevels: [],
    settings: {
      sound: true,
      floatAnimations: false,
      language: 'zh-cn'
    }
  };
}
// 超级用户标识：玩家数据文件中的 deviceId 被手动改为 "superuser" 后，任何设备都允许自动登录
const SUPERUSER_DEVICE = 'superuser';
// 校验设备ID（浏览器生成的随机ID，限长64；superuser 由文件手动设置，不接受请求直接传入）
function isValidDeviceId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9-]{1,64}$/.test(id);
}

function encodeDeviceId(id) {
  return Buffer.from(id, 'utf8').toString('base64');
}
// 读取文件中的设备ID：先按Base64解码；解码结果若不是合法设备ID，则按明文处理
function decodeStoredDeviceId(stored) {
  if (typeof stored !== 'string' || !stored) return '';
  const decoded = Buffer.from(stored, 'base64').toString('utf8');
  if (decoded && isValidDeviceId(decoded)) return decoded;
  return stored;
}
// 校验用户名：1-20位，仅允许中英文、数字、下划线
function isValidUsername(name) {
  return typeof name === 'string' && /^[一-龥a-zA-Z0-9_]{1,20}$/.test(name);
}
// 校验题库ID：仅允许英文、数字、下划线、短横线（题库文件名必须为 {id}.json）
function isValidBankId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{1,40}$/.test(id);
}
// ============ 密码与2FA辅助 ============
// 密码使用 scrypt 哈希，salt 单独存储
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(plain, storedHash, storedSalt) {
  if (typeof plain !== 'string' || !storedHash || !storedSalt) return false;
  try {
    const hash = crypto.scryptSync(plain, storedSalt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
  } catch (e) { return false; }
}
// Base32 编解码（TOTP 密钥用 Base32）
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(str) {
  let bits = '';
  for (const ch of str.toUpperCase().replace(/=+$/, '')) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}
function base32Encode(buf) {
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    out += B32_ALPHABET[parseInt(chunk, 2)];
  }
  while (out.length % 8) out += '=';
  return out;
}
// 生成 TOTP 密钥（160位随机）
function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}
// 生成6位TOTP验证码（RFC 6238）
function generateTotp(secretB32, stepSeconds = 30, digits = 6) {
  const key = base32Decode(secretB32);
  const counter = Math.floor(Date.now() / 1000 / stepSeconds);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % Math.pow(10, digits)).toString().padStart(digits, '0');
}
// 验证TOTP验证码（允许±1步漂移）
function verifyTotp(secretB32, code) {
  if (!code || !/^\d{6}$/.test(String(code))) return false;
  const step = 30;
  const now = Date.now();
  for (let drift = -1; drift <= 1; drift++) {
    const fakeNow = now + drift * step * 1000;
    const key = base32Decode(secretB32);
    const counter = Math.floor(fakeNow / 1000 / step);
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(counter), 0);
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const bin = ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    const expected = (bin % 1000000).toString().padStart(6, '0');
    if (expected === String(code)) return true;
  }
  return false;
}
// 列出 data 目录下所有可用的自定义题库（每个题库为一个 {id}.json 文件）
function handleListBanks(res) {
  try {
    const ignoreFiles = ['progress.json', 'progress.migrated.json'];
    const files = fs.readdirSync(DATA_DIR).filter(f => f.endsWith('.json') && !ignoreFiles.includes(f));
    const banks = [];
    for (const f of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), 'utf8'));
        if (!data || !isValidBankId(String(data.id))) continue;
        if (f !== String(data.id) + '.json') continue;
        const hasPages = Array.isArray(data.pages) ||
          Array.isArray(data.levels) || Array.isArray(data.gushiLevels) || Array.isArray(data.caiziLevels);
        if (!hasPages) continue;
        banks.push({
          id: String(data.id),
          name: typeof data.name === 'string' && data.name ? data.name : String(data.id),
          title: typeof data.title === 'string' && data.title ? data.title : '',
          logo: typeof data.logo === 'string' ? data.logo : '',
          background: typeof data.background === 'string' ? data.background : '',
          shop: Array.isArray(data.shop) ? data.shop : [],
          file: f
        });
      } catch (e) {
        console.warn('跳过无法解析的题库文件:', f, e.message);
      }
    }
    banks.sort((a, b) => {
      if (a.id === 'default') return -1;
      if (b.id === 'default') return 1;
      return a.name.localeCompare(b.name, 'zh-CN');
    });
    sendJson(res, 200, { success: true, banks });
  } catch (error) {
    console.error('获取题库列表失败:', error);
    sendJson(res, 500, { success: false, error: '获取题库列表失败' });
  }
}
// 获取玩家数据文件路径（用户名已通过校验，杜绝路径穿越）
function getPlayerPath(username) {
  return path.join(PLAYER_DIR, username + '.json');
}
// 列出某个目录下的音频文件（用于题库 bgm 目录），按文件名自然顺序返回
const AUDIO_EXT = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac', '.webm', '.opus'];
function handleListBgmFiles(res, query) {
  const dir = String(query.dir || '').trim();
  if (!dir || /^([a-zA-Z]:|\/|\\)/.test(dir) || dir.includes('..')) {
    return sendJson(res, 400, { success: false, error: '目录路径无效' });
  }
  try {
    const dirPath = path.join(__dirname, dir);
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
      return sendJson(res, 404, { success: false, error: '目录不存在' });
    }
    // 防止路径穿越：确认真实路径仍在站点根目录内
    const realDir = fs.realpathSync(dirPath);
    if (!realDir.startsWith(__dirname)) {
      return sendJson(res, 403, { success: false, error: '禁止访问该目录' });
    }
    const files = fs.readdirSync(realDir).filter(f => {
      const ext = path.extname(f).toLowerCase();
      return AUDIO_EXT.includes(ext) && fs.statSync(path.join(realDir, f)).isFile();
    });
    files.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
    sendJson(res, 200, { success: true, files });
  } catch (error) {
    console.error('列出BGM文件失败:', error);
    sendJson(res, 500, { success: false, error: '列出BGM文件失败' });
  }
}
// 读取请求体JSON
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1024 * 1024) {
        reject(new Error('请求体过大'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, obj) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
// ============ 通用缓存（cache 目录，文件持久化） ============
function isValidCacheKey(key) {
  return typeof key === 'string' && /^[a-zA-Z0-9_-]{1,120}$/.test(key);
}
function cacheFilePath(key) {
  return path.join(CACHE_DIR, key + '.json');
}
// GET /api/cache/:key  读取缓存（不存在返回 null）
function handleCacheGet(res, key) {
  if (!isValidCacheKey(key)) return sendJson(res, 400, { success: false, error: '无效的缓存键' });
  const fp = cacheFilePath(key);
  fs.readFile(fp, 'utf8', (err, data) => {
    if (err) return sendJson(res, 200, { success: true, data: null });
    try {
      const obj = JSON.parse(data);
      sendJson(res, 200, { success: true, data: obj });
    } catch (e) {
      sendJson(res, 200, { success: true, data: null });
    }
  });
}
// POST /api/cache/:key  写入缓存（body 为任意 JSON）
function handleCacheSet(req, res, key) {
  if (!isValidCacheKey(key)) return sendJson(res, 400, { success: false, error: '无效的缓存键' });
  let body = '';
  req.on('data', chunk => { body += chunk; if (body.length > 5 * 1024 * 1024) { res.destroy(); } });
  req.on('end', () => {
    try {
      JSON.parse(body);
      const fp = cacheFilePath(key);
      fs.writeFile(fp, body, 'utf8', err => {
        if (err) { console.error('缓存写入失败', key, err.message); return sendJson(res, 500, { success: false, error: '写入失败' }); }
        console.log('缓存已写入:', key, body.length, 'bytes');
        sendJson(res, 200, { success: true });
      });
    } catch (e) {
      sendJson(res, 400, { success: false, error: 'JSON 格式错误' });
    }
  });
  req.on('error', err => console.error('缓存POST请求出错', key, err.code || err.message));
}
// DELETE /api/cache/:key  删除缓存
function handleCacheDel(res, key) {
  if (!isValidCacheKey(key)) return sendJson(res, 400, { success: false, error: '无效的缓存键' });
  const fp = cacheFilePath(key);
  fs.unlink(fp, () => sendJson(res, 200, { success: true }));
}
// ============ PK跨设备匹配（内存态：等待队列+对战房间，服务器重启即清空） ============
let pkMatchQueue = []; // 等待匹配的玩家 [{username, joinedAt}]
let pkRooms = {};      // 进行中的对战房间
// P2P联机码配对房间：{ code, host, guest, createdAt, lastActive, hostBankId, guestBankId, signals:{host:[],guest:[]}, status, roomId }
let pkP2pRooms = {};
const PK_SEEN_TTL = 30 * 1000; // 超过30秒无心跳视为离线
// 清理过期数据：移除超过15秒未轮询的等待者、双方离线或超10分钟的房间
function pkCleanup() {
  const now = Date.now();
  pkMatchQueue = pkMatchQueue.filter(w => now - w.joinedAt < 15 * 1000);
  for (const id of Object.keys(pkRooms)) {
    const room = pkRooms[id];
    const allGone = Object.values(room.progress).every(p => now - p.lastSeen > PK_SEEN_TTL);
    if (allGone || now - room.createdAt > 10 * 60 * 1000) delete pkRooms[id];
  }
  for (const code of Object.keys(pkP2pRooms)) {
    if (now - pkP2pRooms[code].lastActive > 10 * 60 * 1000) delete pkP2pRooms[code];
  }
}
// 房间中某玩家视角的公开信息（含双方当前题库与题库协商状态）
function pkRoomPublic(room, username) {
  const opponent = room.players[0] === username ? room.players[1] : room.players[0];
  return {
    status: 'matched',
    roomId: room.id,
    opponent,
    myBank: room.banks[username] || null,
    opponentBank: room.banks[opponent] || null,
    bankStatus: room.bankStatus,
    bankId: room.bankId || null
  };
}
// 加入匹配队列：队列中已有其他玩家则立即配对建房
function handlePKMatchJoin(req, res) {
  parseBody(req).then(({ username, bankId }) => {
    if (!isValidUsername(username)) {
      return sendJson(res, 400, { success: false, error: '用户名无效' });
    }
    const safeBankId = isValidBankId(bankId) ? bankId : null;
    pkCleanup();
    const now = Date.now();
    for (const room of Object.values(pkRooms)) {
      if (!room.players.includes(username)) continue;
      const allFinished = Object.values(room.progress).every(p => p.finished);
      if (room.left.includes(username) || room.bankStatus === 'mismatch' || allFinished) {
        delete pkRooms[room.id];
        break;
      }
      return sendJson(res, 200, { success: true, ...pkRoomPublic(room, username) });
    }
    // 队列中已有其他等待者：配对成功，创建房间
    const idx = pkMatchQueue.findIndex(w => w.username !== username);
    if (idx >= 0) {
      const waiter = pkMatchQueue.splice(idx, 1)[0];
      pkMatchQueue = pkMatchQueue.filter(w => w.username !== username);
      const roomId = 'pk' + now.toString(36) + Math.random().toString(36).slice(2, 8);
      const waiterBank = isValidBankId(waiter.bankId) ? waiter.bankId : null;
      const sameBank = !!(waiterBank && safeBankId && waiterBank === safeBankId);
      pkRooms[roomId] = {
        id: roomId,
        players: [waiter.username, username],
        createdAt: now,
        progress: {
          [waiter.username]: { score: 0, answered: 0, finished: false, lastSeen: now },
          [username]: { score: 0, answered: 0, finished: false, lastSeen: now }
        },
        banks: { [waiter.username]: waiterBank, [username]: safeBankId },
        bankVotes: {},
        bankStatus: sameBank ? 'agreed' : 'select',
        bankId: sameBank ? safeBankId : null,
        left: []
      };
      return sendJson(res, 200, { success: true, ...pkRoomPublic(pkRooms[roomId], username) });
    }
    // 无可配对玩家：进入队列等待（重复加入则刷新心跳与题库）
    const mine = pkMatchQueue.find(w => w.username === username);
    if (mine) { mine.joinedAt = now; mine.bankId = safeBankId; }
    else pkMatchQueue.push({ username, joinedAt: now, bankId: safeBankId });
    return sendJson(res, 200, { success: true, status: 'waiting' });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 题库协商投票：双方各提交一个题库ID，两次选择一致则用该题库开始，不一致则终止PK
function handlePKRoomBankVote(req, res) {
  parseBody(req).then(({ roomId, username, bankId }) => {
    const room = pkRooms[roomId];
    if (!room || !room.players.includes(username)) {
      return sendJson(res, 200, { success: false, errorCode: 'ROOM_GONE' });
    }
    if (!isValidBankId(bankId)) {
      return sendJson(res, 400, { success: false, error: '题库ID无效' });
    }
    room.bankVotes[username] = bankId;
    const votes = room.players.map(p => room.bankVotes[p]);
    if (votes.every(v => !!v)) {
      if (votes[0] === votes[1]) {
        room.bankStatus = 'agreed';
        room.bankId = votes[0];
      } else {
        room.bankStatus = 'mismatch';
        room.bankId = null;
      }
    }
    return sendJson(res, 200, {
      success: true,
      bankStatus: room.bankStatus,
      bankId: room.bankId || null
    });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 轮询匹配状态（等待中每1.5秒调用一次，同时作为队列心跳）
function handlePKMatchPoll(res, query) {
  const username = query.username;
  if (!isValidUsername(username)) {
    return sendJson(res, 400, { success: false, error: '用户名无效' });
  }
  pkCleanup();
  const waiting = pkMatchQueue.find(w => w.username === username);
  if (waiting) waiting.joinedAt = Date.now();
  for (const room of Object.values(pkRooms)) {
    if (room.players.includes(username)) {
      return sendJson(res, 200, { success: true, ...pkRoomPublic(room, username) });
    }
  }
  return sendJson(res, 200, { success: true, status: 'waiting' });
}
// 取消匹配：移出等待队列
function handlePKMatchCancel(req, res) {
  parseBody(req).then(({ username }) => {
    if (isValidUsername(username)) {
      pkMatchQueue = pkMatchQueue.filter(w => w.username !== username);
    }
    return sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 上报对战进度（每次答题/完成时调用，同时作为房间心跳）
function handlePKRoomProgress(req, res) {
  parseBody(req).then(({ roomId, username, score, answered, finished }) => {
    const room = pkRooms[roomId];
    if (!room || !room.players.includes(username)) {
      return sendJson(res, 200, { success: false, errorCode: 'ROOM_GONE' });
    }
    const p = room.progress[username];
    if (Number.isInteger(score)) p.score = score;
    if (Number.isInteger(answered)) p.answered = answered;
    if (finished === true) p.finished = true;
    p.lastSeen = Date.now();
    return sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 查询房间状态：返回对方实时进度（同时刷新自己的心跳）
function handlePKRoomState(res, query) {
  const { roomId, username } = query;
  pkCleanup();
  const room = pkRooms[roomId];
  if (!room || !room.players.includes(username)) {
    return sendJson(res, 200, { success: false, errorCode: 'ROOM_GONE' });
  }
  const opponent = room.players[0] === username ? room.players[1] : room.players[0];
  const me = room.progress[username];
  me.lastSeen = Date.now();
  const o = room.progress[opponent];
  const opponentLeft = room.left.includes(opponent) || (!o.finished && Date.now() - o.lastSeen > PK_SEEN_TTL);
  return sendJson(res, 200, {
    success: true,
    opponent: { name: opponent, score: o.score, answered: o.answered, finished: o.finished },
    opponentLeft,
    bankStatus: room.bankStatus,
    bankId: room.bankId || null,
    opponentVoted: !!room.bankVotes[opponent]
  });
}
// 退出房间：标记离开，让对方感知
function handlePKRoomLeave(req, res) {
  parseBody(req).then(({ roomId, username }) => {
    const room = pkRooms[roomId];
    if (room && room.players.includes(username)) {
      if (!room.left.includes(username)) room.left.push(username);
      room.progress[username].finished = true;
      if (room.left.length >= 2) delete pkRooms[roomId];
    }
    return sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// ============ P2P联机码配对（房主生成6位联机码，房客凭码配对；配对成功后创建 pkRooms 对战房间并中转WebRTC信令） ============
const P2P_CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 易读字符集（去掉易混淆的0/O/1/I/L）
const P2P_CODE_RE = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/;
// 生成不重复的6位联机码
function pkP2pGenCode() {
  let code = '';
  do {
    code = '';
    for (let i = 0; i < 6; i++) code += P2P_CODE_CHARS[Math.floor(Math.random() * P2P_CODE_CHARS.length)];
  } while (pkP2pRooms[code]);
  return code;
}
// 房主登记：生成联机码等待房客；同一用户重复登记则刷新原房间（返回同一联机码）
function handlePKP2pHost(req, res) {
  parseBody(req).then(({ username, bankId }) => {
    if (!isValidUsername(username)) {
      return sendJson(res, 400, { success: false, error: '用户名无效' });
    }
    const safeBankId = isValidBankId(bankId) ? bankId : null;
    pkCleanup();
    const now = Date.now();
    for (const room of Object.values(pkP2pRooms)) {
      if (room.host !== username) continue;
      if (room.status === 'waiting') {
        room.lastActive = now;
        room.hostBankId = safeBankId;
        return sendJson(res, 200, { success: true, code: room.code });
      }
      delete pkP2pRooms[room.code];
      break;
    }
    const code = pkP2pGenCode();
    pkP2pRooms[code] = {
      code, host: username, guest: null, createdAt: now, lastActive: now,
      hostBankId: safeBankId, guestBankId: null,
      signals: { host: [], guest: [] }, status: 'waiting', roomId: null
    };
    return sendJson(res, 200, { success: true, code });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 房客凭联机码加入：配对成功立即创建 pkRooms 对战房间（房主=P1、房客=P2），
function handlePKP2pJoin(req, res) {
  parseBody(req).then(({ username, code, bankId }) => {
    if (!isValidUsername(username)) {
      return sendJson(res, 400, { success: false, error: '用户名无效' });
    }
    const safeCode = String(code || '').toUpperCase();
    if (!P2P_CODE_RE.test(safeCode)) {
      return sendJson(res, 200, { success: false, error: '联机码无效' });
    }
    const safeBankId = isValidBankId(bankId) ? bankId : null;
    pkCleanup();
    const room = pkP2pRooms[safeCode];
    if (!room) {
      return sendJson(res, 200, { success: false, error: '联机码无效' });
    }
    if (room.host === username) {
      return sendJson(res, 200, { success: false, error: '不能加入自己的房间' });
    }
    room.lastActive = Date.now();
    if (room.status === 'matched' && room.guest === username && room.roomId && pkRooms[room.roomId]
        && !pkRooms[room.roomId].left.includes(username)) {
      return sendJson(res, 200, { success: true, ...pkRoomPublic(pkRooms[room.roomId], username) });
    }
    if (room.status === 'matched') {
      room.guest = null;
      room.guestBankId = null;
      room.status = 'waiting';
      room.roomId = null;
      room.signals = { host: [], guest: [] };
    }
    // 配对成功：创建对战房间，题库协商逻辑与公开匹配一致
    const now = Date.now();
    const sameBank = !!(room.hostBankId && safeBankId && room.hostBankId === safeBankId);
    const roomId = 'pk' + now.toString(36) + Math.random().toString(36).slice(2, 8);
    pkRooms[roomId] = {
      id: roomId,
      players: [room.host, username],
      createdAt: now,
      progress: {
        [room.host]: { score: 0, answered: 0, finished: false, lastSeen: now },
        [username]: { score: 0, answered: 0, finished: false, lastSeen: now }
      },
      banks: { [room.host]: room.hostBankId, [username]: safeBankId },
      bankVotes: {},
      bankStatus: sameBank ? 'agreed' : 'select',
      bankId: sameBank ? safeBankId : null,
      left: []
    };
    room.guest = username;
    room.guestBankId = safeBankId;
    room.status = 'matched';
    room.roomId = roomId;
    return sendJson(res, 200, { success: true, ...pkRoomPublic(pkRooms[roomId], username) });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// WebRTC信令中转：把 data（SDP/ICE候选，任意JSON）追加到对方的消息队列，由对方轮询取走
function handlePKP2pSignal(req, res) {
  parseBody(req).then(({ code, from, data }) => {
    const safeCode = String(code || '').toUpperCase();
    const room = pkP2pRooms[safeCode];
    if (!room || (from !== room.host && from !== room.guest)) {
      return sendJson(res, 200, { success: false, error: '房间不存在' });
    }
    if (data === undefined || data === null || typeof data !== 'object') {
      return sendJson(res, 400, { success: false, error: '信令数据无效' });
    }
    const to = from === room.host ? 'guest' : 'host';
    if (room.signals[to].length < 100) room.signals[to].push(data);
    room.lastActive = Date.now();
    return sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// P2P状态轮询：房主等待房客加入、双方收取对方信令，同时作为P2P房间心跳
function handlePKP2pState(res, query) {
  const { code, username } = query;
  pkCleanup();
  const room = pkP2pRooms[String(code || '').toUpperCase()];
  if (!room || (username !== room.host && username !== room.guest)) {
    return sendJson(res, 200, { success: true, status: 'gone' });
  }
  room.lastActive = Date.now();
  const role = username === room.host ? 'host' : 'guest';
  const signals = room.signals[role];
  room.signals[role] = []; // 取后清空
  const base = { success: true, status: room.status, host: room.host, guest: room.guest, signals };
  if (room.status === 'matched' && room.roomId && pkRooms[room.roomId]) {
    const pub = pkRoomPublic(pkRooms[room.roomId], username);
    return sendJson(res, 200, { ...base, ...pub });
  }
  return sendJson(res, 200, base);
}
// 离开P2P配对房间：一方离开即删除，对方在轮询时感知 status='gone'
function handlePKP2pLeave(req, res) {
  parseBody(req).then(({ code, username }) => {
    const safeCode = String(code || '').toUpperCase();
    const room = pkP2pRooms[safeCode];
    if (room && (username === room.host || username === room.guest)) {
      if (room.roomId && pkRooms[room.roomId]) {
        const battle = pkRooms[room.roomId];
        if (battle.players.includes(username) && !battle.left.includes(username)) {
          battle.left.push(username);
          if (battle.progress[username]) battle.progress[username].finished = true;
          if (battle.left.length >= 2) delete pkRooms[room.roomId];
        }
      }
      delete pkP2pRooms[safeCode];
    }
    return sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 玩家登录
function handlePlayerLogin(req, res) {
  parseBody(req).then(({ username, deviceId, auto, password, totp }) => {
    if (!isValidUsername(username)) {
      return sendJson(res, 400, { success: false, error: '用户名只能包含1-20位中英文、数字或下划线' });
    }
    if (!isValidDeviceId(deviceId)) {
      return sendJson(res, 400, { success: false, error: '设备ID无效' });
    }

    const filePath = getPlayerPath(username);
    if (fs.existsSync(filePath)) {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const storedDeviceId = decodeStoredDeviceId(data.deviceId);
      const hasPassword = !!(data.passwordHash && data.passwordSalt);
      const has2fa = !!data.twoFactorEnabled;

      // 自动登录：仅受信任设备可跳过密码/2FA
      if (auto === true) {
        if (storedDeviceId !== deviceId && storedDeviceId !== SUPERUSER_DEVICE) {
          return sendJson(res, 200, { success: false, errorCode: 'DEVICE_MISMATCH', needsPassword: hasPassword, needs2fa: has2fa, error: '设备不匹配，请手动登录' });
        }
      } else {
        // 手动登录：校验密码
        if (hasPassword) {
          if (!password || !verifyPassword(password, data.passwordHash, data.passwordSalt)) {
            return sendJson(res, 200, { success: false, errorCode: 'WRONG_PASSWORD', error: '密码错误' });
          }
        }
        // 校验2FA
        if (has2fa) {
          if (!totp || !verifyTotp(data.twoFactorSecret, totp)) {
            return sendJson(res, 200, { success: false, errorCode: 'WRONG_2FA', error: '2FA验证码错误' });
          }
        }
        if (storedDeviceId !== SUPERUSER_DEVICE) {
          data.deviceId = encodeDeviceId(deviceId);
        }
      }

      data.lastLogin = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      return sendJson(res, 200, { success: true, exists: true, hasPassword, has2fa, data });
    }

    if (auto === true) {
      return sendJson(res, 200, { success: false, errorCode: 'PLAYER_NOT_FOUND', error: '玩家不存在' });
    }
    // 新玩家
    let progress = createEmptyProgress(username, deviceId);
    fs.writeFileSync(filePath, JSON.stringify(progress, null, 2));
    sendJson(res, 200, { success: true, exists: false, hasPassword: false, has2fa: false, data: progress });
  }).catch(error => {
    console.error('玩家登录失败:', error);
    sendJson(res, 400, { success: false, error: '请求数据无效' });
  });
}
// 设置/修改密码（需登录态，修改密码需提供旧密码）
function handleSetPassword(req, res) {
  parseBody(req).then(({ username, oldPassword, newPassword }) => {
    if (!isValidUsername(username)) return sendJson(res, 400, { success: false, error: '用户名无效' });
    if (typeof newPassword !== 'string' || newPassword.length < 4 || newPassword.length > 64) {
      return sendJson(res, 400, { success: false, error: '新密码长度需4-64位' });
    }
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) return sendJson(res, 404, { success: false, error: '玩家不存在' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const hasPassword = !!(data.passwordHash && data.passwordSalt);
    if (hasPassword) {
      if (!oldPassword || !verifyPassword(oldPassword, data.passwordHash, data.passwordSalt)) {
        return sendJson(res, 400, { success: false, error: '旧密码错误' });
      }
    }
    const { salt, hash } = hashPassword(newPassword);
    data.passwordSalt = salt;
    data.passwordHash = hash;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 清除密码（需旧密码）
function handleClearPassword(req, res) {
  parseBody(req).then(({ username, oldPassword }) => {
    if (!isValidUsername(username)) return sendJson(res, 400, { success: false, error: '用户名无效' });
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) return sendJson(res, 404, { success: false, error: '玩家不存在' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (data.passwordHash && data.passwordSalt) {
      if (!oldPassword || !verifyPassword(oldPassword, data.passwordHash, data.passwordSalt)) {
        return sendJson(res, 400, { success: false, error: '旧密码错误' });
      }
    }
    delete data.passwordHash;
    delete data.passwordSalt;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 生成2FA密钥并返回otpauth URL（暂不启用，需confirm确认）
function handle2faGenerate(req, res) {
  parseBody(req).then(({ username, password }) => {
    if (!isValidUsername(username)) return sendJson(res, 400, { success: false, error: '用户名无效' });
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) return sendJson(res, 404, { success: false, error: '玩家不存在' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    // 已开启2FA则不允许重新生成
    if (data.twoFactorEnabled) return sendJson(res, 400, { success: false, error: '已开启2FA，请先关闭' });
    // 若有密码需校验
    if (data.passwordHash && data.passwordSalt) {
      if (!password || !verifyPassword(password, data.passwordHash, data.passwordSalt)) {
        return sendJson(res, 400, { success: false, error: '密码错误' });
      }
    }
    const secret = generateTotpSecret();
    const otpauth = `otpauth://totp/CZM:${encodeURIComponent(username)}?secret=${secret}&issuer=CZM&algorithm=SHA1&digits=6&period=30`;
    // 暂存待确认密钥（10分钟内有效）
    data._pending2faSecret = secret;
    data._pending2faExpiry = Date.now() + 10 * 60 * 1000;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    sendJson(res, 200, { success: true, secret, otpauth });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 确认2FA（用户输入验证码，验证通过后启用）
function handle2faConfirm(req, res) {
  parseBody(req).then(({ username, totp }) => {
    if (!isValidUsername(username)) return sendJson(res, 400, { success: false, error: '用户名无效' });
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) return sendJson(res, 404, { success: false, error: '玩家不存在' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const secret = data._pending2faSecret;
    const expiry = data._pending2faExpiry || 0;
    if (!secret || Date.now() > expiry) {
      return sendJson(res, 400, { success: false, error: '2FA配置已过期，请重新生成' });
    }
    if (!verifyTotp(secret, totp)) {
      return sendJson(res, 400, { success: false, error: '验证码错误' });
    }
    data.twoFactorSecret = secret;
    data.twoFactorEnabled = true;
    delete data._pending2faSecret;
    delete data._pending2faExpiry;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 关闭2FA（需密码+当前TOTP验证码）
function handle2faDisable(req, res) {
  parseBody(req).then(({ username, password, totp }) => {
    if (!isValidUsername(username)) return sendJson(res, 400, { success: false, error: '用户名无效' });
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) return sendJson(res, 404, { success: false, error: '玩家不存在' });
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!data.twoFactorEnabled) return sendJson(res, 400, { success: false, error: '2FA未开启' });
    if (data.passwordHash && data.passwordSalt) {
      if (!password || !verifyPassword(password, data.passwordHash, data.passwordSalt)) {
        return sendJson(res, 400, { success: false, error: '密码错误' });
      }
    }
    if (!verifyTotp(data.twoFactorSecret, totp)) {
      return sendJson(res, 400, { success: false, error: '2FA验证码错误' });
    }
    data.twoFactorEnabled = false;
    delete data.twoFactorSecret;
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    sendJson(res, 200, { success: true });
  }).catch(() => sendJson(res, 400, { success: false, error: '请求格式错误' }));
}
// 获取玩家进度
function handleGetProgress(res, query) {
  const username = query.username;
  if (!isValidUsername(username)) {
    return sendJson(res, 400, { success: false, error: '用户名无效' });
  }
  const filePath = getPlayerPath(username);
  if (!fs.existsSync(filePath)) {
    return sendJson(res, 404, { success: false, error: '玩家不存在' });
  }
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    sendJson(res, 200, { success: true, data });
  } catch (error) {
    console.error('读取玩家进度失败:', error);
    sendJson(res, 500, { success: false, error: '读取玩家进度失败' });
  }
}
// 保存玩家进度
function handleSaveProgress(req, res) {
  parseBody(req).then(body => {
    const username = body.username;
    if (!isValidUsername(username)) {
      return sendJson(res, 400, { success: false, error: '用户名无效' });
    }
    const filePath = getPlayerPath(username);
    if (!fs.existsSync(filePath)) {
      return sendJson(res, 404, { success: false, error: '玩家不存在' });
    }
    try {
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      data.completedLevels = Array.isArray(body.completedLevels) ? body.completedLevels : [];
      data.gushiCompletedLevels = Array.isArray(body.gushiCompletedLevels) ? body.gushiCompletedLevels : [];
      data.caiziCompletedLevels = Array.isArray(body.caiziCompletedLevels) ? body.caiziCompletedLevels : [];
      if (body.bankId && typeof body.pageProgress === 'object' && body.pageProgress !== null) {
        if (!isValidBankId(body.bankId)) {
          return sendJson(res, 400, { success: false, error: '题库ID无效' });
        }
        const cleanProgress = {};
        for (const [pageKey, value] of Object.entries(body.pageProgress)) {
          if (!/^[一-龥a-zA-Z0-9_-]{1,40}$/.test(String(pageKey))) continue;
          if (!Array.isArray(value)) continue;
          cleanProgress[pageKey] = value
            .slice(0, 500)
            .map(v => (v === null || typeof v === 'string') ? (typeof v === 'string' ? v.slice(0, 64) : v) : null);
        }
        data[body.bankId + '-completelevel'] = cleanProgress;
      }
      if (body.settings && typeof body.settings === 'object') {
        data.settings = body.settings;
      }
      if (body.points !== undefined && body.points !== null) {
        const pts = Math.floor(Number(body.points));
        if (!Number.isFinite(pts) || pts < 0 || pts > 2147483647) {
          return sendJson(res, 400, { success: false, error: '积分数据无效' });
        }
        data.points = pts;
      }
      if (Array.isArray(body.achvClaimed)) {
        const clean = [];
        for (const x of body.achvClaimed) {
          if (typeof x === 'string' && /^[a-zA-Z0-9_-]{1,40}$/.test(x) && !clean.includes(x)) clean.push(x);
          if (clean.length >= 200) break;
        }
        data.achvClaimed = clean;
      }
      if (body.flags && typeof body.flags === 'object' && !Array.isArray(body.flags)) {
        data.flags = {};
        for (const k of ['easter', 'vipLink']) {
          if (body.flags[k] === true) data.flags[k] = true;
        }
      }
      if (Array.isArray(body.shopOwned)) {
        const clean = [];
        for (const x of body.shopOwned) {
          if (typeof x === 'string' && /^[a-zA-Z0-9_-]{1,40}$/.test(x) && !clean.includes(x)) clean.push(x);
          if (clean.length >= 200) break;
        }
        data.shopOwned = clean;
      }
      if (body.shopLevels && typeof body.shopLevels === 'object' && !Array.isArray(body.shopLevels)) {
        const clean = {};
        for (const [k, v] of Object.entries(body.shopLevels)) {
          if (!/^[a-zA-Z0-9_-]{1,40}$/.test(k)) continue;
          const n = Math.floor(Number(v));
          if (Number.isFinite(n) && n >= 0 && n <= 99) clean[k] = n;
          if (Object.keys(clean).length >= 50) break;
        }
        data.shopLevels = clean;
      }
      if (body.uiEffectsEnabled && typeof body.uiEffectsEnabled === 'object' && !Array.isArray(body.uiEffectsEnabled)) {
        const clean = {};
        for (const [k, v] of Object.entries(body.uiEffectsEnabled)) {
          if (!/^ui-[a-z0-9-]{1,30}$/.test(k)) continue;
          if (v === true || v === false) clean[k] = v;
          if (Object.keys(clean).length >= 30) break;
        }
        data.uiEffectsEnabled = clean;
      }
      data.lastLogin = new Date().toISOString();
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      sendJson(res, 200, { success: true });
    } catch (error) {
      console.error('保存玩家进度失败:', error);
      sendJson(res, 500, { success: false, error: '保存玩家进度失败' });
    }
  }).catch(error => {
    console.error('保存玩家进度失败:', error);
    sendJson(res, 400, { success: false, error: '请求数据无效' });
  });
}
// 删除玩家账户（注销用户）：删除整个玩家数据文件
function handleDeletePlayer(res, query) {
  const username = query.username;
  if (!isValidUsername(username)) {
    return sendJson(res, 400, { success: false, error: '用户名无效' });
  }
  const filePath = getPlayerPath(username);
  if (!fs.existsSync(filePath)) {
    return sendJson(res, 404, { success: false, error: '玩家不存在' });
  }
  try {
    fs.unlinkSync(filePath);
    sendJson(res, 200, { success: true });
  } catch (error) {
    console.error('删除玩家失败:', error);
    sendJson(res, 500, { success: false, error: '删除玩家失败' });
  }
}

const server = http.createServer((req, res) => {
  res.on('error', error => {
    console.error('响应流出错（客户端可能已断开）:', req.method, req.url, error.code || error.message);
  });

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;

  if (pathname === '/api/banks' && req.method === 'GET') return handleListBanks(res);
  if (pathname === '/api/bgm-files' && req.method === 'GET') return handleListBgmFiles(res, query);

  if (pathname.startsWith('/api/cache/')) {
    const key = decodeURIComponent(pathname.slice('/api/cache/'.length));
    if (req.method === 'GET') return handleCacheGet(res, key);
    if (req.method === 'POST') return handleCacheSet(req, res, key);
    if (req.method === 'DELETE') return handleCacheDel(res, key);
    return sendJson(res, 405, { success: false, error: '方法不允许' });
  }

  if (pathname === '/api/player/login' && req.method === 'POST') {
    return handlePlayerLogin(req, res);
  }
  if (pathname === '/api/player/progress') {
    if (req.method === 'GET') return handleGetProgress(res, query);
    if (req.method === 'POST') return handleSaveProgress(req, res);

    return sendJson(res, 405, { success: false, error: '方法不允许' });
  }
  if (pathname === '/api/player/delete' && req.method === 'DELETE') return handleDeletePlayer(res, query);
  if (pathname === '/api/player/password' && req.method === 'POST') return handleSetPassword(req, res);
  if (pathname === '/api/player/password/clear' && req.method === 'POST') return handleClearPassword(req, res);
  if (pathname === '/api/player/2fa/generate' && req.method === 'POST') return handle2faGenerate(req, res);
  if (pathname === '/api/player/2fa/confirm' && req.method === 'POST') return handle2faConfirm(req, res);
  if (pathname === '/api/player/2fa/disable' && req.method === 'POST') return handle2faDisable(req, res);

  if (pathname === '/api/pk/match/join' && req.method === 'POST') return handlePKMatchJoin(req, res);
  if (pathname === '/api/pk/match/poll' && req.method === 'GET') return handlePKMatchPoll(res, query);
  if (pathname === '/api/pk/match/cancel' && req.method === 'POST') return handlePKMatchCancel(req, res);
  if (pathname === '/api/pk/room/progress' && req.method === 'POST') return handlePKRoomProgress(req, res);
  if (pathname === '/api/pk/room/bank' && req.method === 'POST') return handlePKRoomBankVote(req, res);
  if (pathname === '/api/pk/room/state' && req.method === 'GET') return handlePKRoomState(res, query);
  if (pathname === '/api/pk/room/leave' && req.method === 'POST') return handlePKRoomLeave(req, res);

  if (pathname === '/api/pk/p2p/host' && req.method === 'POST') return handlePKP2pHost(req, res);
  if (pathname === '/api/pk/p2p/join' && req.method === 'POST') return handlePKP2pJoin(req, res);
  if (pathname === '/api/pk/p2p/signal' && req.method === 'POST') return handlePKP2pSignal(req, res);
  if (pathname === '/api/pk/p2p/state' && req.method === 'GET') return handlePKP2pState(res, query);
  if (pathname === '/api/pk/p2p/leave' && req.method === 'POST') return handlePKP2pLeave(req, res);

  try {
    if (pathname.startsWith('/data/playerdata')) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('403 Forbidden');
    }

    const filePath = path.join(__dirname, pathname === '/' ? 'CZM-main.html' : pathname);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      // 防止路径穿越：确认真实路径仍在站点目录内
      const realPath = fs.realpathSync(filePath);
      if (!realPath.startsWith(__dirname)) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('403 Forbidden');
      }

      const extname = path.extname(filePath);
      const contentType = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'text/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.jfif': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon',
        '.mp3': 'audio/mpeg',
        '.wav': 'audio/wav',
        '.ogg': 'audio/ogg',
        '.m4a': 'audio/mp4',
        '.aac': 'audio/aac',
        '.flac': 'audio/flac',
        '.opus': 'audio/ogg',
        '.webm': 'audio/webm'
      }[extname] || 'application/octet-stream';
      // HTML和JSON禁用缓存：页面与语言包更新后浏览器立即生效，避免改版后仍显示旧版
      const headers = { 'Content-Type': contentType };
      if (extname === '.html' || extname === '.json' || extname === '.css') {
        headers['Cache-Control'] = 'no-cache';
      }
      res.writeHead(200, headers);
      const stream = fs.createReadStream(filePath);
      stream.on('error', error => {
        console.error('读取静态文件流出错:', filePath, error.message);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        }
        res.end('Internal Server Error');
      });
      res.on('error', error => {
        console.error('响应流出错（客户端可能已断开）:', error.message);
        stream.destroy();
      });
      stream.pipe(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
    }
  } catch (error) {
    console.error('提供静态文件失败:', error);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('404 Not Found');
  }
});

const PORT = process.env.PORT || 3000;

server.on('clientError', (error, socket) => {
  console.error('客户端连接错误:', error.code || error.message);
  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  console.log(`服务器启动于http://localhost:${PORT}`);
  console.log(`玩家数据目录：${PLAYER_DIR}`);
});

process.on('uncaughtException', error => {
  console.error('[uncaughtException] 未捕获异常：', error && error.stack ? error.stack : error);
});
process.on('unhandledRejection', reason => {
  console.error('[unhandledRejection] 未处理的Promise拒绝：', reason && reason.stack ? reason.stack : reason);
});
