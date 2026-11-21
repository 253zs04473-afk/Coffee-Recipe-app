const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
const isProd = process.env.NODE_ENV === "production";
const PORT = process.env.PORT || 8000;

// Render はプロキシ経由なので、HTTPS 判定のために必要
app.set("trust proxy", 1);
app.set("view engine", "pug");

// ---- HTTP 通信を禁止（本番では HTTPS にリダイレクト）----
if (isProd) {
  app.use((req, res, next) => {
    if (req.secure) return next();
    res.redirect(301, "https://" + req.headers.host + req.originalUrl);
  });
}

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: isProd, maxAge: 7 * 24 * 60 * 60 * 1000 },
  })
);

// ---- CSRF 対策：ワンタイムトークン ----
// 複数タブでも使えるよう最大5個まで保持し、使ったトークンは破棄する
function issueToken(req) {
  const token = crypto.randomBytes(32).toString("hex");
  const tokens = req.session.csrfTokens || [];
  tokens.push(token);
  req.session.csrfTokens = tokens.slice(-5);
  return token;
}

function verifyToken(req) {
  const actual = req.body && req.body._csrf;
  const tokens = req.session.csrfTokens || [];
  if (typeof actual !== "string") return false;
  const index = tokens.findIndex((t) => {
    const a = Buffer.from(t);
    const b = Buffer.from(actual);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
  if (index < 0) return false;
  tokens.splice(index, 1); // 一度使ったら無効にする
  req.session.csrfTokens = tokens;
  return true;
}

// ---- Basic 認証（管理ページ用）----
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function basicAuth(req, res, next) {
  const user = process.env.ADMIN_USER || (isProd ? null : "admin");
  const pass = process.env.ADMIN_PASSWORD || (isProd ? null : "password");
  if (!user || !pass) {
    return res.status(503).send("管理者の認証情報が設定されていません。");
  }
  const [scheme, encoded] = (req.headers.authorization || "").split(" ");
  if (scheme === "Basic" && encoded) {
    const decoded = Buffer.from(encoded, "base64").toString();
    const i = decoded.indexOf(":");
    if (i >= 0 && safeEqual(decoded.slice(0, i), user) && safeEqual(decoded.slice(i + 1), pass)) {
      return next();
    }
  }
  res.set("WWW-Authenticate", "Basic realm=\"admin\", charset=\"UTF-8\"");
  res.status(401).send("認証が必要です。");
}

// ---- データ（メモリ上。再起動すると消えます）----
const METHODS = ["ハンドドリップ", "ケメックス", "エアロプレス", "フレンチプレス", "エスプレッソ", "水出し"];
const GRINDS = ["極細挽き", "細挽き", "中細挽き", "中挽き", "粗挽き"];

let nextId = 1;
const recipes = [];

function addRecipe(r) {
  recipes.push({ id: nextId++, hasPhoto: Boolean(r.photo), ...r, ratio: Math.round((r.water / r.dose) * 10) / 10 });
}

addRecipe({ name: "朝の定番ハンドドリップ", method: "ハンドドリップ", bean: "エチオピア イルガチェフェ", grind: "中細挽き", dose: 15, water: 250, temp: 92, seconds: 180, rating: 5, notes: "30秒蒸らしてから3回に分けて注ぐ。華やかな香り。" });
addRecipe({ name: "濃いめエアロプレス", method: "エアロプレス", bean: "ブラジル セラード", grind: "中挽き", dose: 17, water: 220, temp: 85, seconds: 90, rating: 4, notes: "逆さ式。ナッツのような甘さが出る。" });

function parseNumber(value, min, max, label, required) {
  const s = String(value || "").trim();
  if (s === "") return required ? { error: label + "を入力してください。" } : { value: null };
  const n = Number(s);
  if (!Number.isFinite(n) || n < min || n > max) {
    return { error: label + "は" + min + "〜" + max + "の数値で入力してください。" };
  }
  return { value: n };
}

function validate(body) {
  const name = (body.name || "").trim();
  const bean = (body.bean || "").trim();
  const notes = (body.notes || "").trim();
  if (!name) return { error: "レシピ名を入力してください。" };
  if (name.length > 30) return { error: "レシピ名は30文字以内にしてください。" };
  if (bean.length > 40) return { error: "豆の名前は40文字以内にしてください。" };
  if (notes.length > 200) return { error: "メモは200文字以内にしてください。" };
  if (!METHODS.includes(body.method)) return { error: "抽出方法を選んでください。" };
  if (!GRINDS.includes(body.grind)) return { error: "挽き目を選んでください。" };

  const dose = parseNumber(body.dose, 1, 100, "粉の量(g)", true);
  if (dose.error) return dose;
  const water = parseNumber(body.water, 1, 2000, "お湯の量(g)", true);
  if (water.error) return water;
  const temp = parseNumber(body.temp, 0, 100, "お湯の温度(℃)", false);
  if (temp.error) return temp;
  const seconds = parseNumber(body.seconds, 1, 86400, "抽出時間(秒)", false);
  if (seconds.error) return seconds;
  const rating = parseNumber(body.rating, 1, 5, "評価", true);
  if (rating.error) return rating;

  return {
    recipe: {
      name, bean, notes,
      method: body.method, grind: body.grind,
      dose: dose.value, water: water.value,
      temp: temp.value, seconds: seconds.value, rating: Math.round(rating.value),
    },
  };
}

// ---- 写真アップロード（メモリ上に保存。再起動すると消えます）----
const MAX_PHOTO_BYTES = 2 * 1024 * 1024; // 2MB
const MAX_PHOTOS = 50; // メモリを使い切らないための上限
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_PHOTO_BYTES, files: 1, fields: 20, fieldSize: 20 * 1024 },
});

// ファイルの先頭バイトで画像の種類を判定する（拡張子や申告された種類は信用しない）
function detectImageType(buf) {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (buf.length >= 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
  if (buf.length >= 12 && buf.slice(0, 4).toString("latin1") === "RIFF" && buf.slice(8, 12).toString("latin1") === "WEBP") return "image/webp";
  return null;
}

// 表示用ヘルパー
app.locals.formatTime = (s) => (s == null ? "-" : Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"));
app.locals.stars = (n) => "★".repeat(n) + "☆".repeat(5 - n);
app.locals.METHODS = METHODS;
app.locals.GRINDS = GRINDS;

// ---- ルーティング ----
function renderIndex(req, res, extra) {
  const q = METHODS.includes(req.query.method) ? req.query.method : "";
  const list = recipes.filter((r) => !q || r.method === q).reverse();
  res.render("index", {
    recipes: list,
    filter: q,
    csrfToken: issueToken(req),
    ownerId: req.session.ownerId || null,
    values: {},
    ...extra,
  });
}

app.get("/", (req, res) => renderIndex(req, res));

app.post("/recipes", (req, res) => {
  upload.single("photo")(req, res, (err) => {
    if (err) {
      const message =
        err.code === "LIMIT_FILE_SIZE"
          ? "写真は2MB以下にしてください。"
          : "フォームの送信内容に問題があります。";
      res.status(400);
      return renderIndex(req, res, { error: message, values: {} });
    }
    if (!verifyToken(req)) {
      return res.status(403).send("不正なリクエストです（CSRFトークンが無効です）。");
    }
    const fail = (message) => {
      res.status(400);
      return renderIndex(req, res, { error: message, values: req.body });
    };
    const result = validate(req.body);
    if (result.error) return fail(result.error);

    const recipe = result.recipe;
    if (req.file && req.file.size > 0) {
      const type = detectImageType(req.file.buffer);
      if (!type) return fail("写真はJPEG、PNG、WebPのいずれかにしてください。");
      if (recipes.filter((r) => r.hasPhoto).length >= MAX_PHOTOS) {
        return fail("写真の保存数が上限に達しています。写真なしで保存してください。");
      }
      recipe.photo = req.file.buffer;
      recipe.photoType = type;
    }
    // 作った人を覚えておく（ログインはないので、ブラウザのセッションで本人を判定する）
    if (!req.session.ownerId) req.session.ownerId = crypto.randomBytes(16).toString("hex");
    recipe.ownerId = req.session.ownerId;
    addRecipe(recipe);
    res.redirect("/");
  });
});

// 写真の配信（Content-Type は判定済みの値を固定で返す）
app.get("/recipes/:id/photo", (req, res) => {
  const r = recipes.find((x) => x.id === Number(req.params.id));
  if (!r || !r.photo) return res.status(404).send("Not found");
  res.set("Content-Type", r.photoType);
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Cache-Control", "public, max-age=300");
  res.send(r.photo);
});

// 自分が作ったレシピだけ削除できる
app.post("/recipes/delete", (req, res) => {
  if (!verifyToken(req)) {
    return res.status(403).send("不正なリクエストです（CSRFトークンが無効です）。");
  }
  const index = recipes.findIndex((r) => r.id === Number(req.body.id));
  if (index < 0) return res.redirect("/");
  const owner = req.session.ownerId;
  if (!owner || recipes[index].ownerId !== owner) {
    return res.status(403).send("このレシピを削除する権限がありません。");
  }
  recipes.splice(index, 1);
  res.redirect("/");
});

app.get("/admin", basicAuth, (req, res) => {
  res.render("admin", { recipes: [...recipes].reverse(), csrfToken: issueToken(req) });
});

app.post("/admin/delete", basicAuth, (req, res) => {
  if (!verifyToken(req)) {
    return res.status(403).send("不正なリクエストです（CSRFトークンが無効です）。");
  }
  const index = recipes.findIndex((r) => r.id === Number(req.body.id));
  if (index >= 0) recipes.splice(index, 1);
  res.redirect("/admin");
});

app.listen(PORT, () => console.log("Listening on port " + PORT));
