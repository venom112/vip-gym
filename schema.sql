CREATE TABLE IF NOT EXISTS docs (
  col TEXT NOT NULL,
  id TEXT NOT NULL,
  data TEXT NOT NULL,
  updated INTEGER NOT NULL,
  PRIMARY KEY (col, id)
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  perms TEXT NOT NULL DEFAULT '{}',
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  iter INTEGER NOT NULL DEFAULT 100000,
  updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  t INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta (k, v) VALUES ('ver', 1);

-- البيانات الافتراضية (تُضاف مرة واحدة فقط)
INSERT OR IGNORE INTO docs (col,id,data,updated) VALUES
('settings','main','{"name":"VIP GYM"}',0),
('ktypes','amount','{"id":"amount","n":"مبلغ ثابت (جنيه)","f":"amount","m":1}',0),
('ktypes','pct','{"id":"pct","n":"نسبة مئوية %","f":"pct","m":1}',0),
('ktypes','day','{"id":"day","n":"أيام × (الأساسي ÷ عدد أيام الشهر)","f":"day","m":1}',0),
('ktypes','half','{"id":"half","n":"نصف يوم × (الأساسي ÷ عدد أيام الشهر)","f":"day","m":0.5,"u":"نصف يوم"}',0),
('methods','m','{"id":"m","n":"مبلغ ثابت","k":"amount"}',0),
('methods','pb','{"id":"pb","n":"نسبة % من الأساسي","k":"pct","b":"basic"}',0),
('methods','pf','{"id":"pf","n":"نسبة % من KPI","k":"pct","b":"fixed"}',0),
('methods','dy','{"id":"dy","n":"يوم من الأساسي","k":"day","d":30}',0),
('methods','hd','{"id":"hd","n":"نصف يوم من الأساسي","k":"half","d":30}',0),
('statuses','s1','{"id":"s1","n":"قيد المراجعة","b":"pending"}',0),
('statuses','s2','{"id":"s2","n":"معتمد","b":"count"}',0),
('statuses','s3','{"id":"s3","n":"مرفوض","b":"none"}',0),
('policies','alert','{"id":"alert","n":"تنبيه بزيادة KPI","b":"alert"}',0),
('policies','basic','{"id":"basic","n":"الخصم من الأساسي تلقائياً","b":"basic"}',0),
('items','1','{"id":1,"n":"تأخير","m":"dy","v":0.25}',0),
('items','2','{"id":2,"n":"غياب بدون إذن","m":"dy","v":1}',0),
('items','3','{"id":3,"n":"جزاء إداري","m":"pb","v":5}',0),
('items','4','{"id":4,"n":"سلفة","m":"m","v":500}',0),
('items','5','{"id":5,"n":"تأمينات اجتماعية","m":"pb","v":11}',0),
('items','6','{"id":6,"n":"خصم نصف يوم","m":"hd","v":1}',0);
