'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),readline=require('readline');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000,DBP=process.env.DB_PATH||path.join(__dirname,'data','mawidi.db');
const TZ=+(process.env.TZ_OFFSET_MIN??60); // الجزائر: UTC+1 بلا توقيت صيفي
const SECURE=process.env.NODE_ENV==='production';
fs.mkdirSync(path.dirname(DBP),{recursive:true});
const db=new DatabaseSync(DBP);
db.exec(`PRAGMA journal_mode=WAL;PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS doctor(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(t TEXT PRIMARY KEY,exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS appts(id INTEGER PRIMARY KEY,ref TEXT UNIQUE,name TEXT NOT NULL,phone TEXT NOT NULL,date TEXT NOT NULL,time TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS uq_slot ON appts(date,time) WHERE status IN('pending','confirmed');
CREATE TABLE IF NOT EXISTS ann(id INTEGER PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,starts TEXT,ends TEXT);
CREATE TABLE IF NOT EXISTS closures(id INTEGER PRIMARY KEY,date TEXT NOT NULL,from_t TEXT,to_t TEXT,note TEXT);`);

/* ---------- كلمات المرور والجلسات ---------- */
const hashPw=p=>{const s=crypto.randomBytes(16);return 's1$'+s.toString('hex')+'$'+crypto.scryptSync(p,s,64).toString('hex')};
const checkPw=(p,h)=>{const [,s,k]=h.split('$');const x=crypto.scryptSync(p,Buffer.from(s,'hex'),64);return crypto.timingSafeEqual(x,Buffer.from(k,'hex'))};
const sha=t=>crypto.createHash('sha256').update(t).digest('hex');

if(process.argv[2]==='create-doctor'){
  if(db.prepare('SELECT 1 FROM doctor').get()){console.error('حساب الطبيب موجود مسبقًا. استخدم صفحة «الأمان» لتغيير كلمة المرور.');process.exit(1)}
  const rl=readline.createInterface({input:process.stdin,output:process.stdout});
  const q=s=>new Promise(r=>rl.question(s,r));
  (async()=>{const u=(await q('اسم المستخدم: ')).trim();const p=process.env.DOCTOR_PASSWORD||await q('كلمة المرور (10 أحرف على الأقل): ');rl.close();
    if(!u||p.length<10){console.error('بيانات غير صالحة.');process.exit(1)}
    db.prepare('INSERT INTO doctor VALUES(1,?,?)').run(u,hashPw(p));console.log('تم إنشاء حساب الطبيب.');process.exit(0)})();
  return;
}

/* ---------- الإعدادات والأوقات ---------- */
const DEF={brand:'موعدي — Mawidi',tagline:'موعدك مع طبيبك، بكل سهولة.',name:'',specialty:'',clinic:'',address:'',phone:'',about:'',
 days:[0,1,2,3,4],start:'08:00',end:'16:00',dur:30,breaks:[{s:'12:00',e:'13:00'}],horizon:30};
const settings=()=>{const r=db.prepare("SELECT v FROM kv WHERE k='s'").get();return {...DEF,...(r?JSON.parse(r.v):{})}};
const m=t=>{const [h,n]=t.split(':');return +h*60+ +n},f=n=>String(n/60|0).padStart(2,'0')+':'+String(n%60).padStart(2,'0');
const nowL=()=>new Date(Date.now()+TZ*60000),todayS=()=>nowL().toISOString().slice(0,10);
const addDays=(d,n)=>new Date(Date.parse(d+'T00:00:00Z')+n*864e5).toISOString().slice(0,10);
const isDate=d=>/^\d{4}-\d{2}-\d{2}$/.test(d)&&!isNaN(Date.parse(d)),isTime=t=>/^([01]\d|2[0-3]):[0-5]\d$/.test(t);
function slots(date,ignorePast){
  const S=settings(),dow=new Date(date+'T00:00:00Z').getUTCDay();
  if(!S.days.includes(dow))return {all:[],free:[]};
  const cl=db.prepare('SELECT * FROM closures WHERE date=?').all(date);
  if(cl.some(c=>!c.from_t))return {all:[],free:[]};
  const bad=[...S.breaks.map(b=>[m(b.s),m(b.e)]),...cl.map(c=>[m(c.from_t),m(c.to_t)])];
  const taken=new Set(db.prepare("SELECT time FROM appts WHERE date=? AND status IN('pending','confirmed')").all(date).map(r=>r.time));
  const n=nowL(),nm=n.getUTCHours()*60+n.getUTCMinutes(),all=[];
  for(let t=m(S.start);t+S.dur<=m(S.end);t+=S.dur){
    if(bad.some(([a,b])=>t<b&&t+S.dur>a))continue;
    if(!ignorePast&&(date<todayS()||(date===todayS()&&t<=nm)))continue;
    all.push(f(t));
  }
  return {all,free:all.filter(x=>!taken.has(x))};
}
const conflicts=()=>db.prepare("SELECT * FROM appts WHERE status IN('pending','confirmed') AND date>=?").all(todayS())
  .filter(a=>!slots(a.date,true).all.includes(a.time)&&(a.date>todayS()||m(a.time)>nowL().getUTCHours()*60+nowL().getUTCMinutes()));

/* ---------- أدوات HTTP ---------- */
const hits=new Map();
function limited(key,max,win){const n=Date.now(),a=(hits.get(key)||[]).filter(t=>n-t<win);a.push(n);hits.set(key,a);return a.length>max}
setInterval(()=>{const n=Date.now();for(const [k,v] of hits)if(!v.some(t=>n-t<36e5))hits.delete(k);db.prepare('DELETE FROM sessions WHERE exp<?').run(n)},6e5).unref();
const E=(c,msg)=>Object.assign(new Error(msg),{code:c});
const body=req=>new Promise((res,rej)=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e4){rej(E(413,'الطلب كبير جدًا'));req.destroy()}});req.on('end',()=>{try{res(b?JSON.parse(b):{})}catch{rej(E(400,'بيانات غير صالحة'))}})});
const cookie=(req,n)=>((req.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith(n+'='))||'').slice(n.length+1);
const authed=req=>{const t=cookie(req,'sid');if(!t)return false;const r=db.prepare('SELECT exp FROM sessions WHERE t=?').get(sha(t));return !!r&&r.exp>Date.now()};
const ip=req=>(process.env.TRUST_PROXY?String(req.headers['x-forwarded-for']||'').split(',').pop().trim():'')||req.socket.remoteAddress;
const str=(v,min,max)=>{v=String(v??'').trim();if(v.length<min||v.length>max)throw E(400,'قيمة غير صالحة');return v};
const slotErr=e=>/UNIQUE/.test(e.message)?E(409,'هذه الساعة محجوزة بالفعل. اختر ساعة أخرى.'):e;

/* ---------- المسارات ---------- */
const R=[];const route=(M,re,auth,fn)=>R.push([M,new RegExp('^'+re+'$'),auth,fn]);
route('GET','/api/public',0,()=>{const S=settings(),t=todayS();
  const {brand,tagline,name,specialty,clinic,address,phone,about,days,start,end,dur,breaks}=S;
  return {brand,tagline,name,specialty,clinic,address,phone,about,days,start,end,dur,breaks,
   ann:db.prepare("SELECT id,title,body FROM ann WHERE active=1 AND (starts IS NULL OR starts='' OR starts<=?) AND (ends IS NULL OR ends='' OR ends>=?) ORDER BY id DESC").all(t,t)}});
route('GET','/api/days',0,()=>{const t=todayS(),H=settings().horizon,out=[];for(let i=0;i<=H;i++){const d=addDays(t,i);if(slots(d).free.length)out.push(d)}return {days:out}});
route('GET','/api/slots',0,(req,_,q)=>{if(!isDate(q.date))throw E(400,'تاريخ غير صالح');return {slots:slots(q.date).free}});
route('POST','/api/book',0,async(req,b)=>{
  if(limited('b'+ip(req),8,36e5))throw E(429,'محاولات كثيرة. حاول لاحقًا.');
  const name=str(b.name,2,80),phone=String(b.phone||'').replace(/[\s.-]/g,'');
  if(!/^\+?\d{8,15}$/.test(phone))throw E(400,'رقم الهاتف غير صالح');
  if(!isDate(b.date)||b.date>addDays(todayS(),settings().horizon)||!slots(b.date).free.includes(b.time))throw E(409,'هذه الساعة لم تعد متاحة. اختر ساعة أخرى.');
  if(db.prepare("SELECT COUNT(*) c FROM appts WHERE phone=? AND status IN('pending','confirmed') AND date>=?").get(phone,todayS()).c>=2)throw E(429,'لديك طلبات قائمة بالفعل. تواصل مع العيادة.');
  const ref='MW-'+crypto.randomBytes(4).toString('hex').toUpperCase();
  try{db.prepare('INSERT INTO appts(ref,name,phone,date,time,created) VALUES(?,?,?,?,?,?)').run(ref,name,phone,b.date,b.time,Date.now())}catch(e){throw slotErr(e)}
  return {ref,date:b.date,time:b.time}});
route('POST','/api/login',0,async(req,b)=>{
  if(limited('l'+ip(req),6,9e5))throw E(429,'محاولات كثيرة. انتظر 15 دقيقة.');
  const d=db.prepare('SELECT * FROM doctor').get();
  const ok=d&&String(b.username)===d.username&&checkPw(String(b.password||''),d.hash);
  if(!ok)throw E(401,'بيانات الدخول غير صحيحة');
  const t=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?)').run(sha(t),Date.now()+432e5);
  return {ok:1,_cookie:`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${SECURE?'; Secure':''}`}});
route('POST','/api/logout',0,req=>{db.prepare('DELETE FROM sessions WHERE t=?').run(sha(cookie(req,'sid')));return {ok:1,_cookie:'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}});
route('GET','/api/admin/me',1,()=>({ok:1}));
route('GET','/api/admin/stats',1,()=>{const t=todayS(),c=(w,...a)=>db.prepare('SELECT COUNT(*) c FROM appts WHERE '+w).get(...a).c;
  return {today:c("date=? AND status IN('pending','confirmed')",t),pending:c("status='pending'"),confirmed:c("status='confirmed' AND date>=?",t),cancelled:c("status IN('cancelled','rejected')"),
   next:db.prepare("SELECT * FROM appts WHERE status='confirmed' AND date>=? ORDER BY date,time LIMIT 5").all(t),
   latest:db.prepare('SELECT * FROM appts ORDER BY id DESC LIMIT 6').all(),conflicts:conflicts()}});
route('GET','/api/admin/appts',1,(req,_,q)=>{const w=[],a=[];
  if(q.q){w.push('(name LIKE ? OR phone LIKE ? OR ref LIKE ?)');const x='%'+q.q.replace(/[%_]/g,'')+'%';a.push(x,x,x)}
  if(q.date){w.push('date=?');a.push(q.date)}if(q.status){w.push('status=?');a.push(q.status)}
  return {rows:db.prepare('SELECT * FROM appts'+(w.length?' WHERE '+w.join(' AND '):'')+' ORDER BY date DESC,time DESC LIMIT 300').all(...a)}});
route('PATCH','/api/admin/appts/(\\d+)',1,async(req,b,q,id)=>{
  const a=db.prepare('SELECT * FROM appts WHERE id=?').get(id);if(!a)throw E(404,'الحجز غير موجود');
  const T={pending:['confirmed','rejected','cancelled'],confirmed:['cancelled','completed'],rejected:['confirmed'],cancelled:[],completed:[]};
  try{
    if(b.status){if(!T[a.status].includes(b.status))throw E(400,'انتقال غير مسموح');db.prepare('UPDATE appts SET status=? WHERE id=?').run(b.status,id)}
    else if(b.date&&b.time){if(!['pending','confirmed'].includes(a.status))throw E(400,'لا يمكن تغيير هذا الموعد');
      if(!isDate(b.date)||!slots(b.date,true).all.includes(b.time))throw E(409,'الفترة الجديدة خارج أوقات العمل');
      db.prepare('UPDATE appts SET date=?,time=? WHERE id=?').run(b.date,b.time,id)}
    else throw E(400,'طلب غير صالح');
  }catch(e){throw slotErr(e)}
  return {ok:1}});
route('GET','/api/admin/settings',1,()=>({s:settings(),conflicts:conflicts()}));
route('PUT','/api/admin/settings',1,async(req,b)=>{const o=settings(),S={...o};
  for(const [k,mx] of [['brand',60],['tagline',120],['name',80],['specialty',80],['clinic',80],['address',200],['phone',30],['about',400]])if(k in b)S[k]=str(b[k],0,mx);
  if('days'in b){if(!Array.isArray(b.days)||b.days.some(d=>!(d>=0&&d<=6)))throw E(400,'أيام غير صالحة');S.days=b.days.map(Number)}
  if('start'in b||'end'in b){if(!isTime(b.start)||!isTime(b.end)||m(b.start)>=m(b.end))throw E(400,'ساعات الدوام غير صالحة');S.start=b.start;S.end=b.end}
  if('dur'in b){if(![10,15,20,30,45,60].includes(+b.dur))throw E(400,'مدة غير صالحة');S.dur=+b.dur}
  if('horizon'in b){S.horizon=Math.min(90,Math.max(1,+b.horizon|0))}
  if('breaks'in b){if(!Array.isArray(b.breaks)||b.breaks.some(x=>!isTime(x.s)||!isTime(x.e)||m(x.s)>=m(x.e)))throw E(400,'فترات الراحة غير صالحة');S.breaks=b.breaks.map(x=>({s:x.s,e:x.e}))}
  db.prepare("INSERT INTO kv VALUES('s',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(JSON.stringify(S));
  return {ok:1,conflicts:conflicts()}});
route('GET','/api/admin/ann',1,()=>({rows:db.prepare('SELECT * FROM ann ORDER BY id DESC').all()}));
const annV=b=>[str(b.title,1,100),str(b.body,1,1000),b.active?1:0,b.starts&&isDate(b.starts)?b.starts:null,b.ends&&isDate(b.ends)?b.ends:null];
route('POST','/api/admin/ann',1,async(req,b)=>{db.prepare('INSERT INTO ann(title,body,active,starts,ends) VALUES(?,?,?,?,?)').run(...annV(b));return {ok:1}});
route('PUT','/api/admin/ann/(\\d+)',1,async(req,b,q,id)=>{db.prepare('UPDATE ann SET title=?,body=?,active=?,starts=?,ends=? WHERE id=?').run(...annV(b),id);return {ok:1}});
route('DELETE','/api/admin/ann/(\\d+)',1,(req,b,q,id)=>{db.prepare('DELETE FROM ann WHERE id=?').run(id);return {ok:1}});
route('GET','/api/admin/closures',1,()=>({rows:db.prepare('SELECT * FROM closures ORDER BY date DESC').all()}));
route('POST','/api/admin/closures',1,async(req,b)=>{if(!isDate(b.date))throw E(400,'تاريخ غير صالح');
  const full=!b.from_t&&!b.to_t;if(!full&&(!isTime(b.from_t)||!isTime(b.to_t)||m(b.from_t)>=m(b.to_t)))throw E(400,'الفترة غير صالحة');
  db.prepare('INSERT INTO closures(date,from_t,to_t,note) VALUES(?,?,?,?)').run(b.date,full?null:b.from_t,full?null:b.to_t,str(b.note,0,120));return {ok:1,conflicts:conflicts()}});
route('DELETE','/api/admin/closures/(\\d+)',1,(req,b,q,id)=>{db.prepare('DELETE FROM closures WHERE id=?').run(id);return {ok:1}});
route('POST','/api/admin/password',1,async(req,b)=>{
  const d=db.prepare('SELECT * FROM doctor').get();
  if(!checkPw(String(b.current||''),d.hash))throw E(403,'كلمة المرور الحالية غير صحيحة');
  if(String(b.next||'').length<10)throw E(400,'كلمة المرور الجديدة قصيرة (10 أحرف على الأقل)');
  db.prepare('UPDATE doctor SET hash=?').run(hashPw(b.next));db.prepare('DELETE FROM sessions WHERE t<>?').run(sha(cookie(req,'sid')));return {ok:1}});

/* ---------- الخادم ---------- */
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
const SEC={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
 'Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"};
const send=(res,c,d,h={})=>{res.writeHead(c,{...SEC,...h});res.end(d)};
const json=(res,c,o)=>{const ck=o&&o._cookie;if(ck)delete o._cookie;send(res,c,JSON.stringify(o),{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...(ck?{'Set-Cookie':ck}:{})})};
http.createServer(async(req,res)=>{
  const u=new URL(req.url,'http://x'),q=Object.fromEntries(u.searchParams);
  if(u.pathname.startsWith('/api/')){
    try{
      for(const [M,re,auth,fn] of R){const mt=u.pathname.match(re);if(M!==req.method||!mt)continue;
        if(auth&&!authed(req))throw E(401,'يلزم تسجيل الدخول');
        let b={};if(M!=='GET'&&M!=='DELETE'){if(!/application\/json/.test(req.headers['content-type']||''))throw E(415,'نوع غير مدعوم');b=await body(req)}
        return json(res,200,await fn(req,b,q,...mt.slice(1)))}
      throw E(404,'غير موجود');
    }catch(e){if(!e.code)console.error(e);return json(res,e.code||500,{error:e.code?e.message:'خطأ في الخادم'})}
  }
  const p=u.pathname==='/'?'/index.html':u.pathname==='/doctor'||u.pathname==='/doctor/login'?'/doctor.html':u.pathname;
  const fp=path.join(__dirname,'public',path.normalize(p));
  if(!fp.startsWith(path.join(__dirname,'public'))||!fs.existsSync(fp)||!fs.statSync(fp).isFile())return send(res,404,'غير موجود');
  send(res,200,fs.readFileSync(fp),{'Content-Type':MIME[path.extname(fp)]||'application/octet-stream'});
}).listen(PORT,()=>console.log('Mawidi → http://localhost:'+PORT));
