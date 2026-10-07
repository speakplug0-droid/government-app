const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const root=__dirname, data=path.join(root,'data');
fs.mkdirSync(data,{recursive:true});
const usersFile=path.join(data,'users.json'), sessionsFile=path.join(data,'sessions.json');
if(!fs.existsSync(usersFile)) fs.writeFileSync(usersFile,'[]');
if(!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile,'{}');
const read=f=>JSON.parse(fs.readFileSync(f,'utf8')), write=(f,v)=>fs.writeFileSync(f,JSON.stringify(v,null,2));
const hash=(p,s)=>crypto.scryptSync(p,s,64).toString('hex');
function json(res,code,obj){res.writeHead(code,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*'});res.end(JSON.stringify(obj))}
function body(req){return new Promise((resolve,reject)=>{let d='';req.on('data',c=>d+=c);req.on('end',()=>{try{resolve(d?JSON.parse(d):{})}catch(e){reject(e)}})})}
function token(){return crypto.randomBytes(32).toString('hex')}
function userFrom(req){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return null;const id=read(sessionsFile)[h.slice(7)];return id?read(usersFile).find(u=>u.id===id):null}
const server=http.createServer(async(req,res)=>{
 if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization'});return res.end()}
 try{
  if(req.url==='/api/register'&&req.method==='POST'){
   const b=await body(req), users=read(usersFile), email=String(b.email||'').trim().toLowerCase(), username=String(b.username||'').trim().replace(/^@/,'');
   if(!email||!username||String(b.password||'').length<6)return json(res,400,{error:'Enter username, email and a password of at least 6 characters.'});
   if(users.some(u=>u.email===email))return json(res,409,{error:'Email already registered.'});
   if(users.some(u=>u.username===username))return json(res,409,{error:'Username already taken.'});
   const salt=crypto.randomBytes(16).toString('hex'),u={id:crypto.randomUUID(),username,email,salt,password:hash(b.password,salt),createdAt:new Date().toISOString()};
   users.push(u);write(usersFile,users);const t=token(),s=read(sessionsFile);s[t]=u.id;write(sessionsFile,s);
   return json(res,201,{token:t,user:{id:u.id,username:u.username,email:u.email}});
  }
  if(req.url==='/api/login'&&req.method==='POST'){
   const b=await body(req), email=String(b.email||'').trim().toLowerCase(), users=read(usersFile),u=users.find(x=>x.email===email);
   if(!u||hash(String(b.password||''),u.salt)!==u.password)return json(res,401,{error:'Incorrect email or password.'});
   const t=token(),s=read(sessionsFile);s[t]=u.id;write(sessionsFile,s);return json(res,200,{token:t,user:{id:u.id,username:u.username,email:u.email}});
  }
  if(req.url==='/api/me'&&req.method==='GET'){const u=userFrom(req);return u?json(res,200,{user:{id:u.id,username:u.username,email:u.email}}):json(res,401,{error:'Not signed in.'})}
  if(req.url==='/api/logout'&&req.method==='POST'){const h=req.headers.authorization||'',s=read(sessionsFile);if(h.startsWith('Bearer '))delete s[h.slice(7)];write(sessionsFile,s);return json(res,200,{ok:true})}
  if(req.url==='/api/health')return json(res,200,{ok:true});
  let p=req.url.split('?')[0];if(p==='/')p='/index.html';const file=path.join(root,p.replace(/^\//,''));if(!file.startsWith(root)||!fs.existsSync(file))return json(res,404,{error:'Not found'});
  const ext=path.extname(file),types={'.html':'text/html','.js':'text/javascript','.css':'text/css'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});fs.createReadStream(file).pipe(res);
 }catch(e){json(res,500,{error:'Server error'})}
});
server.listen(process.env.PORT||10000,'0.0.0.0');
