import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';

const app=express();
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||'CHANGE_ME_BEFORE_PRODUCTION';
const ADMIN_USER=(process.env.ADMIN_USER||'FRD.ALY').toUpperCase();
const ADMIN_PASS=process.env.ADMIN_PASS||'123456';
const db=new Database(process.env.DB_FILE||'yejo.db');

db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,email TEXT UNIQUE,password_hash TEXT NOT NULL,created_at TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS progress(user_id INTEGER PRIMARY KEY,save_json TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);`);
const findUser=db.prepare('SELECT * FROM users WHERE username=?');
const insertUser=db.prepare('INSERT INTO users(username,email,password_hash,created_at,admin) VALUES(?,?,?,?,?)');
const findProgress=db.prepare('SELECT save_json FROM progress WHERE user_id=?');
const upsertProgress=db.prepare('INSERT INTO progress(user_id,save_json,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET save_json=excluded.save_json,updated_at=excluded.updated_at');

function seedAdmin(){let u=findUser.get(ADMIN_USER);if(!u){const hash=bcrypt.hashSync(ADMIN_PASS,12);insertUser.run(ADMIN_USER,null,hash,new Date().toISOString(),1)}}seedAdmin();
function tokenFor(u){return jwt.sign({uid:u.id,username:u.username,admin:!!u.admin},JWT_SECRET,{expiresIn:'30d'})}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'auth_required'});req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{return res.status(401).json({error:'invalid_token'})}}
app.use(helmet({crossOriginResourcePolicy:false}));app.use(cors({origin:true,credentials:true}));app.use(express.json({limit:'256kb'}));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'yejo'}));
app.post('/api/register',(req,res)=>{const username=String(req.body.username||'').trim().toUpperCase();const email=String(req.body.email||'').trim().toLowerCase()||null;const password=String(req.body.password||'');if(!/^[A-Z0-9][A-Z0-9._-]{2,19}$/.test(username))return res.status(400).json({error:'invalid_username'});if(password.length<6)return res.status(400).json({error:'weak_password'});if(username===ADMIN_USER)return res.status(409).json({error:'reserved_username'});if(findUser.get(username))return res.status(409).json({error:'username_taken'});if(email&&db.prepare('SELECT id FROM users WHERE email=?').get(email))return res.status(409).json({error:'email_taken'});const info=insertUser.run(username,email,bcrypt.hashSync(password,12),new Date().toISOString(),0);const u=findUser.get(username);return res.json({token:tokenFor(u),user:{username:u.username,admin:false}})});
app.post('/api/login',(req,res)=>{const username=String(req.body.username||'').trim().toUpperCase(),password=String(req.body.password||'');const u=findUser.get(username);if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'invalid_credentials'});res.json({token:tokenFor(u),user:{username:u.username,admin:!!u.admin}})});
app.get('/api/progress',auth,(req,res)=>{const row=findProgress.get(req.user.uid);res.json({save:row?JSON.parse(row.save_json):null})});
app.put('/api/progress',auth,(req,res)=>{const save=req.body?.save;if(!save||typeof save!=='object')return res.status(400).json({error:'invalid_save'});if(Number(save.unlocked||1)>1500)return res.status(400).json({error:'invalid_level'});upsertProgress.run(req.user.uid,JSON.stringify(save),new Date().toISOString());res.json({ok:true})});
app.get('/api/me',auth,(req,res)=>{const u=db.prepare('SELECT username,email,admin,created_at FROM users WHERE id=?').get(req.user.uid);res.json({user:u})});
app.listen(PORT,()=>console.log(`YEJO API listening on :${PORT}`));
