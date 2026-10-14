import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const digest = token => crypto.createHash('sha256').update(String(token)).digest('hex');
export const secret = () => crypto.randomBytes(32).toString('base64url');
export function equal(a, b) { const x=Buffer.from(String(a)), y=Buffer.from(String(b)); return x.length===y.length && crypto.timingSafeEqual(x,y); }
export class Store {
  constructor(dir) {
    this.dir=dir; fs.mkdirSync(dir,{recursive:true,mode:0o700});
    this.file=path.join(dir,'state.json');
    this.data={devices:{},enrollments:{},keys:{},events:[]};
    if(fs.existsSync(this.file)) this.data=JSON.parse(fs.readFileSync(this.file,'utf8'));
    const keyPath=path.join(dir,'admin-key');
    this.adminKey=fs.existsSync(keyPath)?fs.readFileSync(keyPath,'utf8').trim():secret();
    if(!fs.existsSync(keyPath)) fs.writeFileSync(keyPath,this.adminKey+'\n',{mode:0o600});
  }
  save() { fs.writeFileSync(this.file+'.tmp',JSON.stringify(this.data),{mode:0o600});fs.renameSync(this.file+'.tmp',this.file); }
  event(action, details={}) { this.data.events.unshift({id:crypto.randomUUID(),at:new Date().toISOString(),action,...details});this.data.events=this.data.events.slice(0,500);this.save(); }
  enrollment(name) {
    const code=crypto.randomBytes(16).toString('hex');
    this.data.enrollments[digest(code)]={name:String(name||'New device').slice(0,100),expiresAt:Date.now()+600000};
    for(const [k,v] of Object.entries(this.data.enrollments))if(v.expiresAt<Date.now())delete this.data.enrollments[k];
    this.save();return {code,expiresAt:Date.now()+600000};
  }
  enroll(code, info) {
    const hash=digest(code), e=this.data.enrollments[hash];
    if(!e||e.expiresAt<Date.now())throw Error('Invalid or expired pairing code');
    const id='dev-'+crypto.randomBytes(6).toString('hex'), token=secret();
    this.data.devices[id]={id,name:e.name,hostname:String(info.hostname||'').slice(0,100),platform:String(info.platform||'unknown').slice(0,30),arch:String(info.arch||'').slice(0,30),tokenHash:digest(token),enrolledAt:new Date().toISOString(),revoked:false,tools:[]};
    delete this.data.enrollments[hash];this.event('device_enrolled',{deviceId:id});return {deviceId:id,token};
  }
  deviceAuth(id,token) {const d=Object.hasOwn(this.data.devices,id)?this.data.devices[id]:null;return d&&!d.revoked&&token&&equal(d.tokenHash,digest(token))?d:null;}
  adminAuth(token){return token&&equal(this.adminKey,token);}
  principal(token){if(this.adminAuth(token))return {id:'owner',admin:true,devices:null};for(const k of Object.values(this.data.keys))if(!k.revoked&&equal(k.hash,digest(token)))return {id:k.id,admin:false,devices:k.devices};return null;}
  key(name,devices){const id=crypto.randomUUID(),token=secret();this.data.keys[id]={id,name:String(name||'AI client').slice(0,100),hash:digest(token),devices,createdAt:new Date().toISOString(),revoked:false};this.event('client_key_created',{keyId:id});return {id,token};}
  publicDevices(){return Object.values(this.data.devices).map(({tokenHash,tools,...d})=>({...d,toolCount:tools.length}));}
  publicKeys(){return Object.values(this.data.keys).map(({hash,...k})=>k);}
}
