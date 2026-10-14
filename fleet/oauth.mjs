import crypto from 'node:crypto';
import express from 'express';
import {digest,equal,secret} from './state.mjs';
export class OAuth {
 constructor(store,base){this.store=store;this.base=base.replace(/\/$/,'');this.requests=new Map();this.registrations=new Map();this.codes=new Map();store.data.oauthClients||={};store.data.oauthGrants||={};}
 get resource(){return this.base+'/mcp';}
 prune(){for(const map of [this.requests,this.codes])for(const [k,v] of map)if(v.expiresAt<Date.now())map.delete(k);}
 register(body){
  const uris=body.redirect_uris;if(!Array.isArray(uris)||!uris.length||uris.length>10)throw Error('redirect_uris required');
  for(const uri of uris){const u=new URL(uri);if(u.hash||u.username||u.password||!(u.protocol==='https:'||(u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname))))throw Error('HTTPS redirect URI required (localhost HTTP allowed)');}
  if(Object.keys(this.store.data.oauthClients).length>=500)throw Error('Client registration limit reached');
  if(body.token_endpoint_auth_method&&body.token_endpoint_auth_method!=='none')throw Error('Only public clients with PKCE supported');
  const id=crypto.randomUUID(),client={client_id:id,client_name:String(body.client_name||'MCP client').slice(0,100),redirect_uris:uris,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],client_id_issued_at:Math.floor(Date.now()/1000)};
  this.store.data.oauthClients[id]=client;this.store.save();return client;
 }
 authorize(query){
  this.prune();const c=Object.hasOwn(this.store.data.oauthClients,query.client_id)?this.store.data.oauthClients[query.client_id]:null;
  if(!c||!c.redirect_uris.includes(query.redirect_uri))throw Error('Unknown client or redirect URI');
  if(query.response_type!=='code'||query.code_challenge_method!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(query.code_challenge||''))throw Error('Authorization code with PKCE S256 required');
  if(query.resource!==this.resource)throw Error('Invalid resource');
  if(query.scope&&query.scope!=='fleet:tools')throw Error('Invalid scope');
  if(this.requests.size>=200)throw Error('Too many authorization requests');
  const id=secret();this.requests.set(id,{id,clientId:c.client_id,clientName:c.client_name,redirectUri:query.redirect_uri,state:String(query.state||'').slice(0,2000),challenge:query.code_challenge,expiresAt:Date.now()+600000});return id;
 }
 request(id){this.prune();const r=this.requests.get(id);if(!r)throw Error('Authorization request expired');const {challenge,...out}=r;return out;}
 approve(id,devices,allow){
  const r=this.request(id),full=this.requests.get(id);const redirect=new URL(r.redirectUri);if(r.state)redirect.searchParams.set('state',r.state);
  if(!allow){this.requests.delete(id);redirect.searchParams.set('error','access_denied');return redirect.toString();}
  if(devices!==null&&(!Array.isArray(devices)||devices.some(id=>!Object.hasOwn(this.store.data.devices,id)||this.store.data.devices[id].revoked)))throw Error('Invalid device selection');
  this.requests.delete(id);const code=secret();this.codes.set(digest(code),{...full,devices,expiresAt:Date.now()+60000});redirect.searchParams.set('code',code);return redirect.toString();
 }
 issue(clientId,devices,grantId=null){
  const access=secret(),refresh=secret(),id=grantId||crypto.randomUUID();
  this.store.data.oauthGrants[id]={id,clientId,devices,accessHash:digest(access),refreshHash:digest(refresh),accessExpires:Date.now()+3600000,refreshExpires:Date.now()+30*86400000,revoked:false};this.store.event('oauth_access_granted',{grantId:id,clientId});
  return {access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope:'fleet:tools'};
 }
 token(body){
  this.prune();if(body.resource!==this.resource)throw Error('Invalid resource');if(!Object.hasOwn(this.store.data.oauthClients,body.client_id))throw Error('Unknown client');
  if(body.grant_type==='authorization_code'){
   const hash=digest(body.code),c=this.codes.get(hash);if(!c||c.clientId!==body.client_id||c.redirectUri!==body.redirect_uri||!/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier||''))throw Error('Invalid authorization code');
   const challenge=crypto.createHash('sha256').update(body.code_verifier).digest('base64url');if(!equal(c.challenge,challenge))throw Error('Invalid PKCE verifier');this.codes.delete(hash);return this.issue(c.clientId,c.devices);
  }
  if(body.grant_type==='refresh_token'){
   const g=Object.values(this.store.data.oauthGrants).find(g=>!g.revoked&&g.clientId===body.client_id&&g.refreshExpires>Date.now()&&equal(g.refreshHash,digest(body.refresh_token)));if(!g)throw Error('Invalid refresh token');return this.issue(g.clientId,g.devices,g.id);
  }throw Error('Unsupported grant type');
 }
 principal(token){const g=Object.values(this.store.data.oauthGrants).find(g=>!g.revoked&&g.accessExpires>Date.now()&&equal(g.accessHash,digest(token)));return g?{id:'oauth:'+g.id,admin:false,devices:g.devices}:null;}
 grants(){return Object.values(this.store.data.oauthGrants).map(({accessHash,refreshHash,...g})=>({...g,clientName:this.store.data.oauthClients[g.clientId]?.client_name||'MCP client'}));}
 install(app){
  if(!this.base)return;
  const cors=(req,res,next)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Cache-Control','no-store');if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Headers','content-type');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');return res.sendStatus(204);}next();};app.use(['/.well-known','/oauth/register','/oauth/token'],cors);
  app.get(['/.well-known/oauth-protected-resource','/.well-known/oauth-protected-resource/mcp'],(_req,res)=>res.json({resource:this.resource,authorization_servers:[this.base],scopes_supported:['fleet:tools'],bearer_methods_supported:['header']}));
  app.get('/.well-known/oauth-authorization-server',(_req,res)=>res.json({issuer:this.base,authorization_endpoint:this.base+'/oauth/authorize',token_endpoint:this.base+'/oauth/token',registration_endpoint:this.base+'/oauth/register',response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],token_endpoint_auth_methods_supported:['none'],code_challenge_methods_supported:['S256'],scopes_supported:['fleet:tools']}));
  app.post('/oauth/register',(req,res)=>{try{for(const [ip,r] of this.registrations)if(r.until<Date.now())this.registrations.delete(ip);const ip=req.socket.remoteAddress,rate=this.registrations.get(ip)||{count:0,until:Date.now()+600000};this.registrations.set(ip,rate);if(++rate.count>20)return res.status(429).json({error:'registration_rate_limit'});res.status(201).json(this.register(req.body));}catch(e){res.status(400).json({error:'invalid_client_metadata',error_description:e.message});}});
  app.get('/oauth/authorize',(req,res)=>{try{res.redirect('/?authorize='+encodeURIComponent(this.authorize(req.query)));}catch(e){res.status(400).json({error:'invalid_request',error_description:e.message});}});
  app.post('/oauth/token',express.urlencoded({extended:false,limit:'16kb'}),(req,res)=>{try{res.json(this.token(req.body));}catch(e){res.status(400).json({error:'invalid_grant',error_description:e.message});}});
 }
}
