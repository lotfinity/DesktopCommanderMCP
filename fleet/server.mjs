import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import express from 'express';
import {WebSocketServer} from 'ws';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StreamableHTTPServerTransport} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {ListToolsRequestSchema,CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {Store,digest,secret} from './state.mjs';
import {Router} from './router.mjs';
import {OAuth} from './oauth.mjs';

const root=path.dirname(fileURLToPath(import.meta.url));
export async function start({port=Number(process.env.FLEET_PORT||8800),host=process.env.FLEET_HOST||'127.0.0.1',dir=process.env.FLEET_DATA||path.join(root,'runtime'),base=process.env.FLEET_PUBLIC_URL||''}={}){
 base=base.replace(/\/$/,'');
 const store=new Store(dir),router=new Router(store),oauth=new OAuth(store,base),app=express(),httpServer=http.createServer(app);
 const wsServer=new WebSocketServer({noServer:true,maxPayload:16*1024*1024});
 const failures=new Map();
 const loginTickets=new Map(),adminSessions=new Map();
 const bearer=req=>String(req.headers.authorization||'').replace(/^Bearer /,'');
 app.disable('x-powered-by');
 app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");if(req.path.startsWith('/api')||req.path==='/mcp')res.setHeader('Cache-Control','no-store');next();});
 app.use(express.json({limit:'8mb'}));
 oauth.install(app);
 app.post('/auth/redeem',(req,res)=>{const hash=digest(req.body.ticket||''),expiry=loginTickets.get(hash);if(!expiry||expiry<Date.now())return res.status(403).json({error:'Login link is invalid, expired or already used'});loginTickets.delete(hash);const token=secret();adminSessions.set(digest(token),Date.now()+12*3600000);res.setHeader('Cache-Control','no-store');res.json({token});});
 app.get('/health',(_req,res)=>res.json({ok:true,name:'synaptic-fleet',version:'0.1.0'}));
 app.post('/agent/enroll',(req,res)=>{
  const key=req.socket.remoteAddress, f=failures.get(key)||{count:0,until:Date.now()+60000};
  if(f.until<Date.now()){f.count=0;f.until=Date.now()+60000;}failures.set(key,f);
  if(f.count>=10)return res.status(429).json({error:'Pairing rate limit; retry in a minute'});
  try{res.json(store.enroll(String(req.body.code||''),req.body));}catch(e){f.count++;res.status(403).json({error:e.message});}
 });
 const authPrincipal=req=>{const token=bearer(req);if((adminSessions.get(digest(token))||0)>Date.now())return {id:'owner-session',admin:true,devices:null};return store.principal(token)||oauth.principal(token);};
 app.use(['/api','/mcp'],(req,res,next)=>{req.principal=authPrincipal(req);if(!req.principal){if(base)res.setHeader('WWW-Authenticate',`Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp", scope="fleet:tools"`);return res.status(401).json({error:'Access key required'});}next();});
 const admin=(req,res,next)=>req.principal.admin?next():res.status(403).json({error:'Owner access required'});
 app.post('/api/login-links',admin,(_req,res)=>{for(const [k,v] of loginTickets)if(v<Date.now())loginTickets.delete(k);for(const [k,v] of adminSessions)if(v<Date.now())adminSessions.delete(k);if(loginTickets.size>=100)return res.sendStatus(429);const ticket=secret(),expiresAt=Date.now()+600000;loginTickets.set(digest(ticket),expiresAt);res.json({url:base+'/#ticket='+ticket,expiresAt});});
 app.post('/api/logout',(req,res)=>{adminSessions.delete(digest(bearer(req)));res.json({ok:true});});
 app.get('/api/status',(req,res)=>res.json({version:'0.1.0',admin:req.principal.admin,devices:router.devices(req.principal),endpoint:(base||'')+'/mcp',pending:router.pending.size}));
 app.get('/api/oauth/requests/:id',admin,(req,res)=>{try{res.json(oauth.request(req.params.id));}catch(e){res.status(404).json({error:e.message});}});
 app.post('/api/oauth/requests/:id',admin,(req,res)=>{try{res.json({redirect:oauth.approve(req.params.id,req.body.devices,req.body.allow===true)});}catch(e){res.status(400).json({error:e.message});}});
 app.get('/api/oauth/grants',admin,(_req,res)=>res.json({grants:oauth.grants()}));
 app.delete('/api/oauth/grants/:id',admin,(req,res)=>{const g=Object.hasOwn(store.data.oauthGrants,req.params.id)?store.data.oauthGrants[req.params.id]:null;if(!g)return res.sendStatus(404);g.revoked=true;store.event('oauth_access_revoked',{grantId:g.id});res.json({ok:true});});
 app.get('/api/devices/:id/tools',(req,res)=>{if(!router.allowed(req.principal,req.params.id))return res.sendStatus(403);const d=Object.hasOwn(store.data.devices,req.params.id)?store.data.devices[req.params.id]:null;if(!d||d.revoked)return res.sendStatus(404);res.json({tools:d.tools});});
 app.post('/api/devices/:id/call',async(req,res)=>{try{res.json(await router.call(req.principal,req.params.id,String(req.body.tool||''),req.body.arguments||{}));}catch(e){res.status(400).json({error:e.message});}});
 app.post('/api/enrollments',admin,(req,res)=>{const out=store.enrollment(req.body.name);res.json({...out,server:base});});
 app.patch('/api/devices/:id',admin,(req,res)=>{const d=Object.hasOwn(store.data.devices,req.params.id)?store.data.devices[req.params.id]:null;if(!d)return res.sendStatus(404);if(typeof req.body.name!=='string'||!req.body.name.trim())return res.sendStatus(400);d.name=req.body.name.trim().slice(0,100);store.event('device_renamed',{deviceId:d.id});res.json({ok:true});});
 app.delete('/api/devices/:id',admin,(req,res)=>{try{router.revoke(req.params.id);res.json({ok:true});}catch(e){res.status(404).json({error:e.message});}});
 app.get('/api/activity',(req,res)=>res.json({events:store.data.events.filter(e=>req.principal.admin||(e.deviceId&&router.allowed(req.principal,e.deviceId))).slice(0,100)}));
 app.get('/api/keys',admin,(_req,res)=>res.json({keys:store.publicKeys()}));
 app.post('/api/keys',admin,(req,res)=>{const devices=req.body.devices;if(devices!==null&&(!Array.isArray(devices)||devices.some(id=>!Object.hasOwn(store.data.devices,id)||store.data.devices[id].revoked)))return res.status(400).json({error:'Choose valid device IDs or null for all devices'});res.json(store.key(req.body.name,devices));});
 app.delete('/api/keys/:id',admin,(req,res)=>{const k=Object.hasOwn(store.data.keys,req.params.id)?store.data.keys[req.params.id]:null;if(!k)return res.sendStatus(404);k.revoked=true;store.event('client_key_revoked',{keyId:k.id});res.json({ok:true});});
 const text=x=>({content:[{type:'text',text:JSON.stringify(x,null,2)}]});
 function descriptors(p){
  const result=[{name:'list_devices',description:'List authorized devices, online status and live system information.',inputSchema:{type:'object',properties:{}}},{name:'device_tools',description:'Inspect native MCP tools and argument schemas for a selected device.',inputSchema:{type:'object',properties:{deviceId:{type:'string'}},required:['deviceId']}},{name:'call_device_tool',description:'Call any native MCP tool on an explicitly selected device. Inspect device_tools first. Session IDs belong to the selected device.',inputSchema:{type:'object',properties:{deviceId:{type:'string'},tool:{type:'string'},arguments:{type:'object',additionalProperties:true}},required:['deviceId','tool']}}];
  const seen=new Set();for(const d of router.devices(p))if(!d.revoked)for(const t of store.data.devices[d.id].tools){if(seen.has(t.name))continue;seen.add(t.name);const schema=t.inputSchema||{type:'object'};result.push({name:'dc_'+t.name,description:'Run on the explicit deviceId. '+String(t.description||t.name).slice(0,2000),inputSchema:{...schema,type:'object',properties:{...(schema.properties||{}),deviceId:{type:'string',description:'Target device ID from list_devices'}},required:[...new Set([...(schema.required||[]),'deviceId'])]},annotations:t.annotations});}return result;
 }
 app.post('/mcp',async(req,res)=>{
  const principal=req.principal,server=new Server({name:'synaptic-fleet',version:'0.1.0'},{capabilities:{tools:{}}});
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:descriptors(principal)}));
  server.setRequestHandler(CallToolRequestSchema,async({params})=>{
   try{if(!authPrincipal(req))throw Error('Client key revoked');const a=params.arguments||{};
    if(params.name==='list_devices')return text(router.devices(principal));
    if(params.name==='device_tools'){if(!router.allowed(principal,a.deviceId))throw Error('Device access denied');return text(store.data.devices[a.deviceId]?.tools||[]);}
    if(params.name==='call_device_tool')return await router.call(principal,a.deviceId,a.tool,a.arguments||{});
    if(params.name.startsWith('dc_')){const {deviceId,...args}=a;return await router.call(principal,deviceId,params.name.slice(3),args);}throw Error('Unknown tool');
   }catch(e){return {isError:true,content:[{type:'text',text:e.message}]};}
  });
  const transport=new StreamableHTTPServerTransport({sessionIdGenerator:undefined});
  res.on('close',()=>{transport.close().catch(()=>{});server.close().catch(()=>{});});
  try{await server.connect(transport);await transport.handleRequest(req,res,req.body);}catch(e){if(!res.headersSent)res.status(500).json({error:e.message});}
 });
 app.all('/mcp',(_req,res)=>res.status(405).json({error:'Use Streamable HTTP POST requests'}));
 httpServer.on('upgrade',(req,socket,head)=>{
  let id;try{const url=new URL(req.url,'http://localhost');if(url.pathname!=='/agent/connect')throw Error();id=url.searchParams.get('deviceId');if(!store.deviceAuth(id,bearer(req)))throw Error();}catch{socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');socket.destroy();return;}
  wsServer.handleUpgrade(req,socket,head,ws=>wsServer.emit('connection',ws,id));
 });
 wsServer.on('connection',(ws,id)=>{
  const link=router.attach(id,ws);ws.isAlive=true;const helloTimer=setTimeout(()=>{if(!link.ready)ws.close(4002,'No tool handshake');},30000);
  ws.on('pong',()=>{ws.isAlive=true;});
  ws.on('message',raw=>{try{
   const m=JSON.parse(raw.toString());if(m.type==='hello'){
    if(!Array.isArray(m.tools)||m.tools.length>200)throw Error('Invalid tools');
    const tools=m.tools.filter(t=>t&&/^[a-zA-Z0-9_-]{1,60}$/.test(t.name)&&t.inputSchema?.type==='object').map(t=>({name:t.name,description:String(t.description||'').slice(0,10000),inputSchema:t.inputSchema,...(t.annotations?{annotations:t.annotations}:{})}));
    store.data.devices[id].tools=tools;store.data.devices[id].backend=String(m.backend||'MCP').slice(0,100);store.data.devices[id].lastSeen=new Date().toISOString();store.save();link.ready=true;clearTimeout(helloTimer);
   }else if(m.type==='heartbeat'){link.info=m.info&&typeof m.info==='object'?m.info:{};store.data.devices[id].lastSeen=new Date().toISOString();}
   else if(m.type==='result')router.complete(id,ws,m);
  }catch{ws.close(4002,'Invalid agent message');}});
  ws.on('error',()=>{});ws.on('close',()=>{clearTimeout(helloTimer);router.detach(id,ws);});
 });
 const heartbeat=setInterval(()=>{for(const ws of wsServer.clients){if(!ws.isAlive){ws.terminate();continue;}ws.isAlive=false;ws.ping();}},15000);
 const prune=setInterval(()=>{for(const [k,f] of failures)if(f.until<Date.now())failures.delete(k);},60000);
 app.use(express.static(path.join(root,'public')));
 app.use((err,_req,res,_next)=>res.status(400).json({error:err.type==='entity.too.large'?'Request too large':'Invalid request'}));
 await new Promise(resolve=>httpServer.listen(port,host,resolve));
 return {store,router,oauth,httpServer,address:httpServer.address(),async close(){clearInterval(heartbeat);clearInterval(prune);for(const ws of wsServer.clients)ws.terminate();router.pending.forEach(j=>{clearTimeout(j.timer);j.reject(Error('Gateway stopping'));});await new Promise(r=>httpServer.close(r));}};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const fleet=await start();console.log('Synaptic Fleet listening on '+fleet.address.address+':'+fleet.address.port);
 for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{await fleet.close();process.exit(0);});
}
