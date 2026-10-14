#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import WebSocket from 'ws';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const argv=process.argv.slice(2),arg=(name,fallback='')=>{const i=argv.indexOf(name);return i<0?fallback:argv[i+1];};
const configFile=arg('--config',path.join(os.homedir(),'.config','synaptic-fleet','agent.json'));
let config={};if(fs.existsSync(configFile))config=JSON.parse(fs.readFileSync(configFile,'utf8'));
const server=arg('--server',config.server||'').replace(/\/$/,'');
if(!server){console.error('Usage: node agent.mjs --server https://central-host --pair CODE [--backend /path/to/dist/index.js]');process.exit(2);}
const url=new URL(server);if(url.protocol!=='https:'&&!(url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname)))throw Error('Use HTTPS for remote gateways');
const backend=arg('--backend',config.backend||path.join(path.dirname(fileURLToPath(import.meta.url)),'node_modules','@wonderwhy-er','desktop-commander','dist','index.js'));
if(!fs.existsSync(backend))throw Error('Backend not installed at '+backend+'; install DesktopCommanderMCP or specify --backend');
if(arg('--pair')){
 const r=await fetch(server+'/agent/enroll',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code:arg('--pair'),hostname:os.hostname(),platform:process.platform,arch:os.arch()}),signal:AbortSignal.timeout(15000)});
 const out=await r.json();if(!r.ok)throw Error(out.error||'Pairing failed');
 config={server,backend,...out};fs.mkdirSync(path.dirname(configFile),{recursive:true,mode:0o700});fs.writeFileSync(configFile,JSON.stringify(config,null,2),{mode:0o600});console.log('Paired device '+config.deviceId);
}
if(!config.deviceId||!config.token)throw Error('Pair this agent first with --pair CODE');
const backendClient=new Client({name:'synaptic-fleet-agent',version:'0.1.0'},{capabilities:{}});
const transport=new StdioClientTransport({command:process.execPath,args:[backend,'--no-onboarding'],env:{...process.env,DESKTOP_COMMANDER_DISABLE_TELEMETRY:'1'},stderr:'pipe'});
await backendClient.connect(transport);transport.stderr?.on('data',d=>process.stderr.write(d));
let tools=(await backendClient.listTools()).tools,stopping=false,ws=null,active=0,attempt=0;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const info=()=>({hostname:os.hostname(),platform:process.platform,arch:os.arch(),uptime:os.uptime(),freeMem:os.freemem(),totalMem:os.totalmem(),loadAvg:os.loadavg(),agentRss:process.memoryUsage().rss,backendPid:transport.pid,node:process.version});
backendClient.onclose=()=>{if(!stopping){console.error('MCP backend exited; stopping agent so the service manager can restart it');process.exit(1);}};
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{stopping=true;ws?.close();await backendClient.close();process.exit(0);});
while(!stopping){
 const wsUrl=new URL(server+'/agent/connect');wsUrl.protocol=url.protocol==='https:'?'wss:':'ws:';wsUrl.searchParams.set('deviceId',config.deviceId);
 await new Promise(resolve=>{
  ws=new WebSocket(wsUrl,{headers:{authorization:'Bearer '+config.token},handshakeTimeout:15000,maxPayload:16*1024*1024});let heartbeat;
  const send=value=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(value));};
  ws.on('open',()=>{attempt=0;const version=backendClient.getServerVersion();send({type:'hello',tools,backend:version?version.name+' '+version.version:'MCP backend'});send({type:'heartbeat',info:info()});heartbeat=setInterval(()=>send({type:'heartbeat',info:info()}),10000);console.log('Connected to central dashboard as '+config.deviceId);});
  ws.on('message',async raw=>{let m;try{m=JSON.parse(raw.toString());}catch{return;}if(m.type!=='call')return;
   if(active>=8){send({type:'result',id:m.id,error:'Agent busy'});return;}active++;
   try{const result=await backendClient.callTool({name:m.tool,arguments:m.arguments||{}},undefined,{timeout:120000});send({type:'result',id:m.id,result});}catch(e){send({type:'result',id:m.id,error:e.message});}finally{active--;}
  });
  ws.on('error',e=>console.error('Connection:',e.message));
  ws.on('unexpected-response',(_req,res)=>{if(res.statusCode===401){console.error('Device credentials rejected; pair this device again');stopping=true;}res.resume();ws.terminate();});
  ws.on('close',code=>{clearInterval(heartbeat);if(code===4003){console.error('Device revoked; pair again before restarting');stopping=true;}resolve();});
 });
 if(!stopping)await sleep(Math.min(30000,1000*2**Math.min(attempt++,5))+Math.random()*1000);
}
await backendClient.close();
