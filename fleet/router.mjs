import crypto from 'node:crypto';
export class Router {
  constructor(store){this.store=store;this.links=new Map();this.pending=new Map();}
  allowed(p,id){return p&&(p.admin||p.devices===null||p.devices.includes(id));}
  devices(p){return this.store.publicDevices().filter(d=>this.allowed(p,d.id)).map(d=>({...d,online:!d.revoked&&!!this.links.get(d.id)?.ready,info:this.links.get(d.id)?.info||{},lastSeen:this.store.data.devices[d.id].lastSeen||null}));}
  attach(id,ws){const old=this.links.get(id);if(old)old.ws.close(4001,'Replaced by new connection');this.fail(id,'Device reconnected; outstanding calls have an unknown outcome');const link={ws,info:{},ready:false};this.links.set(id,link);this.store.event('device_connected',{deviceId:id});return link;}
  detach(id,ws){if(this.links.get(id)?.ws!==ws)return;this.links.delete(id);this.fail(id,'Device disconnected; call outcome may be unknown. Calls are never replayed automatically.');this.store.event('device_disconnected',{deviceId:id});}
  fail(id,message){for(const [key,j] of this.pending)if(j.deviceId===id){clearTimeout(j.timer);this.pending.delete(key);j.reject(Error(message));}}
  complete(id,ws,msg){const j=this.pending.get(msg.id);if(!j||j.deviceId!==id||j.ws!==ws)return false;clearTimeout(j.timer);this.pending.delete(msg.id);if(msg.error)j.reject(Error(String(msg.error).slice(0,2000)));else j.resolve(msg.result);return true;}
  async call(p,id,tool,args={},timeout=120000){
    if(!this.allowed(p,id))throw Error('Device access denied');
    const device=this.store.data.devices[id],link=this.links.get(id);
    if(!device||device.revoked||!link?.ready)throw Error('Device is offline');
    if(!device.tools.some(t=>t.name===tool))throw Error('Tool is unavailable on this device');
    if([...this.pending.values()].filter(j=>j.deviceId===id).length>=8)throw Error('Device is busy (8 calls in flight)');
    const requestId=crypto.randomUUID(), start=Date.now();
    this.store.event('tool_started',{deviceId:id,tool,principal:p.id,requestId});
    try{
      const result=await new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{this.pending.delete(requestId);reject(Error('Call timed out; outcome may be unknown. No automatic replay.'));},Math.min(Math.max(timeout,100),120000));
        this.pending.set(requestId,{deviceId:id,ws:link.ws,timer,resolve,reject});
        try{link.ws.send(JSON.stringify({type:'call',id:requestId,tool,arguments:args}));}catch(e){clearTimeout(timer);this.pending.delete(requestId);reject(e);}
      });
      if(!result||!Array.isArray(result.content))throw Error('Invalid MCP result from agent');
      this.store.event('tool_finished',{deviceId:id,tool,principal:p.id,requestId,ms:Date.now()-start,ok:!result.isError});return result;
    }catch(e){this.store.event('tool_failed',{deviceId:id,tool,principal:p.id,requestId,ms:Date.now()-start,error:e.message});throw e;}
  }
  revoke(id){const d=Object.hasOwn(this.store.data.devices,id)?this.store.data.devices[id]:null;if(!d)throw Error('Unknown device');d.revoked=true;this.store.event('device_revoked',{deviceId:id});this.links.get(id)?.ws.close(4003,'Device revoked');this.fail(id,'Device revoked');}
}
