import fs from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {spawn} from 'node:child_process';

// Regression checks against the real frontend in an isolated browser, with
// synthetic conversations and a simulated history transport. No login or live data.
const root=path.dirname(new URL(import.meta.url).pathname);
const staticRoot=process.env.CRYPTIRC_TEST_STATIC||path.resolve(root,'../static');
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-notices-'));
const out=temp;
const server=http.createServer(async(req,res)=>{
 try{
  const u=new URL(req.url,'http://localhost');
  if(u.pathname.endsWith('/auth/status')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({registration:'closed',captcha_enabled:false}));return;}
  const file=path.resolve(staticRoot,u.pathname.replace(/^\/cryptirc\//,'')||'index.html');
  if(!file.startsWith(staticRoot+'/')){res.writeHead(403).end();return;}
  let data=await fs.readFile(file);
  if(file.endsWith('app.js'))data=Buffer.from(data.toString().replaceAll('__CRYPTIRC_VERSION__','test').replaceAll('__CRYPTIRC_BUILD__','test'));
  res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.svg':'image/svg+xml','.json':'application/json','.ttf':'font/ttf','.otf':'font/otf'})[path.extname(file)]||'application/octet-stream');res.end(data);
 }catch{res.writeHead(404).end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
const chrome=spawn(process.env.CHROMIUM||'/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0','--user-data-dir='+temp+'/profile','--no-first-run','about:blank'],{stdio:'ignore'});
chrome.on('error',e=>console.error('Chromium:',e.message));
try{
 let cdpPort;
 for(let n=0;n<100;n++){
  try{cdpPort=Number((await fs.readFile(temp+'/profile/DevToolsActivePort','utf8')).split('\n')[0]);break;}catch{await new Promise(r=>setTimeout(r,100));}
 }
 if(!cdpPort)throw new Error('Chromium did not start; set CHROMIUM to its executable path.');
 const targets=await (await fetch('http://127.0.0.1:'+cdpPort+'/json')).json();
const socket=new WebSocket(targets.find(x=>x.type==='page').webSocketDebuggerUrl);
await new Promise(r=>socket.onopen=r);
let id=0;const pending=new Map(),errors=[];
socket.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(m.error):p.resolve(m.result);}if(m.method==='Runtime.exceptionThrown') errors.push(m.params.exceptionDetails);};
const send=(method,params={})=>new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});socket.send(JSON.stringify({id:n,method,params}));});
const ev=async(expression)=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
await send('Runtime.enable');await send('Page.enable');await send('Network.enable');
await send('Network.setBypassServiceWorker',{bypass:true});
await send('Network.setBlockedURLs',{urls:['https://*','wss://*']});
const fixture=`(()=>{
 document.getElementById('auth-screen').style.display='none';
 ['boot-splash','vault-overlay'].forEach(id=>{const e=document.getElementById(id);if(e)e.remove();});
 document.getElementById('app').style.display='flex';
 currentUser='demo';
 networks.length=0;networks.push({config:{id:'preview',label:'TwistedNET',host:'irc.example.test',port:6697,nickname:'ghost',auto_join:['#dev','#lounge','#music']},nick:'ghost',connected:true,registered:true,channels:[{name:'#dev',names:['@ghost','@Alex','+sushi','Maya','nipsey','pr3dicament','river','Sam'],topic:'Development, ideas, and good company.'},{name:'#lounge',names:['Alex','river'],topic:'Take a seat.'},{name:'#music',names:['Maya'],topic:'What are you listening to?'}]});
 applyThemeCSS({...loadAppearance(),theme:'arctic'});
 setActive('preview','#dev');
 const rows=[['Alex','Morning everyone 👋'],['ghost','Hey! Working on a few finishing touches today.'],['sushi','The little details make a difference.'],['Maya','Especially on a phone. A little breathing room goes a long way.'],['nipsey','Agreed. Keep the IRC feel though.'],['ghost','Absolutely. Same channels, same conversations.'],['river','Nice. Looking forward to it!']];
 for(let i=0;i<24;i++){const [from,text]=rows[i%rows.length];addMessage('preview','#dev',{ts:Math.floor(Date.now()/1000)-1440+i*60,from,text,kind:'privmsg',id:100+i});}
 unread.set('preview/#lounge',4);renderSidebar();
 document.getElementById('msg-input').disabled=false;
 document.getElementById('msg-input').placeholder='Message #dev as ghost…';
 document.getElementById('lag-mobile').dataset.empty='0';document.getElementById('lag-mobile-val').textContent='34ms';
 document.getElementById('lag-mobile-dot').classList.add('good');
 scrollForce();return true;
})()`;
const load=async(width,height,mobile,url='/cryptirc/')=>{
 await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile});
 await send('Emulation.setTouchEmulationEnabled',{enabled:mobile,maxTouchPoints:1});
 await send('Emulation.setEmulatedMedia',{features:[{name:'hover',value:mobile?'none':'hover'},{name:'pointer',value:mobile?'coarse':'fine'},{name:'prefers-reduced-motion',value:'reduce'}]});
 await send('Page.navigate',{url:'http://127.0.0.1:'+port+url});
 for(let i=0;i<80;i++){await sleep(100);if(await ev(`typeof setActive==='function' && document.readyState==='complete'`))break;}
 await ev(fixture);await sleep(350);
};
const shot=async(name)=>{const r=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(out,name+'.png'),Buffer.from(r.data,'base64'));};
const geometry=()=>ev(`(()=>{const rect=id=>{const r=document.getElementById(id).getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height,right:r.right,bottom:r.bottom};};return {viewport:[innerWidth,innerHeight],pageWidth:document.documentElement.scrollWidth,input:rect('input-inner'),text:rect('msg-input'),send:rect('send-btn'),topbar:rect('topbar'),chat:rect('chat-area'),sidebar:rect('sidebar'),nick:rect('nick-panel')};})()`);

const checks=[];const ok=(name,value)=>{checks.push({name,pass:!!value});if(!value)console.error('FAIL:',name);};

// Browser-side delivery uses a fake notification surface, never the real OS.
const prepare=async()=>{await load(1440,900,false);await ev(`(()=>{
 window.__notifications=[];window.__presence=[];
 Object.defineProperty(window,'Notification',{configurable:true,value:class Notification{static permission='granted';constructor(){throw new TypeError('Use ServiceWorkerRegistration.showNotification()');}}});
 swRegistration={showNotification:async(title,options)=>__notifications.push({title,options})};pushSubscription={endpoint:'https://push.example.test/synthetic'};_notifPrefs={enabled:true};
 window.__focus=true;window.__hidden=false;document.hasFocus=()=>__focus;
 Object.defineProperty(document,'hidden',{configurable:true,get:()=>__hidden});
 ws={readyState:1,send:raw=>__presence.push(JSON.parse(raw))};_isIdle=false;
 playNotifSound=()=>{};
 const cfg=loadAppearance();cfg.desktopNotif=true;localStorage.setItem('cryptirc_appearance',JSON.stringify(cfg));
 localStorage.removeItem('cryptirc_dnd');localStorage.setItem('cryptirc_muted','{}');
 })()`);};
const pm=(from='Alex',target='Alex',id=500)=>`addMessage('preview',${JSON.stringify(target)},{id:${id},ts:100,from:${JSON.stringify(from)},text:'hello from a private conversation',kind:'privmsg'});`;
await prepare();await ev(pm());await sleep(60);
ok('foreground unread PM uses mobile-compatible persistent notification API',await ev(`__notifications.length===1&&__notifications[0].title==='DM from Alex'&&__notifications[0].options.data.target==='Alex'&&__notifications[0].options.data.ts===100`));
ok('local PM and Web Push use one conversation notification tag',await ev(`__notifications[0].options.tag==='cryptirc:preview:Alex'`));
await prepare();await ev(`setActive('preview','Alex');`);await ev(pm());await sleep(60);
ok('reading the focused PM does not alert',await ev(`__notifications.length===0`));
await prepare();await ev(`__hidden=true;__focus=false;document.dispatchEvent(new Event('visibilitychange'));`);
ok('backgrounding reports idle immediately without waiting for a timer',await ev(`_isIdle&&__presence.some(x=>x.type==='idle')`));
await ev(`document.dispatchEvent(new Event('mousemove'));`);
ok('queued input cannot reactivate a hidden page',await ev(`_isIdle&&!__presence.some(x=>x.type==='active')`));
await ev(pm());await sleep(60);
ok('background PM leaves delivery to Web Push without a duplicate local alert',await ev(`__notifications.length===0`));
await ev(`__hidden=false;__focus=true;window.dispatchEvent(new Event('focus'));`);
ok('returning to the app restores active presence',await ev(`!_isIdle&&__presence.some(x=>x.type==='active')`));
await prepare();await ev(`__focus=false;window.dispatchEvent(new Event('blur'));`);
ok('unfocused desktop window becomes push-eligible immediately',await ev(`_isIdle&&__presence.some(x=>x.type==='idle')`));

await prepare();await ev(`setActive('preview','Alex');__hidden=true;__focus=false;pushSubscription=null;window.dispatchEvent(new Event('blur'));`);await ev(pm());await sleep(60);
ok('background open PM has a local fallback without a push subscription',await ev(`__notifications.length===1`));
await prepare();await ev(`setActive('preview','Alex');__hidden=true;__focus=false;window.electronAPI={isElectron:true,showNotification:(title,body,meta)=>__notifications.push({title,body,meta})};window.dispatchEvent(new Event('blur'));`);await ev(pm());await sleep(60);
ok('minimized Electron app still alerts for its open PM',await ev(`__notifications.length===1&&__notifications[0].meta.target==='Alex'`));
await prepare();await ev(`setActive('preview','Alex');_isIdle=true;`);await ev(pm());await sleep(60);
ok('idle focused app does not silently lose PM alerts',await ev(`__notifications.length===1`));
await prepare();await ev(`localStorage.setItem('cryptirc_muted',JSON.stringify({'preview/Alex':true}));`);await ev(pm());await sleep(60);
ok('muted PM does not alert',await ev(`__notifications.length===0`));
await prepare();await ev(`localStorage.setItem('cryptirc_dnd','1');`);await ev(pm());await sleep(60);
ok('Do Not Disturb still suppresses PM alerts',await ev(`__notifications.length===0`));
await prepare();await ev(pm('ghost','Alex'));await sleep(60);
ok('own PM echo does not alert',await ev(`__notifications.length===0`));
await prepare();await ev(pm());await sleep(60);
await ev(`navigator.serviceWorker.dispatchEvent(new MessageEvent('message',{data:{type:'notification_click',...__notifications[0].options.data}}));`);await sleep(150);
ok('persistent PM notification opens and highlights the right conversation',await ev(`active.target==='Alex'&&!!document.querySelector('#chat-area .msg-row.flash[data-ts="100"]')`));
await prepare();await ev(`delete window.Notification;`);await ev(pm());await sleep(60);
ok('browsers without Notification API do not throw',true);

await prepare();await ev(`Object.defineProperty(window,'Notification',{configurable:true,value:class Notification{static permission='granted';constructor(title,options){__notifications.push({title,options});}close(){}}});swRegistration.showNotification=async()=>{throw new Error('No active service worker');};`);await ev(pm());await sleep(60);
ok('desktop notification falls back if service worker is not ready',await ev(`__notifications.length===1`));

// Exercise the actual service worker handlers with synthetic clients and payloads.
const handlers=new Map(),shown=[],messages=[],focused=[],opened=[];
let windows=[];
const cache={put:async()=>{},match:async()=>null,delete:async()=>true};
const worker={location:{origin:'https://example.test'},addEventListener:(name,fn)=>handlers.set(name,fn),
 clients:{matchAll:async()=>windows,openWindow:async url=>opened.push(url)},
 registration:{showNotification:async(title,options)=>shown.push({title,options})}};
vm.runInNewContext(await fs.readFile(path.join(staticRoot,'sw.js'),'utf8'),{self:worker,URL,Response,Request,caches:{open:async()=>cache},console,setTimeout,clearTimeout});
const windowClient=(url,visible,isFocused)=>({url,visibilityState:visible?'visible':'hidden',focused:isFocused,postMessage:data=>messages.push(data),focus:async()=>focused.push(url)});
const push=async(clients)=>{windows=clients;shown.length=0;let work;handlers.get('push')({data:{json:()=>({title:'DM from Alex',body:'synthetic test',conn_id:'preview',target:'Alex',from:'Alex',ts:100})},waitUntil:p=>work=p});await work;};
await push([]);ok('closed app shows PM push',shown.length===1);
await push([windowClient('https://example.test/cryptirc/',false,false)]);ok('hidden app shows PM push',shown.length===1);
await push([windowClient('https://example.test/cryptirc/',true,false)]);ok('visible but unfocused desktop app shows PM push',shown.length===1);
await push([windowClient('https://example.test/other-app/',true,true)]);ok('unrelated same-origin page cannot suppress PM push',shown.length===1);
await push([windowClient('https://example.test/cryptirc/',true,true)]);ok('focused app handles its own foreground alerts',shown.length===0);
windows=[windowClient('https://example.test/other-app/',true,true)];let work;
handlers.get('notificationclick')({action:'open',notification:{close(){},data:{url:'https://example.test/cryptirc/',conn_id:'net/one',target:'Alex/name',ts:100,from:'Alex'}},waitUntil:p=>work=p});await work;
const url=new URL(opened.at(-1));ok('push click opens app with separately encoded PM locator',url.pathname==='/cryptirc/'&&url.searchParams.get('conn')==='net/one'&&url.searchParams.get('target')==='Alex/name'&&messages.length===0);
windows=[windowClient('https://example.test/cryptirc/',false,false)];
handlers.get('notificationclick')({action:'open',notification:{close(){},data:{url:'https://example.test/cryptirc/',conn_id:'preview',target:'Alex',ts:100,from:'Alex'}},waitUntil:p=>work=p});await work;
ok('push click focuses existing app and sends PM locator',focused.length===1&&messages.at(-1).target==='Alex');
ok('no browser runtime exceptions',errors.length===0);
const result={passed:checks.filter(x=>x.pass).length,total:checks.length,failed:checks.filter(x=>!x.pass),errors};
console.log(JSON.stringify(result));socket.close();if(result.failed.length)process.exitCode=1;
}finally{chrome.kill();await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
