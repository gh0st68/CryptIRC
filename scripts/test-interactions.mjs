import fs from 'node:fs/promises';
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

const swipe=async(x,y,dy)=>{await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x,y}]});for(let i=1;i<=10;i++){await send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x,y:y+dy*i/10}]});await sleep(16);}await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});await sleep(180);};
const manyChannels=async()=>{await ev(`networks[0].channels=Array.from({length:70},(_,i)=>({name:i===0?'#dev':'#channel-'+i,names:Array.from({length:90},(_,j)=>'user'+j),topic:'Test channel'}));_renderSidebarNow();setActive('preview','#dev');`);await sleep(150);};
for(const [w,h,m] of [[320,640,true],[390,844,true],[768,1024,true],[844,390,true],[1440,900,false]]){
 await load(w,h,m);await manyChannels();
 if(w<=768){await ev('openSidebar()');await sleep(350);}
 const g=await ev(`(()=>{const e=document.getElementById('sidebar-scroll'),r=e.getBoundingClientRect(),x=Math.min(r.right-25,r.x+100),y=r.bottom-40;return {x,y,dy:-Math.min(180,r.height/2),scrolls:e.scrollHeight>e.clientHeight,hit:!!document.elementFromPoint(x,y)?.closest('#sidebar-scroll')};})()`);
 ok(w+'px: long channel list has a scrollable viewport',g.scrolls);
 ok(w+'px: channel list receives touches above backdrop',g.hit);
 if(m){await swipe(g.x,g.y,g.dy);}else{await send('Input.dispatchMouseEvent',{type:'mouseWheel',x:g.x,y:g.y,deltaY:200,deltaX:0});await sleep(150);}
 ok(w+'px: actual input scrolls the channel list',await ev(`document.getElementById('sidebar-scroll').scrollTop>30`));
 ok(w+'px: scrolling neither changes channels nor starts drag',await ev(`active.target==='#dev'&&!_sidebarDragLock`));
 if(w<=768){
  await ev(`closeSidebar();toggleNickPanel()`);await sleep(350);
  const n=await ev(`(()=>{const r=document.getElementById('nick-list').getBoundingClientRect(),x=r.x+r.width/2,y=r.bottom-40;return {x,y,dy:-Math.min(160,r.height/2),hit:!!document.elementFromPoint(x,y)?.closest('#nick-list')};})()`);
  ok(w+'px: user list receives touches above backdrop',n.hit);await swipe(n.x,n.y,n.dy);
  ok(w+'px: actual swipe scrolls the user list',await ev(`document.getElementById('nick-list').scrollTop>30`));
 }
}

const tap=async(selector,touch=true)=>{const p=await ev(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);if(touch){await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[p]});await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});}else{await send('Input.dispatchMouseEvent',{type:'mousePressed',...p,button:'left',clickCount:1});await send('Input.dispatchMouseEvent',{type:'mouseReleased',...p,button:'left',clickCount:1});}await sleep(150);};
const receives=selector=>ev(`(()=>{const e=document.querySelector(${JSON.stringify(selector)}),r=e.getBoundingClientRect();return e.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})()`);
for(const [w,h] of [[320,640],[390,844],[768,1024]]){
 await load(w,h,true);await manyChannels();await ev('openSidebar()');await sleep(350);
 await tap('#sidebar-scroll .chan-item[data-target="#channel-1"]');
 ok(w+'px: tapping a channel selects it and dismisses drawer',await ev(`active.target==='#channel-1'&&!document.getElementById('sidebar').classList.contains('open')`));
 await ev('openSidebar()');await sleep(350);await tap('#settings-gear-btn');
 ok(w+'px: Settings button opens a reachable menu',await ev(`document.getElementById('settings-menu').classList.contains('open')`)&&await receives('#settings-search'));
 // Recreate a root-level install banner overlapping the Settings button. Its
 // existing layer belongs below drawers and menus, not above the entire app.
 await ev(`(()=>{const r=document.getElementById('settings-gear-btn').getBoundingClientRect(),b=document.createElement('div');b.id='audit-banner';b.style.cssText='position:fixed;z-index:40;background:#999;left:'+r.x+'px;top:'+r.y+'px;width:'+r.width+'px;height:'+r.height+'px';document.body.appendChild(b);})()`);
 ok(w+'px: app banner cannot block sidebar controls',await receives('#settings-gear-btn'));
 await ev(`document.getElementById('audit-banner').remove();closeSettingsMenu();`);
 // Tap the real scrim outside the drawer, not a JS-only close call.
 await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x:w-8,y:h/2}]});await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});await sleep(350);
 ok(w+'px: backdrop tap closes the drawer',await ev(`!document.getElementById('sidebar').classList.contains('open')`));
 await ev('showAddNetwork()');await sleep(100);
 ok(w+'px: modal fields remain above app and scrim',await receives('#modal-overlay .form-input'));
 await ev('closeModal()');await sleep(100);
}
for(const theme of ['light','arctic','mirc','hexchat','xchat','irssi','lightning_storm']){
 await load(390,844,true);await manyChannels();await ev(`applyThemeCSS({...loadAppearance(),theme:${JSON.stringify(theme)},mobileTheme:''});openSidebar();`);await sleep(350);
 const g=await ev(`(()=>{const r=document.getElementById('sidebar-scroll').getBoundingClientRect();return {x:r.x+100,y:r.bottom-40};})()`);await swipe(g.x,g.y,-180);
 ok(theme+': touch scrolling works with theme styling',await ev(`document.getElementById('sidebar-scroll').scrollTop>30`));
}
await load(390,430,true);await manyChannels();await ev('openSidebar()');await sleep(350);
const small=await ev(`(()=>{const r=document.getElementById('sidebar-scroll').getBoundingClientRect();return {x:r.x+100,y:r.bottom-20,dy:-Math.min(110,r.height/2)};})()`);await swipe(small.x,small.y,small.dy);
ok('channel list still scrolls in a keyboard-sized viewport',await ev(`document.getElementById('sidebar-scroll').scrollTop>30`));
await load(1440,900,false);await manyChannels();
await tap('#settings-gear-btn',false);ok('desktop settings are reachable',await receives('#settings-search'));
await ev('closeSettingsMenu();showAddNetwork()');ok('desktop modal fields receive input above the app',await receives('#modal-overlay .form-input'));
await ev('closeModal();openFloatDdAt(500,300,[{text:"Synthetic action",action:()=>window.__menuPicked=true}])');await sleep(100);await tap('#float-dropdown button',false);
ok('body-level dropdown remains reachable above app',await ev(`window.__menuPicked===true`));

ok('no runtime exceptions',errors.length===0);
const result={passed:checks.filter(x=>x.pass).length,total:checks.length,failed:checks.filter(x=>!x.pass),errors};console.log(JSON.stringify(result));socket.close();if(result.failed.length)process.exitCode=1;
}finally{chrome.kill();await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
