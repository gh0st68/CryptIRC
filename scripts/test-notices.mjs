import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import {spawn} from 'node:child_process';

// Regression checks against the real frontend in an isolated browser, with
// synthetic conversations and a simulated history transport. No login or live data.
const root=path.dirname(new URL(import.meta.url).pathname);
const staticRoot=path.resolve(root,'../static');
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
const base='/cryptirc/';
const reset=async(w=1440,h=900,m=false)=>{await load(w,h,m,base);await ev(`mentionsList=[];updateMentionsBadge();_pendingLogs.clear();`);};
const click=async(selector,touch=false)=>{const p=await ev(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);if(touch){await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[p]});await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});}else{await send('Input.dispatchMouseEvent',{type:'mousePressed',...p,button:'left',clickCount:1});await send('Input.dispatchMouseEvent',{type:'mouseReleased',...p,button:'left',clickCount:1});}await sleep(100);};
const seed=`mentionsList=[{type:'mention',conn_id:'preview',target:'#lounge',from:'Alex',text:'ghost, have a look at this',ts:100,network:'TwistedNET'}];updateMentionsBadge();`;
for(const [w,h,m] of [[320,640,true],[390,844,true],[844,390,true],[1440,900,false]]){
 await reset(w,h,m);await ev(seed);await click('#mentions-btn',m);
 const g=await ev(`(()=>{const b=document.getElementById('mentions-btn'),p=document.getElementById('mentions-panel'),h=document.getElementById('topbar');const r=b.getBoundingClientRect(),pr=p.getBoundingClientRect(),hr=h.getBoundingClientRect();return {button:b.tagName,bw:r.width,bh:r.height,open:p.classList.contains('show'),expanded:b.getAttribute('aria-expanded'),below:pr.top>=hr.bottom,inside:pr.x>=0&&pr.right<=innerWidth&&pr.bottom<=innerHeight};})()`);
 ok(w+'px: native accessible button',g.button==='BUTTON'&&g.expanded==='true');
 ok(w+'px: adequate hit target',g.bw>=(m?44:32)&&g.bh>=(m?44:32));
 ok(w+'px: click or tap opens panel',g.open);
 ok(w+'px: panel fits below header',g.below&&g.inside);
 if(w===390||w===1440)await shot('cryptirc-notices-'+w+(base==='/baseline/'?'-before':'-after'));
 await ev(`checkMention('preview','#music','river','ghost: fresh notice',101,true)`);
 ok(w+'px: new notices appear while open',await ev(`document.getElementById('mentions-list').textContent.includes('fresh notice')`));
 await click('#msg-input',m);
 ok(w+'px: outside click closes panel',await ev(`!document.getElementById('mentions-panel').classList.contains('show')&&!_overlayStack.some(x=>x.name==='mentionsPanel')`));
}
await reset();await ev(seed);await click('#search-btn');await click('#mentions-btn');
ok('opening Notices closes Search',await ev(`!document.getElementById('search-panel').classList.contains('show')`));
await ev(`document.getElementById('mentions-btn').focus()`);
await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await sleep(120);
ok('Escape closes and restores button focus',await ev(`!document.getElementById('mentions-panel').classList.contains('show')&&document.activeElement.id==='mentions-btn'`));
await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});await sleep(100);
ok('Enter opens button from keyboard',await ev(`document.getElementById('mentions-panel').classList.contains('show')`));
await reset();await ev(`addPmNotice('preview','Sam',{text:'first message',ts:100,id:100});addPmNotice('preview','sam',{text:'latest message',ts:101,id:101});`);
ok('one PM row updates to latest unread message',await ev(`mentionsList.length===1&&mentionsList[0].text==='latest message'&&mentionsList[0].ts===101`));
await ev(`addPmNotice('preview','Sam',{text:'older arrival',ts:99});`);
ok('late PM cannot replace latest preview',await ev(`mentionsList[0].text==='latest message'`));
await ev(`mentionsList=[];checkMention('preview','#music','ghost','ghost says hello',102,true)`);
ok('own messages do not create unread notices',await ev(`mentionsList.length===0`));
await reset();await ev(seed);await click('#mentions-btn');await ev(`unread.set('preview/#music',4);document.querySelector('#mentions-clear,[onclick=\"clearMentions()\"]')?.click()`);
ok('Clear dismisses notices without deleting chat/unread data',await ev(`mentionsList.length===0&&unread.get('preview/#music')===4&&getBuf('preview','#dev').length>0`));
const rows=`(()=>{const b=getBuf('preview','#dev');b.length=0;for(let i=0;i<100;i++)b.push({id:1000+i,ts:1000+i,from:'Alex',text:'Message '+i,kind:'privmsg'});renderChat();})()`;
await reset();await ev(rows);await ev(`jumpToMessage('preview','#dev',1020,'aLeX')`);await sleep(250);
ok('jump matches sender case-insensitively',await ev(`!!document.querySelector('#chat-area .msg-row.flash[data-ts="1020"]')`));
await reset();await ev(rows);await ev(`getBuf('preview','#dev').push({id:9999,ts:1020,from:'Alex',text:'specific second message',kind:'privmsg'});renderChat();jumpToMessage('preview','#dev',1020,'Alex',{id:9999,text:'specific second message'});`);await sleep(180);
ok('same-second messages select the exact message',await ev(`document.querySelector('#chat-area .msg-row.flash .msg-body')?.textContent==='specific second message'`));
await reset();await ev(rows);await ev(`jumpToMessage('preview','#dev',1020,'Alex')`);await sleep(180);await ev(`renderChat()`);await sleep(100);
await ev(`document.querySelector('#chat-area .msg-row.flash')?.classList.add('no-anim')`);
const flashStyle=await ev(`(()=>{const s=getComputedStyle(document.querySelector('#chat-area .msg-row.flash')||document.body);return {bg:s.backgroundColor,shadow:s.boxShadow};})()`);
ok('highlight is visible with burst/reduced-motion animations disabled',flashStyle.bg!=='rgba(0, 0, 0, 0)');
ok('highlight survives a background chat redraw',await ev(`!!document.querySelector('#chat-area .msg-row.flash[data-ts="1020"]')`));
await reset();await ev(rows);await ev(`const decoy=buildRow({ts:500,from:'Alex',text:'wrong conversation',kind:'privmsg'});document.getElementById('split-chat-area').appendChild(decoy);jumpToMessage('preview','#dev',500,'Alex')`);await sleep(180);
ok('jump never highlights a row in another conversation',await ev(`!document.querySelector('#split-chat-area .flash')`));
await reset();await ev(`window.__originalDecrypt=_decryptLogLines;_decryptLogLines=async(...a)=>{await new Promise(r=>setTimeout(r,350));return __originalDecrypt(...a)};ws={readyState:1,send(raw){const q=JSON.parse(raw);if(q.type==='get_logs')setTimeout(()=>handleEvent({type:'log_lines',conn_id:q.conn_id,target:q.target,lines:q.before?[{id:500,ts:500,from:'Alex',text:'older target',kind:'privmsg'}]:[{id:1000,ts:1000,from:'Alex',text:'latest',kind:'privmsg'}]}),30)}};getBuf('preview','#lounge').length=0;jumpToMessage('preview','#lounge',500,'Alex');`);await sleep(1400);
ok('history jump waits for asynchronous decryption/rendering',await ev(`!!document.querySelector('#chat-area .msg-row.flash[data-ts="500"]')&&_jumpAnchor`));
await reset();await ev(rows);await ev(`ws={readyState:1,send(raw){const q=JSON.parse(raw);if(q.type==='get_logs')setTimeout(()=>handleEvent({type:'log_lines',conn_id:q.conn_id,target:q.target,lines:[{id:500,ts:500,from:'Alex',text:'first jump',kind:'privmsg'}]}),450)}};jumpToMessage('preview','#dev',500,'Alex');`);await sleep(140);await ev(`getBuf('preview','#dev').push({id:1050,ts:1050,from:'Alex',text:'newer selection',kind:'privmsg'});renderChat();jumpToMessage('preview','#dev',1050,'Alex');`);await sleep(700);
ok('latest click wins over an earlier pending jump',await ev(`!!document.querySelector('#chat-area .msg-row.flash[data-ts="1050"]')&&!document.querySelector('#chat-area .msg-row.flash[data-ts="500"]')`));

for(const [w,h,m] of [[390,844,true],[1440,900,false]]){
 await reset(w,h,m);
 await ev(`(()=>{const b=getBuf('preview','#lounge');b.length=0;for(let i=0;i<100;i++)b.push({id:1000+i,ts:1000+i,from:'Alex',text:'Message '+i,kind:'privmsg'});mentionsList=[{type:'mention',conn_id:'preview',target:'#lounge',from:'Alex',text:'Message 20',id:1020,ts:1020,network:'TwistedNET'}];updateMentionsBadge();})()`);
 await click('#mentions-btn',m);await click('.mention-item',m);await sleep(200);
 const landed=()=>ev(`(()=>{const r=document.querySelector('#chat-area .msg-row.flash[data-ts="1020"]'),a=document.getElementById('chat-area');if(!r)return false;const rr=r.getBoundingClientRect(),ar=a.getBoundingClientRect();return active.target==='#lounge'&&rr.top>=ar.top&&rr.bottom<=ar.bottom;})()`);
 ok(w+'px: notice click lands on the correct visible message',await landed());
 ok(w+'px: successful jump dismisses the notice',await ev(`mentionsList.length===0&&!document.getElementById('mentions-panel').classList.contains('show')`));
 await sleep(2100);
 ok(w+'px: delayed auto-scroll cannot pull away from jump',await landed());
 if(w===390)await shot('cryptirc-notice-message-highlight');
}
await reset();await ev(seed);await ev(`jumpToMessage('preview','#lounge',100,'Alex',{text:'ghost, have a look at this',notice:true})`);await sleep(6400);
ok('failed/offline jump preserves notice for retry',await ev(`mentionsList.length===1&&document.getElementById('mentions-btn').classList.contains('has-unread')`));


await reset();await ev(rows);await ev(`jumpToMessage('preview','#dev',1060,'Alex')`);await sleep(180);
await ev(`prependLogs('preview','#dev',Array.from({length:100},(_,i)=>({id:2000+i,ts:800+i,from:'river',text:'earlier history '+i,kind:'privmsg'})))`);await sleep(100);
ok('loading earlier history preserves the exact jumped-to message',await ev(`(()=>{const r=document.querySelector('#chat-area .msg-row[data-ts="1060"]').getBoundingClientRect(),a=document.getElementById('chat-area').getBoundingClientRect();return r.top>=a.top&&r.bottom<=a.bottom;})()`));


await reset();await ev(seed);await click('#mentions-btn');await click('#search-btn');await click('#mentions-btn');
ok('switching popovers transfers one Back entry',await ev(`_overlayStack.length===1&&_overlayStack[0].name==='mentionsPanel'`));
await ev(`history.back()`);await sleep(150);
ok('Back closes Notices without leaving the app',await ev(`location.pathname===${JSON.stringify(base)}&&!document.getElementById('mentions-panel').classList.contains('show')&&document.getElementById('mentions-btn').getAttribute('aria-expanded')==='false'`));
await reset(390,844,true);await ev(`document.documentElement.style.setProperty('--sat','24px');document.documentElement.style.setProperty('--sab','20px');`);await ev(seed);await click('#mentions-btn',true);
ok('safe-area header does not cover the panel',await ev(`document.getElementById('mentions-panel').getBoundingClientRect().top>=document.getElementById('topbar').getBoundingClientRect().bottom`));
await reset();await ev(`getBuf('preview','#lounge').push({id:500,ts:100,from:'Alex',text:'ghost, have a look at this',kind:'privmsg'});`);await ev(seed);await click('#mentions-btn');
const press=await ev(`(()=>{const r=document.querySelector('.mention-item').getBoundingClientRect();return {x:r.x+30,y:r.y+20};})()`);
await send('Input.dispatchMouseEvent',{type:'mousePressed',...press,button:'left',clickCount:1});
await ev(`checkMention('preview','#music','river','ghost: arrives during click',101,true)`);
await send('Input.dispatchMouseEvent',{type:'mouseReleased',...press,button:'left',clickCount:1});await sleep(200);
ok('incoming notice cannot destroy a row during a click',await ev(`active.target==='#lounge'&&!!document.querySelector('#chat-area .msg-row.flash[data-ts="100"]')`));


await reset();await ev(`window.__open=window.open;window.__popup={closed:false,_appShown:false,jumpToMessage(...args){window.__delivered=args}};window.open=url=>{window.__popupUrl=url;return __popup};openDetachedWindow('preview','#popup',{ts:100,from:'Alex',match:{id:42,text:'private locator',notice:true}});setTimeout(()=>__popup._appShown=true,120)`);await sleep(400);
ok('cold pop-out receives exact locator after auth without text in URL',await ev(`__delivered?.[4]?.id===42&&__delivered[4].text==='private locator'&&!__popupUrl.includes('private')`));await ev(`window.open=__open`);


// Some effects accumulate opaque trails. Their canvas must never cover chat text.
for(const [w,h,m] of [[390,844,true],[1440,900,false]]){
 await reset(w,h,m);
 await ev(`applyThemeCSS({...loadAppearance(),theme:'lightning_storm',mobileTheme:''});stopAnimation();const overlay=document.getElementById('anim-overlay');overlay.style.display='none';document.getElementById('chat-area').scrollTop=0;`);
 const clip=await ev(`(()=>{const r=document.querySelector('#chat-area .msg-body').getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,scale:1};})()`);
 const brightPixels=async()=>{
  const png=await send('Page.captureScreenshot',{format:'png',clip});
  return ev(`(async()=>{const img=await createImageBitmap(await (await fetch('data:image/png;base64,${png.data}')).blob());const c=new OffscreenCanvas(img.width,img.height),ctx=c.getContext('2d');ctx.drawImage(img,0,0);const pixels=ctx.getImageData(0,0,c.width,c.height).data;let bright=0;for(let i=0;i<pixels.length;i+=4)if(pixels[i]>180&&pixels[i+1]>180&&pixels[i+2]>180)bright++;return bright;})()`);
 };
 const normal=await brightPixels();
 await ev(`(()=>{const c=document.getElementById('anim-canvas');c.width=innerWidth;c.height=innerHeight;const ctx=c.getContext('2d');ctx.fillStyle='#000';ctx.fillRect(0,0,c.width,c.height);document.getElementById('anim-overlay').style.display='block';})()`);
 const saturated=await brightPixels();
 ok(w+'px: opaque animation trails cannot darken message text',normal>0&&saturated>=normal*.9);
}

ok('no runtime exceptions',errors.length===0);
const result={passed:checks.filter(x=>x.pass).length,total:checks.length,failed:checks.filter(x=>!x.pass),errors};
await fs.writeFile(path.join(temp,'results.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));socket.close();if(result.failed.length)process.exitCode=1;

}finally{chrome.kill();await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
