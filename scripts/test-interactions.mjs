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
  if(file.endsWith('/app.js')){
   const controls=await fs.readFile(path.join(staticRoot,'page-controls.js'),'utf8');
   const reactions=await fs.readFile(path.join(staticRoot,'reactions.js'),'utf8');
   data=Buffer.from((controls+'\n'+reactions+'\n'+data.toString()).replaceAll('__CRYPTIRC_VERSION__','test').replaceAll('__CRYPTIRC_BUILD__','test'));
  }
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
const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});socket.send(JSON.stringify({id:n,method,params,sessionId}));});
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
 const previousDocument=await ev('performance.timeOrigin');
 await send('Page.navigate',{url:'http://127.0.0.1:'+port+url});
 // The async auth check shows the login screen after DOMContentLoaded.
 for(let i=0;i<80;i++){
  await sleep(100);
  if(await ev(`performance.timeOrigin!==${previousDocument} && document.readyState==='complete' &&
    document.getElementById('auth-screen')?.style.display==='flex'`)){
   await ev(fixture);await sleep(350);return;
  }
 }
 throw new Error('App did not finish its initial auth check');
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
await load(320,640,true);
await ev(`applyThemeCSS({...loadAppearance(),sidebarW:360,nickPanelW:320});openSidebar();`);
await sleep(350);
ok('phone drawer width is independent of the saved desktop width',await ev(`
 Math.abs(document.getElementById('sidebar').getBoundingClientRect().width-innerWidth*.8)<1`));
await ev('closeSidebar()');await sleep(350);
const drawerState=()=>ev(`(()=>{const n=document.getElementById('sidebar');
 return {open:n.classList.contains('open'),right:n.getBoundingClientRect().right};})()`);
const beginPhoneSwipe=async(x1,x2,y=330)=>{
 await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[{x:x1,y}]});
 await send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[{x:x2,y}]});
 await sleep(350);
};
const endPhoneSwipe=async()=>{
 await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
 await sleep(350);
};
await beginPhoneSwipe(16,100);
ok('dragging from the edge keeps the phone drawer in place until release',(await drawerState()).right<1);
await send('Input.dispatchTouchEvent',{type:'touchCancel',touchPoints:[]});await sleep(350);
ok('a cancelled swipe leaves the phone drawer fully closed',(await drawerState()).right<1);
await swipe(16,330,-140);
ok('vertical scrolling from the edge leaves the drawer closed',!(await drawerState()).open);
// Put nicks in the edge zone, then select a visible nick by hit testing.
await ev("document.querySelectorAll('#chat-area .msg-ts').forEach(n=>n.style.display='none')");
const edgeNickPoint=()=>ev(`(()=>{
 for(const nick of document.querySelectorAll('#chat-area .msg-nick[data-nick]')){
  const rect=nick.getBoundingClientRect();
  const x=Math.ceil(rect.left+2),y=Math.floor(rect.top+rect.height/2);
  if(x>0&&x<40&&document.elementFromPoint(x,y)?.closest('.msg-nick')===nick)return {x,y};
 }
 return null;
})()`);
const swipeNick=await edgeNickPoint();
if(!swipeNick)throw new Error('No visible message nick in the edge zone');
await beginPhoneSwipe(swipeNick.x,swipeNick.x+84,swipeNick.y);await endPhoneSwipe();
ok('a completed horizontal edge swipe still opens the phone drawer',(await drawerState()).open);
ok('an edge swipe over a message does not open a nick menu',await ev("!document.querySelector('.nick-ctx-overlay')"));
await beginPhoneSwipe(210,120);await endPhoneSwipe();
ok('a completed swipe left still closes the phone drawer',!(await drawerState()).open);
const nickDrawerOpen=()=>ev("document.getElementById('nick-panel').classList.contains('open')");
await beginPhoneSwipe(304,220);await endPhoneSwipe();
ok('a completed right-edge swipe still opens the user list',await nickDrawerOpen());
ok('phone user-list width is independent of the saved desktop width',await ev(`
 Math.abs(document.getElementById('nick-panel').getBoundingClientRect().width-innerWidth*.55)<1`));
await beginPhoneSwipe(220,304);await endPhoneSwipe();
ok('a completed swipe right still closes the user list',!await nickDrawerOpen());
const tapNick=await edgeNickPoint();
if(!tapNick)throw new Error('No visible message nick to tap');
await send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[tapNick]});
await send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
ok('a plain tap on that message nick still opens its menu',await ev("!!document.querySelector('.nick-ctx-overlay')"));

const browserUserAgent=await ev('navigator.userAgent');
await send('Emulation.setUserAgentOverride',{userAgent:'iPhone test'});
await load(844,390,true);
const landscapeResize=await ev(`(()=>{
 const previous=loadAppearance(), cfg={...previous,sidebarW:320};
 saveAppearance(cfg);applyThemeCSS(cfg);
 const handle=document.getElementById('rz-sidebarW');
 const drag=pointerType=>{
  handle.dispatchEvent(new PointerEvent('pointerdown',{pointerType,pointerId:1,button:0,clientX:220}));
  document.dispatchEvent(new PointerEvent('pointermove',{pointerType,pointerId:1,clientX:270}));
  document.dispatchEvent(new PointerEvent('pointerup',{pointerType,pointerId:1,clientX:270}));
 };
 drag('touch');
 const touchDragLocked=loadAppearance().sidebarW===cfg.sidebarW;
 handle.dispatchEvent(new MouseEvent('dblclick'));
 const touchResetLocked=loadAppearance().sidebarW===cfg.sidebarW;
 drag('mouse');
 const mouseDragWorks=loadAppearance().sidebarW!==cfg.sidebarW;
 handle.dispatchEvent(new MouseEvent('dblclick'));
 const defaultWidth=RZ_DEFS.find(d=>d.key==='sidebarW').def;
 const mouseResetWorks=defaultWidth!==cfg.sidebarW&&loadAppearance().sidebarW===defaultWidth;
 saveAppearance(previous);applyThemeCSS(previous);
 return {landscape:_IS_IOS&&innerWidth>768,touchDragLocked,touchResetLocked,mouseDragWorks,mouseResetWorks};
})()`);
ok('landscape iPhone touch drag and double-tap leave the saved width alone',
 landscapeResize.landscape&&landscapeResize.touchDragLocked&&landscapeResize.touchResetLocked);
ok('a mouse can still drag and reset the width in a wide layout',
 landscapeResize.mouseDragWorks&&landscapeResize.mouseResetWorks);
await send('Emulation.setUserAgentOverride',{userAgent:browserUserAgent});

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

// Exercise the actual message composer rather than a generic settings input.
await load(1440,900,false);
const composerBox=()=>ev(`['input-wrap','input-inner','msg-input','send-btn','chat-area'].map(id=>{
 const {x,y,width,height}=document.getElementById(id).getBoundingClientRect();
 return [x,y,width,height];
})`);
for(const theme of ['arctic','light','mirc','hexchat','xchat','irssi']){
 await ev(`document.getElementById('msg-input').blur();applyThemeCSS({...loadAppearance(),theme:${JSON.stringify(theme)},mobileTheme:''});`);
 await sleep(250);
 const before=await composerBox();
 await tap('#msg-input',false);
 await sleep(1050);
 const after=await composerBox();
 ok(theme+': desktop click keeps composer and viewport geometry unchanged',JSON.stringify(before)===JSON.stringify(after));
 ok(theme+': desktop composer keeps focus',await ev("document.activeElement.id==='msg-input'"));
}

for(const mobile of [false,true]){
 await load(mobile?390:1440,mobile?844:900,mobile);
 await tap('#msg-input',mobile);
 const platform=mobile?'mobile':'desktop';
 ok(platform+': composer has no credential form or field name',await ev(`(()=>{
  const e=document.getElementById('msg-input');
  return e.tagName==='TEXTAREA' && !e.form && !e.name && e.rows===1 &&
   e.autocomplete==='off' && e.hasAttribute('data-1p-ignore') &&
   e.getAttribute('data-lpignore')==='true' && e.hasAttribute('data-bwignore') &&
   e.getAttribute('data-protonpass-ignore')==='true' && e.getAttribute('inputmode')==='text' &&
   e.getAttribute('enterkeyhint')==='send' &&
   document.getElementById('l-user').autocomplete==='username' &&
   document.getElementById('l-pass').autocomplete==='current-password';
 })()`));
 await ev(`window.composerSent=[];window.originalHandleInput=handleInput;handleInput=async text=>{composerSent.push(text);};`);
 await send('Input.insertText',{text:'Typed message 😺'});
 await ev(`document.getElementById('msg-input').dispatchEvent(new KeyboardEvent('keydown',{
  key:'Enter',bubbles:true,cancelable:true,isComposing:true
 }))`);
 ok(platform+': IME commit does not send a chat message',await ev("composerSent.length===0 && document.getElementById('msg-input').value==='Typed message 😺'"));
 if(mobile){
  await ev(`document.getElementById('msg-input').dispatchEvent(new InputEvent('beforeinput',{
   inputType:'insertLineBreak',bubbles:true,cancelable:true
  }))`);
 } else {
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 }
 ok(platform+': sends exactly once and clears the line',await ev("composerSent.length===1 && composerSent[0]==='Typed message 😺' && !document.getElementById('msg-input').value"));
 await send('Input.insertText',{text:'one\ntwo'});
 ok(platform+': multi-line input stays a single chat line',await ev("document.getElementById('msg-input').value==='onetwo'"));
 await ev("handleInput=originalHandleInput;document.getElementById('msg-input').value='';");
}

await load(1440,900,false);
await ev(`(()=>{
 const time=Date.now()/1000-1000;
 for(const [target,base] of [['#dev',1000],['#lounge',2000],['Maya',3000]]){
  buffers[bk('preview',target)]=Array.from({length:180},(_,i)=>({
   id:base+i,ts:time+i,from:'Alex',text:target+' message '+i,kind:'privmsg'
  }));
 }
 setActive('preview','#dev');scrollForce();
})()`);
await sleep(220);
const scrollUp=async(deltaY)=>{
 const {chat}=await geometry();
 await send('Input.dispatchMouseEvent',{type:'mouseWheel',x:chat.x+chat.w/2,y:chat.y+chat.h/2,deltaX:0,deltaY});
 await sleep(240);
};
const snapshot=()=>ev("captureChatPosition(document.getElementById('chat-area'))");
const sameRow=(a,b)=>a&&b&&a.id===b.id&&Math.abs(a.offset-b.offset)<=2;
await scrollUp(-80);
const dev=await snapshot();
ok('short desktop scroll detaches from the live tail',dev&&await ev('_userScrolledAway'));
await ev("setActive('preview','Maya')");
await sleep(220);
await scrollUp(-510);
const dm=await snapshot();
await ev("setActive('preview','#lounge')");
await sleep(220);
await scrollUp(-280);
const lounge=await snapshot();
await ev(`addMessage('preview','#dev',{id:1400,ts:Date.now()/1000,from:'Sam',text:'new while away',kind:'privmsg'});
 setActive('preview','#dev');`);
ok('channel restores the same message and offset after new traffic',sameRow(dev,await snapshot()));
await ev("renderChat()");
ok('background re-render preserves the restored message and offset',sameRow(dev,await snapshot()));
await ev("setActive('preview','Maya')");
ok('DM restores its own position independently',sameRow(dm,await snapshot()));
await ev("setActive('preview','#lounge')");
ok('another channel retains a third position',sameRow(lounge,await snapshot()));
await ev(`(async()=>{
 const current=getBuf('preview','#lounge')[0].ts;
 await prependLogs('preview','#lounge',Array.from({length:30},(_,i)=>({
  id:600+i,ts:current-100+i,from:'Alex',text:'past '+i,kind:'privmsg'
 })));
})()`);
ok('loading older messages preserves the content in view',sameRow(lounge,await snapshot()));
await ev("_enterHistoryView('preview','#lounge');setActive('preview','#dev');setActive('preview','#lounge');");
ok('a historical window survives switching away and back',await ev("_historyView?.target==='#lounge'")&&sameRow(lounge,await snapshot()));
await ev("_historyView=null;scrollForce();setActive('preview','Maya');setActive('preview','#lounge');");
ok('returning to the bottom restores ordinary live following',await ev("!_userScrolledAway&&_isNearBottom(document.getElementById('chat-area'),8)"));
const signalEcho=await ev(`(async()=>{
 const connId='preview',from=getNick(connId),text='same message on two devices';
 const ts=Math.floor(Date.now()/1000), wire=label=>'[e2edm2]'+btoa(label);
 const local=wire('local'), sibling=wire('sibling'), continuation=wire('continuation');
 const reference=await hashChatReactionReference(local);
 const read=e2eReadDmHistory, wasReady=E2E.keyReady, oldSent=window._sentMsgs;
 const network=networks.find(n=>n.config.id===connId), hadReactions=network.reactions;
 const optimistic=()=>({ts,from,text,kind:'privmsg',own:true,encrypted:true,_dmHistoryWire:local,_dmHistoryState:'ready'});
 const line=(id,wire)=>({id,ts,from,text:wire,kind:'privmsg'});
 const echo=async(target,id,wire)=>{
  handleEvent({type:'irc_echo',conn_id:connId,target,msg_id:id,ts,from,text:wire,kind:'Privmsg'});
  await _e2eQueues.get(connId+'\\n'+target.toLowerCase());
 };
 const hasReaction=async row=>{
  for(let attempt=0;!row.reactionRef&&attempt<30;attempt++) await new Promise(resolve=>setTimeout(resolve,5));
  return row.reactionRef===reference;
 };
 const findings={};
 try{
  E2E.keyReady=true; network.reactions=true; window._sentMsgs=[];
  // Both authenticated wires open to the same text. Exercise the real live
  // and history reconciliation without assuming an IRC echo arrival order.
  e2eReadDmHistory=async(_conn,_target,lines)=>new Map(lines.filter(l=>e2eIsDmHistoryWire(l.text)).map(l=>[l,text]));
  for(const [i,method] of [echo,prependLogs,appendSyncLines].entries()){
   const peer='SignalFixture'+i, own=optimistic();
   const buf=getBuf(connId,peer);
   buf.push(own);
   const deliver=(id,ciphertext)=> i===0 ? method(peer,id,ciphertext) : method(connId,peer,[line(id,ciphertext)]);
   await deliver(5001,sibling);
   const both=buf.length===2&&!own.id&&buf.some(row=>row.id===5001&&row._dmHistoryWire===sibling);
   await deliver(5002,local);
   findings[i]=both&&buf.length===2&&own.id===5002&&await hasReaction(own);
   await deliver(5003,local);
   findings['dedup'+i]=buf.length===2&&own.id===5002;
  }
  const chunkPeer='SignalChunkFixture', first=optimistic(), other={ts,from,text:'unrelated draft',kind:'privmsg',own:true};
  getBuf(connId,chunkPeer).push(first,other);
  window._sentMsgs=[
   {t:Date.now(),conn:connId,target:chunkPeer,text:continuation},
   {t:Date.now(),conn:connId,target:chunkPeer,text:local,row:first},
  ];
  await echo(chunkPeer,5004,continuation);
  findings.chunk= !first.id&&!other.id&&getBuf(connId,chunkPeer).length===2;
  await echo(chunkPeer,5005,local);
  findings.tracked=first.id===5005&&await hasReaction(first);
  const plainPeer='PlainSignalFixture', signal=optimistic();
  getBuf(connId,plainPeer).push(signal);
  await echo(plainPeer,5006,text);
  findings.plain=!signal.id&&getBuf(connId,plainPeer).some(row=>row.id===5006&&!row.encrypted);
  return findings;
 }finally{
  e2eReadDmHistory=read;
  E2E.keyReady=wasReady;
  network.reactions=hadReactions;
  window._sentMsgs=oldSent;
 }
})()`);
ok('live sibling Signal echo matches only its exact wire',signalEcho[0]&&signalEcho.dedup0);
ok('paged Signal history matches only its exact wire',signalEcho[1]&&signalEcho.dedup1);
ok('synced Signal tail matches only its exact wire',signalEcho[2]&&signalEcho.dedup2);
ok('only the first tracked Signal chunk stamps its exact row',signalEcho.chunk&&signalEcho.tracked);
ok('a plaintext echo cannot claim an optimistic Signal row',signalEcho.plain);
await ev(`(()=>{
 const cid='preview', target='FixtureHeld', key=_e2eDmKey(target,cid);
 const input=document.getElementById('msg-input'), state=E2E.state;
 const original={view:active,input:input.value,user:currentUser,state,ready:E2E.keyReady,
   known:E2E._krReceived,resync:E2E._resyncPending,refresh:_e2eRefreshAccountState,read:_e2eRequestSession,decode:_e2eDecodeState,
   queue:_queueChatParts,translate:translateOutgoing,repair:new Map(E2E._sessionSyncRepair)};
 const sent=[], translations=[];
 Object.assign(E2E,{keyReady:true,_krReceived:true,_resyncPending:false,state:{dm:{},ch:{},trust:{}}});
 _e2eRequestSession=async(slot,floor,...rest)=>slot==='__state__' ? {blob:'fixture-held-settings'} :
   slot===key&&floor ? {blob:'',floor_blob:''} : original.read(slot,floor,...rest);
 _e2eDecodeState=async blob=>blob==='fixture-held-settings' ? {dm:{[key]:{on:0,n:2,closedEpoch:2}},trust:{}} : original.decode(blob);
 _e2eRefreshAccountState=async()=>{ E2E.state.dm[key]={on:0,n:2,closedEpoch:2}; return true; };
 _queueChatParts=(c,t,parts)=>sent.push({c,t,parts});
 translateOutgoing=async value=>{ translations.push(value); return value; };
 setActive(cid,target);
 window.fixtureHeldDraft={cid,target,key,input,sent,translations,original};
})()`);
const heldDraft=await ev(`(async()=>{
 const {cid,target,key,input,sent,translations,original}=fixtureHeldDraft;
 const draft='First Signal draft', edited='Corrected Signal draft with another word';
 input.value=draft;
 const hold=(await handleInput(input.value))==='keep'&&E2E._sessionSyncRepair.has(key)&&!sent.length;
 // Device lock discards the repair map. Unlock reloads the authenticated off state.
 E2E._sessionSyncRepair.clear();
 E2E.keyReady=false;
 const locked=(await handleInput(input.value))==='keep'&&input.value===draft&&!sent.length;
 E2E.keyReady=true;
 input.value=edited;
 const unlocked=e2eTargetState(target,{conn_id:cid}).mode==='none'&&
   (await handleInput(input.value))==='keep'&&input.value===edited&&!sent.length;
 const privateEdit=_histLocal.has(edited)&&!translations.includes(edited);
 const save=async()=>{
  await _saveReloadDraft(active,input.value);
  _reloadDraft=JSON.parse(sessionStorage.getItem('cryptirc_reload_draft'));
  _heldSignalDraft=null;
  input.value='';
  _restoreReloadDraft(cid,target);
  for(let i=0;_reloadDraft&&i<20;i++) await new Promise(resolve=>setTimeout(resolve,10));
 };
 await save();
 const scope=!_signalHeldDraftFor('another-network',target)&&!_signalHeldDraftFor(cid,'AnotherTarget');
 const reloaded=input.value===edited&&!!_signalHeldDraftFor(cid,target)&&
   (await handleInput(input.value))==='keep'&&!sent.length;
 const slashEdits=['/me '+edited,'/say '+edited,'/msg '+target+' '+edited,
   '/notice '+target+' '+edited,'/q '+target+' '+edited,'/msg '+target+',AnotherTarget '+edited];
 let commandsHeld=true;
 for(const command of slashEdits){
  input.value=command;
  commandsHeld=await handleInput(command)==='keep'&&commandsHeld&&!sent.length;
 }
 input.value=edited;
 const originalHold=_heldSignalDraft;
 _heldSignalDraft={...originalHold,target:'dan|Work'};
 const aliasMatch=!!_signalHeldDraftFor(cid,'Dan|work');
 _releaseHeldSignalDraft(cid,'DAN|WORK');
 const aliasRelease=!_heldSignalDraft;
 _heldSignalDraft=originalHold;
 setActive(cid,'#dev');
 const crossView=(await handleInput(input.value))==='keep'&&!sent.length;
 await _saveReloadDraft(active,input.value);
 const fromAnotherView=JSON.parse(sessionStorage.getItem('cryptirc_reload_draft'));
 const originalDestination=fromAnotherView.g===target&&fromAnotherView.c===cid&&!!fromAnotherView.heldFor;
 setActive(cid,target);
 await _saveReloadDraft(active,input.value);
 const record=sessionStorage.getItem('cryptirc_reload_draft');
 _reloadDraft=JSON.parse(record);
 _heldSignalDraft=null;
 input.value='';
 currentUser='other-fixture-account';
 _restoreReloadDraft(cid,target);
 for(let i=0;_reloadDraft&&i<20;i++) await new Promise(resolve=>setTimeout(resolve,10));
 const differentAccount=!_reloadDraft&&!input.value&&!_signalHeldDraftFor(cid,target);
 currentUser=original.user;
 sessionStorage.setItem('cryptirc_reload_draft',record);
 _reloadDraft=JSON.parse(record);
 _restoreReloadDraft(cid,target);
 for(let i=0;_reloadDraft&&i<20;i++) await new Promise(resolve=>setTimeout(resolve,10));
 input.focus();input.select();
 return {hold,locked,unlocked,privateEdit,reloaded,scope,differentAccount,commandsHeld,aliasMatch,aliasRelease,crossView,originalDestination};
})()`);
await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
const freshDraft=await ev(`(async()=>{
 const {cid,target,input,sent,original}=fixtureHeldDraft;
 try{
  if(input.value||_signalHeldDraftFor(cid,target)) return false;
  input.value='An ordinary new draft';
  return (await handleInput(input.value))!=='keep'&&sent.length===1&&
   sent[0].c===cid&&sent[0].t===target&&!sent[0].parts[0].encrypted;
 }finally{
  currentUser=original.user;
  Object.assign(E2E,{state:original.state,keyReady:original.ready,_krReceived:original.known,
    _resyncPending:original.resync,_sessionSyncRepair:original.repair});
  _e2eRefreshAccountState=original.refresh;
  _e2eRequestSession=original.read;
  _e2eDecodeState=original.decode;
  _queueChatParts=original.queue;
  translateOutgoing=original.translate;
  _heldSignalDraft=null;
  _reloadDraft=null;
  sessionStorage.removeItem('cryptirc_reload_draft');
  setActive(original.view.conn_id,original.view.target);
  input.value=original.input;
  delete window.fixtureHeldDraft;
 }
})()`);
ok('a Signal draft held after a sibling disables it stays held after lock, unlock and edits',heldDraft.hold&&heldDraft.locked&&heldDraft.unlocked);
ok('an edited held Signal draft stays out of synced input history and translation',heldDraft.privateEdit);
ok('an update reload restores the hold only to the same account, network and peer',heldDraft.reloaded&&heldDraft.scope&&heldDraft.differentAccount);
ok('editing a held DM into an action, chat command or multi-target message keeps the draft local',heldDraft.commandsHeld);
ok('case changes in IRC nicks with punctuation preserve and release the original hold',heldDraft.aliasMatch&&heldDraft.aliasRelease);
ok('switching views cannot send or save a held draft to another chat',heldDraft.crossView&&heldDraft.originalDestination);
ok('clearing the held composer deliberately lets an ordinary fresh draft send afterward',freshDraft);
const namedStatus=await ev(`(async()=>{
 const cid='preview',nick='status',alias=_dmTarget(nick),key=_e2eDmKey(nick,cid),text='Draft to the IRC user named status';
 const flags={keyReady:E2E.keyReady,_krReceived:E2E._krReceived,_resyncPending:E2E._resyncPending,
   state:E2E.state,_serverHints:E2E._serverHints,_sessionSyncRepair:E2E._sessionSyncRepair};
 const original={view:active,held:_heldSignalDraft,read:_e2eRequestSession,translate:translateOutgoing,queue:_queueChatParts};
 let translations=0,sends=0;
 try{
  Object.assign(E2E,{keyReady:true,_krReceived:true,_resyncPending:false,state:_e2eEmptyState(),
    _serverHints:{peers:[],channels:[]},_sessionSyncRepair:new Map()});
  E2E.state.dm[key]={on:0,n:2,closedEpoch:4};
  _e2eRequestSession=async(slot,floor)=>slot===key&&floor?{blob:'saved opaque fixture',floor_blob:''}:null;
  translateOutgoing=async raw=>{translations++;return raw;};_queueChatParts=()=>{sends++;};
  setActive(cid,'status');await handleInput('server window text');await handleInput('/query status');
  const resolved=active.target===alias&&e2eSignalOptOutKey(alias,cid)===key;
  const retained=await handleInput(text)==='keep'&&!!_signalHeldDraftFor(cid,alias)&&!_signalHeldDraftFor(cid,'status');
  _releaseHeldSignalDraft(cid,nick);
  return resolved&&retained&&!_heldSignalDraft&&!translations&&!sends&&_histLocal.has(text)&&!_histSyncOk.has(text);
 }finally{
  Object.assign(E2E,flags);_e2eRequestSession=original.read;translateOutgoing=original.translate;_queueChatParts=original.queue;
  _heldSignalDraft=original.held;setActive(original.view.conn_id,original.view.target);
 }
})()`);
ok('a held draft to the IRC user named status stays in its private query and out of translation and synced history',namedStatus);
const siblingOffDraft=await ev(`(async()=>{
 const cid='preview', activePeer='FixtureStillInstalled', emptyPeer='FixtureDraftOptOut';
 const activeKey=_e2eDmKey(activePeer,cid), emptyKey=_e2eDmKey(emptyPeer,cid);
 const input=document.getElementById('msg-input'), sent=[], translated=[];
 const flags={keyReady:E2E.keyReady,_krReceived:E2E._krReceived,_resyncPending:E2E._resyncPending,
   state:E2E.state,_sessionSyncRepair:E2E._sessionSyncRepair};
 const original={flags,view:active,value:input.value,refresh:_e2eRefreshAccountState,send:_queueChatParts,
   translate:translateOutgoing,read:_e2eRequestSession,decode:_e2eDecodeState,historyIdx};
 window.fixtureOffDraft={cid,emptyPeer,emptyKey,input,sent,translated,original};
 Object.assign(E2E,{keyReady:true,_krReceived:true,_resyncPending:false,state:_e2eEmptyState(),_sessionSyncRepair:new Map()});
 _e2eRequestSession=async(slot,floor,...rest)=>slot==='__state__' ? {blob:'fixture-off-settings'} :
   [emptyKey,activeKey].includes(slot)&&floor ? {blob:'',floor_blob:''} : original.read(slot,floor,...rest);
 _e2eDecodeState=async blob=>blob==='fixture-off-settings' ? {dm:{[activeKey]:{on:0,n:2},[emptyKey]:{on:0,n:2}},trust:{}} : original.decode(blob);
 _e2eRefreshAccountState=async()=>{E2E.state.dm[emptyKey]={on:0,n:2,closedEpoch:8};return true;};
 _queueChatParts=(c,t,parts)=>sent.push({c,t,parts});
 translateOutgoing=async raw=>{translated.push(raw);return raw;};
 const session={RK:'fixture root',CKs:'fixture send chain',startEph:'previous offer',epoch:7};
 E2E.dmSessions[activeKey]=session;
 E2E.state.dm[activeKey]={on:0,n:2,closedEpoch:8};
 setActive(cid,activePeer);
 const text='Draft for a disabled but still installed Signal session';
 input.value=text;
 const held=await handleInput(input.value)==='keep'&&_signalHeldDraftFor(cid,activePeer)&&
   E2E.dmSessions[activeKey]===session&&!E2E._sessionSyncRepair.has(activeKey)&&E2E.lastBlockReason.includes('/encrypt on '+activePeer);
 // A lock and subsequent reopen can remove that stale ratchet while the draft stays in the composer.
 E2E.keyReady=false;
 delete E2E.dmSessions[activeKey];
 const afterLock=await handleInput(input.value)==='keep'&&input.value===text&&sent.length===0;
 E2E.keyReady=true;
 const afterUnlock=e2eTargetState(activePeer,{conn_id:cid}).mode==='none'&&await handleInput(input.value)==='keep'&&sent.length===0;
 _heldSignalDraft=null;
 setActive(cid,emptyPeer);
 input.value='Draft held while checking the account opt-out';
 const noSession=await handleInput(input.value)==='keep'&&!!_signalHeldDraftFor(cid,emptyPeer)&&E2E._sessionSyncRepair.has(emptyKey);
 historyIdx=-1;
 input.focus();
 return {held:!!held,afterLock,afterUnlock,noSession};
})()`);
await send('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
await send('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
const clearedOffDraft=await ev(`(async()=>{
 const {cid,emptyPeer,emptyKey,input,sent,translated}=fixtureOffDraft;
 const discarded=!input.value&&!_signalHeldDraftFor(cid,emptyPeer)&&!E2E._sessionSyncRepair.has(emptyKey);
 const text='Fresh cleartext after discarding the old draft';
 input.value=text;
 const sentFresh=await handleInput(text)!=='keep'&&sent.length===1&&sent[0].t===emptyPeer&&
   !sent[0].parts[0].encrypted&&translated.includes(text);
 // A real repair can also have an empty server revision and must survive a draft clear.
 E2E._sessionSyncRepair.set(emptyKey,'');
 const held='New draft while an independent repair is still required';
 input.value=held;
 const blocked=await handleInput(held)==='keep'&&_histLocal.has(held)&&!_histSyncOk.has(held)&&!translated.includes(held);
 input.focus();input.select();
 return {discarded,sentFresh,blocked};
})()`);
await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Backspace',code:'Backspace',windowsVirtualKeyCode:8});
const keptRepair=await ev(`(async()=>{
 const {cid,emptyPeer,emptyKey,input,sent,translated,original}=fixtureOffDraft;
 try{
  if(input.value||_signalHeldDraftFor(cid,emptyPeer)||E2E._sessionSyncRepair.get(emptyKey)!=='') return false;
  const text='Fresh draft with an independent repair still blocking';
  input.value=text;
  return await handleInput(text)==='keep'&&sent.length===1&&!translated.includes(text)&&_histLocal.has(text)&&!_histSyncOk.has(text);
 }finally{
  Object.assign(E2E,original.flags);
  _e2eRefreshAccountState=original.refresh;
  _e2eRequestSession=original.read;
  _e2eDecodeState=original.decode;
  _queueChatParts=original.send;
  translateOutgoing=original.translate;
  _heldSignalDraft=null;
  historyIdx=original.historyIdx;
  setActive(original.view.conn_id,original.view.target);
  input.value=original.value;
  delete window.fixtureOffDraft;
 }
})()`);
ok('another device turning Signal off holds a draft while its previous ratchet is still installed',
 siblingOffDraft.held&&siblingOffDraft.afterLock&&siblingOffDraft.afterUnlock);
ok('trusted ArrowDown clears the opt-out hold so a deliberately fresh draft can send',
 siblingOffDraft.noSession&&clearedOffDraft.discarded&&clearedOffDraft.sentFresh);
ok('clearing a draft preserves a genuine empty-revision repair and keeps new blocked drafts private',
 clearedOffDraft.blocked&&keptRepair);
await ev(`(()=>{
 const cid='preview', input=document.getElementById('msg-input'), sent=[];
 const flags={keyReady:E2E.keyReady,identityReady:E2E.identityReady,_krReceived:E2E._krReceived,
   _resyncPending:E2E._resyncPending,state:E2E.state,_sessionSyncRepair:E2E._sessionSyncRepair};
 const original={flags,view:active,value:input.value,parts:_queueChatParts,wire:_queueChatSend,encrypt:e2eEncryptOutgoing};
 Object.assign(E2E,{keyReady:true,identityReady:true,_krReceived:true,_resyncPending:false,state:_e2eEmptyState(),_sessionSyncRepair:new Map()});
 _queueChatParts=(c,t,parts,kind)=>sent.push({c,t,kind,encrypted:parts.every(p=>p.encrypted)});
 _queueChatSend=(p,row)=>sent.push({t:p.raw.split(' ')[1],encrypted:!!row.encrypted});
 const installed={RK:'fixture root',CKs:'fixture chain',startEph:'fixture old offer',epoch:7};
 const setOff=(nick,view,raw)=>{
  const key=_e2eDmKey(nick,cid);
  E2E.state.dm[key]={on:0,n:2,closedEpoch:8};
  E2E.dmSessions[key]=installed;
  _heldSignalDraft=null;
  historyIdx=-1;
  setActive(cid,view);
  input.value=raw;input.focus();
  E2E.lastBlockReason=null;
  return key;
 };
 window.fixtureSlashDraft={cid,input,sent,installed,setOff,original};
 fixtureSlashDraft.action='/me action retained for Signal';
 fixtureSlashDraft.a=setOff('FixtureSlashAction','FixtureSlashAction',fixtureSlashDraft.action);
})()`);
const pressDraftKey=async(key,code)=>{
 await send('Input.dispatchKeyEvent',{type:'keyDown',key,code:key,windowsVirtualKeyCode:code});
 await send('Input.dispatchKeyEvent',{type:'keyUp',key,code:key,windowsVirtualKeyCode:code});
};
const waitDraft=async expression=>{
 for(let n=0;n<35;n++){if(await ev(expression))return true;await sleep(50);}
 return false;
};
await pressDraftKey('Enter',13);
await waitDraft("E2E.lastBlockReason?.includes('/encrypt on FixtureSlashAction')");
const firstActionHeld=await ev(`(()=>{
 const {cid,input,sent,a,action}=fixtureSlashDraft;
 const held=input.value===action&&!!_signalHeldDraftFor(cid,'FixtureSlashAction')&&!sent.length;
 E2E.keyReady=false;delete E2E.dmSessions[a];E2E.keyReady=true;
 return held;
})()`);
await pressDraftKey('ArrowDown',40);
const clearedAction=await ev(`!fixtureSlashDraft.input.value&&!_signalHeldDraftFor('preview','FixtureSlashAction')`);
await pressDraftKey('ArrowUp',38);
const recalledAction=await ev(`fixtureSlashDraft.input.value===fixtureSlashDraft.action&&!!_signalHeldDraftFor('preview','FixtureSlashAction')`);
await pressDraftKey('Enter',13);
await sleep(120);
const recalledActionSafe=await ev(`!fixtureSlashDraft.sent.length&&fixtureSlashDraft.input.value===fixtureSlashDraft.action`);
await ev(`(()=>{
 const {setOff}=fixtureSlashDraft;
 fixtureSlashDraft.msg='/msg FixtureSlashMessage text retained for Signal';
 fixtureSlashDraft.b=setOff('FixtureSlashMessage','#dev',fixtureSlashDraft.msg);
})()`);
const submitDraftButton=async()=>{
 const button=await ev(`(()=>{const r=document.getElementById('send-btn').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
 await send('Input.dispatchMouseEvent',{type:'mousePressed',...button,button:'left',clickCount:1});
 await send('Input.dispatchMouseEvent',{type:'mouseReleased',...button,button:'left',clickCount:1});
 await waitDraft('!_sendLock');
};
await submitDraftButton();
const firstMessageHeld=await ev(`(()=>{
 const {cid,input,sent,msg,b}=fixtureSlashDraft;
 const held=input.value===msg&&!!_signalHeldDraftFor(cid,'FixtureSlashMessage')&&!sent.some(e=>e.t==='FixtureSlashMessage');
 E2E.keyReady=false;delete E2E.dmSessions[b];E2E.keyReady=true;
 input.value='/msg #dev text retained for Signal';
 return held;
})()`);
await submitDraftButton();
const readdressedSafe=await ev(`!fixtureSlashDraft.sent.some(e=>e.t==='#dev')&&fixtureSlashDraft.input.value.startsWith('/msg #dev ')`);
await ev(`(()=>{
 const {b,msg,input,installed,original}=fixtureSlashDraft;
 E2E.state.dm[b]={on:1,n:3,closedEpoch:8};E2E.dmSessions[b]=installed;
 e2eEncryptOutgoing=async (...args)=>args[0]==='FixtureSlashMessage'?'[e2edm2]test-wire':original.encrypt(...args);
 input.value=msg;
})()`);
await submitDraftButton();
const encryptedAndReleased=await ev(`(()=>{
 const {cid,input,sent}=fixtureSlashDraft;
 const sentEncrypted=sent.some(e=>e.t==='FixtureSlashMessage'&&e.encrypted)&&!input.value&&!_signalHeldDraftFor(cid,'FixtureSlashMessage');
 setActive(cid,'#dev');input.value='ordinary fresh draft after encrypted slash command';input.focus();
 return sentEncrypted;
})()`);
await pressDraftKey('Enter',13);
await sleep(120);
const freshAfterSlash=await ev(`fixtureSlashDraft.sent.filter(e=>e.t==='#dev'&&!e.encrypted).length===1&&!fixtureSlashDraft.input.value`);
// Put the already-held action above the ordinary channel line just sent. Only
// navigating to the held entry should reattach its original conversation.
await ev(`inputHistory.push(fixtureSlashDraft.action);historyIdx=-1;fixtureSlashDraft.input.focus()`);
await pressDraftKey('ArrowUp',38);
await pressDraftKey('ArrowUp',38);
const ordinaryRecalled=await ev(`fixtureSlashDraft.input.value==='ordinary fresh draft after encrypted slash command'&&!_heldSignalDraft`);
await pressDraftKey('ArrowDown',40);
await submitDraftButton();
const recalledHoldStillPrivate=await ev(`fixtureSlashDraft.input.value===fixtureSlashDraft.action&&
  !!_signalHeldDraftFor('preview','FixtureSlashAction')&&fixtureSlashDraft.sent.filter(e=>e.t==='#dev').length===1`);
await pressDraftKey('ArrowUp',38);
await pressDraftKey('Enter',13);
await waitDraft("!fixtureSlashDraft.input.value");
const unrelatedHistorySent=await ev(`(()=>{
 const {input,sent,original,a,b}=fixtureSlashDraft;
 try{
  return sent.filter(e=>e.t==='#dev'&&!e.encrypted).length===2&&!input.value;
 }finally{
  _releaseHeldSignalDraft('preview','FixtureSlashAction');_releaseHeldSignalDraft('preview','FixtureSlashMessage');
  delete E2E.dmSessions[a];delete E2E.dmSessions[b];
  Object.assign(E2E,original.flags);
  _queueChatParts=original.parts;_queueChatSend=original.wire;e2eEncryptOutgoing=original.encrypt;
  setActive(original.view.conn_id,original.view.target);input.value=original.value;
  delete window.fixtureSlashDraft;
 }
})()`);
ok('a first blocked /me stays protected when it is cleared and recalled through the real composer',
 firstActionHeld&&clearedAction&&recalledAction&&recalledActionSafe);
ok('a first blocked /msg from another chat stays held and cannot be readdressed into that chat',firstMessageHeld&&readdressedSafe);
ok('a successful encrypted slash command releases its live hold and an ordinary fresh draft can send afterward',
 encryptedAndReleased&&freshAfterSlash);
ok('history navigation sends the unrelated channel line while the recalled Signal action stays private in its original chat',
 ordinaryRecalled&&recalledHoldStillPrivate&&unrelatedHistorySent);
const heldStorage=await ev(`(()=>{
 const text='/me locally held history storage fixture', user=currentUser;
 inputHistory.push(text);
 _composerChatApproval(active,text,null).holdSignal('preview','StoredFixtureOne');
 currentUser='other-history-fixture';
 _composerChatApproval(active,text,null).holdSignal('preview','StoredFixtureTwo');
 currentUser=user;
 saveInputHistory();
 const key='cryptirc_input_history_local', snapshot=JSON.parse(localStorage.getItem(key)||'[]');
 const metadata=snapshot.at(-1)?.signalHeld, index=snapshot.indexOf(text);
 const compact=index>=0&&snapshot.filter(x=>x===text).length===1&&Array.isArray(metadata)&&
   metadata.filter(row=>row[0]===index).length===2&&!JSON.stringify(metadata).includes(text)&&
   localStorage.getItem('cryptirc_input_history_signal_held')===null;
 if(metadata){
  const bad={user:'untrusted-history-fixture',connId:'preview',target:'OutOfBounds'};
  metadata.push([-1,bad],[0.25,bad],[snapshot.length-1,bad],[snapshot.length,bad]);
  localStorage.setItem(key,JSON.stringify(snapshot));
 }
 return compact;
})()`);
await load(390,844,true);
const recallStoredFor=async user=>{
 await ev(`currentUser=${JSON.stringify(user)};historyIdx=-1;_heldSignalDraft=null;document.getElementById('msg-input').focus()`);
 await pressDraftKey('ArrowUp',38);
 return ev(`_heldSignalDraft?.target||null`);
};
const firstScope=await recallStoredFor('demo');
const secondScope=await recallStoredFor('other-history-fixture');
const invalidScope=await recallStoredFor('untrusted-history-fixture');
await ev(`(()=>{
 currentUser='demo';_releaseHeldSignalDraft('preview','StoredFixtureOne');
 currentUser='other-history-fixture';_releaseHeldSignalDraft('preview','StoredFixtureTwo');
 currentUser='demo';_heldSignalDraft=null;historyIdx=-1;document.getElementById('msg-input').value='';
})()`);
ok('held history persists as indexed metadata beside its original local-only line',heldStorage);
ok('reopening restores held history by account and ignores invalid snapshot indices',
 firstScope==='StoredFixtureOne'&&secondScope==='StoredFixtureTwo'&&invalidScope===null);
const pinnedLookup=await ev(`(async()=>{
 const cid='preview', target='FixturePinned', draft='draft for pinned Signal peer';
 const key=_e2eDmKey(target,cid), input=document.getElementById('msg-input');
 const original={view:active,input:input.value,user:currentUser,ready:E2E.keyReady,
   refresh:_e2eRefreshAccountState,send:wsend,wsReady:_wsReady,confirm:customConfirm,pin:E2E.trustStore[key],
   reason:E2E.lastBlockReason,boot:E2E._bootPhase,resync:E2E._resyncPending};
 const frames=[];
 let deliverLookup,prompts=0;
 try{
  E2E.keyReady=true;
  E2E._bootPhase='ready';
  E2E._resyncPending=false;
  E2E.trustStore[key]={fingerprint:'authenticated fixture pin',verified:true,keyChanged:false};
  _e2eRefreshAccountState=async()=>true;
  _wsReady=()=>true;
  customConfirm=async()=>{prompts++;return false;};
  wsend=frame=>{
   frames.push(frame);
   if(frame.type==='e2e_fetch_bundle'&&frame.username===target) deliverLookup(frame);
   return true;
  };
  const submit=async (change,reason='unconfirmed')=>{
   setActive(cid,target);
   input.value=draft;
   const lookup=new Promise(resolve=>{deliverLookup=resolve;});
   const submitted=doSend();
   const request=await Promise.race([lookup,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Pinned DM lookup was not requested')),2000))]);
   change?.();
   await e2eHandleEvent({type:'e2e_bundle_missing',conn_id:cid,req:request.req,reason});
   await submitted;
   const result={reason:E2E.lastBlockReason,draft:input.value===draft,longWait:request.wait_for_peer===true,
     visible:document.getElementById('chat-area').textContent.includes('retry /encrypt on '+target)};
   await new Promise(resolve=>setTimeout(resolve,225)); // the composer releases its send lock after 200 ms
   return result;
  };
  const current=await submit();
  const offline=await submit(null,'peer-offline');
  const offlineNotice=getBuf(cid,target).some(row=>row.kind==='error'&&row.text===target+' is offline.');
  const switchedView=await submit(()=>setActive(cid,'#dev'));
  const elsewhere=await submit(()=>setActive(cid,'#dev'),'peer-offline');
  const noOfflineNotice=!getBuf(cid,'#dev').some(row=>row.text?.includes(target+' is offline.'));
  const switchedAccount=await submit(()=>{currentUser='demo-other';});
  const sentChat=frames.some(frame=>frame.type==='send'&&frame.raw?.includes(' '+target+' :'));
  return {current,offline,offlineNotice,switchedView,switchedAccount,elsewhere,noOfflineNotice,prompts,sentChat};
 }finally{
  currentUser=original.user;
  E2E.keyReady=original.ready;
  E2E._bootPhase=original.boot;
  E2E._resyncPending=original.resync;
  _e2eRefreshAccountState=original.refresh;
  wsend=original.send;
  _wsReady=original.wsReady;
  customConfirm=original.confirm;
  if(original.pin) E2E.trustStore[key]=original.pin;
  else delete E2E.trustStore[key];
  _e2ePlainConnections.delete(cid);
  E2E.lastBlockReason=original.reason;
  if(original.view) setActive(original.view.conn_id,original.view.target);
  input.value=original.input;
 }
})()`);
ok('pinned Signal lookup timeout keeps the draft and shows the IRC retry command',
 pinnedLookup.current.longWait&&pinnedLookup.current.draft&&pinnedLookup.current.visible&&
 pinnedLookup.current.reason?.includes('retry /encrypt on '));
ok('pinned Signal lookup timeout neither offers plaintext nor sends the draft',
 pinnedLookup.prompts===0&&!pinnedLookup.sentChat);
ok('an offline recipient is reported in the chat and the draft is kept',pinnedLookup.offlineNotice&&pinnedLookup.offline.draft);
ok('a pinned Signal timeout withholds the retry command after the view or account changes',
 [pinnedLookup.switchedView,pinnedLookup.switchedAccount].every(result=>!result.reason?.includes('retry /encrypt on ')));
ok('a late offline reply cannot display a private contact nickname in the new chat',
 pinnedLookup.noOfflineNotice&&!pinnedLookup.elsewhere.reason?.includes('FixturePinned'));
const restartProof=await ev(`(async()=>{
 const peer='fixture-restart-proof',cid='fixture-network';
 const original={keys:E2E.identityKeys,pin:E2E.trustStore[peer]};
 const identity=async()=>({
   dhKeyPair:await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),
   signKeyPair:await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify'])
 });
 try{
   const [own,contact,otherDevice]=await Promise.all([identity(),identity(),identity()]);
   E2E.identityKeys=own;
   const [local,remote,other]=await Promise.all([own,contact,otherDevice].map(_e2ePublicIdentity));
   const start=other[0], header={sender_ik:remote[0],sender_sign_ik:remote[1],ephemeral_pub:local[0],spk_id:3,used_otpk_id:4};
   const session={connId:cid,isInitiator:true,startEph:start,x3dhPending:{ephemeral_pub:start},
     theirIdentityPub:remote[0],theirSignPub:remote[1],identityAD:bytesToBase64(e2eIdentityAD(...local,...remote))};
   const pin=await _e2eSessFp(session);
   E2E.trustStore[peer]={fingerprint:pin,verified:true,keyChanged:false};
   const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},contact.signKeyPair.privateKey,
     _e2eRestartSignatureData(session,header));
   header.restart_sig=bytesToBase64(new Uint8Array(signature));
   const matches=(options=session,h=header,network=cid)=>_e2eIsSignedSuccessor(peer,options,h,network);
   const exact=await matches();
   const archived={...session,x3dhPending:null,_storeRevision:'synthetic-sealed-revision'};
   const archivedExact=await _e2eIsSignedSuccessor(peer,archived,header,cid,true);
   const archivedOtherStart=await _e2eIsSignedSuccessor(peer,{...archived,startEph:remote[0]},header,cid,true);
   const archivedWithoutRecord=await _e2eIsSignedSuccessor(peer,{...archived,_storeRevision:null},header,cid,true);
   const otherStart=await matches({...session,startEph:remote[0]});
   const confirmed=await matches({...session,x3dhPending:null});
   const otherNetwork=await matches(session,header,'another-network');
   const otherPrekey=await matches(session,{...header,used_otpk_id:5});
   E2E.trustStore[peer].keyChanged=true;
   const disputed=await matches();
   E2E.trustStore[peer].keyChanged=false;
   E2E.identityKeys=otherDevice;
   return {exact,archivedExact,archivedOtherStart,archivedWithoutRecord,otherStart,confirmed,otherNetwork,otherPrekey,disputed,otherIdentity:await matches()};
 }finally{
   E2E.identityKeys=original.keys;
   if(original.pin)E2E.trustStore[peer]=original.pin;else delete E2E.trustStore[peer];
 }
})()`);
ok('a deliberate restart proof matches the original offer on its pinned conversation',restartProof.exact);
ok('history accepts a signed successor for the exact previously saved confirmed session',restartProof.archivedExact);
ok('a restart proof stays bound to both identities, the network, the prekey and an unconfirmed start',
 Object.entries(restartProof).every(([key,value])=>['exact','archivedExact'].includes(key)||value===false));
async function checkCrossedReceiptTiming() {
 const cid=crypto.randomUUID(),nick='FixtureReceipts',peer=_e2eDmKey(nick,cid);
 const saved={identityKeys:E2E.identityKeys,identityReady:E2E.identityReady,keyReady:E2E.keyReady,
   e2eEncKey:E2E.e2eEncKey,state:E2E.state};
 const ws=_e2eWs,decrypt=_e2eDecryptWithFallback,now=Date.now;
 const identity=async()=>({
   dhKeyPair:await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),
   signKeyPair:await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify'])
 });
 try {
   let [own,contact]=await Promise.all([identity(),identity()]);
   let [local,remote]=await Promise.all([own,contact].map(_e2ePublicIdentity));
   if (_e2eCmpBytes(base64ToBytes(local[0]),base64ToBytes(remote[0]))>0) {
     [own,contact]=[contact,own]; [local,remote]=[remote,local];
   }
   const ephemeral=async()=>exportPub((await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits'])).publicKey,'ECDH');
   const [ours,theirs]=await Promise.all([ephemeral(),ephemeral()]);
   const offer={ephemeral_pub:theirs,sender_ik:remote[0],sender_sign_ik:remote[1],used_otpk_id:17,spk_id:3};
   offer.sender_sign_sig=bytesToBase64(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},
     contact.signKeyPair.privateKey,_x3dhHeaderSigMsg(remote[0],theirs,3,17))));
   if (!await _e2eVerifyOffer(offer)) throw new Error('Synthetic restart signature failed');
   E2E.identityKeys=own;
   E2E.identityReady=E2E.keyReady=true;
   E2E.e2eEncKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
   _e2eIdentityRevisions.set(own,'a'.repeat(64));
   E2E.state=_e2eEmptyState();
   E2E.state.dm[peer]={on:1,signal:1};
   const session={connId:cid,startEph:ours,isInitiator:true,x3dhPending:{ephemeral_pub:ours,restart_sig:'locally signed'},
     identityAD:bytesToBase64(e2eIdentityAD(...local,...remote)),theirIdentityPub:remote[0],theirSignPub:remote[1],_storeRevision:'b'.repeat(64)};
   E2E.dmSessions[peer]=session;
   E2E.trustStore[peer]={fingerprint:await _e2eSessFp(session),verified:true};
   _e2eNoteCrossedStart(peer,offer,cid);
   // Seed the exact foreground failure already observed on IRC. The sibling
   // uses real per-message keys, and incoming events go through the renderer.
   _e2eDecryptWithFallback=async()=>{throw new Error('E2E_OTPK_MISSING:17');};
   let sent;
   _e2eWs=async msg=>{if (msg.type==='e2e_live_receipt') sent=msg;};
   async function issue(text,n,{required=true,two=false}={}) {
     const mk=crypto.getRandomValues(new Uint8Array(32)),h={d:theirs,p:0,n};
     const encrypted=await messageEncrypt(mk,new TextEncoder().encode(text),{dh:theirs,pn:0,n},base64ToBytes(session.identityAD));
     const envelope={h,c:bytesToBase64(encrypted)},wire=E2E_DM_PREFIX+btoa(JSON.stringify(envelope));
     _e2eDmHistoryWires.set(envelope,{from:nick,target:nick,text:wire,live:true});
     const sibling={...session,isInitiator:false,startEph:theirs,recent:{}};
     _e2eNoteRecent(sibling,peer+'/'+theirs+'/'+n,mk);
     mk.fill(0);
     sent=null;
     await _e2eShareLiveReceipt(peer,sibling,envelope);
     const receipt=sent;
     if (required && !receipt) throw new Error('The authenticated sibling produced no receipt');
     if (two) await _e2eShareLiveReceipt(peer,sibling,envelope);
     return {text,n,wire,receipt,second:two?sent:null};
   }
   const idle=()=>_e2eEnqueue(cid,nick,()=>{});
   const body=async item=>{
     handleEvent({type:'irc_message',conn_id:cid,from:nick,target:nick,kind:'Privmsg',ts:Math.floor(Date.now()/1000),msg_id:item.n,text:item.wire});
     await idle();
   };
   const rows=getBuf(cid,nick);
   const exact=item=>rows.filter(row=>row._dmHistoryWire===item.wire);
   const delivered=item=>exact(item).length===1 && exact(item)[0].text===item.text && exact(item)[0]._dmHistoryState==='ready';
   const first=await issue('Receipt before its message',1);
   Date.now=()=>now()+600000;
   handleEvent(first.receipt);
   await idle();
   const unopened=rows.length===0 && E2E.dmSessions[peer]===session;
   await body(first);
   const before=delivered(first);
   Date.now=now;
   const delayed=await issue('Receipt after its message',2,{two:true});
   await body(delayed);
   const pending=exact(delayed)[0];
   handleEvent(delayed.receipt);
   handleEvent(delayed.second);
   await idle();
   handleEvent(delayed.receipt);
   await idle();
   const after=delayed.receipt.blob!==delayed.second.blob && !!pending && exact(delayed)[0]===pending && delivered(delayed);
   const absent=await issue('Body never received',3),count=rows.length;
   handleEvent(absent.receipt);
   await idle();
   const noBody=unopened && rows.length===count && !exact(absent).length && E2E.dmSessions[peer]===session;
   const gesture=await e2eDecryptIncoming(nick,nick,absent.wire.replace(E2E_DM_PREFIX,E2E_REACTION_DM_PREFIX),
     {conn_id:cid,live:true,reaction:true});
   const noGesture=gesture.plaintext===null && E2E.dmSessions[peer]===session;
   const explicit=await issue('Receiving profile has no enablement record',5);
   const paused=await issue('Chat turned off before receipt',4);
   await body(paused);
   const pausedRow=rows.find(row=>row.id===paused.n),unread=pausedRow?.text;
   E2E.state.dm[peer].on=0;
   handleEvent(paused.receipt);
   await idle();
   const off=!!pausedRow && pausedRow.text===unread && unread!==paused.text && E2E.dmSessions[peer]===session;
   _e2eCrossedStarts.delete(peer);
   _e2eNoteCrossedStart(peer,offer,cid);
   const disabled=await issue('Sending profile has turned Signal off',6,{required:false});
   delete E2E.state.dm[peer];
   _e2eNoteCrossedStart(peer,offer,cid);
   handleEvent(explicit.receipt);
   const refused=await e2eDecryptIncoming(nick,nick,explicit.wire,{conn_id:cid,live:true});
   const implicit=await issue('Sibling follows its installed signed session',7,{required:false});
   E2E.state.dm[peer]={on:1,signal:1};
   _e2eNoteCrossedStart(peer,offer,cid);
   if (implicit.receipt) handleEvent(implicit.receipt);
   await body(implicit);
   return {before,after,noBody,noGesture,off,published:!!implicit.receipt && delivered(implicit),
     sourceOff:!disabled.receipt,receiverImplicit:!refused.reactionReady && refused.plaintext!==explicit.text};
 } finally {
   Date.now=now; _e2eWs=ws; _e2eDecryptWithFallback=decrypt;
   _e2eForgetSessionRuntime(peer);
   delete E2E.dmSessions[peer]; delete E2E.trustStore[peer]; delete buffers[bk(cid,nick)];
   Object.assign(E2E,saved);
 }
}
const receiptTiming=await ev('('+checkCrossedReceiptTiming+')()');
ok('an earlier receipt opens the exact incoming DM with ten minutes of device clock skew',receiptTiming.before);
ok('a delayed receipt updates the original unread row exactly once',receiptTiming.after);
ok('a receipt alone leaves the conversation empty of that message',receiptTiming.noBody);
ok('crossed-restart receipts leave the existing gesture authentication in effect',receiptTiming.noGesture);
ok('turning off Signal preserves an unread row when its delayed receipt arrives',receiptTiming.off);
ok('a sibling with an installed signed session can share its authenticated message before its DM setting arrives',receiptTiming.published);
ok('an explicit Signal opt-out prevents the sibling from publishing a receipt',receiptTiming.sourceOff);
ok('a foreground profile requires explicit Signal enablement before opening a receipt',receiptTiming.receiverImplicit);
const legacyOff=await ev(`(async()=>{
 const nick='LegacyOffFixture', cid='preview', key=_e2eDmKey(nick,cid);
 const saved={state:E2E.state,keyReady:E2E.keyReady,e2eEncKey:E2E.e2eEncKey,_resyncPending:E2E._resyncPending};
 const request=_e2eRequestSession, priorPin=E2E.trustStore[key];
 try{
  E2E.state=_e2eEmptyState();
  E2E.state.dm[key]={on:0,n:1};
  E2E.keyReady=true; E2E._resyncPending=false;
  E2E.e2eEncKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  E2E.trustStore[key]={fingerprint:'current-fixture-pin'};
  const state=structuredClone(E2E.state);
  _e2eRequestSession=async slot=>slot==='__state__' ? {
   blob:await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(state)),_e2eCtxSession('__state__'))
  } : {blob:'',floor_blob:''};
  const check=()=>e2eCheckOptOutSlot(nick,cid,key);
  const unpinned=await check();
  state.trust[key]={fp:'current-fixture-pin',n:1};
  const legacy=await check();
  state.dm[key].plainFingerprint='current-fixture-pin';
  const confirmed=await check();
  state.trust[key].fp='changed-fixture-pin';
  const changed=await check();
  const guidance=_e2eBundleFailure(nick,legacy);
  return {unpinned,legacy,confirmed,changed,both:guidance.includes('/encrypt on '+nick)&&guidance.includes('/encrypt off '+nick)};
 }finally{
  Object.assign(E2E,saved); _e2eRequestSession=request;
  if(priorPin) E2E.trustStore[key]=priorPin; else delete E2E.trustStore[key];
 }
})()`);
ok('a legacy opt-out with a saved contact pin requires a deliberate choice and offers both commands',
 legacyOff.legacy==='enabling'&&legacyOff.both&&legacyOff.unpinned==='empty');
ok('explicit plaintext is allowed for the confirmed contact and held after its fingerprint changes',
 legacyOff.confirmed==='empty'&&legacyOff.changed==='enabling');
const siblingSignal=await ev(`(async()=>{
 const cid='937abed0-dafd-40e4-a428-f4260cd91129', originalNetwork=networks[0];
 const original={view:active,user:currentUser,request:_e2eReq,send:_e2eWs,refresh:_e2eRefreshAccountState,
   writeSession:_e2eWriteDeviceSession,
   flags:{keyReady:E2E.keyReady,identityReady:E2E.identityReady,identityKeys:E2E.identityKeys,
     e2eEncKey:E2E.e2eEncKey,state:E2E.state,_serverLocked:E2E._serverLocked}};
 const identity=async()=>({
   dhKeyPair:await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits','deriveKey']),
   signKeyPair:await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify'])
 });
 const cases=[['FixtureSiblingConfirmed','on','initiator'],['FixtureSiblingResponder','on','responder'],
   ['FixtureSiblingRestart','restart','initiator'],['FixtureSiblingMismatch','on','mismatch'],
   ['FixtureSiblingOff','on','off']];
 try{
  networks.push({...originalNetwork,config:{...originalNetwork.config,id:cid},channels:[]});
  currentUser='fixture-sibling-signal';
  Object.assign(E2E,{keyReady:true,identityReady:true,identityKeys:await identity(),
    e2eEncKey:await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),
    state:_e2eEmptyState(),_serverLocked:false});
  const peer=await identity(), spk=await identity();
  const spkPub=await exportPub(spk.dhKeyPair.publicKey,'ECDH');
  const spkSig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},peer.signKeyPair.privateKey,base64ToBytes(spkPub));
  const bundle={identity_dh_key:await exportPub(peer.dhKeyPair.publicKey,'ECDH'),
    identity_sign_key:await exportPub(peer.signKeyPair.publicKey,'ECDSA'),signed_prekey:{
      key_id:1,public_key:spkPub,signature:bytesToBase64(new Uint8Array(spkSig))}};
  const pinned=await computeIdentityFingerprint(bundle.identity_dh_key,bundle.identity_sign_key);
  const seed=await x3dhInitiate(bundle);
  const root=bytesToBase64(seed.sharedSecret.subarray(0,32));
  const chain=bytesToBase64(seed.sharedSecret.subarray(32));
  _e2eRefreshAccountState=async()=>true;
  const outcomes={};
  for(const [nick,command,kind] of cases){
   const key=_e2eDmKey(nick,cid), isInitiator=kind!=='responder';
   const winner={nick:key,connId:cid,epoch:8,RK:root,CKs:chain,CKr:chain,Ns:1,Nr:1,PN:0,
     DHs:{pub:spkPub,priv:await exportPriv(spk.dhKeyPair.privateKey)},DHr:spkPub,
     startEph:seed.ephemeralPub,isInitiator,identityAD:seed.identityAD,
     theirIdentityPub:kind==='mismatch'?spkPub:bundle.identity_dh_key,theirSignPub:bundle.identity_sign_key,
     ...(isInitiator?{}:{establishEph:seed.ephemeralPub})};
   const conflict=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(winner)),_e2eCtxSession(key));
   E2E.trustStore[key]={fingerprint:pinned,verified:true};
   E2E.state.trust[key]={fp:pinned,ver:true,n:1};
   let savedSettings=await aesEncryptBlob(new TextEncoder().encode(JSON.stringify(E2E.state)),_e2eCtxSession('__state__'));
   const frames=[];
   let commits=0;
   _e2eWs=async frame=>{frames.push(frame);return true;};
   _e2eReq=async request=>{
    if(request.partner==='__state__'){
      if(request.type==='e2e_load_session')return {blob:savedSettings,req:request.req};
      if(request.type==='e2e_store_session'){savedSettings=request.blob;return {ok:true,req:request.req};}
    }
    if(request.type==='e2e_load_session'&&request.partner===key)
      return {blob:'',...(request.with_floor?{floor_blob:''}:{})};
    if(request.type!=='e2e_commit_session'||request.partner!==key||!request.create)return null;
    commits++;
    return {ok:false,conflict};
   };
   _e2eWriteDeviceSession=async (slot,session)=>{
    await original.writeSession(slot,session);
    if(kind==='off'&&slot===key) E2E.state.dm[key]={on:0,closedEpoch:9,n:2};
   };
   setActive(cid,nick);
   await handleEncryptCommand([command,nick],cid,nick);
   const discovery=frames.find(frame=>frame.type==='e2e_fetch_bundle'&&frame.username===nick);
   if(!discovery)throw new Error('The Signal command did not request the key bundle');
   await e2eHandleEvent({type:'e2e_bundle',username:nick,conn_id:cid,req:discovery.req,bundle});
   const messages=document.getElementById('chat-area').textContent;
   const adopted=E2E.dmSessions[key];
   outcomes[kind==='initiator'?command:kind]={commits,
     winner:adopted?.startEph===winner.startEph&&adopted?.epoch===winner.epoch&&!adopted.x3dhPending,
     mode:e2eTargetState(nick,{conn_id:cid}).mode,off:E2E.state.dm[key]?.on===0,pinned:E2E.trustStore[key]?.fingerprint===pinned,
     ready:messages.includes('is active and ready to send'),waiting:messages.includes('An encrypted reply will confirm'),
     race:messages.includes('Another device updated Signal encryption'),invalid:messages.includes('invalid key bundle')};
  }
  return outcomes;
 }finally{
  await E2E._stateSaving;
  for(const [nick] of cases){
   const key=_e2eDmKey(nick,cid);
   delete E2E.trustStore[key];delete E2E.dmSessions[key];delete E2E._sessionEpoch[key];
   E2E._sessionSyncRepair.delete(key);delete _e2eAdoptedEpochs[key];
  }
  networks.pop();
  currentUser=original.user;
  Object.assign(E2E,original.flags);
  _e2eReq=original.request;
  _e2eWs=original.send;
  _e2eRefreshAccountState=original.refresh;
  _e2eWriteDeviceSession=original.writeSession;
  setActive(original.view.conn_id,original.view.target);
 }
})()`);
ok('Signal setup uses the confirmed initiator session that won the account save',
 siblingSignal.on.commits===1&&siblingSignal.on.winner&&siblingSignal.on.mode==='dm'&&
 siblingSignal.on.ready&&!siblingSignal.on.waiting&&!siblingSignal.on.invalid);
ok('an already established responder stays usable and is reported as a concurrent update',
 siblingSignal.responder.commits===1&&siblingSignal.responder.winner&&siblingSignal.responder.mode==='dm'&&
 siblingSignal.responder.race&&!siblingSignal.responder.ready&&!siblingSignal.responder.invalid);
ok('an explicit restart that loses the save does not claim it restarted the winning session',
 siblingSignal.restart.commits===1&&siblingSignal.restart.winner&&siblingSignal.restart.race&&
 !siblingSignal.restart.ready&&!siblingSignal.restart.invalid);
ok('a competing account save cannot bypass the current identity pin or Signal off',
 siblingSignal.mismatch.commits===1&&!siblingSignal.mismatch.winner&&siblingSignal.mismatch.pinned&&!siblingSignal.mismatch.ready&&
 siblingSignal.off.commits===1&&siblingSignal.off.winner&&siblingSignal.off.off&&
 siblingSignal.off.mode==='blocked'&&!siblingSignal.off.ready);
const signalHeaders=await ev(`(()=>{
 const target='HeaderFixture', connId='preview', originalSend=rateLimitedSend;
 const originalClock=Date.now, originalSent=E2E._hdrSent;
 const equivalent='[headerfixture]', alias='{headerfixture}', originalCaseMap=_e2eCaseMap;
 const oldSession=E2E.dmSessions[equivalent];
 const queued=[];
 let now=Date.now();
 const offer=ephemeral=>({connId,x3dhPending:{ephemeral_pub:ephemeral,sender_sign_sig:'a'.repeat(420)}});
 const send=session=>_e2eSendHeader(target,session,connId);
 const take=()=>{
  const frames=queued.splice(0);
  const prefix='PRIVMSG '+target+' :'+E2E_HDR_FRAG;
  if(frames.length<2||frames.some(frame=>frame.conn_id!==connId||!frame.raw.startsWith(prefix)))return null;
  const fragments=frames.map(frame=>frame.raw.slice(prefix.length).split('~'));
  return JSON.parse(atob(fragments.map(part=>part[3]).join(''))).ephemeral_pub;
 };
 try{
  rateLimitedSend=payload=>queued.push(payload);
  E2E._hdrSent=Object.create(null);
  Date.now=()=>now;
  send(offer('old-offer'));
  const original=take()==='old-offer';
  send(offer('old-offer'));
  const repeat=queued.length===0;
  // Adopting a sibling's session gives this device a different pending offer
  // without running its own bundle handler or resetting the local throttle.
  send(offer('replacement-offer'));
  const replaced=take()==='replacement-offer';
  send(offer('replacement-offer'));
  now+=5*60*1000-1;
  send(offer('replacement-offer'));
  const throttled=queued.length===0;
  now++;
  send(offer('replacement-offer'));
  const expired=take()==='replacement-offer';
  _e2eCaseMap=()=>'rfc1459';
  E2E.dmSessions[equivalent]=offer('alias-offer');
  _e2eSendHeader(alias,E2E.dmSessions[equivalent],connId);
  const aliasSent=queued.splice(0).length>0;
  _e2eSendHeader(equivalent,E2E.dmSessions[equivalent],connId);
  const sharedThrottle=queued.length===0;
  delete E2E._hdrSent[_e2eDmKey(equivalent,connId)];
  _e2eSendHeader(alias,E2E.dmSessions[equivalent],connId);
  return {original,repeat,replaced,throttled,expired,aliasRetry:aliasSent&&sharedThrottle&&queued.length>0};
 }finally{
  rateLimitedSend=originalSend;
  Date.now=originalClock;
  E2E._hdrSent=originalSent;
  _e2eCaseMap=originalCaseMap;
  if(oldSession) E2E.dmSessions[equivalent]=oldSession; else delete E2E.dmSessions[equivalent];
 }
})()`);
ok('a sibling replacement sends its distinct Signal offer despite a recent old offer',signalHeaders.original&&signalHeaders.replaced);
ok('duplicate Signal offers remain throttled for five minutes',signalHeaders.repeat&&signalHeaders.throttled&&signalHeaders.expired);
ok('equivalent IRC nick spellings share the offer throttle and explicit retry',signalHeaders.aliasRetry);
ok('a failed Signal restart gives the applicable retry command',await ev(
 "_e2eBundleFailure('RetryFixture','unconfirmed',true).includes('/encrypt restart RetryFixture')&&_e2eBundleFailure('RetryFixture','unconfirmed').includes('/encrypt on RetryFixture')"));
const sharedReceipt=await ev(`(async()=>{
 const user=currentUser, authed=_wsAuthed, master=E2E.e2eEncKey, ready=E2E.keyReady;
 const cid='preview', target='ReceiptFixture', msgId=7309;
 const prior=new Map(reactionHistory), states=[], refusals=[];
 try{
  currentUser='receipt-'+crypto.randomUUID();
  _wsAuthed=true; E2E.keyReady=true;
  E2E.e2eEncKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  for(const encrypted of [false,true]){
   const key=crypto.randomUUID(), yesterday=Date.now()-86400000, receipt={request_id:key,expires_at:yesterday};
   const reference=encrypted?'a'.repeat(32):'IRC-fixture-anchor', anchor=encrypted?null:reference;
   const slot=reactionHistorySlot(encrypted), row=reactionHistoryKey(cid,target,msgId);
   const stateKey=reactionKey(cid,target,reference,encrypted), cache=loadReactionHistory(encrypted);
   await cache.ready;
   await updateReactionHistory(slot,cache.master,records=>{
    for(const emoji of ['👍','❤️']) saveReactionChange(records,row,anchor,reference,emoji,false,'Fixture','',0);
    records.set(reactionReceiptKey(key),{connId:cid,target,msgId,reference,emoji:'❤️',remove:true,sender:'Fixture',until:yesterday});
   });
   // A still-open second tab may have read its row before the first tab
   // journaled or settled the echo. Both ultimately see the identical receipt.
   const stale=structuredClone(cache.records);
   stale.delete(reactionReceiptKey(key));
   const first=await settleReactionReceipt(cid,receipt,encrypted);
   cache.records=stale;
   chatReactions.set(stateKey,{connId:cid,encrypted,entries:reactionEntryMap(stale.get(row).entries)});
   const wrong=await settleReactionReceipt('other-connection',receipt,encrypted);
   const second=await settleReactionReceipt(cid,receipt,encrypted);
   const shown=chatReactions.get(stateKey).entries;
   states.push(first&&!wrong&&second&&shown.has('👍')&&!shown.has('❤️')&&
     cache.records.get(row).ownReceipts['❤️']===key);
   const refused=crypto.randomUUID(), other=crypto.randomUUID(), unknown=crypto.randomUUID();
   await updateReactionHistory(slot,cache.master,records=>{
    const request={connId:cid,target,msgId,reference,emoji:'❤️',remove:false,sender:'Fixture'};
    for(const requestId of [refused,other])records.set(reactionReceiptKey(requestId),request);
   });
   const error='IRC refused this reaction.';
   await receiveReactionResult({request_id:unknown,error});
   const unrelatedChanges=await readReactionHistory(slot,cache.master);
   await receiveReactionResult({request_id:refused,error});
   const after=await readReactionHistory(slot,cache.master);
   refusals.push(!pendingChatReactions.has(refused)&&unrelatedChanges.has(reactionReceiptKey(refused))&&
     !after.has(reactionReceiptKey(refused))&&after.has(reactionReceiptKey(other))&&
     after.get(row).ownReceipts['❤️']===key);
   chatReactions.delete(stateKey);
   await _e2eIdbOp('readwrite',store=>store.delete(slot),2000);
  }
  return {states,refusals};
 }finally{
  currentUser=user; _wsAuthed=authed; E2E.keyReady=ready; E2E.e2eEncKey=master;
  reactionHistory.clear(); for(const [kind,cache] of prior) reactionHistory.set(kind,cache);
 }
})()`);
ok('a second tab reconciles yesterday’s confirmed plain or sealed reaction only on its original connection',
 sharedReceipt.states.length===2&&sharedReceipt.states.every(Boolean));
ok('an unmatched late refusal leaves other journals intact and a matching refusal clears only its plain or sealed request',
 sharedReceipt.refusals.length===2&&sharedReceipt.refusals.every(Boolean));
const {targetId:reactionTab}=await send('Target.createTarget',{url:'about:blank'});
const {sessionId:reactionSession}=await send('Target.attachToTarget',{targetId:reactionTab,flatten:true});
const otherReactionTab=async(expression)=>{
 const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true},reactionSession);
 if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));
 return r.result.value;
};
try{
 await send('Runtime.enable',{},reactionSession);
 await send('Network.enable',{},reactionSession);
 await send('Network.setBlockedURLs',{urls:['https://*','wss://*']},reactionSession);
 await send('Page.enable',{},reactionSession);
 await send('Page.navigate',{url:'http://127.0.0.1:'+port+'/cryptirc/'},reactionSession);
 const waitReaction=async(probe,label)=>{
  for(let i=0;i<120;i++){
   const result=await probe();
   if(result)return result;
   await sleep(25);
  }
  throw new Error('Timed out waiting for '+label);
 };
 await waitReaction(()=>otherReactionTab("document.readyState==='complete'&&typeof sendChatReaction==='function'"),'second reaction tab');
 await otherReactionTab(fixture);
 const user=await ev("'reaction-order-'+crypto.randomUUID()");
 const prepare=`(async()=>{
  currentUser=${JSON.stringify(user)}; _wsAuthed=true; _wsReady=()=>true;
  E2E.keyReady=true;
  E2E.e2eEncKey=await crypto.subtle.importKey('raw',new Uint8Array(32).fill(47),'AES-GCM',false,['encrypt','decrypt']);
  const originalMode=e2eTargetState;
  e2eTargetState=(target,options)=>options?.conn_id==='preview'&&target==='OrderSealed' ?
   {mode:'psk'} : options?.conn_id==='preview'&&target==='OrderPlain' ? {mode:'none'} : originalMode(target,options);
  e2eEncryptReaction=async()=>'e2r1p:'+crypto.randomUUID();
  window.reactionRequests=[];
  wsend=request=>{if(request.type==='react')window.reactionRequests.push(request);return true;};
  reactionSupport('preview',true);
 })()`;
 await Promise.all([ev(prepare),otherReactionTab(prepare)]);
 const hasHeart="!![...document.querySelectorAll('#chat-area .reaction-count')].find(chip=>chip.textContent==='❤️ 1')";
 const clickHeart=async tab=>{
  const at=await tab('window.reactionRequests.length');
  if(!await tab(`(()=>{
   const row=[...document.querySelectorAll('#chat-area .msg-row')].find(line=>line._msgRef?.text==='Reactions fixture');
   if(!row)return false;
   row.querySelector('.msg-body').click();
   const button=row.querySelector('.reaction-choice[data-emoji="❤️"]');
   button?.click();
   return !!button;
  })()`))throw new Error('Heart action was unavailable in the reaction fixture');
  return waitReaction(()=>tab(`window.reactionRequests[${at}]`),'journaled Heart click');
 };
 for(const encrypted of [false,true]){
  const kind=encrypted?'sealed':'plain', target=encrypted?'OrderSealed':'OrderPlain';
  const reference=encrypted?'c'.repeat(32):'irc-order-fixture', msgId=encrypted?7311:7310;
  const setup=`(()=>{
   setActive('preview',${JSON.stringify(target)});
   addMessage('preview',${JSON.stringify(target)},{id:${msgId},kind:'privmsg',from:'FixturePeer',text:'Reactions fixture',
     ts:Math.floor(Date.now()/1000),encrypted:${encrypted},reactionRef:${JSON.stringify(encrypted?reference:null)}});
   if(!${encrypted})rememberReactionAnchor({conn_id:'preview',target:${JSON.stringify(target)},msg_id:${msgId},reference:${JSON.stringify(reference)}});
  })()`;
  await Promise.all([ev(setup),otherReactionTab(setup)]);
  const added=await clickHeart(otherReactionTab);
  const confirmation=(tab,request,order)=>{
   const {body,reference,emoji,remove}=request.reaction;
   const event={type:encrypted?'sealed_reaction':'irc_reaction',conn_id:'preview',target,from:'ghost',own:true,
     body,reference,emoji,remove,receipt:{request_id:request.request_id,expires_at:order}};
   return tab(`${encrypted?'receiveSealedReaction':'receiveChatReaction'}(${JSON.stringify(event)})`);
  };
  await confirmation(ev,added,100);
  await waitReaction(()=>ev(hasHeart),'first tab displays the add');
  if(!encrypted){
   // Receipt recovery can show the old Heart while its live echo is delayed.
   const recovered={conn_id:'preview',receipts:[{request_id:added.request_id,expires_at:100}]};
   await otherReactionTab(`receiveReactionReceipts(${JSON.stringify(recovered)})`);
   await waitReaction(()=>otherReactionTab(hasHeart),'second tab displays its recovered add');
  }
  const removed=await clickHeart(ev);
  await confirmation(ev,removed,200);
  if(encrypted)await confirmation(otherReactionTab,removed,200);
  await confirmation(otherReactionTab,added,100);
  const durable=await otherReactionTab(`(async()=>{
   await Promise.all(reactionHistoryQueues.values());
   const slot=reactionHistorySlot(${encrypted}), records=await readReactionHistory(slot,${encrypted?'E2E.e2eEncKey':'null'});
   const saved=records.get(reactionHistoryKey('preview',${JSON.stringify(target)},${msgId}));
   return saved?.ownOrder?.['❤️']===200&&!saved.entries.some(([emoji])=>emoji==='❤️');
  })()`);
  ok('late '+kind+' Heart add stays removed in both open tabs and IndexedDB',
    added.reaction.kind===kind&&removed.reaction.kind===kind&&durable&&!await ev(hasHeart)&&!await otherReactionTab(hasHeart));
  // This click's journal is written, but the device loses storage before its
  // valid live acknowledgement arrives.
  const live=await clickHeart(ev);
  await ev(`window.restoreReactionIdb=(()=>{
   const original=_e2eIdbOp;
   _e2eIdbOp=async()=>{throw new Error('Fixture storage unavailable');};
   return ()=>{_e2eIdbOp=original;};
  })()`);
  try{
   await confirmation(ev,live,300);
   await ev('Promise.all(reactionHistoryQueues.values())');
   ok('confirmed '+kind+' Heart renders live when IndexedDB becomes unavailable',await ev(hasHeart));
  }finally{await ev('window.restoreReactionIdb();delete window.restoreReactionIdb;');}
 }
 ok('an account change during a reaction journal write prevents the send and storage warning',await ev(`(async()=>{
  const original={user:currentUser,journal:journalReaction,show:showToast};
  const attempts=window.reactionRequests.length, warnings=[];
  try{
   showToast=text=>warnings.push(text);
   journalReaction=async()=>{currentUser='superseded-reaction-fixture';return false;};
   await sendChatReaction('preview','OrderPlain','irc-order-fixture','👍',false,false,7310);
   return warnings.length===0&&window.reactionRequests.length===attempts;
  }finally{currentUser=original.user;journalReaction=original.journal;showToast=original.show;}
 })()`));
 const canceledReactions=await ev(`(async()=>{
  const peer=_e2eDmKey('OrderSealed','preview');
  const original={user:currentUser,socket:ws,keys:E2E.identityKeys,gen:E2E._lockGen,serverLock:E2E._serverLocked,
   session:E2E.dmSessions[peer],trust:E2E.trustStore[peer],
   deviceLock:encryptionDeviceLocked,mode:e2eTargetState,journal:journalReaction,toast:showToast};
  const results={};
  try{
   e2eTargetState=()=>({mode:'dm'});
   for(const change of ['identity','peer-pin','peer-dispute','session','device-lock','vault-lock','account','connection']){
    const alerts=[], start=window.reactionRequests.length;
    let locked=false, journalFinished=false;
    currentUser=original.user;ws=original.socket;E2E.identityKeys={};E2E._serverLocked=false;
    E2E.dmSessions[peer]={startEph:'first-session'};E2E.trustStore[peer]={fingerprint:'1'.repeat(64)};
    encryptionDeviceLocked=()=>locked;
    showToast=message=>{
     original.toast(message);
     const toast=document.getElementById('generic-toast');
     if(toast?.getAttribute('role')==='status'&&toast.style.opacity==='1')alerts.push(toast.textContent);
    };
    journalReaction=async()=>{
     journalFinished=true;
     if(change==='peer-pin')E2E.trustStore[peer]={fingerprint:'2'.repeat(64)};
     else if(change==='peer-dispute')E2E.trustStore[peer].keyChanged=true;
     else if(change==='session')E2E.dmSessions[peer]={startEph:'second-session'};
     else {E2E.identityKeys={};E2E._lockGen++;}
     if(change==='device-lock')locked=true;
     if(change==='vault-lock')E2E._serverLocked=true;
     if(change==='account')currentUser='different-reaction-fixture';
     if(change==='connection')ws={};
     return false;
    };
    await sendChatReaction('preview','OrderSealed','a'.repeat(32),'❤️',false,true,7311);
    results[change]={held:journalFinished&&window.reactionRequests.length===start,alerts};
   }
  }finally{
   currentUser=original.user;ws=original.socket;E2E.identityKeys=original.keys;E2E._lockGen=original.gen;
   if(original.session)E2E.dmSessions[peer]=original.session;else delete E2E.dmSessions[peer];
   if(original.trust)E2E.trustStore[peer]=original.trust;else delete E2E.trustStore[peer];
   E2E._serverLocked=original.serverLock;encryptionDeviceLocked=original.deviceLock;
   e2eTargetState=original.mode;journalReaction=original.journal;showToast=original.toast;
  }
  return results;
 })()`);
 ok('the originating phone explains a locally canceled Signal reaction',canceledReactions.identity.held&&
  canceledReactions.identity.alerts.length===1&&canceledReactions.identity.alerts[0].includes('Your encryption identity changed'));
 ok('changing or disputing the contact pin or replacing the session during a reaction journal write prevents handoff',
  ['peer-pin','peer-dispute','session'].every(change=>canceledReactions[change].held&&canceledReactions[change].alerts.length===1&&
   canceledReactions[change].alerts[0].includes('Check this contact')));
 ok('a locked device, locked vault, changed account or replacement connection gets no stale reaction notice',
  ['device-lock','vault-lock','account','connection'].every(change=>canceledReactions[change].held&&!canceledReactions[change].alerts.length));
 ok('an expired plaintext choice closes underneath another dialog and leaves that dialog usable',await ev(`(async()=>{
  const count=_confirmDialogs.length;
  const expiry=customConfirm('Timed consent','Send','Cancel',true,undefined,Date.now()+100);
  const first=_confirmDialogs.at(-1);
  const other=customConfirm('A separate decision','Continue','Cancel');
  const second=_confirmDialogs.at(-1);
  const declined=await expiry;
  const intact=!first.isConnected&&second.isConnected&&_confirmDialogs.at(-1)===second;
  second.querySelectorAll('button')[1].click();
  return !declined&&intact&&await other&&_confirmDialogs.length===count;
 })()`));
}finally{await send('Target.closeTarget',{targetId:reactionTab});}
ok('no runtime exceptions',errors.length===0);
const result={passed:checks.filter(x=>x.pass).length,total:checks.length,failed:checks.filter(x=>!x.pass),errors};console.log(JSON.stringify(result));socket.close();if(result.failed.length)process.exitCode=1;
}finally{chrome.kill();await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
