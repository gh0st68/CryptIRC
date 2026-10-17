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
const contrastCode=`window.__ratio=(fg,bg)=>{const numbers=c=>c.match(/[\\d.]+/g).slice(0,3).map(Number),l=c=>numbers(c).map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);const a=l(fg),b=l(bg);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);}`;
let themeCount=0;
for(const [w,h,mobile] of [[1440,900,false],[390,844,true]]){
 await load(w,h,mobile);await ev(contrastCode);
 const result=await ev(`(()=>{
  const failures=[],before={links:0,nicks:0};let count=0;
  const generic=document.createElement('a');generic.href='https://example.test/';generic.textContent='A normal link';document.getElementById('chat-area').appendChild(generic);
  const row=document.querySelector('.msg-row .msg-body');row.innerHTML='<a href="https://example.test/?x=1&amp;y=2" target="_blank" rel="noopener noreferrer">A chat link</a>';
  const link=row.querySelector('a'),own=document.querySelector('.msg-nick.nc-self');
  for(const [name,theme] of Object.entries(THEMES)){
   const cfg={...APPEAR_DEFAULTS,theme:name,mobileTheme:'',accent:'#121218',accent2:'#111119',selfNickColor:'',linkColor:'',esheep:'off',coloredNicks:true};
   applyThemeCSS(cfg);renderNickPanel(['@ghost','Alex']);
   const bg=getComputedStyle(document.documentElement).getPropertyValue('--bg0'),panel=document.querySelector('.nick-entry.nc-self');
   const bgRGB=getComputedStyle(document.body).backgroundColor,panelBg=getComputedStyle(document.getElementById('nick-panel')).backgroundColor;
   const chatBg=name==='mirc'?'rgb(255, 255, 255)':bgRGB;
   for(const [label,color,background] of [['chat link',getComputedStyle(link).color,chatBg],['nickname',getComputedStyle(own).color,chatBg],['user list nickname',getComputedStyle(panel).color,panelBg],['general link',getComputedStyle(generic).color,chatBg]]){
    const ratio=__ratio(color,background);if(ratio<4.5)failures.push({theme:name,label,color,background,ratio});count++;
   }
   if(!getComputedStyle(link).textDecorationLine.includes('underline'))failures.push({theme:name,label:'link underline'});
  }
  return {count,themes:Object.keys(THEMES).length,failures};
 })()`);
 themeCount=result.themes;ok(w+'px: readable links and own nick across '+result.themes+' themes ('+result.count+' color checks)',!result.failures.length);if(result.failures.length)console.error(JSON.stringify(result.failures.slice(0,15)));
 const preferences=await ev(`(()=>{
  const oldWs=ws,packets=[];ws={readyState:1,send:raw=>packets.push(JSON.parse(raw))};
  const cfg={...APPEAR_DEFAULTS,theme:'custom:test',customThemes:{test:{...THEMES.discord,link:'#111111',accent:'#111111',accent2:'#111111'}},linkColor:'#fedcba',selfNickColor:'#ff99cc',mobileTheme:'',coloredNicks:false};
  saveAppearance(cfg);applyThemeCSS(cfg);renderNickPanel(['@ghost','Alex']);populateAppearanceModal(cfg);
  const first=document.documentElement.style.getPropertyValue('--link');
  const pick=document.getElementById('a-self-nick-color');pick.value='#f5b9ef';pick.dispatchEvent(new Event('input',{bubbles:true}));
  const saved=loadAppearance(), own=document.querySelector('.msg-nick.nc-self'),panel=document.querySelector('.nick-entry.nc-self');
  ws=oldWs;
  return {syncPayload:packets.some(p=>p.type==='save_appearance'&&JSON.parse(p.settings).selfNickColor==='#f5b9ef'),syncBudget:JSON.stringify(saved).length<=4096,linkWins:first==='#fedcba',saved:saved.selfNickColor==='#f5b9ef',stored:JSON.parse(localStorage.getItem('cryptirc_appear')).selfNickColor==='#f5b9ef',customPreserved:!!saved.customThemes.test,rendered:getComputedStyle(own).color==='rgb(245, 185, 239)'&&getComputedStyle(panel).color==='rgb(245, 185, 239)',toggle:document.getElementById('a-self-nick-default').getAttribute('aria-checked')==='false'};
 })()`);
 for(const [name,value] of Object.entries(preferences))ok(w+'px: custom nickname/link setting '+name,value);
 await send('Page.reload',{ignoreCache:true});for(let i=0;i<80;i++){await sleep(100);if(await ev(`typeof setActive==='function' && document.readyState==='complete'`))break;}
 ok(w+'px: nickname preference survives reload',await ev(`loadAppearance().selfNickColor==='#f5b9ef'`));
 await ev(fixture);await ev(contrastCode);
 ok(w+'px: reset-to-default switch clears only the nickname override',await ev(`(()=>{const c=loadAppearance();populateAppearanceModal(c);document.getElementById('a-self-nick-default').click();return loadAppearance().selfNickColor===''&&!!loadAppearance().customThemes.test;})()`));
 const overrides=await ev(`(()=>{
  const c={...APPEAR_DEFAULTS,theme:'mirc',mobileTheme:'discord',mobileLink:'#aaffbb',selfNickColor:'#050506',linkColor:'#ffbbee'};applyThemeCSS(c);renderNickPanel(['GHOST','Alex']);
  return {mobileWins:${mobile}?document.documentElement.style.getPropertyValue('--link')==='#aaffbb':document.documentElement.style.getPropertyValue('--link')!=='#aaffbb',caseMatch:!!document.querySelector('.nick-entry.nc-self'),savedNotMutated:c.selfNickColor==='#050506'};
 })()`);
 for(const [name,value] of Object.entries(overrides))ok(w+'px: overrides '+name,value);
 // Simulate an older cached document lacking only the newly added controls.
 ok(w+'px: older page preserves new nickname preference',await ev(`(()=>{const c={...loadAppearance(),selfNickColor:'#cceeff'};saveAppearance(c);populateAppearanceModal(c);document.getElementById('a-self-nick-default').remove();document.getElementById('a-self-nick-color').remove();applyAppearance();return loadAppearance().selfNickColor==='#cceeff';})()`));
}
await load(1440,900,false);await ev(contrastCode);
const cssColors=await ev(`(()=>{const failures=[];for(const bg of ['#101015','#36393f','#eeeeee','#777777'])for(const fg of ['#000','#fff','rgba(5,5,5,.2)','hsl(240,100%,10%)','navy','transparent','#11223300']){
 const out=readableTextColor(fg,bg);const el=document.createElement('div');el.style.color=out;el.style.backgroundColor=bg;document.body.appendChild(el);const s=getComputedStyle(el),r=__ratio(s.color,s.backgroundColor);el.remove();if(r<4.5)failures.push([fg,bg,out,r]);}return failures;})()`);
ok('hex, named, HSL, RGB, and transparent colors remain readable',!cssColors.length);if(cssColors.length)console.error(cssColors);
const html=await fs.readFile(path.join(staticRoot,'index.html'),'utf8'),js=await fs.readFile(path.join(staticRoot,'app.js'),'utf8');
const helper=s=>s.slice(s.indexOf('function readableTextColor('),s.indexOf('\n}',s.indexOf('function readableTextColor('))+2);
ok('boot and runtime use the identical contrast helper',helper(html)===helper(js));
if(process.env.COLOR_AUDIT_OUT){
 await fs.mkdir(process.env.COLOR_AUDIT_OUT,{recursive:true});
 for(const [w,h,mobile] of [[1440,900,false],[390,844,true]]){await load(w,h,mobile);await ev(`saveAppearance({...APPEAR_DEFAULTS,theme:'discord',linkColor:'',selfNickColor:''});applyThemeCSS(loadAppearance());addMessage('preview','#dev',{id:400,ts:Math.floor(Date.now()/1000),kind:'privmsg',from:'ghost',text:'Readable links: https://example.test/project and a brighter nickname.'});scrollForce()`);await sleep(100);const image=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(process.env.COLOR_AUDIT_OUT,'cryptirc-colors-'+w+'.png'),Buffer.from(image.data,'base64'));
 await ev(`showAppearanceModal();document.getElementById('a-self-nick-color').scrollIntoView({block:'center'})`);await sleep(100);
 const box=await ev(`(()=>{const r=document.getElementById('a-self-nick-default').getBoundingClientRect(),p=document.getElementById('a-self-nick-color').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2,visible:r.x>=0&&r.right<=innerWidth&&r.y>=0&&r.bottom<=innerHeight&&p.right<=innerWidth};})()`);
 ok(w+'px: nickname controls are visible and fit the settings panel',box.visible);
 await send('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x,y:box.y,button:'left',clickCount:1});await send('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x,y:box.y,button:'left',clickCount:1});
 ok(w+'px: nickname toggle responds to pointer input',await ev(`document.getElementById('a-self-nick-default').getAttribute('aria-checked')==='false'`));
 const modal=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(process.env.COLOR_AUDIT_OUT,'cryptirc-nickname-settings-'+w+'.png'),Buffer.from(modal.data,'base64'));}
}
ok('no runtime exceptions',errors.length===0);
const result={passed:checks.filter(x=>x.pass).length,total:checks.length,themes:themeCount,failed:checks.filter(x=>!x.pass),errors};console.log(JSON.stringify(result));socket.close();if(result.failed.length)process.exitCode=1;
}finally{chrome.kill();await new Promise(resolve=>server.close(resolve));await fs.rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
