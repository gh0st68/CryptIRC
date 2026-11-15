import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';

// Firefox native smoke without WebDriver, X access, or a production dependency.
// Only test-page property setters map validated CDN assets to local fixture bytes.
const root=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-x-firefox-'));
await fs.writeFile(path.join(temp,'user.js'),'user_pref("media.autoplay.default", 0);\nuser_pref("browser.shell.checkDefaultBrowser", false);\n');
const fixture=JSON.parse(await fs.readFile(path.join(root,'src/twitter/fixtures/normalized/video.json'),'utf8'));
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=','base64');
let finish;const result=new Promise(resolve=>finish=resolve);
const bootstrap=`<script>
window.addEventListener('load',async()=>{
 const result={checks:[],agent:navigator.userAgent};const check=(name,value)=>{result.checks.push({name,pass:!!value});if(!value)throw new Error(name);};
 const wait=async predicate=>{for(let i=0;i<100;i++){if(predicate())return;await new Promise(r=>setTimeout(r,40));}throw new Error('Native fixture wait timed out');};
 try{
  const fixture=await(await fetch('/fixture.json')).json();let metadata=0,videoSources=0,assets=0;
  for(const [prototype,key,local] of [[HTMLImageElement.prototype,'src','/fixture.png'],[HTMLMediaElement.prototype,'src','/fixture.mp4'],[HTMLVideoElement.prototype,'poster','/fixture.png']]){
   const descriptor=Object.getOwnPropertyDescriptor(prototype,key);if(!descriptor)continue;
   Object.defineProperty(prototype,key,{...descriptor,set(value){if(String(value).startsWith('https://pbs.twimg.com/')||String(value).startsWith('https://video.twimg.com/')){if(key==='src'&&prototype===HTMLMediaElement.prototype)videoSources++;else assets++;value=local;}descriptor.set.call(this,value);}});
  }
  const originalFetch=window.fetch;window.fetch=(url,options)=>{
   if(String(url).includes('/tweet/preview')){metadata++;return Promise.resolve(new Response(JSON.stringify({...fixture,expires_at:new Date(Date.now()+600000).toISOString()}),{headers:{'Content-Type':'application/json'}}));}
   return originalFetch(url,options);
  };
  sessionToken='test-token';currentUser='firefox-fixture';wsend=()=>{};ensureTweetAccount();setTweetCapabilities({preview:true,thread:false});
  networks=[{config:{id:'fixture',label:'Offline',nick:'viewer'},nick:'viewer',connected:true,channels:[{name:'#test',names:[],topic:''}]}];
  document.getElementById('auth-screen').style.display='none';document.getElementById('app').style.display='flex';
  document.getElementById('vault-overlay')?.classList.remove('show');document.getElementById('boot-splash')?.remove();
  localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),xPreviewMode:'compact',extMedia:'off'}));invalidateAppearCache();setActive('fixture','#test');
  const row=buildRow({id:1,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:true,text:fixture.url},undefined,tweetConversation('fixture','#test'));document.getElementById('chat-area').appendChild(row);
  check('manual default makes zero requests',metadata===0&&assets===0&&videoSources===0);
  row.querySelector('.msg-tweet button').click();await wait(()=>!!row.querySelector('.msg-tweet-name'));
  check('metadata grant leaves media blocked',metadata===1&&assets===0&&videoSources===0);
  row.querySelector('.msg-tweet-header button').click();check('expanded video still has no source',!row.querySelector('video')&&videoSources===0);
  row.querySelector('.msg-tweet-video button').click();await wait(()=>row.querySelector('video')?.readyState>=2||row.textContent.includes('Media unavailable'));
  const player=row.querySelector('video');result.native=player?.readyState>=2?'decoded fixture MP4':'safe native codec fallback';
  check('native playback or explicit fallback',player?.readyState>=2||row.textContent.includes('Media unavailable'));
  if(player){check('native controls and inline playback',player.controls&&player.playsInline);row.querySelector('.msg-tweet-header button').click();check('collapse pauses native playback',player.paused);}
  disposeTweetPreviews(row);check('disposal releases sources',!player||!player.hasAttribute('src'));
  result.ok=true;
 }catch(error){result.ok=false;result.error=String(error);}
 await fetch('/result',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(result)});
});
</script>`;
const server=http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname==='/result'){let text='';for await(const chunk of req)text+=chunk;finish(JSON.parse(text));res.end('ok');return;}
  if(url.pathname==='/fixture.json'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(fixture));return;}
  if(url.pathname==='/fixture.png'){res.setHeader('Content-Type','image/png');res.end(png);return;}
  if(url.pathname==='/fixture.mp4'){res.setHeader('Content-Type','video/mp4');res.end(await fs.readFile(path.join(root,'scripts/fixtures/x-preview.mp4')));return;}
  if(url.pathname.endsWith('/auth/status')){res.setHeader('Content-Type','application/json');res.end('{"registration":"closed","captcha_enabled":false}');return;}
  const name=url.pathname.replace(/^\/cryptirc\//,'')||'index.html',file=path.resolve(root,'static',name);
  if(!file.startsWith(path.join(root,'static')+'/')){res.writeHead(403).end();return;}
  let bytes=await fs.readFile(file);
  if(file.endsWith('index.html'))bytes=Buffer.from(bytes.toString().replace('</body>',bootstrap+'</body>'));
  if(file.endsWith('app.js'))bytes=Buffer.from(bytes.toString().replaceAll('__CRYPTIRC_VERSION__','test').replaceAll('__CRYPTIRC_BUILD__','test').replaceAll('__CRYPTIRC_ASSETS__','test'));
  res.setHeader('Content-Security-Policy',"default-src 'self' data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; media-src 'self'; font-src 'self' data:;");
  res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');res.end(bytes);
 }catch{res.writeHead(404).end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const firefox=spawn(process.env.FIREFOX||'/usr/bin/firefox',['--headless','--no-remote','--profile',temp,'http://127.0.0.1:'+server.address().port+'/cryptirc/'],{stdio:'ignore'});
let timer;
try{
 const report=await Promise.race([result,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Firefox fixture timed out')),20000);})]);
 console.log(JSON.stringify(report,null,2));if(!report.ok)process.exitCode=1;
}finally{clearTimeout(timer);firefox.kill();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
