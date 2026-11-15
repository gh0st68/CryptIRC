// Fresh-install parity: with no X provider configured (GET /tweet/config → nothing offered),
// the ported frontend must render every NON-X link exactly like the base frontend and make
// no X request beyond the capability probe. Offline: every non-local request is failed and
// recorded. Usage:
//   git archive 76dd905 static | tar -x -C /tmp/base76      # the base frontend
//   CRYPTIRC_TEST_BASE_STATIC=/tmp/base76/static node scripts/test-x-previews-parity.mjs
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';

const root=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const baseStatic=process.env.CRYPTIRC_TEST_BASE_STATIC;
if(!baseStatic)throw new Error('Set CRYPTIRC_TEST_BASE_STATIC to the base (76dd905) static/ directory.');
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-x-parity-'));
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function serve(staticRoot,log){
  const server=http.createServer(async(req,res)=>{
    try{
      const url=new URL(req.url,'http://localhost');
      if(url.pathname.startsWith('/cryptirc/tweet/')||url.pathname.startsWith('/cryptirc/preview')||url.pathname.endsWith('/auth/status'))log.push(url.pathname+(url.pathname.endsWith('/preview')?'?'+url.searchParams.get('url'):''));
      if(url.pathname.endsWith('/auth/status')){res.setHeader('Content-Type','application/json');res.end('{"registration":"closed","captcha_enabled":false}');return;}
      if(url.pathname==='/cryptirc/tweet/config'){res.setHeader('Content-Type','application/json');res.end('{"schema_version":1,"preview":false,"thread":false}');return;}
      if(url.pathname.startsWith('/cryptirc/tweet/')){res.writeHead(500).end();return;}
      if(url.pathname==='/cryptirc/preview'){
        const target=url.searchParams.get('url')||'';
        res.setHeader('Content-Type','application/json');
        res.end(JSON.stringify({url:target,domain:new URL(target).hostname,title:'Title for '+new URL(target).hostname,description:'Description',image:null,site_name:null}));return;
      }
      const name=url.pathname.replace(/^\/cryptirc\//,'')||'index.html',file=path.resolve(staticRoot,name);
      if(!file.startsWith(path.resolve(staticRoot)+'/')){res.writeHead(403).end();return;}
      let bytes=await fs.readFile(file);
      if(file.endsWith('app.js'))bytes=Buffer.from(bytes.toString().replaceAll('__CRYPTIRC_VERSION__','test').replaceAll('__CRYPTIRC_BUILD__','test').replaceAll('__CRYPTIRC_ASSETS__','test'));
      res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.json':'application/json','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');res.end(bytes);
    }catch{res.writeHead(404).end();}
  });
  return new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server)));
}

const messages=[
  {kind:'privmsg',text:'plain words, no links at all',encrypted:false},
  {kind:'privmsg',text:'a page https://example.org/article?q=1 here',encrypted:false},
  {kind:'privmsg',text:'encrypted page https://example.net/private',encrypted:true},
  {kind:'privmsg',text:'image https://images.example.com/cat.png',encrypted:false},
  {kind:'privmsg',text:'video https://media.example.com/clip.mp4 and audio https://media.example.com/a.mp3',encrypted:false},
  {kind:'privmsg',text:'yt https://www.youtube.com/watch?v=dQw4w9WgXcQ',encrypted:false},
  {kind:'action',text:'shares http://insecure.example.org/x',encrypted:false},
  {kind:'notice',from:'service',text:'notice https://notice.example.org/n',encrypted:false},
  {kind:'privmsg',text:'mixed https://example.org/one https://x.com/someone/status/123 https://example.org/two',encrypted:false},
  {kind:'privmsg',text:'x only https://twitter.com/a/status/456 and https://x.com/i/web/status/789',encrypted:true},
];

async function render(staticRoot,label){
  const log=[],external=[];
  const server=await serve(staticRoot,log),port=server.address().port;
  const profile=path.join(temp,label);
  const chrome=spawn(process.env.CHROMIUM||'/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0','--user-data-dir='+profile,'--no-first-run','about:blank'],{stdio:'ignore'});
  let socket;
  try{
    let cdpPort;
    for(let i=0;i<100;i++){try{cdpPort=Number((await fs.readFile(profile+'/DevToolsActivePort','utf8')).split('\n')[0]);break;}catch{await sleep(100);}}
    if(!cdpPort)throw new Error('Chromium unavailable; set CHROMIUM.');
    const tabs=await(await fetch('http://127.0.0.1:'+cdpPort+'/json')).json();
    socket=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise(resolve=>socket.onopen=resolve);
    let seq=0;const pending=new Map(),errors=[];
    const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
    socket.onmessage=async event=>{
      const m=JSON.parse(event.data);
      if(m.id){const r=pending.get(m.id);pending.delete(m.id);m.error?r?.reject(m.error):r?.resolve(m.result);}
      if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails);
      if(m.method==='Fetch.requestPaused'){
        const u=new URL(m.params.request.url);
        if(u.origin==='http://127.0.0.1:'+port){await send('Fetch.continueRequest',{requestId:m.params.requestId});return;}
        external.push(u.hostname);await send('Fetch.failRequest',{requestId:m.params.requestId,errorReason:'BlockedByClient'});
      }
    };
    const ev=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
    await send('Runtime.enable');await send('Page.enable');await send('Network.setBypassServiceWorker',{bypass:true});
    await send('Fetch.enable',{patterns:[{urlPattern:'http*',requestStage:'Request'}]});
    await send('Page.navigate',{url:'http://127.0.0.1:'+port+'/cryptirc/'});
    for(let i=0;i<100&&!(await ev("typeof buildRow==='function'&&document.readyState==='complete'"));i++)await sleep(50);
    await ev(`(async()=>{
      sessionToken='test-token';currentUser='parity';
      document.getElementById('auth-screen').style.display='none';document.getElementById('app').style.display='flex';
      ['boot-splash','vault-overlay'].forEach(id=>document.getElementById(id)?.remove());
      networks=[{config:{id:'net',label:'Parity',nick:'viewer'},nick:'viewer',connected:true,channels:[{name:'#public',names:['viewer','author'],topic:''}]}];
      wsend=()=>{};
      localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),linkPreviews:true,extMedia:'all',ytPreview:'auto'}));invalidateAppearCache();
      setActive('net','#public');
      if(typeof refreshTweetCapabilities==='function'){ensureTweetAccount();await refreshTweetCapabilities();}
      return true;})()`);
    const rows=await ev(`(async()=>{
      const area=document.getElementById('chat-area');area.replaceChildren();
      const conv=typeof tweetConversation==='function'?tweetConversation('net','#public'):undefined;
      const msgs=${JSON.stringify(messages)};
      const rows=msgs.map((m,i)=>{const row=buildRow({id:100+i,ts:1700000000+i,from:m.from||'author',...m},undefined,conv);area.appendChild(row);return row;});
      await new Promise(r=>setTimeout(r,600));
      // Random ids (link-preview / YouTube uids) are not behaviour.
      // Random ids (link-preview / YouTube uids) and the invisible X slot markers are not behaviour.
      return rows.map(r=>r.outerHTML.replace(/<!--x-link-->/g,'').replace(/lp-[a-z0-9]+/g,'lp-ID').replace(/yt-([tdm])-[A-Za-z0-9_-]+?_\\d+_\\d+/g,'yt-$1-ID'));
    })()`);
    return {rows,log,external:external.sort(),errors,tweetCards:await ev("document.querySelectorAll('.msg-tweet').length")};
  }finally{socket?.close();chrome.kill();await new Promise(resolve=>server.close(resolve));}
}

const base=await render(baseStatic,'base');
const port=await render(path.join(root,'static'),'port');
const checks=[];const ok=(name,value)=>{checks.push({name,pass:!!value});assert(value,name);};
const isX=text=>/https:\/\/(x|twitter)\.com\//.test(text);
// Unconfigured server (audit fix): EVERY row, X links included, renders exactly as v0.5.8 —
// X links keep their generic preview and the encrypted click-to-load gate.
messages.forEach((m,i)=>{
  if(base.rows[i]!==port.rows[i])console.error('DIFF row',i,'\nBASE',base.rows[i],'\nPORT',port.rows[i]);
  ok(`${isX(m.text)?'X':'non-X'} row ${i} (${m.kind}) renders identically`,base.rows[i]===port.rows[i]);
});
ok('no X card on an unconfigured server',port.tweetCards===0);
const portPreviews=port.log.filter(l=>l.startsWith('/cryptirc/preview')),basePreviews=base.log.filter(l=>l.startsWith('/cryptirc/preview'));
// Same requests (as a set: an X link's generic card is built right after the message's other
// media, so within one message its fetch may be issued a moment later; the DOM order is identical).
ok('generic /preview requests identical (X links included, as v0.5.8)',JSON.stringify([...portPreviews].sort())===JSON.stringify([...basePreviews].sort()));
ok('only the capability probe touches /tweet',port.log.filter(l=>l.startsWith('/cryptirc/tweet/')).every(l=>l==='/cryptirc/tweet/config'));
ok('third-party requests identical (none to X hosts)',JSON.stringify(port.external)===JSON.stringify(base.external)&&!port.external.some(h=>/(^|\.)(x\.com|twitter\.com|twimg\.com|threadreaderapp\.com)$/.test(h)));
ok('no runtime exceptions',!port.errors.length&&!base.errors.length);
console.log(JSON.stringify({checks,base_preview_requests:basePreviews,port_preview_requests:portPreviews,port_tweet_requests:port.log.filter(l=>l.startsWith('/cryptirc/tweet/')),external:port.external},null,2));
