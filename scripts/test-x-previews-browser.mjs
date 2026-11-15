import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';

const root=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'cryptirc-x-previews-'));
const fixtures=await Promise.all(['text-only','multiple-photo','video','animated-gif','quoted-post','long-post','missing-engagement','restricted']
  .map(async name=>JSON.parse(await fs.readFile(path.join(root,'src/twitter/fixtures/normalized',name+'.json'),'utf8'))));
const counts={generic:0,generic_fallback:0,generic_unconfigured:0,config:0,preview:0,thread:0,assets:0,video:0,video_referer:0,proxy:0,sign:0,blocked:0,unexpected:0,x_hosts:0};
const video=await fs.readFile(path.join(root,'scripts/fixtures/x-preview.mp4'));
const png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
let delay=0,signDelay=0,genericDelay=0,configFail=false,threadEnabled=false,previewEnabled=true,failureCode=null,blockDirectMedia=false;
const server=http.createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,'http://localhost');
    if(url.pathname.endsWith('/auth/status')){res.setHeader('Content-Type','application/json');res.end('{"registration":"closed","captcha_enabled":false}');return;}
    if(url.pathname.endsWith('/tweet/config')){
      counts.config++;if(configFail){res.writeHead(500).end();return;}assert.equal(req.headers.authorization,'Bearer test-token');
      res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','private, no-store');
      res.end(JSON.stringify({schema_version:1,preview:previewEnabled,thread:previewEnabled&&threadEnabled}));return;
    }
    if(url.pathname.endsWith('/tweet/preview')){
      counts.preview++;assert.equal(req.headers.authorization,'Bearer test-token');
      assert([...url.searchParams.keys()].every(k=>['url','refresh'].includes(k)));
      if(failureCode){res.writeHead(503,{'Content-Type':'application/json'}).end(JSON.stringify({schema_version:1,error:{code:failureCode,retryable:true,retry_after_seconds:null}}));return;}
      const id=url.searchParams.get('url')?.split('/').at(-1);
      const found=fixtures.find(f=>f.id===id)||{...fixtures[0],id,url:'https://x.com/i/status/'+id};
      if(delay)await new Promise(r=>setTimeout(r,delay));
      res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','private, no-store');
      res.end(JSON.stringify({...found,thread:threadEnabled?{state:'unknown',provider:'threadreader',count:null}:found.thread,fetched_at:new Date().toISOString(),expires_at:new Date(Date.now()+600000).toISOString()}));return;
    }
    if(url.pathname.endsWith('/tweet/media/sign')){
      counts.sign++;assert.equal(req.headers.authorization,'Bearer test-token');if(signDelay)await new Promise(r=>setTimeout(r,signDelay));
      let body='';for await(const chunk of req)body+=chunk;
      const parsed=JSON.parse(body);
      res.setHeader('Content-Type','application/json');
      res.end(JSON.stringify({urls:parsed.urls.map(u=>({url:u,proxy_url:'/cryptirc/tweet/media?url='+encodeURIComponent(u)+'&exp=9999999999&sig=test'})),expires_in:900}));return;
    }
    if(url.pathname.endsWith('/tweet/media')){
      counts.proxy++;const target=url.searchParams.get('url')||'',isVideo=target.includes('video.twimg.com');
      res.setHeader('Content-Type',isVideo?'video/mp4':'image/png');res.setHeader('Accept-Ranges','bytes');
      res.end(isVideo?video:Buffer.from(png,'base64'));return;
    }
    if(url.pathname.endsWith('/tweet/thread')){
      counts.thread++;const id=url.searchParams.get('url')?.split('/').at(-1);
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify({schema_version:1,root_id:id,provider:'threadreader',availability:{state:'available',reason:null},
        partial:true,reported_count:30,continuation_url:'https://x.com/i/status/'+id,fetched_at:new Date().toISOString(),expires_at:new Date(Date.now()+300000).toISOString(),
        entries:Array.from({length:20},(_,i)=>({key:`tra:${id}:${i}`,id:null,url:null,author:null,created_at:null,text:'Thread entry '+i,entities:[],media:[],metrics:{}}))}));return;
    }
    if(url.pathname==='/cryptirc/preview'){
      if(!previewEnabled&&!configFail){counts.generic_unconfigured++;res.writeHead(404).end();return;}
      if(!configFail){counts.generic++;res.writeHead(404).end();return;}
      counts.generic_fallback++;if(genericDelay)await new Promise(r=>setTimeout(r,genericDelay));
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify({url:url.searchParams.get('url'),domain:'x.com',title:'Generic X title',description:'d',image:'https://pbs.twimg.com/media/og.jpg',site_name:'X'}));return;
    }
    const name=url.pathname.replace(/^\/cryptirc\//,'')||'index.html';
    const file=path.resolve(root,'static',name);if(!file.startsWith(path.join(root,'static')+'/')){res.writeHead(403).end();return;}
    let bytes=await fs.readFile(file);
    if(file.endsWith('app.js'))bytes=Buffer.from(bytes.toString().replaceAll('__CRYPTIRC_VERSION__','test').replaceAll('__CRYPTIRC_BUILD__','test').replaceAll('__CRYPTIRC_ASSETS__','test'));
    res.setHeader('Content-Type',({'.html':'text/html','.js':'application/javascript','.json':'application/json','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream');res.end(bytes);
  }catch{res.writeHead(404).end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
const chrome=spawn(process.env.CHROMIUM||'/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0','--user-data-dir='+temp+'/profile','--no-first-run','about:blank'],{stdio:'ignore'});
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const checks=[],screenshots=[];let socket;
try{
  let cdpPort;
  for(let i=0;i<100;i++){try{cdpPort=Number((await fs.readFile(temp+'/profile/DevToolsActivePort','utf8')).split('\n')[0]);break;}catch{await sleep(100);}}
  if(!cdpPort)throw new Error('Chromium unavailable; set CHROMIUM.');
  const tabs=await(await fetch('http://127.0.0.1:'+cdpPort+'/json')).json();
  socket=new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise(resolve=>socket.onopen=resolve);
  let seq=0;const pending=new Map(),errors=[];
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params}));});
  socket.onmessage=async event=>{
    const message=JSON.parse(event.data);
    if(message.id){const request=pending.get(message.id);pending.delete(message.id);message.error?request?.reject(message.error):request?.resolve(message.result);}
    if(message.method==='Runtime.exceptionThrown')errors.push(message.params.exceptionDetails);
    if(message.method==='Fetch.requestPaused'){
      const p=message.params,url=new URL(p.request.url);
      if(url.origin==='http://127.0.0.1:'+port){await send('Fetch.continueRequest',{requestId:p.requestId});return;}
      if(['pbs.twimg.com','video.twimg.com'].includes(url.hostname)){
        if(blockDirectMedia){counts.blocked++;await send('Fetch.failRequest',{requestId:p.requestId,errorReason:'BlockedByClient'});return;}
        counts.assets++;const isVideo=url.hostname==='video.twimg.com';if(isVideo)counts.video++;
        if(isVideo&&Object.keys(p.request.headers).some(k=>k.toLowerCase()==='referer'))counts.video_referer++;
        await send('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:isVideo?'video/mp4':'image/png'}],body:isVideo?video.toString('base64'):png});
      }else{counts.unexpected++;if(/(^|\.)(x\.com|twitter\.com|t\.co|threadreaderapp\.com)$/.test(url.hostname))counts.x_hosts++;await send('Fetch.failRequest',{requestId:p.requestId,errorReason:'BlockedByClient'});}
    }
  };
  const ev=async expression=>{const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
  const ok=(name,value)=>{checks.push({name,pass:!!value});assert(value,name);};
  const wait=async expression=>{for(let i=0;i<100;i++){if(await ev(expression))return;await sleep(30);}throw new Error('Timed out: '+expression);};
  await send('Runtime.enable');await send('Page.enable');await send('Network.enable');await send('Network.setBypassServiceWorker',{bypass:true});
  await send('Fetch.enable',{patterns:[{urlPattern:'http*',requestStage:'Request'}]});
  await send('Page.navigate',{url:'http://127.0.0.1:'+port+'/cryptirc/'});
  await wait("typeof buildTweetPlaceholder==='function'&&document.readyState==='complete'");
  const setup=`(()=>{
    clearTweetData();sessionToken='test-token';currentUser='test-account';
    document.getElementById('auth-screen').style.display='none';document.getElementById('app').style.display='flex';
    ['boot-splash','vault-overlay'].forEach(id=>document.getElementById(id)?.remove());
    networks=[{config:{id:'fixture',label:'Offline previews',nick:'viewer'},nick:'viewer',connected:true,
      channels:[{name:'#public',names:['viewer','author'],topic:'Offline X preview fixtures'},{name:'#other',names:[],topic:''}]}];
    window.__wire=[];wsend=data=>window.__wire.push(data);
    localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),xPreviewMode:'compact',extMedia:'off',linkPreviews:true}));invalidateAppearCache();
    setActive('fixture','#public');setXDisclosure('manual');window.__wire=[];return true;
  })()`;
  const caps=()=>ev('refreshTweetCapabilities().then(()=>JSON.stringify(_tweetCaps))');
  await ev(setup);await caps();
  ok('server capabilities enable the X branch',await ev('_tweetCaps.preview===true&&_tweetCaps.thread===false'));
  ok('default policy auto-loads public previews and defaults expanded',await ev("normalizeXPolicy(null).load==='auto_public'&&APPEAR_DEFAULTS.xPreviewMode==='expanded'"));
  await ev("openLightbox('/cryptirc/icon-192.png')");await wait("document.getElementById('lightbox-img').naturalWidth>0");
  await ev("toggleLightboxZoom({stopPropagation(){}});navigateLightbox(1)");
  ok('legacy single-image viewer keeps zoom and close behavior',await ev("_lbZoom===3&&_lbItems.length===1"));
  await ev("closeLightbox()");
  const mount=(id,extra='')=>ev(`(()=>{const row=buildRow({id:${JSON.stringify(id)},ts:Date.now()/1000,from:'author',text:'https://x.com/author/status/${id}',kind:'privmsg',encrypted:true},undefined,tweetConversation('fixture','#public'));document.getElementById('chat-area').appendChild(row);${extra}return true;})()`);
  const mountPublic=(id,extra='')=>ev(`(()=>{const row=buildRow({id:${JSON.stringify(id)},ts:Date.now()/1000,from:'author',text:'https://x.com/author/status/${id}',kind:'privmsg',encrypted:false},undefined,tweetConversation('fixture','#public'));document.getElementById('chat-area').appendChild(row);${extra}return true;})()`);
  await mount(fixtures[0].id);await sleep(100);
  ok('default encrypted mount makes no metadata/assets requests',counts.preview===0&&counts.assets===0);
  ok('mixed message media retain source order',await ev(`(()=>{const row=buildRow({id:60001,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:true,
    text:'https://x.com/a/status/551 '+location.origin+'/cryptirc/icon-192.png'},undefined,tweetConversation('fixture','#public'));
    document.getElementById('chat-area').appendChild(row);const x=row.querySelector('.msg-tweet'),image=row.querySelector('.msg-media');
    const ordered=!!(x.compareDocumentPosition(image)&Node.DOCUMENT_POSITION_FOLLOWING);disposeTweetPreviews(row);row.remove();return ordered;})()`));
  ok('extra X links mount in explicit batches of three',await ev(`(()=>{const row=buildRow({id:60002,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:true,
    text:[1,2,3,4,5].map(id=>'https://x.com/a/status/'+id).join(' ')},undefined,tweetConversation('fixture','#public'));
    document.getElementById('chat-area').appendChild(row);const first=row.querySelectorAll('.msg-tweet').length;row.querySelector('.msg-tweet-more-links').click();
    const pass=first===3&&row.querySelectorAll('.msg-tweet').length===5;disposeTweetPreviews(row);row.remove();return pass;})()`));
  await ev(`(()=>{for(const conv of [tweetConversation('fixture','#public'),tweetConversation('fixture','private_nick'),undefined]){
    const row=buildRow({ts:Date.now()/1000,from:'author',text:'https://x.com/a/status/555',kind:'privmsg',encrypted:false},undefined,conv);document.getElementById('chat-area').appendChild(row);}
    return true;})()`);await sleep(50);
  ok('public DM and unknown contexts also default to manual',counts.preview===0&&counts.assets===0);
  await ev("[...document.querySelectorAll('.msg-row')].slice(1).forEach(r=>{disposeTweetPreviews(r);r.remove()})");
  await ev("document.querySelector('.msg-tweet-button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  ok('manual load fetches once and assets stay blocked',counts.preview===1&&counts.assets===0);
  ok('HTML-looking text stays literal',await ev("!document.querySelector('.msg-tweet script')&&document.querySelector('.msg-tweet-text').textContent.includes('<script>')"));
  await ev("window.__modeButton=document.querySelector('.msg-tweet-header button');window.__modeButton.focus()");
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
  await send('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  const keyboardState=await ev("({expanded:window.__modeButton.getAttribute('aria-expanded'),focused:document.activeElement===window.__modeButton,tag:document.activeElement?.tagName,text:window.__modeButton.textContent})");
  if(keyboardState.expanded!=='true'||!keyboardState.focused)console.error('Keyboard state:',keyboardState);
  ok('keyboard mode activation preserves focus and ARIA state',keyboardState.expanded==='true'&&keyboardState.focused&&counts.preview===1);
  await ev("window.__modeButton.click()");
  await mount(fixtures[0].id);await sleep(60);ok('cached encrypted mount still needs consent',await ev("document.querySelectorAll('.msg-tweet-dormant').length===1")&&counts.preview===1);
  await ev("document.querySelector('.msg-tweet-dormant button').click()");await wait("document.querySelectorAll('.msg-tweet-name').length===2");
  ok('authorized cache reuse makes no request',counts.preview===1);
  await ev("disposeTweetPreviews(document.getElementById('chat-area'));document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[1].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  await ev("document.querySelector('.msg-tweet-header button').click()");
  ok('four-photo gallery mounts without blocked src attributes',await ev("document.querySelectorAll('.msg-tweet-gallery .msg-tweet-photo').length===4&&!document.querySelector('.msg-tweet img[src]')"));
  await ev("[...document.querySelectorAll('.msg-tweet-button')].find(b=>b.textContent.startsWith('Load external media')).click()");
  await wait("document.querySelectorAll('.msg-tweet-gallery img[src]').length===4");
  ok('original-size photo is not assigned before viewer activation',await ev("[...document.querySelectorAll('.msg-tweet img[src]')].every(i=>!i.src.includes('name=orig'))"));
  await ev("document.querySelectorAll('.msg-tweet-gallery button')[2].click()");
  ok('third photo opens at its own gallery index',await ev("_lbIndex===2&&document.getElementById('lightbox-img').src.includes('name=orig')"));
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowRight'});ok('gallery arrow navigation',await ev('_lbIndex===3'));
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape'});
  ok('viewer closes, releases source, restores focus',await ev("!document.getElementById('lightbox-img').hasAttribute('src')&&document.activeElement===document.querySelectorAll('.msg-tweet-gallery button')[2]"));
  for(const [width,height] of [[320,640],[390,844],[768,1024],[1440,900]]){
    await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<768});
    for(const theme of ['dark','light']){
      // Persist the theme (a viewport change re-applies the saved appearance) and confirm it took.
      const themeId=theme==='light'?'ivory':'discord';
      await ev(`(()=>{const cfg={...loadAppearance(),theme:${JSON.stringify(themeId)}};localStorage.setItem('cryptirc_appear',JSON.stringify(cfg));invalidateAppearCache();applyThemeCSS(loadAppearance());document.getElementById('chat-area').scrollTop=0;return true;})()`);await sleep(350);
      ok(`${width}px ${theme}: theme applied`,await ev(`getComputedStyle(document.documentElement).getPropertyValue('--bg0').trim().toLowerCase()===THEMES[${JSON.stringify(themeId)}].bg0.toLowerCase()`));
      ok(`${width}px ${theme}: card fits`,await ev("(()=>{const c=document.querySelector('.msg-tweet'),r=c.getBoundingClientRect();return r.width<=520&&r.right<=innerWidth+1&&c.scrollWidth<=c.clientWidth+1;})()"));
      const name=`x-${width}-${theme}.png`,shot=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(temp,name),Buffer.from(shot.data,'base64'));screenshots.push(path.join(temp,name));
    }
  }
  await ev("disposeTweetPreviews(document.getElementById('chat-area'));document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[2].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  await ev("document.querySelector('.msg-tweet-header button').click()");ok('video has no source or player before Play',await ev("!document.querySelector('.msg-tweet video')")&&counts.video===0);
  await ev("[...document.querySelectorAll('.msg-tweet-video button')][0].click()");await wait("!!document.querySelector('.msg-tweet video[src]')");
  await wait("document.querySelector('.msg-tweet video').readyState>=2");
  ok('native video is created only after Play',counts.video<=1&&await ev("document.querySelector('.msg-tweet video').controls&&document.querySelector('.msg-tweet video').playsInline"));
  ok('video requests carry no referrer',counts.video_referer===0);
  await ev("document.querySelector('.msg-tweet-header button').click()");ok('collapse pauses playback',await ev("document.querySelector('.msg-tweet video').paused"));
  const beforeHiddenError=counts.video;
  await ev("window.__removedPlayer=document.querySelector('.msg-tweet video');window.__removedPlayer.dispatchEvent(new Event('error'))");await sleep(40);
  ok('a late playback error cannot restart collapsed video',counts.video===beforeHiddenError&&await ev("!window.__removedPlayer.hasAttribute('src')"));
  await ev("document.querySelector('.msg-row').remove()");await sleep(40);
  ok('removing a card releases native sources',await ev("!window.__removedPlayer.hasAttribute('src')&&_tweetCards.size===0"));
  blockDirectMedia=true;
  await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[2].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  await ev("document.querySelector('.msg-tweet-header button').click()");await ev("document.querySelector('.msg-tweet-video button').click()");
  await wait("!!document.querySelector('.msg-tweet video')");
  await wait("(document.querySelector('.msg-tweet video').src||'').includes('/tweet/media')&&document.querySelector('.msg-tweet video').readyState>=2");
  ok('blocked direct media falls back to the signed proxy',counts.blocked>0&&counts.sign>0&&counts.proxy>0&&await ev("document.querySelector('.msg-tweet video').src.includes('/tweet/media')"));
  await ev("closeLightbox();clearTweetData();document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[1].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  await ev("[...document.querySelectorAll('.msg-tweet-button')].find(b=>b.textContent.startsWith('Load external media'))?.click()");await sleep(50);
  await ev("document.querySelector('.msg-tweet-header button').click()");await wait("document.querySelectorAll('.msg-tweet-gallery button').length>=3");
  await ev("document.querySelectorAll('.msg-tweet-gallery button')[2].click()");
  await wait("document.getElementById('lightbox-img').src.includes('/tweet/media')&&document.getElementById('lightbox-img').naturalWidth>0");
  ok('blocked lightbox image falls back to the signed proxy',await ev("document.getElementById('lightbox-img').src.includes('/tweet/media')"));
  await ev("closeLightbox()");
  blockDirectMedia=false;
  await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");
  for(const fixture of fixtures){
    await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");
    await mount(fixture.id);await ev("document.querySelector('.msg-tweet button').click()");await wait("document.querySelector('.msg-tweet')?.getAttribute('aria-busy')==='false'");
    ok('normalized fixture '+fixture.id+' renders safely',await ev("!document.querySelector('.msg-tweet script,.msg-tweet iframe')&&!!document.querySelector('.msg-tweet')"));
    if(fixture.id===fixtures[0].id){
      await ev("document.querySelector('.msg-tweet-header button').click()");
      ok('all-available metrics need no availability control',await ev("!document.querySelector('.msg-tweet-info')"));
      ok('disabled thread provider leaves no thread row',await ev("!document.querySelector('.msg-tweet-thread')"));
      ok('card actions are icon-only',await ev("document.querySelector('.msg-tweet-actions').textContent.trim()===''&&!!document.querySelector('.msg-tweet-actions .msg-tweet-icon-link')"));
    }
    if(fixture.id===fixtures[6].id){
      await ev("document.querySelector('.msg-tweet-header button').click()");
      ok('missing metrics expose a compact availability disclosure',await ev("!!document.querySelector('.msg-tweet-info')&&document.querySelector('.msg-tweet-info summary').getAttribute('aria-label')==='Metric availability'"));
    }
    if(fixture.quote?.state==='available'){
      const before=counts.preview;await ev("document.querySelector('.msg-tweet-header button').click()");await wait("!!document.querySelector('.msg-tweet-quote .msg-tweet-name')");
      ok('supplied quote renders without another request',counts.preview===before);
    }
    if(fixture.id===fixtures[3].id){
      await ev("document.querySelector('.msg-tweet-header button').click();document.querySelector('.msg-tweet-video button').click()");await wait("document.querySelector('.msg-tweet video')?.readyState>=2");
      ok('GIF playback is explicitly activated muted and looping',await ev("document.querySelector('.msg-tweet video').muted&&document.querySelector('.msg-tweet video').loop"));
    }
    if(fixture.id===fixtures[5].id){
      const before=counts.preview;await ev("document.querySelector('.msg-tweet-header button').click()");
      await wait("[...document.querySelectorAll('.msg-tweet > button')].some(b=>b.textContent==='Show more text'&&!b.hidden)");
      await ev("[...document.querySelectorAll('.msg-tweet > button')].find(b=>b.textContent==='Show more text').click()");
      ok('long text expands independently without refetch',counts.preview===before&&await ev("document.querySelector('.msg-tweet-text').classList.contains('msg-tweet-text-open')"));
    }
  }
  threadEnabled=true;await caps();await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[0].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  await ev("document.querySelector('.msg-tweet-header button').click()");ok('expansion never retrieves thread',counts.thread===0);
  await ev("[...document.querySelectorAll('.msg-tweet-thread button')].find(b=>b.textContent==='Read thread…').click()");
  ok('thread consent precedes provider request',counts.thread===0&&await ev("document.querySelector('.msg-tweet-thread-consent').textContent.includes('receives the post ID')"));
  await ev("[...document.querySelectorAll('.msg-tweet-thread-consent button')].find(b=>b.textContent==='Fetch thread').click()");await wait("document.querySelectorAll('.msg-tweet-thread-entry').length===5");
  ok('thread initially shows five unknown-identity entries',counts.thread===1&&await ev("[...document.querySelectorAll('.msg-tweet-thread-entry')].every(e=>e.textContent.includes('Author unavailable')&&e.textContent.includes('identity unavailable'))"));
  await ev("[...document.querySelectorAll('.msg-tweet-thread-content button')].find(b=>b.textContent==='Show more posts').click()");
  await ev("[...document.querySelectorAll('.msg-tweet-thread > button')][0].click();[...document.querySelectorAll('.msg-tweet-thread > button')][0].click()");
  ok('thread reopens with ten entries without refetch',counts.thread===1&&await ev("document.querySelectorAll('.msg-tweet-thread-entry').length===10"));
  await ev("[...document.querySelectorAll('.msg-tweet-thread-content button')].find(b=>b.textContent==='Show more posts').click();[...document.querySelectorAll('.msg-tweet-thread-content button')].find(b=>b.textContent==='Show more posts').click()");
  ok('thread remains capped at twenty with local batches',counts.thread===1&&await ev("document.querySelectorAll('.msg-tweet-thread-entry').length===20"));
  threadEnabled=false;await caps();
  await ev("clearTweetData();setActive('fixture','#public');document.getElementById('chat-area').replaceChildren()");
  await mount(fixtures[1].id);
  await ev(`(()=>{const area=document.getElementById('chat-area');for(let i=0;i<100;i++)area.appendChild(buildRow({id:900+i,ts:Date.now()/1000,from:'author',kind:'privmsg',text:'History row '+i,encrypted:false},undefined,tweetConversation('fixture','#public')));
    area.scrollTop=450;_userScrolledAway=true;_jumpAnchor=true;_jumpAnchorBk=bk('fixture','#public');
    return true;})()`);await sleep(80);
  const anchor=await ev("(()=>{const s=captureTweetLayout();window.__anchorRow=s.row;return s.top;})()");
  await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");await sleep(80);
  ok('metadata above viewport preserves row within 2px',Math.abs(await ev('window.__anchorRow.getBoundingClientRect().top')-anchor)<=2);
  await ev("document.querySelector('.msg-tweet-header button').click()");await sleep(80);
  ok('mode expansion preserves history anchor within 2px',Math.abs(await ev('window.__anchorRow.getBoundingClientRect().top')-anchor)<=2);
  await ev("document.querySelector('.msg-tweet-header button').focus({preventScroll:true})");
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:' ',code:'Space',windowsVirtualKeyCode:32,text:' '});
  await send('Input.dispatchKeyEvent',{type:'keyUp',key:' ',code:'Space',windowsVirtualKeyCode:32});await sleep(50);
  ok('Space activation preserves the history anchor',await ev('_jumpAnchor')&&Math.abs(await ev('window.__anchorRow.getBoundingClientRect().top')-anchor)<=2);
  await ev("if(!document.querySelector('.msg-tweet')._tweetState.expanded)document.querySelector('.msg-tweet-header button').click()");await sleep(50);
  await ev("[...document.querySelectorAll('.msg-tweet-button')].find(b=>b.textContent.startsWith('Load external media')).click()");await sleep(120);
  ok('media size change preserves history anchor within 2px',Math.abs(await ev('window.__anchorRow.getBoundingClientRect().top')-anchor)<=2);
  ok('preview scroll compensation preserves reading flags',await ev('_userScrolledAway&&_jumpAnchor'));
  await ev("clearTweetData();_jumpAnchor=false;_jumpAnchorBk=null;setActive('fixture','#public')");
  const beforeHidden=counts.preview;
  await ev("localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),linkPreviews:false}));invalidateAppearCache()");
  await mount('888');await sleep(50);ok('global preview disable suppresses X branch without generic fallback',counts.preview===beforeHidden&&await ev("!document.querySelector('.msg-tweet')"));
  await ev("localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),linkPreviews:true}));invalidateAppearCache()");
  const beforeMode=counts.preview;
  await ev("setTweetPreviewMode('expanded')");ok('presentation mode persists without retrieval',counts.preview===beforeMode&&await ev("loadAppearance().xPreviewMode==='expanded'"));
  await ev("setTweetPreviewMode('compact');resetXDisclosure();setXDisclosure('auto_public')");
  const beforeSensitive=counts.preview;await mount('991');await sleep(100);
  ok('auto-public still leaves encrypted messages manual',counts.preview===beforeSensitive&&await ev("!!document.querySelector('.msg-tweet-dormant')"));
  await ev("setXConversationDisclosure('auto')");await wait("[..._tweetCards].some(s=>s.id==='991'&&s.loaded)");
  ok('explicit conversation opt-in enables encrypted preview',counts.preview>beforeSensitive);
  const privacy=await ev("(()=>{const key='cryptirc_x_policy_v1:'+currentUser;const raw=localStorage.getItem(key);return {raw,sync:JSON.stringify(gatherPreferences()),wire:JSON.stringify(window.__wire)};})()");
  ok('disclosure store is absent from preferences and appearance sync',!privacy.sync.includes('auto_public')&&!privacy.wire.includes('cryptirc_x_policy_v1')&&!privacy.wire.includes('conversations'));
  await ev("setXDisclosure('hidden')");ok('revocation disposes previews and purges cache',await ev('_tweetCards.size===0&&_tweetCache.size===0&&_tweetPending.size===0'));
  await ev("resetXDisclosure();currentUser='second-account';ensureTweetAccount()");
  ok('account change forgets server capabilities until re-asked',await ev("_tweetCaps.preview===false&&tweetLoadPolicy(tweetPreviewContext('fixture','#public',false))==='hidden'"));
  await caps();ok('second account inherits no auto permission',await ev("tweetLoadPolicy(tweetPreviewContext('fixture','#public',true))==='manual'"));
  await ev("currentUser='test-account';ensureTweetAccount();resetXDisclosure()");await caps();
  await ev("setTweetPreviewMode('expanded');clearTweetData();document.getElementById('chat-area').replaceChildren()");
  const autoBefore=counts.preview;
  await mountPublic(fixtures[0].id);
  await wait("[..._tweetCards].some(s=>s.id==='"+fixtures[0].id+"'&&s.loaded)");
  ok('public unencrypted previews auto-load expanded without a click',counts.preview===autoBefore+1&&await ev("(()=>{const s=[..._tweetCards].find(s=>s.id==='"+fixtures[0].id+"');const c=s.root;return s.expanded===true&&c.classList.contains('msg-tweet-expanded')&&!c.querySelector('.msg-tweet-dormant')&&!!c.querySelector('.msg-tweet-header button');})()"));
  await ev("setXDisclosure('manual');setTweetPreviewMode('compact');clearTweetData();document.getElementById('chat-area').replaceChildren()");
  const benchmarkFixture=JSON.stringify({...fixtures[0],author:null,media:[],quote:{state:'none'}});
  const timings=await ev(`(()=>{clearTweetData();const area=document.getElementById('chat-area');area.replaceChildren();const samples=[];
    for(let batch=0;batch<5;batch++){const start=performance.now();const nodes=[];
      for(let i=0;i<20;i++){const data={...${benchmarkFixture}},node=buildTweetPlaceholder({id:data.id,url:data.url},tweetPreviewContext('fixture','#public',false));
        area.appendChild(node);node.replaceChildren();node._tweetState.granted=true;buildTweetCard(data,node._tweetState,()=>{});nodes.push(node);}
      samples.push(performance.now()-start);for(const node of nodes){disposeTweetPreviews(node);node.remove();}}
    return samples;})()`);
  ok('20-card insertion batches target under 50ms',Math.max(...timings)<50);
  delay=80;
  await ev(`(()=>{clearTweetData();const area=document.getElementById('chat-area');area.replaceChildren();
    localStorage.setItem('cryptirc_x_policy_v1:'+currentUser,JSON.stringify({version:1,load:'auto_public',conversations:{}}));
    const fragment=document.createDocumentFragment();for(let i=0;i<1000;i++)fragment.appendChild(buildRow({id:10000+i,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,
      text:'https://x.com/author/status/'+(7000000000000000n+BigInt(i%100))},undefined,tweetConversation('fixture','#public')));
    area.appendChild(fragment);area.scrollTop=area.scrollHeight/2;_userScrolledAway=true;_jumpAnchor=false;
    window.__autoAudit=[];const original=window.fetch;window.fetch=(url,options)=>{
      if(String(url).includes('/tweet/preview')){const id=new URL(url,location.href).searchParams.get('url').split('/').at(-1);
        window.__autoAudit.push([..._tweetCards].some(s=>s.id===id&&tweetLoadPolicy(s.context)==='auto'&&tweetWithinViewport(s.root)));}
      return original(url,options);};return true;})()`);
  const work=[];for(let i=0;i<10;i++){await sleep(60);work.push(await ev('({active:_tweetActive,queued:_tweetQueue.length,pending:_tweetPending.size,cache:_tweetCache.size,bytes:_tweetCacheBytes})'));}
  const audit=await ev('window.__autoAudit');
  ok('1,000 messages and 100 IDs disclose only near-viewport posts',audit.length>0&&audit.every(Boolean)&&audit.length<100);
  ok('history scheduling stays within active queue and cache limits',work.every(s=>s.active<=3&&s.queued<=50&&s.cache<=200&&s.bytes<=8*1024*1024));
  await ev("resetXDisclosure();setActive('fixture','#other')");await sleep(120);delay=0;
  const beforeAliases=counts.preview;
  await ev(`(()=>{setXDisclosure('manual');const area=document.getElementById('chat-area');area.replaceChildren();
    const urls=['https://x.com/a/status/8123','https://www.x.com/b/status/8123/','https://mobile.x.com/i/status/8123',
      'https://twitter.com/c/status/8123/photo/1','https://www.twitter.com/d/status/8123/video/2','https://mobile.twitter.com/e/status/8123?private=drop',
      'https://m.twitter.com/f/status/8123','https://x.com/i/web/status/8123','https://x.com/g/status/8123#drop','https://x.com/h/status/8123'];
    for(let i=0;i<10;i++)area.appendChild(buildRow({id:20000+i,ts:Date.now()/1000,from:'author',kind:'privmsg',text:urls[i],encrypted:false},undefined,tweetConversation('fixture','#other')));
    for(const button of area.querySelectorAll('.msg-tweet button'))button.click();return true;})()`);
  await wait("document.querySelectorAll('.msg-tweet-name').length===10");ok('ten URL aliases make one browser API request',counts.preview===beforeAliases+1);
  const galleryGeometry=await ev(`(()=>{clearTweetData();const area=document.getElementById('chat-area');area.replaceChildren();const results=[];
    for(const count of [1,2,3]){const data=${JSON.stringify(fixtures[1])};data.media=data.media.slice(0,count);
      const root=buildTweetPlaceholder({id:data.id,url:data.url},tweetPreviewContext('fixture','#other',false));area.appendChild(root);root.replaceChildren();
      root._tweetState.granted=true;root._tweetState.expanded=true;buildTweetCard(data,root._tweetState,()=>{});
      const cells=[...root.querySelectorAll('.msg-tweet-gallery .msg-tweet-photo')].map(n=>{const r=n.getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height};});results.push({count,cells});}
    return results;})()`);
  ok('one two and three photo layouts retain intended geometry',galleryGeometry.every(g=>g.cells.length===g.count&&g.cells.every(c=>c.w>0&&c.h>0))
    &&galleryGeometry[1].cells[0].y===galleryGeometry[1].cells[1].y&&galleryGeometry[2].cells[0].h>galleryGeometry[2].cells[1].h);
  await send('Emulation.setDeviceMetricsOverride',{width:320,height:640,deviceScaleFactor:1,mobile:true});
  await ev("applyThemeCSS({...loadAppearance(),theme:'ivory',chatSize:26,mobileChatSize:30});document.querySelector('.msg-tweet-name').textContent='اسم طويل جدا '.repeat(30)");
  ok('long RTL names and 200% chat text stay in the card',await ev("[...document.querySelectorAll('.msg-tweet')].every(n=>n.scrollWidth<=n.clientWidth+1&&n.getBoundingClientRect().right<=innerWidth+1)"));
  await ev("clearTweetData();applyThemeCSS(loadAppearance());document.getElementById('chat-area').replaceChildren()");
  const beforeNoObserver=counts.preview;
  await ev(`(()=>{window.__savedIO=window.IntersectionObserver;window.IntersectionObserver=undefined;setXDisclosure('auto_public');
    const row=buildRow({id:30001,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,text:'https://x.com/a/status/8901'},undefined,tweetConversation('fixture','#public'));
    document.getElementById('chat-area').appendChild(row);return true;})()`);await sleep(100);
  ok('missing viewport observation retains a manual fallback',counts.preview===beforeNoObserver&&await ev("!!document.querySelector('.msg-tweet-dormant button')"));
  await ev("window.IntersectionObserver=window.__savedIO;resetXDisclosure();clearTweetData();document.getElementById('chat-area').replaceChildren()");
  for(const code of ['upstream_failure','timeout']){
    failureCode=code;await mount(code==='timeout'?'8903':'8902');await ev("[...document.querySelectorAll('.msg-tweet button')].at(-1).click()");
    await wait("[...document.querySelectorAll('.msg-tweet')].at(-1)?.getAttribute('aria-busy')==='false'");
    ok(code+': small failure retains original link and retry',await ev("(()=>{const c=[...document.querySelectorAll('.msg-tweet')].at(-1);return c.offsetHeight<150&&c.textContent.includes('Retry')&&!!c.querySelector('a');})()"));
    const shot=await send('Page.captureScreenshot',{format:'png'}),file=path.join(temp,'x-'+code+'.png');await fs.writeFile(file,Buffer.from(shot.data,'base64'));screenshots.push(file);
  }
  failureCode=null;await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");
  // Audit fix (split pane): no viewport observer there, so an auto card offers click-to-load
  // instead of "Loading…" forever.
  const beforeSplit=counts.preview;
  ok('split-pane auto previews fall back to click-to-load',await ev(`(async()=>{let area=document.getElementById('split-chat-area'),temp=false;
    if(!area){area=document.createElement('div');area.id='split-chat-area';document.body.appendChild(area);temp=true;}
    setXDisclosure('auto_public');
    const row=buildRow({id:40001,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,text:'https://x.com/a/status/8801'},undefined,tweetConversation('fixture','#public'));
    area.appendChild(row);await new Promise(r=>setTimeout(r,80));
    const pass=!!row.querySelector('.msg-tweet-button')&&!row.textContent.includes('Loading X preview');
    disposeTweetPreviews(row);row.remove();if(temp)area.remove();resetXDisclosure();return pass;})()`)&&counts.preview===beforeSplit);
  // Re-check 3: on an unconfigured server, generic previews for X links that fail or have no
  // title are removed AND unregistered; pane disposal also prunes detached registered nodes.
  previewEnabled=false;await caps();
  // A default install never builds a rich card, so the removal observer does not exist
  // there: detach this page's observer for the check (restored afterwards).
  const registry=JSON.parse(await ev(`(async()=>{const area=document.getElementById('chat-area');disposeTweetPreviews(area);area.replaceChildren();
    const observer=_tweetRemovalObserver;observer?.disconnect();
    for(let i=0;i<100;i++)area.appendChild(buildRow({id:42000+i,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,text:'https://x.com/a/status/'+(9000+i)},undefined,tweetConversation('fixture','#public')));
    const made=_tweetGenericNodes.size;await new Promise(r=>setTimeout(r,900));const left=_tweetGenericNodes.size;
    area.replaceChildren();disposeTweetPreviews(area);const after=_tweetGenericNodes.size;
    observer?.observe(area,{childList:true,subtree:true});
    return JSON.stringify({made,left,after});})()`));
  if(registry.made!==100||registry.left||registry.after)console.error('generic registry',registry,counts.generic_unconfigured);
  ok('100 failed generic X previews leave nothing registered',registry.made===100&&registry.left===0&&registry.after===0&&counts.generic_unconfigured>=100);
  previewEnabled=true;await caps();
  // Re-check 2: with a failed capability probe, X status links take only the generic
  // link-preview path — never direct media, even when crafted to look like an image —
  // and a clicked fallback card is torn down by revocation before it can render.
  configFail=true;
  await ev("localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),extMedia:'all',linkPreviews:true}));invalidateAppearCache();resetXDisclosure()");
  ok('failed probe is unknown, not authoritative',await ev("refreshTweetCapabilities().then(()=>_tweetCaps.failed===true&&_tweetCaps.preview===false)"));
  const xHostsBefore=counts.x_hosts,assetsBefore=counts.assets;
  ok('crafted media-looking X URL in an encrypted DM never loads directly',await ev(`(async()=>{const area=document.getElementById('chat-area');area.replaceChildren();
    const row=buildRow({id:41001,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:true,text:'https://x.com/i/status/123?attachment=.jpg'},undefined,tweetConversation('fixture','friend'));
    const direct=buildMediaEl('https://x.com/i/status/123?attachment=.jpg',false,true);
    area.appendChild(row);await new Promise(r=>setTimeout(r,150));
    return !row.querySelector('img,video,audio')&&row.textContent.includes('🔒 Load link preview')&&!(direct&&direct.querySelector?.('img'))&&direct?.classList?.contains('msg-link-preview');})()`)&&counts.x_hosts===xHostsBefore);
  genericDelay=700;
  const fallbackBefore=counts.generic_fallback;
  const clicked=await ev(`(async()=>{const area=document.getElementById('chat-area');area.replaceChildren();
    const row=buildRow({id:41002,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,text:'https://x.com/a/status/8803'},undefined,tweetConversation('fixture','friend'));
    area.appendChild(row);await new Promise(r=>setTimeout(r,80));
    const button=[...row.querySelectorAll('button')].find(b=>b.textContent.startsWith('Load link preview'));if(!button)return 'no click-to-load';
    button.click();await new Promise(r=>setTimeout(r,80));
    const card=row.querySelector('.msg-link-preview');if(!card)return 'no card';
    setXDisclosure('hidden');
    await new Promise(r=>setTimeout(r,1100));
    return JSON.stringify({connected:card.isConnected,left:!!row.querySelector('.msg-link-preview,.msg-link-preview-img'),rendered:row.textContent.includes('Generic X title')});})()`);
  const clickedState=clicked.startsWith('{')?JSON.parse(clicked):{error:clicked};
  if(clickedState.error||clickedState.connected||clickedState.left||clickedState.rendered||counts.generic_fallback!==fallbackBefore+1||counts.assets!==assetsBefore)
    console.error('clicked fallback state',clickedState,{fallback:counts.generic_fallback-fallbackBefore,assets:counts.assets-assetsBefore});
  ok('clicked fallback card is removed by revocation before it renders',!clickedState.error&&!clickedState.connected&&!clickedState.left&&!clickedState.rendered
    &&counts.generic_fallback===fallbackBefore+1&&counts.assets===assetsBefore);
  genericDelay=0;configFail=false;
  await ev("resetXDisclosure();refreshTweetCapabilities();document.getElementById('chat-area').replaceChildren()");await caps();
  // Re-check fix (split view): closing it stops the hidden pane's pending loads/playback.
  delay=500;
  ok('closing split view tears down its X cards',await ev(`(async()=>{toggleSplitView();clearInterval(_splitWatch);_splitWatch=null;
    const area=document.getElementById('split-chat-area');if(!area)return false;
    const row=buildRow({id:40002,ts:Date.now()/1000,from:'author',kind:'privmsg',encrypted:false,text:'https://x.com/a/status/8802'},undefined,tweetConversation('fixture','#public'));
    area.appendChild(row);await new Promise(r=>setTimeout(r,60));
    row.querySelector('.msg-tweet-button').click();await new Promise(r=>setTimeout(r,60));
    const card=row.querySelector('.msg-tweet');toggleSplitView();
    await new Promise(r=>setTimeout(r,800));
    const pass=!card.isConnected&&!row.querySelector('.msg-tweet-name')&&![..._tweetCards].some(s=>s.root===card);
    row.remove();return pass;})()`));
  delay=0;
  // Audit fix (media permission): a fallback that is signing when External media is revoked
  // must not start the proxied request afterwards.
  blockDirectMedia=true;signDelay=700;
  await ev("clearTweetData();document.getElementById('chat-area').replaceChildren();localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),extMedia:'all',xPreviewMode:'expanded'}));invalidateAppearCache()");
  const signBefore=counts.sign;
  await mount(fixtures[1].id);await ev("document.querySelector('.msg-tweet button').click()");await wait("!!document.querySelector('.msg-tweet-name')");
  for(let i=0;i<100&&counts.sign===signBefore;i++)await sleep(20);
  ok('fallback signing started for a permitted thumbnail',counts.sign>signBefore);
  const proxyBefore=counts.proxy;
  await ev("localStorage.setItem('cryptirc_appear',JSON.stringify({...loadAppearance(),extMedia:'off'}));invalidateAppearCache()");
  await sleep(1200);
  ok('revoking External media stops a pending fallback',counts.proxy===proxyBefore&&await ev("[...document.querySelectorAll('.msg-tweet img')].every(i=>!(i.getAttribute('src')||'').includes('/tweet/media'))"));
  blockDirectMedia=false;signDelay=0;
  await ev("for(let i=0;i<100;i++)setActive('fixture',i%2?'#public':'#other')");
  ok('100 conversation changes leave bounded preview state',await ev('_tweetCards.size===0&&_tweetPending.size===0&&_tweetActive===0'));
  delay=250;await ev("clearTweetData();document.getElementById('chat-area').replaceChildren()");await mount('777');await ev("document.querySelector('.msg-tweet button').click()");
  await sleep(30);await ev("setActive('fixture','#other')");await sleep(350);
  ok('late completion never writes into new channel',await ev("!document.querySelector('.msg-tweet')&&_tweetPending.size===0"));
  ok('preview interactions do not send IRC payloads',await ev("window.__wire.every(m=>!['send','message','privmsg'].includes(m.type))"));
  ok('only explicit thread consent issues a thread request',counts.thread===1);
  ok('configured server: X links never reach the generic /preview fetcher',counts.generic===0);
  ok('no runtime exceptions',errors.length===0);
  console.log(JSON.stringify({browser:(await send('Browser.getVersion')).product,cpu:os.cpus()[0]?.model,checks,counts,timings,work,screenshots},null,2));
}finally{socket?.close();chrome.kill();await new Promise(resolve=>server.close(resolve));}
