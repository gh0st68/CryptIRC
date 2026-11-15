#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

function helpers(extra={}) {
  const source=fs.readFileSync(path.join(root,'static/app.js'),'utf8');
  const section=source.slice(source.indexOf('// ─── X previews:'),source.indexOf('// ─── End X previews'));
  const context=vm.createContext({URL,TextEncoder,console,...extra});
  vm.runInContext(section,context);
  return context;
}

function testValidation() {
  const api=helpers();
  const table=JSON.parse(fs.readFileSync(path.join(root,'scripts/fixtures/x-urls.json'),'utf8'));
  for(const row of table) assert.equal(api.parseTweetUrl(row.url)?.id||null,row.id,row.url);
  assert.equal(api.parseTweetUrl('https://x.com/a/status/123).',true).id,'123');
  for(const value of ['https://pbs.twimg.com.evil/a','https://@pbs.twimg.com/a','https://pbs.twimg.com/a.svg','https://pbs.twimg.com/a#x','https://pbs.twimg.com/a%2esvg']) {
    assert.equal(api.validateTweetMediaUrl(value),null,value);
  }
  assert.equal(api.validateTweetMediaUrl('https://video.twimg.com/a.mp4',true),'https://video.twimg.com/a.mp4');
  for(const value of ['0','18446744073709551615'])assert.equal(api.validTweetCount(value),true);
  for(const value of ['18446744073709551616','01',true,-1,'+1'])assert.equal(api.validTweetCount(value),false);
  const fixture=JSON.parse(fs.readFileSync(path.join(root,'src/twitter/fixtures/normalized/text-only.json'),'utf8'));
  assert.equal(api.validTweetPayload(fixture,fixture.id),true);
  assert.equal(api.validTweetPayload({...fixture,schema_version:2},fixture.id),false);
  for(const value of ['javascript:alert(1)','https://u:p@example.org/a','https://example.org/\n'])assert.equal(api.validateTweetNavigationUrl(value),null);
  const variants=[600000,2176000,5000000].map((bitrate,i)=>({url:`https://video.twimg.com/${i}.mp4`,content_type:'video/mp4',bitrate}));
  const media={mp4:variants,hls_url:'https://video.twimg.com/native.m3u8'};
  const choose=options=>api.tweetVideoCandidates(media,{viewportWidth:390,canPlayType:type=>type==='video/mp4',...options});
  assert.equal(choose({})[0].bitrate,2176000);
  assert.equal(choose({viewportWidth:1440})[0].bitrate,5000000);
  assert.equal(choose({saveData:true})[0].bitrate,600000);
  assert.equal(choose({effectiveType:'2g'})[0].bitrate,600000);
  assert.equal(choose({canPlayType:()=>false}).length,0);
  assert.equal(api.tweetVideoCandidates({mp4:[],hls_url:media.hls_url},{viewportWidth:390,canPlayType:()=>true})[0].url,media.hls_url);
  assert.equal(api.tweetVideoCandidates({mp4:variants.map(({bitrate,...v})=>v)},{viewportWidth:390})[0].url,variants[0].url);
  assert.equal(api.compactTweetCount('0'),'0');assert.equal(api.compactTweetCount('1200'),'1.2K');
  assert.equal(api.compactTweetCount('18446744073709551615'),'18E');
  assert.equal(helpers({BigInt:undefined}).compactTweetCount('18446744073709551615'),'18446744073709551615');
  const entries=api.normalizedThreadEntries({entries:[{id:'123',text:'root',media:[]},{id:'124',text:'first',media:[]},
    {id:'124',text:'duplicate known',media:[]},{id:null,text:'unknown',media:[]},{id:null,text:'unknown',media:[]}]},'123');
  // Audit fix: only proven IDs establish same-post identity; equal unknown entries both stay.
  assert.equal(entries.length,3);assert.equal(entries[0].id,'124');assert.equal(entries[1].id,null);assert.equal(entries[2].id,null);
}

async function testMediaProxy() {
  const requests=[];let hold=null;
  const answer=options=>({ok:true,json:async()=>({urls:JSON.parse(options.body).urls.map(u=>({url:u,proxy_url:'/cryptirc/tweet/media?url='+encodeURIComponent(u)+'&exp=1&a=s&sig=test'})),expires_in:300})});
  const api=helpers({sessionToken:'token',currentUser:'alice',setTimeout,clearTimeout,AbortController,fetch:async(url,options)=>{
    requests.push({url,options});if(hold)await hold;return answer(options);
  }});
  const proxied=u=>'/cryptirc/tweet/media?url='+encodeURIComponent(u)+'&exp=1&a=s&sig=test';
  const a='https://pbs.twimg.com/media/a.jpg';
  assert.equal(await api.proxyTweetMedia(a),proxied(a));
  assert.equal(requests.length,1);
  assert.equal(requests[0].url,'/cryptirc/tweet/media/sign');
  assert.equal(requests[0].options.headers.Authorization,'Bearer token');
  assert.deepEqual(JSON.parse(requests[0].options.body),{urls:[a]});
  assert.equal(await api.proxyTweetMedia(a),proxied(a));
  assert.equal(requests.length,1,'cached');
  assert.equal(await api.proxyTweetMedia('https://example.org/a.jpg'),null);
  // Audit fix (red before: 40 concurrent callers sent 40 signing requests): one asset, one
  // request; distinct assets in the same tick share one batch.
  const b='https://pbs.twimg.com/media/b.jpg',c='https://pbs.twimg.com/media/c.jpg',d='https://pbs.twimg.com/media/d.jpg';
  const same=await Promise.all(Array.from({length:40},()=>api.proxyTweetMedia(b)));
  assert(same.every(v=>v===proxied(b)));
  assert.equal(requests.length,2,'40 concurrent callers for one asset → one request');
  const many=await Promise.all([c,d,c,d].map(u=>api.proxyTweetMedia(u)));
  assert.deepEqual(many,[proxied(c),proxied(d),proxied(c),proxied(d)]);
  assert.equal(requests.length,3,'distinct assets batched');
  assert.deepEqual(JSON.parse(requests[2].options.body).urls,[c,d]);
  // Audit fix (red before: a late response repopulated the cleared cache).
  let release;hold=new Promise(r=>{release=r;});
  const late=api.proxyTweetMedia('https://pbs.twimg.com/media/late.jpg');
  await new Promise(r=>setTimeout(r,60));
  assert.equal(requests.length,4,'signing request in flight');
  api.clearTweetData();
  assert.equal(vm.runInContext('_tweetProxyCache.size',api),0);
  release();
  assert.equal(await late,null,'late signature discarded');
  assert.equal(vm.runInContext('_tweetProxyCache.size',api),0,'cleared cache stays cleared');
  hold=null;
  const queued=api.proxyTweetMedia('https://pbs.twimg.com/media/queued.jpg');api.clearTweetData();
  assert.equal(await queued,null,'queued signing cancelled by teardown');
}

async function testCapabilitiesAndContext(){
  const store=new Map(),localStorage={getItem:key=>store.get(key)||null,setItem:(key,value)=>store.set(key,String(value)),removeItem:key=>store.delete(key)};
  let e2eConversations=new Set(),e2eKnown=false;
  const api=helpers({currentUser:'alice',localStorage,networks:[{config:{id:'net'}}],isUploadsConn:()=>false,isMessagesConn:()=>false,
    bk:(c,t)=>c+'/'+t.toLowerCase(),loadAppearance:()=>({linkPreviews:true}),
    _isE2eConversation:target=>e2eConversations.has(target),_e2eKnown:()=>e2eKnown});
  const pub=()=>api.tweetPreviewContext('net','#public',false);
  // Nothing offered by the server (default install): X UI is hidden, nothing is fetched.
  assert.equal(api.tweetLoadPolicy(pub()),'hidden');
  vm.runInContext('_tweetCaps={preview:true,thread:false}',api);
  assert.equal(api.tweetLoadPolicy(pub()),'auto');
  // encrypted===true always wins; unknown rows need positive evidence
  assert.equal(api.tweetPreviewContext('net','#public',true).encrypted,true);
  assert.equal(api.tweetPreviewContext('net','#public',undefined).encrypted,null);
  e2eKnown=true;
  assert.equal(api.tweetPreviewContext('net','#public',undefined).encrypted,false,'known non-E2E channel history');
  e2eConversations.add('#secret');
  for(const flag of [false,undefined,null])assert.equal(api.tweetPreviewContext('net','#secret',flag).encrypted,null,'E2E conversation row');
  assert.equal(api.tweetLoadPolicy(api.tweetPreviewContext('net','#secret',false)),'manual');
  assert.equal(api.tweetPreviewContext('net','#secret',true).encrypted,true);
  // pseudo views / server window / unknown network are unknown contexts
  for(const [c,t] of [['net','status'],['other','#public'],[null,'#public'],['net','']])assert.equal(api.tweetConversation(c,t),null);
  assert.equal(api.tweetLoadPolicy(api.tweetRowContext(null,false)),'manual');
  assert(Object.isFrozen(pub()));
  // the thread operation needs its own capability; permission still comes first
  vm.runInContext("sessionToken='t'",api);
  await assert.rejects(api.fetchTweetPreview('123',{permission:true,operation:'thread'}).promise,e=>e.code==='permission_required');
  // generic media keeps the v0.5.8 contract: buildMediaEl(url, encrypted-flag)
  let calls=[];
  const document={createComment:text=>({nodeType:8,text})};
  const media=helpers({currentUser:'alice',localStorage,networks:[{config:{id:'net'}}],isUploadsConn:()=>false,isMessagesConn:()=>false,
    bk:(c,t)=>c+'/'+t.toLowerCase(),loadAppearance:()=>({linkPreviews:true}),extractMediaUrls:text=>text.split(' '),document,
    buildMediaEl:(url,flag,genericOnly)=>{calls.push([url,flag,genericOnly===true]);return {nodeType:1,url,remove(){}};}});
  const makeBody=()=>{const kids=[],body={kids,appendChild(n){n.parentNode=body;kids.push(n);return n;},
    insertBefore(n,ref){n.parentNode=body;const i=ref?kids.indexOf(ref):-1;if(i<0)kids.push(n);else kids.splice(i,0,n);return n;},querySelectorAll:()=>[]};return body;};
  const conv=media.tweetConversation('net','#public');
  const mixed={kind:'privmsg',encrypted:true,text:'https://example.org/a https://x.com/a/status/9'};
  media.mountMessageMedia(mixed,conv,makeBody());
  media.mountMessageMedia({kind:'privmsg',text:'https://example.org/b'},undefined,makeBody());
  assert.deepEqual(calls,[['https://example.org/a',true,false],['https://example.org/b',false,false]],'X link waits for the server answer');
  // Audit fix (red before: an unconfigured server dropped X links' v0.5.8 generic preview
  // and the encrypted click-to-load gate): no X provider ⇒ the generic path, flag intact.
  vm.runInContext('_tweetCaps={known:true,preview:false,thread:false};buildTweetGenericSlot=(slot,body,mode)=>{genericSlots.push(slot.url+" "+mode);return {nodeType:1,url:slot.url,remove(){}};};var genericSlots=[];',media);
  calls=[];
  const body=makeBody();media.mountMessageMedia(mixed,conv,body);
  assert.deepEqual(calls,[['https://example.org/a',true,false]],'X links never go through buildMediaEl/direct media');
  assert.equal(vm.runInContext('genericSlots.join("|")',media),'https://x.com/a/status/9 encrypted','generic link-preview path with the encrypted gate');
  assert.deepEqual(body.kids.map(n=>n.nodeType),[1,8,1],'generic node, X slot marker, X generic node: source order kept');
  assert.equal(body.kids[2].url,'https://x.com/a/status/9');
  calls=[];media.mountMessageMedia({kind:'notice',text:'https://x.com/a/status/9'},conv,makeBody());
  assert.equal(vm.runInContext('genericSlots.join("|")',media),'https://x.com/a/status/9 encrypted|https://x.com/a/status/9 auto','notices too, like v0.5.8');
  // With X previews offered, X links never take the generic path (notices: nothing).
  vm.runInContext('_tweetCaps={known:true,preview:true,thread:false}',media);
  calls=[];media.mountMessageMedia({kind:'notice',text:'https://x.com/a/status/9'},conv,makeBody());
  assert.deepEqual(calls,[]);
}

// Re-check fixes (browser lane): a failed capability probe never makes X links less private
// than the viewer's X choices; a late probe answer after teardown is dropped; nothing is
// built behind a lock; signing is bounded, timed out and cancelled on teardown.
async function testProbeFailureLockAndSigningBounds(){
  const store=new Map(),localStorage={getItem:k=>store.has(k)?store.get(k):null,setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k)};
  let locked=false,probe=null,shorten=false;const timers=[];
  const document={createComment:text=>({nodeType:8,text}),querySelectorAll:()=>[],getElementById:id=>id==='vault-overlay'?{classList:{contains:c=>c==='show'&&locked}}:null};
  const calls=[];
  const api=helpers({currentUser:'alice',sessionToken:'t',localStorage,networks:[{config:{id:'net'}}],isUploadsConn:()=>false,isMessagesConn:()=>false,
    bk:(c,t)=>c+'/'+t.toLowerCase(),loadAppearance:()=>({linkPreviews:true}),extractMediaUrls:text=>text.split(' '),document,queueMicrotask,
    setTimeout:(fn,ms)=>{const t=setTimeout(fn,ms===10000&&shorten?40:ms);if(ms>=30000)t.unref?.();timers.push(t);return t;},clearTimeout,AbortController,requestAnimationFrame:()=>0,active:null,
    buildMediaEl:(url,flag,genericOnly)=>{calls.push(['generic',url,flag,genericOnly===true]);return {nodeType:1,url,remove(){}};},
    fetch:url=>probe(url)});
  vm.runInContext("buildTweetGenericSlot=(slot,body,mode)=>{calls_click.push(slot.url+' '+mode);return {nodeType:1,url:slot.url,remove(){}};};var calls_click=[];var refreshes=0;const _realRefresh=refreshTweetPolicyUI;refreshTweetPolicyUI=()=>{refreshes++;_realRefresh();};",api);
  const makeBody=()=>{const kids=[],body={kids,appendChild(n){n.parentNode=body;kids.push(n);return n;},
    insertBefore(n,ref){n.parentNode=body;const i=ref?kids.indexOf(ref):-1;if(i<0)kids.push(n);else kids.splice(i,0,n);return n;},querySelectorAll:()=>[]};return body;};
  const x='https://x.com/a/status/9';
  // (1) the probe fails → generic path, but never less private than the X choice
  probe=async()=>{throw new Error('offline');};
  await api.refreshTweetCapabilities();
  assert.deepEqual(JSON.parse(vm.runInContext('JSON.stringify(_tweetCaps)',api)),{known:true,preview:false,thread:false,failed:true});
  assert(vm.runInContext('!!_tweetCapsRetry',api),'a failed probe is retried later');
  store.set('cryptirc_x_policy_v1:alice',JSON.stringify({version:2,load:'hidden',conversations:{}}));
  api.mountMessageMedia({kind:'privmsg',encrypted:false,text:x},api.tweetConversation('net','#public'),makeBody());
  assert.deepEqual(calls,[],'Hide X previews: nothing, not even the generic preview');
  store.delete('cryptirc_x_policy_v1:alice');
  assert.equal(vm.runInContext('calls_click.length',api),0);
  api.mountMessageMedia({kind:'privmsg',encrypted:false,text:x},api.tweetConversation('net','friend'),makeBody());
  api.mountMessageMedia({kind:'privmsg',encrypted:true,text:x},api.tweetConversation('net','#public'),makeBody());
  api.mountMessageMedia({kind:'privmsg',encrypted:false,text:x},api.tweetConversation('net','#public'),makeBody());
  assert.deepEqual(calls,[],'X links never take buildMediaEl (direct media) in fallback mode');
  assert.equal(vm.runInContext('calls_click.join("|")',api),[x+' click',x+' encrypted',x+' auto'].join('|'),'DM click-to-load; encrypted gate; auto public generic');
  // (2) a probe answer that arrives after a teardown (vault lock) is dropped
  let answer;probe=()=>new Promise(r=>{answer=r;});
  vm.runInContext('_tweetCaps={known:false,preview:false,thread:false,failed:false}',api);
  const pending=api.refreshTweetCapabilities();
  locked=true;api.clearTweetData();
  const before=vm.runInContext('refreshes',api);
  answer({ok:true,json:async()=>({schema_version:1,preview:true,thread:false})});await pending;
  assert.equal(vm.runInContext('_tweetCaps.known',api),false,'late answer not applied');
  assert.equal(vm.runInContext('refreshes',api),before,'no rebuild behind the lock');
  // (3) behind a lock, X policy is hidden and slots stay empty even with X offered
  vm.runInContext('_tweetCaps={known:true,preview:true,thread:false,failed:false}',api);
  assert.equal(api.tweetLoadPolicy(api.tweetPreviewContext('net','#public',false)),'hidden');
  calls.length=0;api.mountMessageMedia({kind:'privmsg',encrypted:false,text:x},api.tweetConversation('net','#public'),makeBody());
  assert.deepEqual(calls,[]);
  locked=false;
  assert.equal(api.tweetLoadPolicy(api.tweetPreviewContext('net','#public',false)),'auto');
  // (4) signing: ≤2 batches in flight, aborted by teardown, timed out
  const signals=[];
  probe=(url,options)=>new Promise((_,reject)=>{signals.push(options.signal);options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});});
  vm.runInContext("fetch=(url,options)=>signFetch(url,options)",api);api.signFetch=probe;
  const assets=Array.from({length:64},(_,i)=>`https://pbs.twimg.com/media/s${i}.jpg`);
  const results=assets.map(u=>api.proxyTweetMedia(u));
  await new Promise(r=>setTimeout(r,120));
  assert.equal(signals.length,2,'at most two signing batches in flight');
  assert.equal(vm.runInContext('_tweetSignActive.size',api),2);
  api.clearTweetData();
  assert(signals.every(sig=>sig.aborted),'teardown aborts in-flight signing');
  assert((await Promise.all(results)).every(v=>v===null));
  assert.equal(vm.runInContext('_tweetSignActive.size',api),0);
  signals.length=0;shorten=true;
  const slow=api.proxyTweetMedia('https://pbs.twimg.com/media/slow.jpg');
  assert.equal(await slow,null,'a stalled signing request times out');
  assert(signals.length===1&&signals[0].aborted);
  shorten=false;signals.length=0;
  // (5) re-check 2: signing work has owners. Items whose requesting cards are all gone are
  // dropped before a batch; a batch whose items all lost their owners is aborted.
  let liveA=true,liveB=true;
  const gone=api.proxyTweetMedia('https://pbs.twimg.com/media/gone.jpg',()=>liveA);
  liveA=false;
  assert.equal(await gone,null,'owner gone before the batch: dropped');
  assert.equal(signals.length,0,'…and never sent');
  const shared1=api.proxyTweetMedia('https://pbs.twimg.com/media/shared.jpg',()=>false);
  const shared2=api.proxyTweetMedia('https://pbs.twimg.com/media/shared.jpg',()=>liveB);
  await new Promise(r=>setTimeout(r,60));
  assert.equal(signals.length,1,'kept while one owner is alive');
  assert.equal(shared1,shared2);
  liveB=false;api.pruneTweetSigning();
  assert(signals[0].aborted,'batch aborted once no item has an owner');
  assert.equal(await shared1,null);
  for(const t of timers)clearTimeout(t);
}

// Self-review fix (red before: a stored v1 'manual' was silently migrated to auto_public,
// and unreadable storage fell back to the auto default).
function testPolicyUpgradeFailsClosed(){
  let store=new Map(),broken=false;
  const localStorage={getItem:key=>{if(broken)throw new Error('denied');return store.has(key)?store.get(key):null;},setItem:(k,v)=>store.set(k,String(v)),removeItem:k=>store.delete(k)};
  const api=helpers({currentUser:'alice',localStorage,networks:[{config:{id:'net'}}],isUploadsConn:()=>false,isMessagesConn:()=>false,
    bk:(c,t)=>c+'/'+t.toLowerCase(),loadAppearance:()=>({linkPreviews:true})});
  vm.runInContext('_tweetCaps={preview:true,thread:false}',api);
  const key='cryptirc_x_policy_v1:alice',pub=api.tweetPreviewContext('net','#public',false);
  const load=raw=>{store=new Map();if(raw!==undefined)store.set(key,raw);return api.loadXPolicy().load;};
  // 1. an explicit Manual choice (either stored version) stays Manual
  assert.equal(load(JSON.stringify({version:1,load:'manual',conversations:{}})),'manual');
  assert.equal(load(JSON.stringify({version:2,load:'manual',conversations:{}})),'manual');
  assert.equal(api.tweetLoadPolicy(pub),'manual','no public auto-load after upgrading a Manual choice');
  assert.equal(load(JSON.stringify({version:1,load:'hidden',conversations:{}})),'hidden');
  // 2. only a missing / never-set policy gets the new auto_public default
  assert.equal(load(undefined),'auto_public');
  assert.equal(api.tweetLoadPolicy(pub),'auto');
  // 3. unparseable, unknown or unreadable storage fails closed to Manual
  for(const raw of ['{not json','null','[]','"manual"','42',JSON.stringify({version:9,load:'auto_public',conversations:{}}),
    JSON.stringify({version:1,load:'bogus',conversations:{}}),JSON.stringify({version:2,load:'auto_public',conversations:[]}),
    JSON.stringify({version:2,load:'auto_public'}),'x'.repeat(70000)]){
    assert.equal(load(raw),'manual',raw.slice(0,60));
    assert.notEqual(api.tweetLoadPolicy(pub),'auto',raw.slice(0,60));
  }
  store=new Map();broken=true;assert.equal(api.loadXPolicy().load,'manual','unreadable storage');broken=false;
}

async function testScheduler() {
  let now=Date.parse('2026-10-20T12:01:00Z');
  class FakeDate extends Date {static now(){return now;}}
  const requests=[];
  const api=helpers({currentUser:'alice',sessionToken:'same-origin-test-token',Date:FakeDate,
    queueMicrotask,setTimeout,clearTimeout,clearInterval,AbortController,
    fetch:(url,options)=>new Promise((resolve,reject)=>{
      const request={url,options,resolve,reject};requests.push(request);
      options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});
    })});
  vm.runInContext('_tweetCaps={preview:true,thread:true};_tweetAccount=currentUser',api);
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  const fixture=JSON.parse(fs.readFileSync(path.join(root,'src/twitter/fixtures/normalized/text-only.json'),'utf8'));
  const finish=(request,id)=>request.resolve({ok:true,json:async()=>({...fixture,id,url:'https://x.com/i/status/'+id})});
  const leases=Array.from({length:10},()=>api.fetchTweetPreview('123',{permission:true}));
  assert(leases.every(x=>x.promise===leases[0].promise));await flush();assert.equal(requests.length,1);
  assert.equal(new URL(requests[0].url,'https://local.test').searchParams.get('url'),'https://x.com/i/status/123');
  assert.deepEqual(Object.keys(requests[0].options.headers),['Authorization']);
  finish(requests[0],'123');await Promise.all(leases.map(x=>x.promise));
  await assert.rejects(api.fetchTweetPreview('123').promise);
  await api.fetchTweetPreview('123',{permission:true}).promise;assert.equal(requests.length,1);
  leases.forEach(x=>x.dispose());
  now+=301000;
  const fresh=api.fetchTweetPreview('123',{permission:true});await flush();assert.equal(requests.length,2);
  finish(requests[1],'123');await fresh.promise;fresh.dispose();
  const a=api.fetchTweetPreview('124',{permission:true}),b=api.fetchTweetPreview('124',{permission:true});
  a.promise.catch(()=>{});await flush();a.dispose();assert.equal(requests[2].options.signal.aborted,false);
  b.dispose();await assert.rejects(b.promise);await flush();assert.equal(requests[2].options.signal.aborted,true);
  assert.equal(vm.runInContext("_tweetCache.has('preview:124')",api),false);
  const active=[];for(let i=0;i<3;i++){const x=api.fetchTweetPreview(String(500+i),{permission:true});x.promise.catch(()=>{});active.push(x);}
  await flush();assert.equal(vm.runInContext('_tweetActive',api),3);
  const queued=[];for(let i=0;i<50;i++){const x=api.fetchTweetPreview(String(600+i),{permission:true});x.promise.catch(()=>{});queued.push(x);}
  assert.equal(vm.runInContext('_tweetQueue.length',api),50);
  await assert.rejects(api.fetchTweetPreview('999',{permission:true}).promise);
  [...active,...queued].forEach(x=>x.dispose());await flush();
  assert.equal(vm.runInContext('_tweetPending.size',api),0);assert.equal(vm.runInContext('_tweetActive',api),0);
  for(let i=0;i<201;i++)api.cacheTweetResult('preview:'+i,{...fixture,expires_at:new FakeDate(now+300000).toISOString()},null);
  assert.equal(vm.runInContext('_tweetCache.size',api),200);
  for(let i=0;i<80;i++)api.cacheTweetResult('preview:large'+i,{...fixture,test_padding:'x'.repeat(180000),expires_at:new FakeDate(now+300000).toISOString()},null);
  assert(vm.runInContext('_tweetCacheBytes<=8*1024*1024',api));assert(vm.runInContext('_tweetCache.size<200',api));
  vm.runInContext("currentUser='bob'",api);api.ensureTweetAccount();
  assert.equal(vm.runInContext('_tweetCache.size',api),0);
}

function testDisclosureAndAppearanceStorage(){
  const store=new Map(),localStorage={getItem:key=>store.get(key)||null,setItem:(key,value)=>store.set(key,String(value)),removeItem:key=>store.delete(key)};
  let enabled=true;
  const api=helpers({currentUser:'alice',localStorage,networks:[{config:{id:'net'}}],isUploadsConn:()=>false,isMessagesConn:()=>false,
    bk:(c,t)=>c+'/'+t.toLowerCase(),loadAppearance:()=>({linkPreviews:enabled})});
  vm.runInContext('_tweetCaps={preview:true,thread:false}',api);
  const pub=api.tweetPreviewContext('net','#public',false),encrypted=api.tweetPreviewContext('net','#public',true),dm=api.tweetPreviewContext('net','nick',false);
  assert.equal(api.tweetLoadPolicy(pub),'auto');
  store.set('cryptirc_x_policy_v1:alice',JSON.stringify({version:1,load:'auto_public',conversations:{}}));
  assert.equal(api.tweetLoadPolicy(pub),'auto');assert.equal(api.tweetLoadPolicy(encrypted),'manual');assert.equal(api.tweetLoadPolicy(dm),'manual');assert.equal(api.tweetLoadPolicy({}),'manual');
  for(const [global,override,want] of [['manual','auto','auto'],['auto_public','manual','manual'],['hidden','auto','hidden'],['manual','hidden','hidden']]){
    store.set('cryptirc_x_policy_v1:alice',JSON.stringify({version:1,load:global,conversations:{'net/#public':{load:override}}}));assert.equal(api.tweetLoadPolicy(encrypted),want);
  }
  enabled=false;assert.equal(api.tweetLoadPolicy(pub),'hidden');enabled=true;
  vm.runInContext("currentUser='bob'",api);assert.equal(api.tweetLoadPolicy(pub),'auto');
  const bounded=api.normalizeXPolicy({version:1,load:'manual',conversations:Object.fromEntries(Array.from({length:110},(_,i)=>['net/#'+i,{load:'auto'}]))});
  assert.equal(Object.keys(bounded.conversations).length,100);assert(!bounded.conversations['net/#0']);
  assert.equal(api.normalizeXPolicy({version:2,load:'manual',conversations:{}}).load,'manual');
  assert.equal(api.normalizeXPolicy({version:1,load:'manual',conversations:{}}).load,'manual','an explicit v1 Manual choice survives the upgrade');
  const source=fs.readFileSync(path.join(root,'static/app.js'),'utf8'),wire=[];
  const load=source.slice(source.indexOf('function loadAppearance(){'),source.indexOf('let _appearOversizeWarned='));
  const save=source.slice(source.indexOf('function saveAppearance(cfg){'),source.indexOf('function applyAppearance(){'));
  const context=vm.createContext({localStorage,Date,console,TextEncoder,wsend:value=>wire.push(value),showToast:()=>{}});
  vm.runInContext("const APPEAR_DEFAULTS={xPreviewMode:'compact',other:'preserved'};let _appearCache=null,_appearCacheTs=0,_appearOversizeWarned=false;function _utf8Len(s){return new TextEncoder().encode(s).length;}"+load+save,context);
  context.saveAppearance({xPreviewMode:'expanded',other:'unchanged'});assert.equal(context.loadAppearance().xPreviewMode,'expanded');
  context.saveAppearance({xPreviewMode:'compact',other:'unchanged'});assert.equal(context.loadAppearance().xPreviewMode,'compact');
  context.saveAppearance({xPreviewMode:'invalid',other:'unchanged'});assert.equal(context.loadAppearance().xPreviewMode,'expanded');
  assert.equal(context.loadAppearance().other,'unchanged');assert(wire.every(m=>!m.settings.includes('conversations')));
  const sent=wire.length;context.saveAppearance({xPreviewMode:'compact',padding:'x'.repeat(4100)});assert.equal(wire.length,sent);
  let storageListener,revoked=0;
  const crossTab=helpers({currentUser:'alice',window:{addEventListener:(event,fn)=>{if(event==='storage')storageListener=fn;}}});
  crossTab.refreshTweetPolicyUI=()=>revoked++;crossTab.populateXDisclosureControls=()=>{};crossTab.invalidateAppearCache=()=>{};
  storageListener({key:'cryptirc_appear',oldValue:'{}',newValue:'{"linkPreviews":true,"xPreviewMode":"expanded"}'});assert.equal(revoked,0);
  storageListener({key:'cryptirc_appear',oldValue:'{"linkPreviews":true}',newValue:'{"linkPreviews":false}'});assert.equal(revoked,1);
  storageListener({key:'cryptirc_x_policy_v1:alice'});assert.equal(revoked,2);
}

async function testServiceWorker() {
  for (const prefix of ['/cryptirc', '/nested/prefix', '']) {
    const handlers = new Map();
    let writes = 0;
    const source = fs.readFileSync(path.join(root, 'static/sw.js'), 'utf8').replaceAll('/cryptirc', prefix);
    vm.runInNewContext(source, {
      self: {addEventListener: (name, fn) => handlers.set(name, fn)},
      caches: {match: async () => undefined, open: async () => ({put: () => writes++})},
      fetch: async () => new Response('{"schema_version":1}', {headers: {'Content-Type': 'application/json'}}),
      URL, Response, console,
    });
    for (const operation of ['preview', 'thread', 'config', 'media', 'media/sign']) {
      let pending;
      let responded = false;
      handlers.get('fetch')({request: {method: 'GET', url: `https://local.test${prefix}/tweet/${operation}?url=private`}, respondWith: p => { responded = true; pending = p; }});
      assert.equal(responded, false, 'service worker must pass X API requests straight to the network');
      if (pending) await pending;
      await Promise.resolve();
    }
    assert.equal(writes, 0, 'service worker must never persist X API responses');
  }
}

let completed=false;
process.on('exit',code=>{if(!completed&&code===0){console.error('X preview tests did not complete');process.exitCode=1;}});
async function main() {
  testValidation();
  await testMediaProxy();
  testPolicyUpgradeFailsClosed();
  await testProbeFailureLockAndSigningBounds();
  await testCapabilitiesAndContext();
  await testScheduler();
  testDisclosureAndAppearanceStorage();
  await testServiceWorker();
  completed=true;
  console.log('X preview tests passed: shared URL table, validators, contract, service worker.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
