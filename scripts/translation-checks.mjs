import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';

const fixtureKey='isolated-translation-test-key';
const translations=new Map([
  ['Guten Morgen! Wie geht es dir?','Good morning! How are you?'],
  ['Ein Test für den Chat','A test for the chat'],
  ['Eine automatische Übersetzung','An automatic translation'],
  ['Deutsche Überschrift\nEine deutsche Beschreibung','German headline\nA German description'],
  ['Ein Beitrag aus Deutschland','A post from Germany'],
  ['Das war ein Zitat','That was a quote'],
  ['Nachricht vom anderen Teilnehmer','Message from the other participant'],
  ['See you later','Bis später'],
  ['Good evening','Guten Abend'],
  ['A reply to the original','Eine Antwort auf das Original'],
  ['A literal slash result','/literal <b>markup</b>'],
]);

export async function startTranslator(){
  const calls=[];
  const server=http.createServer(async(req,res)=>{
    try{
      assert.equal(req.url,'/v1/chat/completions');
      assert.equal(req.headers.authorization,'Bearer '+fixtureKey);
      const chunks=[];
      for await(const chunk of req)chunks.push(chunk);
      const {messages,model}=JSON.parse(Buffer.concat(chunks));
      assert.equal(model,'translation-fixture');
      assert.equal(messages.length,2);
      assert.equal(messages[0].role,'system');
      assert.equal(messages[1].role,'user');
      const input=JSON.parse(messages[1].content);
      assert.deepEqual(Object.keys(input).sort(),['target','text']);
      calls.push(input);
      if(input.text==='Provider is offline'){res.writeHead(503).end();return;}
      if(input.text==='Slow account lock')await new Promise(resolve=>setTimeout(resolve,750));
      const source=['See you later','Good evening','A literal slash result'].includes(input.text)?'en':'de';
      const text=translations.get(input.text)||input.text;
      res.setHeader('Content-Type','application/json');
      res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({source,text})}}]}));
    }catch{
      res.writeHead(400).end();
    }
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {calls,base:'http://127.0.0.1:'+server.address().port+'/v1',close:()=>server.close()};
}

export async function checkTranslation({
  ev,cdp,check,waitFor,pause,request,tmp,owner,other,ownerSession,otherSession,ownerWs,otherWs,networkA,networkB,channel,translator,
}){
  const j=JSON.stringify;
  const {calls}=translator;
  const translate=(body,token=ownerSession)=>request('/api/translation',{method:'POST',body,token});
  const sample={provider:'custom',model:'translation-fixture',custom_base:translator.base,target:'en',text:'Ein Test für den Chat'};
  check('translation API requires an account session',(await translate(sample,null)).status===401);
  check('translation API rejects malformed language tags',(await translate({...sample,target:'en<script>'})).status===400);
  check('translation API rejects oversized text',(await translate({...sample,text:'あ'.repeat(1500)})).status===400);
  check('a missing hosted translation credential is reported',(await translate({...sample,provider:'google-translate'})).status===412);
  check('other accounts cannot borrow the configured provider credential',(await translate(sample,otherSession)).status===502);

  await waitFor(()=>ev('_e2eKnown()'),'translation encryption metadata');
  await ev("document.getElementById('settings-gear-btn').click();const search=document.getElementById('settings-search');search.value='translate twitter';settingsSearch(search.value);");
  check('settings search finds translation for Twitter previews',await ev("[...document.querySelectorAll('#settings-search-results button')].some(b=>b.textContent.includes('Translation'))"));
  await ev("[...document.querySelectorAll('#settings-search-results button')].find(b=>b.textContent.includes('Translation')).click()");
  check('search opens the Translation panel',await ev("document.getElementById('translation-panel').open"));
  check('translation lists every provider in Bots plus Google Cloud',await ev("translationFields().provider.options.length===AI_PROVIDER_OPTIONS.length+1"));
  await ev(`(()=>{const f=translationFields();f.provider.value='custom';populateTranslationProvider();f.model.value='translation-fixture';f.base.value=${j(translator.base)};f.credential.value=${j(fixtureKey)};saveTranslationCredential(false);})()`);
  await waitFor(()=>ev("translationFields().keyState.textContent==='Saved in vault'"),'translation credential saved');
  const encrypted=await fs.readFile(path.join(tmp,'users',owner,'ai_keys.enc'),'utf8');
  check('the shared provider key is encrypted at rest',!encrypted.includes(fixtureKey)&&(await fs.stat(path.join(tmp,'users',owner,'ai_keys.enc'))).mode%512===0o600);
  await ev('testTranslationProvider()');
  check('test provider displays an actual sample result',await ev("translationFields().notice.textContent.includes('Good morning')"));
  await ev("translationFields().enabled.checked=true;document.querySelector('#translation-panel form').requestSubmit()");
  check('translation remains opt-in and uses English by default',await ev("translationSettings().enabled&&translationSettings().language==='en'&&!translationSettings().auto"));
  const response=await translate(sample);
  check('the route returns detected language and no-store response',response.status===200&&response.data.source==='de'&&response.headers.get('cache-control')==='no-store');

  const row=phrase=>`[...document.querySelectorAll('#chat-area .msg-row')].find(r=>r._jumpText===${j(phrase)})`;
  const send=message=>otherWs.send({type:'send',conn_id:networkB,raw:'PRIVMSG '+channel+' :'+message});
  const selectChat=async(target,code)=>ev(`(()=>{showTranslationChat(${j(networkA)},${j(target)});const f=translationFields();${code};document.querySelector('#translation-panel form').requestSubmit();})()`);
  const manual='Ein Test für den Chat';
  const prior=calls.length;
  send(manual);
  await waitFor(()=>ev(`!!(${row(manual)})?.querySelector('.translation-button')`),'real IRC message Translate control');
  check('manual mode waits for the click',calls.length===prior);
  await ev(`(${row(manual)}).querySelector('.translation-button').click()`);
  await waitFor(()=>ev(`(${row(manual)})?.textContent.includes('A test for the chat')`),'manual inline translation');
  check('manual translation keeps the original message visible',await ev(`(${row(manual)}).textContent.includes(${j(manual)})`));
  await ev(`(${row(manual)}).querySelector('.translation-button').click()`);
  check('inline translation can be hidden',await ev(`(${row(manual)}).querySelector('.translation-result').hidden`));

  const fixture=JSON.parse(await fs.readFile(new URL('../src/twitter/fixtures/normalized/quoted-post.json',import.meta.url),'utf8'));
  fixture.text='Ein Beitrag aus Deutschland';
  fixture.entities=[];
  fixture.media=[];
  fixture.quote.post.text='Das war ein Zitat';
  fixture.quote.post.entities=[];
  fixture.quote.post.media=[];
  await ev(`(()=>{
    const real=window.fetch.bind(window),fixture=${j(fixture)};
    window.fetch=(url,opt)=>{
      const parsed=new URL(url,location.origin);
      if(parsed.pathname.endsWith('/preview')&&!parsed.pathname.includes('/tweet/')){
        return Promise.resolve(Response.json({domain:'example.test',title:'Deutsche Überschrift',description:'Eine deutsche Beschreibung'}));
      }
      if(parsed.pathname.endsWith('/tweet/preview')){
        return Promise.resolve(Response.json({...fixture,expires_at:new Date(Date.now()+60000).toISOString()}));
      }
      return real(url,opt);
    };
    setTweetCapabilities({known:true,preview:true,thread:false});
  })()`);
  send('https://example.test/de');
  await waitFor(()=>ev("!!document.querySelector('.link-preview-container .translation-button')"),'website preview Translate button');
  await ev("document.querySelector('.link-preview-container .translation-button').click()");
  await waitFor(()=>ev("document.querySelector('.link-preview-container .translation-result')?.textContent.includes('A German description')"),'website preview translation');
  check('the preview title and description translate together without sending the link',calls.some(c=>c.text==='Deutsche Überschrift\nEine deutsche Beschreibung')&&!calls.some(c=>c.text.includes('example.test')));
  check('website preview links remain real clickable anchors',await ev("document.querySelector('.link-preview-container a').href==='https://example.test/de'&&!document.querySelector('.link-preview-container a button')"));
  send(fixture.url);
  await waitFor(()=>ev("!!document.querySelector('.msg-tweet button[aria-label=\"Translate X post\"]')"),'rich X preview Translate button');
  await ev("document.querySelector('.msg-tweet button[aria-label=\"Translate X post\"]').click()");
  await waitFor(()=>ev("document.querySelector('.msg-tweet .translation-result')?.textContent==='A post from Germany'"),'rich X preview translation');
  check('original X post and translation are both visible',await ev("document.querySelector('.msg-tweet').textContent.includes('Ein Beitrag aus Deutschland')"));
  await ev("document.querySelector('.msg-tweet-mode').click()");
  await waitFor(()=>ev("!!document.querySelector('.msg-tweet-quote .translation-button')"),'quoted X Translate button');
  await ev("document.querySelector('.msg-tweet-quote .translation-button').click()");
  await waitFor(()=>ev("document.querySelector('.msg-tweet-quote .translation-result')?.textContent==='That was a quote'"),'quoted X translation');

  await selectChat(channel,"f.incoming.value='on';f.outgoing.value='language';f.outLanguage.value='de'");
  send('Eine automatische Übersetzung');
  await waitFor(()=>ev(`(${row('Eine automatische Übersetzung')})?.textContent.includes('An automatic translation')`),'automatic translation of the incoming IRC line');
  check('automatic translation uses the selected reading language',calls.some(c=>c.text==='Eine automatische Übersetzung'&&c.target==='en'));
  const draft=text=>ev(`document.getElementById('msg-input').value=${j(text)};doSend()`);
  await draft('See you later');
  await otherWs.wait(e=>e.type==='irc_message'&&e.text==='Bis später','translated outgoing channel message');
  check('channel peer received the translation without a preview prompt',calls.some(c=>c.text==='See you later'&&c.target==='de'));
  await pause(220);
  await ev(`setReply(${j(other)},'Original reply quote',{conn_id:${j(networkA)},target:${j(channel)}})`);
  await draft('A reply to the original');
  await otherWs.wait(e=>e.type==='irc_message'&&e.text==='Eine Antwort auf das Original','translated reply');
  check('translated replies still send their original quote',otherWs.events.some(e=>e.text===`> <${other}> Original reply quote`)&&!calls.some(c=>c.text.includes('Original reply quote')));
  await pause(220);
  await draft('A literal slash result');
  await otherWs.wait(e=>e.type==='irc_message'&&e.text==='/literal <b>markup</b>','translated slash is plain chat');
  check('a provider result starting with slash goes out as chat',true);
  await pause(220);
  await draft('Provider is offline');
  check('provider failure leaves the original draft and sends nothing',await ev("document.getElementById('msg-input').value==='Provider is offline'")&&!otherWs.events.some(e=>e.text==='Provider is offline'));
  await pause(220);

  otherWs.send({type:'send',conn_id:networkB,raw:'PRIVMSG '+owner+' :Nachricht vom anderen Teilnehmer'});
  await waitFor(()=>ev(`getBuf(${j(networkA)},${j(other)}).some(m=>m.text==='Nachricht vom anderen Teilnehmer')`),'incoming DM in the browser');
  await ev(`setActive(${j(networkA)},${j(other)})`);
  await selectChat(other,"f.outgoing.value='peer'");
  const allowPlain = `Array.from(document.querySelectorAll('button')).find(b=>['Allow unencrypted','Send unencrypted'].includes(b.textContent))`;
  await draft('Good evening');
  await otherWs.wait(e=>e.type==='irc_message'&&e.text==='Guten Abend','translated outgoing DM');
  check('plain DM auto-matches the last incoming language and sends without confirmation',
    calls.filter(c=>c.text==='Good evening'&&c.target==='de').length===1&&!await ev(`!!(${allowPlain})`));
  await pause(220);
  await ev(`setActive(${j(networkA)},${j(channel)})`);

  await ev(`(()=>{
    const node=document.createElement('div');node.id='translation-protected-fixture';document.getElementById('chat-area').append(node);
    mountTranslation(node,'Private German test',{connId:${j(networkA)},target:${j(channel)},protected:true,live:true},'message');
  })()`);
  await pause(130);
  check('encrypted text is skipped automatically',!calls.some(c=>c.text==='Private German test'));
  await ev("document.querySelector('#translation-protected-fixture button').click()");
  check('manual encrypted translation asks for consent',await ev("document.body.textContent.includes('Send this text from an encrypted conversation')"));
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  check('declining encrypted translation shares no text',!calls.some(c=>c.text==='Private German test'));

  const delayed=translate({...sample,text:'Slow account lock'});
  await waitFor(()=>calls.some(c=>c.text==='Slow account lock'),'provider request started');
  ownerWs.send({type:'lock_vault'});
  await ownerWs.wait(e=>e.type==='vault_locked','account vault lock');
  check('a lock while translating suppresses the late provider response',(await delayed).status===423);
  check('locked vault blocks new requests',(await translate(sample)).status===423);
  await ev(`document.getElementById('vault-pass').value='TestOnly-Vault-92!';doUnlock()`);
  await waitFor(()=>ev("!document.getElementById('vault-overlay').classList.contains('show')"),'vault unlock after translation test');
  await ev('showTranslation()');
  await waitFor(()=>ev("translationFields().keyState.textContent==='Saved in vault'"),'credential retained across vault lock');
  await ev('saveTranslationCredential(true)');
  await waitFor(()=>ev("translationFields().notice.textContent==='Credential removed.'"),'credential removal acknowledgement');
  check('credential can be removed from Translation and the shared vault',(await translate(sample)).status===502);
  await cdp('Emulation.setDeviceMetricsOverride',{width:320,height:680,deviceScaleFactor:1,mobile:true});
  check('Translation settings fit the 320 px mobile view',await ev("(()=>{const r=document.getElementById('translation-panel').getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.bottom<=innerHeight;})()"));
  await ev("translationFields().enabled.checked=false;document.querySelector('#translation-panel form').requestSubmit()");
  const afterDisable=calls.length;
  send('Aktuell ist die Übersetzung ausgeschaltet');
  await waitFor(()=>ev(`!!(${row('Aktuell ist die Übersetzung ausgeschaltet')})`),'IRC line with translation disabled');
  check('disabling translation removes the message and preview controls',await ev("!document.querySelector('.translation-button,.translation-result')"));
  check('the previous chat override cannot translate while the feature is disabled',calls.length===afterDisable);
  await ev("setTweetCapabilities({known:true,preview:false,thread:false});");
}
