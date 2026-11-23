// Run against the browser already signed in to a disposable account on the
// linked testnet. All interaction with the search UI goes through Chromium input.
export async function checkSettingsSearch({ev,cdp,check,waitFor,pause,network,grantAdmin}) {
  const selectors={input:'#settings-search',results:'#settings-search-results',gear:'#settings-gear-btn'};
  const asJS=expr=>JSON.stringify(expr);
  async function key(key) {
    const options={key,code:key,windowsVirtualKeyCode:{Enter:13,Escape:27,ArrowDown:40,ArrowUp:38}[key]};
    await cdp('Input.dispatchKeyEvent',{type:'keyDown',...options});
    await cdp('Input.dispatchKeyEvent',{type:'keyUp',...options});
  }
  async function tap(selector,touch=false) {
    const point=await waitFor(()=>ev('(()=>{const e=document.querySelector('+asJS(selector)+');if(!e)return null;'+
      'const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;'+
      'return r.width&&r.height&&e.contains(document.elementFromPoint(x,y))?{x,y}:null;})()'),'visible '+selector);
    if(touch){
      await cdp('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point]});
      await cdp('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
    }else{
      await cdp('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});
      await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point});
    }
  }
  async function viewport(width,height,mobile) {
    await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile});
    await cdp('Emulation.setTouchEmulationEnabled',{enabled:mobile,maxTouchPoints:1});
    await cdp('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'},
      {name:'pointer',value:mobile?'coarse':'fine'},{name:'hover',value:mobile?'none':'hover'}]});
  }
  async function openSearch(mobile=false) {
    await ev('closeSettingsMenu();'+(mobile?'openSidebar();':''));
    if(mobile) await pause(240);
    await tap(selectors.gear,mobile);
    await tap(selectors.input,mobile);
    await waitFor(()=>ev("document.activeElement.id==='settings-search'"),'focused Settings search');
  }
  async function query(text) {
    await ev("document.getElementById('settings-search').select()");
    await cdp('Input.insertText',{text});
    return ev("[...document.querySelectorAll('#settings-search-results .ssh-label')].map(x=>x.textContent)");
  }
  async function openResult(queryText,selector,closeAction,mobile=false) {
    await openSearch(mobile);
    const items=await query(queryText);
    check('Settings search has a result for '+queryText,items.length>0);
    if(mobile) await tap('#settings-hit-0',true);
    else await key('Enter');
    await waitFor(()=>ev('(document.querySelector('+asJS(selector)+')?.classList.contains("settings-hit-flash"))||false'),
      'Settings search opens '+selector);
    const inView=await ev('(()=>{const e=document.querySelector('+asJS(selector)+');'+
      'const box=e.getBoundingClientRect();const viewport=window.visualViewport?.height||innerHeight;'+
      'return box.bottom>0&&box.top<viewport&&box.width>0&&box.height>0;})()');
    check('Settings search opens and highlights '+selector+' within the viewport',inView);
    await ev(closeAction);
  }

  await viewport(1440,900,false);
  await openSearch();
  const missed=await ev(`(()=>{
    const indexed=new Set(_settingsSearchIndex().map(entry=>entry.target));
    return [
      ['#appearance-overlay .appear-row','.appear-label'],
      ['#security-overlay .appear-row','.appear-label'],
      ['#notif-modal .notif-row','.notif-label'],
      ['#modal-overlay .form-field','.form-label']
    ].flatMap(([selector,label])=>[...document.querySelectorAll(selector)]
      .filter(row=>!row.closest('#notif-network-list') && row.querySelector(label) && !indexed.has(row))
      .map(row=>row.querySelector(label).textContent.trim()));
  })()`);
  check('Settings search covers each labeled static setting row (missing: '+missed.join(', ')+')',missed.length===0);
  for(const [text,label] of [
    ['MCP','MCP access'],['model context protocol','MCP access'],['revoke bearer token','MCP access'],
    ['where is the MCP config','MCP access'],['passkey settings','Passkeys'],
    ['pass key','Passkeys'],['Face ID','Passkeys'],['avatr','Avatar'],
    ['recovery email','Email address'],['change vault passphrase','Change vault passphrase'],
    ['desktop popups','Desktop popups'],['font szie','Font Size'],
    ['hide older messages','Message expiry'],['auto rejoin kick','Auto-rejoin on kick'],
    ['spell check','Spellcheck'],['url previews','Link previews'],
    ['tls','TLS'],['self-signed','Accept Invalid TLS'],['nickname','Nickname'],
    ['startup commands','Perform / On-connect commands'],['SASL auth','SASL authentication'],
    ['bot master switch','Bot settings'],['ai provider','AI chatbot'],['weather','Weather'],
    ['bad word filter','Bad-word filter'],['Arctic','Arctic'],
    ['clear all data','Clear All Data'],
  ]){
    const hits=await query(text);
    check('Settings search ranks '+label+' first for '+text+' (first result: '+(hits[0]||'none')+')',
      String(hits[0]||'').toLowerCase().includes(label.toLowerCase()));
  }
  check('Settings search finds notifications for the connected network',
    (await query('notifications for '+network)).some(label=>label==='Notifications for '+network));
  check('Settings search hides operator-only settings for a regular account',
    !(await query('sign up captcha')).some(label=>label==='Sign-up captcha'));
  check('Settings search shows an empty state for unrelated text',(await query('zzzrqpqwz')).length===0);
  check('Settings search announces no results',await ev("document.getElementById('settings-search-status').textContent==='No settings match.'"));
  const many=await query('theme');
  check('Settings search keeps results beyond the former 12-hit cap',many.length>12);
  await key('ArrowDown');
  check('Settings search exposes the keyboard selection',
    await ev("document.querySelector('#settings-hit-0').getAttribute('aria-selected')==='true' && document.activeElement.getAttribute('aria-activedescendant')==='settings-hit-0'"));
  await key('ArrowDown');
  check('Settings search arrows move to the next result',
    await ev("document.activeElement.getAttribute('aria-activedescendant')==='settings-hit-1'"));
  await key('ArrowUp');
  check('Settings search arrows move back to the previous result',
    await ev("document.activeElement.getAttribute('aria-activedescendant')==='settings-hit-0'"));
  await key('Escape');
  check('Escape clears the query while keeping Settings open',
    await ev("!document.getElementById('settings-search').value && document.getElementById('settings-menu').classList.contains('open')"));
  await key('Escape');
  check('A second Escape closes Settings and returns focus',
    await ev("!document.getElementById('settings-menu').classList.contains('open') && document.activeElement.id==='settings-gear-btn'"));

  // Profile cards do not exist before the first search. Other panels may
  // rebuild rows after their HTTP or WebSocket response arrives.
  await openResult('mcp','#profile-mcp-card','closeProfilePanel()');
  await openResult('passkeys','#profile-passkeys-card','closeProfilePanel()');
  await openResult('avatar','#profile-avatar-card','closeProfilePanel()');
  await openResult('change vault passphrase','#profile-vault-passphrase','closeProfilePanel()');
  await openResult('delete account','#profile-delete-account','closeProfilePanel()');
  await openResult('spellcheck','.appear-row:has(#sec-spellcheck)','closeSecurityPanel()');
  await openResult('notifications for '+network,'#notif-network-list .notif-row','closeNotifModal()');
  await openResult('self signed','.form-field:has(#f-tls-invalid)','closeModal()');
  await openResult('weather','[data-bot-enable="weather"]','closeBotPanel()');
  const originalTheme=await ev('loadAppearance().theme');
  await openResult('Arctic','#theme-grid [data-theme="arctic"]','closeAppearanceModal()');
  check('Settings search opens a theme without applying it',await ev('loadAppearance().theme')===originalTheme);

  await grantAdmin(true);
  await ev('checkAdmin()');
  await openResult('sign-up captcha','#admin-captcha-enabled','closeAdminPanel()');
  await grantAdmin(false);
  await ev('checkAdmin()');
  await openSearch();
  check('Admin search destinations disappear after permission is removed',!(await query('sign-up captcha')).includes('Sign-up captcha'));
  await ev('closeSettingsMenu()');

  for(const [width,height] of [[390,844],[320,520]]){
    await viewport(width,height,true);
    await openResult('mcp','#profile-mcp-card','closeProfilePanel()',true);
    await openResult('pass key','#profile-passkeys-card','closeProfilePanel()',true);
    check(width+' px mobile search keeps the page within its viewport',
      await ev('document.documentElement.scrollWidth<=innerWidth+1'));
  }
  await ev('closeSettingsMenu();closeSidebar()');
  await viewport(1440,900,false);
}
