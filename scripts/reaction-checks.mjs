const q=JSON.stringify;

export function reactionRow(text){
  return `[...document.querySelectorAll('#chat-area .msg-row')].find(r=>r._msgRef?.text===${q(text)})`;
}

export function reactionButton(text,emoji){
  return `(()=>{const row=${reactionRow(text)};
    if(!row)return false;
    if(!row.querySelector('.message-actions'))row.querySelector('.msg-body').click();
    const button=[...row.querySelectorAll('.reaction-choice')].find(b=>b.dataset.emoji===${q(emoji)});
    if(!button)return false;
    button.click();return true;
  })()`;
}

export async function checkLegacyReactionMenu({ev,check,waitFor,ownerWs,legacyNetwork,legacyNick,legacyPlain,legacySender,stamp}){
  const text=`legacy reaction sender ${stamp}`;
  await waitFor(()=>ev(`reactionEnabled(${q(legacyNetwork)})`),'old reaction capability retained');
  await ev(`setActive(${q(legacyNetwork)},${q(legacyPlain)})`);
  legacySender.send(`PRIVMSG ${legacyNick} :${text}`);
  const anchor=await waitFor(()=>ev(`(()=>{const row=${reactionRow(text)};return row&&messageReactionFor(row)?.reference;})()`),
    'old module still supplies real message anchors');
  check('the legacy module offers Reply, Like, Heart and Haha',await ev(`(()=>{
    const row=${reactionRow(text)};row.querySelector('.msg-body').click();
    return [...row.querySelectorAll('.message-actions button')].map(b=>b.getAttribute('aria-label')||b.textContent).join(',')==='Reply,Like,Heart,Haha';
  })()`));
  const request_id=crypto.randomUUID();
  ownerWs.send({type:'react',conn_id:legacyNetwork,target:legacyPlain,request_id,
    reaction:{kind:'plain',reference:anchor,emoji:'👎',remove:false}});
  check('the web server rejects a thumbs-down on the old module',!!(await ownerWs.wait(
    e=>e.type==='reaction_result'&&e.request_id===request_id&&e.error,'unsupported thumbs-down refusal')));
  check('Like still works with the old module',await ev(reactionButton(text,'👍'))&&await waitFor(
    ()=>ev(`(${reactionRow(text)})?.querySelector('.reaction-count')?.textContent==='👍 1'`),'old module reaction echo'));
  check('the old module carries Haha using the existing emoji',await ev(reactionButton(text,'😂'))&&await waitFor(
    ()=>ev(`Array.from((${reactionRow(text)})?.querySelectorAll('.reaction-count')||[]).some(chip=>chip.textContent==='😂 1')`),
    'old module Haha echo'));
}

export async function checkOrdinaryClientReactions({ev,peer,check,waitFor,plain,plainNick,owner,networkA,networkB,channel,stamp}){
  const channelText=`ordinary channel sender ${stamp}`;
  const directText=`ordinary DM sender ${stamp}`;
  plain.send('JOIN '+channel);
  await waitFor(()=>plain.lines.some(line=>line.startsWith(`:${plainNick}!`)&&line.split(' ')[1]==='JOIN'&&
    line.split(' ')[2]?.replace(/^:/,'')===channel),
    'plain IRC fixture joined the reaction channel');
  await ev(`setActive(${q(networkA)},${q(channel)})`);
  await peer(`setActive(${q(networkB)},${q(channel)})`);
  plain.send(`PRIVMSG ${channel} :${channelText}`);
  const hasAnchor=text=>`(()=>{const row=${reactionRow(text)};return !!row&&!!messageReactionFor(row);})()`;
  await waitFor(async()=>await ev(hasAnchor(channelText))&&await peer(hasAnchor(channelText)),'ordinary message anchor in both clients');
  const before=plain.lines.length;
  const count=(text,emoji)=>`[...(${reactionRow(text)})?.querySelectorAll('.reaction-count')||[]].some(b=>b.textContent===${q(emoji+' 1')})`;
  for(const emoji of ['👍','👎','❤️','😂']){
    check('CryptIRC can react '+emoji+' to a plain IRC channel message',await ev(reactionButton(channelText,emoji)));
    check('another CryptIRC viewer renders '+emoji+' on the plain IRC message',await waitFor(
      ()=>peer(count(channelText,emoji)),'reaction on ordinary sender in second browser'));
  }
  await ev(`setActive(${q(networkA)},${q(plainNick)})`);
  plain.send(`PRIVMSG ${owner} :${directText}`);
  await waitFor(()=>ev(hasAnchor(directText)),'ordinary private message anchor');
  check('CryptIRC can give a plain IRC private message a thumbs-down',await ev(reactionButton(directText,'👎')));
  check('the private thumbs-down is confirmed on the sending CryptIRC client',await waitFor(
    ()=>ev(count(directText,'👎')),'private reaction echo to CryptIRC'));
  plain.send('PING :reaction-fixture-finished');
  await waitFor(()=>plain.lines.slice(before).some(line=>line.includes(' PONG ')&&line.endsWith('reaction-fixture-finished')),
    'plain client received the final test marker');
  check('reaction adds no IRC lines visible to the ordinary client',!plain.lines.slice(before).some(line=>
    /\bTAGMSG\b|cryptirc\.com\/react|\+draft\/react|👍|👎|❤️|😂/.test(line)));
  await peer(`setActive(${q(networkB)},${q(plainNick)})`);
  check('another CryptIRC account cannot see the private message or its reaction',await peer(
    `!(${reactionRow(directText)})&&!document.querySelector('#chat-area .reaction-count')`));
}

export async function checkPlainReactions({ev,cdp,check,waitFor,ownerWs,otherWs,owner,other,networkA,networkB,channel,stamp,unsupportedNetwork,unsupportedSender,unsupportedNick}){
  const send=(target,text)=>otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${target} :${text}`});
  check('encrypted reaction indices retain their existing order',await ev(
    `CHAT_REACTION_EMOJI.join(',')==='❤️,👍,😂,🎉,🔥,👀,✅,🙏,👎'`));
  for(const [target,conversation] of [[channel,channel],[owner,other]]){
    const parent=`reaction parent ${target} ${stamp}`;
    await ev(`setActive(${q(networkA)},${q(conversation)})`);
    send(target,parent);
    await waitFor(()=>ev(`(()=>{const row=${reactionRow(parent)};return !!row&&!!messageReactionFor(row);})()`),'reaction anchor for real IRC message');
    check('tapping the message shows Reply, Like, Dislike, Heart and Haha',await ev(`(()=>{
      const row=${reactionRow(parent)};row.querySelector('.msg-body').click();
      const names=[...row.querySelectorAll('.message-actions button')].map(b=>b.getAttribute('aria-label')||b.textContent);
      return names.join(',')==='Reply,Like,Dislike,Heart,Haha'&&!row.querySelector('.reaction-picker');
    })()`));
    for(const emoji of target===channel?['❤️','👎']:['👎']){
      const before=otherWs.events.length;
      const peerSaw=remove=>otherWs.events.slice(before).some(e=>e.type==='irc_reaction'&&e.emoji===emoji&&e.remove===remove);
      check('the menu adds '+emoji+' in '+(target===channel?'a channel':'a PM'),await ev(reactionButton(parent,emoji)));
      await waitFor(()=>peerSaw(false),'peer received '+emoji);
      check(emoji+' count shows beside the original message',await waitFor(()=>ev(
        `(${reactionRow(parent)})?.querySelector('.reaction-count')?.textContent===${q(emoji+' 1')}`),'own reaction confirmed'));
      check('the menu removes your own '+emoji,await ev(reactionButton(parent,emoji)));
      await waitFor(()=>peerSaw(true),'peer received the removal of '+emoji);
      check('removing '+emoji+' clears the count',await waitFor(()=>ev(
        `!(${reactionRow(parent)})?.querySelector('.reaction-count')`),'own reaction removal confirmed'));
    }
  }
  const secondChannel=channel+'-second';
  for(const [ws,connId,nick] of [[ownerWs,networkA,owner],[otherWs,networkB,other]]){
    ws.send({type:'send',conn_id:connId,raw:`JOIN ${secondChannel}`});
    await ws.wait(e=>['irc_join','irc_join_ex'].includes(e.type)&&e.channel===secondChannel&&e.nick===nick,
      'both reaction clients join the second channel');
  }
  const repeated=`same text in two channels ${stamp}`;
  for(const room of [channel,secondChannel]){
    await ev(`_sidebarActivate(${q(networkA)},${q(room)})`);
    send(room,repeated);
    await waitFor(()=>ev(`(()=>{const row=${reactionRow(repeated)};return !!row&&!!messageReactionFor(row);})()`),
      'same-text message is anchored in '+room);
  }
  const at=otherWs.events.length;
  check('the second channel can send a Haha reaction',await ev(reactionButton(repeated,'😂')));
  await waitFor(()=>otherWs.events.slice(at).some(e=>e.type==='irc_reaction'&&e.target===secondChannel&&e.emoji==='😂'),
    'the second channel receives Haha');
  await ev(`_sidebarActivate(${q(networkA)},${q(channel)})`);
  check('a reaction never appears beside identical text in the other channel',
    await ev(`(()=>{const row=${reactionRow(repeated)};return !!row&&!row.querySelector('.reaction-count');})()`)&&
      !otherWs.events.slice(at).some(e=>e.type==='irc_reaction'&&e.target===channel&&e.emoji==='😂'));
  await ev(`setActive(${q(networkA)},${q(channel)})`);
  const mobileParent='mobile actions '+stamp;
  const [desktopWidth,desktopHeight]=await ev('[innerWidth,innerHeight]');
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await cdp('Emulation.setTouchEmulationEnabled',{enabled:true,maxTouchPoints:1});
  try {
    send(channel,mobileParent);
    await waitFor(()=>ev(`(()=>{const row=${reactionRow(mobileParent)};return !!row&&!!messageReactionFor(row);})()`),'mobile message anchor');
    const point=await ev(`(()=>{
      const row=${reactionRow(mobileParent)};
      row.scrollIntoView({block:'nearest'});
      const r=row.querySelector('.msg-body').getBoundingClientRect();
      return {x:r.left+10,y:r.top+r.height/2};
    })()`);
    await cdp('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point]});
    await cdp('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
    check('a phone-width touch opens 44px message actions',await waitFor(()=>ev(`
      [...(${reactionRow(mobileParent)}).querySelectorAll('.message-actions button')].filter(b=>b.getBoundingClientRect().height>=44).length===5
    `),'mobile message actions'));
  } finally {
    await cdp('Emulation.setTouchEmulationEnabled',{enabled:false});
    await cdp('Emulation.setDeviceMetricsOverride',{width:desktopWidth,height:desktopHeight,deviceScaleFactor:1,mobile:false});
  }
  check('losing thumbs-down support clears its counts and pending sends while preserving Heart',await ev(`(()=>{
    const conn_id=${q(networkA)}, target=${q(channel)}, request='dislike-capability-fixture';
    const row=${reactionRow(mobileParent)}, reference=messageReactionFor(row).reference;
    const apply=(emoji,remove)=>applyChatReaction(conn_id,target,reference,emoji,remove,'fixture',true,false);
    apply('👎',false); apply('❤️',false);
    pendingChatReactions.set(request,{connId:conn_id,emoji:'👎'});
    try {
      handleEvent({type:'reaction_support',conn_id,enabled:true,dislike:false});
      apply('👎',false);
      const values=messageReactionFor(row).counts;
      return !values.has('👎')&&values.has('❤️')&&!pendingChatReactions.has(request)&&
        !row.querySelector('.reaction-choice[data-emoji="👎"]');
    } finally {
      handleEvent({type:'reaction_support',conn_id,enabled:true,dislike:true});
      apply('❤️',true);
      pendingChatReactions.delete(request);
    }
  })()`));
  check('link clicks and selected message text leave the menu closed',await ev(`(()=>{
    const row=${reactionRow(mobileParent)}, body=row.querySelector('.msg-body');
    document.body.click();
    const link=document.createElement('a');link.textContent='link';body.append(link);
    link.click();link.remove();
    const closed=!row.querySelector('.message-actions');
    const selection=getSelection(), range=document.createRange();
    range.selectNodeContents(body);selection.removeAllRanges();selection.addRange(range);
    body.click();
    const preserved=!selection.isCollapsed&&!row.querySelector('.message-actions');
    selection.removeAllRanges();
    return closed&&preserved;
  })()`));
  check('keyboard opens the message actions and Escape returns focus',await ev(`(()=>{
    const row=${reactionRow(mobileParent)};
    const pane=document.getElementById('chat-area');
    pane.focus();
    pane.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowUp',bubbles:true,cancelable:true}));
    if(document.activeElement!==row || pane.querySelector('.msg-row[tabindex="0"]'))return false;
    row.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true,cancelable:true}));
    const got=document.activeElement.textContent==='Reply';
    document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));
    return got&&document.activeElement===row&&!row.querySelector('.message-actions');
  })()`));
  check('leaving the message actions lets the next control handle Escape',await ev(`(()=>{
    const row=${reactionRow(mobileParent)}, input=document.getElementById('msg-input');
    row.focus();
    row.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true,cancelable:true}));
    input.focus();
    let passed=false;
    const receive=()=>{passed=true;};
    input.addEventListener('keydown',receive,{once:true});
    input.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));
    input.removeEventListener('keydown',receive);
    return passed&&document.activeElement===input&&!row.querySelector('.message-actions');
  })()`));
  const late='delayed echo fixture '+stamp;
  check('a 45-second local echo still attaches its already received reaction anchor',await ev(`(()=>{
    const conn_id=${q(networkA)}, target=${q(channel)}, text=${q(late)}, from=getNick(conn_id);
    const ts=Math.floor(Date.now()/1000), key=bk(conn_id,target), oldCursor=_lastMsgId[key], msg_id=900000001;
    const message={ts:ts-45,from,text,kind:'privmsg',own:true};
    const previous={ts:ts-50,from,text:'earlier fixture',kind:'privmsg',own:true};
    addMessage(conn_id,target,previous);
    addMessage(conn_id,target,message);
    (window._sentMsgs||=[]).push({t:Date.now()-45000,conn:conn_id,target,text,row:message});
    handleEvent({type:'reaction_anchor',conn_id,target,msg_id,reference:'FixtureMessageId'});
    handleEvent({type:'irc_echo',conn_id,target,msg_id,from,text,ts,kind:'Privmsg'});
    const row=${reactionRow(late)};
    const ready=message.id===msg_id&&!!row&&!!messageReactionFor(row);
    const buffer=getBuf(conn_id,target);buffer.splice(buffer.indexOf(message),1);
    window._sentMsgs.push({t:Date.now(),conn:conn_id,target,text,row:message});
    handleEvent({type:'irc_echo',conn_id,target,msg_id:msg_id+1,from,text,ts,kind:'Privmsg'});
    buffer.splice(buffer.indexOf(previous),1);
    if(oldCursor===undefined)delete _lastMsgId[key];else _lastMsgId[key]=oldCursor;
    renderChat();
    return ready&&!previous.id;
  })()`));
  await waitFor(()=>ev('_rateTimer===null&&_rateQueue.length===0'),'idle send queue before refused-send check');
  check('an immediate refusal marks the optimistic row as failed',await ev(`(()=>{
    const original=_queuedPlainVerdict, msg={ts:0,text:'test',kind:'privmsg'};
    try{
      _queuedPlainVerdict=()=>({refuse:true,target:${q(channel)},reason:'test fixture'});
      _queueChatSend({type:'send',conn_id:${q(networkA)},raw:'PRIVMSG '+${q(channel)}+' :test'},msg);
      return msg.sendState==='failed';
    }finally{
      _queuedPlainVerdict=original;
      clearTimeout(_rateTimer);_rateTimer=null;
    }
  })()`));
  const noReaction=`unsupported parent ${stamp}`;
  await ev(`setActive(${q(unsupportedNetwork)},${q(other)})`);
  otherWs.send({type:'send',conn_id:unsupportedSender,raw:`PRIVMSG ${unsupportedNick} :${noReaction}`});
  await waitFor(()=>ev(`!!(${reactionRow(noReaction)})`),'unsupported network message');
  check('a message on an unsupported IRCd offers Reply only',await ev(`(()=>{
    const row=${reactionRow(noReaction)};
    row.querySelector('.msg-body').click();
    const buttons=row.querySelectorAll('.message-actions button');
    const replyOnly=buttons.length===1&&buttons[0].textContent==='Reply';
    buttons[0]?.click();
    const targeted=_replyTo?.text===${q(noReaction)}&&_replyTo?.conn_id===${q(unsupportedNetwork)};
    cancelReply();
    return replyOnly&&targeted;
  })()`));

  await ev(`setActive(${q(networkA)},${q(channel)});lastChatEffect=-Infinity`);
  await cdp('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'no-preference'}]});
  send(channel,'fireworks');
  check('an exact live cue plays fireworks',await waitFor(()=>ev("document.querySelectorAll('.chat-effect-layer .effect-spark').length===36"),'live fireworks effect'));
  const cooldown=await ev(`(()=>{const layer=chatEffectLayer;playChatEffect(${q(networkA)},${q(channel)},'confetti');return chatEffectLayer===layer;})()`);
  check('effects respect a cooldown',cooldown);
  for (const [cue, effect] of [['congrats!','.effect-paper'],['happy birthday!','🎈'],['hearts','♥']]) {
    await ev('clearChatEffect();lastChatEffect=-Infinity');
    send(channel,cue);
    check(cue+' plays a live chat effect',await waitFor(()=>ev(`[...document.querySelectorAll('.chat-effect-layer i')]
      .some(p=>${effect.startsWith('.') ? `p.matches(${q(effect)})` : `p.textContent===${q(effect)}`})`),'live effect '+cue));
  }
  await cdp('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  check('effects respect reduced motion',await ev(`clearChatEffect();lastChatEffect=-Infinity;playChatEffect(${q(networkA)},${q(channel)},'hearts');!chatEffectLayer`));
  await cdp('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'no-preference'}]});
  check('the device effects setting suppresses animations',await ev(`(()=>{
    const toggle=document.getElementById('notif-chat-effects');toggle.click();
    playChatEffect(${q(networkA)},${q(channel)},'balloons');const quiet=!chatEffectLayer;
    toggle.click();return quiet;
  })()`));
  check('replaying a buffered cue does not start an animation',await ev('renderChat();!chatEffectLayer'));
  check('reaction frames stay out of ordinary private chat text',!ownerWs.events.some(e=>e.type==='irc_message'&&['❤️','❤️ 1'].includes(e.text)));
}

export async function checkSealedReaction({browser,peer,check,waitFor,sourceWs,text,target,emoji}){
  await waitFor(()=>peer.evaluate(`(()=>{const row=${reactionRow(text)};return !!row&&!!messageReactionFor(row);})()`),'encrypted message reaction anchor');
  const sent=peer.frames.length, before=sourceWs.events.length;
  check('encrypted '+target+' lets the recipient choose a reaction',await peer.evaluate(reactionButton(text,emoji)));
  await waitFor(()=>sourceWs.events.slice(before).some(e=>e.type==='sealed_reaction'),'encrypted reaction delivered over IRC');
  check('encrypted '+target+' displays the correct reaction to the sender',await waitFor(()=>browser.evaluate(
    `(${reactionRow(text)})?.querySelector('.reaction-count')?.textContent===${q(emoji+' 1')}`),'sealed reaction rendered'));
  const outbound=peer.frames.slice(sent).map(frame=>JSON.parse(frame)).find(frame=>frame.type==='react');
  check('encrypted '+target+' keeps emoji and message reference inside ciphertext',
    !!outbound&&outbound.reaction.kind==='sealed'&&typeof outbound.reaction.body==='string'&&
    !JSON.stringify(outbound).includes(emoji)&&!Object.hasOwn(outbound.reaction,'reference'));
  await waitFor(()=>peer.evaluate(`(${reactionRow(text)})?.querySelector('.reaction-count')?.getAttribute('aria-pressed')==='true'`),
    'IRC echo confirms own encrypted reaction');
  const beforeUndo=sourceWs.events.length;
  check('encrypted '+target+' lets the recipient remove their own reaction',await peer.evaluate(reactionButton(text,emoji)));
  await waitFor(()=>sourceWs.events.slice(beforeUndo).some(e=>e.type==='sealed_reaction'),'encrypted removal delivered');
  check('encrypted '+target+' removes the count beside the original message',await waitFor(()=>browser.evaluate(
    `!(${reactionRow(text)})?.querySelector('.reaction-count')`),'sealed removal rendered'));
}
