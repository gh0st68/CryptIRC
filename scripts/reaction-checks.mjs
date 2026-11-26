const q=JSON.stringify;

export function reactionRow(text){
  return `[...document.querySelectorAll('#chat-area .msg-row')].find(r=>r._msgRef?.text===${q(text)})`;
}

export function reactionButton(text,emoji){
  return `(()=>{const row=${reactionRow(text)};const toggle=row?.querySelector('.reaction-picker');
    if(!toggle)return false;
    if(toggle.getAttribute('aria-expanded')==='false')toggle.click();
    const button=[...row.querySelectorAll('.reaction-choice')].find(b=>b.textContent===${q(emoji)});
    if(!button)return false;
    button.click();return true;
  })()`;
}

export async function checkPlainReactions({ev,cdp,check,waitFor,ownerWs,otherWs,owner,other,networkA,networkB,channel,stamp,unsupportedNetwork,unsupportedSender,unsupportedNick}){
  const send=(target,text)=>otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${target} :${text}`});
  for(const [target,conversation] of [[channel,channel],[owner,other]]){
    const parent=`reaction parent ${target} ${stamp}`;
    await ev(`setActive(${q(networkA)},${q(conversation)})`);
    send(target,parent);
    await waitFor(()=>ev(`!!(${reactionRow(parent)})?.querySelector('.reaction-picker')`),'reaction picker for real IRC message');
    const before=otherWs.events.length;
    check('the picker adds a reaction in '+(target===channel?'a channel':'a PM'),await ev(reactionButton(parent,'❤️')));
    await waitFor(()=>otherWs.events.slice(before).some(e=>e.type==='irc_reaction'&&e.emoji==='❤️'&&!e.remove),'peer received reaction');
    check('a heart count shows beside the original message',await waitFor(()=>ev(`(${reactionRow(parent)})?.querySelector('.reaction-count')?.textContent==='❤️ 1'`),'own reaction confirmed'));
    check('the picker removes your own reaction',await ev(reactionButton(parent,'❤️')));
    await waitFor(()=>otherWs.events.slice(before).some(e=>e.type==='irc_reaction'&&e.emoji==='❤️'&&e.remove),'peer received removal');
    check('removing the last reaction clears its count',await waitFor(()=>ev(`!(${reactionRow(parent)})?.querySelector('.reaction-count')`),'own reaction removal confirmed'));
  }
  await ev(`setActive(${q(networkA)},${q(channel)})`);
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
    const ready=message.id===msg_id&&!!(${reactionRow(late)})?.querySelector('.reaction-picker');
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
  check('reaction controls stay hidden on a real IRCd without the module',await ev(`!reactionEnabled(${q(unsupportedNetwork)})&&!(${reactionRow(noReaction)})?.querySelector('.reaction-picker')`));

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
  await waitFor(()=>peer.evaluate(`!!(${reactionRow(text)})?.querySelector('.reaction-picker')`),'encrypted message reaction picker');
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
