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

async function reopenReactionChat(device,connId,target,waitFor,encrypted=false){
  const before=await device.evaluate('performance.timeOrigin');
  await device.send('Page.reload');
  await waitFor(()=>device.evaluate(`performance.timeOrigin!==${before}&&window._appShown&&_wsReady()&&
    reactionEnabled(${q(connId)})${encrypted?'&&E2E._bootPhase==="ready"':''}`).catch(()=>false),'reopened reaction chat');
  await device.evaluate(`_sidebarActivate(${q(connId)},${q(target)})`);
}

export async function checkReactionHistory({browser,check,waitFor,otherWs,networkA,networkB,channel,stamp}){
  const text='persistent reaction message '+stamp;
  await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(channel)})`);
  otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${channel} :${text}`});
  await waitFor(()=>browser.evaluate(`(()=>{const row=${reactionRow(text)};return !!row&&!!messageReactionFor(row);})()`),
    'persistent plain reaction anchor');
  const choices = ['👍','❤️'];
  for (const emoji of choices) {
    const at=otherWs.events.length;
    check('can react '+emoji+' before closing the device',await browser.evaluate(reactionButton(text,emoji)));
    await waitFor(()=>otherWs.events.slice(at).some(e=>e.type==='irc_reaction'&&e.emoji===emoji),'plain reaction delivered');
  }
  const id=await browser.evaluate(`(${reactionRow(text)})._msgRef.id`);
  await waitFor(async()=>{
    const record=await reactionDiskRecord(browser,networkA,channel,id);
    return choices.every(emoji=>record?.entries.some(([code,actors])=>code===emoji&&actors.some(([actor])=>!actor)));
  },'this message’s confirmed plain reactions are saved');
  check('a temporary read failure preserves earlier saved reactions',await browser.evaluate(`(async()=>{
    const slot=reactionHistorySlot(false), read=_e2eIdbOp;
    const before=JSON.stringify([...await readReactionHistory(slot,null)]);
    _e2eIdbOp=(mode,...args)=>mode==='readonly'?Promise.reject(new Error('fixture read failure')):read(mode,...args);
    try{
      updateReactionHistory(slot,null,records=>records.clear());
      await reactionHistoryQueues.get(JSON.stringify(slot));
    }finally{_e2eIdbOp=read;}
    return before===JSON.stringify([...await readReactionHistory(slot,null)]);
  })()`));
  await browser.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:3,mobile:true});
  try {
    await reopenReactionChat(browser,networkA,channel,waitFor);
    check('own Like and Heart survive an iPhone-width page reopen',await waitFor(()=>browser.evaluate(`(()=>{
      const row=${reactionRow(text)};
      return ${q(choices)}.every(emoji=>[...row?.querySelectorAll('.reaction-count[aria-pressed=true]')||[]]
        .some(chip=>chip.textContent===emoji+' 1'));
    })()`),'reopened Like and Heart'));
    const at=otherWs.events.length;
    check('a reopened reaction can be removed from the original message',await browser.evaluate(reactionButton(text,'❤️')));
    await waitFor(()=>otherWs.events.slice(at).some(e=>e.type==='irc_reaction'&&e.emoji==='❤️'&&e.remove),'plain removal delivered');
    await waitFor(()=>browser.evaluate('reactionHistoryQueues.size===0'),'saved reaction removal');
    await reopenReactionChat(browser,networkA,channel,waitFor);
    check('removing Heart persists without removing Like',await waitFor(()=>browser.evaluate(`(()=>{
      const row=${reactionRow(text)};
      return row?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1'&&row.querySelectorAll('.reaction-count').length===1;
    })()`),'reopened after removing Heart'));
  } finally { await browser.send('Emulation.clearDeviceMetricsOverride'); }
}

// Delay delivery of one real own echo to this document without affecting the
// independent account sockets, server acknowledgements, or other IRC events.
function holdOwnReactionEcho(connId,target,type,plain){
  return `(()=>{
    const socket=ws, deliver=socket.onmessage, blocked=[];
    window.reactionEchoFixture={blocked,release(replay){
      if(socket===ws)socket.onmessage=deliver;
      if(replay&&socket===ws)for(const message of blocked)deliver.call(socket,message);
      delete window.reactionEchoFixture;
    }};
    socket.onmessage=function(message){
      const ev=JSON.parse(message.data), plain=${q(plain||null)};
      if(ev.type===${q(type)}&&ev.own===true&&ev.conn_id===${q(connId)}&&ev.target===${q(target)}&&
          (!plain||(ev.reference===plain.reference&&ev.emoji===plain.emoji&&ev.remove===plain.remove))){
        blocked.push(message);
        return;
      }
      deliver.call(socket,message);
    };
  })()`;
}

function reactionDiskRecord(browser,connId,target,id,encrypted=false){
  return browser.evaluate(`(async()=>{
    const slot=reactionHistorySlot(${encrypted});
    const records=await readReactionHistory(slot,${encrypted?'E2E.e2eEncKey':'null'});
    return records.get(reactionHistoryKey(${q(connId)},${q(target)},${q(id)}))||null;
  })()`);
}

export async function checkReactionEchoDurability({browser,reopen,dateReceipt,ownerWs,otherWs,check,waitFor,networkA,networkB,channel,owner,stamp}){
  const choices=['👍','❤️'];
  const ownChoices=record=>record?.entries.filter(([,actors])=>actors.some(([actor,nick])=>!actor&&nick===owner))
    .map(([emoji])=>emoji).sort().join(',');
  const observe=(observer,conn,reference,emoji,remove,own,start)=>observer.events.slice(start).filter(event=>
    event.type==='irc_reaction'&&event.conn_id===conn&&event.target===channel&&event.reference===reference&&
    event.emoji===emoji&&event.remove===remove&&event.own===own);
  const results=[];
  for(const context of ['browser reopen','web-only restart','overnight reopen']){
    const webRestart=context==='web-only restart';
    const overnight=context==='overnight reopen';
    const text=`reaction echo durability ${context} ${stamp}`;
    await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(channel)})`);
    otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${channel} :${text}`});
    const {id,reference}=await waitFor(()=>browser.evaluate(`(()=>{
      const row=${reactionRow(text)}, reaction=row&&messageReactionFor(row);
      return reaction&&row._msgRef?.id ? {id:row._msgRef.id,reference:reaction.reference} : null;
    })()`),'real reaction anchor before '+context);
    const disk=()=>reactionDiskRecord(browser,networkA,channel,id);
    const expected=(record,emojis)=>record?.reference===reference&&record.anchor===reference&&
      record.entries.length===emojis.length&&record.entries.every(([,actors])=>actors.length===1)&&
      ownChoices(record)===[...emojis].sort().join(',');
    for(const emoji of choices){
      const at=otherWs.events.length;
      check('the real message accepts '+emoji+' before '+context,await browser.evaluate(reactionButton(text,emoji)));
      await waitFor(()=>observe(otherWs,networkB,reference,emoji,false,false,at).length===1,'peer receives '+emoji);
    }
    await waitFor(async()=>expected(await disk(),choices),'IndexedDB contains both confirmed reactions');

    if(context==='browser reopen'){
      const at=otherWs.events.length;
      await browser.evaluate(`(()=>{
        const send=wsend, receive=receiveReactionResult;
        window.reactionRejectionFixture={request:null,error:null,release(){
          wsend=send;receiveReactionResult=receive;delete window.reactionRejectionFixture;
        }};
        wsend=frame=>{
          if(frame.type==='react'&&frame.conn_id===${q(networkA)}&&frame.target===${q(channel)}&&frame.reaction.emoji==='😂'){
            window.reactionRejectionFixture.request=frame.request_id;
            // A stale message anchor is a normal server-side rejection.
            frame={...frame,reaction:{...frame.reaction,reference:${q('expired-'+stamp)}}};
          }
          return send(frame);
        };
        receiveReactionResult=event=>{
          const fixture=window.reactionRejectionFixture;
          if(event.request_id===fixture.request&&event.error)fixture.error=event.error;
          return receive(event);
        };
      })()`);
      try{
        check('a rejected reaction starts from the real message action',await browser.evaluate(reactionButton(text,'😂')));
        await waitFor(()=>browser.evaluate('!!window.reactionRejectionFixture.error'),'real server rejects the stale anchor');
        check('a rejected reaction leaves the confirmed UI and IndexedDB state intact',
          expected(await disk(),choices)&&!observe(otherWs,networkB,reference,'😂',false,false,at).length&&
          !await browser.evaluate(`(${reactionRow(text)})?.textContent.includes('😂')`));
        await waitFor(()=>browser.evaluate(`(async()=>{
          const journal=await readReactionHistory(reactionHistorySlot(false),null);
          return !journal.has('receipt:'+window.reactionRejectionFixture.request);
        })()`),'a rejected click leaves no replayable receipt in IndexedDB');
      } finally { await browser.evaluate('window.reactionRejectionFixture?.release()'); }
    }

    const ownerAt=ownerWs.events.length, peerAt=otherWs.events.length;
    await browser.evaluate(holdOwnReactionEcho(networkA,channel,'irc_reaction',{reference,emoji:'❤️',remove:true}));
    check('the sender removes Heart through the real message menu before '+context,
      await browser.evaluate(reactionButton(text,'❤️')));
    const confirmation=await waitFor(()=>{
      const own=observe(ownerWs,networkA,reference,'❤️',true,true,ownerAt);
      return observe(otherWs,networkB,reference,'❤️',true,false,peerAt).length===1&&own.length===1 ? own[0] : null;
    },'peer and independent sender sockets confirm the real Heart removal');
    await waitFor(()=>browser.evaluate('window.reactionEchoFixture.blocked.length===1'),'the browser’s own Heart removal echo was withheld');
    check('the withheld own echo never reached the browser reducer before '+context,expected(await disk(),choices));
    const receiptKey=confirmation.receipt?.request_id && 'receipt:'+confirmation.receipt.request_id;
    const pending=()=>browser.evaluate(`(async()=>{
      const journal=await readReactionHistory(reactionHistorySlot(false),null);
      return journal.has(${q(receiptKey||'')});
    })()`);
    if(receiptKey) check('the actual confirmed removal has a matching pending IndexedDB action before '+context,await pending());
    const dated=overnight&&confirmation.receipt ? await dateReceipt(browser,confirmation.receipt,ownerWs) : null;
    ({browser,ownerWs,otherWs}=await reopen(browser,webRestart));
    await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(channel)})`);
    const restored=async()=>({record:await disk(),ui:await browser.evaluate(`(()=>{
      const row=${reactionRow(text)};
      return !!row&&row._msgRef.id===${q(id)}&&row.querySelectorAll('.reaction-count').length===1&&
        row.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1';
    })()`)});
    const good=await waitFor(async()=>{
      const state=await restored();
      return state.ui&&expected(state.record,['👍'])&&(!receiptKey||!await pending());
    },'only Like is rendered and on disk after '+context,10000).catch(()=>false);
    if(!good){
      const state=await restored();
      console.log('REACTION-DURABILITY '+JSON.stringify({context,ui:state.ui,stored:ownChoices(state.record),
        peerConfirmed:true,appEchoWithheld:true}));
    }
    const requested=dated&&browser.frames.some(frame=>{
      const message=JSON.parse(frame);
      return message.type==='get_reaction_receipts'&&message.conn_id===networkA&&
        message.request_ids?.includes(confirmation.receipt.request_id);
    });
    if(dated) console.log('REACTION-OVERNIGHT '+JSON.stringify({...dated,browserRequestedReceipt:requested,restoredLikeOnly:good}));
    results.push([context,good&&(!overnight||(dated?.serverStillConfirms&&requested))]);
  }
  for(const [context,good] of results)check(context==='overnight reopen' ?
    'only Like survives a simulated fourteen-hour absence after the real Heart removal' :
    'only Like survives '+context+' in the UI and IndexedDB without processing the own echo',good);
}

export async function checkReactionMidpoint({browser,reopen,gate,witness,ownerWs,otherWs,check,waitFor,networkA,networkB,channel,owner,stamp}){
  const unlabeled=process.env.CRYPTIRC_TEST_REACTION_UNLABELED==='1';
  if(unlabeled){
    let withdrawn=false;
    gate.match=event=>{
      if(event.conn_id===networkA&&event.line.includes(' CAP ')&&event.line.includes(' ACK ')){
        withdrawn ||= event.line.split(' :').at(-1).trim().split(/ +/).includes('-labeled-response');
      }
      return false;
    };
    ownerWs.send({type:'send',conn_id:networkA,raw:'CAP REQ :-labeled-response'});
    check('the real IRC server acknowledged dropping labeled-response',await waitFor(()=>withdrawn,'IRC CAP ACK -labeled-response'));
  }
  const text='reaction midpoint fixture '+stamp;
  await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(channel)})`);
  otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${channel} :${text}`});
  const {id,reference}=await waitFor(()=>browser.evaluate(`(()=>{
    const row=${reactionRow(text)}, reaction=row&&messageReactionFor(row);
    return reaction&&row._msgRef?.id ? {id:row._msgRef.id,reference:reaction.reference} : null;
  })()`),'a real message is available for midpoint reactions');
  const disk=()=>reactionDiskRecord(browser,networkA,channel,id);
  const ownChoices=record=>record?.entries.filter(([,actors])=>actors.some(([actor,nick])=>!actor&&nick===owner))
    .map(([emoji])=>emoji).sort().join(',');
  for(const emoji of ['👍','❤️']){
    const at=otherWs.events.length;
    check('midpoint fixture really clicks '+emoji,await browser.evaluate(reactionButton(text,emoji)));
    await waitFor(()=>otherWs.events.slice(at).some(event=>event.type==='irc_reaction'&&event.reference===reference&&
      event.emoji===emoji&&event.remove===false),'the peer sees '+emoji);
  }
  await waitFor(async()=>ownChoices(await disk())==='❤️,👍','IndexedDB confirms both choices before the restart');

  const parse=line=>{
    const [fields,prefix,command,target]=line.trim().split(' ');
    return {prefix,command,target,tags:new Map(fields.slice(1).split(';').map(tag=>tag.split('=',2)))};
  };
  const matches=line=>{
    const {prefix,command,target,tags}=parse(line);
    return command==='TAGMSG'&&prefix?.startsWith(`:${owner}!`)&&target===channel&&
      (tags.get('+reply')??tags.get('+draft/reply'))===reference&&tags.get('+draft/unreact')==='❤️';
  };
  gate.match=event=>event.conn_id===networkA&&matches(event.line);
  const at=witness.lines.length, ownerAt=ownerWs.events.length, frameAt=browser.frames.length;
  check('a real browser click queues the Heart removal before web stops',await browser.evaluate(reactionButton(text,'❤️')));
  const request=await waitFor(()=>browser.frames.slice(frameAt).map(frame=>JSON.parse(frame)).find(frame=>
    frame.type==='react'&&frame.reaction?.reference===reference&&frame.reaction?.remove===true),
  'browser sends the actual removal request');
  await waitFor(()=>gate.held,'the old core receives the actual own IRC echo while the web handler is gated');
  const relayed=await waitFor(()=>witness.lines.slice(at).find(matches),'a separate connection to the linked IRC server receives the real Heart removal');
  check('the real IRC reaction reached the peer while old web had not processed its own echo',
    ownChoices(await disk())==='❤️,👍'&&!ownerWs.events.slice(ownerAt).some(event=>event.type==='irc_reaction'&&event.own&&
      event.reference===reference&&event.remove===true));
  check('the browser already journaled the genuine action before the web restart',await browser.evaluate(`(async()=>{
    const records=await readReactionHistory(reactionHistorySlot(false),null);
    return records.has(${q('receipt:'+request.request_id)});
  })()`));

  ({browser,ownerWs,otherWs}=await reopen(browser,true));
  const replay=await waitFor(()=>gate.replay,'the surviving core replays the matching reaction over IPC');
  const ircBatch=parse(replay.line).tags.has('batch');
  check('the existing core replays the same raw TAGMSG as IPC backlog outside IRCv3 CHATHISTORY',
    replay.line===gate.held.line&&replay.replayed===true&&replay.backlog===true&&!ircBatch);
  await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(channel)})`);
  const rendered=()=>browser.evaluate(`(()=>{
    const row=${reactionRow(text)};
    return !!row&&row._msgRef.id===${q(id)}&&row.querySelectorAll('.reaction-count').length===1&&
      row.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1';
  })()`);
  const restored=await waitFor(async()=>await rendered()&&ownChoices(await disk())==='👍',
    'the replacement web restores only Like in the original profile',10000).catch(()=>false);
  const acknowledgedAt=ownerWs.events.length;
  ownerWs.send({type:'get_reaction_receipts',conn_id:networkA,request_ids:[request.request_id]});
  const response=await waitFor(()=>ownerWs.events.slice(acknowledgedAt).find(event=>
    event.type==='reaction_receipts'&&event.conn_id===networkA),'replacement web answers the actual receipt lookup');
  const confirmed=response.receipts.some(receipt=>receipt.request_id===request.request_id);
  const ownLabel=parse(replay.line).tags.has('label'), peerLabel=parse(relayed).tags.has('label');
  console.log('REACTION-MIDPOINT '+JSON.stringify({peerConfirmed:true,ipcReplayed:replay.replayed,ipcBacklog:replay.backlog,
    ircBatch,sequenced:replay.seq>0,ownLabel,peerLabel,confirmed,restoredLikeOnly:restored,stored:ownChoices(await disk())}));
  check('a web restart before handling the real own IRC echo still commits the Heart removal',
    confirmed&&restored&&ownLabel===!unlabeled&&!peerLabel);

  const joinedText='reaction after replacement web '+stamp;
  otherWs.send({type:'send',conn_id:networkB,raw:`PRIVMSG ${channel} :${joinedText}`});
  const {id:joinedId,reference:joinedAnchor}=await waitFor(()=>browser.evaluate(`(()=>{
    const row=${reactionRow(joinedText)}, reaction=row&&messageReactionFor(row);
    return reaction&&row._msgRef?.id ? {id:row._msgRef.id,reference:reaction.reference} : null;
  })()`),'a new channel message has a real IRC anchor after the web restart');
  const newHeart=line=>{
    const {prefix,command,target,tags}=parse(line);
    return command==='TAGMSG'&&prefix?.startsWith(`:${owner}!`)&&target===channel&&
      (tags.get('+reply')??tags.get('+draft/reply'))===joinedAnchor&&tags.get('+draft/react')==='❤️';
  };
  let newEcho;
  gate.match=event=>{
    if(event.conn_id===networkA&&newHeart(event.line))newEcho=event.line;
    return false;
  };
  const witnessAt=witness.lines.length;
  check('the reopened browser can click a new Heart after the web-only restart',
    await browser.evaluate(reactionButton(joinedText,'❤️')));
  const newRelay=await waitFor(()=>newEcho&&witness.lines.slice(witnessAt).find(newHeart),
    'the core and an independent IRC client see the new post-restart reaction');
  check(unlabeled?'the new IRC reaction after web restart succeeds without labels on either connection':
      'the new IRC reaction after web restart has a label only on the sending connection',
    parse(newEcho).tags.has('label')===!unlabeled&&!parse(newRelay).tags.has('label'));
  await waitFor(()=>browser.evaluate(`(${reactionRow(joinedText)})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='❤️ 1'`),
    'the new Heart is confirmed in the reopened browser');

  // The witness opens a disposable moderated room so Unreal sends a real
  // ERR_CANNOTSENDTOCHAN instead of silently dropping an offline reaction.
  const moderated='#rxmod'+stamp, moderatedText='moderated reaction after restart '+stamp;
  witness.send('JOIN '+moderated);
  await waitFor(()=>witness.lines.some(line=>line.includes(' 353 ')&&line.includes(' '+moderated+' :')),
    'the independent witness opened the disposable moderated room');
  witness.send('MODE '+moderated+' +m');
  await waitFor(()=>witness.lines.some(line=>line.includes(' MODE '+moderated+' +m')),
    'the independent witness enabled moderation');
  ownerWs.send({type:'send',conn_id:networkA,raw:'JOIN '+moderated});
  await waitFor(()=>browser.evaluate(`!!networks.find(n=>n.config.id===${q(networkA)})?.channels.some(c=>c.name===${q(moderated)})`),
    'the browser joined the moderated room without voice');
  await browser.evaluate(`_sidebarActivate(${q(networkA)},${q(moderated)})`);
  witness.send(`PRIVMSG ${moderated} :${moderatedText}`);
  const moderatedAnchor=await waitFor(()=>browser.evaluate(`(${reactionRow(moderatedText)})&&
    messageReactionFor(${reactionRow(moderatedText)})?.reference`),'the moderated room message has a real IRC anchor');
  let moderatedRejection;
  gate.match=event=>{
    if(event.conn_id===networkA&&event.line.includes(` 404 ${owner} ${moderated} `))moderatedRejection=event.line;
    return false;
  };
  await browser.evaluate(`(()=>{
    const receive=receiveReactionResult;
    receiveReactionResult=event=>event.error?undefined:receive(event);
  })()`);
  const resultAt=ownerWs.events.length, submitAt=browser.frames.length;
  check('the reopened browser submits a real reaction in the moderated room',
    await browser.evaluate(reactionButton(moderatedText,'❤️')));
  const submitted=await waitFor(()=>browser.frames.slice(submitAt).map(JSON.parse).find(frame=>
    frame.type==='react'&&frame.target===moderated&&frame.reaction?.reference===moderatedAnchor),
  'the new moderated reaction is submitted');
  await waitFor(()=>moderatedRejection,'the original IRC connection received numeric 404 from the moderated room');
  if(unlabeled){
    // Allow both observer sockets to finish processing the controlled refusal.
    await new Promise(resolve=>setTimeout(resolve,500));
    const refusalTags=moderatedRejection.startsWith('@')?parse(moderatedRejection).tags:new Map();
    check('an unlabeled IRC refusal claims no reaction request and preserves the confirmed Heart',
      !refusalTags.has('label')&&!refusalTags.has('batch')&&!ownerWs.events.slice(resultAt).some(event=>
        event.type==='reaction_result'&&event.error)&&
      ownChoices(await reactionDiskRecord(browser,networkA,channel,joinedId))==='❤️');
    return;
  }
  const refusal=await waitFor(()=>ownerWs.events.slice(resultAt).find(event=>event.type==='reaction_result'&&
    event.request_id===submitted.request_id&&event.error==='IRC refused this reaction.'),
  'the surviving IRC connection refuses the labeled reaction in the moderated room');
  const journaled=device=>device.evaluate(`(async()=>{
    const records=await readReactionHistory(reactionHistorySlot(false),null);
    return records.has(${q('receipt:'+submitted.request_id)});
  })()`);
  check('the real IRC refusal identifies the journaled reaction on the replacement web',await journaled(browser));
  ({browser,ownerWs}=await reopen(browser,false));
  const inMemory=await browser.evaluate(`pendingChatReactions.has(${q(submitted.request_id)})`);
  check('the reloaded profile retains the journal without an in-memory action',!inMemory&&await journaled(browser));
  await browser.evaluate(`receiveReactionResult(${q(refusal)})`);
  await waitFor(async()=>!await journaled(browser),'the late genuine refusal clears its IndexedDB action');
  check('the late real refusal removes only its journal entry and displays the IRC error',
    await browser.evaluate("document.getElementById('generic-toast')?.textContent==='IRC refused this reaction.'"));
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

export async function prepareResumeReaction({stale,peer,networkA,remote,remoteNetwork,owner,stamp,compose,waitFor}) {
  const text='rx parent '+stamp, row=reactionRow(text);
  await stale.evaluate(`setActive(${q(networkA)},${q(remote)})`);
  await waitFor(()=>peer.evaluate('!_sendLock'),'the author can send the encrypted reaction parent');
  await compose(peer,remoteNetwork,owner,text);
  const reference=await waitFor(()=>stale.evaluate(`(${row})?._msgRef?.encrypted && (${row})._msgRef.reactionRef`),
    'the recipient read the encrypted parent before choosing to turn off Signal');
  await waitFor(()=>peer.evaluate(`reactionEnabled(${q(remoteNetwork)}) && (${row})?._msgRef?.reactionRef===${q(reference)}`),
    'both test accounts have the same original encrypted message reference');
  return {text,reference};
}

export async function checkResumeReaction({stale,peer,networkA,remote,remoteNetwork,owner,ownerWs,parent,finish,waitFor,check}) {
  const row=reactionRow(parent.text);
  await stale.evaluate(`(()=>{
    const dispatch=handleEvent, key=_e2eDmKey(${q(remote)},${q(networkA)});
    const flow=window.resumeGesture={arrivals:[],key,restore:()=>{handleEvent=dispatch;}};
    handleEvent=event=>{
      if(event.type==='sealed_reaction' && !event.own && event.conn_id===${q(networkA)} && event.from===${q(remote)})
        flow.arrivals.push({body:event.body,off:E2E.state.dm[key]?.on===0,pending:!!E2E._pendingOn?.[key]?.resumeResult});
      return dispatch(event);
    };
  })()`);
  try {
    await peer.evaluate(`setActive(${q(remoteNetwork)},${q(owner)})`);
    const at=peer.frames.length,mark=ownerWs.events.length;
    check('the pending Resume still displays the original readable parent with its correct reference',
      await stale.evaluate(`(${row})?._msgRef?.reactionRef===${q(parent.reference)}`));
    check('the author can Like this parent during the other device’s explicit Resume',await peer.evaluate(reactionButton(parent.text,'👍')));
    const delivery=await waitFor(()=>ownerWs.events.slice(mark).find(e=>e.type==='sealed_reaction'&&!e.own&&e.conn_id===networkA&&e.from===remote),
      'an independent IRC observer saw the sealed gesture during genuine opt-out');
    await waitFor(()=>stale.evaluate(`resumeGesture.arrivals.some(a=>a.body===${q(delivery.body)} && a.off && a.pending)`),
      'the opted-out device actually received that same event while its explicit request was waiting');
    const hidden=await stale.evaluate(`!!(${row}) && !(${row}).querySelector('.reaction-count')`);
    await finish();
    await waitFor(()=>stale.evaluate(`!E2E._pendingOn?.[resumeGesture.key] && E2E.state.dm[resumeGesture.key]?.on===1 && reactionMode(${q(networkA)},${q(remote)})==='dm'`),
      'the recipient affirmatively resumed the newer, already trusted Signal conversation');
    const received=await waitFor(()=>stale.evaluate(`(${row})?.querySelector('.reaction-count')?.textContent==='👍 1'`),
      'the recipient sees the earlier Like on the original parent after consent',6000).catch(()=>false);
    const author=await peer.evaluate(`(${row})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1'`);
    const frames=peer.frames.slice(at).map(JSON.parse).filter(e=>e.type==='react'&&e.reaction.kind==='sealed').length;
    const relay=ownerWs.events.slice(mark).filter(e=>e.type==='sealed_reaction'&&!e.own&&e.body===delivery.body).length;
    console.log('SEALED-REACTION-REAL-RESUME '+JSON.stringify({hidden,received:!!received,author,frames,relay}));
    check('the explicit device Resume restores the authentic gesture only after consent, without sending it a second time',hidden&&received&&author&&frames===1&&relay===1);
  } finally { await stale.evaluate('resumeGesture.restore()'); }
}

export async function checkFirstSignalReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,otherWs,waitFor,check,accept,oppositeGlare}){
  const mine = reactionRow(dm);
  await waitFor(()=>browser.evaluate(`(()=>{
    const m=(${mine})?._msgRef, s=E2E.dmSessions[_e2eDmKey(${q(other)},${q(networkA)})];
    return m?.encrypted && s?.x3dhPending && s.Ns===1 && !s.CKr &&
      reactionAnchors.has(reactionAnchorKey(${q(networkA)},m.id));
  })()`),'the author has a real IRC anchor for the first ordinary Signal message');
  await waitFor(()=>peer.evaluate("!!document.querySelector('#e2e-id-accept:not(:disabled)')"),'the recipient is still choosing whether to accept the first identity');
  check('the recipient has no usable Signal session while the first ordinary message is waiting for approval',
    await peer.evaluate(`reactionMode(${q(networkB)},${q(owner)})!=='dm'`));
  const mark=otherWs.events.length, at=browser.frames.length;
  const received=()=>otherWs.events.slice(mark).filter(e=>e.type==='sealed_reaction' && !e.own && e.conn_id===networkB && e.from===owner);
  check('an author can tap Heart on their first Signal message before a reply',await browser.evaluate(reactionButton(dm,'❤️')));
  await waitFor(()=>received().length===1,'one first-author Heart reaches the independent recipient on IRC');
  check('the first-author Heart stays sealed and waits behind the ordinary message and its identity prompt',
    received().length===1 && browser.frames.slice(at).map(JSON.parse).filter(f=>f.type==='react'&&f.reaction.kind==='sealed').length===1 &&
    await peer.evaluate(`!document.querySelector('#chat-area .reaction-count') && !!document.querySelector('#e2e-id-accept:not(:disabled)')`));
  await accept();
  await waitFor(()=>peer.evaluate(`(${mine})?.querySelector('.reaction-count')?.textContent==='❤️ 1'`),'after approval the recipient opens the initial text and its waiting Heart');
  check('the first-author Heart appears once beside the right text on both devices',
    received().length===1 && await browser.evaluate(`(${mine})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='❤️ 1'`));
  check('the author can remove the initial Heart without receiving a reply',await browser.evaluate(reactionButton(dm,'❤️')));
  await waitFor(()=>received().length===2,'the first-author removal reaches the independent recipient');
  await waitFor(()=>peer.evaluate(`!!(${mine}) && !(${mine}).querySelector('.reaction-count')`),'the recipient removes the initial Heart');
  if (oppositeGlare || process.env.CRYPTIRC_TEST_REACTION_RESYNC === '1')
    await checkReactionDuringReconnect({browser,peer,networkB,owner,dm,otherWs,waitFor,check});
  const manual=oppositeGlare?'bundle':process.env.CRYPTIRC_TEST_REACTION_MANUAL;
  if (['1','restart','bundle'].includes(manual))
    await checkReactionDuringSignalSetup({browser,peer,networkA,networkB,owner,other,dm,ownerWs,otherWs,waitFor,check,manual,oppositeGlare});
}

async function checkReactionDuringReconnect({browser,peer,networkB,owner,dm,otherWs,waitFor,check}) {
  const sent = browser.frames.length, observed = otherWs.events.length;
  const mine = reactionRow(dm);
  await peer.evaluate(`(() => {
    const request = _e2eReq, dispatch = handleEvent;
    const flow = window.reactionReconnect = {oldSocket:ws,arrivals:[]};
    _e2eReq = async (msg,...args) => {
      const answer=await request(msg,...args);
      if (msg.type==='e2e_load_keyring' && E2E._resyncRunning && !flow.release) {
        await new Promise(resolve=>{flow.release=resolve;});
      }
      return answer;
    };
    handleEvent=event=>{
      if (event.type==='sealed_reaction' && !event.own && event.conn_id===${q(networkB)} && event.from===${q(owner)})
        flow.arrivals.push({syncing:E2E._resyncPending,body:event.body});
      return dispatch(event);
    };
    flow.restore=()=>{flow.release?.();_e2eReq=request;handleEvent=dispatch;};
    ws.close();
  })()`);
  try {
    await waitFor(()=>peer.evaluate(`ws!==reactionReconnect.oldSocket && _wsReady() && E2E._resyncPending && !!reactionReconnect.release && reactionEnabled(${q(networkB)})`),'the real reconnected recipient is waiting for its authenticated keyring response');
    check('author can Like the original encrypted message while its recipient reconnects',await browser.evaluate(reactionButton(dm,'👍')));
    const arrival=await waitFor(()=>otherWs.events.slice(observed).find(e=>e.type==='sealed_reaction'&&!e.own&&e.conn_id===networkB&&e.from===owner),'the recipient’s independent observer receives the sealed Like');
    await waitFor(()=>peer.evaluate(`reactionReconnect.arrivals.some(e=>e.syncing && e.body===${q(arrival.body)})`),'the real recipient browser sees the identical sealed event during its resync');
    await new Promise(resolve=>setTimeout(resolve,280));
    await peer.evaluate('reactionReconnect.release()');
    await waitFor(()=>peer.evaluate(`!E2E._resyncPending && reactionMode(${q(networkB)},${q(owner)})==='dm'`),'the original contact and authenticated session are ready on the new connection');
    await peer.evaluate(`setActive(${q(networkB)},${q(owner)})`);
    const like=await waitFor(()=>peer.evaluate(`(${mine})?.querySelector('.reaction-count')?.textContent==='👍 1'`),'the recipient displays the Like after resync',4000).catch(()=>false);
    const state={receiver:!!like,author:await browser.evaluate(`(${mine})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1'`),
      senderFrames:browser.frames.slice(sent).map(JSON.parse).filter(e=>e.type==='react'&&e.reaction.kind==='sealed').length,
      relay:otherWs.events.slice(observed).filter(e=>e.type==='sealed_reaction'&&!e.own&&e.body===arrival.body).length,
      syncing:await peer.evaluate('reactionReconnect.arrivals[0]?.syncing'),reader:await peer.evaluate(`!!(${mine})?._msgRef?.encrypted`)};
    console.log('SEALED-REACTION-RECONNECT '+JSON.stringify(state));
    check('one real Like received during a short authenticated reconnect appears on the same original message in both browsers',state.receiver&&state.author&&state.senderFrames===1&&state.relay===1&&state.syncing&&state.reader);
    check('the author can undo the Like after the recipient resumes',await browser.evaluate(reactionButton(dm,'👍')));
    await waitFor(()=>peer.evaluate(`!!(${mine}) && !(${mine}).querySelector('.reaction-count')`),'the recipient removes the resynchronized Like');
  } finally { await peer.evaluate('reactionReconnect.restore()'); }
}

export async function checkReactionDuringSignalSetup({browser,peer,networkA,networkB,owner,other,dm,ownerWs,otherWs,waitFor,check,manual,oppositeGlare}) {
  const mine=reactionRow(dm), late=manual==='bundle', restart=manual!=='1', command=restart?'restart':'on';
  const compose=text=>peer.evaluate(`(()=>{
    setActive(${q(networkB)},${q(owner)});
    const input=document.getElementById('msg-input');
    input.value=${q(text)};
    input.dispatchEvent(new Event('input',{bubbles:true}));
    document.getElementById('send-btn').click();
  })()`);
  await peer.evaluate(`(()=>{
    const request=_e2eReq, dispatch=handleEvent, key=_e2eDmKey(${q(owner)},${q(networkB)});
    const start=()=>E2E.dmSessions[key]?.startEph||E2E.dmSessions[key]?.establishEph;
    const flow=window.manualReaction={arrivals:[],key,start,pin:E2E.trustStore[key].fingerprint,original:start()};
    _e2eReq=async(msg,...args)=>{
      const reply=await request(msg,...args);
      if(!${q(late)} && msg.type==='e2e_load_session' && msg.partner==='__state__' && E2E._pendingOn?.[key]?.checking && !flow.release)
        await new Promise(resolve=>{flow.release=resolve;});
      return reply;
    };
    handleEvent=event=>{
      const pending=E2E._pendingOn?.[key];
      if(${q(late)} && event.type==='e2e_bundle' && event.username===${q(owner)} && pending?.req===event.req && !flow.release) {
        let released=false;
        flow.release=()=>{if(!released){released=true;dispatch(event);}};
        return;
      }
      if(event.type==='sealed_reaction' && !event.own && event.conn_id===${q(networkB)} && event.from===${q(owner)})
        flow.arrivals.push({body:event.body,checking:${q(late)}?!!pending?.replacementRevision:!!pending?.checking,
          trusted:flow.original===start() && flow.pin===E2E.trustStore[key]?.fingerprint && !E2E.trustStore[key]?.keyChanged});
      return dispatch(event);
    };
    flow.restore=()=>{flow.release?.();_e2eReq=request;handleEvent=dispatch;};
  })()`);
  try {
    await compose('/encrypt '+command+' '+owner);
    await waitFor(()=>peer.evaluate(`!!manualReaction.release && reactionMode(${q(networkB)},${q(owner)})==='blocked' && !!(${mine})`),
      'the real manual command checks an already approved Signal chat while sends are held');
    const first=browser.frames.length, mark=otherWs.events.length;
    check('an author can Like existing text while its recipient checks the Signal session',await browser.evaluate(reactionButton(dm,'👍')));
    const arrival=await waitFor(()=>otherWs.events.slice(mark).find(e=>e.type==='sealed_reaction'&&!e.own&&e.conn_id===networkB&&e.from===owner),
      'the independent IRC observer sees the sealed Like during the command');
    await waitFor(()=>peer.evaluate(`manualReaction.arrivals.some(a=>a.checking && a.trusted && a.body===${q(arrival.body)})`),
      'the receiving browser saw the identical gesture while still on the original accepted session');
    if (late) {
      await peer.evaluate(`_e2eEnqueue(${q(networkB)},${q(owner)},()=>true)`);
      const text='incoming '+dm.slice(-6), sentAt=browser.frames.length, ircAt=otherWs.events.length;
      await waitFor(()=>browser.evaluate('!_sendLock'),'the author’s ordinary composer is ready');
      await browser.evaluate(`(()=>{
        setActive(${q(networkA)},${q(other)});
        const input=document.getElementById('msg-input');input.value=${q(text)};
        input.dispatchEvent(new Event('input',{bubbles:true}));document.getElementById('send-btn').click();
      })()`);
      const wire=await waitFor(()=>otherWs.events.slice(ircAt).find(e=>e.type==='irc_message'&&e.conn_id===networkB&&e.from===owner&&e.text?.startsWith('[e2edm2]')),
        'an independent recipient saw the new ordinary encrypted text during the same pending Restart');
      check('the ordinary text also advances the trusted session while replacement is waiting',
        await waitFor(()=>peer.evaluate(`!!(${reactionRow(text)})?._msgRef?.encrypted && !!E2E._pendingOn?.[manualReaction.key]?.replacementRevision`),
          'the recipient reads the ordinary text before releasing the genuine Restart bundle') &&
        browser.frames.slice(sentAt).map(JSON.parse).filter(e=>e.type==='send'&&e.raw?.endsWith(' :'+wire.text)).length===1);
    } else await new Promise(resolve=>setTimeout(resolve,220));
    await peer.evaluate('manualReaction.release()');
    await waitFor(()=>peer.evaluate(`!E2E._pendingOn?.[manualReaction.key] && reactionMode(${q(networkB)},${q(owner)})==='dm'`),
      'the manual Signal command returns to encrypted messaging');
    const recipient=await waitFor(()=>peer.evaluate(`(${mine})?.querySelector('.reaction-count')?.textContent==='👍 1'`),
      'the real recipient still has the original text and its Like',4000).catch(()=>false);
    const state=await peer.evaluate(`(()=>{const f=manualReaction,t=E2E.trustStore[f.key],m=(${mine})?._msgRef;
      return {sameSession:f.original===f.start(),samePin:f.pin===t?.fingerprint && !t?.keyChanged,
        consent:E2E.state?.dm?.[f.key]?.on===1,originalReadable:!!m?.encrypted,anchor:!!m?.reactionRef,
        pendingAtArrival:f.arrivals[0]?.checking,sameDuring:f.arrivals[0]?.trusted};})()`);
    Object.assign(state,{recipient:!!recipient,author:await browser.evaluate(`(${mine})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent==='👍 1'`),
      senderFrames:browser.frames.slice(first).map(JSON.parse).filter(e=>e.type==='react'&&e.reaction.kind==='sealed').length,
      relay:otherWs.events.slice(mark).filter(e=>e.type==='sealed_reaction'&&!e.own&&e.body===arrival.body).length});
    console.log((late?'SEALED-REACTION-RESTART-BUNDLE ':restart?'SEALED-REACTION-RESTART ':'SEALED-REACTION-MANUAL ')+JSON.stringify(state));
    check('both users retain the Like on the original message after /encrypt '+command,state.recipient&&state.author&&
      state.samePin&&state.sameDuring&&state.sameSession===!restart&&state.consent&&state.originalReadable&&state.anchor&&
      state.senderFrames===1&&state.relay===1&&state.pendingAtArrival);
    if (restart) {
      const next='restart '+dm.slice(-6);
      await waitFor(()=>peer.evaluate('!_sendLock'),'the composer is ready again after the manual command');
      const sent=peer.frames.length,observed=ownerWs.events.length;
      await compose(next);
      await waitFor(()=>browser.evaluate(`!!(${reactionRow(next)})?._msgRef?.encrypted`),'the replacement session delivers an ordinary encrypted message');
      if(oppositeGlare){
        const frames=peer.frames.slice(sent).map(JSON.parse).filter(e=>e.type==='send'&&e.conn_id===networkB&&e.raw?.startsWith('PRIVMSG '+owner+' :[e2edm2]'));
        const wire=frames[0]?.raw.split(' :')[1];
        const shortRelays=()=>ownerWs.events.slice(observed).filter(e=>e.type==='irc_message'&&e.conn_id===networkA&&e.from===other&&e.text===wire);
        check('the replacement’s first readable short message matches exactly one authenticated IRC delivery',
          frames.length===1&&await waitFor(()=>shortRelays().length===1,'the independent observer sees the matching first text'));
        await checkOppositeGlareReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,waitFor,check});
      }
    }
    check('the author can remove the Like after the manual Signal command',await browser.evaluate(reactionButton(dm,'👍')));
    await waitFor(()=>peer.evaluate(`!!(${mine}) && !(${mine}).querySelector('.reaction-count')`),'the recipient removes the Like after the manual command');
  } finally { await peer.evaluate('manualReaction.restore()'); }
}

async function checkOppositeGlareReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,waitFor,check}) {
  const row=reactionRow(dm);
  const state=page=>page.evaluate(`(()=>{
    const element=(${row}),message=element?._msgRef;
    const chips=[...(element?.querySelectorAll('.reaction-count')||[])];
    const heart=chips.find(c=>c.textContent==='❤️ 1');
    return {reference:message?.reactionRef,readable:!!message?.encrypted,heart:!!heart,
      pressed:heart?.getAttribute('aria-pressed')==='true',originalLike:chips.some(c=>c.textContent==='👍 1')};
  })()`);
  const identityOrder=(page,id,nick)=>page.evaluate(`(async()=>{
    const key=_e2eDmKey(${q(nick)},${q(id)}),s=E2E.dmSessions[key];
    const pub=await exportPub(E2E.identityKeys.dhKeyPair.publicKey,'ECDH');
    return _e2eCmpBytes(base64ToBytes(pub),base64ToBytes(s.theirIdentityPub))<0;
  })()`);
  const [authorWins,restartingWins,author,reactor]=await Promise.all([identityOrder(browser,networkA,other),identityOrder(peer,networkB,owner),state(browser),state(peer)]);
  check('two real identities have opposite tie positions and share the original readable PM reference',
    authorWins!==restartingWins&&author.readable&&reactor.readable&&author.reference&&author.reference===reactor.reference&&
    author.originalLike&&reactor.originalLike&&!author.heart&&!reactor.heart);
  console.log('RESTART-INITIATOR-HEART-ORDER '+(authorWins?'original-author-wins':'restarting-person-wins'));
  await browser.evaluate(`(()=>{
    const decrypt=e2eDecryptIncoming;
    window.restartHeartWitness={opened:[],restore:()=>{e2eDecryptIncoming=decrypt;}};
    e2eDecryptIncoming=async(...args)=>{
      const result=await decrypt(...args);
      if(args[3]?.reaction&&args[0]===${q(other)}&&result?.encrypted&&!result.duplicate){
        let value;try{value=JSON.parse(result.plaintext);}catch{}
        if(value?.ref===${q(author.reference)}&&CHAT_REACTION_EMOJI[value.emoji]==='❤️')
          restartHeartWitness.opened.push(value.remove);
      }
      return result;
    };
  })()`);
  try{
    for(const remove of [false,true]){
      const sent=peer.frames.length,observed=ownerWs.events.length;
      check('the restarting person can select Heart on the original message',await peer.evaluate(reactionButton(dm,'❤️')));
      const body=await waitFor(()=>{
        const frames=peer.frames.slice(sent).map(JSON.parse).filter(f=>f.type==='react');
        const frame=frames[0];
        return frames.length===1&&frame.reaction.kind==='sealed'&&!JSON.stringify(frame).includes('❤️')&&
          !Object.hasOwn(frame.reaction,'reference')&&frame.reaction.body;
      },'the real menu submits a single sealed gesture');
      const relays=()=>ownerWs.events.slice(observed).filter(e=>e.type==='sealed_reaction'&&!e.own&&e.conn_id===networkA&&e.from===other&&e.body===body);
      await waitFor(()=>relays().length===1,'the original author independently receives this exact sealed gesture');
      await waitFor(async()=>{
        const [a,b]=await Promise.all([state(browser),state(peer)]);
        return [a,b].every(v=>v.readable&&v.reference===author.reference&&v.originalLike&&v.heart===!remove)&&!a.pressed&&b.pressed===!remove;
      },'both clients apply the gesture on the original row while retaining its earlier Like');
      check(remove?'the restarting person’s Heart removal is authenticated once and clears on both original rows':
        'the restarting person’s Heart is authenticated once and appears on both original rows',
        relays().length===1&&await browser.evaluate('JSON.stringify(restartHeartWitness.opened)==='+q(JSON.stringify(remove?[0,1]:[0]))));
    }
  }finally{await browser.evaluate('restartHeartWitness.restore();delete window.restartHeartWitness');}
}

export async function checkRestartedSignalReaction({browser,peer,networkA,networkB,owner,other,dm,ownerWs,compose,waitFor,check,stamp,echoGate}){
  const key=`_e2eDmKey(${q(owner)},${q(networkB)})`, session=`E2E.dmSessions[${key}]`;
  const confirmation='confirm the preceding Signal exchange '+stamp;
  await compose(browser,networkA,other,confirmation);
  await waitFor(()=>peer.evaluate(`!!(${reactionRow(confirmation)})?._msgRef?.encrypted && !${session}?.x3dhPending`),
    'the recipient has authenticated a reply on the preceding session before choosing Restart');
  const oldStart=await peer.evaluate(`${session}.startEph`);
  await waitFor(()=>peer.evaluate(`!_sendLock && Date.now()-(_e2eRestartRequested.get(JSON.stringify([_e2eUser(),${key}]))||0)>=15000`),
    'the second manual restart is eligible under the normal retry interval');
  await compose(peer,networkB,owner,'/encrypt restart '+owner);
  await waitFor(()=>peer.evaluate(`!!${session}?.x3dhPending && ${session}.startEph!==${q(oldStart)} && ${session}.Ns===0`),
    'the recipient starts a new initiator session before reacting to an earlier incoming message');
  const start=await peer.evaluate(`${session}.startEph`);
  const message='first ordinary message on restarted reaction session '+stamp;
  const at=peer.frames.length, mark=ownerWs.events.length;
  const outbound=()=>peer.frames.slice(at).map(JSON.parse);
  const received=()=>ownerWs.events.slice(mark).filter(e=>e.type==='sealed_reaction' && !e.own && e.conn_id===networkA && e.from===other);
  await waitFor(()=>peer.evaluate('!_rateQueue.length && !_rateDmRetry'),'the recipient’s ordinary IRC send queue is idle');
  await peer.evaluate(`(()=>{
    clearTimeout(_rateTimer); _rateTimer=setTimeout(()=>{},60000);
    const show=showToast; window.heldReactionToasts=[];
    showToast=(text,...args)=>{window.heldReactionToasts.push(text);return show(text,...args);};
    window.restoreReactionToast=()=>{showToast=show;};
  })()`);
  try {
    await compose(peer,networkB,owner,message);
    await waitFor(()=>peer.evaluate(`_rateQueue.some(f=>f.raw?.includes(' :[e2edm2]')) && ${session}.Ns===1`),
      'the first ordinary encrypted text is committed but still waiting in the actual send queue');
    check('the recipient can open the earlier incoming message and choose Like while that text is held',await peer.evaluate(reactionButton(dm,'👍')));
    await waitFor(()=>peer.evaluate("heldReactionToasts.some(t=>t.includes('Wait for IRC to confirm'))"),'an unconfirmed first handoff explains why the Like must wait');
    check('an old session’s real IRC anchors cannot release a reaction ahead of the new first text',
      !outbound().some(f=>f.type==='react'||f.raw?.includes(' :[e2edm2]')) && received().length===0 &&
      await peer.evaluate(`${session}.Ns===1 && !${session}.reactionRun && ${session}.startEph===${q(start)}`));
  } finally {
    if(echoGate)echoGate.delayOwnEcho=event=>event.conn_id===networkB&&event.line.includes(' PRIVMSG '+owner+' :[e2edm2]');
    await peer.evaluate('window.restoreReactionToast();delete window.restoreReactionToast;delete window.heldReactionToasts;_kickRateQueue()');
  }
  await waitFor(()=>browser.evaluate(`!!(${reactionRow(message)})?._msgRef?.encrypted`),'the first ordinary text on the restarted session is readable at the real peer',echoGate?55000:20000);
  await waitFor(()=>peer.evaluate(`(()=>{
    const m=(${reactionRow(message)})?._msgRef;
    return m && reactionAnchors.has(reactionAnchorKey(${q(networkB)},m.id)) && ${session}.startEph===${q(start)} && !!${session}.x3dhPending;
  })()`),'the first ordinary text has a real IRC echo while the new offer still awaits a reply',echoGate?55000:20000);
  if(echoGate)check('the actual own IRC echo was held for at least seventeen seconds',echoGate.delayedMs>=16950);
  await checkSealedReaction({browser,peer,check,waitFor,sourceWs:ownerWs,text:dm,target:'earlier incoming PM after a restart',emoji:'👍'});
  check('the Like and undo each cross IRC once without confirming the pending offer',
    received().length===2 && outbound().filter(f=>f.type==='react'&&f.reaction.kind==='sealed').length===2 &&
    await peer.evaluate(`!!${session}.x3dhPending && ${session}.reactionRun===2`));
}

export async function checkSealedReaction({browser,peer,check,waitFor,sourceWs,text,target,emoji,reopen}){
  if (reopen) {
    await waitFor(()=>peer.evaluate('reactionHistoryQueues.size===0'),'earlier encrypted reaction writes settled');
    await reopenReactionChat(peer,reopen.connId,reopen.target,waitFor,true);
    check('a restored encrypted message can react without a live IRC anchor',await waitFor(()=>peer.evaluate(`(async()=>{
      const row=${reactionRow(text)}, id=row?._msgRef?.id;
      if(!id||!row._msgRef?.reactionRef||reactionAnchors.has(reactionAnchorKey(${q(reopen.connId)},id)))return false;
      await loadReactionHistory(true)?.ready;
      return !!messageReactionFor(row)&&!storedReaction(${q(reopen.connId)},${q(reopen.target)},id,true);
    })()`),'restored encrypted message has no live or saved IRC anchor'));
  }
  await waitFor(()=>peer.evaluate(`(()=>{const row=${reactionRow(text)};return !!row&&!!messageReactionFor(row);})()`),'encrypted message reaction anchor');
  const sent=peer.frames.length, before=sourceWs.events.length;
  const delayOwnEcho=process.env.CRYPTIRC_TEST_REACTION_DURABILITY==='1'&&reopen;
  let localDisk, pendingReceipt;
  if(delayOwnEcho){
    const id=await peer.evaluate(`(${reactionRow(text)})._msgRef.id`);
    localDisk=()=>reactionDiskRecord(peer,reopen.connId,reopen.target,id,true);
    await peer.evaluate(holdOwnReactionEcho(reopen.connId,reopen.target,'sealed_reaction'));
  }
  try {
    check('encrypted '+target+' lets the recipient choose a reaction',await peer.evaluate(reactionButton(text,emoji)));
    await waitFor(()=>sourceWs.events.slice(before).some(e=>e.type==='sealed_reaction'&&e.own===false),'encrypted reaction delivered over IRC');
    check('encrypted '+target+' displays the correct reaction to the sender',await waitFor(()=>browser.evaluate(
      `(${reactionRow(text)})?.querySelector('.reaction-count')?.textContent===${q(emoji+' 1')}`),'sealed reaction rendered'));
    if(delayOwnEcho){
      await waitFor(()=>peer.evaluate('window.reactionEchoFixture.blocked.length===1'),'actual own sealed echo is withheld');
      const request=peer.frames.slice(sent).map(frame=>JSON.parse(frame)).find(frame=>frame.type==='react')?.request_id;
      check('the pending sealed reaction has a request ID',!!request);
      pendingReceipt='receipt:'+request;
      check('sealed reaction stays unconfirmed in the sender UI and committed IndexedDB before its actual own echo',
        !(await localDisk())?.entries.some(([code,actors])=>code===emoji&&actors.some(([actor])=>!actor))&&
        !await peer.evaluate(`!!(${reactionRow(text)})?.querySelector('.reaction-count[aria-pressed=true]')`));
      check('the pending sealed reaction journal is present only inside the vault-encrypted IndexedDB blob',
        await peer.evaluate(`(async()=>{
          const slot=reactionHistorySlot(true);
          const raw=await _e2eIdbOp('readonly',store=>store.get(slot),2000);
          const sealed=await readReactionHistory(slot,E2E.e2eEncKey);
          return raw instanceof Uint8Array&&raw.length>32&&sealed.has(${q(pendingReceipt)});
        })()`));
    }
  } finally { if(delayOwnEcho) await peer.evaluate('window.reactionEchoFixture?.release(true)'); }
  const outbound=peer.frames.slice(sent).map(frame=>JSON.parse(frame)).find(frame=>frame.type==='react');
  check('encrypted '+target+' keeps emoji and message reference inside ciphertext',
    !!outbound&&outbound.reaction.kind==='sealed'&&typeof outbound.reaction.body==='string'&&
    !JSON.stringify(outbound).includes(emoji)&&!Object.hasOwn(outbound.reaction,'reference'));
  await waitFor(()=>peer.evaluate(`(${reactionRow(text)})?.querySelector('.reaction-count')?.getAttribute('aria-pressed')==='true'`),
    'IRC echo confirms own encrypted reaction');
  if(delayOwnEcho) await waitFor(()=>peer.evaluate(`(async()=>{
    const records=await readReactionHistory(reactionHistorySlot(true),E2E.e2eEncKey);
    return !records.has(${q(pendingReceipt)});
  })()`),'confirming the sealed reaction consumes its pending journal entry');
  if (reopen) {
    await waitFor(()=>peer.evaluate(`(()=>{
      const id=(${reactionRow(text)})?._msgRef?.id;
      return id&&reactionHistoryQueues.size===0&&
        storedReaction(${q(reopen.connId)},${q(reopen.target)},id,true)?.entries.some(([emoji])=>emoji===${q(emoji)});
    })()`),'encrypted reaction saved');
    check('sealed local reaction history is stored as ciphertext',await peer.evaluate(`(async()=>{
      const slot=reactionHistorySlot(true), stored=await _e2eIdbOp('readonly',store=>store.get(slot),2000);
      return stored instanceof Uint8Array&&stored.length>32;
    })()`));
    await reopenReactionChat(peer,reopen.connId,reopen.target,waitFor,true);
    check('a sealed reaction added to restored history survives reopening the device again',await waitFor(()=>peer.evaluate(
      `(${reactionRow(text)})?.querySelector('.reaction-count[aria-pressed=true]')?.textContent===${q(emoji+' 1')}`),'reopened encrypted reaction'));
  }
  const beforeUndo=sourceWs.events.length;
  check('encrypted '+target+' lets the recipient remove their own reaction',await peer.evaluate(reactionButton(text,emoji)));
  await waitFor(()=>sourceWs.events.slice(beforeUndo).some(e=>e.type==='sealed_reaction'),'encrypted removal delivered');
  await waitFor(()=>peer.evaluate(`(()=>{
    const row=${reactionRow(text)};
    return !!row && !row.querySelector('.reaction-count[aria-pressed=true]');
  })()`),'the recipient sees its own encrypted removal');
  check('encrypted '+target+' removes the count beside the original message',await waitFor(()=>browser.evaluate(
    `!(${reactionRow(text)})?.querySelector('.reaction-count')`),'sealed removal rendered'));
}
