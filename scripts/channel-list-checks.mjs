// Browser checks using the real IRC testnet, plus a large directory fixture.
export async function checkChannelList({ev, cdp, waitFor, check, network, channel}) {
  const select = (id, value, event) => ev(`(()=>{
    const control=document.getElementById(${JSON.stringify('chanlist-'+id)});
    control.value=${JSON.stringify(value)};
    control.dispatchEvent(new Event(${JSON.stringify(event)},{bubbles:true}));
  })()`);
  const click = id => ev(`document.getElementById(${JSON.stringify('chanlist-'+id)}).click()`);
  const rows = () => ev("Array.from(document.querySelectorAll('.chanlist-row .chanlist-chan'),row=>row.textContent)");
  const hasCompleteList = async () => await ev('chanList && !chanList.loading') && (await rows()).includes(channel);
  const connection = JSON.stringify(network);
  const room = JSON.stringify(channel);
  await ev(`setActive(${connection},'status');
    window.listRequests=[];window.originalListSend=wsend;
    wsend=message=>{
      if(message.type==='list_channels'){
        listRequests.push(message.pattern);
        if(message.pattern==='#directory-fixture-*') return true;
      }
      return originalListSend(message);
    }`);
  try {
    await ev("handleInput('/list')");
    await select('search',channel,'input');
    await waitFor(hasCompleteList, 'real testnet channel directory');
    check('/list displays a channel returned by the real testnet', await ev('listRequests.length===1'));
    check('/list opens a sidebar tab with the results in the main view',
      await ev("document.querySelector('#sidebar #chanlist-tab.active:not([hidden])') && document.querySelector('#main #chanlist-box:not([hidden])') && !document.getElementById('app').inert"));
    check('the channel list does not have a chat composer',
      await ev("(async()=>getComputedStyle(document.getElementById('input-wrap')).display==='none' && (await handleInput('local draft'))==='keep')()"));
    await click('tab-close');
    await ev("handleInput('/list')");
    check('opening the same directory reuses its cache',
      await ev("listRequests.length===1 && document.getElementById('chanlist-count').textContent.includes('Cached')"));
    await select('search',channel,'input');
    check('search narrows the real channel list', (await rows()).join()===channel);
    check('the test account has not already joined the directory result',
      await ev(`!networks.find(n=>n.config.id===${connection}).channels.some(c=>c.name===${room})`));
    await ev("document.querySelector('.chanlist-row').click()");
    await waitFor(()=>ev(`active.target===${room} && active.conn_id===${connection} &&
      networks.find(n=>n.config.id===${connection}).channels.some(c=>c.name===${room})`), 'joined from the directory');
    check('joining a channel keeps the channel list as an inactive sidebar tab', await ev(`
      document.querySelector('#sidebar #chanlist-tab:not([hidden]):not(.active)') &&
      document.getElementById('chanlist-box').hidden &&
      getComputedStyle(document.getElementById('input-wrap')).display!=='none'`));
    await click('tab-open');
    check('the tab restores the same search and results without another IRC LIST', await ev(`
      document.getElementById('chanlist-tab-open').getAttribute('aria-current')==='page' &&
      document.getElementById('chanlist-search').value===${room} &&
      document.querySelector('.chanlist-row .chanlist-chan')?.textContent===${room} &&
      listRequests.length===1`));
    await ev(`setActive(${connection},${room})`);
    await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await waitFor(()=>ev('isMobileView()'),'phone-sized viewport');
    await ev("document.getElementById('hamburger').click()");
    check('the channel list tab is accessible from the phone sidebar', await ev(
      "document.querySelector('#sidebar.open #chanlist-tab:not([hidden]) #chanlist-tab-open') !== null"));
    await click('tab-open');
    check('opening the list tab closes the phone drawer and gives the results the main view', await ev(`
      !document.getElementById('sidebar').classList.contains('open') &&
      !document.getElementById('chanlist-box').hidden &&
      document.querySelector('#main .chanlist-row .chanlist-chan')?.textContent===${room}`));
    await ev("document.querySelector('.chanlist-row').click()");
    check('on a phone, tapping a result returns to chat and leaves the list tab open', await ev(`
      document.getElementById('chanlist-box').hidden &&
      !document.getElementById('chanlist-tab').hidden && active.target===${room}`));
    await cdp('Emulation.clearDeviceMetricsOverride');
    await click('tab-open');
    await click('refresh');
    await waitFor(hasCompleteList, 'real channel directory refresh');
    check('Refresh sends a new IRC LIST from the channel list tab', await ev('listRequests.length===2'));
    await select('cache','0','change');
    await click('tab-close');
    check('closing the active list tab removes it and returns to the previous chat',
      await ev(`document.getElementById('chanlist-tab').hidden && document.getElementById('chanlist-box').hidden &&
        !document.querySelector('.chanlist-row') && active.target===${room}`));
    await ev("handleInput('/list')");
    await select('search',channel,'input');
    await waitFor(hasCompleteList, 'uncached IRC LIST');
    check('Cache Off reloads the real directory', await ev('listRequests.length===3'));

    await select('cache','5','change');
    await ev(`setActive(${connection},${room});handleInput('/list #directory-fixture-*')`);
    await ev(`(()=>{
      const request_id=chanList.requestId;
      const unrelated=[{channel:'#unrelated',users:10000,topic:''}];
      handleListBatch({conn_id:'unrelated',request_id,entries:unrelated});
      handleListEnd({conn_id:'unrelated',request_id});
      handleListBatch({conn_id:${connection},request_id:'another-tab',entries:unrelated});
      handleListEnd({conn_id:${connection},request_id:'another-tab'});
      const entries=Array.from({length:5000},(_,i)=>({channel:'#directory-fixture-'+(i+1),
        users:5000-i,topic:i===4999?'Unique topic needle':'Test directory'}));
      for(let i=0;i<entries.length;i+=64) handleListBatch({conn_id:${connection},request_id,entries:entries.slice(i,i+64)});
      handleListEnd({conn_id:${connection},request_id,total:entries.length});
    })()`);
    check('a 5,000-channel directory renders only the first 50 results', (await rows()).length===50 &&
      await ev("document.getElementById('chanlist-count').textContent.includes('5,000')"));
    await select('limit','1000','change');
    check('the selected page size can show 1,000 channels', (await rows()).length===1000);
    await click('next');
    check('paging reaches the next set of results', (await rows())[0]==='#directory-fixture-1001');
    await ev(`setActive(${connection},${room})`);
    await click('tab-open');
    check('switching tabs keeps the current list page',
      (await rows())[0]==='#directory-fixture-1001' && await ev("document.getElementById('chanlist-page').textContent==='2 / 5'"));
    await select('search','unique topic needle','input');
    check('search finds a topic beyond the visible pages', (await rows()).join()==='#directory-fixture-5000');
    await ev("for(const entry of chanListCache.values()) entry.fetchedAt-=6*60000");
    await ev(`setActive(${connection},${room});handleInput('/list #directory-fixture-*')`);
    check('an expired cache sends LIST again with the original server filter', await ev(`
      listRequests.filter(pattern=>pattern==='#directory-fixture-*').length===2 &&
      document.getElementById('chanlist-refresh').disabled`));
    await ev(`handleListEnd({conn_id:${connection},request_id:chanList.requestId,total:1})`);
    check('a directory with missing rows is reported and never cached', await ev(`
      !chanListCache.has(chanList.key) && chanList.error.includes('not received')`));
    await ev(`setActive(${connection},${room})`);
    await click('tab-close');
    check('closing the inactive list tab leaves the current chat open',
      await ev(`document.getElementById('chanlist-tab').hidden && active.target===${room}`));

    await ev("handleInput('/list #directory-fixture-*')");
    await ev('ws.close()');
    await waitFor(()=>ev("!chanList.loading && chanList.error.includes('web connection closed')"), 'list detects WebSocket closure');
    check('losing the WebSocket ends the pending request and keeps the list tab',
      await ev("!document.getElementById('chanlist-tab').hidden && pendingChanLists.size===0"));
    await waitFor(()=>ev('_wsReady()'), 'WebSocket reconnected for tab fallback');
    await ev(`wsend({type:'part_channel',conn_id:${connection},channel:${room}})`);
    await waitFor(()=>ev(`!networks.find(n=>n.config.id===${connection}).channels.some(c=>c.name===${room})`), 'left the previous channel on the testnet');
    await click('tab-close');
    check('closing the list after parting the previous channel returns to network status',
      await ev(`active.conn_id===${connection} && active.target==='status'`));
  } catch (error) {
    const state = await ev(`({requests:listRequests.length,entries:chanList?.entries.length,
      loading:chanList?.loading,count:document.getElementById('chanlist-count').textContent})`);
    throw new Error(error.message+' '+JSON.stringify(state),{cause:error});
  } finally {
    await cdp('Emulation.clearDeviceMetricsOverride');
    await ev(`closeChanList();wsend=originalListSend;delete window.originalListSend;delete window.listRequests;
      localStorage.removeItem(CHAN_LIST_CACHE_KEY);`);
  }
}
