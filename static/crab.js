/*!
 * CryptIRC Desktop Pet — Angry Crab 🦀
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) silly angry crab that
 * scuttles SIDEWAYS around the client window, snaps its claws, rages, blows
 * bubbles, charges, waves, and mutters crab things. Drawn procedurally as an
 * articulated SVG (no sprite sheet) and animated with CSS + a rAF position loop.
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like esheep.js):
 *   window.CryptIRCCrab.enable()  spawn the crab (idempotent)
 *   .disable()  remove it + stop all timers/listeners (no leaks)
 *   .isOn()     -> boolean
 * Off by default. SILENT. Confined to the window; never steals clicks
 * (pointer-events:none) — but it reacts angrily when you click near it.
 */
(function(){
'use strict';

var Z = 89;                  // above chat (≤60), below panels/menus/modals (≥100); 1 below the sheep (90) for stable paint order when both are on
var _enabled = false;
var _crab = null;

var SAYINGS = [
  'GRRR', 'SNIP SNIP', 'PINCH!', 'MINE!', 'back OFF', 'skrrt skrrt',
  'no thoughts only pinch', 'i will nip you', 'sideways gang', '🦀💢',
  'i am NOT a snack', 'CLACK CLACK', 'fear the claw', 'beach? never heard of it',
  'i run this channel now', 'pinchy mcpinchface', 'angy', 'krill issue'
];
// said only when it goes to pester the eSheep (both pets enabled)
var SHEEP_TAUNTS = [
  'MINE!', 'scram, wool boy', 'this is MY beach', 'pinch the sheep',
  'baaa? more like NAH', '🦀 > 🐑', 'no sheep allowed', 'shoo!', 'get nipped, sheep'
];

// ── styles (injected once) ───────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-crab-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-crab{position:fixed;z-index:'+Z+';width:66px;height:50px;pointer-events:auto;cursor:move;touch-action:manipulation;',
      'will-change:left,top,transform;user-select:none;-webkit-user-select:none;transition:transform .22s ease;filter:drop-shadow(0 3px 3px rgba(0,0,0,.45))}',
    '.cryptirc-crab svg{display:block;width:100%;height:100%;overflow:visible;pointer-events:none}',
    /* picked up & dragged: dangle, flail legs, snap claws, look mad */
    '.cryptirc-crab.drag{animation:ccDangle .5s ease-in-out infinite;cursor:grabbing}',
    '.cryptirc-crab.drag .ccleg{animation:ccLeg .18s ease-in-out infinite}',
    '.cryptirc-crab.drag .pinT{animation:ccSnapT .18s ease-in-out infinite}',
    '.cryptirc-crab.drag .pinB{animation:ccSnapB .18s ease-in-out infinite}',
    '@keyframes ccDangle{0%,100%{transform:rotate(-7deg)}50%{transform:rotate(7deg)}}',
    /* body bob + leg scuttle while walking */
    '.cryptirc-crab.walk .ccb,.cryptirc-crab.crawl .ccb{animation:ccBob .44s ease-in-out infinite}',
    '.cryptirc-crab.walk .ccleg,.cryptirc-crab.crawl .ccleg{animation:ccLeg .44s ease-in-out infinite}',
    '.cryptirc-crab.walk .ccleg.b,.cryptirc-crab.crawl .ccleg.b{animation-delay:.22s}',
    '@keyframes ccBob{50%{transform:translateY(2px)}}',
    '@keyframes ccLeg{50%{transform:rotate(var(--sw,17deg))}}',
    /* claw snap */
    '.cryptirc-crab.snap .pinT{animation:ccSnapT .16s ease-in-out infinite}',
    '.cryptirc-crab.snap .pinB{animation:ccSnapB .16s ease-in-out infinite}',
    '@keyframes ccSnapT{50%{transform:rotate(-26deg)}}',
    '@keyframes ccSnapB{50%{transform:rotate(26deg)}}',
    /* rage: shake + go deep red */
    '.cryptirc-crab.rage{animation:ccShake .07s linear infinite}',
    '.cryptirc-crab.rage .shell,.cryptirc-crab.rage .arm,.cryptirc-crab.rage .pin{fill:#ff2b1f!important}',
    '@keyframes ccShake{0%{transform:translate(1px,0) rotate(.6deg)}25%{transform:translate(-1px,1px) rotate(-.6deg)}50%{transform:translate(1px,-1px) rotate(.4deg)}75%{transform:translate(-1px,0) rotate(-.4deg)}}',
    /* charge: lean into it */
    '.cryptirc-crab.charge .ccleg{animation:ccLeg .2s ease-in-out infinite}',
    '.cryptirc-crab.charge .ccb{animation:ccBob .2s ease-in-out infinite}',
    /* wave one claw */
    '.cryptirc-crab.wave .armR{animation:ccWave .5s ease-in-out infinite;transform-origin:62px 40px}',
    '@keyframes ccWave{50%{transform:rotate(-34deg)}}',
    /* eyes look + angry brow twitch */
    '.cryptirc-crab .pupil{animation:ccLook 3.2s ease-in-out infinite}',
    '@keyframes ccLook{0%,40%{transform:translateX(0)}50%,70%{transform:translateX(1.6px)}80%,100%{transform:translateX(-1.6px)}}',
    /* speech bubble */
    '.cc-say{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-family:var(--mono,ui-monospace,monospace);',
      'font-size:11px;font-weight:700;color:#3a0a06;background:#ffd9b0;border:2px solid #c0381f;',
      'border-radius:9px;padding:3px 8px;white-space:nowrap;box-shadow:0 3px 8px rgba(0,0,0,.35);',
      'opacity:0;transform:translateY(4px) scale(.9);transition:opacity .14s,transform .14s}',
    '.cc-say.show{opacity:1;transform:none}',
    '.cc-say::after{content:"";position:absolute;bottom:-7px;left:14px;border:6px solid transparent;border-top-color:#c0381f}',
    /* rising bubbles */
    '.cc-bub{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 35% 30%,rgba(255,255,255,.9),rgba(160,210,255,.35));',
      'border:1px solid rgba(255,255,255,.5);animation:ccBubble linear forwards}',
    '@keyframes ccBubble{0%{opacity:.9;transform:translateY(0) scale(.6)}100%{opacity:0;transform:translateY(-46px) scale(1.1)}}',
    /* anger mark */
    '.cc-anger{position:fixed;z-index:'+(Z+1)+';pointer-events:none;color:#ff2b1f;font-weight:900;',
      'font-family:var(--sans,sans-serif);font-size:18px;animation:ccAnger .7s ease-out forwards}',
    '@keyframes ccAnger{0%{opacity:0;transform:scale(.3) rotate(-20deg)}30%{opacity:1;transform:scale(1.2)}100%{opacity:0;transform:scale(1) translateY(-12px)}}',
    /* a shrimp the crab finds and nibbles */
    '.cc-shrimp{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:18px;line-height:1;transform-origin:center;filter:drop-shadow(0 2px 2px rgba(0,0,0,.4));transition:transform .35s ease,opacity .35s ease}',
    /* sleepy Zzz */
    '.cc-zzz{position:fixed;z-index:'+(Z+1)+';pointer-events:none;color:#2f4f8f;font-weight:800;font-family:var(--mono,ui-monospace,monospace);animation:ccZzz 1.3s ease-out forwards}',
    '@keyframes ccZzz{0%{opacity:0;transform:translate(0,0) rotate(0)}20%{opacity:.9}100%{opacity:0;transform:translate(10px,-26px) rotate(12deg)}}',
    /* dug-up sand grains */
    '.cc-sand{position:fixed;z-index:'+(Z-1)+';pointer-events:none;background:#caa46a;border-radius:50%;animation:ccSand .7s ease-out forwards}',
    '@keyframes ccSand{0%{opacity:.9;transform:translateY(0)}100%{opacity:0;transform:translateY(-14px)}}',
    /* napping: eyes droop */
    '.cryptirc-crab.nap .pupil{opacity:.25}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-crab *,.cryptirc-crab{animation:none!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the crab SVG (front view; legs/claws/eyes are articulated) ───────────────
function crabSVG(){
  // colors: shell orange-red, lighter belly, dark outline via stroke
  var leg = function(x, cls){
    return '<path class="ccleg '+cls+'" d="M'+x+' 50 q -6 6 -10 13" stroke="#7a1c0e" stroke-width="3.4" fill="none" stroke-linecap="round" style="transform-origin:'+x+'px 50px"/>';
  };
  return '<svg viewBox="0 0 100 64" xmlns="http://www.w3.org/2000/svg">'+
    '<g class="ccb">'+
      // legs (left + right, two phase groups a/b)
      leg(34,'a')+leg(40,'b')+leg(46,'a')+
      '<g style="transform:scaleX(-1);transform-origin:50px 0">'+leg(34,'a')+leg(40,'b')+leg(46,'a')+'</g>'+
      // left arm + claw
      '<g class="arm armL">'+
        '<path class="arm" d="M36 42 q -16 -2 -24 -10" stroke="#9c2410" stroke-width="6" fill="none" stroke-linecap="round"/>'+
        '<g class="pin" style="transform-origin:12px 32px">'+
          '<path class="pin pinT" d="M12 32 q -12 -8 -2 -16 q 8 4 8 12 z" fill="#c0381f" stroke="#7a1c0e" stroke-width="1.5" style="transform-origin:12px 32px"/>'+
          '<path class="pin pinB" d="M12 32 q -12 6 -2 14 q 8 -2 8 -10 z" fill="#c0381f" stroke="#7a1c0e" stroke-width="1.5" style="transform-origin:12px 32px"/>'+
        '</g>'+
      '</g>'+
      // right arm + claw (mirrored)
      '<g class="arm armR">'+
        '<path class="arm" d="M64 42 q 16 -2 24 -10" stroke="#9c2410" stroke-width="6" fill="none" stroke-linecap="round"/>'+
        '<g class="pin" style="transform-origin:88px 32px">'+
          '<path class="pin pinT" d="M88 32 q 12 -8 2 -16 q -8 4 -8 12 z" fill="#c0381f" stroke="#7a1c0e" stroke-width="1.5" style="transform-origin:88px 32px"/>'+
          '<path class="pin pinB" d="M88 32 q 12 6 2 14 q -8 -2 -8 -10 z" fill="#c0381f" stroke="#7a1c0e" stroke-width="1.5" style="transform-origin:88px 32px"/>'+
        '</g>'+
      '</g>'+
      // shell
      '<ellipse class="shell" cx="50" cy="44" rx="22" ry="15" fill="#d8431f" stroke="#7a1c0e" stroke-width="2.5"/>'+
      '<ellipse cx="50" cy="47" rx="16" ry="8" fill="#ef6b3f" opacity=".7"/>'+
      // eye stalks
      '<line x1="43" y1="32" x2="42" y2="22" stroke="#7a1c0e" stroke-width="3"/>'+
      '<line x1="57" y1="32" x2="58" y2="22" stroke="#7a1c0e" stroke-width="3"/>'+
      '<circle cx="42" cy="20" r="6" fill="#fff" stroke="#7a1c0e" stroke-width="1.5"/>'+
      '<circle cx="58" cy="20" r="6" fill="#fff" stroke="#7a1c0e" stroke-width="1.5"/>'+
      '<circle class="pupil" cx="42" cy="21" r="2.6" fill="#111" style="transform-origin:42px 21px"/>'+
      '<circle class="pupil" cx="58" cy="21" r="2.6" fill="#111" style="transform-origin:58px 21px"/>'+
      // angry brows
      '<path d="M37 15 l9 4" stroke="#7a1c0e" stroke-width="3" stroke-linecap="round"/>'+
      '<path d="M63 15 l-9 4" stroke="#7a1c0e" stroke-width="3" stroke-linecap="round"/>'+
      // grumpy mouth
      '<path d="M44 52 q 6 -4 12 0" stroke="#7a1c0e" stroke-width="2" fill="none" stroke-linecap="round"/>'+
    '</g>'+
  '</svg>';
}

// ── crab instance ────────────────────────────────────────────────────────────
function Crab(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-crab';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = crabSVG();
  this.say = document.createElement('div');
  this.say.className = 'cc-say';
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this.W = 66; this.H = 50;
  this.dragging = false; this._didDrag = false; this._pressX = null; this._pressY = null;
  this._talkGate = 0;                              // frames of quiet remaining (talks less)
  this._encGate = 600 + (Math.random()*900|0);     // frames until it may go pester the sheep
  this._seekT = 0;
  this._bounds();
  // start somewhere along the floor
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = this._floorY();
  this.dir = Math.random()<0.5 ? 1 : -1;
  this.vx = 0; this.vy = 0;
  this.state = 'walk';
  this.t = 0; this.next = 70 + (Math.random()*90|0);
  this.lastFrame = 0;
}
Crab.prototype._bounds = function(){
  this.screenW = window.innerWidth || document.documentElement.clientWidth || 800;
  this.screenH = window.innerHeight || document.documentElement.clientHeight || 600;
};
Crab.prototype._on = function(target, ev, fn, opts){
  target.addEventListener(ev, fn, opts);
  this._listeners.push({t:target, e:ev, fn:fn, opts:opts});
};
Crab.prototype._after = function(ms, fn){
  var self=this, id=setTimeout(function(){ if(!self._dead) fn(); }, ms);
  this._timers.push(id); return id;
};
Crab.prototype.clamp = function(){
  this.x = Math.max(0, Math.min(this.x, this.screenW - this.W));
  // Floor states (including being dragged) can't be pulled BELOW the floor line, so
  // a release always falls down to it; climb/ceil/fall legitimately ride above it.
  var _fy = (this.state==='climb'||this.state==='ceil'||this.state==='fall') ? (this.screenH - this.H) : this._floorY();
  this.y = Math.max(0, Math.min(this.y, _fy));
};
Crab.prototype.face = function(d){ this.dir = d; this._applyTransform(); };
// Orientation: floor states face left/right; climbing a wall rotates the crab 90°
// so it crawls UP the wall (legs into the wall); on the ceiling it hangs flipped.
Crab.prototype._applyTransform = function(){
  if(!this.el) return;
  var rot = 0, sx = this.dir;
  if(this.state==='climb'){ rot = (this.wall==='L' ? 90 : -90); sx = 1; }
  else if(this.state==='ceil'){ rot = 180; }
  // consistent rotate()+scaleX() so the orientation TWEENS (see transition on .cryptirc-crab)
  this.el.style.transform = 'rotate('+rot+'deg) scaleX('+sx+')';
};

Crab.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  document.body.appendChild(this.say);
  this.face(this.dir);
  this.setState('walk');

  var self=this;
  this._wire();
  this._on(window, 'resize', function(){ self._bounds(); self.clamp(); });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } } // truly pause: cancel the deferred frame
    else { self.lastFrame=0; self.loop(); }
  });

  this.loop();
};

// Grab-to-drag + click handling (mirrors the eSheep). The crab is
// pointer-events:auto so you can pick it up, but a plain (non-drag) click is
// forwarded to the UI underneath so it NEVER steals a click — and also pokes
// the crab into a rage. Every listener is tracked for clean teardown.
Crab.prototype._wire = function(){
  var self=this;
  this._on(this.el, 'mousedown', function(e){
    if(self._dead) return;
    self._didDrag=false; self._pressX=e.clientX; self._pressY=e.clientY;
  });
  this._on(this.el, 'mousemove', function(e){
    if(self._dead || self.dragging) return;
    if(e.buttons===1 && e.button===0) self._beginDrag();
  });
  this._on(document, 'mousemove', function(e){
    if(!self.dragging || self._dead || !self.el) return;
    if(self._pressX==null || Math.abs(e.clientX-self._pressX)>3 || Math.abs(e.clientY-self._pressY)>3) self._didDrag=true;
    self.x = e.clientX - self.W/2;
    self.y = e.clientY - self.H/2;
    self.clamp();
    self.el.style.left = self.x+'px';
    self.el.style.top  = self.y+'px';
  });
  var endDrag = function(){ if(self.dragging) self._endDrag(); };
  this._on(this.el, 'mouseup', endDrag);
  this._on(document, 'mouseup', endDrag);
  this._on(this.el, 'click', function(e){
    if(self._dead) return;
    if(self._didDrag){ self._didDrag=false; return; }   // it was a drag, not a click
    self.poke();
    e.stopPropagation();
    // Forward the click to the real UI underneath: hide the crab (and any sheep)
    // from the hit-test, resolve elementFromPoint, then re-dispatch the click.
    var prev=self.el.style.pointerEvents; self.el.style.pointerEvents='none';
    var sheep=document.querySelectorAll('.cryptirc-esheep'), saved=[];
    for(var i=0;i<sheep.length;i++){ saved.push([sheep[i],sheep[i].style.pointerEvents]); sheep[i].style.pointerEvents='none'; }
    var under=document.elementFromPoint(e.clientX,e.clientY);
    self.el.style.pointerEvents=prev;
    for(var j=0;j<saved.length;j++){ saved[j][0].style.pointerEvents=saved[j][1]; }
    if(under && !(under.closest && under.closest('.cryptirc-crab'))){
      under.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,clientX:e.clientX,clientY:e.clientY,view:window}));
    }
  });
  this._on(this.el, 'contextmenu', function(e){ e.preventDefault(); return false; });
  this._on(this.el, 'dragstart', function(e){ e.preventDefault(); return false; });
};

Crab.prototype._beginDrag = function(){
  this.dragging = true;
  this.state = 'drag';
  this.el.classList.remove('walk','snap','rage','charge','wave','dance','crawl');
  this.el.classList.add('drag');
  this.wall = null;
  this._applyTransform();                            // ccDangle animation overrides this anyway
  if(Math.random()<0.5) this.speak(Math.random()<0.5?'PUT ME DOWN':'unhand me', true);
};
Crab.prototype._endDrag = function(){
  this.dragging = false;
  this.el.classList.remove('drag');
  this.lastFrame = 0;                                // don't let a big dt jolt the first frame back
  this.vy = 0; this.setState('fall');                // let go → plop down to the floor
};

Crab.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;                            // already a frame queued — never double-schedule
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Crab.prototype.frame = function(ts){
  if(this._dead) return;
  if(this.dragging){ this.lastFrame = ts; this.loop(); return; }   // held by the cursor — physics frozen
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;   // 0-dt frames (first frame / odd timers) still advance one step

  if(this._talkGate > 0) this._talkGate -= k;

  // Every now and then, when the eSheep is ALSO on, go pester it. Only kicks off
  // from a calm floor state so it never interrupts a climb/charge/drag.
  if(this.state==='walk' || this.state==='idle'){
    if(this._encGate > 0) this._encGate -= k;
    else if(this._sheepTarget()){ this.setState('seek'); this._seekT = 0; }
    else this._encGate = 240;                       // sheep off — re-check in a few seconds
  }

  this.t++;
  if(this.t >= this.next){ this.pickState(); }

  switch(this.state){
    case 'walk':    this.x += this.vx*k; break;
    case 'charge':  this.x += this.vx*k; break;
    case 'climb':   this.y += this.vy*k; break;
    case 'ceil':    this.x += this.vx*k; break;
    case 'fall':    this.vy += 0.5*k; this.y += this.vy*k; var _fl=this._floorY(); if(this.y >= _fl){ this.y=_fl; this.setState('snap'); } break;
    case 'seek': {
      var tgt = this._sheepTarget();
      if(!tgt){ this.setState('walk'); break; }      // sheep vanished mid-chase
      var cc = this.x + this.W/2, d = tgt.cx - cc;
      this.face(d<0 ? -1 : 1);
      this.vx = (Math.abs(d) < 6 ? 0 : (d<0 ? -1 : 1)) * 0.8;
      this.x += this.vx*k;
      this._seekT++;
      if(Math.abs(d) < this.W*0.7 || this._seekT > 1200){ this._encounter(tgt); }   // arrived (or gave up ~20s)
      break;
    }
    // snap / rage / wave / idle / dance / eat / nap / dig: mostly stationary (dance shuffles)
    case 'dance':   this.x += Math.sin(this.t*0.4)*1.1*this.dir; break;
  }
  // Floor states ride the LIVE input-bar floor (desktop) every frame, so the crab
  // tracks the bar even when it moves without a resize (reply bar / typing indicator).
  if(this.state!=='climb' && this.state!=='ceil' && this.state!=='fall') this.floorize();

  // wall handling for floor walkers → sometimes climb the wall
  if((this.state==='walk'||this.state==='charge')){
    if(this.x <= 0){ this.x=0; this.bounceOrClimb(1); }
    else if(this.x >= this.screenW-this.W){ this.x=this.screenW-this.W; this.bounceOrClimb(-1); }
  }
  if(this.state==='climb'){
    if(this.y <= 2){ this.y=2; this.setState('ceil'); this.vx = 0.7*(this.x < this.screenW/2 ? 1 : -1); this.face(this.vx<0?-1:1); this.x = Math.max(2, Math.min(this.x, this.screenW - this.W - 2)); }
  }
  if(this.state==='ceil'){
    if(this.x<=0 || this.x>=this.screenW-this.W){ this.x=Math.max(0,Math.min(this.x,this.screenW-this.W)); this.setState('fall'); this.vy=0; }
  }

  this.clamp();
  this.el.style.left = this.x + 'px';
  this.el.style.top  = this.y + 'px';
  this.loop();
};

// The "floor" the crab walks on. On DESKTOP, sit on top of the input bar so the
// crab never crawls over the typing area. On mobile (≤768px) it's the window
// bottom (overlap there is fine). Recomputed each call so it tracks layout.
Crab.prototype._floorY = function(){
  if((window.innerWidth||0) > 768){
    if(!this._iw || !this._iw.isConnected) this._iw = document.querySelector('.esheep-perch') || document.getElementById('input-wrap');
    if(this._iw){ var r = this._iw.getBoundingClientRect(); if(r.height>0 && r.top>0) return Math.max(0, Math.round(r.top) - this.H); }
  }
  return this.screenH - this.H - 4;
};
Crab.prototype.floorize = function(){ this.y = this._floorY(); };

Crab.prototype.bounceOrClimb = function(newDir){
  if(Math.random() < 0.4 && this.state==='walk'){ this.wall = (newDir>0?'L':'R'); this.x = (newDir>0?0:this.screenW-this.W); this.setState('climb'); this.vy = -0.85; }
  else { this.face(newDir); this.vx = Math.abs(this.vx||1.1) * newDir; if(Math.random()<0.5) this.setState('snap'); }
};

Crab.prototype.setState = function(st){
  this.state = st;
  this.el.classList.remove('walk','snap','rage','charge','wave','dance','crawl','drag','nap');
  this.t = 0;
  switch(st){
    case 'walk':   this.el.classList.add('walk'); this.vx = 0.3*this.dir; this.next = 180 + (Math.random()*200|0); break;   // slower, ambles longer
    case 'seek':   this.el.classList.add('walk'); this.vx = 0; this.next = 99999; break;   // ends via _encounter
    case 'charge': this.el.classList.add('charge','rage'); this.vx = 1.5*this.dir; this.next = 65 + (Math.random()*50|0); if(Math.random()<0.3) this.speak(Math.random()<0.5?'CHARGE!':'WEEEE'); break;
    case 'snap':   this.el.classList.add('snap'); this.vx = 0; this.next = 24 + (Math.random()*20|0); if(Math.random()<0.18) this.speak('SNIP SNIP'); break;
    case 'rage':   this.el.classList.add('rage','snap'); this.vx = 0; this.next = 34 + (Math.random()*26|0); this.anger(); if(Math.random()<0.45) this.speak(pick()); break;
    case 'wave':   this.el.classList.add('wave'); this.vx = 0; this.next = 55; if(Math.random()<0.4) this.speak(Math.random()<0.5?'oi':'come here'); break;
    case 'dance':  this.el.classList.add('dance','walk'); this.vx = 0; this.next = 80; if(Math.random()<0.25) this.speak('sideways gang'); break;
    case 'eat':    this.el.classList.add('snap'); this.vx = 0; this.next = 110; this.eatShrimp(); break;          // 🦐 nom
    case 'nap':    this.el.classList.add('nap');  this.vx = 0; this.next = 150 + (Math.random()*120|0); this.naptime(); if(Math.random()<0.4) this.speak('zzz'); break;
    case 'dig':    this.el.classList.add('snap'); this.vx = 0; this.next = 70; this.digSand(); if(Math.random()<0.4) this.speak(Math.random()<0.5?'digging':'treasure?'); break;
    case 'idle':   this.vx = 0; this.next = 50 + (Math.random()*70|0); break;
    case 'bubble': this.el.classList.add('snap'); this.vx=0; this.next = 30; this.bubbles(); break;
    case 'climb':  this.el.classList.add('crawl'); break;
    case 'ceil':   this.el.classList.add('crawl'); break;
    case 'fall':   break;
  }
  this._applyTransform();
};

Crab.prototype.pickState = function(){
  if(this.state==='climb'||this.state==='ceil'||this.state==='fall'||this.state==='seek'||this.dragging) return;
  var r = Math.random();
  if(r < 0.40)      this.setState('walk');
  else if(r < 0.52) this.setState('snap');
  else if(r < 0.60) this.setState('rage');
  else if(r < 0.68) this.setState('charge');
  else if(r < 0.76) this.setState('wave');
  else if(r < 0.83) this.setState('dance');
  else if(r < 0.90) this.setState('eat');     // find + eat a shrimp 🦐
  else if(r < 0.95) this.setState('nap');     // catch some Zzz
  else if(r < 0.99) this.setState('dig');     // dig in the sand
  else              this.setState('bubble');
};

Crab.prototype.poke = function(){
  if(this._dead) return;
  this.setState('rage');
  this.anger(); this.anger();
  if(Math.random()<0.5) this.speak(pick(), true);    // poking always gets a (forced) reaction sometimes
};

// Where the eSheep is right now (screen coords), or null when it isn't running.
Crab.prototype._sheepTarget = function(){
  try{
    var S = window.CryptIRCSheep;
    if(!S || !S.isOn || !S.isOn() || !S.pos) return null;
    return S.pos();
  }catch(_){ return null; }
};
// Reached the sheep: snap at it, taunt, and make it bolt away. Then cool down.
Crab.prototype._encounter = function(tgt){
  this._encGate = 1800 + (Math.random()*2400|0);     // ~30–70s until the next pestering
  this.setState('rage');
  this.speak(SHEEP_TAUNTS[Math.random()*SHEEP_TAUNTS.length|0], true);
  this.anger(); this.anger();
  try{ if(window.CryptIRCSheep && window.CryptIRCSheep.startle) window.CryptIRCSheep.startle(this.x + this.W/2); }catch(_){ }
};

// ── silly fx ─────────────────────────────────────────────────────────────────
function pick(){ return SAYINGS[Math.random()*SAYINGS.length|0]; }
// Talks LESS: a global cooldown gates spontaneous chatter; `force` (pokes,
// encounters, drag) bypasses the gate but still arms it so the crab then hushes.
Crab.prototype.speak = function(txt, force){
  if(this._dead) return;
  if(!force && this._talkGate > 0) return;
  this._talkGate = 420 + (Math.random()*480|0);      // ~7–15s of quiet after each line
  this.say.textContent = txt;
  var bx = this.x + this.W/2, by = this.y - 8;
  this.say.style.left = Math.max(6, bx) + 'px';
  this.say.style.top  = by + 'px';
  this.say.style.transform = 'translate(-50%,-100%)';
  this.say.classList.add('show');
  var self=this;
  clearTimeout(this._sayT);
  this._sayT = setTimeout(function(){ if(!self._dead) self.say.classList.remove('show'); }, 1400);
  this._timers.push(this._sayT);
};
Crab.prototype.anger = function(){
  if(this._dead) return;
  var a = document.createElement('div');
  a.className = 'cc-anger'; a.textContent = '💢';
  a.style.left = (this.x + (Math.random()<0.5? 4 : this.W-18)) + 'px';
  a.style.top  = (this.y - 6) + 'px';
  document.body.appendChild(a);
  var self=this; this._after(750, function(){ if(a.parentNode) a.parentNode.removeChild(a); });
};
Crab.prototype.bubbles = function(){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<5;i++){ (function(n){ self._after(n*120, function(){
    var b = document.createElement('div'); b.className='cc-bub';
    var sz = 5 + (Math.random()*7|0);
    b.style.width=sz+'px'; b.style.height=sz+'px';
    b.style.left = (self.x + 20 + Math.random()*44) + 'px';
    b.style.top  = (self.y + 6) + 'px';
    b.style.animationDuration = (0.9 + Math.random()*0.7) + 's';
    document.body.appendChild(b);
    self._after(1700, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
  }); })(i); }
};
// 🦐 a shrimp appears in front of the crab; it nibbles it down to nothing.
Crab.prototype.eatShrimp = function(){
  if(this._dead) return;
  var self=this, mirror = this.dir<0 ? 'scaleX(-1) ' : '';
  var sh = document.createElement('div');
  sh.className = 'cc-shrimp'; sh.textContent = '🦐';
  sh.style.left = (this.x + (this.dir>0 ? this.W-10 : -12)) + 'px';
  sh.style.top  = (this.y + this.H*0.5) + 'px';
  sh.style.transform = mirror + 'scale(1)';
  document.body.appendChild(sh);
  if(Math.random()<0.6) this.speak('ooh, shrimp', true);
  this._after(650,  function(){ sh.style.transform = mirror + 'scale(.6)';  sh.style.opacity='.6';  });
  this._after(1050, function(){ sh.style.transform = mirror + 'scale(.2)';  sh.style.opacity='.15'; });
  this._after(1400, function(){ if(sh.parentNode) sh.parentNode.removeChild(sh); self.speak(Math.random()<0.5?'nom nom':'yum', true); });
};
// drowsy Zzz drift up while the crab naps.
Crab.prototype.naptime = function(){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<3;i++){ (function(n){ self._after(n*700, function(){
    var z=document.createElement('div'); z.className='cc-zzz'; z.textContent='z';
    z.style.fontSize=(11+n*3)+'px';
    z.style.left=(self.x + self.W*0.66)+'px'; z.style.top=(self.y - 4)+'px';
    document.body.appendChild(z);
    self._after(1300,function(){ if(z.parentNode) z.parentNode.removeChild(z); });
  }); })(i); }
};
// kicks up little sand grains while digging.
Crab.prototype.digSand = function(){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<6;i++){ (function(){ self._after(i*90, function(){
    var d=document.createElement('div'); d.className='cc-sand';
    var sz=3+(Math.random()*3|0); d.style.width=sz+'px'; d.style.height=sz+'px';
    d.style.left=(self.x + self.W*0.5 + (Math.random()*30-15))+'px';
    d.style.top =(self.y + self.H - 6)+'px';
    document.body.appendChild(d);
    self._after(700,function(){ if(d.parentNode) d.parentNode.removeChild(d); });
  }); })(); }
};

Crab.prototype.destroy = function(){
  this._dead = true;
  if(this._raf) cancelAnimationFrame(this._raf);
  for(var i=0;i<this._timers.length;i++){ clearTimeout(this._timers[i]); }
  this._timers.length = 0;
  for(var j=0;j<this._listeners.length;j++){ var L=this._listeners[j]; try{ L.t.removeEventListener(L.e,L.fn,L.opts); }catch(_){ } }
  this._listeners.length = 0;
  if(this.el && this.el.parentNode) this.el.parentNode.removeChild(this.el);
  if(this.say && this.say.parentNode) this.say.parentNode.removeChild(this.say);
  // sweep any stray fx
  var stray = document.querySelectorAll('.cc-bub, .cc-anger, .cc-shrimp, .cc-zzz, .cc-sand');
  for(var k=0;k<stray.length;k++){ if(stray[k].parentNode) stray[k].parentNode.removeChild(stray[k]); }
};

// ── public manager ───────────────────────────────────────────────────────────
window.CryptIRCCrab = {
  enable: function(){
    if(_enabled) return;
    _enabled = true;
    try{ _crab = new Crab(); _crab.start(); }
    catch(e){ _enabled=false; try{ console.warn('[crab] start failed', e); }catch(_){ } }
  },
  disable: function(){
    _enabled = false;
    if(_crab){ try{ _crab.destroy(); }catch(_){ } _crab = null; }
  },
  isOn: function(){ return _enabled; }
};

})();
