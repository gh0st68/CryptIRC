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

// ── styles (injected once) ───────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-crab-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-crab{position:fixed;z-index:'+Z+';width:84px;height:64px;pointer-events:none;',
      'will-change:left,top,transform;user-select:none;filter:drop-shadow(0 3px 3px rgba(0,0,0,.45))}',
    '.cryptirc-crab svg{display:block;width:100%;height:100%;overflow:visible}',
    /* body bob + leg scuttle while walking */
    '.cryptirc-crab.walk .ccb{animation:ccBob .26s ease-in-out infinite}',
    '.cryptirc-crab.walk .ccleg{animation:ccLeg .26s ease-in-out infinite}',
    '.cryptirc-crab.walk .ccleg.b{animation-delay:.13s}',
    '@keyframes ccBob{50%{transform:translateY(2px)}}',
    '@keyframes ccLeg{50%{transform:rotate(var(--sw,12deg))}}',
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
    '.cryptirc-crab.charge .ccleg{animation:ccLeg .12s ease-in-out infinite}',
    '.cryptirc-crab.charge .ccb{animation:ccBob .12s ease-in-out infinite}',
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
  this.W = 84; this.H = 64;
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
  this.y = Math.max(0, Math.min(this.y, this.screenH - this.H));
};
Crab.prototype.face = function(d){ this.dir = d; this.el.style.transform = d<0 ? 'scaleX(-1)' : 'scaleX(1)'; };

Crab.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  document.body.appendChild(this.say);
  this.face(this.dir);
  this.setState('walk');

  var self=this;
  // poke reaction — DOES NOT steal the click (crab is pointer-events:none); just
  // checks proximity and makes it rage. Listener is tracked for teardown.
  this._on(document, 'mousedown', function(e){
    if(self._dead) return;
    var cx = self.x + self.W/2, cy = self.y + self.H/2;
    var dx = e.clientX - cx, dy = e.clientY - cy;
    if(dx*dx + dy*dy < 95*95){ self.poke(); }
  }, true);
  this._on(window, 'resize', function(){ self._bounds(); self.clamp(); });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } } // truly pause: cancel the deferred frame
    else { self.lastFrame=0; self.loop(); }
  });

  this.loop();
};

Crab.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;                            // already a frame queued — never double-schedule
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Crab.prototype.frame = function(ts){
  if(this._dead) return;
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;   // 0-dt frames (first frame / odd timers) still advance one step

  this.t++;
  if(this.t >= this.next){ this.pickState(); }

  switch(this.state){
    case 'walk':    this.x += this.vx*k; break;
    case 'charge':  this.x += this.vx*k; break;
    case 'climb':   this.y += this.vy*k; break;
    case 'ceil':    this.x += this.vx*k; break;
    case 'fall':    this.vy += 0.9*k; this.y += this.vy*k; var _fl=this._floorY(); if(this.y >= _fl){ this.y=_fl; this.setState('snap'); } break;
    // snap / rage / wave / idle / dance: mostly stationary (dance shuffles)
    case 'dance':   this.x += Math.sin(this.t*0.5)*2.4*this.dir; break;
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
    if(this.y <= 2){ this.y=2; this.setState('ceil'); this.vx = 1.4*(this.x < this.screenW/2 ? 1 : -1); this.face(this.vx<0?-1:1); this.x = Math.max(2, Math.min(this.x, this.screenW - this.W - 2)); }
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
  if(Math.random() < 0.4 && this.state==='walk'){ this.setState('climb'); this.vy = -1.6; this.x = (newDir>0?0:this.screenW-this.W); }
  else { this.face(newDir); this.vx = Math.abs(this.vx||1.1) * newDir; if(Math.random()<0.5) this.setState('snap'); }
};

Crab.prototype.setState = function(st){
  this.state = st;
  this.el.classList.remove('walk','snap','rage','charge','wave','dance');
  this.t = 0;
  switch(st){
    case 'walk':   this.el.classList.add('walk'); this.vx = 1.0*this.dir; this.next = 90 + (Math.random()*110|0); break;
    case 'charge': this.el.classList.add('charge','rage'); this.vx = 4.2*this.dir; this.next = 40 + (Math.random()*40|0); this.speak(Math.random()<0.5?'CHARGE!':'WEEEE'); break;
    case 'snap':   this.el.classList.add('snap'); this.vx = 0; this.next = 22 + (Math.random()*20|0); if(Math.random()<0.5) this.speak('SNIP SNIP'); break;
    case 'rage':   this.el.classList.add('rage','snap'); this.vx = 0; this.next = 34 + (Math.random()*26|0); this.anger(); this.speak(pick()); break;
    case 'wave':   this.el.classList.add('wave'); this.vx = 0; this.next = 50; this.speak(Math.random()<0.5?'oi':'come here'); break;
    case 'dance':  this.el.classList.add('dance','walk'); this.vx = 0; this.next = 70; if(Math.random()<0.6) this.speak('sideways gang'); break;
    case 'idle':   this.vx = 0; this.next = 50 + (Math.random()*70|0); break;
    case 'bubble': this.el.classList.add('snap'); this.vx=0; this.next = 30; this.bubbles(); break;
    case 'climb':  break;
    case 'ceil':   this.el.classList.add('walk'); break;
    case 'fall':   break;
  }
};

Crab.prototype.pickState = function(){
  if(this.state==='climb'||this.state==='ceil'||this.state==='fall') return;
  var r = Math.random();
  if(r < 0.44) this.setState('walk');
  else if(r < 0.58) this.setState('snap');
  else if(r < 0.70) this.setState('rage');
  else if(r < 0.80) this.setState('charge');
  else if(r < 0.88) this.setState('wave');
  else if(r < 0.95) this.setState('dance');
  else this.setState('bubble');
};

Crab.prototype.poke = function(){
  if(this._dead) return;
  this.setState('rage');
  this.anger(); this.anger();
};

// ── silly fx ─────────────────────────────────────────────────────────────────
function pick(){ return SAYINGS[Math.random()*SAYINGS.length|0]; }
Crab.prototype.speak = function(txt){
  if(this._dead) return;
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
  var stray = document.querySelectorAll('.cc-bub, .cc-anger');
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
