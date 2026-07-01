/*!
 * CryptIRC Desktop Pet — Little Green Alien 👽🛸
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) flying saucer with a tiny
 * green alien peeking out of the dome. It hovers and glides around the client
 * and randomly does cool sci-fi stuff: tractor-beam abductions, teleports,
 * scanning sweeps, laser zaps, barrel spins, hologram glitches, wormhole
 * jumps, glyph "signals", a split mini-saucer buddy, stardust trails, probe
 * drops and more. CLICK near it and it swoops over and beams up a little
 * something at your cursor. SILENT (no audio/text chat).
 *
 * Design (do NOT regress):
 *   1. NO eval / NO network — SVG + CSS only, all inline.
 *   2. NEVER in the way — the layer is pointer-events:none, so it can never
 *      block/steal a UI click or change the cursor. Interaction is a passive
 *      document 'click' listener (proximity-gated, never preventDefault).
 *   3. Clean teardown — every timer/listener/rAF/spawned node is tracked and
 *      removed by destroy(); disable() leaves nothing behind.
 *   4. Light — one saucer, capped transient fx, rAF paused while tab hidden.
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like ghost.js/fish.js):
 *   window.CryptIRCAlien.enable()  spawn (idempotent)
 *   .disable()  remove it + all fx/timers/listeners
 *   .isOn()     -> boolean
 * Off by default.
 */
(function(){
'use strict';

var Z = 91;                 // a UFO rides above the other pets (sheep 90); still below panels/menus/modals (>=100)
var _enabled = false;
var _alien = null;
// Sweep stray fx by the shared marker attribute (catches any future al-* node even
// if it isn't listed below) plus the hand-maintained class list.
var STRAY = '[data-pet="alien"], .al-beam, .al-obj, .al-bolt, .al-spark, .al-ring, .al-portal, .al-buddy, .al-dust, .al-glyph, .al-probe, .al-zzz';

// ── styles (injected once) ─────────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-alien-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-alien{position:fixed;z-index:'+Z+';width:90px;height:60px;pointer-events:none;',
      'will-change:left,top,transform;transform-origin:center center;',
      'transition:transform .5s ease;filter:drop-shadow(0 6px 10px rgba(40,90,60,.35))}',
    '.cryptirc-alien svg{display:block;width:100%;height:100%;overflow:visible}',
    // perpetual gentle idle: rim lights pulse, antenna tips glow, alien eyes shimmer
    '.cryptirc-alien .allight{animation:alLights 1.6s linear infinite}',
    '.cryptirc-alien .allight.b{animation-delay:.2s}.cryptirc-alien .allight.c{animation-delay:.4s}',
    '.cryptirc-alien .allight.d{animation-delay:.6s}.cryptirc-alien .allight.e{animation-delay:.8s}',
    '.cryptirc-alien .alant{animation:alAnt 2.2s ease-in-out infinite}',
    '.cryptirc-alien .aleye{animation:alEye 4.5s ease-in-out infinite}',
    '@keyframes alLights{0%,100%{fill:#7CFC9A}33%{fill:#46d6ff}66%{fill:#ffd24a}}',
    '@keyframes alAnt{0%,100%{opacity:.5}50%{opacity:1}}',
    '@keyframes alEye{0%,90%,100%{transform:translateY(0)}45%{transform:translateY(.6px)}}',
    // state classes on the saucer
    '.cryptirc-alien.spin{animation:alSpin 1.5s ease-in-out}',
    '@keyframes alSpin{from{transform:rotate(0)}to{transform:rotate(360deg)}}',
    '.cryptirc-alien.wobble{animation:alWobble 1.4s ease-in-out}',
    '@keyframes alWobble{0%,100%{transform:rotate(0)}25%{transform:rotate(8deg)}75%{transform:rotate(-8deg)}}',
    '.cryptirc-alien.glitch{animation:alGlitch .12s steps(2) infinite}',
    '@keyframes alGlitch{0%{transform:translate(0,0);filter:drop-shadow(2px 0 0 #ff2d6a) drop-shadow(-2px 0 0 #19e0ff)}50%{transform:translate(-1px,1px)}100%{transform:translate(1px,-1px);filter:drop-shadow(-2px 0 0 #ff2d6a) drop-shadow(2px 0 0 #19e0ff)}}',
    '.cryptirc-alien.warpout{animation:alWarp .26s ease-in forwards}',
    '@keyframes alWarp{0%{transform:scale(1);opacity:1}100%{transform:scale(.05,1.6);opacity:0}}',
    '.cryptirc-alien.warpin{animation:alWarpIn .3s ease-out}',
    '@keyframes alWarpIn{0%{transform:scale(.05,1.6);opacity:0}60%{transform:scale(1.1,.9);opacity:1}100%{transform:scale(1)}}',
    '.cryptirc-alien.charge .aldome{animation:alCharge .36s ease-in-out infinite}',
    '@keyframes alCharge{0%,100%{opacity:.85}50%{opacity:1;fill:#bafff0}}',
    '.cryptirc-alien.signal .alant{animation:alAnt .35s ease-in-out infinite}',
    // tractor beam (a downward-widening translucent cone)
    '.al-beam{position:fixed;z-index:'+(Z-1)+';pointer-events:none;transform-origin:top center;',
      'background:linear-gradient(to bottom,rgba(140,255,180,.5),rgba(140,255,180,.04));',
      'clip-path:polygon(36% 0,64% 0,100% 100%,0 100%);animation:alBeam 1.2s ease-out forwards}',
    '@keyframes alBeam{0%{opacity:0;transform:scaleY(.15)}25%{opacity:1;transform:scaleY(1)}80%{opacity:.9}100%{opacity:0}}',
    // an object being abducted (rises into the saucer)
    '.al-obj{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:18px;line-height:1;filter:drop-shadow(0 0 4px rgba(150,255,190,.8))}',
    // laser bolt + impact spark
    '.al-bolt{position:fixed;z-index:'+(Z-1)+';pointer-events:none;width:3px;border-radius:2px;',
      'background:linear-gradient(to bottom,rgba(120,255,170,.1),#7CFC9A,#eafff2);box-shadow:0 0 6px #7CFC9A;animation:alBolt .5s ease-out forwards}',
    '@keyframes alBolt{0%{opacity:0;transform:scaleY(.2)}30%{opacity:1;transform:scaleY(1)}100%{opacity:0}}',
    '.al-spark{position:fixed;z-index:'+(Z-1)+';pointer-events:none;border-radius:50%;background:radial-gradient(circle,#eafff2,rgba(124,252,154,.1));animation:alSpark .5s ease-out forwards}',
    '@keyframes alSpark{0%{opacity:.9;transform:scale(.3)}100%{opacity:0;transform:scale(2.2)}}',
    // scan ring shockwave
    '.al-ring{position:fixed;z-index:'+(Z-1)+';pointer-events:none;border:2px solid rgba(120,255,170,.6);border-radius:50%;animation:alRing 1s ease-out forwards}',
    '@keyframes alRing{0%{opacity:.6;transform:scale(.2)}100%{opacity:0;transform:scale(2.6)}}',
    // wormhole portal
    '.al-portal{position:fixed;z-index:'+(Z-1)+';pointer-events:none;border-radius:50%;',
      'background:conic-gradient(from 0deg,#19e0ff,#7C4DFF,#19e0ff,#7C4DFF,#19e0ff);',
      'filter:blur(1px) drop-shadow(0 0 8px #7C4DFF);animation:alPortal .9s linear}',
    '@keyframes alPortal{0%{opacity:0;transform:scale(.1) rotate(0)}25%{opacity:1}100%{opacity:0;transform:scale(1) rotate(320deg)}}',
    // split mini-saucer buddy
    '.al-buddy{position:fixed;z-index:'+(Z)+';pointer-events:none;opacity:0;will-change:left,top;',
      'transition:opacity .5s ease;filter:drop-shadow(0 4px 7px rgba(40,90,60,.3))}',
    '.al-buddy.in{opacity:.92}.al-buddy svg{display:block;width:100%;height:100%;overflow:visible}',
    // stardust + alien glyph signal + recalled probe + sleepy Zzz
    '.al-dust{position:fixed;z-index:'+(Z-1)+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 40% 35%,#fff,rgba(124,200,255,.2));animation:alDust 1.3s ease-out forwards}',
    '@keyframes alDust{0%{opacity:.9;transform:scale(1) translateY(0)}100%{opacity:0;transform:scale(.2) translateY(14px)}}',
    '.al-glyph{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:13px;color:#9cffc4;',
      'text-shadow:0 0 6px #7CFC9A;animation:alGlyph 1.4s ease-out forwards}',
    '@keyframes alGlyph{0%{opacity:0;transform:translateY(0) scale(.6)}25%{opacity:1}100%{opacity:0;transform:translateY(-26px) scale(1.1)}}',
    '.al-probe{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:15px;transition:left .5s ease,top .5s ease}',
    '.al-zzz{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:13px;color:#cfe;animation:alZzz 1.8s ease-in forwards}',
    '@keyframes alZzz{0%{opacity:0;transform:translate(0,0) rotate(0)}20%{opacity:.9}100%{opacity:0;transform:translate(12px,-26px) rotate(14deg)}}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-alien *,.cryptirc-alien,.al-buddy{animation:none!important}',
      // also silence the spawned FX nodes (al-*) and hide the decorative ones
      '.al-beam,.al-obj,.al-bolt,.al-spark,.al-ring,.al-portal,.al-dust,.al-glyph,.al-probe,.al-zzz{animation:none!important;opacity:0!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the flying-saucer SVG (drawn level; faces both ways the same) ──────────────
function saucerSVG(mini){
  var lights = '';
  var lx = [16,30,44,58,72], cls=['','b','c','d','e'];
  for(var i=0;i<lx.length;i++){ lights += '<circle class="allight '+cls[i]+'" cx="'+lx[i]+'" cy="41" r="2.6" fill="#7CFC9A"/>'; }
  return '<svg viewBox="0 0 90 60" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'+
    '<defs>'+
      '<linearGradient id="alHull" x1="0" y1="0" x2="0" y2="1">'+
        '<stop offset="0" stop-color="#cfd8e3"/><stop offset=".5" stop-color="#9aa7b6"/><stop offset="1" stop-color="#6b7686"/>'+
      '</linearGradient>'+
      '<radialGradient id="alDomeG" cx="45%" cy="35%" r="65%">'+
        '<stop offset="0" stop-color="#dcfff6" stop-opacity=".95"/><stop offset="1" stop-color="#5fd6c2" stop-opacity=".45"/>'+
      '</radialGradient>'+
      '<radialGradient id="alHead" cx="40%" cy="30%" r="75%">'+
        '<stop offset="0" stop-color="#b6ff8e"/><stop offset="1" stop-color="#3fae3a"/>'+
      '</radialGradient>'+
    '</defs>'+
    // soft ground glow under the saucer
    '<ellipse cx="45" cy="46" rx="34" ry="6" fill="rgba(120,255,170,.18)"/>'+
    // dome (glass)
    '<path class="aldome" d="M27 36 C27 18 63 18 63 36 Z" fill="url(#alDomeG)" stroke="#bfeee6" stroke-width="1.5" stroke-opacity=".7"/>'+
    // the little alien inside the dome
    '<g class="alguy">'+
      '<line class="alant" x1="40" y1="20" x2="37" y2="11" stroke="#3fae3a" stroke-width="1.6" stroke-linecap="round"/>'+
      '<line class="alant" x1="50" y1="20" x2="53" y2="11" stroke="#3fae3a" stroke-width="1.6" stroke-linecap="round"/>'+
      '<circle class="alant" cx="37" cy="10" r="2" fill="#aaffd0"/>'+
      '<circle class="alant" cx="53" cy="10" r="2" fill="#aaffd0"/>'+
      '<ellipse cx="45" cy="27" rx="9.5" ry="10.5" fill="url(#alHead)"/>'+
      '<g class="aleye">'+
        '<ellipse cx="41" cy="27" rx="2.6" ry="4.2" fill="#06121a" transform="rotate(-16 41 27)"/>'+
        '<ellipse cx="49" cy="27" rx="2.6" ry="4.2" fill="#06121a" transform="rotate(16 49 27)"/>'+
        '<circle cx="40.4" cy="25.4" r=".7" fill="#fff" fill-opacity=".85"/>'+
        '<circle cx="48.4" cy="25.4" r=".7" fill="#fff" fill-opacity=".85"/>'+
      '</g>'+
    '</g>'+
    // saucer hull
    '<ellipse cx="45" cy="38" rx="43" ry="11" fill="url(#alHull)" stroke="#5b6675" stroke-width="1"/>'+
    '<ellipse cx="45" cy="35.5" rx="30" ry="6" fill="#b9c4d2" fill-opacity=".5"/>'+
    // rim lights
    lights+
    // small emitter underneath
    '<ellipse cx="45" cy="45" rx="8" ry="3" fill="#7CFC9A" fill-opacity=".5"/>'+
  '</svg>';
}

// ── alien instance ──────────────────────────────────────────────────────────────
function Alien(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-alien';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = saucerSVG(false);
  this.W = 90; this.H = 60;
  this.HIT = Math.max(this.W, this.H)/2 + 26;
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this._floatY = 0;
  this._buddy = null;
  this._probe = null;
  this._bounds();
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,((this.screenH*0.6)-this.H));   // tends to ride in the upper area
  this.tx = this.x; this.ty = this.y;
  this.bob = Math.random()*Math.PI*2;
  this.state = 'drift';
  this.t = 0; this.next = 140 + (Math.random()*160|0);
  this.lastFrame = 0;
}
Alien.prototype._bounds = function(){
  this.screenW = window.innerWidth  || document.documentElement.clientWidth  || 800;
  this.screenH = window.innerHeight || document.documentElement.clientHeight || 600;
};
Alien.prototype._on = function(t,e,fn,o){ t.addEventListener(e,fn,o); this._listeners.push({t:t,e:e,fn:fn,o:o}); };
Alien.prototype._after = function(ms,fn){ var self=this,id=setTimeout(function(){ if(!self._dead) fn(); },ms); this._timers.push(id); return id; };
Alien.prototype.clamp = function(){
  this.x = Math.max(0, Math.min(this.x, this.screenW - this.W));
  this.y = Math.max(0, Math.min(this.y, this.screenH - this.H));
};
Alien.prototype._pickTarget = function(){
  var pad = 10;
  this.tx = pad + Math.random()*Math.max(1,(this.screenW - this.W - pad*2));
  // bias toward the upper ~70% of the screen so it reads as "flying"
  this.ty = pad + Math.random()*Math.max(1,((this.screenH*0.72) - this.H - pad));
};

Alien.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  this.el.style.left = this.x + 'px';
  this.el.style.top  = this.y + 'px';
  var self=this;
  // proximity click → swoop over and beam something up (passive; never blocks UI)
  this._on(document, 'click', function(e){
    if(self._dead) return;
    var cx = self.x + self.W/2, cy = self.y + self._floatY + self.H/2;
    var dx = e.clientX - cx, dy = e.clientY - cy;
    if(dx*dx + dy*dy <= self.HIT*self.HIT){ self.react(e.clientX); }
  }, true);
  this._on(window, 'resize', function(){
    self._bounds(); self.clamp();
    if(self.tx > self.screenW - self.W) self.tx = self.screenW - self.W;
    if(self.ty > self.screenH - self.H) self.ty = self.screenH - self.H;
  });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } }
    else { self.lastFrame=0; self.loop(); }
  });
  this.loop();
};

// clicked nearby → glide over the cursor x and do an abduction there
Alien.prototype.react = function(px){
  if(this._dead) return;
  this.tx = Math.max(0, Math.min(px - this.W/2, this.screenW - this.W));
  this.setState('abduct');
};

Alien.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Alien.prototype.frame = function(ts){
  if(this._dead) return;
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;

  this.bob += 0.025 * k;
  this.t++;
  if(this.t >= this.next){ this.pickState(); }

  // moving states ease toward the target; everything else hovers in place
  if(this.state==='drift' || this.state==='dart' || this.state==='scan' || this.state==='abduct'){
    var sp = (this.state==='dart' ? 0.06 : this.state==='scan' ? 0.012 : this.state==='abduct' ? 0.05 : 0.02) * k;
    this.x += (this.tx - this.x) * sp;
    this.y += (this.ty - this.y) * sp;
    if(this.state==='drift'){
      var ddx = this.tx - this.x, ddy = this.ty - this.y;
      if(ddx*ddx + ddy*ddy < 20){ this._pickTarget(); }
    }
  }
  this.clamp();
  this._floatY = Math.sin(this.bob) * 3.2;
  this.el.style.left = this.x + 'px';
  this.el.style.top  = (this.y + this._floatY) + 'px';

  this._buddyTick(k);
  this.loop();
};

Alien.prototype.setState = function(st){
  this.state = st;
  this.el.className = 'cryptirc-alien';
  this.t = 0;
  switch(st){
    case 'drift':    this._pickTarget(); this.next = 200 + (Math.random()*240|0); break;
    case 'hover':    this.next = 120 + (Math.random()*140|0); break;
    case 'dart':     this._pickTarget(); this.next = 70;  break;
    case 'spin':     this.el.classList.add('spin');   this.next = 95;  break;
    case 'wobble':   this.el.classList.add('wobble');  this.next = 86;  break;
    case 'glitch':   this.el.classList.add('glitch');  this.next = 80;  break;
    case 'signal':   this.el.classList.add('signal');  this.next = 110; this.signal(); break;
    case 'scan':     this._wallTarget(); this.next = 150; this.scan(); break;
    case 'zap':      this.el.classList.add('charge');   this.next = 64; this._after(360, this.fireZap.bind(this)); break;
    case 'abduct':   this.next = 130; this.abduct(); break;
    case 'stardust': this.next = 80;  this.stardust(); break;
    case 'probe':    this.next = 150; this.probe(); break;
    case 'teleport': this.el.classList.add('warpout'); this.next = 30; this._after(260, this._doTeleport.bind(this)); break;
    case 'wormhole': this.el.classList.add('warpout'); this.next = 34; this.wormhole(); break;
    case 'snooze':   this.next = 150 + (Math.random()*120|0); this.snooze(); break;
  }
};

// keep calm hovering/drifting dominant; the flashy stuff is occasional
Alien.prototype.pickState = function(){
  var r = Math.random();
  if(r < 0.30)       this.setState('drift');
  else if(r < 0.45)  this.setState('hover');
  else if(r < 0.52)  this.setState('dart');
  else if(r < 0.59)  this.setState('abduct');
  else if(r < 0.65)  this.setState('scan');
  else if(r < 0.71)  this.setState('signal');
  else if(r < 0.77)  this.setState('stardust');
  else if(r < 0.82)  this.setState('spin');
  else if(r < 0.87)  this.setState('wobble');
  else if(r < 0.90)  this.setState('glitch');
  else if(r < 0.925) this.setState('zap');
  else if(r < 0.95)  this.setState('probe');
  else if(r < 0.975) this.setState('teleport');
  else if(r < 0.99)  this.setState('wormhole');
  else               this.setState('snooze');
};

Alien.prototype._wallTarget = function(){
  this.tx = (this.x < this.screenW/2) ? (this.screenW - this.W - 8) : 8;   // sweep across
};

// ── fx ─────────────────────────────────────────────────────────────────────────
Alien.prototype._saucerBottom = function(){ return { x:this.x + this.W/2, y:this.y + this._floatY + this.H*0.66 }; };

// tractor beam straight down from the saucer; returns the beam's reach (px)
Alien.prototype.beam = function(reach){
  if(this._dead || document.hidden) return 0;
  var b = this._saucerBottom();
  var h = Math.max(40, Math.min(reach || 150, this.screenH - b.y - 4));
  var w = this.W * 0.5;
  var d = document.createElement('div'); d.className = 'al-beam'; d.setAttribute('data-pet','alien');
  d.style.width = w + 'px'; d.style.height = h + 'px';
  d.style.left = (b.x - w/2) + 'px'; d.style.top = b.y + 'px';
  document.body.appendChild(d);
  this._after(1300, function(){ if(d.parentNode) d.parentNode.removeChild(d); });
  return h;
};

var ABDUCT_OBJS = ['🐄','🌟','🛰️','❓','🐟','🌵','📦','🚗','🧀','🪨'];
Alien.prototype.abduct = function(){
  if(this._dead || document.hidden) return;
  var h = this.beam(160);
  var b = this._saucerBottom();
  var o = document.createElement('div'); o.className = 'al-obj'; o.setAttribute('data-pet','alien');
  o.textContent = ABDUCT_OBJS[(Math.random()*ABDUCT_OBJS.length)|0];
  var startY = b.y + h - 16, endY = b.y - 6;
  o.style.left = (b.x - 9) + 'px'; o.style.top = startY + 'px';
  o.style.transition = 'top 1s ease-in, opacity .3s ease';
  document.body.appendChild(o);
  var self=this;
  this._after(30,  function(){ o.style.top = endY + 'px'; });   // float up into the saucer
  this._after(1000,function(){ o.style.opacity = '0'; });
  this._after(1350,function(){ if(o.parentNode) o.parentNode.removeChild(o); });
};

Alien.prototype.fireZap = function(){
  if(this._dead || document.hidden) return;
  this.el.classList.remove('charge');
  var b = this._saucerBottom();
  var len = Math.max(40, Math.min(120 + (Math.random()*120|0), this.screenH - b.y - 4));
  var bolt = document.createElement('div'); bolt.className = 'al-bolt'; bolt.setAttribute('data-pet','alien');
  bolt.style.height = len + 'px'; bolt.style.left = (b.x - 1.5) + 'px'; bolt.style.top = b.y + 'px';
  bolt.style.transformOrigin = 'top center';
  document.body.appendChild(bolt);
  this._after(520, function(){ if(bolt.parentNode) bolt.parentNode.removeChild(bolt); });
  // impact spark where the bolt lands
  var sx = b.x, sy = b.y + len;
  var sp = document.createElement('div'); sp.className = 'al-spark'; sp.setAttribute('data-pet','alien');
  var sz = 18; sp.style.width=sz+'px'; sp.style.height=sz+'px';
  sp.style.left=(sx-sz/2)+'px'; sp.style.top=(sy-sz/2)+'px';
  document.body.appendChild(sp);
  this._after(520, function(){ if(sp.parentNode) sp.parentNode.removeChild(sp); });
};

Alien.prototype.scan = function(){
  if(this._dead || document.hidden) return;
  var b = this._saucerBottom();
  var r = document.createElement('div'); r.className = 'al-ring'; r.setAttribute('data-pet','alien');
  var sz = 30; r.style.width=sz+'px'; r.style.height=sz+'px';
  r.style.left=(b.x-sz/2)+'px'; r.style.top=(this.y + this._floatY + this.H/2 - sz/2)+'px';
  document.body.appendChild(r);
  this._after(1050, function(){ if(r.parentNode) r.parentNode.removeChild(r); });
};

var GLYPHS = ['✦','⌬','☌','⏃','◬','⟁','✶','⍟','⏚','⊹'];
Alien.prototype.signal = function(){
  if(this._dead || document.hidden) return;
  var n = 2 + (Math.random()*2|0), self=this;
  for(var i=0;i<n;i++){
    (function(idx){
      self._after(idx*180, function(){
        if(self._dead) return;
        var g = document.createElement('div'); g.className='al-glyph'; g.setAttribute('data-pet','alien');
        g.textContent = GLYPHS[(Math.random()*GLYPHS.length)|0];
        g.style.left = (self.x + self.W*0.5 + (Math.random()*24-12)) + 'px';
        g.style.top  = (self.y + self._floatY + 6) + 'px';
        document.body.appendChild(g);
        self._after(1450, function(){ if(g.parentNode) g.parentNode.removeChild(g); });
      });
    })(i);
  }
};

Alien.prototype.stardust = function(){
  if(this._dead || document.hidden) return;
  var n = 4 + (Math.random()*4|0), self=this;
  for(var i=0;i<n;i++){
    (function(idx){
      self._after(idx*90, function(){
        if(self._dead) return;
        var d = document.createElement('div'); d.className='al-dust'; d.setAttribute('data-pet','alien');
        var sz = 3 + (Math.random()*4|0);
        d.style.width=sz+'px'; d.style.height=sz+'px';
        d.style.left = (self.x + self.W*0.5 + (Math.random()*40-20)) + 'px';
        d.style.top  = (self.y + self._floatY + self.H*0.5 + (Math.random()*10-5)) + 'px';
        document.body.appendChild(d);
        self._after(1400, function(){ if(d.parentNode) d.parentNode.removeChild(d); });
      });
    })(i);
  }
};

// a little probe droid drops, hovers, then is recalled
Alien.prototype.probe = function(){
  if(this._dead || document.hidden || this._probe) return;
  var b = this._saucerBottom();
  var p = document.createElement('div'); p.className='al-probe'; p.setAttribute('data-pet','alien'); p.textContent='🛸';
  p.style.left = (b.x - 8) + 'px'; p.style.top = b.y + 'px';
  document.body.appendChild(p);
  this._probe = p;
  var self=this;
  var dropY = Math.min(b.y + 70 + (Math.random()*60|0), this.screenH - 24);
  this._after(40,   function(){ if(self._probe===p){ p.style.left=(b.x-8+(Math.random()*60-30))+'px'; p.style.top=dropY+'px'; } });
  this._after(1100, function(){ if(self._probe===p){ var nb=self._saucerBottom(); p.style.left=(nb.x-8)+'px'; p.style.top=nb.y+'px'; } });
  this._after(1700, function(){ if(p.parentNode) p.parentNode.removeChild(p); if(self._probe===p) self._probe=null; });
};

Alien.prototype.snooze = function(){
  if(this._dead || document.hidden) return;
  var n = 3, self=this;
  for(var i=0;i<n;i++){
    (function(idx){
      self._after(idx*420, function(){
        if(self._dead) return;
        var z = document.createElement('div'); z.className='al-zzz'; z.setAttribute('data-pet','alien'); z.textContent='z';
        z.style.left = (self.x + self.W*0.62) + 'px';
        z.style.top  = (self.y + self._floatY + 4) + 'px';
        document.body.appendChild(z);
        self._after(1850, function(){ if(z.parentNode) z.parentNode.removeChild(z); });
      });
    })(i);
  }
};

Alien.prototype._doTeleport = function(){
  if(this._dead) return;
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,((this.screenH*0.7)-this.H));
  this.tx = this.x; this.ty = this.y;
  this.el.style.left = this.x+'px'; this.el.style.top = this.y+'px';
  this.el.className = 'cryptirc-alien warpin';
  this.setState('hover');
  this.el.classList.add('warpin');
};

// open a portal where it is, blink to a new spot, open another portal there
Alien.prototype.wormhole = function(){
  if(this._dead) return;
  var self=this;
  this._portalAt(this.x + this.W/2, this.y + this._floatY + this.H/2);
  this._after(300, function(){
    if(self._dead) return;
    self.x = Math.random()*Math.max(1,(self.screenW-self.W));
    self.y = Math.random()*Math.max(1,((self.screenH*0.7)-self.H));
    self.tx=self.x; self.ty=self.y;
    self.el.style.left=self.x+'px'; self.el.style.top=self.y+'px';
    self._portalAt(self.x + self.W/2, self.y + self.H/2);
    self.el.className='cryptirc-alien warpin';
    self.setState('hover');
    self.el.classList.add('warpin');
  });
};
Alien.prototype._portalAt = function(cx, cy){
  if(this._dead || document.hidden) return;
  var p = document.createElement('div'); p.className='al-portal'; p.setAttribute('data-pet','alien');
  var sz = 60; p.style.width=sz+'px'; p.style.height=sz+'px';
  p.style.left=(cx-sz/2)+'px'; p.style.top=(cy-sz/2)+'px';
  document.body.appendChild(p);
  this._after(950, function(){ if(p.parentNode) p.parentNode.removeChild(p); });
};

// ── split mini-saucer buddy (occasional companion) ──────────────────────────────
Alien.prototype._buddyTick = function(k){
  if(!this._buddy){
    if(this._buddyGate == null){ this._buddyGate = 700 + (Math.random()*1400|0); }
    if(this._buddyGate > 0){ this._buddyGate -= k; }
    else { this._spawnBuddy(); this._buddyGate = 2600 + (Math.random()*3600|0); }
    return;
  }
  this._buddyBob += 0.04*k;
  var fw=this._buddyW, fh=this._buddyH;
  var fx = this.x + this._buddySide*(this.W*0.7) + Math.sin(this._buddyBob)*10;
  var fy = this.y + this._floatY - 6 + Math.cos(this._buddyBob*1.3)*8;
  fx = Math.max(0, Math.min(fx, this.screenW - fw));
  fy = Math.max(0, Math.min(fy, this.screenH - fh));
  this._buddy.style.left = fx+'px'; this._buddy.style.top = fy+'px';
  this._buddyT -= k;
  if(this._buddyT <= 0){ this._despawnBuddy(); }
};
Alien.prototype._spawnBuddy = function(){
  if(this._dead || document.hidden || this._buddy) return;
  var f = document.createElement('div'); f.className='al-buddy'; f.setAttribute('data-pet','alien');
  var fw = Math.round(this.W*0.6), fh = Math.round(this.H*0.6);
  f.style.width=fw+'px'; f.style.height=fh+'px';
  f.innerHTML = saucerSVG(true);
  this._buddyW=fw; this._buddyH=fh; this._buddySide=Math.random()<0.5?-1:1;
  this._buddyBob=Math.random()*Math.PI*2; this._buddyT=900+(Math.random()*900|0);
  document.body.appendChild(f); this._buddy=f;
  var self=this; this._after(30, function(){ if(self._buddy===f) f.classList.add('in'); });
};
Alien.prototype._despawnBuddy = function(){
  var f=this._buddy; this._buddy=null; this._buddyT=0;
  if(!f) return;
  f.classList.remove('in');
  this._after(600, function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};

Alien.prototype.destroy = function(){
  this._dead = true;
  if(this._raf) cancelAnimationFrame(this._raf);
  for(var i=0;i<this._timers.length;i++){ clearTimeout(this._timers[i]); }
  this._timers.length = 0;
  for(var j=0;j<this._listeners.length;j++){ var L=this._listeners[j]; try{ L.t.removeEventListener(L.e,L.fn,L.o); }catch(_){ } }
  this._listeners.length = 0;
  this._buddy = null; this._probe = null;
  if(this.el && this.el.parentNode) this.el.parentNode.removeChild(this.el);
  this.el = null;
  var stray = document.querySelectorAll(STRAY);
  for(var m=0;m<stray.length;m++){ if(stray[m].parentNode) stray[m].parentNode.removeChild(stray[m]); }
};

// ── public manager ─────────────────────────────────────────────────────────────
window.CryptIRCAlien = {
  enable: function(){
    if(_enabled) return;
    _enabled = true;
    try{ _alien = new Alien(); _alien.start(); }
    catch(e){ _enabled=false; try{ console.warn('[alien] start failed', e); }catch(_){ } }
  },
  disable: function(){
    _enabled = false;
    if(_alien){ try{ _alien.destroy(); }catch(_){ } _alien = null; }
  },
  isOn: function(){ return _enabled; }
};

})();
