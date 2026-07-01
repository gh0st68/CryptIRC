/*!
 * CryptIRC Desktop Pet — Spooky Ghost 👻
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) eerie spectre that drifts
 * slowly around the whole client window — phasing through walls, flickering,
 * teleporting, stretching, sinking into the floor, and (rarely) lunging at you
 * with a wail. SILENT: no text. Drawn procedurally as an articulated SVG and
 * animated with CSS + a rAF position loop.
 *
 * You can DRAG it (grab-to-drag, like the crab/eSheep), but it never steals
 * clicks: a plain click is forwarded to the UI underneath.
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like crab.js):
 *   window.CryptIRCGhost.enable()  spawn (idempotent)
 *   .disable()  remove it + its companion + all timers/listeners (no leaks)
 *   .isOn()     -> boolean
 * Off by default. Slow & low-key; pauses when the tab is hidden.
 */
(function(){
'use strict';

var Z = 88;                  // paints UNDER the crab (89) and sheep (90)
var _enabled = false;
var _ghost = null;

// Topmost element at (x,y) that is NOT a desktop-pet node, so a forwarded click
// resolves to the real UI beneath instead of another pet.
var PET_SELECTOR = '.cryptirc-ghost, .gh-friend, .cryptirc-crab, .cryptirc-esheep, .cryptirc-alien, .al-buddy, .cryptirc-fish';
function topUnderPets(x, y){
  var stack = (document.elementsFromPoint ? document.elementsFromPoint(x, y) : null);
  if(stack){
    for(var i=0;i<stack.length;i++){
      var el = stack[i];
      if(el && el.closest && el.closest(PET_SELECTOR)) continue;
      return el;
    }
    return null;
  }
  var pets = document.querySelectorAll(PET_SELECTOR), saved=[];
  for(var j=0;j<pets.length;j++){ saved.push([pets[j], pets[j].style.pointerEvents]); pets[j].style.pointerEvents='none'; }
  var under = document.elementFromPoint(x, y);
  for(var m=0;m<saved.length;m++){ saved[m][0].style.pointerEvents = saved[m][1]; }
  if(under && under.closest && under.closest(PET_SELECTOR)) return null;
  return under;
}

// pale, sickly spectre; the companion is a darker shadow-wraith
var TINT_MAIN   = { body:'#e8efea', sh:'#9fb0ab' };
var TINT_FRIEND = { body:'#c4cfca', sh:'#7f8e89' };

// ── styles (injected once) ───────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-ghost-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-ghost{position:fixed;z-index:'+Z+';width:58px;height:70px;pointer-events:auto;cursor:grab;touch-action:manipulation;',
      'will-change:left,top,transform;user-select:none;-webkit-user-select:none;opacity:.86;',
      'transition:opacity .6s ease;filter:drop-shadow(0 0 9px rgba(150,200,190,.55))}',
    '.cryptirc-ghost svg{display:block;width:100%;height:100%;overflow:visible;pointer-events:none}',
    /* the shadow companion (not draggable) */
    '.gh-friend{position:fixed;z-index:'+(Z)+';pointer-events:none;opacity:0;',
      'will-change:left,top;transition:opacity 1.1s ease;filter:drop-shadow(0 0 8px rgba(110,150,140,.5))}',
    '.gh-friend.in{opacity:.7}',
    '.gh-friend svg{display:block;width:100%;height:100%;overflow:visible}',
    /* idle: a slow eerie sway + the tattered tail drifts; eyes glow faintly */
    '.cryptirc-ghost .ghb,.gh-friend .ghb{animation:ghSway 5.2s ease-in-out infinite;transform-origin:32px 30px}',
    '.cryptirc-ghost .ghtat,.gh-friend .ghtat{animation:ghTatter 3.4s ease-in-out infinite}',
    '.cryptirc-ghost .ghglow{animation:ghEye 4.6s ease-in-out infinite}',
    '@keyframes ghSway{0%,100%{transform:rotate(-2.5deg)}50%{transform:rotate(2.5deg)}}',
    '@keyframes ghTatter{0%,100%{transform:translateY(0) scaleY(1)}50%{transform:translateY(2px) scaleY(1.06)}}',
    '@keyframes ghEye{0%,92%,100%{opacity:.0}40%,60%{opacity:.5}}',
    /* fade: phase through the wall (effectively invisible → don't intercept clicks) */
    '.cryptirc-ghost.fade{opacity:.08;pointer-events:none;cursor:default}',
    /* flicker: a dying-bulb glitch + tiny jitter */
    '.cryptirc-ghost.flicker{animation:ghFlicker .5s steps(2) infinite}',
    '@keyframes ghFlicker{0%{opacity:.86;transform:translateX(0)}20%{opacity:.18;transform:translateX(1px)}40%{opacity:.86;transform:translateX(-1px)}60%{opacity:.3}80%{opacity:.86;transform:translateX(1px)}100%{opacity:.5}}',
    /* stretch: taffy distort, then snap back */
    '.cryptirc-ghost.stretch{animation:ghStretch 1.4s ease-in-out}',
    '@keyframes ghStretch{0%{transform:scale(1,1)}40%{transform:scale(.7,1.5)}70%{transform:scale(1.25,.8)}100%{transform:scale(1,1)}}',
    /* spin: a slow uneasy turn */
    '.cryptirc-ghost.spin{animation:ghSpin 3s ease-in-out}',
    '@keyframes ghSpin{from{transform:rotate(0)}to{transform:rotate(360deg)}}',
    /* lunge: RARE jump-at-you with red eyes (see .rage swap below) */
    '.cryptirc-ghost.lunge{animation:ghLunge .8s ease-out}',
    '@keyframes ghLunge{0%{transform:scale(1)}30%{transform:scale(1.85) translateY(-6px)}45%{transform:scale(1.8) rotate(-5deg)}60%{transform:scale(1.8) rotate(5deg)}100%{transform:scale(1)}}',
    '.cryptirc-ghost.rage .ghvoid{fill:#c01818}',
    '.cryptirc-ghost.rage .ghglow{opacity:.9!important;animation:none}',
    /* wail: the gaping mouth widens + a cold ring radiates */
    '.cryptirc-ghost.wail .ghmouth{animation:ghWail .9s ease-in-out}',
    '@keyframes ghWail{0%,100%{transform:scaleY(1)}50%{transform:scaleY(1.7)}}',
    /* held: clutched in your cursor — writhes */
    '.cryptirc-ghost.held{cursor:grabbing;animation:ghWrithe .5s ease-in-out infinite}',
    '@keyframes ghWrithe{0%,100%{transform:rotate(-6deg) scale(1.04,.96)}50%{transform:rotate(6deg) scale(.96,1.04)}}',
    /* cold mist it leaves behind */
    '.gh-mist{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 45% 35%,rgba(220,235,228,.7),rgba(150,180,170,.12));',
      'filter:blur(1.2px);animation:ghMist linear forwards}',
    '@keyframes ghMist{0%{opacity:.55;transform:translateY(0) scale(.7)}100%{opacity:0;transform:translateY(-30px) scale(1.6)}}',
    /* cold-ring shockwave on a wail/lunge */
    '.gh-ring{position:fixed;z-index:'+Z+';pointer-events:none;border:2px solid rgba(190,220,210,.6);border-radius:50%;animation:ghRing .8s ease-out forwards}',
    '@keyframes ghRing{0%{opacity:.6;transform:scale(.2)}100%{opacity:0;transform:scale(2.4)}}',
    /* stare: eyes lock on + glow */
    '.cryptirc-ghost.staring .ghglow{opacity:.85!important;animation:none}',
    '.cryptirc-ghost.staring .ghvoid{fill:#16241f}',
    /* melt: drip toward the floor then re-form */
    '.cryptirc-ghost.melt{animation:ghMelt 2s ease-in-out}',
    '@keyframes ghMelt{0%{transform:scaleY(1)}45%{transform:scale(1.12,.55) translateY(16px)}72%{transform:scale(.9,1.18)}100%{transform:scale(1,1)}}',
    /* vanish: gone for a moment (fully invisible → don't intercept clicks) */
    '.cryptirc-ghost.vanish{opacity:0;pointer-events:none;cursor:default}',
    /* split after-image clone */
    '.gh-clone{position:fixed;z-index:'+Z+';pointer-events:none;opacity:.4;will-change:left,top,opacity;transition:left .55s ease,top .55s ease,opacity .55s ease;filter:drop-shadow(0 0 7px rgba(150,200,190,.4))}',
    '.gh-clone svg{display:block;width:100%;height:100%;overflow:visible}',
    /* blood drip */
    '.gh-drip{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:12px;animation:ghDrip 1.5s ease-in forwards}',
    '@keyframes ghDrip{0%{opacity:0;transform:translateY(-2px)}20%{opacity:1}100%{opacity:0;transform:translateY(28px)}}',
    /* glowing eyes in the dark */
    '.gh-eyes{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:14px;letter-spacing:2px;filter:drop-shadow(0 0 8px #7fdcc8);animation:ghEyes 1.2s ease-in-out}',
    '@keyframes ghEyes{0%,100%{opacity:0}30%,72%{opacity:.95}}',
    /* spider on a thread */
    '.gh-web{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:13px;animation:ghWeb 2.3s ease-in-out forwards}',
    '.gh-web::before{content:"";position:absolute;left:50%;top:-22px;width:1px;height:22px;background:rgba(205,222,216,.45)}',
    '@keyframes ghWeb{0%{opacity:0;transform:translateY(-22px)}22%{opacity:.95;transform:translateY(0)}80%{opacity:.95}100%{opacity:0;transform:translateY(-14px)}}',
    /* ── NEW spooky fx ─────────────────────────────────────────────────── */
    /* will-o'-wisp: tiny orbs that orbit then fade */
    '.gh-wisp{position:fixed;z-index:'+(Z+1)+';pointer-events:none;width:9px;height:9px;border-radius:50%;',
      'background:radial-gradient(circle at 40% 35%,rgba(190,255,235,.95),rgba(110,200,180,.15));',
      'filter:blur(.4px) drop-shadow(0 0 6px #7fdcc8);opacity:0;animation:ghWisp ease-in-out forwards}',
    '@keyframes ghWisp{0%{opacity:0}14%,80%{opacity:.9}100%{opacity:0}}',
    /* bat that flutters off */
    '.gh-bat{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:15px;animation:ghBat 2.4s ease-in forwards}',
    '@keyframes ghBat{0%{opacity:0;transform:translate(0,0) rotate(0)}12%{opacity:.95}50%{transform:translate(-60px,-46px) rotate(-12deg)}100%{opacity:0;transform:translate(-150px,-130px) rotate(8deg)}}',
    /* frost-breath fog puff */
    '.gh-frost{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 50% 50%,rgba(225,245,255,.6),rgba(180,215,235,.05));',
      'filter:blur(3px);animation:ghFrost 2.1s ease-out forwards}',
    '@keyframes ghFrost{0%{opacity:0;transform:scale(.3)}25%{opacity:.55}100%{opacity:0;transform:scale(2.2) translateY(-8px)}}',
    /* shadow-puddle it sinks into the floor */
    '.cryptirc-ghost.puddle{animation:ghPuddle 2.4s ease-in-out}',
    '@keyframes ghPuddle{0%{transform:scale(1,1)}40%{transform:scale(1.5,.18) translateY(26px);opacity:.5}70%{transform:scale(1.5,.18) translateY(26px);opacity:.5}100%{transform:scale(1,1);opacity:.86}}',
    '.gh-puddle{position:fixed;z-index:'+(Z-1)+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(ellipse at 50% 50%,rgba(10,16,14,.6),rgba(10,16,14,0));',
      'filter:blur(2px);animation:ghPuddleFx 2.4s ease-in-out forwards}',
    '@keyframes ghPuddleFx{0%{opacity:0;transform:scaleX(.2)}30%,70%{opacity:.65;transform:scaleX(1)}100%{opacity:0;transform:scaleX(.2)}}',
    /* mirror doppelganger — a horizontally-flipped twin that mimics then fades */
    '.gh-mirror{position:fixed;z-index:'+Z+';pointer-events:none;opacity:0;transform:scaleX(-1);',
      'will-change:opacity;transition:opacity .5s ease;filter:drop-shadow(0 0 7px rgba(150,200,190,.4))}',
    '.gh-mirror.in{opacity:.45}',
    '.gh-mirror svg{display:block;width:100%;height:100%;overflow:visible}',
    /* floating jack-o-lantern */
    '.gh-pumpkin{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:18px;filter:drop-shadow(0 0 7px #ff8a1e);animation:ghPumpkin 3.2s ease-in-out forwards}',
    '@keyframes ghPumpkin{0%{opacity:0;transform:translateY(8px) scale(.6)}18%{opacity:.95}50%{transform:translateY(-10px) scale(1)}82%{opacity:.95}100%{opacity:0;transform:translateY(-26px) scale(.7)}}',
    /* flickering candle it lights */
    '.gh-candle{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:15px;filter:drop-shadow(0 0 6px #ffcf6a);animation:ghCandle 2.8s ease-in-out forwards}',
    '@keyframes ghCandle{0%{opacity:0;transform:scale(.7)}16%{opacity:1}24%{opacity:.55}30%{opacity:1}55%{opacity:.6}62%{opacity:1}85%{opacity:.9}100%{opacity:0;transform:scale(.6)}}',
    /* spectral chains rattle — the ghost shudders */
    '.cryptirc-ghost.chains{animation:ghChains .45s ease-in-out 4}',
    '@keyframes ghChains{0%,100%{transform:translateX(0) rotate(0)}25%{transform:translateX(-2px) rotate(-2deg)}75%{transform:translateX(2px) rotate(2deg)}}',
    '.gh-chain{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:14px;letter-spacing:-2px;animation:ghChain 1.9s ease-out forwards}',
    '@keyframes ghChain{0%{opacity:0;transform:translateY(-10px) rotate(0)}20%{opacity:.9}40%{transform:translateY(0) rotate(-6deg)}60%{transform:rotate(6deg)}100%{opacity:0;transform:translateY(6px)}}',
    /* gravestone rises from the floor then sinks */
    '.gh-grave{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:22px;filter:drop-shadow(0 2px 3px rgba(0,0,0,.4));animation:ghGrave 3.6s ease-in-out forwards}',
    '@keyframes ghGrave{0%{opacity:0;transform:translateY(26px)}18%{opacity:.95;transform:translateY(0)}78%{opacity:.95;transform:translateY(0)}100%{opacity:0;transform:translateY(26px)}}',
    /* eerie rune that glows and fades */
    '.gh-rune{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:18px;color:#a8ffe6;',
      'filter:drop-shadow(0 0 9px #4fd9bd);animation:ghRune 2.6s ease-in-out forwards}',
    '@keyframes ghRune{0%{opacity:0;transform:scale(.4) rotate(-30deg)}25%{opacity:.95;transform:scale(1) rotate(0)}55%{opacity:.55}70%{opacity:.95}100%{opacity:0;transform:scale(1.4) rotate(20deg)}}',
    /* possess-the-cursor: the ghost shrinks & shadows the pointer (movement via JS) */
    '.cryptirc-ghost.possess{transform:scale(.62);opacity:.7}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-ghost *,.cryptirc-ghost,.gh-friend *,.gh-friend{animation:none!important;transition:opacity .6s ease!important}',
      // also silence the spawned FX nodes (gh-*) and hide the decorative ones
      '.gh-mist,.gh-ring,.gh-clone,.gh-drip,.gh-eyes,.gh-web,.gh-wisp,.gh-bat,.gh-frost,.gh-puddle,.gh-mirror,.gh-pumpkin,.gh-candle,.gh-chain,.gh-grave,.gh-rune{animation:none!important;opacity:0!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the spooky ghost SVG (hollow void eyes, gaping wail, tattered tail) ───────
function ghostSVG(tint){
  tint = tint || TINT_MAIN;
  return '<svg viewBox="0 0 64 76" xmlns="http://www.w3.org/2000/svg">'+
    '<g class="ghb" style="transform-origin:32px 30px">'+
      // sickly aura
      '<ellipse cx="32" cy="34" rx="27" ry="36" fill="rgba(150,200,185,.14)"/>'+
      // elongated drippy body
      '<path d="M9 40 C9 14 22 4 32 4 C42 4 55 14 55 40 L55 58 L9 58 Z" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="2"/>'+
      // inner darkness for depth
      '<path d="M14 40 C14 19 23 9 31 7 C22 12 18 24 18 40 L18 56 L14 56 Z" fill="rgba(120,140,135,.35)"/>'+
      // tattered, jagged tail (sharp points, not cute humps)
      '<g class="ghtat" style="transform-origin:32px 58px"><path d="M9 58 L15 72 L20 58 L26 70 L32 58 L38 71 L44 58 L49 73 L55 58 Z" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="2" stroke-linejoin="round"/></g>'+
      // faint eye glow (animated)
      '<ellipse class="ghglow" cx="23" cy="31" rx="6" ry="7.5" fill="#7fdcc8" opacity="0"/>'+
      '<ellipse class="ghglow" cx="41" cy="31" rx="6" ry="7.5" fill="#7fdcc8" opacity="0"/>'+
      // angular menacing brows
      '<path d="M16 24 L29 30" stroke="#2b3330" stroke-width="2.6" stroke-linecap="round"/>'+
      '<path d="M48 24 L35 30" stroke="#2b3330" stroke-width="2.6" stroke-linecap="round"/>'+
      // hollow void eyes (no pupils/sparkles) — slightly slanted for menace
      '<ellipse class="ghvoid" cx="23" cy="32" rx="5" ry="7.2" fill="#0c0f12" transform="rotate(-8 23 32)"/>'+
      '<ellipse class="ghvoid" cx="41" cy="32" rx="5" ry="7.2" fill="#0c0f12" transform="rotate(8 41 32)"/>'+
      // gaping wailing mouth
      '<ellipse class="ghmouth" cx="32" cy="47" rx="4.6" ry="7" fill="#0c0f12" style="transform-origin:32px 47px"/>'+
    '</g>'+
  '</svg>';
}

// ── ghost instance ───────────────────────────────────────────────────────────
function Ghost(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-ghost';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = ghostSVG(TINT_MAIN);
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this.W = 58; this.H = 70;
  this.dragging = false; this._didDrag = false; this._pressX = null; this._pressY = null;
  this._bounds();
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,(this.screenH-this.H));
  this.tx = this.x; this.ty = this.y;
  this.bob = Math.random()*Math.PI*2;
  this.state = 'drift';
  this.t = 0; this.next = 120 + (Math.random()*150|0);
  this.lastFrame = 0;
  this._mistGate = 60 + (Math.random()*90|0);
  // a shadow companion that haunts alongside it now and then
  this._friend = null; this._friendT = 0; this._friendBob = 0; this._friendSide = 1;
  this._friendGate = 900 + (Math.random()*1800|0);
  this._mirror = null;   // transient mirror-doppelganger node
}
Ghost.prototype._bounds = function(){
  this.screenW = window.innerWidth || document.documentElement.clientWidth || 800;
  this.screenH = window.innerHeight || document.documentElement.clientHeight || 600;
};
Ghost.prototype._on = function(target, ev, fn, opts){
  target.addEventListener(ev, fn, opts);
  this._listeners.push({t:target, e:ev, fn:fn, opts:opts});
};
Ghost.prototype._after = function(ms, fn){
  var self=this, id=setTimeout(function(){ if(!self._dead) fn(); }, ms);
  this._timers.push(id); return id;
};
Ghost.prototype.clamp = function(){
  this.x = Math.max(0, Math.min(this.x, this.screenW - this.W));
  this.y = Math.max(0, Math.min(this.y, this.screenH - this.H));
};
Ghost.prototype._pickTarget = function(){
  this.tx = Math.random()*Math.max(1,(this.screenW-this.W));
  this.ty = Math.random()*Math.max(1,(this.screenH-this.H));
};
Ghost.prototype._pickCorner = function(){
  var pad = 10;
  this.tx = Math.max(0, (Math.random()<0.5 ? pad : (this.screenW - this.W - pad)));
  this.ty = Math.max(0, (Math.random()<0.5 ? pad : (this.screenH - this.H - pad)));
};

Ghost.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  this.setState('drift');
  this._wire();

  var self=this;
  this._on(window, 'resize', function(){ self._bounds(); self.clamp(); if(self.tx>self.screenW-self.W) self.tx=self.screenW-self.W; if(self.ty>self.screenH-self.H) self.ty=self.screenH-self.H; });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } }
    else { self.lastFrame=0; self.loop(); }
  });
  this.loop();
};

// Grab-to-drag + click forwarding (mirrors the crab). pointer-events:auto so it can
// be grabbed, but a plain click is re-dispatched to the UI underneath — never stolen.
Ghost.prototype._wire = function(){
  var self=this;
  this._on(document, 'mousemove', function(e){ self._mx=e.clientX; self._my=e.clientY; });   // for the 'stare' event
  this._on(this.el, 'mousedown', function(e){ if(self._dead) return; self._didDrag=false; self._pressX=e.clientX; self._pressY=e.clientY; });
  this._on(this.el, 'mousemove', function(e){ if(self._dead||self.dragging) return; if(e.buttons===1 && e.button===0) self._beginDrag(); });
  this._on(document, 'mousemove', function(e){
    if(!self.dragging || self._dead || !self.el) return;
    if(self._pressX==null || Math.abs(e.clientX-self._pressX)>3 || Math.abs(e.clientY-self._pressY)>3) self._didDrag=true;
    self.x = e.clientX - self.W/2; self.y = e.clientY - self.H/2; self.clamp();
    self.el.style.left = self.x+'px'; self.el.style.top = self.y+'px';
  });
  var endDrag = function(){ if(self.dragging) self._endDrag(); };
  this._on(this.el, 'mouseup', endDrag);
  this._on(document, 'mouseup', endDrag);
  this._on(this.el, 'click', function(e){
    if(self._dead) return;
    if(self._didDrag){ self._didDrag=false; return; }
    self.poke();
    e.stopPropagation();
    // Resolve the real UI underneath via elementsFromPoint, skipping ANY pet node
    // in the stack, then re-dispatch with full pointer fidelity.
    var under=topUnderPets(e.clientX,e.clientY);
    if(under){
      under.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,view:window,
        clientX:e.clientX,clientY:e.clientY,button:e.button,detail:e.detail,
        ctrlKey:e.ctrlKey,shiftKey:e.shiftKey,altKey:e.altKey,metaKey:e.metaKey}));
    }
  });
  this._on(this.el, 'contextmenu', function(e){ e.preventDefault(); return false; });
  this._on(this.el, 'dragstart', function(e){ e.preventDefault(); return false; });
};
Ghost.prototype._beginDrag = function(){
  this.dragging = true; this.state = 'held';
  this.el.className = 'cryptirc-ghost held';
};
Ghost.prototype._endDrag = function(){
  this.dragging = false;
  this.tx = this.x; this.ty = this.y;
  this.setState('drift');
};
// clicked → an uneasy reaction (no text)
Ghost.prototype.poke = function(){
  if(this._dead || this.dragging) return;
  this.setState(Math.random()<0.5 ? 'flicker' : 'wail');
  this.ring();
};

Ghost.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Ghost.prototype.frame = function(ts){
  if(this._dead) return;
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;

  this.bob += 0.016*k;                              // very slow, dreamy hover

  if(!this.dragging){
    this.t++;
    if(this.t >= this.next){ this.pickState(); }

    if(this.state==='drift' || this.state==='peek' || this.state==='stare' || this.state==='wallcrawl' || this.state==='possess'){
      var sp = (this.state==='peek' ? 0.007 : this.state==='wallcrawl' ? 0.02 : this.state==='possess' ? 0.06 : this.state==='stare' ? 0.013 : 0.009) * k;
      this.x += (this.tx - this.x) * sp;
      this.y += (this.ty - this.y) * sp;
      if(this.state==='stare'){ this._stareTarget(); }   // keep tracking the cursor
      if(this.state==='possess'){ this._possessTarget(); }   // shadow the pointer
      if(this.state==='drift'){
        var dx = this.tx - this.x, dy = this.ty - this.y;
        if(dx*dx + dy*dy < 25){ this._pickTarget(); }
      }
    } else if(this.state==='sink'){
      // ooze halfway into the bottom of the window, then rise back
      var floor = this.screenH - this.H*0.4;
      this.y += (floor - this.y) * 0.04 * k;
    }
    this.clamp();
    var floatY = Math.sin(this.bob) * 3.5;
    this.el.style.left = this.x + 'px';
    this.el.style.top  = (this.y + floatY) + 'px';
  }

  // leaves a faint cold mist behind as it moves
  if(this._mistGate > 0){ this._mistGate -= k; }
  else { this._mistGate = 70 + (Math.random()*110|0); if(this.state!=='fade') this.mist(); }

  this._friendTick(k);
  this.loop();
};

Ghost.prototype.setState = function(st){
  this.state = st;
  this.el.className = 'cryptirc-ghost';   // clear all state classes
  this.t = 0;
  switch(st){
    case 'drift':    this._pickTarget(); this.next = 220 + (Math.random()*260|0); break;
    case 'fade':     this.el.classList.add('fade');    this.next = 100 + (Math.random()*90|0); break;
    case 'flicker':  this.el.classList.add('flicker'); this.next = 70 + (Math.random()*60|0); break;
    case 'spin':     this.el.classList.add('spin');    this.next = 190; break;
    case 'stretch':  this.el.classList.add('stretch'); this.next = 90; break;
    case 'wail':     this.el.classList.add('wail');    this.next = 70; this.ring(); break;
    case 'sink':     this.next = 150 + (Math.random()*120|0); break;
    case 'peek':     this._pickCorner(); this.next = 240 + (Math.random()*260|0); break;
    case 'teleport': this.el.classList.add('fade');    this.next = 26; this._after(280, this._doTeleport.bind(this)); break;
    case 'lunge':    this.el.classList.add('lunge','rage'); this.next = 60; this.ring(); break;
    // ── new spooky events ──
    case 'stare':    this.el.classList.add('staring'); this._stareTarget(); this.next = 110 + (Math.random()*70|0); break;
    case 'eyes':     this.el.classList.add('fade');    this.next = 36; this._eyesThenAppear(); break;
    case 'split':    this.next = 80; this.split(); break;
    case 'melt':     this.el.classList.add('melt');    this.next = 130; break;
    case 'drip':     this.next = 86; this.drip(); break;
    case 'cobweb':   this.next = 150; this.cobweb(); break;
    case 'vanish':   this.el.classList.add('vanish');  this.next = 150 + (Math.random()*120|0); this._after(2200, this._vanishBack.bind(this)); break;
    case 'wallcrawl':this._wallTarget();               this.next = 200 + (Math.random()*160|0); break;
    // ── new spooky events ──
    case 'wisps':    this.next = 96;  this.wisps(); break;
    case 'bat':      this.next = 90;  this.bat(); break;
    case 'frost':    this.next = 110; this.frost(); break;
    case 'puddle':   this.el.classList.add('puddle'); this.next = 150; this.puddle(); break;
    case 'mirror':   this.next = 150; this.mirror(); break;
    case 'pumpkin':  this.next = 130; this.pumpkin(); break;
    case 'candle':   this.next = 130; this.candle(); break;
    case 'chains':   this.el.classList.add('chains');  this.next = 120; this.chains(); break;
    case 'grave':    this.next = 170; this.grave(); break;
    case 'rune':     this.next = 120; this.rune(); break;
    case 'possess':  this.el.classList.add('possess'); this._possessTarget(); this.next = 150 + (Math.random()*90|0); break;
  }
};

// keep hovering just above the cursor while staring at it
Ghost.prototype._stareTarget = function(){
  var mx = (this._mx!=null?this._mx:this.screenW/2), my = (this._my!=null?this._my:this.screenH/2);
  this.tx = Math.max(0, Math.min(mx - this.W/2,    this.screenW - this.W));
  this.ty = Math.max(0, Math.min(my - this.H - 12, this.screenH - this.H));
};
// glide to a window edge and slide along it
Ghost.prototype._wallTarget = function(){
  var pad = 4;
  this.tx = (this.x < this.screenW/2) ? pad : (this.screenW - this.W - pad);
  this.ty = (this.y < this.screenH/2) ? (this.screenH - this.H - pad) : pad;
};
Ghost.prototype._vanishBack = function(){
  if(this._dead) return;
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,(this.screenH-this.H));
  this.tx = this.x; this.ty = this.y;
  this.el.style.left = this.x+'px'; this.el.style.top = this.y+'px';
  this.setState('flicker');
};
// two glowing eyes blink in a corner, then it materializes there
Ghost.prototype._eyesThenAppear = function(){
  if(this._dead || document.hidden) return;
  var self=this, pad=14;
  var ex = Math.max(0, (Math.random()<0.5?pad:(this.screenW-this.W-pad)));
  var ey = Math.max(0, (Math.random()<0.5?pad:(this.screenH-this.H-pad)));
  var e=document.createElement('div'); e.className='gh-eyes'; e.setAttribute('data-pet','ghost'); e.textContent='👁 👁';
  e.style.left=(ex+this.W*0.16)+'px'; e.style.top=(ey+this.H*0.34)+'px';
  document.body.appendChild(e);
  this._after(1150, function(){ if(e.parentNode) e.parentNode.removeChild(e); });
  this._after(560, function(){
    self.x=ex; self.y=ey; self.tx=ex; self.ty=ey;
    self.el.style.left=ex+'px'; self.el.style.top=ey+'px';
    self.setState('flicker');
  });
};
// a faint after-image splits off and merges back
Ghost.prototype.split = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  var c=document.createElement('div'); c.className='gh-clone'; c.setAttribute('data-pet','ghost');
  c.style.width=this.W+'px'; c.style.height=this.H+'px';
  c.style.left=this.x+'px'; c.style.top=this.y+'px';
  c.innerHTML=this.el.innerHTML;
  document.body.appendChild(c);
  var off=40+(Math.random()*44|0);
  this._after(40,  function(){ c.style.left=(self.x - off)+'px'; c.style.opacity='.28'; });
  this._after(520, function(){ c.style.left=self.x+'px'; c.style.top=self.y+'px'; c.style.opacity='0'; });
  this._after(950, function(){ if(c.parentNode) c.parentNode.removeChild(c); });
};
// a slow red drip falls from it
Ghost.prototype.drip = function(){
  if(this._dead || document.hidden) return;
  var d=document.createElement('div'); d.className='gh-drip'; d.setAttribute('data-pet','ghost'); d.textContent='🩸';
  d.style.left=(this.x + this.W*0.4 + Math.random()*this.W*0.2)+'px';
  d.style.top =(this.y + this.H*0.5)+'px';
  document.body.appendChild(d);
  this._after(1600, function(){ if(d.parentNode) d.parentNode.removeChild(d); });
};
// a spider descends on a thread beside it
Ghost.prototype.cobweb = function(){
  if(this._dead || document.hidden) return;
  var w=document.createElement('div'); w.className='gh-web'; w.setAttribute('data-pet','ghost'); w.textContent='🕷️';
  w.style.left=(this.x + this.W + 2)+'px'; w.style.top=(this.y + 8)+'px';
  document.body.appendChild(w);
  this._after(2400, function(){ if(w.parentNode) w.parentNode.removeChild(w); });
};

// ── NEW spooky behaviors ──────────────────────────────────────────────────────
// a few will-o'-wisps orbit the ghost, then snuff out
Ghost.prototype.wisps = function(){
  if(this._dead || document.hidden) return;
  var self=this, n=3+(Math.random()*2|0), cx=this.x+this.W/2, cy=this.y+this.H/2;
  for(var i=0;i<n;i++){
    var w=document.createElement('div'); w.className='gh-wisp'; w.setAttribute('data-pet','ghost');
    var ang=Math.random()*Math.PI*2, rad=18+(Math.random()*22|0);
    w.style.left=(cx + Math.cos(ang)*rad - 4.5)+'px';
    w.style.top =(cy + Math.sin(ang)*rad - 4.5)+'px';
    w.style.animationDuration=(1.6 + Math.random()*1.4)+'s';
    document.body.appendChild(w);
    (function(node){ self._after(3200, function(){ if(node.parentNode) node.parentNode.removeChild(node); }); })(w);
  }
};
// a bat detaches and flutters away
Ghost.prototype.bat = function(){
  if(this._dead || document.hidden) return;
  var b=document.createElement('div'); b.className='gh-bat'; b.setAttribute('data-pet','ghost'); b.textContent='🦇';
  b.style.left=(this.x + this.W*0.3 + Math.random()*this.W*0.4)+'px';
  b.style.top =(this.y + this.H*0.2)+'px';
  document.body.appendChild(b);
  this._after(2500, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
};
// exhales a creeping cloud of frost-breath
Ghost.prototype.frost = function(){
  if(this._dead || document.hidden) return;
  var f=document.createElement('div'); f.className='gh-frost'; f.setAttribute('data-pet','ghost');
  var sz=34+(Math.random()*26|0);
  f.style.width=sz+'px'; f.style.height=sz+'px';
  f.style.left=(this.x + this.W*0.5 - sz/2)+'px';
  f.style.top =(this.y + this.H*0.55 - sz/2)+'px';
  document.body.appendChild(f);
  this._after(2300, function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};
// a dark shadow-puddle pools beneath as it oozes into the floor
Ghost.prototype.puddle = function(){
  if(this._dead || document.hidden) return;
  var p=document.createElement('div'); p.className='gh-puddle'; p.setAttribute('data-pet','ghost');
  var pw=this.W*1.6;
  p.style.width=pw+'px'; p.style.height=(this.H*0.3)+'px';
  p.style.left=(this.x + this.W/2 - pw/2)+'px';
  p.style.top =(this.y + this.H - 8)+'px';
  document.body.appendChild(p);
  this._after(2600, function(){ if(p.parentNode) p.parentNode.removeChild(p); });
};
// a horizontally-flipped doppelganger fades in beside it, mimics, then fades
Ghost.prototype.mirror = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  var m=document.createElement('div'); m.className='gh-mirror'; m.setAttribute('data-pet','ghost');
  m.style.width=this.W+'px'; m.style.height=this.H+'px';
  var side=(this.x < this.screenW/2) ? 1 : -1;
  var mx=Math.max(0, Math.min(this.x + side*(this.W*1.1), this.screenW - this.W));
  m.style.left=mx+'px'; m.style.top=this.y+'px';
  m.innerHTML=this.el.innerHTML;
  document.body.appendChild(m);
  this._mirror=m;
  this._after(30,   function(){ if(self._mirror===m) m.classList.add('in'); });
  this._after(1600, function(){ if(self._mirror===m) m.classList.remove('in'); });
  this._after(2300, function(){ if(self._mirror===m) self._mirror=null; if(m.parentNode) m.parentNode.removeChild(m); });
};
// a grinning jack-o'-lantern bobs up beside it
Ghost.prototype.pumpkin = function(){
  if(this._dead || document.hidden) return;
  var p=document.createElement('div'); p.className='gh-pumpkin'; p.setAttribute('data-pet','ghost'); p.textContent='🎃';
  p.style.left=(this.x + this.W + 2)+'px';
  p.style.top =(this.y + this.H*0.4)+'px';
  document.body.appendChild(p);
  this._after(3300, function(){ if(p.parentNode) p.parentNode.removeChild(p); });
};
// it lights a guttering candle beside itself
Ghost.prototype.candle = function(){
  if(this._dead || document.hidden) return;
  var c=document.createElement('div'); c.className='gh-candle'; c.setAttribute('data-pet','ghost'); c.textContent='🕯️';
  c.style.left=(this.x - 14)+'px';
  c.style.top =(this.y + this.H*0.5)+'px';
  document.body.appendChild(c);
  this._after(2900, function(){ if(c.parentNode) c.parentNode.removeChild(c); });
};
// spectral chains rattle around it
Ghost.prototype.chains = function(){
  if(this._dead || document.hidden) return;
  var c=document.createElement('div'); c.className='gh-chain'; c.setAttribute('data-pet','ghost'); c.textContent='⛓️';
  c.style.left=(this.x + this.W*0.3)+'px';
  c.style.top =(this.y - 6)+'px';
  document.body.appendChild(c);
  this._after(2000, function(){ if(c.parentNode) c.parentNode.removeChild(c); });
};
// a gravestone heaves up out of the floor below it, then sinks back
Ghost.prototype.grave = function(){
  if(this._dead || document.hidden) return;
  var g=document.createElement('div'); g.className='gh-grave'; g.setAttribute('data-pet','ghost'); g.textContent='🪦';
  g.style.left=(this.x + this.W*0.3)+'px';
  g.style.top =(this.y + this.H - 10)+'px';
  document.body.appendChild(g);
  this._after(3700, function(){ if(g.parentNode) g.parentNode.removeChild(g); });
};
// an eerie rune flares into being then fades
Ghost.prototype.rune = function(){
  if(this._dead || document.hidden) return;
  var glyphs=['ᚦ','ᚱ','ᛟ','ᛉ','ᛏ','ᚷ','ᛞ','ᚹ'];
  var u=document.createElement('div'); u.className='gh-rune'; u.setAttribute('data-pet','ghost');
  u.textContent=glyphs[(Math.random()*glyphs.length)|0];
  u.style.left=(this.x + this.W*0.5 - 9)+'px';
  u.style.top =(this.y - 18)+'px';
  document.body.appendChild(u);
  this._after(2700, function(){ if(u.parentNode) u.parentNode.removeChild(u); });
};
// possess the cursor: shrink and shadow the pointer for a beat (movement in frame())
Ghost.prototype._possessTarget = function(){
  var mx=(this._mx!=null?this._mx:this.screenW/2), my=(this._my!=null?this._my:this.screenH/2);
  this.tx=Math.max(0, Math.min(mx - this.W/2, this.screenW - this.W));
  this.ty=Math.max(0, Math.min(my - this.H/2, this.screenH - this.H));
};

// blink out, reappear somewhere else with a flicker
Ghost.prototype._doTeleport = function(){
  if(this._dead) return;
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,(this.screenH-this.H));
  this.tx = this.x; this.ty = this.y;
  this.el.style.left = this.x+'px'; this.el.style.top = this.y+'px';
  this.setState('flicker');
};

// Weighted toward calm drifting; the scary stuff is occasional, the lunge is RARE.
Ghost.prototype.pickState = function(){
  if(this.dragging) return;
  var r = Math.random();
  if(r < 0.28)        this.setState('drift');        // calm drifting stays dominant
  else if(r < 0.355)  this.setState('fade');
  else if(r < 0.405)  this.setState('flicker');
  else if(r < 0.450)  this.setState('peek');
  else if(r < 0.495)  this.setState('teleport');
  else if(r < 0.535)  this.setState('stretch');
  else if(r < 0.575)  this.setState('sink');
  else if(r < 0.620)  this.setState('stare');        // locks onto your cursor
  else if(r < 0.655)  this.setState('eyes');         // eyes in the dark, then appears
  else if(r < 0.685)  this.setState('split');        // after-image
  else if(r < 0.715)  this.setState('melt');         // drips & re-forms
  else if(r < 0.740)  this.setState('drip');         // blood drip
  else if(r < 0.765)  this.setState('cobweb');       // spider on a thread
  else if(r < 0.790)  this.setState('wallcrawl');    // slides along an edge
  else if(r < 0.810)  this.setState('vanish');       // gone for a moment
  // ── new spooky events (small probability each) ──
  else if(r < 0.836)  this.setState('wisps');        // orbiting will-o'-wisps
  else if(r < 0.860)  this.setState('frost');        // frost-breath fog
  else if(r < 0.884)  this.setState('puddle');       // shadow-puddle in the floor
  else if(r < 0.904)  this.setState('mirror');       // mimicking doppelganger
  else if(r < 0.922)  this.setState('rune');         // glowing eerie rune
  else if(r < 0.938)  this.setState('candle');       // flickering candle
  else if(r < 0.954)  this.setState('chains');       // rattling spectral chains
  else if(r < 0.966)  this.setState('bat');          // a bat flutters off
  else if(r < 0.976)  this.setState('pumpkin');      // floating jack-o'-lantern
  else if(r < 0.984)  this.setState('grave');        // gravestone rises & sinks
  else if(r < 0.990)  this.setState('possess');      // shrinks & shadows the cursor
  else                this.setState('lunge');        // ~1% — rare jump-scare
};

// ── the shadow companion ───────────────────────────────────────────────────────
Ghost.prototype._spawnFriend = function(){
  if(this._dead || this._friend) return;
  var f = document.createElement('div');
  f.className = 'gh-friend'; f.setAttribute('data-pet','ghost');
  var fw = Math.round(this.W*0.74), fh = Math.round(this.H*0.74);
  f.style.width = fw+'px'; f.style.height = fh+'px';
  f.innerHTML = ghostSVG(TINT_FRIEND);
  this._friendW = fw; this._friendH = fh;
  this._friendSide = Math.random()<0.5 ? -1 : 1;
  this._friendBob = Math.random()*Math.PI*2;
  this._friendT = 1000 + (Math.random()*1100|0);
  document.body.appendChild(f);
  this._friend = f;
  var self=this; this._after(30, function(){ if(self._friend===f) f.classList.add('in'); });
};
Ghost.prototype._despawnFriend = function(){
  var f = this._friend; this._friend = null; this._friendT = 0;
  if(!f) return;
  f.classList.remove('in');
  this._after(1150, function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};
Ghost.prototype._friendTick = function(k){
  if(!this._friend){
    if(this._friendGate > 0) this._friendGate -= k;
    else { this._spawnFriend(); this._friendGate = 3000 + (Math.random()*4200|0); }
    return;
  }
  this._friendBob += 0.02*k;
  var fx = this.x + this._friendSide*(this.W*0.95) + Math.sin(this._friendBob)*6;
  var fy = this.y + 8 + Math.cos(this._friendBob*1.2)*10;
  fx = Math.max(0, Math.min(fx, this.screenW - this._friendW));
  fy = Math.max(0, Math.min(fy, this.screenH - this._friendH));
  this._friend.style.left = fx+'px';
  this._friend.style.top  = fy+'px';
  this._friendT -= k;
  if(this._friendT <= 0){ this._despawnFriend(); }
};

// ── cold fx (visual only — no text) ───────────────────────────────────────────
Ghost.prototype.mist = function(){
  if(this._dead || document.hidden) return;
  var m = document.createElement('div'); m.className='gh-mist'; m.setAttribute('data-pet','ghost');
  var sz = 7 + (Math.random()*9|0);
  m.style.width=sz+'px'; m.style.height=sz+'px';
  m.style.left = (this.x + 14 + Math.random()*30) + 'px';
  m.style.top  = (this.y + this.H - 16 + Math.random()*10) + 'px';
  m.style.animationDuration = (1.6 + Math.random()*1.1) + 's';
  document.body.appendChild(m);
  this._after(2800, function(){ if(m.parentNode) m.parentNode.removeChild(m); });
};
Ghost.prototype.ring = function(){
  if(this._dead || document.hidden) return;
  var r = document.createElement('div'); r.className='gh-ring'; r.setAttribute('data-pet','ghost');
  var sz = 40;
  r.style.width=sz+'px'; r.style.height=sz+'px';
  r.style.left = (this.x + this.W/2 - sz/2) + 'px';
  r.style.top  = (this.y + this.H/2 - sz/2) + 'px';
  document.body.appendChild(r);
  this._after(900, function(){ if(r.parentNode) r.parentNode.removeChild(r); });
};

Ghost.prototype.destroy = function(){
  this._dead = true;
  if(this._raf) cancelAnimationFrame(this._raf);
  for(var i=0;i<this._timers.length;i++){ clearTimeout(this._timers[i]); }
  this._timers.length = 0;
  for(var j=0;j<this._listeners.length;j++){ var L=this._listeners[j]; try{ L.t.removeEventListener(L.e,L.fn,L.opts); }catch(_){ } }
  this._listeners.length = 0;
  if(this.el && this.el.parentNode) this.el.parentNode.removeChild(this.el);
  this._friend = null; this._mirror = null;
  // sweep by the shared marker attribute (catches any future gh-* node even if it
  // isn't in the hand-maintained class list) plus the classes.
  var stray = document.querySelectorAll('[data-pet="ghost"], .gh-mist, .gh-ring, .gh-friend, .gh-clone, .gh-drip, .gh-eyes, .gh-web, .gh-wisp, .gh-bat, .gh-frost, .gh-puddle, .gh-mirror, .gh-pumpkin, .gh-candle, .gh-chain, .gh-grave, .gh-rune');
  for(var k=0;k<stray.length;k++){ if(stray[k].parentNode) stray[k].parentNode.removeChild(stray[k]); }
};

// ── public manager ───────────────────────────────────────────────────────────
window.CryptIRCGhost = {
  enable: function(){
    if(_enabled) return;
    _enabled = true;
    try{ _ghost = new Ghost(); _ghost.start(); }
    catch(e){ _enabled=false; try{ console.warn('[ghost] start failed', e); }catch(_){ } }
  },
  disable: function(){
    _enabled = false;
    if(_ghost){ try{ _ghost.destroy(); }catch(_){ } _ghost = null; }
  },
  isOn: function(){ return _enabled; }
};

})();
