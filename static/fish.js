/*!
 * CryptIRC Desktop Pet — Calm Fish 🐟
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) little fish that swims
 * slowly and gracefully around the whole client window. Click on (or right
 * next to) the fish to FEED it: a food flake drops into the water and the
 * fish calmly glides over to nibble it, blowing a couple of bubbles. SILENT:
 * no text, no audio. Drawn procedurally as an inline SVG (flowing fins) and
 * animated with CSS (fin waves) + a requestAnimationFrame swim loop.
 *
 * Design notes (do NOT regress these):
 *   1. NO eval / NO network — everything is inline; nothing is fetched.
 *   2. NEVER in the way — the fish layer is pointer-events:none, so it can
 *      NEVER steal a click, block a button, or change the cursor. Feeding is
 *      detected by a passive document 'click' listener that only reacts when
 *      the click lands near the fish; it never calls preventDefault, so the
 *      underlying UI keeps working exactly as before.
 *   3. Clean teardown — every timer, listener, rAF and spawned DOM node is
 *      tracked so disable() fully removes the pet with no leaks.
 *   4. Calm — slow easing, long gentle pauses, soft bobbing, smooth turns.
 *   5. Light — one fish, a few capped food flakes and bubbles, and the rAF
 *      loop pauses entirely while the tab is hidden.
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like ghost.js/crab.js):
 *   window.CryptIRCFish.enable()   spawn (idempotent)
 *   .disable()  remove the fish + all food/bubbles/timers/listeners
 *   .isOn()     -> boolean
 * Off by default.
 */
(function(){
'use strict';

var Z = 87;                      // paints under the ghost(88)/crab(89)/sheep(90); below every panel/menu/modal (>=100)
var FOOD_CAP = 8;                // most flakes alive at once (ignore extra feed clicks)
var _enabled = false;
var _fish = null;

// ── styles (injected once) ────────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-fish-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    // The fish layer never intercepts pointer events (feeding is via a document listener).
    '.cryptirc-fish{position:fixed;z-index:'+Z+';width:64px;height:40px;pointer-events:none;',
      'will-change:left,top,transform;transform-origin:center center;',
      'transition:transform .55s ease;filter:drop-shadow(0 3px 5px rgba(0,40,70,.30))}',
    '.cryptirc-fish svg{display:block;width:100%;height:100%;overflow:visible}',
    // gentle, perpetual fin/tail waving
    '.cryptirc-fish .fishtail{animation:fishTail 2.3s ease-in-out infinite;transform-origin:24px 24px}',
    '.cryptirc-fish .fishdorsal{animation:fishFin 2.9s ease-in-out infinite;transform-origin:40px 16px}',
    '.cryptirc-fish .fishpec{animation:fishFin 2.6s ease-in-out infinite;transform-origin:46px 30px}',
    '@keyframes fishTail{0%,100%{transform:rotate(-7deg)}50%{transform:rotate(7deg)}}',
    '@keyframes fishFin{0%,100%{transform:rotate(-3.5deg)}50%{transform:rotate(3.5deg)}}',
    // a brief livelier flick right after eating
    '.cryptirc-fish.happy .fishtail{animation-duration:.9s}',
    // food flake — a soft warm crumb that slowly sinks and sways
    '.fishfood{position:fixed;z-index:'+Z+';width:7px;height:7px;border-radius:50% 50% 50% 50%/60% 60% 40% 40%;',
      'pointer-events:none;background:radial-gradient(circle at 38% 32%,#ffe3a6,#d98b34);',
      'box-shadow:0 0 3px rgba(180,110,40,.5);transition:opacity .4s ease}',
    '.fishfood.gone{opacity:0}',
    // rising bubble
    '.fishbub{position:fixed;z-index:'+Z+';border-radius:50%;pointer-events:none;',
      'background:radial-gradient(circle at 35% 30%,rgba(255,255,255,.85),rgba(170,215,235,.18));',
      'border:1px solid rgba(200,235,250,.5);animation:fishBub linear forwards}',
    '@keyframes fishBub{0%{opacity:.55;transform:translateY(0) scale(.55)}100%{opacity:0;transform:translateY(-30px) scale(1.15)}}',
    // ── calm flourish effects (all pointer-events:none, all slow & gentle) ──
    // slow expanding bubble-ring
    '.fishring{position:fixed;z-index:'+Z+';border-radius:50%;pointer-events:none;',
      'border:1.5px solid rgba(205,238,252,.6);box-shadow:0 0 5px rgba(200,235,250,.3);',
      'animation:fishRing 3.4s ease-out forwards}',
    '@keyframes fishRing{0%{opacity:.6;transform:scale(.25)}100%{opacity:0;transform:scale(1.7)}}',
    // soft surface ripple ring
    '.fishripple{position:fixed;z-index:'+Z+';border-radius:50%;pointer-events:none;',
      'border:1.5px solid rgba(210,240,255,.55);animation:fishRipple 3.2s ease-out forwards}',
    '@keyframes fishRipple{0%{opacity:.5;transform:scaleX(.4) scaleY(.18)}100%{opacity:0;transform:scaleX(2.2) scaleY(.9)}}',
    // drifting sparkle (shimmer/trail)
    '.fishspark{position:fixed;z-index:'+Z+';width:5px;height:5px;border-radius:50%;pointer-events:none;',
      'background:radial-gradient(circle at 40% 35%,rgba(255,255,255,.95),rgba(255,240,200,.15));',
      'box-shadow:0 0 5px rgba(255,245,210,.8);animation:fishSpark 2.6s ease-in-out forwards}',
    '@keyframes fishSpark{0%{opacity:0;transform:scale(.3)}25%{opacity:.9;transform:scale(1)}100%{opacity:0;transform:scale(.4) translateY(-10px)}}',
    // tiny silhouette friend drifting past
    '.fishfriend{position:fixed;z-index:'+Z+';width:18px;height:11px;pointer-events:none;opacity:.22;',
      'background:#5a7a8c;clip-path:polygon(0 50%,32% 0,100% 22%,100% 78%,32% 100%);',
      'will-change:left,top;transition:opacity 1s ease}',
    '.fishfriend.gone{opacity:0}',
    // drifting plankton speck
    '.fishplank{position:fixed;z-index:'+Z+';width:4px;height:4px;border-radius:50%;pointer-events:none;',
      'background:radial-gradient(circle at 40% 35%,rgba(210,255,225,.95),rgba(120,200,150,.2));',
      'box-shadow:0 0 4px rgba(180,255,200,.6);transition:opacity .5s ease}',
    '.fishplank.gone{opacity:0}',
    // soft scale-shimmer glow over the fish body
    '.cryptirc-fish.shimmer{filter:drop-shadow(0 3px 5px rgba(0,40,70,.30)) drop-shadow(0 0 6px rgba(255,245,210,.7));',
      'animation:fishShimmer 2.8s ease-in-out}',
    '@keyframes fishShimmer{0%,100%{filter:drop-shadow(0 3px 5px rgba(0,40,70,.30))}',
      '50%{filter:drop-shadow(0 3px 5px rgba(0,40,70,.30)) drop-shadow(0 0 8px rgba(255,248,215,.85))}}',
    // slow gill-flare "yawn" — gentle, slow fin breathing (no transform; keeps facing)
    '.cryptirc-fish.yawn .fishtail,.cryptirc-fish.yawn .fishdorsal,.cryptirc-fish.yawn .fishpec{animation-duration:3.6s}',
    '.cryptirc-fish.yawn{filter:drop-shadow(0 3px 5px rgba(0,40,70,.30)) drop-shadow(0 0 4px rgba(255,235,190,.5))}',
    // slow happy wiggle — just a livelier (but still gentle) tail sway
    '.cryptirc-fish.wiggle .fishtail{animation-duration:1.1s}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-fish *,.cryptirc-fish{animation:none!important}',
      '.fishring,.fishripple,.fishspark,.fishfriend,.fishplank{animation:none!important;opacity:0!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the fish SVG (drawn facing RIGHT; the container is scaleX(-1) to face left) ─
function fishSVG(){
  return '<svg viewBox="0 0 76 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'+
    '<defs>'+
      '<linearGradient id="fishBodyG" x1="0" y1="0" x2="0" y2="1">'+
        '<stop offset="0" stop-color="#ffc278"/><stop offset=".55" stop-color="#ff9d40"/><stop offset="1" stop-color="#f17f29"/>'+
      '</linearGradient>'+
      '<linearGradient id="fishBellyG" x1="0" y1="0" x2="0" y2="1">'+
        '<stop offset="0" stop-color="#fff3db" stop-opacity=".9"/><stop offset="1" stop-color="#ffdba6" stop-opacity=".15"/>'+
      '</linearGradient>'+
      '<linearGradient id="fishFinG" x1="1" y1="0" x2="0" y2="0">'+
        '<stop offset="0" stop-color="#ffb968" stop-opacity=".8"/><stop offset="1" stop-color="#ffd9a6" stop-opacity=".15"/>'+
      '</linearGradient>'+
    '</defs>'+
    // flowing tail fin (left), gently waving
    '<g class="fishtail">'+
      '<path d="M26 24 C14 16 8 8 4 6 C8 16 8 32 4 42 C8 40 14 32 26 24 Z" fill="url(#fishFinG)" stroke="#f08f37" stroke-width="1" stroke-opacity=".5"/>'+
    '</g>'+
    // dorsal fin (top), gently waving
    '<g class="fishdorsal">'+
      '<path d="M30 15 C38 4 50 5 54 14 C46 12 38 13 32 18 Z" fill="url(#fishFinG)" stroke="#f08f37" stroke-width="1" stroke-opacity=".4"/>'+
    '</g>'+
    // body
    '<ellipse cx="42" cy="24" rx="22" ry="12.5" fill="url(#fishBodyG)" stroke="#ec8632" stroke-width="1" stroke-opacity=".4"/>'+
    // soft belly highlight
    '<ellipse cx="44" cy="29.5" rx="17" ry="6.5" fill="url(#fishBellyG)"/>'+
    // a couple of calm scale hints
    '<path d="M34 17 C40 22 40 26 34 31" fill="none" stroke="#f6a253" stroke-width="1" stroke-opacity=".45"/>'+
    '<path d="M40 16 C46 22 46 26 40 32" fill="none" stroke="#f6a253" stroke-width="1" stroke-opacity=".35"/>'+
    // pectoral fin (lower side), gently waving
    '<g class="fishpec">'+
      '<path d="M48 28 C50 36 46 39 41 38 C44 33 44 30 46 27 Z" fill="url(#fishFinG)" stroke="#f08f37" stroke-width="1" stroke-opacity=".4"/>'+
    '</g>'+
    // gill line
    '<path d="M52 16 C49 20 49 28 52 32" fill="none" stroke="#e07f2c" stroke-width="1.2" stroke-opacity=".5"/>'+
    // eye + highlight
    '<circle cx="58" cy="20.5" r="3.1" fill="#21323d"/>'+
    '<circle cx="59.1" cy="19.4" r="1" fill="#ffffff" fill-opacity=".9"/>'+
    // small calm mouth
    '<path d="M63.5 24.5 C65 24 66 24.4 66.4 25.2" fill="none" stroke="#c96f24" stroke-width="1.2" stroke-linecap="round"/>'+
  '</svg>';
}

// ── fish instance ──────────────────────────────────────────────────────────────
function Fish(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-fish';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = fishSVG();
  this.W = 64; this.H = 40;
  this.HIT = Math.max(this.W, this.H)/2 + 24;   // generous feed click radius
  this.EAT = 15;                                 // distance at which a flake is eaten
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this._food = [];                               // [{el,x,y,vy,sway,phase,life}]
  this._dir = 1;                                 // 1 = facing right, -1 = facing left
  this._floatY = 0;
  this._roll = 0;                                // current barrel-roll angle (deg), eased
  this._rollGoal = 0;                            // target roll angle
  this._fancyBusy = false;                       // a multi-step flourish is mid-flight
  this._fancyGate = 420 + (Math.random()*420|0); // frames until the next calm flourish chance
  this._planktons = [];                          // [{el,x,y,phase,life}] calm specks to follow
  this._bobGate = 180 + (Math.random()*240|0);   // frames until next ambient bubble
  this._bounds();
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = this._bandTop() + Math.random()*Math.max(1,(this._bandBot()-this._bandTop()));
  this.tx = this.x; this.ty = this.y;
  this.bob = Math.random()*Math.PI*2;
  this.restT = 60;                               // frames to hover after reaching a target
  this.lastFrame = 0;
}
Fish.prototype._bounds = function(){
  this.screenW = window.innerWidth  || document.documentElement.clientWidth  || 800;
  this.screenH = window.innerHeight || document.documentElement.clientHeight || 600;
};
// vertical swim band (keep a little off the very top/bottom). Derived from the
// available room so it can never exceed the clamp range — on a tiny viewport the
// margins shrink instead of pinning the fish to an edge.
Fish.prototype._room    = function(){ return Math.max(0, this.screenH - this.H); };
Fish.prototype._bandTop = function(){ var r=this._room(); return Math.min(12, Math.floor(r/2)); };
Fish.prototype._bandBot = function(){ var r=this._room(); return Math.max(this._bandTop(), r - Math.min(12, Math.floor(r/2))); };
Fish.prototype._on = function(target, ev, fn, opts){
  target.addEventListener(ev, fn, opts);
  this._listeners.push({t:target, e:ev, fn:fn, opts:opts});
};
Fish.prototype._after = function(ms, fn){
  var self=this, id=setTimeout(function(){ if(!self._dead) fn(); }, ms);
  this._timers.push(id); return id;
};
Fish.prototype.clamp = function(){
  this.x = Math.max(0, Math.min(this.x, this.screenW - this.W));
  this.y = Math.max(0, Math.min(this.y, this.screenH - this.H));
};
Fish.prototype._pickTarget = function(){
  var pad = 12;
  this.tx = pad + Math.random()*Math.max(1,(this.screenW - this.W - pad*2));
  this.ty = this._bandTop() + Math.random()*Math.max(1,(this._bandBot() - this._bandTop()));
};

Fish.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  this.el.style.left = this.x + 'px';
  this.el.style.top  = this.y + 'px';
  this._applyTransform();
  var self=this;
  // Feed when a click lands on/near the fish. Passive observer — never blocks the UI.
  this._on(document, 'click', function(e){
    if(self._dead) return;
    var cx = self.x + self.W/2, cy = self.y + self._floatY + self.H/2;
    var dx = e.clientX - cx, dy = e.clientY - cy;
    if(dx*dx + dy*dy <= self.HIT*self.HIT){ self.feed(e.clientX, e.clientY); }
  }, true);
  this._on(window, 'resize', function(){
    self._bounds(); self.clamp();
    if(self.tx > self.screenW - self.W) self.tx = self.screenW - self.W;
    if(self.ty > self._bandBot()) self.ty = self._bandBot();
  });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } }
    else { self.lastFrame=0; self.loop(); }
  });
  this.loop();
};

// drop a food flake at (clamped) screen coords; the fish will glide over to eat it
Fish.prototype.feed = function(px, py){
  if(this._dead || document.hidden || this._food.length >= FOOD_CAP) return;
  var f = document.createElement('div');
  f.className = 'fishfood'; f.setAttribute('data-pet','fish');
  var x = Math.max(2, Math.min(px - 3.5, this.screenW - 9));
  // Keep the flake within the fish's vertical reach so it can always be eaten
  // (the fish centre can descend to screenH - H/2; require the flake centre at/above it).
  var y = Math.max(2, Math.min(py - 3.5, this.screenH - this.H/2 - 4));
  f.style.left = x + 'px';
  f.style.top  = y + 'px';
  document.body.appendChild(f);
  this._food.push({ el:f, x:x+3.5, y:y+3.5, vy:0.22+Math.random()*0.12, sway:4+Math.random()*4, phase:Math.random()*Math.PI*2, life:0 });
};

Fish.prototype._removeFood = function(i, eaten){
  var fd = this._food[i];
  if(!fd) return;
  this._food.splice(i, 1);
  var el = fd.el;
  if(el){
    el.classList.add('gone');
    this._after(eaten ? 120 : 420, function(){ if(el.parentNode) el.parentNode.removeChild(el); });
  }
};

// nearest live flake to the fish centre, or -1
Fish.prototype._nearestFood = function(cx, cy){
  var best=-1, bd=Infinity;
  for(var i=0;i<this._food.length;i++){
    var dx=this._food[i].x-cx, dy=this._food[i].y-cy, d=dx*dx+dy*dy;
    if(d<bd){ bd=d; best=i; }
  }
  return best;
};

Fish.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Fish.prototype.frame = function(ts){
  if(this._dead) return;
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;

  this.bob += 0.03 * k;                                   // slow, gentle bob

  // ── advance & maybe eat food ─────────────────────────────────────────────
  for(var i=this._food.length-1; i>=0; i--){
    var fd = this._food[i];
    fd.life += k;
    fd.phase += 0.05 * k;
    fd.y += fd.vy * k;                                    // slow sink
    var fx = fd.x + Math.sin(fd.phase) * fd.sway * 0.15;  // tiny sway (visual)
    fd.el.style.top  = (fd.y - 3.5) + 'px';
    fd.el.style.left = (fx - 3.5) + 'px';
    // drifted off the bottom or sat uneaten too long → dissolve
    if(fd.y > this.screenH + 8 || fd.life > 780){ this._removeFood(i, false); }
  }

  // ── advance any drifting plankton specks (the fish calmly follows & eats) ──
  for(var pi=this._planktons.length-1; pi>=0; pi--){
    var pk = this._planktons[pi];
    pk.life += k;
    pk.phase += 0.02 * k;
    pk.x += Math.cos(pk.phase) * 0.18 * k;                // slow lateral drift
    pk.y += (Math.sin(pk.phase*0.7) * 0.12 + 0.02) * k;   // gentle rise/fall
    pk.x = Math.max(6, Math.min(pk.x, this.screenW-6));
    pk.y = Math.max(this._bandTop()+4, Math.min(pk.y, this._bandBot()+this.H/2));
    if(pk.el){ pk.el.style.left = (pk.x-2)+'px'; pk.el.style.top = (pk.y-2)+'px'; }
    if(pk.life > 900){ this._removePlankton(pi, false); }
  }

  var cx = this.x + this.W/2, cy = this.y + this.H/2;     // logical centre (no bob) for steering
  var goalX, goalY, speed;
  var fi = this._food.length ? this._nearestFood(cx, cy) : -1;

  if(fi >= 0){
    // ── feeding: glide to the nearest flake (a touch quicker, still calm) ──
    var target = this._food[fi];
    goalX = target.x - this.W/2; goalY = target.y - this.H/2;
    speed = 0.034 * k;
    var edx = target.x - cx, edy = target.y - cy;
    if(edx*edx + edy*edy <= this.EAT*this.EAT){
      this._removeFood(fi, true);
      this.bubble(this.x + (this._dir>0 ? this.W*0.78 : this.W*0.22), this.y + this.H*0.35);
      if(Math.random()<0.5) this.bubble(this.x + this.W*0.5, this.y + this.H*0.3);
      this._happy();
    }
  } else if(this._planktons.length){
    // ── calmly follow & nibble the nearest drifting plankton speck ──────────
    var pbest=-1, pbd=Infinity;
    for(var q=0;q<this._planktons.length;q++){ var qx=this._planktons[q].x-cx, qy=this._planktons[q].y-cy, qd=qx*qx+qy*qy; if(qd<pbd){pbd=qd;pbest=q;} }
    var pt = this._planktons[pbest];
    goalX = pt.x - this.W/2; goalY = pt.y - this.H/2; speed = 0.016 * k;
    var pdx = pt.x - cx, pdy = pt.y - cy;
    if(pdx*pdx + pdy*pdy <= this.EAT*this.EAT){
      this._removePlankton(pbest, true);
      if(Math.random()<0.5) this.bubble(this.x + (this._dir>0 ? this.W*0.78 : this.W*0.22), this.y + this.H*0.32);
    }
  } else {
    // ── calm wander: ease to a target, then hover a beat, then pick another ──
    var dx = this.tx - this.x, dy = this.ty - this.y;
    if(dx*dx + dy*dy < 16){
      this.restT -= k;
      if(this.restT <= 0){ this._pickTarget(); this.restT = 50 + (Math.random()*120|0); }
    }
    goalX = this.tx; goalY = this.ty; speed = 0.012 * k;
  }

  this.x += (goalX - this.x) * speed;
  this.y += (goalY - this.y) * speed;
  this.clamp();

  // ── facing: turn smoothly toward travel direction (deadzone avoids flutter) ─
  var aimX = goalX + this.W/2;
  if(aimX - cx > 10 && this._dir !== 1){ this._dir = 1; this._applyTransform(); }
  else if(aimX - cx < -10 && this._dir !== -1){ this._dir = -1; this._applyTransform(); }

  // ── ease the barrel-roll angle toward its goal, smoothly ─────────────────
  if(Math.abs(this._rollGoal - this._roll) > 0.1){
    this._roll += (this._rollGoal - this._roll) * 0.05 * k;
    this._applyTransform();
  } else if(this._roll !== this._rollGoal){
    this._roll = this._rollGoal; this._applyTransform();
  }

  // ── render (with a soft vertical bob) ────────────────────────────────────
  this._floatY = Math.sin(this.bob) * 2.6;
  this.el.style.left = this.x + 'px';
  this.el.style.top  = (this.y + this._floatY) + 'px';

  // ── occasional ambient bubble ────────────────────────────────────────────
  if(this._bobGate > 0){ this._bobGate -= k; }
  else { this._bobGate = 220 + (Math.random()*340|0); this.bubble(this.x + (this._dir>0 ? this.W*0.78 : this.W*0.22), this.y + this.H*0.32); }

  // ── occasional calm flourish (only while plain swimming — not feeding) ────
  if(this._fancyGate > 0){ this._fancyGate -= k; }
  else {
    this._fancyGate = 540 + (Math.random()*720|0);       // long, easy spacing between flourishes
    if(fi < 0 && !this._fancyBusy && this._planktons.length === 0){ this._pickFancy(); }
  }

  this.loop();
};

Fish.prototype._happy = function(){
  if(this._dead) return;
  this.el.classList.add('happy');
  var self=this;
  this._after(1100, function(){ if(self.el) self.el.classList.remove('happy'); });
};

// compose facing (scaleX by _dir) with the eased barrel-roll angle in one transform
Fish.prototype._applyTransform = function(){
  if(!this.el) return;
  this.el.style.transform = 'scaleX('+this._dir+') rotate('+(this._roll*this._dir).toFixed(2)+'deg)';
};

// remove a plankton speck (eaten = quick fade)
Fish.prototype._removePlankton = function(i, eaten){
  var pk = this._planktons[i];
  if(!pk) return;
  this._planktons.splice(i, 1);
  var el = pk.el;
  if(el){ el.classList.add('gone'); this._after(eaten ? 140 : 520, function(){ if(el.parentNode) el.parentNode.removeChild(el); }); }
};

// ── tiny effect spawners (all pointer-events:none; tracked removal) ──────────
Fish.prototype._spawnRing = function(cx, cy, sz){
  if(this._dead || document.hidden) return;
  var r = document.createElement('div'); r.className='fishring'; r.setAttribute('data-pet','fish');
  r.style.width=sz+'px'; r.style.height=sz+'px';
  r.style.left=Math.max(0,Math.min(cx-sz/2,this.screenW-sz))+'px';
  r.style.top =Math.max(0,Math.min(cy-sz/2,this.screenH-sz))+'px';
  document.body.appendChild(r);
  this._after(3500, function(){ if(r.parentNode) r.parentNode.removeChild(r); });
};
Fish.prototype._spawnSpark = function(cx, cy){
  if(this._dead || document.hidden) return;
  var s = document.createElement('div'); s.className='fishspark'; s.setAttribute('data-pet','fish');
  s.style.left=Math.max(0,Math.min(cx-2.5,this.screenW-5))+'px';
  s.style.top =Math.max(0,Math.min(cy-2.5,this.screenH-5))+'px';
  document.body.appendChild(s);
  this._after(2700, function(){ if(s.parentNode) s.parentNode.removeChild(s); });
};

// ── the 10 calm flourishes ───────────────────────────────────────────────────
// pick ONE calm flourish at random (kept rare via the long _fancyGate)
Fish.prototype._pickFancy = function(){
  if(this._dead || this._fancyBusy) return;
  var fns = [
    this._fancyBubbleRing, this._fancyBarrelRoll, this._fancySurfaceNibble,
    this._fancySinkAndSway, this._fancyFriendsPass, this._fancyFigureEight,
    this._fancyShimmer, this._fancyYawn, this._fancyPlankton, this._fancyHover
  ];
  fns[Math.random()*fns.length|0].call(this);
};

// 1) blow a slow, expanding bubble-ring out in front
Fish.prototype._fancyBubbleRing = function(){
  var self=this; this._fancyBusy=true;
  var mx = this.x + (this._dir>0 ? this.W*0.82 : this.W*0.18), my = this.y + this._floatY + this.H*0.4;
  this._spawnRing(mx, my, 14);
  this._after(700,  function(){ if(!self._dead) self._spawnRing(mx, my, 22); });
  this._after(1400, function(){ if(!self._dead) self._spawnRing(mx, my, 30); });
  this._after(2200, function(){ self._fancyBusy=false; });
};

// 2) a graceful, slow barrel-roll (eased rotate via _rollGoal, then back)
Fish.prototype._fancyBarrelRoll = function(){
  var self=this; this._fancyBusy=true;
  // Hold position during the roll so facing can't flip mid-spin (a flip would
  // invert the rotate() and visibly snap the fish). It just rolls gently in place.
  this.tx = this.x; this.ty = this.y; this.restT = 280;
  this._rollGoal = 360;
  this._after(4200, function(){ if(self._dead) return; self._roll = 0; self._rollGoal = 0; self._applyTransform(); self._fancyBusy=false; });
};

// 3) rise to nibble the surface, leaving a soft ripple ring at the top
Fish.prototype._fancySurfaceNibble = function(){
  var self=this; this._fancyBusy=true;
  this.ty = this._bandTop(); this.tx = this.x; this.restT = 240;   // glide up & linger
  this._after(2600, function(){
    if(self._dead){ self._fancyBusy=false; return; }
    var rp = document.createElement('div'); rp.className='fishripple'; rp.setAttribute('data-pet','fish');
    var w=34;
    rp.style.width=w+'px'; rp.style.height=(w*0.4)+'px';
    rp.style.left=Math.max(0,Math.min(self.x+self.W/2-w/2,self.screenW-w))+'px';
    rp.style.top =Math.max(0, self._bandTop()-2)+'px';
    document.body.appendChild(rp);
    self._after(3300, function(){ if(rp.parentNode) rp.parentNode.removeChild(rp); });
    if(Math.random()<0.6) self.bubble(self.x+self.W*0.5, self.y+self.H*0.25);
  });
  this._after(3600, function(){ self._fancyBusy=false; });
};

// 4) sink to rest near the bottom and gently sway there a while
Fish.prototype._fancySinkAndSway = function(){
  var self=this; this._fancyBusy=true;
  this.ty = this._bandBot(); this.tx = this.x; this.restT = 360;   // long, restful hover
  this.el.classList.add('wiggle');
  this._after(4800, function(){ if(self.el) self.el.classList.remove('wiggle'); self._fancyBusy=false; });
};

// 5) a few tiny silhouette fish friends drift slowly past in the background
Fish.prototype._fancyFriendsPass = function(){
  var self=this; this._fancyBusy=true;
  var dir = Math.random()<0.5 ? 1 : -1;
  var n = 2 + (Math.random()*2|0);
  var baseY = this._bandTop() + Math.random()*Math.max(1,(this._bandBot()-this._bandTop()));
  for(var i=0;i<n;i++){
    (function(idx){
      self._after(idx*600, function(){
        if(self._dead) return;
        var fr = document.createElement('div'); fr.className='fishfriend'; fr.setAttribute('data-pet','fish');
        var startX = dir>0 ? -24 : self.screenW+24;
        var fy = baseY + (idx*9) + (Math.random()*8-4);
        fr.style.left=startX+'px'; fr.style.top=fy+'px';
        fr.style.transform='scaleX('+dir+')';
        document.body.appendChild(fr);
        // ease it across over many seconds, then fade & remove
        var endX = dir>0 ? self.screenW+24 : -24;
        var px=startX;
        var step=function(){
          if(self._dead){ if(fr.parentNode) fr.parentNode.removeChild(fr); return; }
          px += (endX - px) * 0.012;
          fr.style.left = px + 'px';
          fr.style.top  = (fy + Math.sin(px*0.02)*3) + 'px';
          if(Math.abs(endX - px) > 30){ self._after(32, step); }
          else { fr.classList.add('gone'); self._after(1100, function(){ if(fr.parentNode) fr.parentNode.removeChild(fr); }); }
        };
        step();
      });
    })(i);
  }
  this._after(n*600 + 14000, function(){ self._fancyBusy=false; });
};

// 6) drift in a slow figure-eight by chaining four eased waypoints
Fish.prototype._fancyFigureEight = function(){
  var self=this; this._fancyBusy=true;
  var cx0 = Math.max(60, Math.min(this.x, this.screenW - this.W - 60));
  var cy0 = Math.max(this._bandTop()+10, Math.min(this.y, this._bandBot()-10));
  var rx = 46, ry = Math.min(26, (this._bandBot()-this._bandTop())/2);
  // lobes of a figure-eight (relative offsets), traversed as gentle waypoints
  var pts = [[rx,-ry],[0,0],[-rx,-ry],[0,0],[rx,ry],[0,0],[-rx,ry],[0,0]];
  var idx=0;
  var hop=function(){
    if(self._dead){ self._fancyBusy=false; return; }
    // yield immediately to feeding / plankton so the figure-eight never thrashes
    // the swim target or holds _fancyBusy while the fish should be eating
    if(self._food.length || (self._planktons && self._planktons.length)){ self._fancyBusy=false; return; }
    if(idx>=pts.length){ self._fancyBusy=false; return; }
    self.tx = Math.max(12, Math.min(cx0+pts[idx][0], self.screenW-self.W-12));
    self.ty = Math.max(self._bandTop(), Math.min(cy0+pts[idx][1], self._bandBot()));
    self.restT = 6;
    idx++;
    self._after(1300, hop);
  };
  hop();
};

// 7) scales shimmer/sparkle softly (a glow pass + a couple of sparkles)
Fish.prototype._fancyShimmer = function(){
  var self=this; this._fancyBusy=true;
  this.el.classList.add('shimmer');
  this._spawnSpark(this.x+this.W*0.55, this.y+this._floatY+this.H*0.4);
  this._after(700, function(){ if(!self._dead) self._spawnSpark(self.x+self.W*0.4, self.y+self._floatY+self.H*0.5); });
  this._after(2800, function(){ if(self.el) self.el.classList.remove('shimmer'); self._fancyBusy=false; });
};

// 8) a slow gill-flare "yawn" — gentle, slow breathing of the fins
Fish.prototype._fancyYawn = function(){
  var self=this; this._fancyBusy=true;
  this.el.classList.add('yawn');
  if(Math.random()<0.6) this.bubble(this.x + (this._dir>0 ? this.W*0.8 : this.W*0.2), this.y + this.H*0.4);
  this._after(2700, function(){ if(self.el) self.el.classList.remove('yawn'); self._fancyBusy=false; });
};

// 9) release a tiny drifting plankton speck it then calmly follows & eats
Fish.prototype._fancyPlankton = function(){
  var self=this; this._fancyBusy=true;
  var px = Math.max(20, Math.min(this.x + (this._dir>0 ? -40 : this.W+40), this.screenW-20));
  var py = Math.max(this._bandTop()+8, Math.min(this.y + this.H*0.4 + (Math.random()*30-15), this._bandBot()+this.H/2));
  var el = document.createElement('div'); el.className='fishplank'; el.setAttribute('data-pet','fish');
  el.style.left=(px-2)+'px'; el.style.top=(py-2)+'px';
  document.body.appendChild(el);
  this._planktons.push({ el:el, x:px, y:py, phase:Math.random()*Math.PI*2, life:0 });
  // the frame loop handles the calm follow/eat; just release the busy flag
  this._after(1400, function(){ self._fancyBusy=false; });
};

// 10) gentle pause-and-hover while the fins fan (a calm, still beat)
Fish.prototype._fancyHover = function(){
  var self=this; this._fancyBusy=true;
  this.tx = this.x; this.ty = this.y; this.restT = 300;            // hold position & fan fins
  this._after(3400, function(){ self._fancyBusy=false; });
};

Fish.prototype.bubble = function(bx, by){
  if(this._dead || document.hidden) return;
  var b = document.createElement('div');
  b.className = 'fishbub'; b.setAttribute('data-pet','fish');
  var sz = 4 + (Math.random()*4|0);
  b.style.width = sz+'px'; b.style.height = sz+'px';
  b.style.left = Math.max(0, Math.min(bx, this.screenW-sz)) + 'px';
  b.style.top  = Math.max(0, Math.min(by, this.screenH-sz)) + 'px';
  b.style.animationDuration = (1.4 + Math.random()*1.0) + 's';
  document.body.appendChild(b);
  this._after(2600, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
};

Fish.prototype.destroy = function(){
  this._dead = true;
  if(this._raf) cancelAnimationFrame(this._raf);
  for(var i=0;i<this._timers.length;i++){ clearTimeout(this._timers[i]); }
  this._timers.length = 0;
  for(var j=0;j<this._listeners.length;j++){ var L=this._listeners[j]; try{ L.t.removeEventListener(L.e,L.fn,L.opts); }catch(_){ } }
  this._listeners.length = 0;
  for(var n=0;n<this._food.length;n++){ var fe=this._food[n].el; if(fe && fe.parentNode) fe.parentNode.removeChild(fe); }
  this._food.length = 0;
  for(var p=0;p<this._planktons.length;p++){ var pe=this._planktons[p].el; if(pe && pe.parentNode) pe.parentNode.removeChild(pe); }
  this._planktons.length = 0;
  if(this.el && this.el.parentNode) this.el.parentNode.removeChild(this.el);
  this.el = null;
  // sweep by the shared marker attribute (catches any future fish-fx node even if
  // it isn't in the hand-maintained class list) plus the classes.
  var stray = document.querySelectorAll('[data-pet="fish"], .fishfood, .fishbub, .fishring, .fishripple, .fishspark, .fishfriend, .fishplank');
  for(var m=0;m<stray.length;m++){ if(stray[m].parentNode) stray[m].parentNode.removeChild(stray[m]); }
};

// ── public manager ─────────────────────────────────────────────────────────────
window.CryptIRCFish = {
  enable: function(){
    if(_enabled) return;
    _enabled = true;
    try{ _fish = new Fish(); _fish.start(); }
    catch(e){ _enabled=false; try{ console.warn('[fish] start failed', e); }catch(_){ } }
  },
  disable: function(){
    _enabled = false;
    if(_fish){ try{ _fish.destroy(); }catch(_){ } _fish = null; }
  },
  isOn: function(){ return _enabled; }
};

})();
