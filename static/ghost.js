/*!
 * CryptIRC Desktop Pet — Flying Ghost 👻
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) calm little bedsheet ghost
 * that FLIES FREELY around the whole client window — gently wandering toward
 * random targets with a slow hovering bob, occasionally fading "through walls",
 * spinning, wobbling, peeking into corners, trailing wisps, and (rarely) saying
 * BOO. Drawn procedurally as an articulated SVG (no sprite sheet) and animated
 * with CSS + a rAF position loop. Ethereal: pointer-events:none ALWAYS, so it
 * never blocks or steals clicks and is NOT draggable.
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like crab.js):
 *   window.CryptIRCGhost.enable()  spawn the ghost (idempotent)
 *   .disable()  remove it + stop all timers/listeners (no leaks)
 *   .isOn()     -> boolean
 * Off by default. Calm & low-key — slow movement, low opacity, infrequent
 * dramatic actions, infrequent speech. Confined to the window.
 */
(function(){
'use strict';

var Z = 88;                  // paints UNDER the crab (89) and sheep (90)
var _enabled = false;
var _ghost = null;

var SAYINGS = [
  'boo', 'wooOOoo', 'spooky', "don't mind me", 'i float', '🫥',
  'oOOoo', 'boo?'
];

// ── styles (injected once) ───────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-ghost-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-ghost{position:fixed;z-index:'+Z+';width:58px;height:64px;pointer-events:none;',
      'will-change:left,top,transform;user-select:none;-webkit-user-select:none;opacity:.82;',
      'transition:opacity .5s ease,transform .3s ease;filter:drop-shadow(0 0 6px rgba(150,180,255,.55))}',
    '.cryptirc-ghost svg{display:block;width:100%;height:100%;overflow:visible;pointer-events:none}',
    /* idle hover: body breathes a touch, bottom humps wobble gently */
    '.cryptirc-ghost .ghb{animation:ghBreathe 3.6s ease-in-out infinite}',
    '.cryptirc-ghost .ghhump{animation:ghWobble 2.4s ease-in-out infinite}',
    '.cryptirc-ghost .ghhump.b{animation-delay:.6s}',
    '.cryptirc-ghost .ghhump.c{animation-delay:1.2s}',
    '@keyframes ghBreathe{0%,100%{transform:scale(1)}50%{transform:scale(1.03,.985)}}',
    '@keyframes ghWobble{0%,100%{transform:translateY(0)}50%{transform:translateY(1.6px)}}',
    /* drift: nothing extra — the rAF loop handles motion (keep it calm) */
    /* fade: phase through the wall */
    '.cryptirc-ghost.fade{opacity:.12}',
    /* spin: slow lazy 360 */
    '.cryptirc-ghost.spin{animation:ghSpin 2.6s ease-in-out}',
    '@keyframes ghSpin{from{transform:rotate(0)}to{transform:rotate(360deg)}}',
    /* wobble: gentle squash/jiggle in place */
    '.cryptirc-ghost.wobble .ghb{animation:ghJiggle .5s ease-in-out infinite}',
    '@keyframes ghJiggle{0%,100%{transform:scale(1,1)}25%{transform:scale(1.06,.94) rotate(2deg)}75%{transform:scale(.94,1.06) rotate(-2deg)}}',
    /* boo: quick lunge + shake (RARE) */
    '.cryptirc-ghost.boo{animation:ghBoo .6s ease-out}',
    '@keyframes ghBoo{0%{transform:scale(1)}18%{transform:scale(1.45) translateY(-4px)}30%{transform:scale(1.4) translate(2px,-3px)}45%{transform:scale(1.4) translate(-2px,-3px)}60%{transform:scale(1.4) translate(2px,-3px)}100%{transform:scale(1)}}',
    /* eyes drift a little so it feels alive */
    '.cryptirc-ghost .ghpupil{animation:ghLook 4.4s ease-in-out infinite}',
    '@keyframes ghLook{0%,40%{transform:translateX(0)}50%,70%{transform:translateX(1.4px)}80%,100%{transform:translateX(-1.4px)}}',
    /* speech bubble — pale, ghostly */
    '.gh-say{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-family:var(--mono,ui-monospace,monospace);',
      'font-size:11px;font-weight:700;color:#2a3258;background:rgba(238,244,255,.92);border:2px solid #aab8e0;',
      'border-radius:9px;padding:3px 8px;white-space:nowrap;box-shadow:0 0 10px rgba(150,180,255,.45);',
      'opacity:0;transform:translateY(4px) scale(.9);transition:opacity .18s,transform .18s}',
    '.gh-say.show{opacity:1;transform:none}',
    '.gh-say::after{content:"";position:absolute;bottom:-7px;left:14px;border:6px solid transparent;border-top-color:#aab8e0}',
    /* rising wisp particles */
    '.gh-wisp{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 40% 30%,rgba(238,244,255,.85),rgba(170,184,224,.18));',
      'filter:blur(.5px);animation:ghWispRise linear forwards}',
    '@keyframes ghWispRise{0%{opacity:.7;transform:translateY(0) scale(.8)}100%{opacity:0;transform:translateY(-40px) scale(1.3)}}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-ghost *,.cryptirc-ghost{animation:none!important;transition:opacity .5s ease!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the ghost SVG (bedsheet ghost; humps + body are parted so they can wobble) ─
function ghostSVG(){
  // colors: pale white-blue body, soft blue shadow, slight translucency
  return '<svg viewBox="0 0 64 72" xmlns="http://www.w3.org/2000/svg">'+
    '<g class="ghb" style="transform-origin:32px 38px">'+
      // soft outer aura
      '<ellipse cx="32" cy="36" rx="27" ry="33" fill="rgba(180,200,255,.18)"/>'+
      // body: rounded dome head flowing into the sheet
      '<path d="M8 40 C8 16 24 5 32 5 C40 5 56 16 56 40 L56 60 L8 60 Z" fill="#eef4ff" stroke="#c4d2f2" stroke-width="2"/>'+
      // soft inner shadow down the left for a little volume
      '<path d="M12 40 C12 20 22 9 30 7 C20 12 16 24 16 40 L16 58 L12 58 Z" fill="rgba(196,210,242,.45)"/>'+
      // wavy/scalloped bottom edge — 3 humps, each parted for wobble
      '<g class="ghhump a"><path d="M8 60 q 6 9 12 0 z" fill="#eef4ff" stroke="#c4d2f2" stroke-width="2"/></g>'+
      '<g class="ghhump b"><path d="M20 60 q 6 9 12 0 z" fill="#eef4ff" stroke="#c4d2f2" stroke-width="2"/></g>'+
      '<g class="ghhump c"><path d="M32 60 q 6 9 12 0 z" fill="#eef4ff" stroke="#c4d2f2" stroke-width="2"/></g>'+
      '<g class="ghhump a"><path d="M44 60 q 6 9 12 0 z" fill="#eef4ff" stroke="#c4d2f2" stroke-width="2"/></g>'+
      // two oval eyes with small dark pupils
      '<ellipse cx="24" cy="32" rx="4.5" ry="6" fill="#fff" stroke="#c4d2f2" stroke-width="1"/>'+
      '<ellipse cx="40" cy="32" rx="4.5" ry="6" fill="#fff" stroke="#c4d2f2" stroke-width="1"/>'+
      '<circle class="ghpupil" cx="24" cy="33" r="2.2" fill="#2a3258" style="transform-origin:24px 33px"/>'+
      '<circle class="ghpupil" cx="40" cy="33" r="2.2" fill="#2a3258" style="transform-origin:40px 33px"/>'+
      // small open mouth
      '<ellipse cx="32" cy="45" rx="4" ry="5.5" fill="#2a3258" opacity=".82"/>'+
    '</g>'+
  '</svg>';
}

// ── ghost instance ───────────────────────────────────────────────────────────
function Ghost(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-ghost';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = ghostSVG();
  this.say = document.createElement('div');
  this.say.className = 'gh-say';
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this.W = 58; this.H = 64;
  this._talkGate = 0;                              // frames of quiet remaining (talks less)
  this._bounds();
  // start somewhere in the window
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,(this.screenH-this.H));
  // wander target + a slow vertical sine bob phase
  this.tx = this.x; this.ty = this.y;
  this.bob = Math.random()*Math.PI*2;
  this.state = 'drift';
  this.t = 0; this.next = 90 + (Math.random()*120|0);
  this.lastFrame = 0;
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
// pick a fresh random wander target somewhere inside the window
Ghost.prototype._pickTarget = function(){
  this.tx = Math.random()*Math.max(1,(this.screenW-this.W));
  this.ty = Math.random()*Math.max(1,(this.screenH-this.H));
};

Ghost.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
  document.body.appendChild(this.say);
  this.setState('drift');

  var self=this;
  this._on(window, 'resize', function(){ self._bounds(); self.clamp(); if(self.tx>self.screenW-self.W) self.tx=self.screenW-self.W; if(self.ty>self.screenH-self.H) self.ty=self.screenH-self.H; });
  this._on(document, 'visibilitychange', function(){
    if(document.hidden){ if(self._raf){ cancelAnimationFrame(self._raf); self._raf=0; } } // truly pause: cancel the deferred frame
    else { self.lastFrame=0; self.loop(); }
  });

  this.loop();
};

Ghost.prototype.loop = function(){
  if(this._dead || document.hidden) return;
  if(this._raf) return;                            // already a frame queued — never double-schedule
  var self=this;
  this._raf = requestAnimationFrame(function(ts){ self._raf = 0; self.frame(ts); });
};

Ghost.prototype.frame = function(ts){
  if(this._dead) return;
  if(!this.lastFrame) this.lastFrame = ts;
  var dt = Math.min(40, ts - this.lastFrame); this.lastFrame = ts;
  var k = dt > 0 ? dt/16 : 1;   // frame-rate independent step

  if(this._talkGate > 0) this._talkGate -= k;

  this.t++;
  if(this.t >= this.next){ this.pickState(); }

  // gentle hovering bob — always advancing so it looks like it's floating
  this.bob += 0.035*k;

  switch(this.state){
    case 'drift':
    case 'peek': {
      // ease toward the target (lerp), slow & smooth
      var sp = (this.state==='peek' ? 0.018 : 0.022) * k;
      this.x += (this.tx - this.x) * sp;
      this.y += (this.ty - this.y) * sp;
      // arrived? drift picks a new target; peek lingers (next timer ends it)
      if(this.state==='drift'){
        var dx = this.tx - this.x, dy = this.ty - this.y;
        if(dx*dx + dy*dy < 25){ this._pickTarget(); }
      }
      break;
    }
    // fade / spin / wobble / boo: hold position (still bob a touch via offset)
  }

  this.clamp();
  // add the slow vertical sine float on render so it always hovers
  var floatY = Math.sin(this.bob) * 4;
  this.el.style.left = this.x + 'px';
  this.el.style.top  = (this.y + floatY) + 'px';
  this.loop();
};

Ghost.prototype.setState = function(st){
  this.state = st;
  this.el.classList.remove('fade','spin','wobble','boo');
  this.t = 0;
  switch(st){
    case 'drift':  this._pickTarget(); this.next = 160 + (Math.random()*200|0); break;
    case 'fade':   this.el.classList.add('fade'); this.next = 90 + (Math.random()*70|0); break;
    case 'spin':   this.el.classList.add('spin'); this.next = 160; break;
    case 'wobble': this.el.classList.add('wobble'); this.next = 70 + (Math.random()*50|0); if(Math.random()<0.2) this.speak(pick()); break;
    case 'boo':    this.el.classList.add('boo'); this.next = 60; this.speak('BOO!', true); this.wisps(); break;
    case 'peek':   this._pickCorner(); this.next = 200 + (Math.random()*240|0); if(Math.random()<0.2) this.speak(pick()); break;
  }
};

// peek: drift toward a random screen corner and linger there
Ghost.prototype._pickCorner = function(){
  var pad = 8;
  this.tx = (Math.random()<0.5 ? pad : (this.screenW - this.W - pad));
  this.ty = (Math.random()<0.5 ? pad : (this.screenH - this.H - pad));
  this.tx = Math.max(0, this.tx); this.ty = Math.max(0, this.ty);
};

// Weighted heavily toward calm drifting; boo & speech are rare.
Ghost.prototype.pickState = function(){
  var r = Math.random();
  if(r < 0.58) this.setState('drift');
  else if(r < 0.72) this.setState('fade');
  else if(r < 0.82) this.setState('wobble');
  else if(r < 0.90) this.setState('spin');
  else if(r < 0.98) this.setState('peek');
  else this.setState('boo');                         // ~2% — RARE
};

// ── silly fx ─────────────────────────────────────────────────────────────────
function pick(){ return SAYINGS[Math.random()*SAYINGS.length|0]; }
// Talks LESS: a global cooldown gates spontaneous chatter; `force` (boo)
// bypasses the gate but still arms it so the ghost then hushes.
Ghost.prototype.speak = function(txt, force){
  if(this._dead) return;
  if(!force && this._talkGate > 0) return;
  this._talkGate = 540 + (Math.random()*600|0);      // ~9–19s of quiet after each line
  this.say.textContent = txt;
  var bx = this.x + this.W/2, by = this.y - 8;
  this.say.style.left = Math.max(6, bx) + 'px';
  this.say.style.top  = by + 'px';
  this.say.style.transform = 'translate(-50%,-100%)';
  this.say.classList.add('show');
  var self=this;
  clearTimeout(this._sayT);
  this._sayT = setTimeout(function(){ if(!self._dead) self.say.classList.remove('show'); }, 1500);
  this._timers.push(this._sayT);
};
// faint trailing wisps that rise and fade
Ghost.prototype.wisps = function(){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<4;i++){ (function(n){ self._after(n*140, function(){
    var w = document.createElement('div'); w.className='gh-wisp';
    var sz = 6 + (Math.random()*8|0);
    w.style.width=sz+'px'; w.style.height=sz+'px';
    w.style.left = (self.x + 12 + Math.random()*34) + 'px';
    w.style.top  = (self.y + self.H - 10 + Math.random()*8) + 'px';
    w.style.animationDuration = (1.2 + Math.random()*0.9) + 's';
    document.body.appendChild(w);
    self._after(2100, function(){ if(w.parentNode) w.parentNode.removeChild(w); });
  }); })(i); }
};

Ghost.prototype.destroy = function(){
  this._dead = true;
  if(this._raf) cancelAnimationFrame(this._raf);
  for(var i=0;i<this._timers.length;i++){ clearTimeout(this._timers[i]); }
  this._timers.length = 0;
  for(var j=0;j<this._listeners.length;j++){ var L=this._listeners[j]; try{ L.t.removeEventListener(L.e,L.fn,L.opts); }catch(_){ } }
  this._listeners.length = 0;
  if(this.el && this.el.parentNode) this.el.parentNode.removeChild(this.el);
  if(this.say && this.say.parentNode) this.say.parentNode.removeChild(this.say);
  // sweep any stray fx
  var stray = document.querySelectorAll('.gh-wisp');
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
