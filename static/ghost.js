/*!
 * CryptIRC Desktop Pet — Cute Ghost 👻
 * ------------------------------------------------------------------------
 * A self-contained, CSP-safe (no eval, no network) adorable little ghost that
 * FLIES FREELY around the whole client window — gently wandering with a slow
 * hovering bob, fading "through walls", twirling, waving, blowing little hearts,
 * playing peek-a-boo, and (now and then) inviting a GHOST FRIEND to float
 * alongside it for a while. Drawn procedurally as an articulated SVG (no sprite
 * sheet) and animated with CSS + a rAF position loop.
 *
 * You can DRAG it around (grab-to-drag, like the crab/eSheep) — but it never
 * steals clicks: a plain click is forwarded to the UI underneath (and tickles
 * the ghost into a happy little reaction).
 *
 * Public API (wired to Appearance ▸ Desktop Pet, like crab.js):
 *   window.CryptIRCGhost.enable()  spawn the ghost (idempotent)
 *   .disable()  remove it + its friend + all timers/listeners (no leaks)
 *   .isOn()     -> boolean
 * Off by default. Calm, cute & low-key. Confined to the window; pauses when the
 * tab is hidden.
 */
(function(){
'use strict';

var Z = 88;                  // paints UNDER the crab (89) and sheep (90)
var _enabled = false;
var _ghost = null;

var SAYINGS = [
  'hi!', 'tee hee', 'boo~', 'wheee', 'float float', '💗', '✨', 'oOOoo',
  "let's be friends", 'spooky cute', 'peekaboo'
];
var TINT_MAIN   = { body:'#eef2ff', sh:'#cdd6f5', blush:'#ffadc8' };
var TINT_FRIEND = { body:'#ffeef5', sh:'#f3c6da', blush:'#ff9ec2' };

// ── styles (injected once) ───────────────────────────────────────────────────
var STYLE_ID = 'cryptirc-ghost-style';
function injectStyle(){
  if(document.getElementById(STYLE_ID)) return;
  var s = document.createElement('style');
  s.id = STYLE_ID;
  s.textContent = [
    '.cryptirc-ghost{position:fixed;z-index:'+Z+';width:58px;height:64px;pointer-events:auto;cursor:grab;touch-action:manipulation;',
      'will-change:left,top,transform;user-select:none;-webkit-user-select:none;opacity:.9;',
      'transition:opacity .5s ease;filter:drop-shadow(0 0 7px rgba(160,185,255,.6))}',
    '.cryptirc-ghost svg{display:block;width:100%;height:100%;overflow:visible;pointer-events:none}',
    /* the floaty friend (not draggable) */
    '.gh-friend{position:fixed;z-index:'+(Z)+';pointer-events:none;opacity:0;',
      'will-change:left,top;transition:opacity .9s ease;filter:drop-shadow(0 0 6px rgba(255,180,210,.6))}',
    '.gh-friend.in{opacity:.82}',
    '.gh-friend svg{display:block;width:100%;height:100%;overflow:visible}',
    /* idle hover: body breathes, humps wobble, eyes blink */
    '.cryptirc-ghost .ghb,.gh-friend .ghb{animation:ghBreathe 3.6s ease-in-out infinite}',
    '.cryptirc-ghost .ghhump,.gh-friend .ghhump{animation:ghWobble 2.4s ease-in-out infinite}',
    '.cryptirc-ghost .ghhump.b,.gh-friend .ghhump.b{animation-delay:.6s}',
    '.cryptirc-ghost .ghhump.c,.gh-friend .ghhump.c{animation-delay:1.2s}',
    '.cryptirc-ghost .gheyes,.gh-friend .gheyes{animation:ghBlink 4.8s ease-in-out infinite;transform-origin:32px 33px}',
    '@keyframes ghBreathe{0%,100%{transform:scale(1)}50%{transform:scale(1.03,.985)}}',
    '@keyframes ghWobble{0%,100%{transform:translateY(0)}50%{transform:translateY(1.6px)}}',
    '@keyframes ghBlink{0%,93%,100%{transform:scaleY(1)}96.5%{transform:scaleY(.12)}}',
    /* fade: phase through the wall */
    '.cryptirc-ghost.fade{opacity:.12}',
    /* spin: happy little 360 twirl */
    '.cryptirc-ghost.spin{animation:ghSpin 2.4s ease-in-out}',
    '@keyframes ghSpin{from{transform:rotate(0)}to{transform:rotate(360deg)}}',
    /* twirl: a quick loop-de-loop */
    '.cryptirc-ghost.twirl{animation:ghTwirl 1.1s ease-in-out}',
    '@keyframes ghTwirl{0%{transform:rotate(0) scale(1)}50%{transform:rotate(200deg) scale(.8)}100%{transform:rotate(360deg) scale(1)}}',
    /* wobble: giggle in place */
    '.cryptirc-ghost.wobble .ghb{animation:ghJiggle .5s ease-in-out infinite}',
    '@keyframes ghJiggle{0%,100%{transform:scale(1,1)}25%{transform:scale(1.06,.94) rotate(2deg)}75%{transform:scale(.94,1.06) rotate(-2deg)}}',
    /* wave a little arm */
    '.cryptirc-ghost.wave .gharm.r{animation:ghWave .5s ease-in-out infinite;transform-origin:52px 42px}',
    '@keyframes ghWave{0%,100%{transform:rotate(0)}50%{transform:rotate(-32deg)}}',
    /* boo: a cute pop (not scary) */
    '.cryptirc-ghost.boo{animation:ghBoo .6s ease-out}',
    '@keyframes ghBoo{0%{transform:scale(1)}25%{transform:scale(1.4) translateY(-5px)}45%{transform:scale(1.32) rotate(-6deg)}65%{transform:scale(1.32) rotate(6deg)}100%{transform:scale(1)}}',
    /* held: squish happily while dragged */
    '.cryptirc-ghost.held{cursor:grabbing;animation:ghHeld .45s ease-in-out infinite}',
    '@keyframes ghHeld{0%,100%{transform:scale(1.06,.94)}50%{transform:scale(.94,1.06)}}',
    /* speech bubble — pale, ghostly */
    '.gh-say{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-family:var(--mono,ui-monospace,monospace);',
      'font-size:11px;font-weight:700;color:#3a3f63;background:rgba(240,243,255,.95);border:2px solid #b9c4ea;',
      'border-radius:10px;padding:3px 8px;white-space:nowrap;box-shadow:0 0 10px rgba(160,185,255,.5);',
      'opacity:0;transform:translateY(4px) scale(.9);transition:opacity .18s,transform .18s}',
    '.gh-say.show{opacity:1;transform:none}',
    '.gh-say::after{content:"";position:absolute;bottom:-7px;left:14px;border:6px solid transparent;border-top-color:#b9c4ea}',
    /* floaty hearts */
    '.gh-heart{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:13px;animation:ghHeart 1.6s ease-out forwards}',
    '@keyframes ghHeart{0%{opacity:0;transform:translateY(0) scale(.4)}20%{opacity:1}100%{opacity:0;transform:translateY(-34px) scale(1.1)}}',
    /* twinkle sparkles */
    '.gh-spark{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:11px;animation:ghSpark 1s ease-out forwards}',
    '@keyframes ghSpark{0%{opacity:0;transform:scale(.3) rotate(0)}30%{opacity:1}100%{opacity:0;transform:scale(1.1) rotate(90deg) translateY(-12px)}}',
    /* rising wisp particles */
    '.gh-wisp{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;',
      'background:radial-gradient(circle at 40% 30%,rgba(240,243,255,.85),rgba(180,195,235,.18));',
      'filter:blur(.5px);animation:ghWispRise linear forwards}',
    '@keyframes ghWispRise{0%{opacity:.7;transform:translateY(0) scale(.8)}100%{opacity:0;transform:translateY(-40px) scale(1.3)}}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-ghost *,.cryptirc-ghost,.gh-friend *,.gh-friend{animation:none!important;transition:opacity .5s ease!important}}'
  ].join('');
  document.head.appendChild(s);
}

// ── the cute ghost SVG (big sparkly eyes, blush, smile, tiny arms) ────────────
function ghostSVG(tint){
  tint = tint || TINT_MAIN;
  var hump = function(x,cls){ return '<g class="ghhump '+cls+'"><path d="M'+x+' 56 q 5.75 9 11.5 0 z" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="2"/></g>'; };
  return '<svg viewBox="0 0 64 72" xmlns="http://www.w3.org/2000/svg">'+
    '<g class="ghb" style="transform-origin:32px 38px">'+
      // soft aura
      '<ellipse cx="32" cy="36" rx="28" ry="33" fill="rgba(185,205,255,.16)"/>'+
      // tiny arms (behind the body)
      '<g class="gharm l"><ellipse cx="11" cy="42" rx="5" ry="6" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="1.5"/></g>'+
      '<g class="gharm r"><ellipse cx="53" cy="42" rx="5" ry="6" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="1.5"/></g>'+
      // round body
      '<path d="M9 42 C9 17 23 5 32 5 C41 5 55 17 55 42 L55 59 Z" fill="'+tint.body+'" stroke="'+tint.sh+'" stroke-width="2"/>'+
      // soft inner shading on the left for a little volume
      '<path d="M13 42 C13 21 22 10 29 8 C21 13 17 24 17 42 L17 57 Z" fill="rgba(205,214,245,.4)"/>'+
      // scalloped bottom — four little humps
      hump(9,'a')+hump(20.5,'b')+hump(32,'c')+hump(43.5,'a')+
      // big kawaii eyes (dark, with white sparkles) — grouped so they can blink
      '<g class="gheyes">'+
        '<ellipse cx="23" cy="33" rx="5.2" ry="6.8" fill="#3a3f63"/>'+
        '<ellipse cx="41" cy="33" rx="5.2" ry="6.8" fill="#3a3f63"/>'+
        '<circle cx="24.8" cy="30.6" r="1.9" fill="#fff"/>'+
        '<circle cx="42.8" cy="30.6" r="1.9" fill="#fff"/>'+
        '<circle cx="21.6" cy="35" r="1" fill="#fff" opacity=".75"/>'+
        '<circle cx="39.6" cy="35" r="1" fill="#fff" opacity=".75"/>'+
      '</g>'+
      // rosy blush
      '<ellipse cx="16.5" cy="40.5" rx="3.4" ry="2.2" fill="'+tint.blush+'" opacity=".7"/>'+
      '<ellipse cx="47.5" cy="40.5" rx="3.4" ry="2.2" fill="'+tint.blush+'" opacity=".7"/>'+
      // little smile
      '<path d="M28 42 q 4 4.2 8 0" stroke="#3a3f63" stroke-width="2" fill="none" stroke-linecap="round"/>'+
    '</g>'+
  '</svg>';
}

// ── ghost instance ───────────────────────────────────────────────────────────
function Ghost(){
  this.el = document.createElement('div');
  this.el.className = 'cryptirc-ghost';
  this.el.setAttribute('aria-hidden','true');
  this.el.innerHTML = ghostSVG(TINT_MAIN);
  this.say = document.createElement('div');
  this.say.className = 'gh-say';
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this.W = 58; this.H = 64;
  this.dragging = false; this._didDrag = false; this._pressX = null; this._pressY = null;
  this._talkGate = 0;                                   // frames of quiet remaining
  this._bounds();
  this.x = Math.random()*Math.max(1,(this.screenW-this.W));
  this.y = Math.random()*Math.max(1,(this.screenH-this.H));
  this.tx = this.x; this.ty = this.y;
  this.bob = Math.random()*Math.PI*2;
  this.state = 'drift';
  this.t = 0; this.next = 90 + (Math.random()*120|0);
  this.lastFrame = 0;
  // friend who visits now and then
  this._friend = null; this._friendT = 0; this._friendBob = 0; this._friendSide = 1;
  this._friendGate = 700 + (Math.random()*1400|0);      // frames until the first friend visit (~12–35s)
  this._heartGate = 0;
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
  document.body.appendChild(this.say);
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

// Grab-to-drag + click handling (mirrors the crab/eSheep). The ghost is
// pointer-events:auto so you can pick it up, but a plain click is forwarded to
// the UI underneath so it NEVER steals a click — and tickles the ghost.
Ghost.prototype._wire = function(){
  var self=this;
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
    var prev=self.el.style.pointerEvents; self.el.style.pointerEvents='none';
    var pets=document.querySelectorAll('.cryptirc-ghost, .gh-friend, .cryptirc-crab, .cryptirc-esheep'), saved=[];
    for(var i=0;i<pets.length;i++){ saved.push([pets[i],pets[i].style.pointerEvents]); pets[i].style.pointerEvents='none'; }
    var under=document.elementFromPoint(e.clientX,e.clientY);
    self.el.style.pointerEvents=prev;
    for(var j=0;j<saved.length;j++){ saved[j][0].style.pointerEvents=saved[j][1]; }
    if(under && !(under.closest && under.closest('.cryptirc-ghost'))){
      under.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true,clientX:e.clientX,clientY:e.clientY,view:window}));
    }
  });
  this._on(this.el, 'contextmenu', function(e){ e.preventDefault(); return false; });
  this._on(this.el, 'dragstart', function(e){ e.preventDefault(); return false; });
};
Ghost.prototype._beginDrag = function(){
  this.dragging = true; this.state = 'held';
  this.el.classList.remove('fade','spin','wobble','boo','wave','twirl');
  this.el.classList.add('held');
  if(Math.random()<0.5) this.speak(Math.random()<0.5?'wheee':'💗', true);
};
Ghost.prototype._endDrag = function(){
  this.dragging = false;
  this.el.classList.remove('held');
  this.tx = this.x; this.ty = this.y;     // drift onward from where it was dropped
  this.setState('drift');
};
// tickled by a click → a happy little reaction
Ghost.prototype.poke = function(){
  if(this._dead || this.dragging) return;
  var r = Math.random();
  if(r < 0.4){ this.setState('twirl'); }
  else if(r < 0.75){ this.setState('wave'); }
  else { this.setState('wobble'); }
  this.hearts(1 + (Math.random()*2|0));
  this.speak(['hi!','tee hee','💗','peekaboo'][Math.random()*4|0], true);
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

  if(this._talkGate > 0) this._talkGate -= k;
  this.bob += 0.024*k;                              // slow, dreamy hover

  if(!this.dragging){
    this.t++;
    if(this.t >= this.next){ this.pickState(); }

    if(this.state==='drift' || this.state==='peek'){
      var sp = (this.state==='peek' ? 0.010 : 0.013) * k;   // slower, more gliding drift
      this.x += (this.tx - this.x) * sp;
      this.y += (this.ty - this.y) * sp;
      if(this.state==='drift'){
        var dx = this.tx - this.x, dy = this.ty - this.y;
        if(dx*dx + dy*dy < 25){ this._pickTarget(); }
      }
    }
    this.clamp();
    var floatY = Math.sin(this.bob) * 4;
    this.el.style.left = this.x + 'px';
    this.el.style.top  = (this.y + floatY) + 'px';
  }

  // the friend lives its own little life (and follows along even while dragged)
  this._friendTick(k);

  this.loop();
};

Ghost.prototype.setState = function(st){
  this.state = st;
  this.el.classList.remove('fade','spin','wobble','boo','wave','twirl','held');
  this.t = 0;
  switch(st){
    case 'drift':  this._pickTarget(); this.next = 220 + (Math.random()*260|0); break;
    case 'fade':   this.el.classList.add('fade'); this.next = 80 + (Math.random()*70|0); break;
    case 'spin':   this.el.classList.add('spin'); this.next = 150; break;
    case 'twirl':  this.el.classList.add('twirl'); this.next = 70; if(Math.random()<0.4) this.sparkles(); break;
    case 'wobble': this.el.classList.add('wobble'); this.next = 70 + (Math.random()*50|0); if(Math.random()<0.25) this.speak(pick()); break;
    case 'wave':   this.el.classList.add('wave'); this.next = 80; if(Math.random()<0.5) this.speak(Math.random()<0.5?'hi!':'👋'); break;
    case 'heart':  this.next = 60; this.hearts(2 + (Math.random()*2|0)); if(Math.random()<0.4) this.speak('💗', false); break;
    case 'peek':   this._pickCorner(); this.next = 200 + (Math.random()*240|0); if(Math.random()<0.25) this.speak('peekaboo'); break;
    case 'boo':    this.el.classList.add('boo'); this.next = 60; this.speak('boo~', true); this.wisps(); break;
  }
};

// Weighted toward calm drifting; cute actions sprinkled in, boo is rare.
Ghost.prototype.pickState = function(){
  if(this.dragging) return;
  var r = Math.random();
  if(r < 0.46)      this.setState('drift');
  else if(r < 0.58) this.setState('fade');
  else if(r < 0.68) this.setState('wobble');
  else if(r < 0.77) this.setState('wave');
  else if(r < 0.85) this.setState('heart');
  else if(r < 0.91) this.setState('twirl');
  else if(r < 0.97) this.setState('peek');
  else              this.setState('boo');     // ~3% — rare
};

// ── the visiting friend ───────────────────────────────────────────────────────
Ghost.prototype._spawnFriend = function(){
  if(this._dead || this._friend) return;
  var f = document.createElement('div');
  f.className = 'gh-friend';
  var fw = Math.round(this.W*0.78), fh = Math.round(this.H*0.78);
  f.style.width = fw+'px'; f.style.height = fh+'px';
  f.innerHTML = ghostSVG(TINT_FRIEND);
  this._friendW = fw; this._friendH = fh;
  this._friendSide = Math.random()<0.5 ? -1 : 1;
  this._friendBob = Math.random()*Math.PI*2;
  this._friendT = 900 + (Math.random()*900|0);          // hangs out ~15–30s
  document.body.appendChild(f);
  this._friend = f;
  // fade in next tick
  var self=this; this._after(30, function(){ if(self._friend===f) f.classList.add('in'); });
  this.speak(Math.random()<0.5?'a friend! 💗':'hi friend', true);
};
Ghost.prototype._despawnFriend = function(){
  var f = this._friend; this._friend = null; this._friendT = 0;
  if(!f) return;
  f.classList.remove('in');                              // fade out
  var self=this; this._after(950, function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};
Ghost.prototype._friendTick = function(k){
  // schedule a visit
  if(!this._friend){
    if(this._friendGate > 0) this._friendGate -= k;
    else { this._spawnFriend(); this._friendGate = 2400 + (Math.random()*3600|0); }  // next visit in ~40–100s
    return;
  }
  // float beside the ghost with its own gentle orbit
  this._friendBob += 0.028*k;
  var fx = this.x + this._friendSide*(this.W*0.92) + Math.sin(this._friendBob)*7;
  var fy = this.y + 6 + Math.cos(this._friendBob*1.3)*9;
  fx = Math.max(0, Math.min(fx, this.screenW - this._friendW));
  fy = Math.max(0, Math.min(fy, this.screenH - this._friendH));
  this._friend.style.left = fx+'px';
  this._friend.style.top  = fy+'px';
  // every so often a heart pops between the two
  if(this._heartGate > 0){ this._heartGate -= k; }
  else { this._heartGate = 150 + (Math.random()*180|0); this._heartAt((this.x + fx)/2 + this.W/2 - 6, Math.min(this.y, fy) - 4); }
  // visit winding down
  this._friendT -= k;
  if(this._friendT <= 0){ this.speak(Math.random()<0.5?'bye 💗':'see ya!', true); this._despawnFriend(); }
};

// ── cute fx ───────────────────────────────────────────────────────────────────
function pick(){ return SAYINGS[Math.random()*SAYINGS.length|0]; }
Ghost.prototype.speak = function(txt, force){
  if(this._dead) return;
  if(!force && this._talkGate > 0) return;
  this._talkGate = 540 + (Math.random()*600|0);          // ~9–19s of quiet after each line
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
Ghost.prototype._heartAt = function(px, py){
  if(this._dead) return;
  var h = document.createElement('div'); h.className='gh-heart'; h.textContent = Math.random()<0.5?'💗':'💕';
  h.style.left = px+'px'; h.style.top = py+'px';
  document.body.appendChild(h);
  this._after(1700, function(){ if(h.parentNode) h.parentNode.removeChild(h); });
};
Ghost.prototype.hearts = function(n){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<n;i++){ (function(j){ self._after(j*160, function(){
    self._heartAt(self.x + self.W*0.3 + Math.random()*self.W*0.4, self.y - 4 - Math.random()*6);
  }); })(i); }
};
Ghost.prototype.sparkles = function(){
  if(this._dead) return;
  var self=this;
  for(var i=0;i<4;i++){ (function(j){ self._after(j*90, function(){
    var sp=document.createElement('div'); sp.className='gh-spark'; sp.textContent = Math.random()<0.5?'✨':'✦';
    sp.style.left=(self.x + Math.random()*self.W)+'px'; sp.style.top=(self.y + Math.random()*self.H*0.6)+'px';
    document.body.appendChild(sp);
    self._after(1100, function(){ if(sp.parentNode) sp.parentNode.removeChild(sp); });
  }); })(i); }
};
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
  this._friend = null;
  // sweep any stray fx + friend
  var stray = document.querySelectorAll('.gh-wisp, .gh-heart, .gh-spark, .gh-friend');
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
