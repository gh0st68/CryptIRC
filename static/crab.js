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

// Topmost element at (x,y) that is NOT a desktop-pet node, so a forwarded click
// resolves to the real UI beneath instead of another pet.
var PET_SELECTOR = '.cryptirc-crab, .cryptirc-esheep, .cryptirc-ghost, .gh-friend, .cryptirc-alien, .al-buddy, .cryptirc-fish';
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
      'will-change:left,top,transform;user-select:none;-webkit-user-select:none;transition:transform .22s ease,opacity .4s ease;filter:drop-shadow(0 3px 3px rgba(0,0,0,.45))}',
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
    '.cc-shrimp.pop{animation:ccPop .4s cubic-bezier(.2,1.4,.5,1)}',           /* shrimp hops into view */
    '@keyframes ccPop{0%{transform:translateY(-10px) scale(.4);opacity:0}60%{transform:translateY(2px) scale(1.1)}100%{transform:none;opacity:1}}',
    /* napping: eyes droop */
    '.cryptirc-crab.nap .pupil{opacity:.25}',
    /* dizzy stars after a wall bonk / flip */
    '.cc-dizzy{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:13px;animation:ccDizzy .9s ease-out forwards}',
    '@keyframes ccDizzy{0%{opacity:0;transform:translate(0,0) rotate(0) scale(.5)}25%{opacity:1}100%{opacity:0;transform:translate(8px,-20px) rotate(160deg) scale(1)}}',
    /* flipped onto its back: rock side to side, legs flailing in the air */
    '.cryptirc-crab.flipped{animation:ccFlip .42s ease-in-out infinite}',
    '@keyframes ccFlip{0%,100%{transform:rotate(173deg)}50%{transform:rotate(187deg)}}',
    '.cryptirc-crab.flipped .ccleg{animation:ccLeg .13s ease-in-out infinite}',
    '.cryptirc-crab.flipped .ccleg.b{animation-delay:.06s}',
    /* new random-event fx */
    '.cc-castle,.cc-fish{position:fixed;z-index:'+(Z-1)+';pointer-events:none;font-size:16px;line-height:1;filter:drop-shadow(0 2px 2px rgba(0,0,0,.4));transition:transform .35s ease,opacity .35s ease}',
    '.cc-treasure{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:15px;line-height:1;animation:ccTreasure 1.4s ease-out forwards}',
    '@keyframes ccTreasure{0%{opacity:0;transform:translateY(6px) scale(.5)}25%{opacity:1;transform:translateY(-2px) scale(1.1)}100%{opacity:0;transform:translateY(-10px)}}',
    '.cc-shell{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:15px;line-height:1;animation:ccShellBob 1.5s ease-in-out}',
    '@keyframes ccShellBob{0%,100%{transform:translateY(0) rotate(-6deg)}50%{transform:translateY(-3px) rotate(6deg)}}',
    '.cc-gull{position:fixed;z-index:'+(Z-1)+';pointer-events:none;width:54px;height:14px;background:radial-gradient(ellipse,rgba(0,0,0,.32),rgba(0,0,0,0) 70%)}',
    '.cc-tide{position:fixed;z-index:'+(Z-1)+';pointer-events:none;width:72px;height:9px;border-radius:50%;background:radial-gradient(ellipse,rgba(120,190,230,.5),rgba(120,190,230,0) 70%)}',
    '.cryptirc-crab.duck{animation:ccDuck .5s ease-in-out}',
    '@keyframes ccDuck{0%,100%{transform:scaleY(1)}40%,70%{transform:scaleY(.7) translateY(8px)}}',
    '.cryptirc-crab.hop{animation:ccHop .5s ease-out}',
    '@keyframes ccHop{0%,100%{transform:translateY(0)}40%{transform:translateY(-14px)}}',
    '.cryptirc-crab.burrow{opacity:0;pointer-events:none;cursor:default}',
    /* ── 10 new grumpy-crab behaviors ── */
    /* 1. shuffle: snappy sidestep shuffle-dance */
    '.cryptirc-crab.shuffle .ccb{animation:ccBob .2s ease-in-out infinite}',
    '.cryptirc-crab.shuffle .ccleg{animation:ccLeg .2s ease-in-out infinite}',
    '.cryptirc-crab.shuffle .pinT{animation:ccSnapT .4s ease-in-out infinite}',
    '.cryptirc-crab.shuffle .pinB{animation:ccSnapB .4s ease-in-out infinite}',
    /* 2. peek: hunkered down in a hole, only top showing */
    '.cryptirc-crab.peek{animation:ccPeek 1.6s ease-in-out}',
    '@keyframes ccPeek{0%,100%{transform:translateY(0)}25%,75%{transform:translateY(16px)}}',
    '.cc-hole{position:fixed;z-index:'+(Z-1)+';pointer-events:none;width:46px;height:14px;border-radius:50%;background:radial-gradient(ellipse,rgba(60,40,20,.65),rgba(90,66,36,.4) 70%);border:2px solid #caa46a;animation:ccHoleFade 1.7s ease-out forwards}',
    '@keyframes ccHoleFade{0%{opacity:0}15%,80%{opacity:1}100%{opacity:0}}',
    /* 3. angry sideways bubble stream */
    '.cc-jet{position:fixed;z-index:'+Z+';pointer-events:none;border-radius:50%;background:radial-gradient(circle at 35% 30%,rgba(255,255,255,.9),rgba(160,210,255,.35));border:1px solid rgba(255,255,255,.5);animation:ccJet linear forwards}',
    '@keyframes ccJet{0%{opacity:.95;transform:translate(0,0) scale(.5)}100%{opacity:0;transform:translate(var(--jx,40px),-6px) scale(1.2)}}',
    /* 4. sunbathe: lean back, claws up */
    '.cryptirc-crab.sunbathe{animation:ccSunbathe 2.4s ease-in-out}',
    '@keyframes ccSunbathe{0%,100%{transform:rotate(0)}20%,80%{transform:rotate(-12deg)}}',
    '.cryptirc-crab.sunbathe .armL,.cryptirc-crab.sunbathe .armR{animation:ccArmsUp 2.4s ease-in-out;transform-origin:50px 40px}',
    '@keyframes ccArmsUp{0%,100%{transform:rotate(0)}20%,80%{transform:rotate(-18deg)}}',
    '.cc-sun{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:17px;line-height:1;animation:ccSun 2.4s ease-in-out forwards}',
    '@keyframes ccSun{0%{opacity:0;transform:scale(.4)}20%,80%{opacity:1;transform:scale(1) rotate(20deg)}100%{opacity:0}}',
    /* 5. claw-drum a rhythm */
    '.cryptirc-crab.drum .pinT{animation:ccSnapT .12s ease-in-out infinite}',
    '.cryptirc-crab.drum .pinB{animation:ccSnapB .12s ease-in-out infinite}',
    '.cryptirc-crab.drum .armR{animation:ccDrum .24s ease-in-out infinite;transform-origin:62px 40px}',
    '.cryptirc-crab.drum .armL{animation:ccDrum .24s ease-in-out infinite .12s;transform-origin:38px 40px}',
    '@keyframes ccDrum{50%{transform:rotate(-10deg) translateY(2px)}}',
    '.cc-note{position:fixed;z-index:'+(Z+1)+';pointer-events:none;color:#7a1c0e;font-weight:800;font-size:13px;animation:ccNote 1s ease-out forwards}',
    '@keyframes ccNote{0%{opacity:0;transform:translate(0,0) rotate(-10deg)}25%{opacity:1}100%{opacity:0;transform:translate(9px,-22px) rotate(14deg)}}',
    /* 6. snip at a drifting bubble */
    '.cryptirc-crab.snipbub .pinT{animation:ccSnapT .15s ease-in-out infinite}',
    '.cryptirc-crab.snipbub .pinB{animation:ccSnapB .15s ease-in-out infinite}',
    '.cryptirc-crab.snipbub .armR{animation:ccReach .8s ease-in-out;transform-origin:62px 40px}',
    '@keyframes ccReach{0%,100%{transform:rotate(0)}45%{transform:rotate(-40deg) translateY(-6px)}}',
    /* 7. tiny defiant flag wave */
    '.cc-flag{position:fixed;z-index:'+(Z+1)+';pointer-events:none;font-size:15px;line-height:1;transform-origin:bottom left;animation:ccFlag .5s ease-in-out infinite}',
    '@keyframes ccFlag{0%,100%{transform:rotate(-8deg)}50%{transform:rotate(8deg)}}',
    '.cryptirc-crab.flag .armR{animation:ccWave .5s ease-in-out infinite;transform-origin:62px 40px}',
    /* 8. jolt-startle then scuttle */
    '.cryptirc-crab.jolt{animation:ccJolt .45s ease-out}',
    '@keyframes ccJolt{0%{transform:translateY(0)}20%{transform:translateY(-12px) scale(1.08)}45%{transform:translateY(0)}}',
    '.cc-jolt{position:fixed;z-index:'+(Z+1)+';pointer-events:none;color:#ffce1f;font-weight:900;font-size:20px;-webkit-text-stroke:1px #7a1c0e;animation:ccJoltMark .6s ease-out forwards}',
    '@keyframes ccJoltMark{0%{opacity:0;transform:scale(.2) translateY(4px)}30%{opacity:1;transform:scale(1.3)}100%{opacity:0;transform:scale(1) translateY(-14px)}}',
    /* 9. pinch the air, both claws jabbing */
    '.cryptirc-crab.pinchair .pinT{animation:ccSnapT .13s ease-in-out infinite}',
    '.cryptirc-crab.pinchair .pinB{animation:ccSnapB .13s ease-in-out infinite}',
    '.cryptirc-crab.pinchair .armL{animation:ccJab .26s ease-in-out infinite;transform-origin:38px 40px}',
    '.cryptirc-crab.pinchair .armR{animation:ccJab .26s ease-in-out infinite .13s;transform-origin:62px 40px}',
    '@keyframes ccJab{50%{transform:translateX(var(--jab,3px)) translateY(-2px)}}',
    /* 10. defiant little victory dance */
    '.cryptirc-crab.victory{animation:ccVictory .5s ease-in-out infinite}',
    '@keyframes ccVictory{0%,100%{transform:translateY(0) rotate(-4deg)}50%{transform:translateY(-9px) rotate(4deg)}}',
    '.cryptirc-crab.victory .armL,.cryptirc-crab.victory .armR{animation:ccCheer .5s ease-in-out infinite;transform-origin:50px 40px}',
    '@keyframes ccCheer{0%,100%{transform:rotate(0)}50%{transform:rotate(-22deg)}}',
    '.cc-confetti{position:fixed;z-index:'+(Z+1)+';pointer-events:none;width:5px;height:5px;border-radius:1px;animation:ccConfetti 1s ease-out forwards}',
    '@keyframes ccConfetti{0%{opacity:1;transform:translate(0,0) rotate(0)}100%{opacity:0;transform:translate(var(--cx,0),var(--cy,-22px)) rotate(220deg)}}',
    '@media(prefers-reduced-motion:reduce){.cryptirc-crab *,.cryptirc-crab{animation:none!important}',
      // also silence every spawned FX node (cc-*) and hide the purely-decorative ones
      '.cc-bub,.cc-anger,.cc-shrimp,.cc-zzz,.cc-sand,.cc-dizzy,.cc-castle,.cc-treasure,.cc-fish,.cc-gull,.cc-shell,.cc-tide,.cc-hole,.cc-jet,.cc-sun,.cc-note,.cc-flag,.cc-jolt,.cc-confetti{animation:none!important;opacity:0!important}}'
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
  this._timers = [];
  this._listeners = [];
  this._raf = 0;
  this._dead = false;
  this.W = 66; this.H = 50;
  this.dragging = false; this._didDrag = false; this._pressX = null; this._pressY = null;
  this._talkGate = 0;                              // frames of quiet remaining (talks less)
  this._encGate = 600 + (Math.random()*900|0);     // frames until it may go pester the sheep
  this._seekT = 0;
  this._shrimp = null;                             // a real shrimp element on the floor, when one's out
  this._shrimpX = 0;                               // its center x
  this._shrimpTtl = 0;                             // frames before an uneaten shrimp scuttles off
  this._shrimpGate = 500 + (Math.random()*1200|0); // frames until the next shrimp appears
  this._pendDir = 1;                               // direction to amble after a wall bonk / flip
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
  else if(this.state==='flipped'){ rot = 180; sx = 1; }   // bonked onto its back, legs in the air
  // consistent rotate()+scaleX() so the orientation TWEENS (see transition on .cryptirc-crab)
  this.el.style.transform = 'rotate('+rot+'deg) scaleX('+sx+')';
};

Crab.prototype.start = function(){
  injectStyle();
  document.body.appendChild(this.el);
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
    // Forward the click to the real UI underneath. Resolve via elementsFromPoint
    // skipping ANY pet node in the stack (crab/sheep/ghost/alien/fish), then
    // re-dispatch with full pointer fidelity (button/detail/modifiers/coords).
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

  // Keep a live shrimp sitting on the floor; if one goes uneaten too long it scuttles off.
  if(this._shrimp){
    this._shrimp.style.top = (this._floorY() + this.H - 18) + 'px';
    if(this.state!=='eat'){ if(this._shrimpTtl > 0) this._shrimpTtl -= k; else this.removeShrimp(); }
  }

  // From a calm floor state the crab decides what to do: chase FOOD first (a shrimp
  // that randomly appeared), otherwise occasionally go pester the eSheep if it's on.
  if(this.state==='walk' || this.state==='idle'){
    if(!this._shrimp){
      if(this._shrimpGate > 0) this._shrimpGate -= k;
      else { this.spawnShrimp(); this._shrimpGate = 1400 + (Math.random()*2600|0); }   // a shrimp every ~25–70s
    }
    if(this._shrimp){ this.setState('toshrimp'); }                                      // food! go get it
    else if(this._encGate > 0) this._encGate -= k;
    else if(this._sheepTarget()){ this.setState('seek'); this._seekT = 0; }
    else this._encGate = 240;                                                           // sheep off — re-check soon
  }

  this.t++;
  if(this.t >= this.next){
    if(this.state==='bonk'){                              // impact over → flop onto its back, or shake it off
      if(Math.random()<0.6) this.setState('flipped');
      else { this.face(this._pendDir); this.setState('walk'); }
    } else if(this.state==='flipped'){ this.face(this._pendDir); this.setState('walk'); }   // right itself, amble away
    else if(this.state==='jolt'){ this.face(Math.random()<0.5?-1:1); this.setState('charge'); }   // startled → bolt away
    else this.pickState();
  }

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
      this.vx = (Math.abs(d) < 6 ? 0 : (d<0 ? -1 : 1)) * 0.55;
      this.x += this.vx*k;
      this._seekT++;
      if(Math.abs(d) < this.W*0.7 || this._seekT > 1200){ this._encounter(tgt); }   // arrived (or gave up ~20s)
      break;
    }
    case 'toshrimp': {
      if(!this._shrimp){ this.setState('walk'); break; }              // shrimp gone — never mind
      var sc = this.x + this.W/2, sd = this._shrimpX - sc;
      this.face(sd<0 ? -1 : 1);
      this.vx = (Math.abs(sd) < 8 ? 0 : (sd<0 ? -1 : 1)) * 0.32;      // a slow, deliberate approach
      this.x += this.vx*k;
      if(Math.abs(sd) < this.W*0.45){ this.setState('eat'); }         // reached it → chomp
      break;
    }
    // snap / rage / wave / idle / dance / eat / nap / dig / bonk / flipped: mostly stationary (dance shuffles)
    case 'dance':   this.x += Math.sin(this.t*0.4)*0.8*this.dir; break;
    case 'shuffle': this.x += Math.sin(this.t*0.55)*1.3*this.dir; break;    // brisk side-to-side shuffle scoot
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
  var r = Math.random();
  if(r < 0.16){ this._pendDir = newDir; this.setState('bonk'); }   // ran straight into the wall — bonk! (then maybe flips over)
  else if(r < 0.48 && this.state==='walk'){ this.wall = (newDir>0?'L':'R'); this.x = (newDir>0?0:this.screenW-this.W); this.setState('climb'); this.vy = -0.85; }
  else { this.face(newDir); this.vx = Math.abs(this.vx||1.1) * newDir; if(Math.random()<0.5) this.setState('snap'); }
};

Crab.prototype.setState = function(st){
  this.state = st;
  this.el.classList.remove('walk','snap','rage','charge','wave','dance','crawl','drag','nap','flipped','bonk','duck','hop','burrow',
    'shuffle','peek','sunbathe','drum','snipbub','flag','jolt','pinchair','victory');
  this.t = 0;
  switch(st){
    case 'walk':   this.el.classList.add('walk'); this.vx = 0.22*this.dir; this.next = 240 + (Math.random()*260|0); break;  // slower, ambles longer
    case 'seek':   this.el.classList.add('walk'); this.vx = 0; this.next = 99999; break;   // ends via _encounter
    case 'toshrimp': this.el.classList.add('walk'); this.vx = 0; this.next = 99999; break; // ends on arrival → eat
    case 'charge': this.el.classList.add('charge','rage'); this.vx = 1.1*this.dir; this.next = 80 + (Math.random()*60|0); break;
    case 'snap':   this.el.classList.add('snap'); this.vx = 0; this.next = 24 + (Math.random()*20|0); break;
    case 'rage':   this.el.classList.add('rage','snap'); this.vx = 0; this.next = 34 + (Math.random()*26|0); this.anger(); break;
    case 'wave':   this.el.classList.add('wave'); this.vx = 0; this.next = 55; break;
    case 'dance':  this.el.classList.add('dance','walk'); this.vx = 0; this.next = 80; break;
    case 'eat':    this.el.classList.add('snap'); this.vx = 0; this.next = 110; this.chompShrimp(); break;        // chomp the floor shrimp
    case 'nap':    this.el.classList.add('nap');  this.vx = 0; this.next = 150 + (Math.random()*120|0); this.naptime(); break;
    case 'dig':    this.el.classList.add('snap'); this.vx = 0; this.next = 70; this.digSand(); break;
    case 'bonk':   this.el.classList.add('snap'); this.vx = 0; this.next = 18 + (Math.random()*12|0); this.dizzy(); break;
    case 'flipped':this.el.classList.add('flipped'); this.vx = 0; this.next = 80 + (Math.random()*90|0); this.dizzy(); break;
    // ── new random events ──
    case 'castle': this.el.classList.add('snap'); this.vx = 0; this.next = 130; this.sandcastle(); break;          // build then SMASH it
    case 'treasure': this.el.classList.add('wave'); this.vx = 0; this.next = 90; this.treasure(); break;           // hold up a shiny
    case 'fish':   this.el.classList.add('snap'); this.vx = 0; this.next = 90; this.fishBy(); break;               // snap at a passing fish
    case 'gull':   this.el.classList.add('duck'); this.vx = 0; this.next = 70; this.gullShadow(); break;           // duck a gull shadow
    case 'hermit': this.el.classList.add('wave'); this.vx = 0; this.next = 100; this.hermitShell(); break;         // try on a shell
    case 'chase':  this.el.classList.add('dance','walk'); this.vx = 0; this.next = 80; this.chaseBubble(); break;  // chase a bubble
    case 'tide':   this.el.classList.add('hop'); this.vx = 0; this.next = 60; this.tideWave(); break;              // hop a tide ripple
    case 'burrow': this.el.classList.add('snap'); this.vx = 0; this.next = 90; this.burrow(); break;               // dig under, pop up elsewhere
    // ── 10 more random behaviors ──
    case 'shuffle':  this.el.classList.add('shuffle'); this.vx = 0; this.next = 96; break;                          // sidestep shuffle-dance (moved in frame())
    case 'peek':     this.el.classList.add('peek');    this.vx = 0; this.next = 100; this.peekHole(); break;        // dig a hole, peek out
    case 'jet':      this.el.classList.add('snap');    this.vx = 0; this.next = 56; this.bubbleJet(); break;        // angry sideways bubble stream
    case 'sunbathe': this.el.classList.add('sunbathe');this.vx = 0; this.next = 150; this.sunbathe(); break;        // lean back, claws up, sun overhead
    case 'drum':     this.el.classList.add('drum');    this.vx = 0; this.next = 90; this.clawDrum(); break;         // claw-drum a rhythm
    case 'snipbub':  this.el.classList.add('snipbub'); this.vx = 0; this.next = 70; this.snipBubble(); break;       // snip at a drifting bubble
    case 'flag':     this.el.classList.add('flag');    this.vx = 0; this.next = 110; this.tinyFlag(); break;        // wave a tiny defiant flag
    case 'jolt':     this.el.classList.add('jolt');    this.vx = 0; this.next = 30; this.joltStartle(); break;      // startle, then scuttle off
    case 'pinchair': this.el.classList.add('pinchair');this.vx = 0; this.next = 78; this.anger(); break;            // jab and pinch the air
    case 'victory':  this.el.classList.add('victory'); this.vx = 0; this.next = 96; this.confetti(); break;         // defiant little victory dance
    case 'idle':   this.vx = 0; this.next = 50 + (Math.random()*70|0); break;
    case 'bubble': this.el.classList.add('snap'); this.vx=0; this.next = 30; this.bubbles(); break;
    case 'climb':  this.el.classList.add('crawl'); break;
    case 'ceil':   this.el.classList.add('crawl'); break;
    case 'fall':   break;
  }
  this._applyTransform();
};

Crab.prototype.pickState = function(){
  // climb/ceil/fall/seek/toshrimp/bonk/flipped run their own course; eating is driven
  // by a real shrimp appearing (not picked at random here).
  if(this.state==='climb'||this.state==='ceil'||this.state==='fall'||this.state==='seek'||
     this.state==='toshrimp'||this.state==='bonk'||this.state==='flipped'||this.dragging) return;
  var r = Math.random();
  if(r < 0.32)        this.setState('walk');    // calm ambling stays dominant
  else if(r < 0.40)   this.setState('snap');
  else if(r < 0.45)   this.setState('rage');
  else if(r < 0.50)   this.setState('charge');
  else if(r < 0.545)  this.setState('wave');
  else if(r < 0.59)   this.setState('dance');
  else if(r < 0.63)   this.setState('nap');
  else if(r < 0.66)   this.setState('dig');
  else if(r < 0.685)  this.setState('castle');
  else if(r < 0.71)   this.setState('treasure');
  else if(r < 0.732)  this.setState('fish');
  else if(r < 0.754)  this.setState('gull');
  else if(r < 0.776)  this.setState('hermit');
  else if(r < 0.798)  this.setState('chase');
  else if(r < 0.815)  this.setState('tide');
  else if(r < 0.825)  this.setState('burrow');
  else if(r < 0.84)   this.setState('bubble');
  // ── 10 new behaviors, small probability each ──
  else if(r < 0.858)  this.setState('shuffle');
  else if(r < 0.876)  this.setState('peek');
  else if(r < 0.894)  this.setState('jet');
  else if(r < 0.910)  this.setState('sunbathe');
  else if(r < 0.928)  this.setState('drum');
  else if(r < 0.946)  this.setState('snipbub');
  else if(r < 0.962)  this.setState('flag');
  else if(r < 0.976)  this.setState('jolt');
  else if(r < 0.990)  this.setState('pinchair');
  else                this.setState('victory');
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
// The crab is now SILENT — no text bubbles. speak() is a no-op kept so the many
// call sites stay harmless; it expresses itself purely through visual fx instead.
Crab.prototype.speak = function(){ /* no text */ };
Crab.prototype.anger = function(){
  if(this._dead || document.hidden) return;
  var a = document.createElement('div');
  a.className = 'cc-anger'; a.setAttribute('data-pet','crab'); a.textContent = '💢';
  a.style.left = (this.x + (Math.random()<0.5? 4 : this.W-18)) + 'px';
  a.style.top  = (this.y - 6) + 'px';
  document.body.appendChild(a);
  var self=this; this._after(750, function(){ if(a.parentNode) a.parentNode.removeChild(a); });
};
Crab.prototype.bubbles = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  for(var i=0;i<5;i++){ (function(n){ self._after(n*120, function(){
    var b = document.createElement('div'); b.className='cc-bub'; b.setAttribute('data-pet','crab');
    var sz = 5 + (Math.random()*7|0);
    b.style.width=sz+'px'; b.style.height=sz+'px';
    b.style.left = (self.x + 20 + Math.random()*44) + 'px';
    b.style.top  = (self.y + 6) + 'px';
    b.style.animationDuration = (0.9 + Math.random()*0.7) + 's';
    document.body.appendChild(b);
    self._after(1700, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
  }); })(i); }
};
// 🦐 a real shrimp pops up at a random spot on the floor. The crab spots it
// (toshrimp), walks over, and eats it (chompShrimp). One shrimp at a time.
Crab.prototype.spawnShrimp = function(){
  if(this._dead || this._shrimp) return;
  var sh = document.createElement('div');
  sh.className = 'cc-shrimp pop'; sh.setAttribute('data-pet','crab'); sh.textContent = '🦐';
  // a random spot along the floor (kept a little off the edges)
  var sx = 24 + Math.random()*Math.max(40, this.screenW - this.W - 48);
  this._shrimpX = sx + 9;                                   // ~center of the emoji
  sh.style.left = sx + 'px';
  sh.style.top  = (this._floorY() + this.H - 18) + 'px';
  document.body.appendChild(sh);
  this._shrimp = sh;
  this._shrimpTtl = 1700 + (Math.random()*900|0);           // ~28–43s before it wanders off if ignored
  if(Math.random()<0.5) this.speak(Math.random()<0.5?'ooh, a shrimp':'shrimp!', true);
};
Crab.prototype.removeShrimp = function(){
  var sh = this._shrimp; this._shrimp = null; this._shrimpTtl = 0;
  if(!sh) return;
  sh.style.transform = 'scale(.2)'; sh.style.opacity = '0';
  var self=this; this._after(320, function(){ if(sh.parentNode) sh.parentNode.removeChild(sh); });
};
// chomp the shrimp the crab walked up to — shrink it away, then "nom".
Crab.prototype.chompShrimp = function(){
  if(this._dead) return;
  var self=this, sh=this._shrimp;
  if(!sh){ this.setState('walk'); return; }                 // nothing to eat (it left)
  this._after(420, function(){ if(sh.parentNode){ sh.style.transform='scale(.6)';  sh.style.opacity='.6';  } });
  this._after(780, function(){ if(sh.parentNode){ sh.style.transform='scale(.22)'; sh.style.opacity='.15'; } });
  this._after(1080,function(){ if(sh.parentNode) sh.parentNode.removeChild(sh); if(self._shrimp===sh){ self._shrimp=null; self._shrimpTtl=0; } self.speak(['nom nom','yum','tasty','🦐'][Math.random()*4|0], true); });
};
// little ✦/💫 stars spin off the crab's head when it bonks a wall or flips over.
Crab.prototype.dizzy = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  for(var i=0;i<3;i++){ (function(n){ self._after(n*130, function(){
    var d=document.createElement('div'); d.className='cc-dizzy'; d.setAttribute('data-pet','crab'); d.textContent=(n%2?'✦':'💫');
    d.style.left=(self.x + self.W*0.3 + n*10)+'px'; d.style.top=(self.y - 8)+'px';
    document.body.appendChild(d);
    self._after(900, function(){ if(d.parentNode) d.parentNode.removeChild(d); });
  }); })(i); }
};
// drowsy Zzz drift up while the crab naps.
Crab.prototype.naptime = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  for(var i=0;i<3;i++){ (function(n){ self._after(n*700, function(){
    var z=document.createElement('div'); z.className='cc-zzz'; z.setAttribute('data-pet','crab'); z.textContent='z';
    z.style.fontSize=(11+n*3)+'px';
    z.style.left=(self.x + self.W*0.66)+'px'; z.style.top=(self.y - 4)+'px';
    document.body.appendChild(z);
    self._after(1300,function(){ if(z.parentNode) z.parentNode.removeChild(z); });
  }); })(i); }
};
// kicks up little sand grains while digging.
Crab.prototype.digSand = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  for(var i=0;i<6;i++){ (function(){ self._after(i*90, function(){
    var d=document.createElement('div'); d.className='cc-sand'; d.setAttribute('data-pet','crab');
    var sz=3+(Math.random()*3|0); d.style.width=sz+'px'; d.style.height=sz+'px';
    d.style.left=(self.x + self.W*0.5 + (Math.random()*30-15))+'px';
    d.style.top =(self.y + self.H - 6)+'px';
    document.body.appendChild(d);
    self._after(700,function(){ if(d.parentNode) d.parentNode.removeChild(d); });
  }); })(); }
};
// 🏰 builds a tiny sandcastle, admires it, then smashes it in a fit.
Crab.prototype.sandcastle = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  var c=document.createElement('div'); c.className='cc-castle'; c.setAttribute('data-pet','crab'); c.textContent='🏰';
  c.style.left=(this.x + (this.dir>0?this.W-8:-14))+'px'; c.style.top=(this.y + this.H - 24)+'px';
  c.style.transform='scale(0)'; document.body.appendChild(c);
  this._after(40,  function(){ c.style.transform='scale(1)'; });
  this._after(900, function(){ if(c.parentNode){ c.style.transform='scale(.2) rotate(40deg)'; c.style.opacity='0'; self.anger(); self.digSand(); } });
  this._after(1300,function(){ if(c.parentNode) c.parentNode.removeChild(c); });
};
// 💎 proudly holds up a shiny it found.
Crab.prototype.treasure = function(){
  if(this._dead || document.hidden) return;
  var t=document.createElement('div'); t.className='cc-treasure'; t.setAttribute('data-pet','crab'); t.textContent=Math.random()<0.5?'💎':'🪙';
  t.style.left=(this.x + this.W*0.5 - 8)+'px'; t.style.top=(this.y - 14)+'px';
  document.body.appendChild(t);
  this._after(1500, function(){ if(t.parentNode) t.parentNode.removeChild(t); });
};
// 🐟 a fish drifts past; the crab snaps at it.
Crab.prototype.fishBy = function(){
  if(this._dead || document.hidden) return;
  var self=this, d=this.dir;
  var f=document.createElement('div'); f.className='cc-fish'; f.setAttribute('data-pet','crab'); f.textContent='🐟';
  f.style.left=(this.x + (d>0 ? this.W+34 : -42))+'px'; f.style.top=(this.y + this.H*0.28)+'px';
  if(d>0) f.style.transform='scaleX(-1)';
  document.body.appendChild(f);
  this._after(30,  function(){ f.style.transition='left 1.1s ease,opacity .3s'; f.style.left=(self.x + (d>0?-42:self.W+34))+'px'; });
  this._after(1250,function(){ f.style.opacity='0'; });
  this._after(1600,function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};
// 🦅 a gull shadow sweeps over; the crab ducks (handled by the .duck class).
Crab.prototype.gullShadow = function(){
  if(this._dead || document.hidden) return;
  var self=this, fromLeft=Math.random()<0.5;
  var g=document.createElement('div'); g.className='cc-gull'; g.setAttribute('data-pet','crab');
  g.style.top=(this.y + this.H - 7)+'px'; g.style.left=(fromLeft ? this.x-50 : this.x+this.W+50)+'px';
  document.body.appendChild(g);
  this._after(30,  function(){ g.style.transition='left 1.2s linear,opacity .4s'; g.style.left=(fromLeft ? self.x+self.W+50 : self.x-50)+'px'; });
  this._after(1300,function(){ if(g.parentNode) g.parentNode.removeChild(g); });
};
// 🐚 tries on a different shell for a moment.
Crab.prototype.hermitShell = function(){
  if(this._dead || document.hidden) return;
  var s=document.createElement('div'); s.className='cc-shell'; s.setAttribute('data-pet','crab'); s.textContent='🐚';
  s.style.left=(this.x + this.W*0.5 - 9)+'px'; s.style.top=(this.y - 4)+'px';
  document.body.appendChild(s);
  this._after(1600, function(){ if(s.parentNode) s.parentNode.removeChild(s); });
};
// 🫧 chases a drifting bubble (excited shuffle via the .dance class).
Crab.prototype.chaseBubble = function(){
  if(this._dead || document.hidden) return;
  var b=document.createElement('div'); b.className='cc-bub'; b.setAttribute('data-pet','crab');
  b.style.width='9px'; b.style.height='9px';
  b.style.left=(this.x + this.W*0.55)+'px'; b.style.top=(this.y - 4)+'px';
  b.style.animationDuration='1.4s';
  document.body.appendChild(b);
  this._after(1500, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
};
// 🌊 a tide ripple sweeps the floor; the crab hops it (via the .hop class).
Crab.prototype.tideWave = function(){
  if(this._dead || document.hidden) return;
  var self=this, fromLeft=Math.random()<0.5;
  var w=document.createElement('div'); w.className='cc-tide'; w.setAttribute('data-pet','crab');
  w.style.top=(this._floorY() + this.H - 7)+'px'; w.style.left=(fromLeft ? -70 : this.screenW)+'px';
  document.body.appendChild(w);
  this._after(30,  function(){ w.style.transition='left 1.6s ease-in-out,opacity .5s'; w.style.left=(fromLeft ? self.screenW : -70)+'px'; });
  this._after(1700,function(){ if(w.parentNode) w.parentNode.removeChild(w); });
};
// 🕳️ digs straight under, vanishes, and pops up somewhere else on the floor.
Crab.prototype.burrow = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  this.digSand();
  this.el.classList.add('burrow');                       // CSS fades it out
  this._after(560, function(){
    self.x = 24 + Math.random()*Math.max(40, self.screenW - self.W - 48);
    self.el.style.left = self.x + 'px';
    self.el.classList.remove('burrow');                  // fade back in
    self.digSand();
  });
};

// 1. 🕳️ a little hole the crab is peeking out of (kicks sand up, then watches).
Crab.prototype.peekHole = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  this.digSand();
  var h=document.createElement('div'); h.className='cc-hole'; h.setAttribute('data-pet','crab');
  h.style.left=(this.x + this.W*0.5 - 23)+'px'; h.style.top=(this.y + this.H - 7)+'px';
  document.body.appendChild(h);
  this._after(900, function(){ self.anger(); });          // grumpy peek
  this._after(1700, function(){ if(h.parentNode) h.parentNode.removeChild(h); });
};
// 2. 🫧 an angry sideways stream of bubbles jetting out the front.
Crab.prototype.bubbleJet = function(){
  if(this._dead || document.hidden) return;
  var self=this, d=this.dir;
  for(var i=0;i<7;i++){ (function(n){ self._after(n*70, function(){
    var b=document.createElement('div'); b.className='cc-jet'; b.setAttribute('data-pet','crab');
    var sz=4+(Math.random()*6|0); b.style.width=sz+'px'; b.style.height=sz+'px';
    b.style.left=(self.x + (d>0?self.W-10:6))+'px'; b.style.top=(self.y + self.H*0.4 + (Math.random()*8-4))+'px';
    b.style.setProperty('--jx', (d * (32+Math.random()*28))+'px');
    b.style.animationDuration=(0.7+Math.random()*0.5)+'s';
    document.body.appendChild(b);
    self._after(1400, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
  }); })(i); }
};
// 3. ☀️ sunbathes (leans back, claws behind head) while a sun beats down.
Crab.prototype.sunbathe = function(){
  if(this._dead || document.hidden) return;
  var su=document.createElement('div'); su.className='cc-sun'; su.setAttribute('data-pet','crab'); su.textContent='☀️';
  su.style.left=(this.x + this.W*0.5 - 8)+'px'; su.style.top=(this.y - 22)+'px';
  document.body.appendChild(su);
  this._after(2400, function(){ if(su.parentNode) su.parentNode.removeChild(su); });
};
// 4. 🎵 drums a rhythm with its claws, musical notes popping off.
Crab.prototype.clawDrum = function(){
  if(this._dead || document.hidden) return;
  var self=this;
  for(var i=0;i<5;i++){ (function(n){ self._after(n*170, function(){
    var m=document.createElement('div'); m.className='cc-note'; m.setAttribute('data-pet','crab'); m.textContent=(n%2?'♪':'♫');
    m.style.left=(self.x + self.W*0.5 + (Math.random()*24-12))+'px'; m.style.top=(self.y - 6)+'px';
    document.body.appendChild(m);
    self._after(1000, function(){ if(m.parentNode) m.parentNode.removeChild(m); });
  }); })(i); }
};
// 5. 🫧 a single bubble drifts up past the crab, which snips at it.
Crab.prototype.snipBubble = function(){
  if(this._dead || document.hidden) return;
  var self=this, d=this.dir;
  var b=document.createElement('div'); b.className='cc-bub'; b.setAttribute('data-pet','crab');
  b.style.width='11px'; b.style.height='11px';
  b.style.left=(this.x + (d>0?this.W-6:-4))+'px'; b.style.top=(this.y + 4)+'px';
  b.style.animationDuration='1.1s';
  document.body.appendChild(b);
  this._after(620, function(){ self.anger(); });          // missed it — angy
  this._after(1300, function(){ if(b.parentNode) b.parentNode.removeChild(b); });
};
// 6. 🚩 hoists a tiny defiant flag and waves it.
Crab.prototype.tinyFlag = function(){
  if(this._dead || document.hidden) return;
  var f=document.createElement('div'); f.className='cc-flag'; f.setAttribute('data-pet','crab'); f.textContent='🚩';
  f.style.left=(this.x + (this.dir>0?this.W-10:0))+'px'; f.style.top=(this.y - 8)+'px';
  document.body.appendChild(f);
  this._after(1700, function(){ if(f.parentNode) f.parentNode.removeChild(f); });
};
// 7. ❗ jolts in alarm with an exclamation, then bolts (handled in frame()).
Crab.prototype.joltStartle = function(){
  if(this._dead || document.hidden) return;
  var j=document.createElement('div'); j.className='cc-jolt'; j.setAttribute('data-pet','crab'); j.textContent='!';
  j.style.left=(this.x + this.W*0.5 - 4)+'px'; j.style.top=(this.y - 16)+'px';
  document.body.appendChild(j);
  this._after(600, function(){ if(j.parentNode) j.parentNode.removeChild(j); });
};
// 8. 🎉 flings a burst of confetti for a defiant little victory dance.
Crab.prototype.confetti = function(){
  if(this._dead || document.hidden) return;
  var self=this, cols=['#ff2b1f','#ffce1f','#3fb0ff','#6bff8f','#ff6bd0'];
  for(var i=0;i<10;i++){ (function(n){ self._after(20 + (n*30), function(){
    var c=document.createElement('div'); c.className='cc-confetti'; c.setAttribute('data-pet','crab');
    c.style.background=cols[n%cols.length];
    c.style.left=(self.x + self.W*0.5 - 2)+'px'; c.style.top=(self.y + 4)+'px';
    c.style.setProperty('--cx', (Math.random()*44-22)+'px');
    c.style.setProperty('--cy', (-18 - Math.random()*22)+'px');
    document.body.appendChild(c);
    self._after(1100, function(){ if(c.parentNode) c.parentNode.removeChild(c); });
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
  this._shrimp = null;
  // sweep any stray fx — by the shared marker attribute (catches any future cc-*
  // node even if it isn't in the hand-maintained class list) plus the classes.
  var stray = document.querySelectorAll('[data-pet="crab"], .cc-bub, .cc-anger, .cc-shrimp, .cc-zzz, .cc-sand, .cc-dizzy, .cc-castle, .cc-treasure, .cc-fish, .cc-gull, .cc-shell, .cc-tide, .cc-hole, .cc-jet, .cc-sun, .cc-note, .cc-flag, .cc-jolt, .cc-confetti');
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
