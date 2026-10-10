'use strict';
// W9 SITE GUARD. Checks the three marketing pages for the defect classes that
// have actually bitten this project, and emits the rule 37 output contract so a
// push script can consume it.
//
//   node w9-guard.js <dir>     checks index.html, landing.html, product.html in dir
//   node w9-guard.js <file>    checks one page
//
// Last two lines are always exactly:
//     checks passed N of N
//   GUARD PASS            (or GUARD FAIL)
// exit 0 on pass, 1 on fail. A missing input gives named check W0, one
// "checks passed 0 of 1" line, GUARD FAIL, exit 1 and ZERO stack frames, per
// rule 76: a stack trace reads as a crash rather than a verdict.
//
// WHY A GUARD AT ALL. Across SITE28 to SITE35 the recurring failures are stale
// pinned values, selectors that look dead but are not, false or orphaned
// comments, a missing icon link, secret shaped literals, dashes in copy, and
// aggregateRating. Every one of those is mechanically detectable. Nothing was
// checking for them, so each was found by hand, once, after it shipped.
//
// FIVE CORRECTIONS MEASURED BEFORE THIS FILE WAS WRITTEN. Each was a wrong
// result from my own first draft of these checks, so each is a check that would
// have reported a defect that does not exist, or missed one that does.
//
//  1. BRACE COUNTING STRIPS COMMENTS FIRST. Landing's CSS reported depth -1 and
//     looked unbalanced. The imbalance is a brace inside a CSS COMMENT, itself a
//     note from drop S110 about two missing @media opening lines. Comment
//     stripped, landing is balanced. Counting raw would fail a sound page.
//
//  2. FIVE DECLARATION FORMS, NOT ONE. Looking only for "function NAME(" said 7
//     of product's inline handlers named functions that do not exist. They are
//     declared as window.psShow=function(...). Measured across the three pages:
//     index 50 plus 1, landing 43 plus 1 plus 1, product 33 plus 7 plus 2, every
//     declaration accounted for.
//
//  3. KEYFRAMES ARE CHECKED OVER CSS DECLARATIONS, NOT RUNNING ANIMATIONS. A
//     field check that asks whether every RUNNING animation has keyframes is
//     vacuous: a declaration with no keyframes never becomes an animation
//     object, so it cannot appear in getAnimations(). That is why ixDot, which
//     is declared on index and product with no @keyframes rule anywhere, passed
//     a browser check and is caught here.
//
//  4. THE ORPHAN LIST IS DERIVED, NEVER PINNED. Rule 80. SITE33 removed 20 dead
//     keyframes from index using a hand written list; a derived list finds 18
//     more still there, including the same 14 name v* family removed from
//     product at SITE34.
//
//  5. HANDLERS ARE READ FROM MARKUP AND FROM SCRIPT BUILT STRINGS. Landing's
//     osGo is wired by onclick="osGo('+i+')" inside a template built in script,
//     so a markup only scan does not see it.
//
// AND ONE DELIBERATE EXCLUSION. The secret check must not match e.key===, which
// is an ordinary keyboard comparison present once on every page. A guard that
// cries wolf on every run is a guard that gets ignored.

const path = require('path');

function die0(msg) {
  console.log('  W0  companion or input missing: ' + msg);
  console.log('  checks passed 0 of 1');
  console.log('GUARD FAIL');
  process.exit(1);
}

let fs, crypto, S, stripComments;
try {
  fs = require('fs');
  crypto = require('crypto');
  S = require(path.join(__dirname, 'cssscan.js'));
  ({ stripComments } = require(path.join(__dirname, 'stripcomments.js')));
} catch (e) { die0('cssscan.js or stripcomments.js beside this file'); }

const PAGES = ['index.html', 'landing.html', 'product.html'];
const target = process.argv[2];
if (!target) die0('no path given');
if (!fs.existsSync(target)) die0(target);

let files;
if (fs.statSync(target).isDirectory()) {
  files = PAGES.map(p => path.join(target, p)).filter(p => fs.existsSync(p));
  if (!files.length) die0('no page found in ' + target);
} else files = [target];

const md5 = s => crypto.createHash('md5').update(s, 'utf8').digest('hex');
const esc = t => String(t).replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');

// Lance's own business contact, allowlisted BY HASH so no plaintext contact
// appears in this file, in its output, or in any commit. Names as hashes,
// contacts by count. Pinned from the pages at d17623b.
// THE EXAMPLE DOMAIN FILTER IS ANCHORED TO A DOMAIN BOUNDARY. Unanchored,
// /example\.(com|org|net)$/ also matches notexample.org, so the sabotage case
// that planted stranger@notexample.org walked straight past W13 and the guard
// reported PASS. That was the suite's only ESCAPE, and it was a real hole in the
// check, not a bad test.
const CONTACT_ALLOW = new Set([
  '7483a07f14c03d03364b24df45941210',
  '46889ce315280c67fdc94ed87a71118b',
  '8a8e9681495464ba2aad630fe279e7a5'
]);

function readPage(file) {
  const h = fs.readFileSync(file, 'utf8');
  const css = S.allCss(h);
  const scripts = S.scriptBlocks(h).map(b => b.text).join('\n');
  return {
    name: path.basename(file), h,
    css, cssNoComments: css.replace(/\/\*[\s\S]*?\*\//g, ''),
    code: scripts, clean: stripComments(scripts),
    markup: S.markupOnly(h), blocks: S.styleBlocks(h)
  };
}

// CORRECTION 2: every declaration form, measured.
function declaredNames(clean) {
  const out = new Set();
  const forms = [
    /(?:^|[^\w$.])(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g,
    /window\s*\.\s*([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()/g,
    /(?:^|[^\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function/g,
    /(?:^|[^\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/g,
    /(?:^|[^\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?[A-Za-z_$][\w$]*\s*=>/g
  ];
  for (const re of forms) { let m; re.lastIndex = 0; while ((m = re.exec(clean))) out.add(m[1]); }
  return out;
}

// CORRECTION 5: handlers from markup AND from script built strings.
function handlerNames(p) {
  const out = new Set();
  const grab = src => {
    for (const m of src.matchAll(/\bon(?:click|change|input|submit|keydown|keyup)\s*=\s*\\?("|')([\s\S]*?)\\?\1/gi)) {
      const fn = (m[2].trim().match(/^([A-Za-z_$][\w$]*)\s*\(/) || [])[1];
      if (fn && !/^(this|window|document|event|return)$/.test(fn)) out.add(fn);
    }
  };
  grab(p.markup);
  grab(p.clean);
  return out;
}

function keyframeFacts(p) {
  const declared = new Set([...p.cssNoComments.matchAll(/@(?:-webkit-)?keyframes\s+([A-Za-z_][\w-]*)/g)].map(m => m[1]));
  // Names USED in any animation shorthand or animation-name, anywhere.
  const used = new Set();
  const take = v => v.split(',').forEach(part => {
    const t = part.trim().split(/\s+/)[0];
    if (t && /^[A-Za-z_][\w-]*$/.test(t) && !/^(none|inherit|initial|unset|revert|normal|alternate|infinite|linear|ease|ease-in|ease-out|ease-in-out|both|forwards|backwards|running|paused)$/.test(t)) used.add(t);
  });
  for (const m of p.cssNoComments.matchAll(/animation(?:-name)?\s*:\s*([^;}]+)/g)) take(m[1]);
  for (const m of p.markup.matchAll(/animation(?:-name)?\s*:\s*([^;"']+)/g)) take(m[1]);
  for (const m of p.clean.matchAll(/animation(?:-name)?\s*:\s*([^;"'`]+)/g)) take(m[1]);
  // CORRECTION 4: orphans derived, never pinned.
  const referenced = new Set();
  for (const n of declared) {
    const tk = new RegExp('(?<![\\w-])' + esc(n) + '(?![\\w-])');
    if (used.has(n) || tk.test(p.markup) || tk.test(p.clean)) referenced.add(n);
  }
  return {
    declared, used, referenced,
    orphans: [...declared].filter(n => !referenced.has(n)),
    missing: [...used].filter(n => !declared.has(n))
  };
}

const balance = t => { let d = 0; for (const c of t) { if (c === '{') d++; else if (c === '}') d--; if (d < 0) return -1; } return d; };

// DECLARED EXCEPTIONS. A guard that stays red on a known, deliberately unfixed
// defect gets ignored, which is the same failure as a check that cries wolf. But
// an exception that hides a defect is worse than no check. So an exception must
// name the page, state the reason, carry the date it was accepted, and PRINT on
// every run. It counts as passed, and the summary reports how many are in force
// so they cannot be quietly forgotten.
// NO EXCEPTIONS ARE IN FORCE. One was drafted for W6 on index, excusing the
// empty @media(max-width:700px) wrapper on the grounds that its S110 recovery
// note was a breadcrumb for a live bug between 481 and 700px. CHECKING THAT
// REASON SHOWED IT WAS FALSE: index has zero phone demo code, no pd- and no lp-
// in script or markup, and .lp-mob-active and .lp-phone appear only inside
// comment text, never as selectors. The note records a version that is gone, so
// the wrapper is residue like the rest, SITE35 section G removes it, and the
// exception was deleted rather than shipped. The mechanism stays because a
// future accepted defect must be declared loudly rather than left to rot the
// guard red, but an exception whose reason is wrong is worse than no check.
const EXCEPTIONS = [];

const checks = [];
const C = (id, label, fn) => checks.push([id, label, fn]);

C('W1', 'every page has at least one rel=icon link', ps =>
  ps.filter(p => [...p.h.matchAll(/<link[^>]*rel\s*=\s*("|')[^"']*icon[^"']*\1/gi)].length === 0).map(p => p.name));

C('W2', 'zero en or em dashes in any page', ps =>
  ps.filter(p => (p.h.match(/[‐-―−]/g) || []).length > 0).map(p => p.name));

C('W3', 'aggregateRating is never populated with a ratingValue', ps =>
  ps.filter(p => /aggregateRating[\s\S]{0,300}ratingValue/.test(p.h)).map(p => p.name));

C('W4', 'no PIN, key, token or secret literal, and e.key=== is not a hit', ps =>
  ps.filter(p => /(?:api[_-]?key|client[_-]?secret|\bsecret\s*[:=]|bearer\s+[A-Za-z0-9._-]{12,}|\bpin\s*[:=]\s*["']?\d{4,})/i.test(p.h)).map(p => p.name));

C('W5', 'CSS braces balanced in every style block, comments stripped first', ps =>
  ps.filter(p => !p.blocks.every(b => balance(b.text.replace(/\/\*[\s\S]*?\*\//g, '')) === 0)).map(p => p.name));

C('W6', 'no empty at rule left behind', ps =>
  ps.filter(p => /@(?:media|supports|container|layer)\b[^{]*\{\s*\}/.test(p.cssNoComments)).map(p => p.name));

C('W7', 'every animation name used has a @keyframes rule', ps =>
  ps.filter(p => keyframeFacts(p).missing.length)
    .map(p => p.name + ' [' + keyframeFacts(p).missing.join(', ') + ']'));

C('W8', 'zero orphaned keyframes, derived not pinned', ps =>
  ps.filter(p => keyframeFacts(p).orphans.length)
    .map(p => p.name + ' [' + keyframeFacts(p).orphans.length + ': ' + keyframeFacts(p).orphans.slice(0, 6).join(', ') + (keyframeFacts(p).orphans.length > 6 ? ', ...' : '') + ']'));

C('W9', 'every inline handler names a declared function', ps =>
  ps.filter(p => { const d = declaredNames(p.clean); return [...handlerNames(p)].some(n => !d.has(n)); })
    .map(p => { const d = declaredNames(p.clean); return p.name + ' [' + [...handlerNames(p)].filter(n => !d.has(n)).join(', ') + ']'; }));

C('W10', 'no CSS comment claims a library the page does not load', ps =>
  ps.filter(p => {
    const gsap = /gsap\.min\.js|GSAPScrollTrigger/i.test(p.h), lenis = /lenis\.min\.js|new\s+Lenis/i.test(p.h);
    return [...p.css.matchAll(/\/\*[\s\S]*?\*\//g)].some(m => (/gsap/i.test(m[0]) && !gsap) || (/lenis/i.test(m[0]) && !lenis));
  }).map(p => p.name));

C('W11', 'zero dynamic dispatch, so W9 stays a real verdict', ps =>
  ps.filter(p => /window\s*\[|(?<![\w$])eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*["']/.test(p.clean)).map(p => p.name));

C('W12', 'every page has a canonical link', ps =>
  ps.filter(p => (p.h.match(/<link[^>]*rel\s*=\s*("|')canonical\1/gi) || []).length !== 1).map(p => p.name));

C('W13', 'the only real contact is the allowlisted one, matched by hash', ps =>
  ps.filter(p => {
    const emails = [...p.h.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)].map(m => m[0])
      .filter(e => !/(?:^|@|\.)example\.(?:com|org|net)$/i.test(e) && !/@(?:schema|sentry|cloudflare)\./i.test(e));
    const phones = [...p.h.matchAll(/(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g)].map(m => m[0])
      .filter(t => !/555[\s.-]?01\d\d/.test(t));
    const bad = [...emails, ...phones].filter(v => !CONTACT_ALLOW.has(md5(v.replace(/[^\w@.+]/g, '').toLowerCase())));
    return bad.length > 0;
  }).map(p => p.name + ' [' + 'unallowlisted contacts by count: ' + (() => {
    const emails = [...p.h.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)].map(m => m[0]).filter(e => !/(?:^|@|\.)example\.(?:com|org|net)$/i.test(e) && !/@(?:schema|sentry|cloudflare)\./i.test(e));
    const phones = [...p.h.matchAll(/(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g)].map(m => m[0]).filter(t => !/555[\s.-]?01\d\d/.test(t));
    return [...emails, ...phones].filter(v => !CONTACT_ALLOW.has(md5(v.replace(/[^\w@.+]/g, '').toLowerCase()))).length;
  })() + ']'));

// W14's helper. A declared function is LIVE if it is referenced outside its own
// body OR if it is immediately invoked. The IIFE case is not optional: 11 of the
// 13 zero reference functions found on these pages are named IIFEs, including
// index's initOSFeed which drives the live feed. Treating those as dead would
// have deleted 19,300 chars of running code, so this check is only safe with the
// IIFE test in it.
function deadFunctions(p) {
  const clean = p.clean;
  const dead = [];
  const re = /(?:^|[^\w$.])function\s+([A-Za-z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = re.exec(clean))) {
    const name = m[1];
    const open = clean.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    let i = open, d = 0, end = clean.length;
    for (; i < clean.length; i++) {
      const c = clean[i];
      if (c === '{') d++;
      else if (c === '}') { d--; if (d === 0) { end = i + 1; break; } }
    }
    // immediately invoked, either (function f(){})() or (function f(){}())
    const after = clean.slice(end, end + 10);
    const declStart = clean.slice(Math.max(0, m.index), m.index + m[0].length);
    const openParen = /\(\s*(?:async\s+)?function\s*$/.test(clean.slice(Math.max(0, m.index - 4), m.index + m[0].length - name.length - 1));
    if (/^\s*\)\s*\(/.test(after) || /^\s*\(\s*\)/.test(after) || openParen) continue;
    const outside = clean.slice(0, m.index) + '\n' + clean.slice(end);
    const tk = new RegExp('(?<![\\w$])' + esc(name) + '(?![\\w$])', 'g');
    const refs = (outside.match(tk) || []).length + (p.markup.match(tk) || []).length;
    if (refs === 0) dead.push(name + ' (' + (end - m.index) + ' chars)');
  }
  return dead;
}

C('W14', 'every declared function is referenced or immediately invoked', ps =>
  ps.filter(p => deadFunctions(p).length).map(p => p.name + ' [' + deadFunctions(p).join(', ') + ']'));

const pages = files.map(readPage);

let passed = 0;
console.log('===== W9 SITE GUARD =====');
console.log('  pages checked: ' + pages.map(p => p.name).join(', '));
console.log('');
let excused = 0;
for (const [id, label, fn] of checks) {
  let offenders;
  try { offenders = fn(pages); } catch (e) { offenders = ['check threw: ' + e.message.slice(0, 80)]; }
  const exc = EXCEPTIONS.filter(x => x.id === id);
  const remaining = offenders.filter(o => !exc.some(x => String(o).startsWith(x.page)));
  const ok = remaining.length === 0;
  const usedExc = exc.filter(x => offenders.some(o => String(o).startsWith(x.page)));
  if (ok) passed++;
  console.log('  ' + (ok ? (usedExc.length ? 'ok* ' : 'ok  ') : 'FAIL') + '  ' + id + '  ' + label);
  remaining.forEach(o => console.log('           ' + o));
  for (const x of usedExc) {
    excused++;
    console.log('           EXCEPTION ' + x.page + ', accepted ' + x.since);
    x.why.replace(/(.{1,74})(\s|$)/g, '$1\n').trim().split('\n').forEach(l => console.log('             ' + l.trim()));
  }
}
console.log('  exceptions in force ' + excused);
console.log('  checks passed ' + passed + ' of ' + checks.length);
console.log(passed === checks.length ? 'GUARD PASS' : 'GUARD FAIL');
process.exit(passed === checks.length ? 0 : 1);
