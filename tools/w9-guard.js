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
    name: path.basename(file), dir: path.dirname(file), h,
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

// DUPLICATE ATTRIBUTE TOKENIZER, for W15.
//
// WHY A STATE MACHINE AND NOT A PATTERN. A regex over attributes cannot tell a
// `>` inside a quoted value from the end of a tag, cannot skip script and style
// bodies, and cannot normalise attribute name case. Three scanners in this
// project have already been fooled by content that merely resembled what they
// matched, most recently one that read the hex colours #F2F4F6 and #F7F8F5 as
// Canadian postal codes. This one was built against a 21 case trap suite and
// cross checked against an independent tokenizer on all three pages, which
// agreed exactly.
//
// LIMITS, stated where they are used, per rule 121. It reports MARKUP only.
// A duplicate inside a string that script later injects is a real defect too,
// but nothing can distinguish an injected fragment from an example in a comment,
// so those are out of scope rather than silently counted clean. Attribute names
// compare case insensitively, which is how HTML treats them.
function dupAttrs(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  const lineAt = (q) => { let l = 1; for (let k = 0; k < q; k++) if (src.charCodeAt(k) === 10) l++; return l; };
  while (i < n) {
    const lt = src.indexOf('<', i);
    if (lt < 0) break;
    i = lt;
    if (src.startsWith('<!--', i)) { const e = src.indexOf('-->', i + 4); i = e < 0 ? n : e + 3; continue; }
    if (src.startsWith('<!', i))   { const e = src.indexOf('>', i + 2);   i = e < 0 ? n : e + 1; continue; }
    if (src.startsWith('</', i))   { const e = src.indexOf('>', i + 2);   i = e < 0 ? n : e + 1; continue; }
    // a letter is required, which is what keeps "a < b" in text from reading as a tag
    if (!/[a-zA-Z]/.test(src[i + 1] || '')) { i = lt + 1; continue; }
    let p = i + 1;
    while (p < n && /[^\s/>]/.test(src[p])) p++;
    const tag = src.slice(i + 1, p).toLowerCase();
    const seen = new Map();
    while (p < n) {
      while (p < n && /\s/.test(src[p])) p++;
      if (p >= n) break;
      if (src[p] === '>') { p++; break; }
      if (src[p] === '/') {
        let q = p + 1; while (q < n && /\s/.test(src[q])) q++;
        if (src[q] === '>') { p = q + 1; break; }
        p++; continue;
      }
      const ns = p;
      while (p < n && !/[\s=/>]/.test(src[p])) p++;
      const name = src.slice(ns, p).toLowerCase();
      let q = p; while (q < n && /\s/.test(src[q])) q++;
      let value = null;
      if (src[q] === '=') {
        q++; while (q < n && /\s/.test(src[q])) q++;
        const ch = src[q];
        if (ch === '"' || ch === "'") {
          const e = src.indexOf(ch, q + 1);
          value = e < 0 ? src.slice(q + 1) : src.slice(q + 1, e);
          p = e < 0 ? n : e + 1;
        } else {
          const vs = q; while (q < n && !/[\s>]/.test(src[q])) q++;
          value = src.slice(vs, q); p = q;
        }
      }
      if (!name) { p++; continue; }
      if (!seen.has(name)) seen.set(name, []);
      seen.get(name).push(value);
    }
    for (const [name, vals] of seen) {
      if (vals.length > 1) out.push({ tag, name, values: vals, line: lineAt(i) });
    }
    if (tag === 'script' || tag === 'style') {
      const m = src.slice(p).match(new RegExp('</' + tag + '\\s*>', 'i'));
      i = m ? p + m.index + m[0].length : n;
    } else i = p;
  }
  return out;
}

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

// The dash class is written with \u escapes, not the characters themselves. A
// detector that must match en and em dashes would otherwise be the one file in
// every drop that breaks the no dashes rule, and an exception nobody can argue
// with is still an exception. The escapes are identical to the engine.
C('W2', 'zero en or em dashes in any page', ps =>
  ps.filter(p => (p.h.match(/[\u2010-\u2015\u2212]/g) || []).length > 0).map(p => p.name));

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

// W15. NO ELEMENT MAY CARRY THE SAME ATTRIBUTE TWICE.
//
// Every HTML parser keeps the FIRST occurrence and silently discards the rest,
// so a duplicate is a handler, class or source the author wrote and the browser
// never runs. It cannot be seen in a rendered page and it produces no console
// error, which is why index carried one for an unknown number of drops: a mobile
// menu item opened the builder modal and left the menu open behind it, because
// its second onclick, the one that closed the menu, was discarded.
//
// It surfaced only because a count in a brief disagreed with the page, six inline
// closeMenu handlers in the source against five live on it. Nothing in this guard
// would have caught it, which is the reason for this check.
C('W15', 'no element carries the same attribute twice', ps => {
  const bad = [];
  for (const p of ps) {
    for (const d of dupAttrs(p.h)) {
      bad.push(p.name + ' line ' + d.line + ' <' + d.tag + '> has ' + d.name +
               ' ' + d.values.length + ' times, only the first is used');
    }
  }
  return bad;
});

// SHARED INSTRUMENT FOR W16 AND W17. The ids and classes a page's own script
// creates. Both checks ask the same question from opposite ends, so they share one
// reader: W17 asks whether every id the script READS can exist, W16 asks whether
// every class the script WRITES can matter.
//
// WHY THESE TWO CHECKS EXIST. One rebuild of the hero and section markup, commits
// 90b727c, 6988358 and 4ebd5e6, left the runtime referring to markup that was gone.
// It produced the hero copy rewrite that never fired, every tagged LinkedIn and
// email click landing on generic copy, and it was silent because both lookups were
// guarded. It also produced 33 orphaned classes, 9 dead handles and 3990 characters
// of inert script. W17 would have caught the hero defect the day it landed.
//
// FOUR MEASURED CORRECTIONS, each one a wrong result from an earlier draft.
//
//  1. classList.remove IS NOT A READER. A class that something adds and something
//     removes, with no rule styling it and nothing testing it, is still dead. Only
//     contains, querySelector, querySelectorAll, closest and matches branch on a
//     class. Counting remove as a reader hid two real orphans on index.
//
//  2. A CLASS STYLED ONLY IN A FETCHED PAYLOAD IS NOT DEAD. landing creates
//     pd-body, which no page stylesheet mentions; it is styled inside the css field
//     of pd/hq.json, pd/psw.json and pd/fam.json. Those paths are DERIVED from the
//     page's own source rather than pinned here, per rule 127, and a payload the
//     page names but which is missing is reported, not silently ignored, because a
//     missing stylesheet source would turn every class it styles into a false
//     orphan.
//
//  3. A CONCATENATION PREFIX IS NOT A TOKEN. bldchip-, osni-, ix-msg- and friends
//     are built as 'bldchip-'+id. Treating them as class or id names produced four
//     false orphans across the three pages.
//
//  4. CLASS SELECTORS COME FROM RULE PRELUDES, PARSED, NOT FROM THE RAW STYLESHEET.
//     Testing a token against the whole stylesheet text matches decimal points, url
//     paths and strings: .w3 and .org both appeared as classes, out of w3.org. An
//     earlier fix that stripped quoted strings from the stylesheet destroyed 86
//     percent of it, 49237 characters down to 6988, and reported styled classes as
//     orphans. cssscan's rules() parser is used instead, which is brace aware and
//     strips comments while preserving offsets.
function createdTokens(p) {
  const classes = new Map(), ids = new Map();
  const add = (m, t, how) => { if (t && !m.has(t)) m.set(t, how); };
  const c = p.clean;
  for (const m of c.matchAll(/classList\s*\.\s*(?:add|toggle|replace)\(\s*["']([\w-]+)["']/g)) add(classes, m[1], 'classList');
  for (const m of c.matchAll(/class\s*=\s*\\?["']([^"'\\]+)/g)) m[1].split(/\s+/).forEach(t => add(classes, t, 'built string'));
  for (const m of c.matchAll(/className\s*=\s*["']([^"']*)["']/g)) m[1].split(/\s+/).forEach(t => add(classes, t, 'className'));
  for (const m of c.matchAll(/setAttribute\(\s*["']class["']\s*,\s*["']([^"']*)["']/g)) m[1].split(/\s+/).forEach(t => add(classes, t, 'setAttribute'));
  for (const m of c.matchAll(/id\s*=\s*\\?["']([A-Za-z][\w-]*)/g)) add(ids, m[1], 'built string');
  for (const m of c.matchAll(/\.id\s*=(?!=)\s*["']([\w-]+)["']/g)) add(ids, m[1], 'id assignment');
  for (const m of c.matchAll(/setAttribute\(\s*["']id["']\s*,\s*["']([\w-]+)["']/g)) add(ids, m[1], 'setAttribute');
  return { classes, ids };
}

// Every JSON payload this page names, read for extra stylesheet text and for the
// scope values it assigns as ids. Derived from the page, never pinned.
function payloadFacts(p) {
  const css = [], scopes = new Set(), missing = [];
  const rels = new Set([...p.h.matchAll(/["'`]([\w./-]*pd\/[\w.-]+\.json)["'`]/g)].map(m => m[1]));
  for (const rel of rels) {
    const f = path.join(p.dir, rel);
    if (!fs.existsSync(f)) { missing.push(rel); continue; }
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (typeof j.css === 'string') css.push(j.css);
      if (typeof j.scope === 'string') scopes.add(j.scope);
    } catch (e) { missing.push(rel + ' is not readable JSON'); }
  }
  return { css, scopes, missing };
}

// Class tokens that appear in a parsed rule prelude, from the page's stylesheets
// and from any payload stylesheet. At rule frames are skipped, their nested rules
// are not, so a class styled only inside a media query still counts.
function styledClasses(cssTexts) {
  const set = new Set();
  for (const text of cssTexts) {
    for (const r of S.rules(text)) {
      if (r.isAtRule) continue;
      for (const sel of S.selectorList(r.sel))
        for (const m of sel.matchAll(/\.([A-Za-z_][\w-]*)/g)) set.add(m[1]);
    }
  }
  return set;
}

const isConcatPrefix = (p, t) => /-$/.test(t) || p.h.indexOf("'" + t + "'+") >= 0 || p.h.indexOf('"' + t + '"+') >= 0;

function branchesOnClass(p, t) {
  const q = esc(t);
  return new RegExp('classList\\s*\\.\\s*contains\\(\\s*["\']' + q + '["\']').test(p.clean)
    || new RegExp('(?:querySelector(?:All)?|closest|matches)\\(\\s*["\'][^"\']{0,90}\\.' + q + '(?![\\w-])').test(p.clean);
}

// W16. A CLASS THE SCRIPT CREATES THAT NOTHING STYLES AND NOTHING BRANCHES ON.
C('W16', 'every class the script creates is styled or branched on', ps => {
  const bad = [];
  for (const p of ps) {
    const made = createdTokens(p).classes;
    const pay = payloadFacts(p);
    pay.missing.forEach(m => bad.push(p.name + ' names ' + m + ' but it is missing, so classes it styles cannot be verified'));
    const styled = styledClasses([p.css, ...pay.css]);
    const inMarkup = S.classTokens(p.h);
    for (const [t, how] of made) {
      if (styled.has(t) || inMarkup.has(t) || isConcatPrefix(p, t) || branchesOnClass(p, t)) continue;
      bad.push(p.name + ' class ' + t + ', created by ' + how + ', is styled by no rule and read by nothing');
    }
  }
  return bad;
});

// W17. A getElementById LITERAL THAT CANNOT RESOLVE.
// LIMIT, STATED WHERE IT IS USED, rule 121. An id assigned from an expression
// cannot be resolved statically. Two exist, both on landing: a style element id
// built as 'pd-css-' + id, which the concatenation prefix rule covers, and a screen
// id taken from a payload scope, which the payload scope values cover. Any future
// dynamic assignment that a literal read depends on will make this check FAIL
// rather than pass quietly, which is the correct direction for a guard.
C('W17', 'every getElementById literal resolves to markup or to a created id', ps => {
  const bad = [];
  for (const p of ps) {
    const { ids } = createdTokens(p);
    const pay = payloadFacts(p);
    const markupIds = new Set([...p.markup.matchAll(/\sid\s*=\s*("([^"]*)"|'([^']*)')/g)]
      .map(m => (m[2] !== undefined ? m[2] : m[3])));
    for (const m of p.clean.matchAll(/getElementById\(\s*["']([^"']+)["']/g)) {
      const t = m[1];
      if (markupIds.has(t) || ids.has(t) || pay.scopes.has(t) || isConcatPrefix(p, t)) continue;
      bad.push(p.name + " getElementById('" + t + "') resolves to no markup id and nothing creates it");
    }
  }
  return bad;
});

// W18. THE PAGES MUST AGREE ON THE HEAD METADATA THEY CARRY, AND THE APPLE TOUCH
// ICON MUST BE A PNG THAT EXISTS.
//
// WHY. Three pages that are one site drifted apart in their own head. product.html
// carried no theme-color while the other two did, so it rendered a different
// browser chrome colour on mobile. landing.html carried twitter:card alone, with no
// twitter:title, twitter:description or twitter:image, so a share of the page Lance
// actually sends people to fell back to whatever each platform could infer. And all
// three pointed apple-touch-icon at an SVG, a format Safari does not accept for
// that link, so the iOS home screen tile fell back to a screenshot of the page.
//
// None of that is visible from inside a single page, which is why no earlier check
// caught it: every one of them reads one page at a time. This check is the first
// that compares the pages AGAINST EACH OTHER.
//
// THE SET IS DERIVED, NOT PINNED, rule 127. The union of the metadata keys present
// across the pages given is computed every run, and any page missing a key another
// page carries is reported. Pinning a list here would need editing every time a tag
// is added, and a list nobody updates is a check that quietly stops working.
//
// LIMIT, STATED WHERE IT IS USED, rule 121. Run against a single file, the union is
// that file's own set, so the agreement half of this check finds nothing. It
// discriminates only across a directory. The apple touch icon half works either way.
//
// WHY THE FORMAT RULE IS WORTH ENFORCING AND NOT JUST FIXING ONCE. The icon link is
// the kind of line that gets copied from page to page. One SVG href copied into a
// new page would silently break that page's tile with nothing to say so.
// THE ONE MARKUP ATTRIBUTE READER. Every check that pulls a value out of a markup
// tag goes through this and nothing else.
//
// SITE43, rule 137. Before this, five call sites each carried their own
// content\s*=\s*["']([^"']*)["'] whose negated class excludes BOTH quote marks, so a
// value delimited by one quote mark stopped at the first occurrence of the other.
// landing.html's description reads "We build your agency's AI operating system in 7
// days." and all five readers returned "We build your agency". W17 already did it
// correctly with the alternation below; this makes that the only form in the file.
//
// IT RETURNS undefined WHEN THE ATTRIBUTE IS ABSENT, never ''. W19 branches on
// src === undefined to tell a page with no og:image from one with an empty og:image,
// so coercing here would make it resolve an empty path and report a missing file on a
// page that simply has no share image. Callers keep their own coercion.
//
// WHAT DOES NOT USE THIS, deliberately: the CSS animation value readers, where
// stopping at a quote keeps a quoted string out of a name; W1's rel search, which
// already backreferences its delimiter; and the readers that scan raw JAVASCRIPT for
// class=, className, setAttribute and getElementById, which are not markup tags. A
// class name, an element id and a rel token cannot contain a quote mark.
//
// `name` may be an alternation such as 'property|name'. It is interpolated into a
// non capturing group, so every caller in this file passes a literal attribute name.
function attrOf(tag, name) {
  const m = String(tag).match(new RegExp('\\s(?:' + name + ')\\s*=\\s*("[^"]*"|\'[^\']*\')', 'i'));
  return m ? m[1].slice(1, -1) : undefined;
}

C('W18', 'the pages agree on their head metadata, and the apple touch icon is a png that exists', ps => {
  const bad = [];
  const keyOf = tag => (attrOf(tag, 'property|name') || '').toLowerCase();
  /* only the keys that describe the page to the outside world. Anything else, such
   * as viewport or charset, is boilerplate that pages may legitimately differ on. */
  const WANTED = /^(description|theme-color|og:|twitter:)/;
  const metaKeys = p => new Set(
    [...p.markup.matchAll(/<meta\b[^>]*>/gi)].map(m => keyOf(m[0])).filter(k => WANTED.test(k))
  );

  const sets = ps.map(p => ({ name: p.name, keys: metaKeys(p) }));
  const union = new Set();
  sets.forEach(s => s.keys.forEach(k => union.add(k)));
  for (const s of sets) {
    for (const k of union) {
      if (!s.keys.has(k)) bad.push(s.name + ' is missing head metadata ' + k + ', which another page carries');
    }
  }

  for (const p of ps) {
    const link = (p.markup.match(/<link\b[^>]*rel\s*=\s*["']apple-touch-icon["'][^>]*>/i) || [])[0];
    if (!link) { bad.push(p.name + ' has no apple touch icon link'); continue; }
    const href = attrOf(link, 'href') || '';
    if (!/\.png(\?|$)/i.test(href)) {
      bad.push(p.name + ' apple touch icon points at ' + href + ', which is not a png, and Safari accepts only png here');
      continue;
    }
    /* a link to a png that is not there is worse than a link to the wrong format */
    let rel = href.replace(/[?#].*$/, '');
    if (rel.charAt(0) === '/') rel = rel.slice(1);
    if (!/^https?:/i.test(href) && !fs.existsSync(path.join(p.dir, rel))) {
      bad.push(p.name + ' apple touch icon points at ' + href + ' but that file is not beside the page');
    }
  }
  return bad;
});

// W19. EVERY og:image DECLARATION MUST MATCH THE ASSET IT POINTS AT.
//
// WHY. og-image.png is a JPEG. Both index and product declared og:image:type as
// image/png, and nothing anywhere could tell, because every check written so far
// reads markup against markup. This one reads the ASSET. It opens the file the page
// points at, derives the true format from its signature and the true dimensions
// from its own header, and fails any page that claims otherwise.
//
// WHY IT IS WORTH A CHECK RATHER THAN A ONE TIME FIX. The dangerous version of this
// is not today's. It is someone replacing the share image with a differently sized
// one and leaving og:image:width and og:image:height behind. The declaration would
// then be confidently wrong, every share would be cropped or letterboxed by the
// platform, and nothing would say a word. Deriving the dimensions from the file
// every run is the only way that stays true.
//
// WHY THE DIMENSIONS ARE READ BY HAND. Reading them means parsing two headers, and
// a dependency to do it would have to be vendored into the repository for one
// check. PNG carries width and height as two big endian integers at a fixed offset
// in IHDR. JPEG carries them in whichever start of frame marker appears, which has
// to be walked segment by segment because the markers are not at a fixed offset and
// APP segments of arbitrary length sit in front of them.
//
// LIMIT, STATED WHERE IT IS USED, rule 121. Only an og:image that resolves to a
// file beside the page is opened. One on another host is reported as unverifiable
// rather than passed silently, because a check that quietly skips what it cannot
// reach reads as a verdict it has not earned.
function imageFacts(file) {
  let b;
  try { b = fs.readFileSync(file); } catch (e) { return null; }
  if (b.length > 24 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    return { mime: 'image/png', width: b.readUInt32BE(16), height: b.readUInt32BE(20), bytes: b.length };
  }
  if (b.length > 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) { i++; continue; }
      const marker = b[i + 1];
      /* start of frame markers carry the size. C4, C8 and CC are not frames. */
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { mime: 'image/jpeg', height: b.readUInt16BE(i + 5), width: b.readUInt16BE(i + 7), bytes: b.length };
      }
      if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd9)) { i += 2; continue; }
      i += 2 + b.readUInt16BE(i + 2);
    }
    return { mime: 'image/jpeg', width: null, height: null, bytes: b.length };
  }
  if (b.length > 6 && b.slice(0, 3).toString('latin1') === 'GIF') {
    return { mime: 'image/gif', width: b.readUInt16LE(6), height: b.readUInt16LE(8), bytes: b.length };
  }
  if (b.length > 12 && b.slice(0, 4).toString('latin1') === 'RIFF' && b.slice(8, 12).toString('latin1') === 'WEBP') {
    return { mime: 'image/webp', width: null, height: null, bytes: b.length };
  }
  return { mime: 'unknown', width: null, height: null, bytes: b.length };
}

C('W19', 'every og:image declaration matches the asset it points at', ps => {
  const bad = [];
  const metaOf = (p, key) => {
    for (const m of p.markup.matchAll(/<meta\b[^>]*>/gi)) {
      const t = m[0];
      const k = (attrOf(t, 'property|name') || '').toLowerCase();
      if (k === key) return attrOf(t, 'content');
    }
    return undefined;
  };
  for (const p of ps) {
    const src = metaOf(p, 'og:image');
    if (src === undefined) continue;          /* W18 is what reports a missing one */
    /* An absolute og:image is only resolved locally when it sits on THIS site. The
     * site's own origin is derived from the page's canonical link rather than
     * assumed, rule 127. Without this, an og:image hosted on a CDN would have its
     * path pulled out and looked for beside the page, and reported missing when it
     * is simply somewhere else. An image this check cannot reach is reported as
     * unverified rather than passed, because silently skipping what it cannot open
     * would make this a verdict it has not earned. */
    const canon = (p.markup.match(/<link\b[^>]*rel\s*=\s*["']canonical["'][^>]*>/i) || [])[0] || '';
    const canonHref = attrOf(canon, 'href') || '';
    const origin = (canonHref.match(/^(https?:\/\/[^/]+)/i) || [])[1];
    let rel = src;
    if (/^https?:\/\//i.test(src)) {
      if (!origin || src.slice(0, origin.length).toLowerCase() !== origin.toLowerCase()) {
        bad.push(p.name + ' og:image ' + src + ' is not on this site, so its format and size cannot be verified here');
        continue;
      }
      rel = src.slice(origin.length) || '/';
    }
    if (rel.charAt(0) === '/') rel = rel.slice(1);
    const file = path.join(p.dir, rel.replace(/[?#].*$/, ''));
    if (!fs.existsSync(file)) {
      bad.push(p.name + ' og:image points at ' + src + ' but no such file sits beside the page');
      continue;
    }
    const f = imageFacts(file);
    if (!f) { bad.push(p.name + ' og:image ' + src + ' could not be read'); continue; }

    const type = metaOf(p, 'og:image:type');
    if (type !== undefined && type.toLowerCase() !== f.mime) {
      bad.push(p.name + ' declares og:image:type ' + type + ' but the file is ' + f.mime);
    }
    for (const dim of ['width', 'height']) {
      const declared = metaOf(p, 'og:image:' + dim);
      if (declared === undefined) continue;
      if (f[dim] === null) { bad.push(p.name + ' declares og:image:' + dim + ' but the ' + f.mime + ' header could not be read'); continue; }
      if (String(f[dim]) !== String(declared).trim()) {
        bad.push(p.name + ' declares og:image:' + dim + ' ' + declared + ' but the file is ' + f[dim]);
      }
    }
  }
  return bad;
});

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
