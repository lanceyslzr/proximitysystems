// cssscan.js  SITE26 hardened scanner primitives.
// Every function here exists because an earlier drop was wrong without it.
// The test file test-cssscan.js proves each trap is caught, not asserted.

// TRAP 1, SITE24. A global /<style>[\s\S]*?<\/style>/g also matches the literal
// text <style> inside a CSS comment, creating a block that does not exist and
// double parsing the real one. Walk forward past each closing tag instead.
function styleBlocks(html) {
  const out = [];
  let i = 0;
  while (true) {
    const a = html.indexOf('<style', i);
    if (a < 0) break;
    const o = html.indexOf('>', a);
    if (o < 0) break;
    const c = html.indexOf('</style>', o);
    if (c < 0) break;
    out.push({ open: a, textStart: o + 1, textEnd: c, close: c + 8, text: html.slice(o + 1, c) });
    i = c + 8;
  }
  return out;
}

function scriptBlocks(html) {
  const out = [];
  let i = 0;
  while (true) {
    const a = html.indexOf('<script', i);
    if (a < 0) break;
    const o = html.indexOf('>', a);
    if (o < 0) break;
    const c = html.indexOf('</script>', o);
    if (c < 0) break;
    out.push({ open: a, textStart: o + 1, textEnd: c, close: c + 9, text: html.slice(o + 1, c) });
    i = c + 9;
  }
  return out;
}

function allCss(html) { return styleBlocks(html).map(b => b.text).join('\n'); }

// TRAP 2, SITE22 G10 read a comment as a selector. SITE25 G11 counted a selector
// that the drop's OWN inserted comment mentions. Strip before measuring.
// Length preserving variant keeps offsets valid for splicing.
function stripComments(css, preserveLength) {
  if (!preserveLength) return css.replace(/\/\*[\s\S]*?\*\//g, '');
  return css.replace(/\/\*[\s\S]*?\*\//g, m => ' '.repeat(m.length));
}

// TRAP 3, SITE22. A flat regex cannot handle @media nesting and undercounted
// 47 rules / 4,637 bytes against a true 48 / 4,843. Track depth.
// Returns leaf rules only, each with its ancestor at-rule chain.
function rules(cssText) {
  const css = stripComments(cssText, true);
  const out = [];
  const stack = [];
  let segStart = 0;
  for (let i = 0; i < css.length; i++) {
    const ch = css[i];
    if (ch === '{') {
      stack.push({ sel: css.slice(segStart, i).trim(), selStart: segStart, bodyStart: i + 1 });
      segStart = i + 1;
    } else if (ch === '}') {
      const f = stack.pop();
      if (f) {
        const body = css.slice(f.bodyStart, i);
        out.push({
          sel: f.sel,
          body,
          isAtRule: f.sel.startsWith('@'),
          hasNested: body.indexOf('{') >= 0,
          ancestors: stack.map(s => s.sel),
          start: f.selStart,
          end: i + 1,
          raw: cssText.slice(f.selStart, i + 1)
        });
      }
      segStart = i + 1;
    }
  }
  return out;
}

function leafRules(cssText) { return rules(cssText).filter(r => !r.hasNested && !r.isAtRule); }

// TRAP 4, SITE25 rig bug 32. /[^{}]*,\s*a\s*\{/ matched a FRAGMENT of
// .footer-links a,.footer-contact-list li starting inside ".footer-links a",
// inventing a bare anchor colour rule with !important that does not exist.
// Split the selector list on top level commas and compare WHOLE selectors.
function selectorList(sel) {
  const out = [];
  let depth = 0, quote = null, cur = '';
  for (const ch of sel) {
    if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[') depth++;
    if (ch === ')' || ch === ']') depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean);
}

// TRAP 5, THREE occurrences: SITE23 hero-sub inside hero-sub-new, SITE24's token
// test, SITE25 G10 where \bmf-note\b matched mf-note-gone. A hyphen is a non word
// character so \b does not bound a hyphenated token. Compare whole tokens.
function hasToken(attrValue, token) {
  if (!attrValue) return false;
  return String(attrValue).split(/\s+/).filter(Boolean).indexOf(token) >= 0;
}

function classTokens(html) {
  const seen = new Map();
  const sb = styleBlocks(html), sc = scriptBlocks(html);
  const inBlock = (i) => sb.some(b => i >= b.textStart && i < b.textEnd)
                      || sc.some(b => i >= b.textStart && i < b.textEnd);
  for (const m of html.matchAll(/\sclass\s*=\s*("([^"]*)"|'([^']*)')/g)) {
    if (inBlock(m.index)) continue;
    const v = m[2] !== undefined ? m[2] : m[3];
    for (const t of v.split(/\s+/).filter(Boolean)) seen.set(t, (seen.get(t) || 0) + 1);
  }
  return seen;
}

// TRAP 6, FOUR occurrences: SITE22 G7, SITE24 G12, SITE25 G11 twice.
// indexOf succeeds while N-1 of N occurrences are intact. Count, never find.
function countOccurrences(text, needle) {
  if (!needle) throw new Error('countOccurrences: empty needle');
  let n = 0, i = 0;
  while ((i = text.indexOf(needle, i)) >= 0) { n++; i += needle.length; }
  return n;
}

// A whole token search in free text, for CSS tokens in script strings and markup.
// Boundaries are characters that cannot be part of a CSS identifier, which
// INCLUDES the hyphen problem: we require the neighbours to be non identifier.
function countWholeToken(text, token) {
  const idChar = (c) => c !== undefined && /[A-Za-z0-9_-]/.test(c);
  let n = 0, i = 0;
  while ((i = text.indexOf(token, i)) >= 0) {
    const before = i > 0 ? text[i - 1] : undefined;
    const after = i + token.length < text.length ? text[i + token.length] : undefined;
    if (!idChar(before) && !idChar(after)) n++;
    i += token.length;
  }
  return n;
}

function markupOnly(html) {
  const blocks = [...styleBlocks(html), ...scriptBlocks(html)].sort((a, b) => a.open - b.open);
  let out = '', cursor = 0;
  for (const b of blocks) { out += html.slice(cursor, b.open); cursor = b.close; }
  out += html.slice(cursor);
  return out;
}

module.exports = { styleBlocks, scriptBlocks, allCss, stripComments, rules, leafRules,
  selectorList, hasToken, classTokens, countOccurrences, countWholeToken, markupOnly };
