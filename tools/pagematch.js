'use strict';
/* pagematch, a normalised comparison between a served page and its committed bytes.
 *
 * WHY THIS EXISTS. Nothing in this repository has ever shown that the live pages match the
 * files that were committed. Field checks probe a handful of strings typed by hand, and one
 * of those strings was wrong: a probe looked for "#proof{" when the bytes said "#proof {",
 * so it proved nothing while appearing to pass. A probe list can only find what somebody
 * thought to list.
 *
 * WHY A PLAIN md5 CANNOT DO IT. The edge rewrites the page on the way out. Email links are
 * replaced per request, and analytics scripts are injected. So the served bytes are never
 * the committed bytes and a pinned digest can never match. That is a property of the server,
 * not a fault in the page.
 *
 * HOW THIS WORKS INSTEAD. The differences are DERIVED and then CLASSIFIED, never pinned. A
 * small number of declared classes are reversed on the served side, and then the two texts
 * must be identical. Anything left over is reported as UNKNOWN and FAILS. Unknown is not a
 * pass: that is the same rule the asset check follows when it refuses to call an unreachable
 * reference verified.
 *
 * LIMITS, STATED WHERE THE INSTRUMENT IS USED. The reversal classes below are HYPOTHESES
 * about what the edge does. They were written without a served page to look at, because the
 * build environment cannot reach the site. Every class therefore reports how many times it
 * fired, so a class that fires zero times is visible as dead rather than silently carried.
 * The first run against the real site IS the measurement of what the edge does, and any
 * class that turns out to be wrong will show up as an unknown hunk rather than as a pass.
 *
 * Email addresses are DECODED back to their real form rather than blanked on both sides.
 * Blanking would hide a genuine change to an address, which is exactly the drift worth
 * catching.
 *
 * WHICH CHECK CARRIES THE VERDICT, measured rather than assumed. M4, the identity check, is
 * the only load bearing one. With M2 and M3 both forced true, every malformed page still
 * fails by M4 alone. M2, M3 and the printable guard inside the decoder are DIAGNOSTICS:
 * they name the cause so the operator is not left reading a diff, and removing any of them
 * costs the explanation but never the refusal. That is stated here because a reader
 * comparing the four checks would otherwise assume they are four independent lines of
 * defence, and the sabotage suite scores them accordingly instead of pretending each one
 * can change an outcome on its own.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

/* ------------------------------------------------------------------ redaction
 * A printer that emits bytes out of a page will eventually emit a secret or a person's
 * name. One probe written during this build printed a live map key, because the key rides
 * on a basemap tile URL as a query parameter. Redaction belongs in the printer, not in the
 * attention of whoever reads the output.
 */
const REDACT = [
  [/([?&](?:key|token|api_?key|access_?token|secret|sig|signature)=)[^&\s"'<>]+/gi, '$1[redacted]'],
  [/\b[A-Za-z0-9._%+]+@[A-Za-z0-9.]+\.[A-Za-z]{2,}\b/g, '[address redacted]'],
  [/((?:data-name|data-client|data-psw|aria-label|title)\s*=\s*)(\\?["'])(.*?)\2/gi,
    (m, a, q, v) => a + q + '[redacted ' + v.length + ' chars]' + q],
  [/(data-cf-beacon\s*=\s*)(['"]).*?\2/gi, '$1$2[redacted]$2']
];
function redact(s) {
  let out = String(s);
  for (const [re, to] of REDACT) out = out.replace(re, to);
  return out;
}

/* ------------------------------------------------------------------ email decode
 * The edge encodes an address as hex, where the first byte is the key and every later byte
 * is a character of the address XORed with it. The transform is deterministic and therefore
 * exactly reversible, which is what lets the comparison run against real content.
 */
function cfDecode(hex) {
  if (typeof hex !== 'string' || hex.length < 4 || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) return null;
  const key = parseInt(hex.slice(0, 2), 16);
  let out = '';
  for (let i = 2; i < hex.length; i += 2) {
    const c = parseInt(hex.substr(i, 2), 16) ^ key;
    if (c < 9 || c > 126) return null;              /* not a printable address, so not ours */
    out += String.fromCharCode(c);
  }
  return out;
}

/* ------------------------------------------------------------------ the classes */
function normalise(served) {
  const fired = { E0: 0, E1a: 0, E1b: 0, E2: 0, E3: 0 };
  const problems = [];
  let t = served;

  /* E0, line endings. The field machine is Windows and a saved copy can arrive with CRLF
   * while the committed blob holds LF. That is a transport artefact, not page drift. It is
   * counted so a page that genuinely changed its endings is still visible. */
  const crlf = (t.match(/\r\n/g) || []).length;
  if (crlf) { fired.E0 = crlf; t = t.replace(/\r\n/g, '\n'); }

  /* E1a, an obfuscated link target returned to its mailto form. */
  t = t.replace(/\/cdn-cgi\/l\/email-protection#([0-9a-fA-F]+)/g, (m, hex) => {
    const addr = cfDecode(hex);
    if (addr === null) { problems.push('E1a could not decode an email protection target of ' + hex.length + ' hex characters'); return m; }
    fired.E1a++;
    return 'mailto:' + addr;
  });

  /* E1b, the visible address, which the edge wraps in an element carrying the same hex.
   * Both the span form and the anchor form are produced in the wild. */
  t = t.replace(/<(span|a)\b[^>]*\bclass\s*=\s*["'][^"']*__cf_email__[^"']*["'][^>]*>[\s\S]*?<\/\1>/gi, (m) => {
    const hm = m.match(/data-cfemail\s*=\s*["']([0-9a-fA-F]+)["']/i);
    if (!hm) { problems.push('E1b found a __cf_email__ element carrying no data-cfemail attribute'); return m; }
    const addr = cfDecode(hm[1]);
    if (addr === null) { problems.push('E1b could not decode a data-cfemail of ' + hm[1].length + ' hex characters'); return m; }
    fired.E1b++;
    return addr;
  });

  /* E1a leaves a bare protection path behind when the edge also rewrote an href that had no
   * fragment. That form carries no address, so it cannot be reversed and must not be
   * quietly dropped. */
  const bare = (t.match(/\/cdn-cgi\/l\/email-protection(?![#0-9a-fA-F])/g) || []).length;
  if (bare) problems.push('E1a found ' + bare + ' email protection path(s) with no hex fragment, which carry no address to restore');

  /* E3, the injected beacon, which declares itself with a configuration attribute. It runs
   * BEFORE E2 and E2 also skips it explicitly, so each artefact has exactly ONE owning
   * class. That is not tidiness: the beacon carries both a src on the analytics host and
   * this attribute, so a single predicate written for the src would swallow it and E3 would
   * never fire. A class whose input another class consumes is dead code reporting zero, and
   * the fire counts exist precisely so a dead class is visible. */
  t = t.replace(/<script\b[^>]*\bdata-cf-beacon\s*=[^>]*>[\s\S]*?<\/script>\s*/gi, () => { fired.E3++; return ''; });

  /* E2, injected script elements. The committed pages contain zero occurrences of cdn-cgi
   * and zero of cloudflareinsights, measured at the commit under test, so every one of
   * these on the served page is an injection rather than something the page asked for.
   * The beacon is E3's, so it is skipped here whatever order these run in. */
  t = t.replace(/<script\b[^>]*\bsrc\s*=\s*["'][^"']*(?:\/cdn-cgi\/|cloudflareinsights\.com)[^"']*["'][^>]*>\s*<\/script>\s*/gi,
    (m) => { if (/data-cf-beacon\s*=/i.test(m)) return m; fired.E2++; return ''; });

  return { text: t, fired, problems };
}

/* ------------------------------------------------------------------ bounded line diff
 * Common leading and trailing lines are trimmed first, which is what makes this cheap on a
 * quarter of a megabyte. Only the window between them is refined, and only when it is small
 * enough that refining it is honest work rather than a guess. A window larger than the cap
 * is reported coarsely and SAYS SO, instead of producing a confident but arbitrary
 * alignment.
 */
function lineDiff(committed, servedNorm, cap) {
  const A = committed.split('\n'), B = servedNorm.split('\n');
  let s = 0;
  while (s < A.length && s < B.length && A[s] === B[s]) s++;
  let ea = A.length - 1, eb = B.length - 1;
  while (ea >= s && eb >= s && A[ea] === B[eb]) { ea--; eb--; }
  if (s > ea && s > eb) return { hunks: [], refined: true, lines: [A.length, B.length] };

  const wa = A.slice(s, ea + 1), wb = B.slice(s, eb + 1);
  if (wa.length > cap || wb.length > cap) {
    return {
      refined: false, lines: [A.length, B.length],
      hunks: [{ coarse: true, at: s + 1, aLen: wa.length, bLen: wb.length, aFirst: wa[0] || '', bFirst: wb[0] || '' }]
    };
  }

  const n = wa.length, m = wb.length;
  const dp = [];
  for (let i = 0; i <= n; i++) dp.push(new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = wa[i] === wb[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);

  const ops = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (wa[i] === wb[j]) { ops.push(['=', wa[i]]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push(['-', wa[i]]); i++; }
    else { ops.push(['+', wb[j]]); j++; }
  }
  while (i < n) ops.push(['-', wa[i++]]);
  while (j < m) ops.push(['+', wb[j++]]);

  const hunks = [];
  let cur = null, line = s;
  for (const [k, text] of ops) {
    if (k === '=') { if (cur) { hunks.push(cur); cur = null; } line++; continue; }
    if (!cur) cur = { coarse: false, at: line + 1, removed: [], added: [] };
    if (k === '-') { cur.removed.push(text); line++; } else cur.added.push(text);
  }
  if (cur) hunks.push(cur);
  return { hunks, refined: true, lines: [A.length, B.length] };
}

/* ------------------------------------------------------------------ inputs */
function fromGit(repo, ref, file) {
  /* stderr is captured rather than inherited: when a ref or a path is wrong this function
   * is already reporting it through a named check, and letting git's own fatal line through
   * as well makes a handled case look like a crash. */
  return execFileSync('git', ['show', ref + ':' + file],
    { cwd: repo, maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'] });
}
function fromUrl(url) {
  /* Node's own client only. Nothing here may depend on a package being installed on the
   * machine that ships, which is why this tool has no dependencies at all. */
  const https = require(url.startsWith('http://') ? 'http' : 'https');
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'accept-encoding': 'identity', 'user-agent': 'pagematch' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume(); return resolve(fromUrl(new URL(res.headers.location, url).toString()));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('http ' + res.statusCode)); }
      const parts = [];
      res.on('data', d => parts.push(d));
      res.on('end', () => resolve(Buffer.concat(parts)));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('timed out after 30s')));
  });
}

/* ------------------------------------------------------------------ report */
const checks = [];
function C(id, label, ok, detail) {
  checks.push({ id, label, ok });
  console.log('  ' + (ok ? 'ok  ' : 'FAIL') + '  ' + id + '  ' + label + (detail ? '\n           ' + detail : ''));
}
function finish(name) {
  const pass = checks.filter(c => c.ok).length;
  console.log('');
  console.log('checks passed ' + pass + ' of ' + checks.length);
  console.log(name + (pass === checks.length && checks.length > 0 ? ' PASS' : ' FAIL'));
  process.exit(pass === checks.length && checks.length > 0 ? 0 : 1);
}

function usage(msg) {
  /* Rule 76 shape: a missing input gives a NAMED check and a verdict, never a stack trace,
   * because an instrument that dies with a stack frame has told the operator nothing. */
  console.log('  FAIL  M0  input missing or unusable' + (msg ? ': ' + msg : ''));
  console.log('');
  console.log('        pagematch compares a served page against its committed bytes.');
  console.log('        node pagematch.js --file <saved.html> --repo <dir> --ref <ref> --path <file>');
  console.log('        node pagematch.js --url <url> --repo <dir> --ref <ref> --path <file>');
  console.log('');
  console.log('checks passed 0 of 1');
  console.log('PAGEMATCH FAIL');
  process.exit(1);
}

(async () => {
  const a = process.argv.slice(2);
  const opt = {};
  for (let i = 0; i < a.length; i++) {
    const m = a[i].match(/^--([a-z]+)$/);
    if (m) { opt[m[1]] = a[i + 1]; i++; }
  }
  const cap = parseInt(opt.cap || '400', 10);
  if (!opt.file && !opt.url) usage('give either --file or --url');
  if (!opt.path) usage('give --path, the file inside the repository to compare against');
  const repo = opt.repo || process.cwd();
  const ref = opt.ref || 'origin/main';

  let servedBuf, committedBuf;
  try {
    servedBuf = opt.file ? fs.readFileSync(opt.file) : await fromUrl(opt.url);
  } catch (e) { usage('could not read the served page, ' + e.message); }
  try {
    committedBuf = fromGit(repo, ref, opt.path);
  } catch (e) { usage('could not read ' + ref + ':' + opt.path + ' from ' + repo); }

  console.log('  served   ' + (opt.file ? path.basename(opt.file) : redact(opt.url)) + '   ' + servedBuf.length + ' bytes');
  console.log('  committed ' + ref + ':' + opt.path + '   ' + committedBuf.length + ' bytes');
  console.log('');

  C('M1', 'both inputs carry bytes',
    servedBuf.length > 0 && committedBuf.length > 0,
    servedBuf.length > 0 && committedBuf.length > 0 ? null : 'served ' + servedBuf.length + ', committed ' + committedBuf.length);

  const committed = committedBuf.toString('utf8');
  const { text: servedNorm, fired, problems } = normalise(servedBuf.toString('utf8'));

  console.log('           class fire counts: ' + Object.entries(fired).map(([k, v]) => k + ' ' + v).join(', '));
  const dead = Object.entries(fired).filter(([, v]) => v === 0).map(([k]) => k);
  if (dead.length) console.log('           classes that fired zero times, carried but unproven here: ' + dead.join(', '));

  C('M2', 'every email obfuscation reversed cleanly', problems.length === 0,
    problems.length ? problems.map(redact).join('; ') : null);

  const left = (servedNorm.match(/cdn-cgi|__cf_email__|cloudflareinsights/gi) || []).length;
  C('M3', 'no edge artefact survives normalisation', left === 0,
    left ? left + ' occurrence(s) of an edge marker remain after all classes ran' : null);

  const d = lineDiff(committed, servedNorm, cap);
  const same = d.hunks.length === 0;
  C('M4', 'the normalised served page equals the committed bytes', same,
    same ? null : d.hunks.length + ' unknown hunk(s), committed ' + d.lines[0] + ' lines against normalised ' + d.lines[1]);

  if (!same) {
    console.log('');
    console.log('  UNKNOWN DIFFERENCES. These are not in any declared class, so they are reported');
    console.log('  rather than passed. Content is redacted.');
    if (!d.refined) console.log('  The differing window exceeded the ' + cap + ' line cap, so it is reported coarsely.');
    d.hunks.slice(0, 12).forEach((h, n) => {
      console.log('');
      if (h.coarse) {
        console.log('   hunk ' + (n + 1) + ' at line ' + h.at + ', committed window ' + h.aLen + ' lines, served window ' + h.bLen + ' lines');
        console.log('     committed first line: ' + redact(h.aFirst).slice(0, 150));
        console.log('     served    first line: ' + redact(h.bFirst).slice(0, 150));
      } else {
        console.log('   hunk ' + (n + 1) + ' at committed line ' + h.at +
          ', ' + h.removed.length + ' line(s) only in the commit, ' + h.added.length + ' only on the server');
        h.removed.slice(0, 3).forEach(l => console.log('     commit only: ' + redact(l).trim().slice(0, 150)));
        h.added.slice(0, 3).forEach(l => console.log('     server only: ' + redact(l).trim().slice(0, 150)));
      }
    });
    if (d.hunks.length > 12) console.log('\n   ' + (d.hunks.length - 12) + ' further hunk(s) not shown');
  }

  finish('PAGEMATCH');
})().catch(e => { usage('unexpected failure, ' + e.message); });
