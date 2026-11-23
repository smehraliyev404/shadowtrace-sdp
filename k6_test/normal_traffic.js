// ShadowTrace normal traffic: seeded shopper state machine.
//
// Reads data/runs/<run>/manifest.json (written by scripts/scenario_sampler.py) and
// takes EVERY random choice from a PRNG seeded by the manifest, so the same seed
// replays the same shopper behaviour. Only trace IDs are truly random.
//
// Provenance: every request carries our own
//   traceparent: 00-<trace_id>-<span_id>-01
// and k6 prints one line per request:
//   ORIGIN {"trace_id":..., "origin":"normal", "client":"k6", ...}
// k6 cannot write files, so run it with
//   k6 run --log-format raw --console-output <run>/k6_console.log \
//          -e MANIFEST=data/runs/<run>/manifest.json k6_test/normal_traffic.js
// and merge afterwards (collect_run.sh does both):
//   ./venv/bin/python scripts/provenance.py merge-k6 <run>/k6_console.log <run>/origin.jsonl
// Do not add other console.log calls: only lines starting with "ORIGIN " are merged,
// but extra output makes the file large for nothing.
//
// Redirects are NOT followed automatically (a followed 302 re-sends the same
// traceparent, putting two requests in one trace). follow() does it by hand with
// a new trace ID per hop.

import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';
const AUTH = __ENV.AUTH_URL || 'http://localhost:8081';
if (!__ENV.MANIFEST) {
  throw new Error('MANIFEST is required: -e MANIFEST=data/runs/<run>/manifest.json');
}
const M = JSON.parse(open(__ENV.MANIFEST));
const N = M.normal;
const J = N.journey;
const RUN_ID = M.run_id;

export const options = {
  scenarios: {
    shoppers: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: N.load.stages,
      gracefulRampDown: '15s',
    },
  },
  // keep the summary small; per-request info goes through ORIGIN lines
  summaryTrendStats: ['avg', 'p(95)'],
};

// ------------------------------------------------------------- seeded PRNG
// mulberry32: tiny, fast, good enough for traffic choices. One stream per
// (VU, iteration), so a VU's n-th session is the same for the same seed.
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function sessionRng() {
  return mulberry32((N.k6_seed ^ Math.imul(__VU, 0x9E3779B1) ^ Math.imul(__ITER + 1, 0x85EBCA77)) >>> 0);
}
const uniform = (r, lo, hi) => lo + r() * (hi - lo);
const randint = (r, lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
function weighted(r, weights) {        // {key: weight}
  const keys = Object.keys(weights);
  let x = r() * keys.reduce((s, k) => s + weights[k], 0);
  for (const k of keys) { x -= weights[k]; if (x <= 0) return k; }
  return keys[keys.length - 1];
}
function think(r) { sleep(uniform(r, N.think_time_s.min, N.think_time_s.max)); }

// ------------------------------------------------------------- provenance
function hex(n) {                       // n random bytes, no leading zero
  let h;
  do {
    h = Array.from(new Uint8Array(crypto.randomBytes(n)))
      .map((b) => b.toString(16).padStart(2, '0')).join('');
  } while (h[0] === '0');
  return h;
}

// Ground truth: every ORIGIN line carries the personal data that
// request really sent ("pii"): the session id on every frontend request, the
// credentials on logins, all checkout values. The leakage measurement searches
// spans for exactly these values (no regex guessing), and the L1 redactor's
// precision/recall is measured against them. All values are synthetic.
let SESSION_ID = null;     // set per session, see default()

// One request under a fresh client-chosen trace ID; hand-follows redirects.
function send(method, url, body, step, extraHeaders, pii) {
  let followOf = null;
  let res = null;
  for (let hop = 0; hop < 4; hop++) {
    const traceId = hex(16);
    const spanId = hex(8);
    // a redirect hop re-sends extraHeaders (Authorization, X-User-Email, ...), so its
    // ground truth keeps the pii too; values a hop does not send just never appear
    const resent = hop > 0 && extraHeaders && Object.keys(extraHeaders).length > 0;
    const truth = Object.assign({}, url.startsWith(BASE) && SESSION_ID ? { session_id: SESSION_ID } : {},
                                hop === 0 || resent ? (pii || {}) : {});
    console.log('ORIGIN ' + JSON.stringify({
      ts: Date.now() / 1000, trace_id: traceId, span_id: spanId,
      origin: 'normal', client: 'k6', run_id: RUN_ID, seed: M.seed,
      method: method, path: url.replace(/^https?:\/\/[^/]+/, '').split('?')[0],
      step: step, vu: __VU, iter: __ITER, follow_of: followOf,
      pii: Object.keys(truth).length ? truth : undefined,
    }));
    const params = {
      redirects: 0,
      headers: Object.assign({ traceparent: `00-${traceId}-${spanId}-01` }, extraHeaders || {}),
      tags: { step: step },
    };
    res = http.request(method, url, body, params);
    if (res.status < 300 || res.status >= 400 || !res.headers['Location']) return res;
    const loc = res.headers['Location'];
    url = loc.startsWith('http') ? loc : `${url.match(/^https?:\/\/[^/]+/)[0]}${loc}`;
    method = 'GET'; body = null; followOf = traceId; step = step + '_redirect';
  }
  return res;
}

// ------------------------------------------------------------- synthetic people
// Varied, realistic-looking but fictional personal data, so leaked
// values are not one trivial pattern (the L1 redactor must really work):
// e-mails in several formats and domains, addresses from several countries,
// phone numbers, random Luhn-valid Visa/MasterCard numbers. Names come from
// people.json, shared with the credential-stuffing attack scripts.
const PEOPLE = JSON.parse(open('./people.json'));
const ACCOUNT_SECRET = 'shadowtrace-lab-accounts-v1';   // = authservice ACCOUNT_SECRET
const N_ACCOUNTS = 500;

// countries with numeric postcodes only (the frontend parses zip_code as a number)
const COUNTRIES = [
  { country: 'United States', w: 4, zip: 5, street: (r) => `${randint(r, 1, 9999)} ${cap(pick(r, PEOPLE.last_names))} ${pick(r, ['St', 'Ave', 'Rd', 'Blvd', 'Ln', 'Dr', 'Way'])}${r() < 0.3 ? `, Apt ${randint(r, 1, 40)}${pick(r, ['A', 'B', 'C'])}` : ''}`,
    places: [['Mountain View', 'CA'], ['Austin', 'TX'], ['Seattle', 'WA'], ['Boston', 'MA'], ['Denver', 'CO'], ['Chicago', 'IL']] },
  { country: 'Germany', w: 2, zip: 5, street: (r) => `${cap(pick(r, PEOPLE.last_names))}${pick(r, ['strasse', 'weg', 'allee'])} ${randint(r, 1, 180)}`,
    places: [['Berlin', 'Berlin'], ['Munich', 'Bavaria'], ['Hamburg', 'Hamburg'], ['Cologne', 'NRW']] },
  { country: 'Azerbaijan', w: 2, zip: 4, street: (r) => `${pick(r, ['Nizami', 'Fuzuli', 'Istiqlaliyyat', 'Azadliq', 'Samad Vurgun'])} str. ${randint(r, 1, 120)}${r() < 0.4 ? `, apt ${randint(r, 1, 90)}` : ''}`,
    places: [['Baku', 'Baku'], ['Ganja', 'Ganja'], ['Sumqayit', 'Absheron']] },
  { country: 'Turkey', w: 1, zip: 5, street: (r) => `${pick(r, ['Ataturk', 'Istiklal', 'Cumhuriyet', 'Bagdat'])} Cd. No:${randint(r, 1, 250)}`,
    places: [['Istanbul', 'Istanbul'], ['Ankara', 'Ankara'], ['Izmir', 'Izmir']] },
  { country: 'France', w: 1, zip: 5, street: (r) => `${randint(r, 1, 120)} ${pick(r, ['rue de la Paix', 'avenue Victor Hugo', 'boulevard Voltaire', 'rue Lafayette'])}`,
    places: [['Paris', 'Ile-de-France'], ['Lyon', 'Auvergne-Rhone-Alpes'], ['Nice', 'PACA']] },
  { country: 'India', w: 1, zip: 6, street: (r) => `${randint(r, 1, 400)} ${pick(r, ['MG Road', 'Brigade Road', 'Park Street', 'Linking Road'])}`,
    places: [['Bengaluru', 'Karnataka'], ['Mumbai', 'Maharashtra'], ['Kolkata', 'West Bengal']] },
];
const PHONES = {
  'United States': (r) => pick(r, [`+1 (${randint(r, 201, 989)}) 555-${String(randint(r, 0, 9999)).padStart(4, '0')}`, `${randint(r, 201, 989)}-555-${String(randint(r, 0, 9999)).padStart(4, '0')}`]),
  'Germany': (r) => `+49 ${randint(r, 30, 89)} ${randint(r, 1000000, 9999999)}`,
  'Azerbaijan': (r) => `+994 ${pick(r, ['50', '51', '55', '70', '77'])} ${randint(r, 100, 999)} ${randint(r, 10, 99)} ${randint(r, 10, 99)}`,
  'Turkey': (r) => `+90 5${randint(r, 30, 59)} ${randint(r, 100, 999)} ${randint(r, 10, 99)} ${randint(r, 10, 99)}`,
  'France': (r) => `+33 6 ${randint(r, 10, 99)} ${randint(r, 10, 99)} ${randint(r, 10, 99)} ${randint(r, 10, 99)}`,
  'India': (r) => `+91 ${randint(r, 70000, 99999)} ${randint(r, 10000, 99999)}`,
};

function cap(x) { return x.charAt(0).toUpperCase() + x.slice(1); }
function digits(r, n) { let d = ''; for (let i = 0; i < n; i++) d += String(Math.floor(r() * 10)); return d; }

function emailFor(r, first, last) {
  const nn = randint(r, 1, 99);
  let local = pick(r, [`${first}.${last}`, `${first[0]}${last}`, `${first}_${last}`, `${first}${last}${nn}`,
                       `${first}.${last}+shop`, `${last}.${first}`, `${first}${nn}`]);
  if (r() < 0.1) local = local.split('.').map(cap).join('.');       // Anna.Schmidt@...
  return `${local}@${pick(r, PEOPLE.email_domains)}`;
}

function personFor(r) {
  const first = pick(r, PEOPLE.first_names), last = pick(r, PEOPLE.last_names);
  const c = weighted(r, Object.fromEntries(COUNTRIES.map((x, i) => [i, x.w])));
  const C = COUNTRIES[Number(c)];
  const [city, state] = pick(r, C.places);
  return {
    id: randint(r, 100000, 999999),
    first: first, last: last, name: `${cap(first)} ${cap(last)}`,
    email: emailFor(r, first, last),
    phone: PHONES[C.country](r),
    street: C.street(r), city: city, state: state, country: C.country,
    zip: String(randint(r, 1, 9) * Math.pow(10, C.zip - 1) + randint(r, 0, Math.pow(10, C.zip - 1) - 1)),
  };
}

// the shop's user database: fixed (seed independent of the run), so the same
// customers come back across runs; the password is derived from the username
// with the same HMAC authservice uses, so 500 accounts need no shared file
const ACCOUNTS = (() => {
  const r = mulberry32(0x5eed);
  const out = [], seen = new Set();
  while (out.length < N_ACCOUNTS) {
    const p = personFor(r);
    const username = `${p.first}.${p.last}${r() < 0.5 ? randint(r, 1, 99) : ''}`;
    if (seen.has(username)) continue;
    seen.add(username);
    p.username = username;
    p.password = crypto.hmac('sha256', ACCOUNT_SECRET, username, 'hex').slice(0, 12);
    out.push(p);
  }
  return out;
})();

const VISA_ELECTRON = /^(4026|417500|4508|4844|491(3|7))/;   // same pattern as simple-card-validator

function luhnDigit(partial) {          // check digit that makes partial+digit Luhn-valid
  let sum = 0, dbl = true;
  for (let i = partial.length - 1; i >= 0; i--) {
    let d = Number(partial[i]);
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d; dbl = !dbl;
  }
  return String((10 - (sum % 10)) % 10);
}

function cardFields(r, invalid) {
  const prefix = r() < 0.6 ? '4' : String(randint(r, 51, 55));     // Visa / MasterCard
  let partial = prefix + digits(r, 15 - prefix.length);
  // paymentservice (simple-card-validator 1.1.0) classifies these Visa prefixes as
  // Visa Electron and rejects them ("Only VISA or MasterCard"): draw again
  while (VISA_ELECTRON.test(partial)) partial = prefix + digits(r, 15 - prefix.length);
  let number = partial + luhnDigit(partial);
  let year = 2027 + randint(r, 0, 8);
  if (invalid) {
    if (r() < 0.5) {   // Luhn failure: change the last digit
      number = number.slice(0, -1) + String((Number(number.slice(-1)) + 1) % 10);
    } else {           // expired card
      year = 2015 + randint(r, 0, 5);
    }
  }
  return {
    credit_card_number: number,
    credit_card_expiration_month: String(randint(r, 1, 12)),
    credit_card_expiration_year: String(year),
    credit_card_cvv: String(randint(r, 100, 999)),
  };
}

function b64url(obj) { return encoding.b64encode(JSON.stringify(obj), 'rawurl'); }

// ------------------------------------------------------------- one session
export default function () {
  const r = sessionRng();
  const abandon = () => r() < J.p_abandon_step;
  // the shop session cookie, chosen here (seeded) instead of by the frontend, so the
  // session id is known for every request of the session (frontend keeps a cookie
  // it receives, see ensureSessionID); cookie jars are reset between sessions
  const rh = (n) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join('');
  SESSION_ID = `${rh(8)}-${rh(4)}-4${rh(3)}-${'89ab'[Math.floor(r() * 4)]}${rh(3)}-${rh(12)}`;
  http.cookieJar().set(BASE, 'shop_session-id', SESSION_ID);
  // logged-in shoppers are one of the 500 accounts, guests a fresh random person
  const roll = r();
  const loggedIn = roll < J.p_login_typo + J.p_login;
  const who = loggedIn ? pick(r, ACCOUNTS) : personFor(r);

  // 0. login: ~15% with their own account, ~5% mistype first, then retry
  if (loggedIn) {
    if (roll < J.p_login_typo) {
      // three typos that always differ from the password (it is 12 hex characters, so
      // an upper-case variant would equal an all-digit password); same RNG draws as before
      const last = who.password.slice(-1);
      const typo = pick(r, [who.password.slice(0, -1), who.password.slice(0, -1) + (last === '0' ? '1' : '0'),
                            who.password.slice(1) + who.password[0]]);
      send('POST', `${AUTH}/login`, { username: who.username, password: typo }, 'login_typo', null,
           { username: who.username, password: typo });
      think(r);
    }
    const res = send('POST', `${AUTH}/login`,
      { username: who.username, password: who.password }, 'login', null,
      { username: who.username, password: who.password });
    check(res, { 'login 200': (x) => x.status === 200 });
    think(r);
    if (abandon()) return;
  }

  // 1. home
  check(send('GET', `${BASE}/`, null, 'home'), { 'home 200': (x) => x.status === 200 });
  think(r);
  if (abandon()) return;

  // 2. currency
  if (r() < J.p_currency) {
    send('POST', `${BASE}/setCurrency`, { currency_code: pick(r, J.currencies) }, 'set_currency');
    think(r);
  }

  // 3. browse a few products
  const nBrowse = randint(r, J.browse_products.min, J.browse_products.max);
  for (let i = 0; i < nBrowse; i++) {
    send('GET', `${BASE}/product/${weighted(r, J.product_weights)}`, null, 'product');
    think(r);
    if (abandon()) return;
  }

  // 4. cart
  let cartSize = 0;
  if (r() < J.p_add_to_cart) {
    const nItems = randint(r, J.cart_items.min, J.cart_items.max);
    const chosen = new Set();
    for (let i = 0; i < nItems; i++) chosen.add(weighted(r, J.product_weights));
    for (const pid of chosen) {
      const res = send('POST', `${BASE}/cart`, {
        product_id: pid, quantity: String(randint(r, J.quantity.min, J.quantity.max)),
      }, 'add_to_cart');
      if (res.status < 400) cartSize++;
      think(r);
      if (abandon()) return;
    }
    send('GET', `${BASE}/cart`, null, 'view_cart');
    think(r);

    if (r() < J.p_empty_cart) {
      send('POST', `${BASE}/cart/empty`, null, 'empty_cart');
      cartSize = 0;
      think(r);
    }
  }

  // 5. checkout (~10% with an invalid card)
  if (cartSize > 0 && r() < J.p_checkout) {
    const invalid = r() < J.p_invalid_card;
    const sessHex = Math.floor(r() * 0xffffffff).toString(16);
    const body = Object.assign({
      email: who.email, street_address: who.street, zip_code: who.zip,
      city: who.city, state: who.state, country: who.country,
      phone: who.phone,                       // shop forms ask for it; the frontend ignores it
    }, cardFields(r, invalid));
    // what a real client sends besides the form: a bearer token (JWT with user
    // claims), the user's e-mail, a session token, and the card only MASKED
    // (first 6 + last 4) plus a payment token - never the full number in a header
    const jwt = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: who.username || `guest-${who.id}`,
      email: who.email, name: who.name, iat: 1794400000 + randint(r, 0, 999999) })}.${hex(16)}`;
    const cc = body.credit_card_number;
    const masked = `${cc.slice(0, 6)}${'*'.repeat(cc.length - 10)}${cc.slice(-4)}`;
    const payToken = `tok_${hex(12)}`, sessToken = `sess_${sessHex}_auth`;
    const userId = String(who.username || who.id);
    // e-mail and user id in the query string too, as many shop front ends do; the
    // frontend records url.query (leak.go) - one of the leak channels
    const query = `user_email=${encodeURIComponent(who.email)}&user_id=${userId}`;
    const res = send('POST', `${BASE}/cart/checkout?${query}`, body, invalid ? 'checkout_invalid_card' : 'checkout', {
      'Authorization': `Bearer ${jwt}`,
      'X-User-Email': who.email,
      'X-Card-Display': masked,
      'X-Payment-Token': payToken,
      'X-Session-Token': sessToken,
    }, {
      email: who.email, name: who.name, phone: who.phone, user_id: userId,
      street: who.street, city: who.city, state: who.state, zip: who.zip, country: who.country,
      card: cc, cvv: body.credit_card_cvv, card_exp: `${body.credit_card_expiration_month}/${body.credit_card_expiration_year}`,
      card_masked: masked, payment_token: payToken, session_token: sessToken, jwt: jwt,
    });
    check(res, { 'checkout handled': (x) => (invalid ? x.status >= 400 : x.status === 200) });
    think(r);
  }

  // 6. logout
  if (r() < J.p_logout) {
    send('GET', `${BASE}/logout`, null, 'logout');
    think(r);
  }
}
