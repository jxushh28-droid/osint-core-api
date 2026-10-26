'use strict';
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ── CORS: allow all origins (frontend is static HTML) ──────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Rate limiter: 60 req/min per IP ────────────────────────────────────────
const limiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false });
app.use('/api/', limiter);

// ── API keys (set as Railway env vars) ─────────────────────────────────────
const KEYS = {
  numverify:    process.env.NUMVERIFY_KEY    || '',
  abstract:     process.env.ABSTRACT_KEY     || '',
  hibp:         process.env.HIBP_KEY         || '',
  hunter:       process.env.HUNTER_KEY       || '',
  ipinfo:       process.env.IPINFO_KEY       || '',
  whoisxml:     process.env.WHOISXML_KEY     || 'at_demo',
  virustotal:   process.env.VIRUSTOTAL_KEY   || '',
  leakcheck:    process.env.LEAKCHECK_KEY    || '',
  opencnam:     process.env.OPENCNAM_SID     || '',
  opencnam_tok: process.env.OPENCNAM_TOKEN   || '',
  shodan:       process.env.SHODAN_KEY       || '',
};

// ── Helpers ─────────────────────────────────────────────────────────────────
async function jfetch(url, opts = {}) {
  try {
    const r = await fetch(url, { timeout: 8000, ...opts });
    if (!r.ok) return { _error: r.status };
    return await r.json();
  } catch (e) {
    return { _error: e.message };
  }
}
async function tfetch(url, opts = {}) {
  try {
    const r = await fetch(url, { timeout: 8000, ...opts });
    if (!r.ok) return '';
    return await r.text();
  } catch (e) {
    return '';
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PHONE LOOKUP  /api/phone?q=+77001234567
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/phone', async (req, res) => {
  const q = (req.query.q || '').replace(/\s/g, '');
  if (!q) return res.json({ error: 'no query' });

  const results = [];

  // 1. NumVerify — name, carrier, line_type, location
  if (KEYS.numverify) {
    const d = await jfetch(`http://apilayer.net/api/validate?access_key=${KEYS.numverify}&number=${encodeURIComponent(q)}&format=1`);
    if (!d._error) results.push({ source: 'NumVerify', data: {
      valid: d.valid,
      number: d.international_format,
      local: d.local_format,
      country: d.country_name,
      carrier: d.carrier,
      line_type: d.line_type,
      location: d.location,
    }});
  }

  // 2. AbstractAPI Phone Validation
  if (KEYS.abstract) {
    const d = await jfetch(`https://phonevalidation.abstractapi.com/v1/?api_key=${KEYS.abstract}&phone=${encodeURIComponent(q)}`);
    if (!d._error) results.push({ source: 'AbstractAPI', data: {
      valid: d.valid,
      format_international: d.format?.international,
      format_local: d.format?.local,
      country: d.country?.name,
      carrier: d.carrier,
      type: d.type,
    }});
  }

  // 3. OpenCNAM — caller ID / name
  if (KEYS.opencnam && KEYS.opencnam_tok) {
    const d = await jfetch(`https://api.opencnam.com/v3/phone/${encodeURIComponent(q)}?format=json&account_sid=${KEYS.opencnam}&auth_token=${KEYS.opencnam_tok}`);
    if (!d._error && d.name) results.push({ source: 'OpenCNAM CallerID', data: { name: d.name, number: d.phone } });
  }

  // 4. ipinfo.io carrier lookup by phone prefix (free tier)
  if (KEYS.ipinfo) {
    // not phone specific, skip if no better key
  }

  // 5. Leakcheck — breach check by phone
  if (KEYS.leakcheck) {
    const d = await jfetch(`https://leakcheck.io/api/public?key=${KEYS.leakcheck}&check=${encodeURIComponent(q)}`);
    if (!d._error && d.result) results.push({ source: 'LeakCheck', data: {
      found: d.found,
      sources: d.sources,
    }});
  }

  // 6. HLR-style prefix decode (built-in, no key needed)
  results.push({ source: 'Prefix Decode', data: phonePrefixDecode(q) });

  // 7. GetContact-style search via Truecaller public API (no auth required for basic)
  const tc = await truecallerLookup(q);
  if (tc) results.push({ source: 'Truecaller', data: tc });

  res.json({ query: q, results });
});

// ── Prefix decode (KZ/RU built-in, no API) ─────────────────────────────────
function phonePrefixDecode(phone) {
  const d = phone.replace(/\D/g, '');
  const info = { raw: phone, e164: '+' + d };
  if (d.startsWith('7')) {
    info.country = 'KZ/RU';
    const p3 = d.slice(1, 4);
    // KZ prefixes
    const kzOps = { '700':'Beeline KZ','701':'Beeline KZ','702':'Beeline KZ','703':'Beeline KZ','704':'Beeline KZ',
      '705':'Beeline KZ','706':'Beeline KZ','707':'Beeline KZ','708':'Beeline KZ','709':'Beeline KZ',
      '710':'Beeline KZ','711':'Beeline KZ','712':'Landline KZ','713':'Landline KZ','714':'Landline KZ',
      '715':'Landline KZ','716':'Landline KZ','717':'Astana KZ','718':'Almaty KZ','719':'Landline KZ',
      '720':'Kcell KZ','721':'Landline KZ','722':'Landline KZ','723':'Almaty KZ','724':'Landline KZ',
      '725':'Landline KZ','726':'Landline KZ','727':'Almaty KZ','728':'Shymkent KZ','729':'Landline KZ',
      '730':'Tele2 KZ','731':'Tele2 KZ','732':'Tele2 KZ','733':'Tele2 KZ','734':'Tele2 KZ',
      '735':'Tele2 KZ','736':'Tele2 KZ','737':'Tele2 KZ','738':'Tele2 KZ','739':'Tele2 KZ',
      '740':'Activ KZ','741':'Activ KZ','742':'Activ KZ','743':'Activ KZ','744':'Activ KZ',
      '745':'Activ KZ','746':'Activ KZ','747':'Activ KZ','748':'Activ KZ','749':'Activ KZ',
      '750':'Kcell KZ','751':'Kcell KZ','752':'Kcell KZ','753':'Kcell KZ','754':'Kcell KZ',
      '755':'Kcell KZ','756':'Kcell KZ','757':'Kcell KZ','758':'Kcell KZ','759':'Kcell KZ',
      '760':'Altel KZ','761':'Altel KZ','762':'Altel KZ','763':'Altel KZ','764':'Altel KZ',
      '765':'Altel KZ','766':'Altel KZ','767':'Altel KZ','768':'Altel KZ','769':'Altel KZ',
      '770':'Beeline KZ','771':'Beeline KZ','772':'Beeline KZ','773':'Beeline KZ','774':'Beeline KZ',
      '775':'Beeline KZ','776':'Beeline KZ','777':'Beeline KZ','778':'Beeline KZ','779':'Beeline KZ',
    };
    // RU prefixes
    const ruOps = { '900':'MTS RU','901':'MTS RU','902':'MTS RU','903':'MTS RU','904':'MTS RU',
      '905':'MTS RU','906':'MTS RU','907':'MTS RU','908':'MTS RU','909':'MTS RU',
      '910':'MTS RU','911':'MTS RU','912':'MTS RU','913':'MTS RU','914':'MTS RU',
      '915':'MTS RU','916':'MTS RU','917':'MTS RU','918':'MTS RU','919':'MTS RU',
      '920':'MegaFon RU','921':'MegaFon RU','922':'MegaFon RU','923':'MegaFon RU','924':'MegaFon RU',
      '925':'MTS RU','926':'MTS RU','927':'MegaFon RU','928':'MegaFon RU','929':'MTS RU',
      '930':'MTS RU','931':'MegaFon RU','932':'MegaFon RU','933':'MegaFon RU','934':'MegaFon RU',
      '935':'MTS RU','936':'MTS RU','937':'MegaFon RU','938':'MegaFon RU','939':'MegaFon RU',
      '950':'Beeline RU','951':'Beeline RU','952':'Beeline RU','953':'Beeline RU','954':'Beeline RU',
      '955':'Beeline RU','956':'Beeline RU','957':'Beeline RU','958':'Beeline RU','959':'Beeline RU',
      '960':'Beeline RU','961':'Beeline RU','962':'Beeline RU','963':'Beeline RU','964':'Beeline RU',
      '965':'Beeline RU','966':'Beeline RU','967':'Beeline RU','968':'Beeline RU','969':'Beeline RU',
      '977':'MTS RU','978':'MTS RU (Crimea)','979':'MTS RU (Crimea)',
      '980':'MTS RU','981':'MTS RU','982':'MTS RU','983':'MTS RU','984':'MTS RU',
      '985':'MTS RU','986':'MTS RU','987':'MTS RU','988':'MTS RU','989':'MTS RU',
      '990':'Beeline RU','991':'Beeline RU','992':'MTS RU','993':'MTS RU','994':'MTS RU',
      '995':'MegaFon RU','996':'Beeline RU','997':'Beeline RU','998':'Beeline RU','999':'Beeline RU',
    };
    if (kzOps[p3]) { info.country = 'Kazakhstan'; info.operator = kzOps[p3]; info.prefix = '+7' + p3; }
    else if (ruOps[p3]) { info.country = 'Russia'; info.operator = ruOps[p3]; info.prefix = '+7' + p3; }
    else { info.operator = 'Unknown'; info.prefix = '+7' + p3; }
  } else if (d.startsWith('380')) {
    info.country = 'Ukraine'; info.prefix = '+380';
  } else if (d.startsWith('375')) {
    info.country = 'Belarus'; info.prefix = '+375';
  } else if (d.startsWith('998')) {
    info.country = 'Uzbekistan'; info.prefix = '+998';
  } else if (d.startsWith('996')) {
    info.country = 'Kyrgyzstan'; info.prefix = '+996';
  } else if (d.startsWith('992')) {
    info.country = 'Tajikistan'; info.prefix = '+992';
  } else if (d.startsWith('993')) {
    info.country = 'Turkmenistan'; info.prefix = '+993';
  } else if (d.startsWith('994')) {
    info.country = 'Azerbaijan'; info.prefix = '+994';
  }
  return info;
}

// ── Truecaller public search (unofficial, no auth) ──────────────────────────
async function truecallerLookup(phone) {
  try {
    // Truecaller doesn't have a free API — but we can check their public search
    // This is the closest free approach: search via their web
    const d = await jfetch(`https://api4.truecaller.com/v1/search?countryCode=KZ&dialCode=7&phone=${encodeURIComponent(phone.replace(/\D/g,'').slice(1))}&type=4&locAddr=&placement=SEARCHRESULTS%2CHISTORY%2CCONTACTVIEW&encoding=json`, {
      headers: { 'Authorization': 'Bearer anonymous', 'Accept': 'application/json' }
    });
    if (d._error || !d.data) return null;
    const p = d.data[0];
    if (!p) return null;
    return { name: p.name, type: p.phones?.[0]?.numberType, carrier: p.phones?.[0]?.carrier, score: p.score };
  } catch { return null; }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  IIN / BIN LOOKUP  /api/iin?q=900115300141
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/iin', async (req, res) => {
  const q = (req.query.q || '').replace(/\D/g, '').trim();
  if (!/^\d{12}$/.test(q)) return res.json({ error: 'IIN/BIN must be 12 digits' });

  const results = [];

  // 1. Client-side decodable data (always works)
  results.push({ source: 'IIN Decoder', data: decodeIIN(q) });

  // 2. KZ eGov public API — legal entity info (BIN)
  const d5 = parseInt(q[4]);
  if (d5 >= 4 && d5 <= 6) {
    // BIN → try legal entity lookup
    const egov = await jfetch(`https://stat.gov.kz/api/juridical/counter/api/?bin=${q}&lang=ru`);
    if (!egov._error && egov.obj) {
      results.push({ source: 'Stat.gov.kz', data: {
        name: egov.obj.name || egov.obj.nameRu,
        bin: egov.obj.bin,
        status: egov.obj.status,
        okedName: egov.obj.okedName,
        krpName: egov.obj.krpName,
        registrationDate: egov.obj.registrationDate,
        address: egov.obj.address,
        director: egov.obj.director,
      }});
    }

    // eGov business registry
    const egov2 = await jfetch(`https://egov.kz/services/P30.11/rest/bus-service/getBusInfo?bin=${q}`);
    if (!egov2._error && egov2.result) {
      results.push({ source: 'eGov Business', data: egov2.result });
    }

    // KGD tax payer search (public endpoint)
    const kgd = await jfetch(`https://kgd.gov.kz/ru/api/taxpayers/${q}`);
    if (!kgd._error) results.push({ source: 'KGD Taxpayer', data: kgd });

  } else {
    // IIN → individual
    // Try ENPF (pension fund) public check — just returns status
    const enpf = await jfetch(`https://www.enpf.kz/api/iin-check?iin=${q}`);
    if (!enpf._error) results.push({ source: 'ENPF', data: enpf });

    // eGov individual check
    const egov3 = await jfetch(`https://egov.kz/services/P30.11/rest/mobile-id/getStatus?iin=${q}`);
    if (!egov3._error) results.push({ source: 'eGov Status', data: egov3 });

    // Open Data Kazakhstan portal
    const opendata = await jfetch(`https://data.egov.kz/api/v4/iin_data?access_token=demo&iin=${q}`);
    if (!opendata._error && !opendata.status?.includes('error')) results.push({ source: 'OpenData KZ', data: opendata });
  }

  // 3. Leakcheck by IIN
  if (KEYS.leakcheck) {
    const d = await jfetch(`https://leakcheck.io/api/public?key=${KEYS.leakcheck}&check=${encodeURIComponent(q)}`);
    if (!d._error && d.found > 0) results.push({ source: 'LeakCheck', data: { found: d.found, sources: d.sources } });
  }

  res.json({ query: q, results });
});

function decodeIIN(n) {
  const d = n.split('').map(Number);
  // checksum
  const w1 = [1,2,3,4,5,6,7,8,9,10,11];
  const w2 = [3,4,5,6,7,8,9,10,11,1,2];
  let s = 0; for (let i=0;i<11;i++) s += d[i]*w1[i]; let c = s%11;
  if (c===10) { s=0; for (let i=0;i<11;i++) s+=d[i]*w2[i]; c=s%11; }
  const valid = c === d[11];

  const d5 = d[4];
  if (d5 >= 4 && d5 <= 6) {
    // BIN
    const typeMap = {4:'ЮЛ-резидент',5:'ЮЛ-нерезидент',6:'ИП'};
    const subMap  = {1:'головная организация',2:'филиал',3:'представительство'};
    const yy = String(d[0]).padStart(2,'0') + String(d[1]);
    const mm = String(d[2]).padStart(2,'0') + String(d[3]);
    return {
      type: 'BIN',
      regDate: `${mm}.20${yy}`,
      entityType: typeMap[d5] || 'неизвестно',
      subType: subMap[d[5]] || `код ${d[5]}`,
      checksum: valid,
    };
  } else {
    // IIN
    const cenMap = {1:'1800',2:'1800',3:'1900',4:'1900',5:'2000',6:'2000'};
    const cent = cenMap[d[6]] || '????';
    const yy2 = String(d[0]).padStart(2,'0') + String(d[1]);
    const mm2 = String(d[2]).padStart(2,'0') + String(d[3]);
    const dd2 = String(d[4]).padStart(2,'0') + String(d[5]);  // note: d[4]=d5 here is 0-3
    // recompute for IIN: first 6 digits = YYMMDD, 7th = century+gender
    const yr   = n.slice(0,2);
    const mo   = n.slice(2,4);
    const dy   = n.slice(4,6);
    const cent2= cenMap[d[6]];
    const fullYear = cent2 ? parseInt(cent2) + parseInt(yr) : '????';
    const dob  = `${dy}.${mo}.${fullYear}`;
    const gender = (d[6] % 2 === 1) ? 'Мужской ♂' : 'Женский ♀';
    const now  = new Date();
    const bDate= new Date(fullYear, parseInt(mo)-1, parseInt(dy));
    let age = now.getFullYear() - bDate.getFullYear();
    const mDiff = now.getMonth() - bDate.getMonth();
    if (mDiff < 0 || (mDiff === 0 && now.getDate() < bDate.getDate())) age--;
    return {
      type: 'IIN',
      dob,
      gender,
      age: isNaN(age) ? '?' : age,
      checksum: valid,
    };
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  EMAIL LOOKUP  /api/email?q=user@example.com
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/email', async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q.includes('@')) return res.json({ error: 'invalid email' });

  const results = [];
  const [user, domain] = q.split('@');

  // 1. HIBP — what sites/services did they register with?
  if (KEYS.hibp) {
    const d = await jfetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(q)}?truncateResponse=false`, {
      headers: { 'hibp-api-key': KEYS.hibp, 'User-Agent': 'OSINT-Core' }
    });
    if (!d._error && Array.isArray(d)) {
      results.push({ source: 'HaveIBeenPwned', data: {
        breachCount: d.length,
        sites: d.map(b => ({ name: b.Name, domain: b.Domain, date: b.BreachDate, dataClasses: b.DataClasses }))
      }});
    } else {
      // Try pastes too
      const p = await jfetch(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(q)}`, {
        headers: { 'hibp-api-key': KEYS.hibp, 'User-Agent': 'OSINT-Core' }
      });
      if (!p._error && Array.isArray(p)) {
        results.push({ source: 'HIBP Pastes', data: { pasteCount: p.length, pastes: p } });
      }
    }
  }

  // 2. Hunter.io email verification
  if (KEYS.hunter) {
    const d = await jfetch(`https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(q)}&api_key=${KEYS.hunter}`);
    if (!d._error && d.data) results.push({ source: 'Hunter.io', data: {
      result: d.data.result,
      score: d.data.score,
      regexp: d.data.regexp,
      gibberish: d.data.gibberish,
      disposable: d.data.disposable,
      webmail: d.data.webmail,
      mx_records: d.data.mx_records,
      smtp_server: d.data.smtp_server,
      smtp_check: d.data.smtp_check,
      accept_all: d.data.accept_all,
      block: d.data.block,
      sources: d.data.sources?.slice(0,5),
    }});
  }

  // 3. Gravatar profile
  const md5 = await emailMd5(q);
  if (md5) {
    const grav = await jfetch(`https://www.gravatar.com/${md5}.json`);
    if (!grav._error && grav.entry) {
      const e = grav.entry[0];
      results.push({ source: 'Gravatar', data: {
        name: e.displayName || e.name?.formatted,
        username: e.preferredUsername,
        location: e.currentLocation,
        bio: e.aboutMe,
        accounts: e.accounts,
        urls: e.urls,
        photos: e.photos,
      }});
    }
  }

  // 4. MX / deliverability check
  const mx = await jfetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
  if (!mx._error) {
    results.push({ source: 'MX Check', data: {
      domain,
      hasMx: !!(mx.Answer?.length),
      records: mx.Answer?.map(a => a.data) || [],
    }});
  }

  // 5. Leakcheck
  if (KEYS.leakcheck) {
    const d = await jfetch(`https://leakcheck.io/api/public?key=${KEYS.leakcheck}&check=${encodeURIComponent(q)}`);
    if (!d._error && d.found > 0) results.push({ source: 'LeakCheck Breaches', data: { found: d.found, sources: d.sources }});
  }

  // 6. Check social platforms that expose email→username
  const ghUser = await jfetch(`https://api.github.com/search/users?q=${encodeURIComponent(q)}+in:email`, {
    headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'OSINT-Core' }
  });
  if (!ghUser._error && ghUser.items?.length) {
    results.push({ source: 'GitHub Account', data: {
      login: ghUser.items[0].login,
      profileUrl: ghUser.items[0].html_url,
      avatar: ghUser.items[0].avatar_url,
    }});
  }

  // 7. Disify disposable check
  const dis = await jfetch(`https://www.disify.com/api/email/${encodeURIComponent(q)}`);
  if (!dis._error) results.push({ source: 'Disify', data: {
    format: dis.format,
    disposable: dis.disposable,
    dns: dis.dns,
    domain: dis.domain,
  }});

  res.json({ query: q, results });
});

async function emailMd5(email) {
  try {
    const { createHash } = require('crypto');
    return createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  } catch { return null; }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  USERNAME / NICKNAME LOOKUP  /api/username?q=handle
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/username', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ error: 'no query' });

  const results = [];

  // GitHub
  const gh = await jfetch(`https://api.github.com/users/${encodeURIComponent(q)}`, {
    headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'OSINT-Core' }
  });
  if (!gh._error && gh.login) results.push({ source: 'GitHub', found: true, data: {
    login: gh.login, name: gh.name, bio: gh.bio,
    company: gh.company, location: gh.location,
    email: gh.email, blog: gh.blog,
    followers: gh.followers, following: gh.following,
    publicRepos: gh.public_repos, created: gh.created_at,
    avatar: gh.avatar_url, url: gh.html_url,
  }});

  // Reddit
  const rd = await jfetch(`https://www.reddit.com/user/${encodeURIComponent(q)}/about.json`, {
    headers: { 'User-Agent': 'OSINT-Core/1.0' }
  });
  if (!rd._error && rd.data?.name) results.push({ source: 'Reddit', found: true, data: {
    name: rd.data.name, karma: rd.data.total_karma,
    link_karma: rd.data.link_karma, comment_karma: rd.data.comment_karma,
    created: new Date(rd.data.created_utc * 1000).toISOString(),
    verified: rd.data.verified, icon: rd.data.icon_img,
    is_gold: rd.data.is_gold, is_mod: rd.data.is_mod,
  }});

  // Keybase
  const kb = await jfetch(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(q)}`);
  if (!kb._error && kb.them?.[0]) {
    const them = kb.them[0];
    results.push({ source: 'Keybase', found: true, data: {
      username: them.basics?.username,
      fullName: them.profile?.full_name,
      location: them.profile?.location,
      bio: them.profile?.bio,
      proofs: Object.keys(them.proofs_summary || {}),
    }});
  }

  // Telegram (public username check via t.me)
  const tg = await tfetch(`https://t.me/${encodeURIComponent(q)}`);
  if (tg.includes('tgme_page_title') || tg.includes('og:title')) {
    const nameMatch = tg.match(/<meta property="og:title" content="([^"]+)"/);
    const descMatch = tg.match(/<meta property="og:description" content="([^"]+)"/);
    if (nameMatch) results.push({ source: 'Telegram', found: true, data: {
      name: nameMatch[1], description: descMatch?.[1], url: `https://t.me/${q}`
    }});
  }

  // Twitter/X oEmbed (public, no auth)
  const tw = await jfetch(`https://publish.twitter.com/oembed?url=https://twitter.com/${encodeURIComponent(q)}`);
  if (!tw._error && tw.author_name) results.push({ source: 'Twitter/X', found: true, data: {
    name: tw.author_name, url: tw.author_url
  }});

  // Instagram (public page scrape — checks existence)
  const ig = await tfetch(`https://www.instagram.com/${encodeURIComponent(q)}/?__a=1&__d=dis`);
  if (ig && ig.includes('"username"')) {
    try {
      const parsed = JSON.parse(ig);
      const u = parsed.graphql?.user || parsed.data?.user;
      if (u) results.push({ source: 'Instagram', found: true, data: {
        username: u.username, name: u.full_name,
        bio: u.biography, followers: u.edge_followed_by?.count,
        following: u.edge_follow?.count, posts: u.edge_owner_to_timeline_media?.count,
        verified: u.is_verified, private: u.is_private,
      }});
    } catch {}
  }

  // TikTok (public metadata)
  const tk = await tfetch(`https://www.tiktok.com/@${encodeURIComponent(q)}`);
  if (tk && tk.includes('"uniqueId"')) {
    const nicknameMatch = tk.match(/"nickname":"([^"]+)"/);
    const sigMatch = tk.match(/"signature":"([^"]+)"/);
    const fansMatch = tk.match(/"followerCount":(\d+)/);
    if (nicknameMatch) results.push({ source: 'TikTok', found: true, data: {
      nickname: nicknameMatch[1],
      bio: sigMatch?.[1],
      followers: fansMatch?.[1],
      url: `https://www.tiktok.com/@${q}`,
    }});
  }

  // Twitch
  const twitch = await tfetch(`https://www.twitch.tv/${encodeURIComponent(q)}`);
  if (twitch && twitch.includes('"displayName"')) {
    const dnMatch = twitch.match(/"displayName":"([^"]+)"/);
    if (dnMatch) results.push({ source: 'Twitch', found: true, data: {
      displayName: dnMatch[1], url: `https://www.twitch.tv/${q}`
    }});
  }

  // Steam vanity URL
  const steam = await tfetch(`https://steamcommunity.com/id/${encodeURIComponent(q)}`);
  if (steam && steam.includes('class="persona_name"')) {
    const steamNameMatch = steam.match(/class="persona_name">([^<]+)</);
    if (steamNameMatch) results.push({ source: 'Steam', found: true, data: {
      name: steamNameMatch[1].trim(), url: `https://steamcommunity.com/id/${q}`
    }});
  }

  // Pinterest
  const pin = await jfetch(`https://www.pinterest.com/${encodeURIComponent(q)}/`);
  if (!pin._error && pin.resource_response?.data?.full_name) {
    results.push({ source: 'Pinterest', found: true, data: {
      name: pin.resource_response.data.full_name,
      bio: pin.resource_response.data.about,
    }});
  }

  res.json({ query: q, results });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DOMAIN LOOKUP  /api/domain?q=example.com
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/domain', async (req, res) => {
  const q = (req.query.q || '').trim().replace(/^https?:\/\//,'').split('/')[0];
  if (!q) return res.json({ error: 'no domain' });

  const results = [];

  // WHOIS XML
  const whois = await jfetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${KEYS.whoisxml}&domainName=${encodeURIComponent(q)}&outputFormat=JSON`);
  if (!whois._error && whois.WhoisRecord) {
    const w = whois.WhoisRecord;
    results.push({ source: 'WHOIS', data: {
      domain: w.domainName,
      registrar: w.registrarName,
      registrant: w.registrant?.name || w.registrant?.organization,
      registrantEmail: w.registrant?.email,
      registrantCountry: w.registrant?.country,
      created: w.createdDate,
      expires: w.expiresDate,
      updated: w.updatedDate,
      nameservers: w.nameServers?.hostNames || [],
      status: w.status,
    }});
  }

  // crt.sh SSL certs
  const crt = await jfetch(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json`);
  if (!crt._error && Array.isArray(crt)) {
    const unique = [...new Set(crt.map(c => c.name_value).join('\n').split('\n'))].filter(x=>x&&!x.startsWith('*')).slice(0,30);
    results.push({ source: 'crt.sh Subdomains', data: {
      count: unique.length,
      subdomains: unique,
      latestCert: crt[0]?.issuer_name,
    }});
  }

  // DNS records
  for (const type of ['A','AAAA','MX','NS','TXT','CNAME']) {
    const d = await jfetch(`https://dns.google/resolve?name=${encodeURIComponent(q)}&type=${type}`);
    if (!d._error && d.Answer?.length) {
      results.push({ source: `DNS ${type}`, data: d.Answer.map(a => ({ name: a.name, type: a.type, data: a.data, ttl: a.TTL })) });
    }
  }

  // VirusTotal
  if (KEYS.virustotal) {
    const vt = await jfetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(q)}`, {
      headers: { 'x-apikey': KEYS.virustotal }
    });
    if (!vt._error && vt.data?.attributes) {
      const a = vt.data.attributes;
      results.push({ source: 'VirusTotal', data: {
        reputation: a.reputation,
        malicious: a.last_analysis_stats?.malicious,
        suspicious: a.last_analysis_stats?.suspicious,
        harmless: a.last_analysis_stats?.harmless,
        categories: a.categories,
        tags: a.tags,
        creationDate: a.creation_date,
        registrar: a.registrar,
      }});
    }
  }

  // Shodan host info for domain's IP
  if (KEYS.shodan) {
    // resolve first
    const dnsA = await jfetch(`https://dns.google/resolve?name=${encodeURIComponent(q)}&type=A`);
    const ip = dnsA.Answer?.[0]?.data;
    if (ip) {
      const sh = await jfetch(`https://api.shodan.io/shodan/host/${ip}?key=${KEYS.shodan}`);
      if (!sh._error) results.push({ source: 'Shodan', data: {
        ip, org: sh.org, isp: sh.isp, country: sh.country_name,
        ports: sh.ports, hostnames: sh.hostnames,
        vulns: sh.vulns, os: sh.os,
      }});
    }
  }

  res.json({ query: q, results });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  IP LOOKUP  /api/ip?q=1.2.3.4
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/ip', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ error: 'no IP' });

  const results = [];

  // ipinfo.io
  const token = KEYS.ipinfo ? `?token=${KEYS.ipinfo}` : '';
  const ip = await jfetch(`https://ipinfo.io/${encodeURIComponent(q)}/json${token}`);
  if (!ip._error) results.push({ source: 'ipinfo.io', data: {
    ip: ip.ip, hostname: ip.hostname, city: ip.city,
    region: ip.region, country: ip.country, loc: ip.loc,
    org: ip.org, postal: ip.postal, timezone: ip.timezone,
  }});

  // ipapi.co
  const ipapi = await jfetch(`https://ipapi.co/${encodeURIComponent(q)}/json/`);
  if (!ipapi._error && ipapi.ip) results.push({ source: 'ipapi.co', data: {
    ip: ipapi.ip, city: ipapi.city, region: ipapi.region,
    country: ipapi.country_name, isp: ipapi.org, asn: ipapi.asn,
    latitude: ipapi.latitude, longitude: ipapi.longitude,
    timezone: ipapi.timezone, currency: ipapi.currency,
  }});

  // Shodan
  if (KEYS.shodan) {
    const sh = await jfetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(q)}?key=${KEYS.shodan}`);
    if (!sh._error) results.push({ source: 'Shodan', data: {
      org: sh.org, isp: sh.isp, country: sh.country_name,
      ports: sh.ports, hostnames: sh.hostnames, vulns: sh.vulns, os: sh.os,
      data: sh.data?.slice(0,5).map(d=>({ port:d.port, transport:d.transport, product:d.product, version:d.version })),
    }});
  }

  res.json({ query: q, results });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  NAME LOOKUP  /api/name?q=John+Doe
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/name', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ error: 'no query' });

  const results = [];

  // GitHub people search
  const gh = await jfetch(`https://api.github.com/search/users?q=${encodeURIComponent(q)}+in:fullname&per_page=5`, {
    headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'OSINT-Core' }
  });
  if (!gh._error && gh.items?.length) {
    results.push({ source: 'GitHub People', data: gh.items.map(u => ({
      login: u.login, url: u.html_url, avatar: u.avatar_url
    }))});
  }

  // Keybase search by name
  const kb = await jfetch(`https://keybase.io/_/api/1.0/user/autocomplete.json?q=${encodeURIComponent(q)}`);
  if (!kb._error && kb.completions?.length) {
    results.push({ source: 'Keybase Search', data: kb.completions.slice(0,5).map(c => ({
      username: c.components?.username?.val,
      fullName: c.components?.full_name?.val,
      bio: c.components?.bio?.val,
    }))});
  }

  // WebMii public search
  const wm = await tfetch(`https://webmii.com/people?n=${encodeURIComponent(q)}`);
  if (wm) {
    const matches = [];
    const nameRe = /class="name"[^>]*>([^<]+)</g;
    let m;
    while ((m = nameRe.exec(wm)) !== null && matches.length < 5) {
      matches.push(m[1].trim());
    }
    if (matches.length) results.push({ source: 'WebMii', data: { matches }});
  }

  res.json({ query: q, results });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  GEO LOOKUP  /api/geo?q=lat,lon  OR  /api/geo?q=address
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/geo', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ error: 'no query' });

  const results = [];
  const latLonRe = /^-?\d+\.?\d*,\s*-?\d+\.?\d*$/;

  if (latLonRe.test(q)) {
    const [lat, lon] = q.split(',');
    const nom = await jfetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`, {
      headers: { 'User-Agent': 'OSINT-Core/1.0' }
    });
    if (!nom._error) results.push({ source: 'Nominatim Reverse', data: {
      display: nom.display_name,
      address: nom.address,
      osm_type: nom.osm_type,
      osm_id: nom.osm_id,
    }});
  } else {
    const nom = await jfetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(q)}&limit=5&addressdetails=1`, {
      headers: { 'User-Agent': 'OSINT-Core/1.0' }
    });
    if (!nom._error && Array.isArray(nom)) results.push({ source: 'Nominatim Search', data: nom.map(r => ({
      display: r.display_name, lat: r.lat, lon: r.lon,
      type: r.type, class: r.class, importance: r.importance,
    }))});
  }

  res.json({ query: q, results });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PLATE LOOKUP  /api/plate?q=A001BC
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/api/plate', async (req, res) => {
  const q = (req.query.q || '').trim().toUpperCase().replace(/\s/g,'');
  if (!q) return res.json({ error: 'no plate' });

  const results = [];

  // KZ plate region decode
  results.push({ source: 'KZ Plate Decode', data: kzPlateDecode(q) });

  // RU plate region decode
  results.push({ source: 'RU Plate Decode', data: ruPlateDecode(q) });

  res.json({ query: q, results });
});

function kzPlateDecode(plate) {
  const kzRegions = {
    'A':'Almaty city','B':'Akmola','C':'Aktobe','D':'Almaty oblast',
    'E':'Atyrau','F':'East Kazakhstan','G':'Zhambyl','H':'West Kazakhstan',
    'I':'Karaganda','J':'Kostanay','K':'Kyzylorda','L':'Mangystau',
    'M':'Pavlodar','N':'North Kazakhstan','O':'Shymkent city',
    'P':'Turkestan','R':'Nur-Sultan (Astana)','S':'Shymkent',
    'T':'South Kazakhstan','U':'Ulytau','V':'Abai','Z':'Zhetisu',
  };
  const first = plate[0];
  return {
    plate,
    region: kzRegions[first] || 'Unknown',
    format: /^[A-Z]\d{3}[A-Z]{2}$/.test(plate) ? 'Standard KZ (X000XX)' :
            /^[A-Z]\d{4}[A-Z]$/.test(plate) ? 'Old KZ format' : 'Non-standard',
  };
}

function ruPlateDecode(plate) {
  const ruRegCodes = {
    '01':'Adygea','02':'Bashkortostan','03':'Buryatia','04':'Altai Republic',
    '05':'Dagestan','06':'Ingushetia','07':'Kabardino-Balkaria','08':'Kalmykia',
    '09':'Karachay-Cherkessia','10':'Karelia','11':'Komi','12':'Mari El',
    '13':'Mordovia','14':'Sakha (Yakutia)','15':'North Ossetia','16':'Tatarstan',
    '17':'Tuva','18':'Udmurtia','19':'Khakassia','20':'Chechnya',
    '21':'Chuvashia','22':'Altai Krai','23':'Krasnodar Krai','24':'Krasnoyarsk Krai',
    '25':'Primorsky Krai','26':'Stavropol Krai','27':'Khabarovsk Krai',
    '28':'Amur','29':'Arkhangelsk','30':'Astrakhan','31':'Belgorod',
    '32':'Bryansk','33':'Vladimir','34':'Volgograd','35':'Vologda',
    '36':'Voronezh','37':'Ivanovo','38':'Irkutsk','39':'Kaliningrad',
    '40':'Kaluga','41':'Kamchatka','42':'Kemerovo','43':'Kirov',
    '44':'Kostroma','45':'Kurgan','46':'Kursk','47':'Leningrad oblast',
    '48':'Lipetsk','49':'Magadan','50':'Moscow oblast','51':'Murmansk',
    '52':'Nizhny Novgorod','53':'Novgorod','54':'Novosibirsk','55':'Omsk',
    '56':'Orenburg','57':'Oryol','58':'Penza','59':'Perm',
    '60':'Pskov','61':'Rostov','62':'Ryazan','63':'Samara',
    '64':'Saratov','65':'Sakhalin','66':'Sverdlovsk','67':'Smolensk',
    '68':'Tambov','69':'Tver','70':'Tomsk','71':'Tula',
    '72':'Tyumen','73':'Ulyanovsk','74':'Chelyabinsk','75':'Chita (Zabaykalsky)',
    '76':'Yaroslavl','77':'Moscow','78':'St. Petersburg',
    '79':'Jewish AO','83':'Nenets AO','86':'Khanty-Mansi AO',
    '87':'Chukotka','89':'Yamalo-Nenets AO','95':'Chechnya',
    '96':'Sverdlovsk','97':'Moscow (fed)','98':'St. Petersburg (fed)',
    '99':'Moscow (fed)',
  };
  // Standard RU format: X000XX00 or similar
  const numMatch = plate.match(/(\d{2,3})$/);
  if (numMatch) {
    const code = numMatch[1].slice(-2);
    return {
      plate,
      region: ruRegCodes[code] || `Code ${code} (unknown)`,
      format: /^[А-ЯA-Z]\d{3}[А-ЯA-Z]{2}\d{2,3}$/.test(plate) ? 'Standard RU' : 'Non-standard',
    };
  }
  return { plate, region: 'Could not decode', format: 'Unknown' };
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ROOT + HEALTH
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/', (_, res) => res.json({
  name: 'OSINT Core API',
  status: 'online',
  version: '1.0.0',
  endpoints: ['/health','/api/phone','/api/iin','/api/email','/api/username','/api/domain','/api/ip','/api/name','/api/geo','/api/plate'],
}));

app.get('/health', (_, res) => res.json({
  status: 'ok',
  version: '1.0.0',
  endpoints: ['/api/phone','/api/iin','/api/email','/api/username','/api/domain','/api/ip','/api/name','/api/geo','/api/plate'],
  keys: Object.fromEntries(Object.entries(KEYS).map(([k,v]) => [k, v ? '✓ set' : '✗ missing'])),
}));

app.listen(PORT, () => console.log(`OSINT Core API running on :${PORT}`));
