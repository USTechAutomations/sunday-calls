"use strict";
// Shared by index.html and r/index.html. Everything from a lookup or a result file is untrusted: textContent only.
const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const BLOCKED = /^(gmail|googlemail|yahoo|outlook|hotmail|live|msn|aol|icloud|me|proton|protonmail|gmx|mail|yandex|zoho|example)\.(com|me|org|net)$|\.(local|internal|localhost|lan|test|invalid|onion|corp|home|intranet|example)$/;
const TYPES = { MX: 15, TXT: 16, CNAME: 5 };
const DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"];
const COULD_NOT = "could not look this up";
const DMARC_NONE = "Your DMARC policy is p=none: it only watches and reports. It does not block any fake mail yet.";  // same words as the service (tested)

function cleanDomain(text) {
  const s = String(text || "").trim().toLowerCase().replace(/^https?:\/\//, "").split(/[\/?#]/)[0].replace(/^www\./, "");
  return DOMAIN_RE.test(s) ? s : null;
}
function parseData(data, type) {
  const d = String(data);
  if (type === "TXT") {  // quoted, sometimes several quoted pieces: join them
    const m = d.match(/"(?:[^"\\]|\\.)*"/g);
    return m ? m.map(x => x.slice(1, -1).replace(/\\(.)/g, "$1")).join("") : d;
  }
  return d.trim().split(/\s+/).pop().replace(/\.$/, "").toLowerCase();  // MX "10 host." or CNAME "host."
}
async function ask(url, name, type) {
  const r = await fetch(url + "?name=" + encodeURIComponent(name) + "&type=" + type,
    { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error("http " + r.status);
  const j = await r.json();
  if (j.Status !== 0 && j.Status !== 3) throw new Error("status " + j.Status);  // 3 = name does not exist = no records
  return (j.Answer || []).filter(a => a.type === TYPES[type]).map(a => parseData(a.data, type));
}
async function lookup(name, type) {  // array of answers, or null when both services failed (never "missing")
  for (const u of DOH) { try { return await ask(u, name, type); } catch (e) { /* try the next service */ } }
  return null;
}

// Only what the free check can see in the SPF line itself. The service also follows includes; if it still says no, the buyer is refunded.
const TERM = /^(?:\+?(?:include:[a-z0-9._-]+|(?:a|mx)(?::[a-z0-9._-]+)?(?:\/\d{1,2})?(?:\/\/\d{1,3})?)|[+?~-]?ip[46]:[0-9a-f:.]+(?:\/\d{1,3})?)$/i;
function spfRefusal(record, inc) {
  const tk = record.trim().split(/\s+/).slice(1), end = tk.findIndex(x => /^[+?~-]?all$/i.test(x)), terms = end < 0 ? tk : tk.slice(0, end);
  const need = inc && !terms.some(x => x.toLowerCase().replace(/^\+/, "") === "include:" + inc) ? ["include:" + inc] : [];
  const cidr = x => { const m = /^\+?(?:a|mx)(?::[^\/]+)?(?:\/(\d+))?(?:\/\/(\d+))?$/i.exec(x); return !!m && (+m[1] > 32 || +m[2] > 128); };
  if (terms.some(x => !TERM.test(x) || cidr(x))) return "your current SPF line has an entry we cannot safely keep";
  if (terms.filter(x => /^\+?(include:|a(:|\/|$)|mx(:|\/|$))/i.test(x)).length + need.length > 10) return "your SPF line would need more than 10 lookups";
  if (("v=spf1 " + terms.concat(need).join(" ") + " -all").length > 255) return "your finished SPF line would be too long to paste as one line";
  return null;
}
function judge(mx, txt, dmarcTxt, dkimAnswers, providers) {
  const P = providers, unknown = { state: "unknown", why: COULD_NOT };
  const ok = why => ({ state: "ok", why }), bad = why => ({ state: "bad", why });
  let provider = null, host = mx === null ? "unknown" : "none";
  if (mx && mx.length) {
    const keys = new Set(mx.map(h => Object.keys(P).find(k => P[k].kind === "mailbox" &&
      P[k].mx_suffixes.some(m => h === m || h.endsWith("." + m))) || ""));
    provider = keys.size === 1 && !keys.has("") ? [...keys][0] : null;
    host = provider ? "ok" : keys.has("") ? "unsupported" : "mixed";
  }
  let refuse = null, spf = unknown, dmarc = unknown, dkim = { state: "na", why: "only checked for mail providers we support" };
  if (txt) {
    const r = txt.filter(t => /^v=spf1(\s|$)/i.test(t.trim()));
    if (r.length !== 1) spf = bad(r.length ? "more than one SPF line" : "no SPF line found");
    else {
      const tk = r[0].trim().split(/\s+/), inc = provider && P[provider].spf_include;
      if (!/^[-~]all$/i.test(tk[tk.length - 1])) spf = bad("the line does not end in -all or ~all");
      else if (inc && !tk.some(t => t.toLowerCase().replace(/^\+/, "") === "include:" + inc)) spf = bad("it does not list " + inc);
      else spf = ok("one SPF line, ending safely");
      refuse = spfRefusal(r[0], inc);
    }
  }
  if (dmarcTxt) {
    const r = dmarcTxt.filter(t => /^v=DMARC1/i.test(t.trim()));
    if (r.length !== 1) dmarc = bad(r.length ? "more than one DMARC line" : "no DMARC line found");
    else dmarc = /(^|;)\s*p=/i.test(r[0]) ? ok("one DMARC line with a policy." + (/(^|;)\s*p=none\s*(;|$)/i.test(r[0]) ? " " + DMARC_NONE : "")) : bad("the DMARC line has no policy (p=)");
  }
  if (provider) {
    const got = P[provider].dkim.hosts.map(h => (dkimAnswers || {})[h]);
    dkim = got.some(a => a == null) ? unknown : got.every(a => a.length) ? ok("found at the usual name") : bad("not found at the usual name");
  }
  const all = [spf, dkim, dmarc];
  return { provider, host, spf, dkim, dmarc, needsFix: !!provider && !refuse && all.some(x => x.state === "bad"), refuse,
    unknown: all.some(x => x.state === "unknown") };
}
function makeRef(domain, senders) {
  const ref = domain.replace(/\./g, "_") + senders.map(s => "__" + s).join("");
  return /^[A-Za-z0-9_-]+$/.test(ref) && ref.length <= 200 ? ref : null;
}
async function keyFor(sessionId) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionId));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

// Need: result files on the public site are encrypted with a key made from the session id (see orders.py seal).
async function unlock(sessionId, box) {
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("fd-result-v1\n" + sessionId));
  const k = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(box.iv) }, k, b64(box.ct))));
}

// ---- pages (browser only) ----
const $ = id => document.getElementById(id);
function el(tag, text, cls, parent) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  if (parent) parent.appendChild(e);
  return e;
}
async function getJSON(url, fallback) {
  try { const r = await fetch(url, { cache: "no-store" }); if (!r.ok) throw new Error(r.status); return await r.json(); }
  catch (e) { if (fallback !== undefined) return fallback; throw e; }
}
const VERBS = { ok: "Looks right: ", bad: "Needs fixing: ", unknown: "", na: "" };

async function checkPage(P, pay) {
  $("f").addEventListener("submit", async ev => {
    ev.preventDefault();
    const d = cleanDomain($("d").value), v = $("verdict"), buy = $("buy");
    $("res").hidden = false; $("res").scrollIntoView(); buy.hidden = true; $("rows").textContent = "";
    if (!Object.keys(P).length) { v.textContent = "We could not load the check. Please reload the page."; return; }  // no sheet: say so, run no lookups
    if (!d || BLOCKED.test(d)) { v.textContent = "That does not look like a business web address we can check (for example: acme-tools.co.uk)."; return; }
    v.textContent = "Looking up the public records for " + d + " ...";
    const [mx, txt, dm] = await Promise.all([lookup(d, "MX"), lookup(d, "TXT"), lookup("_dmarc." + d, "TXT")]);
    const pre = judge(mx, txt, dm, {}, P), dk = {};
    if (pre.provider) await Promise.all(P[pre.provider].dkim.hosts.map(async h => { dk[h] = await lookup(h + "." + d, P[pre.provider].dkim.type); }));
    const j = judge(mx, txt, dm, dk, P);
    [["SPF", "Lists who is allowed to send mail as you.", j.spf], ["DKIM", "A signature that proves mail really came from you.", j.dkim],
     ["DMARC", "Tells receiving mail systems what to do with mail that fails.", j.dmarc]].forEach(([n, what, s]) => {
      const tr = el("tr", null, null, $("rows")); el("th", n, null, tr); el("td", what, null, tr); el("td", VERBS[s.state] + s.why, null, tr);
    });
    if (j.host === "unknown") v.textContent = "We could not look up this address just now. Please try again in a minute.";
    else if (j.host === "none") v.textContent = "This address has no mail servers set up, so there is nothing for us to fix. Keep your money.";
    else if (!j.provider) v.textContent = "We cannot help with this mail provider yet. Nothing to pay.";
    else if (j.refuse) v.textContent = "We cannot fix this one: " + j.refuse + ". Nothing to pay.";
    else if (!j.needsFix && j.unknown) v.textContent = "A lookup failed, so the check is not finished. Please try again in a minute.";
    else if (!j.needsFix) v.textContent = "Nothing to fix on the points we can check. Keep your money.";
    else { v.textContent = fixLine(j); buyBlock(d, P, pay); }
  });
}
// lead, 10 Nov: when only DKIM is bad, say plainly what the money buys before the pay block
function fixLine(j) {
  return j.spf.state === "ok" && j.dmarc.state === "ok"
    ? "Your SPF and DMARC lines are already right. Only DKIM was not found at the usual name, and it may already be set up under another name. The paid fix would be the DKIM steps for your mail provider only."
    : "We found something to fix. Tick any other services that send mail as you, then choose.";
}
function buyBlock(d, P, pay) {
  const boxes = $("boxes"), note = $("buynote"); boxes.textContent = ""; $("buy").hidden = false;
  Object.keys(P).filter(k => P[k].kind === "bulk").forEach(k => {
    const l = el("label", " " + P[k].name, "btn-note", boxes), i = document.createElement("input");
    i.type = "checkbox"; i.value = k; i.addEventListener("change", links); l.prepend(i); boxes.appendChild(document.createElement("br"));
  });
  function links() {
    const senders = [...boxes.querySelectorAll("input:checked")].map(i => i.value), ref = makeRef(d, senders);
    let shown = 0;
    [["b49", "fix"], ["b99", "fix_recheck"]].forEach(([id, tier]) => {
      const a = $(id), url = pay[tier], good = ref && typeof url === "string" && /^https:\/\//.test(url);
      a.hidden = !good; if (good) { a.href = url + "?client_reference_id=" + ref; shown++; }
    });
    note.textContent = !ref ? "This name is too long to order." : shown ? "" : "Not on sale yet.";
  }
  links();
}

function lineBlock(out, title, how, text, host, note, changed) {  // the copy button only appears when the line really needs to go in
  const s = el("section", null, null, out); el("h2", title, null, s); el("p", how, null, s);
  const c = el("p", text, "card", s); c.style.overflowWrap = "anywhere"; c.style.fontFamily = "var(--mono)";
  if (changed) {
    const b = el("button", "Copy this line", "btn btn-ghost", s); b.type = "button";
    b.addEventListener("click", () => navigator.clipboard.writeText(text).then(() => { b.textContent = "Copied"; }));
  }
  if (note) el("p", note, null, s);
  const w = el("p", "Checking the live records ...", "btn-note", s);
  lookup(host, "TXT").then(a => { w.textContent = "Live look: " + (a === null ? COULD_NOT : a.some(x => norm(x) === norm(text)) ? "in place" : "not showing yet"); });
}
async function resultPage(P) {
  const sid = new URLSearchParams(location.search).get("s"), st = $("st"), out = $("out");
  if (!sid) { st.textContent = "This address is missing its order code. Use the link you were sent to after paying."; return; }
  const key = await keyFor(sid);
  let doc, box;
  try { box = await getJSON(key + ".json"); } catch (e) {
    st.textContent = "Your order is being worked on. This page checks again every minute. Bookmark it."; setTimeout(() => resultPage(P), 60000); return;
  }
  try { doc = await unlock(sid, box); } catch (e) { st.textContent = "We could not open this result. Use the exact link you were sent to after paying."; return; }
  const money = " The money is coming back, by a person at the company.";
  st.textContent = ({ ready: readyLine(doc.result),
    nothing_to_fix: "We found nothing to fix on " + doc.domain + "." + money,
    could_not_do: "We could not do this job: " + doc.reason + money,
    no_order_details: "We could not read your order details." + money })[doc.status] || "Unknown status.";
  out.textContent = "";
  const r = doc.result, list = (items, parent) => { const ol = el("ol", null, "steps", parent); items.forEach(t => el("li", t, null, ol)); };
  if (doc.status === "ready" && r) {
    const line = (...a) => lineBlock(out, ...a);
    line("1. SPF line", r.spf_changed ? "At your domain provider, delete every SPF record for " + doc.domain + " and add one TXT record named @ with this value." : "Your SPF line is already right. Leave it as it is.", r.final_spf, doc.domain, null, r.spf_changed);
    line("2. DMARC line", r.dmarc_changed ? "Add one TXT record named _dmarc (delete any older DMARC record first) with this value." : "Your DMARC line is already right. Leave it as it is.", r.final_dmarc, "_dmarc." + doc.domain, r.dmarc_note, r.dmarc_changed);
    const k = el("section", null, null, out); el("h2", "3. DKIM, " + r.dkim.name, null, k);
    if (r.dkim.valid) el("p", "We saw a DKIM key record published at " + r.dkim.hosts.join(", ") + ". We cannot see from outside whether " + r.dkim.name + " is switched on to sign your mail. Please check the switch: " + ((P[r.dkim.provider] || {}).dkim_switch || "in your mail provider's settings") + ".", null, k);
    else { el("p", "Only your mail provider can create this one. Follow these steps:", null, k); list(r.dkim.steps, k); }
    r.senders_info.forEach(x => { const s = el("section", null, null, out); el("h2", "Sending service: " + (P[x.key] ? P[x.key].name : x.key), null, s); list(x.steps, s); });
    if (r.problems.length) { const s = el("section", null, null, out); el("h2", "What we found", null, s); r.problems.forEach(t => el("p", t, null, s)); }
  }
  const lines = (title, items) => { if (!items.length) return; const s = el("section", null, null, out); el("h2", title, null, s); items.forEach(t => el("p", t, null, s)); };
  lines("Our tests", (doc.checks || []).map(c => niceName(c.name) + ": " + (c.pass ? "passed" : "failed") + (c.detail ? " (" + c.detail + ")" : "")));
  lines("Later looks", (doc.rechecks || []).map(x => "Day " + x.day + " look (" + String(x.ts).slice(0, 10) + "): " + (x.valid ? "all three settings valid. " : "not all three valid yet. ") + (x.note || "")));
}
function readyLine(r) {  // names only the lines that really need to go in
  const n = [r && r.spf_changed && "SPF", r && r.dmarc_changed && "DMARC"].filter(Boolean), tail = " and this page will show what it finds.";
  if (n.length === 2) return "Your fix is ready. Put the two lines in, follow the steps for the third setting," + tail;
  if (n.length) return "Your fix is ready. Put the " + n[0] + " line in (your other line is already right), follow the steps for the third setting," + tail;
  return "Your SPF and DMARC lines are already right. Only the third setting needs you: follow the steps below," + tail;
}
const niceName = s => { const w = String(s).replace(/_/g, " "); return w[0].toUpperCase() + w.slice(1); };
const norm = s => String(s).trim().split(/\s+/).join(" ").toLowerCase();

if (typeof module !== "undefined") module.exports = { fixLine, lineBlock, readyLine, niceName, BLOCKED, cleanDomain, judge, makeRef, keyFor, parseData, unlock };
if (typeof document !== "undefined") {
  const base = document.currentScript.src.replace(/[^\/]*$/, "");
  getJSON(base + "providers.json", {}).then(async P => {
    if ($("f")) { const pay = await getJSON(base + "pay.json", {}); if ($("presale") && Object.keys(pay).length) $("presale").hidden = true;  // the page says "not on sale yet" until a pay link exists
      checkPage(P, pay); }
    else if ($("out")) resultPage(P);
  });
}
