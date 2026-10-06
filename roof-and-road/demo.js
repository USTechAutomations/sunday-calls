/* Roof and Road free demo: required amount (Civil Code 5570(b)(4)) and percent funded for up to
   three components. Small on purpose; it is not the planner. Nothing leaves the page. */
(function (root) {
  "use strict";

  function toNum(v) {
    if (v === null || v === undefined) { return NaN; }
    var s = String(v).replace(/[$,\s]/g, "");
    return s === "" ? NaN : Number(s);
  }

  // Round half away from zero to `places` decimals.
  function roundTo(x, places) {
    var p = Math.pow(10, places);
    var v = Math.floor(Math.abs(x) * p + 0.5 + 1e-9) / p;
    return x < 0 ? -v : v;
  }

  function withCommas(x, places) {
    var r = roundTo(x, places);
    var parts = Math.abs(r).toFixed(places).split(".");
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return (r < 0 ? "-" : "") + parts.join(".");
  }

  // rows: [{cost, life, age}], reserves, units -> {need, pct, shortfall, used}
  function compute(rows, reserves, units) {
    var need = 0, used = 0;
    for (var i = 0; i < rows.length && i < 3; i++) {
      var cost = toNum(rows[i].cost), life = toNum(rows[i].life), age = toNum(rows[i].age);
      if (!(cost > 0) || !(life > 0) || !(age >= 0)) { continue; }
      var inService = age > life ? life : age;   // past its life: counted as fully due
      need += cost * inService / life;
      used += 1;
    }
    var cash = toNum(reserves), homes = toNum(units);
    var out = { need: need, used: used, pct: null, shortfall: null };
    if (need > 0 && cash >= 0) { out.pct = 100 * cash / need; }
    if (cash >= 0 && homes > 0) { out.shortfall = Math.max(0, need - cash) / homes; }
    return out;
  }

  // The item (6) sentence with the three numbers filled in (form: whole dollars, 1 decimal percent).
  function formLine(result, reserves) {
    var pct = result.pct === null ? "—" : withCommas(result.pct, 1);
    return "The estimated amount required in the reserve fund at the end of the current fiscal year is $" +
      withCommas(result.need, 0) + " ... The projected reserve fund cash balance at the end of the current " +
      "fiscal year is $" + withCommas(toNum(reserves) || 0, 0) + ", resulting in reserves being " + pct +
      " percent funded.";
  }

  var api = { compute: compute, formLine: formLine, roundTo: roundTo, withCommas: withCommas };
  root.RRDemo = api;
  if (typeof module !== "undefined" && module.exports) { module.exports = api; }

  if (typeof document === "undefined") { return; }

  function val(id) { var el = document.getElementById(id); return el ? el.value : ""; }
  function put(id, text) { var el = document.getElementById(id); if (el) { el.textContent = text; } }

  function update() {
    var rows = [];
    for (var i = 1; i <= 3; i++) {
      rows.push({ cost: val("d-c" + i), life: val("d-u" + i), age: val("d-a" + i) });
    }
    var res = val("d-res"), r = compute(rows, res, val("d-units"));
    put("d-need", "$" + withCommas(r.need, 0));
    put("d-pct", r.pct === null ? "—" : withCommas(r.pct, 2) + "%");
    put("d-short", r.shortfall === null ? "—" : "$" + withCommas(r.shortfall, 0));
    put("d-f-need", withCommas(r.need, 0));
    put("d-f-res", withCommas(toNum(res) || 0, 0));
    put("d-f-pct", r.pct === null ? "—" : withCommas(r.pct, 1));
    put("d-msg", r.used === 0
      ? "Enter a cost, a useful life and years in service for at least one component."
      : "Arithmetic on the numbers typed above, worked in this page. Nothing is sent anywhere. " +
        "Civil Code 5570 does not say how to round; this planner shows percent funded to one decimal place.");
  }

  function start() {
    var box = document.getElementById("demo");
    if (!box) { return; }
    box.addEventListener("input", update);
    update();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
}(typeof self === "object" ? self : this));
