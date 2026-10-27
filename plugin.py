"""Technitium DNS: record sync, custom records, and record discovery per host.

Records labdex manages carry the comment 'labdex'; nothing else is ever
changed or deleted. Endpoints used: zones/records/{get,add,delete}
(checked against Technitium DNS Server 15.6.2 APIDOCS.md).
"""
import ipaddress

from labdex.plugins.base import Change, Plugin as Base, PluginError

COMMENT = "labdex"
TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "SRV")


def _key(name, rtype, value):
    return (name.lower().rstrip("."), rtype, value)


def _norm_value(t: str, v: str) -> str:
    v = str(v).strip()
    if t == "CNAME":
        return v.lower().rstrip(".")
    if t == "TXT":
        return " ".join(part.strip('"') for part in v.split('" "'))
    if t == "SRV":
        prio, weight, port, target = v.split()
        return f"{int(prio)} {int(weight)} {int(port)} {target.lower().rstrip('.')}"
    if t == "MX":
        pref, exchange = v.split()
        return f"{int(pref)} {exchange.lower().rstrip('.')}"
    if t in ("A", "AAAA"):
        return str(ipaddress.ip_address(v))
    return v


def _value_from_api(rec: dict) -> str:
    t, d = rec.get("type"), rec.get("rData") or {}
    if t in ("A", "AAAA"):
        return d.get("ipAddress", "")
    if t == "CNAME":
        return (d.get("cname") or "").lower().rstrip(".")
    if t == "TXT":
        return d.get("text", "")
    if t == "SRV":
        return f"{d.get('priority')} {d.get('weight')} {d.get('port')} {(d.get('target') or '').lower().rstrip('.')}"
    if t == "MX":
        return f"{d.get('preference')} {(d.get('exchange') or '').lower().rstrip('.')}"
    return str(d)


# zone types that hold records labdex may write: Primary, and Conditional Forwarder zones
# (Technitium answers their records locally and forwards the rest, e.g. local names inside a
# public domain whose ACME challenges must still resolve upstream)
WRITABLE = {"Primary", "Forwarder"}


class Plugin(Base):
    """Zones: every zone labdex writes records into is synced; each record goes into the closest
    zone that exists on the server (zones/list). Extra zones are only read (import, host view)."""

    @property
    def domain(self) -> str:
        return self.ctx.inventory.settings()["domain"].rstrip(".").lower()

    @property
    def zone(self) -> str:
        """Base for custom record names: the old single-zone setting if set, else the domain."""
        return (self.settings.get("zone") or self.domain).rstrip(".").lower()

    def _call(self, path, **params):
        # Technitium 13+ reads the token from "Authorization: Bearer"; the form field is the fallback.
        api = self.ctx.http(self.settings["url"].rstrip("/") + "/api", headers={"Authorization": f"Bearer {self.settings['token']}"})
        r = api.post(path, data=params).json()
        if r.get("status") != "ok":
            raise PluginError(f"{path}: {r.get('errorMessage') or r.get('status')}")
        return r.get("response") or {}

    # --------------------------------------------------------------- zones
    def extra_zones(self) -> list[str]:
        raw = self.settings.get("extra_zones") or []
        if isinstance(raw, str):
            raw = raw.replace(",", " ").split()
        legacy = [self.settings["zone"]] if self.settings.get("zone") else []
        return list(dict.fromkeys(z.strip().rstrip(".").lower() for z in [*raw, *legacy] if z.strip()))

    def server_zones(self) -> list[str] | None:
        """Primary zones on the server, or None when the token may not list them."""
        if not hasattr(self, "_server_zones"):
            try:
                zs = self._call("zones/list").get("zones") or []
                self._server_zones = sorted({z["name"].lower() for z in zs if z.get("type") in WRITABLE and not z.get("internal")
                                             and not z.get("disabled") and z.get("name")}, key=lambda z: -len(z))
            except PluginError as exc:
                self.log(f"can't list zones ({exc}); using labdex's own zones")
                self._server_zones = None
        return self._server_zones

    def zone_for(self, fqdn: str) -> str | None:
        """The closest zone on the server that holds this name; None when there is none."""
        zones = self.server_zones()
        if zones is None:
            zones = sorted({*self.ctx.inventory.dns_zones(), *self.extra_zones()}, key=lambda z: -len(z))
        return next((z for z in zones if fqdn == z or fqdn.endswith("." + z)), None)

    def test(self):
        zones = self.server_zones()
        mine = self.ctx.inventory.dns_zones()
        if zones is None:
            recs = self._records(mine[0])
            return f"Connected; {mine[0]} has {len(recs)} records (the token can't list zones)"
        missing = [z for z in mine if not self.zone_for(z)]
        msg = f"Connected; {len(zones)} zone(s) on the server"
        return msg + (f"; missing for labdex: {', '.join(missing)}" if missing else "")

    def _records(self, zone: str | None = None):
        zone = zone or self.zone
        resp = self._call("zones/records/get", domain=zone, zone=zone, listZone="true")
        return resp.get("records") or []

    def sync_zones(self, desired: dict | None = None) -> list[str]:
        desired = self.desired() if desired is None else desired
        return sorted({m["zone"] for m in desired.values() if m.get("zone")})

    def read_zones(self) -> list[str]:
        """Zones to read from: those labdex writes into (as they exist on the server) plus the extra ones."""
        mine = [self.zone_for(z) for z in self.ctx.inventory.dns_zones()]
        return list(dict.fromkeys([z for z in mine if z] + self.extra_zones()))

    def all_records(self, zones) -> list[dict]:
        out = []
        for z in zones:
            try:
                out += [r | {"_zone": z} for r in self._records(z)]
            except PluginError as exc:
                self.log(f"zone {z}: {exc}")
        return out

    # ------------------------------------------------------------- desired
    def _abs(self, name: str, default: str = "") -> str:
        name = (name or "").strip()
        if not name:
            return default
        if name == "@":
            return self.zone
        if name.endswith("."):
            return name.rstrip(".").lower()
        return f"{name}.{self.zone}".lower()

    def desired(self) -> dict:
        """key → {"source": "inventory"|"custom", "host": name, "zone": server zone}. Per-host extra records
        come from the inventory (the host's DNS tab) like every generated record."""
        out = {}
        self._new_zones: set[str] = set()
        hosts = {h["name"]: h for h in self.ctx.hosts()}
        all_names = {h["name"] for h in self.ctx.inventory.hosts()}
        no_zone: set[str] = set()

        def add(fqdn, rtype, value, source, host="", public=False):
            zone = self.zone_for(fqdn)
            if zone is None and public and self.settings.get("split_horizon", True):
                zone = fqdn  # its own zone, so the rest of the public domain still resolves outside
                self._new_zones.add(fqdn)
            if zone is None:
                no_zone.add(fqdn.split(".", 1)[-1] if "." in fqdn else fqdn)
                return
            try:
                k = _key(fqdn, rtype, _norm_value(rtype, value))
            except (ValueError, TypeError):
                self.log(f"skip {fqdn} {rtype} {value!r}: malformed value")
                return
            out.setdefault(k, {"source": source, "host": host, "zone": zone})

        for r in self.ctx.inventory.dns_records():
            host = r.get("host") or ""
            if host and host in all_names:
                h = hosts.get(host)
                if h is None or h["module_settings"].get("skip_generated"):
                    continue  # not selected for this integration, or opted out
            add(r["fqdn"].lower(), r["type"], r["value"], "inventory", host, r.get("public", False))
        for r in self.settings.get("custom_records") or []:
            add(self._abs(r.get("name"), self.zone), r["type"], r["value"], "custom")
        if no_zone:
            self.log("no zone on the server for: " + ", ".join(sorted(no_zone)) + " (create the zone in Technitium to publish these)")
        return out

    # ---------------------------------------------------------------- sync
    def plan_sync_records(self, params):
        desired = self.desired()
        zones = self.sync_zones(desired)
        self.log("zones: " + (", ".join(zones) or "none"))
        new_zones = sorted(self._new_zones)
        existing = {_key(rec.get("name", ""), rec.get("type"), _value_from_api(rec))
                    : rec for rec in self.all_records([z for z in zones if z not in new_zones])}
        changes = [Change("create", "zone", z, "split horizon: a zone of its own for this public name", data={"zone": z}) for z in new_zones]
        for k, meta in desired.items():
            if k not in existing:
                src = {"inventory": "", "custom": " (custom)"}[meta["source"]]
                changes.append(Change("create", "record", f"{k[0]} {k[1]}", f"{k[1]} {k[2]}{src}", None, k[2],
                                      {"name": k[0], "type": k[1], "value": k[2], "zone": meta["zone"]}))
        if self.settings.get("allow_delete", True):
            for k, rec in existing.items():
                if k not in desired and (rec.get("comments") or "") == COMMENT:
                    changes.append(Change("delete", "record", f"{k[0]} {k[1]}", f"{k[1]} {k[2]}", k[2], None,
                                          {"name": k[0], "type": k[1], "value": k[2], "zone": rec["_zone"]}))
        return changes

    def _params(self, rtype, value):
        if rtype in ("A", "AAAA"):
            return {"ipAddress": value}
        if rtype == "CNAME":
            return {"cname": value}
        if rtype == "TXT":
            return {"text": value}
        if rtype == "SRV":
            prio, weight, port, target = value.split()
            return {"priority": prio, "weight": weight, "port": port, "target": target}
        if rtype == "MX":
            pref, exchange = value.split()
            return {"preference": pref, "exchange": exchange}
        raise PluginError(f"unsupported record type {rtype}")

    def apply_sync_records(self, changes, params):
        errors, done = [], 0
        ttl = str(self.settings.get("ttl") or 300)
        for c in sorted(changes, key=lambda c: (c.kind != "zone", c.op != "delete")):  # new zones, then deletes, then the rest
            d = c.data
            try:
                if c.kind == "zone":
                    self._call("zones/create", zone=d["zone"], type="Primary")
                    if hasattr(self, "_server_zones"):
                        del self._server_zones
                elif c.op == "create":
                    self._call("zones/records/add", domain=d["name"], zone=d.get("zone") or self.zone, type=d["type"], ttl=ttl,
                               comments=COMMENT, **self._params(d["type"], d["value"]))
                else:
                    self._call("zones/records/delete", domain=d["name"], zone=d.get("zone") or self.zone, type=d["type"],
                               **self._params(d["type"], d["value"]))
                done += 1
                self.log(f"{c.op} {c.name} {d.get('value', '')}: ok")
            except PluginError as exc:
                errors.append(f"{c.op} {c.name}: {exc}")
                self.log(f"{c.op} {c.name}: FAILED {exc}")
        if errors:
            raise PluginError(f"{len(errors)} of {len(changes)} change(s) failed: " + "; ".join(errors[:5]))
        return {"applied": done}

    # ------------------------------------------------------------ discovery
    def run_import_records(self, params):
        known = {i[k] for h in self.ctx.inventory.hosts(include_offline=True) for i in h["interfaces"] for k in ("ip4", "ip6") if i.get(k)} | {a for h in self.ctx.inventory.hosts(include_offline=True) for i in h["interfaces"] for a in i.get("ip6_all") or []}
        entries, seen = [], set()
        zones = self.read_zones()
        for rec in self.all_records(zones):
            if rec.get("type") not in ("A", "AAAA"):
                continue
            ip = _value_from_api(rec)
            if ip and ip not in known and ip not in seen:
                seen.add(ip)
                entries.append({"ip": ip, "mac": "", "hostname": rec.get("name", ""), "vendor": ""})
        n = self.ctx.discovery.record_neighbours(f"dns:{self.ctx.name}", entries, mark_up=False)
        self.log(f"{n} address(es) in {', '.join(zones)} that aren't in the inventory")
        return {"addresses": n}

    # ------------------------------------------------------------ host view
    def server_records(self) -> dict:
        """For the DNS overview: every record in the zones labdex reads, and every record it
        wants, each with a status (in sync, missing, stale, unmanaged)."""
        desired = self.desired()
        zones = self.read_zones()
        existing = {_key(r.get("name", ""), r.get("type"), _value_from_api(r)): r for r in self.all_records(zones)}
        rows = []
        for k in sorted(set(desired) | set(existing)):
            rec, want = existing.get(k), desired.get(k)
            managed = rec is not None and (rec.get("comments") or "") == COMMENT
            status = "in sync" if rec is not None and want else "missing" if want else "stale" if managed else "unmanaged"
            rows.append({"name": k[0], "type": k[1], "value": k[2], "zone": (rec or {}).get("_zone") or (want or {}).get("zone") or "",
                         "status": status, "host": (want or {}).get("host", ""), "source": (want or {}).get("source", "")})
        return {"zones": zones, "records": rows}

    def host_view(self, host: dict) -> dict:
        """Every record in the zone that belongs to this host, compared with what labdex wants."""
        labels = {host["name"]} | {n for n in (host.get("fun_names") or ([host["fun"]] if host.get("fun") else [])) if n}
        ips = {i[k] for i in host["interfaces"] for k in ("ip4", "ip6") if i.get(k)} | {a for i in host["interfaces"] for a in i.get("ip6_all") or []}
        desired = {k: m for k, m in self.desired().items() if m.get("host") == host["name"]}
        own_names = {k[0] for k in desired}
        zones = self.read_zones()
        try:
            zone_records = self.all_records(zones)
        except PluginError as exc:
            return {"error": str(exc)}
        existing = {_key(r.get("name", ""), r.get("type"), _value_from_api(r)): r for r in zone_records}
        targets = own_names | {f"{label}.{z}" for label in labels for z in zones}

        def related(k):
            name, rtype, value = k
            first = name.split(".")[0]
            if first in labels or any(name.startswith(f"{label}-") for label in labels) or name in own_names:
                return "name"
            if rtype in ("A", "AAAA") and value in ips:
                return "address"
            if rtype in ("CNAME", "SRV", "MX") and value.split()[-1] in targets:
                return "points here"
            return ""

        rows = []
        for k in sorted(set(desired) | {k for k in existing if related(k)}):
            rec = existing.get(k)
            managed = rec is not None and (rec.get("comments") or "") == COMMENT
            if k in desired and rec is not None:
                status, tone = "in sync", "ok"
            elif k in desired:
                status, tone = "missing: sync to create", "warn"
            elif managed:
                status, tone = "stale: next sync deletes it", "warn"
            else:
                stale_ip = k[1] in ("A", "AAAA") and k[2] not in ips
                status, tone = ("unmanaged, points to an address the host doesn't have", "err") if stale_ip else ("unmanaged", "")
            rows.append({"name": k[0], "type": k[1], "value": k[2], "matched_by": related(k) or desired.get(k, {}).get("source", ""),
                         "status": status, "_tone": tone})
        counts = {}
        for r in rows:
            counts[r["_tone"]] = counts.get(r["_tone"], 0) + 1
        return {
            "summary": [{"label": "in sync", "value": counts.get("ok", 0), "tone": "ok"},
                        {"label": "to change", "value": counts.get("warn", 0), "tone": "warn"},
                        {"label": "suspicious", "value": counts.get("err", 0), "tone": "err"},
                        {"label": "unmanaged", "value": counts.get("", 0), "tone": ""}],
            "sections": [{
                "title": f"Records in {', '.join(zones)}", "type": "table",
                "columns": [{"key": "name", "label": "Name"}, {"key": "type", "label": "Type"}, {"key": "value", "label": "Value"},
                            {"key": "matched_by", "label": "Why"}, {"key": "status", "label": "Status"}],
                "rows": rows, "empty": "No records in the zone relate to this host.",
            }],
            "note": "Matched by the host name, fun name, its addresses, and names pointing at it. Unmanaged records are never changed.",
        }
