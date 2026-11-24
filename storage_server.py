"""
storage_server.py

SQLite metadata storage, search queries, a text analyst CLI and a small
local web dashboard (standard library only, bound to 127.0.0.1).

Only metadata is stored: parties, timestamps, IPs, ports, tower id, size,
protocol, host and DPI flags. All queries use bound parameters.
"""

import base64
import csv
import getpass
import html
import json
import os
import sqlite3
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from access_control import CASE_RE

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id TEXT UNIQUE,
    ts REAL,
    ts_iso TEXT,
    protocol TEXT,
    caller_id TEXT,
    callee_id TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    cell_tower_id TEXT,
    packet_size INTEGER,
    host TEXT,
    flags TEXT,
    severity INTEGER,
    severity_level TEXT,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_meta_ts ON metadata(ts);
CREATE INDEX IF NOT EXISTS idx_meta_caller ON metadata(caller_id);
CREATE INDEX IF NOT EXISTS idx_meta_callee ON metadata(callee_id);
CREATE INDEX IF NOT EXISTS idx_meta_protocol ON metadata(protocol);
CREATE INDEX IF NOT EXISTS idx_meta_severity ON metadata(severity);
"""

COLUMNS = [
    ("id", "ID", 5), ("ts_iso", "TIME (UTC)", 20), ("protocol", "PROTO", 6),
    ("caller_id", "CALLER", 14), ("callee_id", "CALLEE", 14),
    ("src_ip", "SRC IP", 15), ("dst_ip", "DST IP", 15),
    ("cell_tower_id", "TOWER", 8), ("packet_size", "SIZE", 8),
    ("severity_level", "LEVEL", 7), ("flags", "FLAGS", 34),
]


class StorageServer:
    def __init__(self, db_path="sorm_metadata.db"):
        folder = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(folder, exist_ok=True)
        self.db_path = db_path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()

    def clear(self):
        with self.lock:
            self.conn.execute("DELETE FROM metadata")
            self.conn.commit()

    def insert_many(self, results):
        rows = [(
            r.packet_id, r.ts, r.ts_iso, r.protocol, r.caller_id, r.callee_id,
            r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.cell_tower_id,
            r.packet_size, r.host, ";".join(r.flags), r.severity,
            r.severity_level, r.summary) for r in results]
        with self.lock:
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO metadata (packet_id, ts, ts_iso, protocol, caller_id, "
                "callee_id, src_ip, dst_ip, src_port, dst_port, cell_tower_id, packet_size, "
                "host, flags, severity, severity_level, summary) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.conn.commit()
            return cur.rowcount

    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM metadata").fetchone()[0]

    def search(self, caller=None, callee=None, party=None, ip=None, protocol=None,
               tower=None, flag=None, min_severity=None, keyword=None,
               since=None, until=None, limit=50):
        clauses, params = [], []
        if caller:
            clauses.append("caller_id LIKE ?")
            params.append("%" + caller + "%")
        if callee:
            clauses.append("callee_id LIKE ?")
            params.append("%" + callee + "%")
        if party:
            clauses.append("(caller_id LIKE ? OR callee_id LIKE ?)")
            params.extend(["%" + party + "%"] * 2)
        if ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params.extend([ip, ip])
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol.upper())
        if tower:
            clauses.append("cell_tower_id = ?")
            params.append(tower.upper())
        if flag:
            clauses.append("flags LIKE ?")
            params.append("%" + flag + "%")
        if min_severity is not None:
            clauses.append("severity >= ?")
            params.append(int(min_severity))
        if keyword:
            clauses.append("(summary LIKE ? OR host LIKE ? OR flags LIKE ?)")
            params.extend(["%" + keyword + "%"] * 3)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(float(since))
        if until is not None:
            clauses.append("ts <= ?")
            params.append(float(until))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = "SELECT * FROM metadata" + where + " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def stats(self):
        with self.lock:
            q = self.conn.execute
            total = q("SELECT COUNT(*) FROM metadata").fetchone()[0]
            flagged = q("SELECT COUNT(*) FROM metadata WHERE severity > 0").fetchone()[0]
            total_bytes = q("SELECT COALESCE(SUM(packet_size),0) FROM metadata").fetchone()[0]
            by_proto = dict(q("SELECT protocol, COUNT(*) FROM metadata GROUP BY protocol").fetchall())
            by_level = dict(q("SELECT severity_level, COUNT(*) FROM metadata GROUP BY severity_level").fetchall())
            by_tower = dict(q("SELECT cell_tower_id, COUNT(*) FROM metadata GROUP BY cell_tower_id ORDER BY 2 DESC").fetchall())
            top_callers = [tuple(r) for r in q(
                "SELECT caller_id, COUNT(*) AS n FROM metadata WHERE caller_id != '' "
                "GROUP BY caller_id ORDER BY n DESC LIMIT 5").fetchall()]
            flag_rows = q("SELECT flags FROM metadata WHERE flags != ''").fetchall()
        kinds = Counter()
        for row in flag_rows:
            for item in row[0].split(";"):
                kinds[item.split(":")[0]] += 1
        return {
            "total_records": total, "flagged_records": flagged, "total_bytes": total_bytes,
            "by_protocol": by_proto, "by_severity_level": by_level, "by_tower": by_tower,
            "top_callers": top_callers, "flag_types": dict(kinds),
        }

    def export_csv(self, path, rows):
        if not rows:
            return 0
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
def format_rows(rows):
    if not rows:
        return "No matching records."
    header = " ".join(label.ljust(width) for _, label, width in COLUMNS)
    lines = [header, "-" * len(header)]
    for row in rows:
        lines.append(" ".join(str(row[key])[:width].ljust(width) for key, _, width in COLUMNS))
    return "\n".join(lines)


def format_stats(stats):
    lines = [
        "TOTAL RECORDS    : %d" % stats["total_records"],
        "FLAGGED RECORDS  : %d" % stats["flagged_records"],
        "TOTAL BYTES      : %d" % stats["total_bytes"],
        "BY PROTOCOL      : %s" % stats["by_protocol"],
        "BY SEVERITY      : %s" % stats["by_severity_level"],
        "FLAG TYPES       : %s" % stats["flag_types"],
        "BY TOWER         : %s" % stats["by_tower"],
        "TOP CALLERS      : %s" % stats["top_callers"],
    ]
    return "\n".join(lines)


AUDIT_COLUMNS = [
    ("id", "ID", 5), ("ts_iso", "TIME (UTC)", 20), ("username", "USER", 12),
    ("role", "ROLE", 8), ("action", "ACTION", 18), ("outcome", "RESULT", 8),
    ("case_ref", "CASE", 15), ("detail", "DETAIL", 60),
]


def format_audit(rows):
    if not rows:
        return "No audit entries."
    header = " ".join(label.ljust(width) for _, label, width in AUDIT_COLUMNS)
    lines = [header, "-" * len(header)]
    for row in rows:
        lines.append(" ".join(str(row[key] or "")[:width].ljust(width)
                              for key, _, width in AUDIT_COLUMNS))
    return "\n".join(lines)


def format_users(rows):
    lines = ["USERNAME".ljust(14) + "ROLE".ljust(10) + "ACTIVE".ljust(8) + "LOCKED".ljust(8) + "LAST LOGIN"]
    for r in rows:
        lines.append(r["username"].ljust(14) + r["role"].ljust(10) + str(bool(r["active"])).ljust(8)
                     + str(bool(r["locked"])).ljust(8) + str(r["last_login"] or "never"))
    return "\n".join(lines)


HELP_BY_ROLE = {
    "ANALYST": """  case CASE-2026-001      set the case reference for your next queries
  search key=value ...    keys: caller callee party ip protocol tower flag
                          min_severity keyword limit
  number NUMBER           records where NUMBER is caller or callee
  ip ADDRESS              records involving an IP address
  alerts                  records with severity 30 or higher
  export FILE.csv         export the last result set
  stats                   summary statistics""",
    "AUDITOR": """  audit [limit=N] [user=NAME] [action=TEXT]   show the audit log
  verify                  check the audit hash chain for tampering
  stats                   summary statistics""",
    "ADMIN": """  users                   list accounts
  adduser NAME ROLE       create an account (ROLE: ADMIN, ANALYST, AUDITOR)
  resetpw NAME            reset a password and unlock the account
  disable NAME            disable an account
  enable NAME             enable an account
  unlock NAME             clear a lockout
  stats                   summary statistics""",
}


def help_text(role):
    return ("COMMANDS FOR ROLE %s\n%s\n  passwd                  change your own password\n"
            "  whoami                  show your login\n  help                    this text\n"
            "  quit                    leave the terminal") % (role, HELP_BY_ROLE.get(role, ""))


def _read_new_password():
    first = getpass.getpass("New password: ")
    second = getpass.getpass("Repeat new password: ")
    if first != second:
        print("Passwords do not match.")
        return None
    return first


def _parse_filters(args, allowed):
    filters = {}
    for item in args:
        if "=" not in item:
            return None
        key, value = item.split("=", 1)
        if key not in allowed:
            return None
        filters[key] = value
    return filters


def analyst_cli(ctl, session):
    print("\nTERMINAL: logged in as %s (%s). Every action is audited. Type help."
          % (session.username, session.role))
    case_ref = None
    last = []
    allowed = {"caller", "callee", "party", "ip", "protocol", "tower", "flag",
               "min_severity", "keyword", "limit"}
    while True:
        try:
            line = input("sorm:%s> " % session.username).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ("quit", "exit", "q"):
            return
        if cmd == "help":
            print(help_text(session.role))
        elif cmd == "whoami":
            print("%s (%s)" % (session.username, session.role))
        elif cmd == "passwd":
            old = getpass.getpass("Current password: ")
            new = _read_new_password()
            if new is not None:
                print(ctl.change_own_password(session, old, new)[1])
        elif cmd == "stats":
            ok, res = ctl.stats(session)
            print(format_stats(res) if ok else res)
        elif cmd == "case":
            if args and CASE_RE.match(args[0].upper()):
                case_ref = args[0].upper()
                print("Case reference set to %s" % case_ref)
            else:
                print("Invalid case reference. Example: CASE-2026-001")
        elif cmd in ("search", "number", "ip", "alerts"):
            if cmd == "search":
                filters = _parse_filters(args, allowed)
            elif cmd == "alerts":
                filters = {"min_severity": 30, "limit": 40}
            elif args:
                filters = {"party" if cmd == "number" else "ip": args[0], "limit": 40}
            else:
                filters = None
            if filters is None:
                print("Invalid syntax. Type help.")
                continue
            ok, res = ctl.search(session, case_ref, **filters)
            if ok:
                last = res
                print(format_rows(res))
            else:
                print(res)
        elif cmd == "export" and args:
            print(ctl.export(session, case_ref, args[0], last)[1])
        elif cmd == "audit":
            opts = _parse_filters(args, {"limit", "user", "action"})
            if opts is None:
                print("Invalid syntax. Type help.")
                continue
            ok, res = ctl.view_audit(session, **opts)
            print(format_audit(res) if ok else res)
        elif cmd == "verify":
            print(ctl.verify_audit(session)[1])
        elif cmd == "users":
            ok, res = ctl.list_users(session)
            print(format_users(res) if ok else res)
        elif cmd == "adduser" and len(args) == 2:
            if "ADMIN" == session.role:
                password = _read_new_password()
                if password is not None:
                    print(ctl.add_user(session, args[0], password, args[1])[1])
            else:
                print(ctl.add_user(session, args[0], "x", args[1])[1])
        elif cmd == "resetpw" and args:
            password = _read_new_password() if session.role == "ADMIN" else "x"
            if password is not None:
                print(ctl.reset_password(session, args[0], password)[1])
        elif cmd == "disable" and args:
            print(ctl.disable_user(session, args[0])[1])
        elif cmd == "enable" and args:
            print(ctl.enable_user(session, args[0])[1])
        elif cmd == "unlock" and args:
            print(ctl.unlock_user(session, args[0])[1])
        else:
            print("Unknown command. Type help.")


# ---------------------------------------------------------------------------
# Web dashboard (local only, HTTP Basic login, every request audited)
# ---------------------------------------------------------------------------
def _to_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


PAGE_STYLE = (
    "<style>body{font-family:Arial,sans-serif;margin:20px;background:whitesmoke}"
    "table{border-collapse:collapse;width:100%;font-size:12px;background:white}"
    "th,td{border:1px solid lightgray;padding:4px 6px;text-align:left}"
    "th{background:darkslategray;color:white}"
    ".card{display:inline-block;margin:4px;padding:8px 14px;background:white;border:1px solid lightgray}"
    ".HIGH{background:mistyrose}.MEDIUM{background:lightyellow}label{margin-right:10px}"
    ".warn{color:darkred}</style>")


def _page(session, body):
    esc = html.escape
    return ("<!doctype html><html><head><meta charset='utf-8'><title>SORM Simulation Dashboard</title>"
            + PAGE_STYLE + "</head><body><h2>SORM Simulation Dashboard</h2>"
            "<p>Educational simulation, synthetic data. Logged in as <b>%s</b> (%s). "
            "<a href='/'>Search</a> | <a href='/audit'>Audit log</a> | <a href='/stats'>Stats JSON</a></p>"
            % (esc(session.username), esc(session.role)) + body + "</body></html>")


def render_search_page(ctl, session, q):
    esc = html.escape

    def field(name, label):
        return "<label>%s <input name='%s' value='%s'></label>" % (label, name, esc(q.get(name, "")))

    notice, rows = "", None
    if "case" in q:
        ok, result = ctl.search(
            session, q.get("case", "").strip().upper(),
            party=q.get("party") or None, ip=q.get("ip") or None,
            protocol=q.get("protocol") or None, tower=q.get("tower") or None,
            min_severity=_to_int(q.get("min_severity")), keyword=q.get("keyword") or None,
            limit=_to_int(q.get("limit"), 50) or 50)
        if ok:
            rows = result
        else:
            notice = "<p class='warn'>%s</p>" % esc(result)
    form = ("<form method='get'>" + field("case", "Case reference") + field("party", "Number")
            + field("ip", "IP") + field("protocol", "Protocol") + field("tower", "Tower")
            + field("min_severity", "Min severity") + field("keyword", "Keyword")
            + field("limit", "Limit") + "<button>Search</button></form>")
    table = ""
    if rows is not None:
        head = "".join("<th>%s</th>" % esc(label) for _, label, _ in COLUMNS)
        body = "".join(
            "<tr class='%s'>%s</tr>" % (
                esc(str(r["severity_level"])),
                "".join("<td>%s</td>" % esc(str(r[key])) for key, _, _ in COLUMNS))
            for r in rows)
        table = "<p>%d records</p><table><tr>%s</tr>%s</table>" % (len(rows), head, body)
    elif "case" not in q:
        table = "<p>Enter a case reference and run a search. Every query is recorded in the audit log.</p>"
    return _page(session, form + notice + table)


def render_audit_page(ctl, session, q):
    esc = html.escape
    ok, rows = ctl.view_audit(session, limit=_to_int(q.get("limit"), 100) or 100)
    if not ok:
        return _page(session, "<p class='warn'>%s</p>" % esc(rows))
    _, chain = ctl.verify_audit(session)
    head = "".join("<th>%s</th>" % esc(label) for _, label, _ in AUDIT_COLUMNS)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc(str(r[key] or ""))
                                           for key, _, _ in AUDIT_COLUMNS) for r in rows)
    return _page(session, "<p>%s</p><table><tr>%s</tr>%s</table>" % (esc(chain), head, body))


def make_handler(ctl):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _session(self):
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return None
            try:
                user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
            except Exception:
                return None
            session, _ = ctl.authenticate(user, password, log_success=False)
            return session

        def _send(self, code, body, ctype):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            session = self._session()
            if session is None:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="SORM Simulation"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            parsed = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if parsed.path == "/":
                self._send(200, render_search_page(ctl, session, q), "text/html; charset=utf-8")
            elif parsed.path == "/audit":
                self._send(200, render_audit_page(ctl, session, q), "text/html; charset=utf-8")
            elif parsed.path == "/stats":
                ok, result = ctl.stats(session)
                self._send(200 if ok else 403,
                           json.dumps(result if ok else {"error": result}, indent=2),
                           "application/json")
            else:
                self.send_error(404)
    return Handler


def run_dashboard(ctl, port=8080):
    server = HTTPServer(("127.0.0.1", port), make_handler(ctl))
    print("Dashboard running at http://127.0.0.1:%d  (log in with a SORM account; Ctrl+C to stop)" % port)
    print("Note: HTTP Basic login is only acceptable here because the server is bound to loopback.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
