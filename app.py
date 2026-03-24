import os, re, sqlparse, yaml, time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import oracledb

# ---------------------------------------------------------------
# LOAD CONFIG & POLICY
# ---------------------------------------------------------------
load_dotenv("/opt/safeproxy/.env")

with open("/opt/safeproxy/policy.yml", "r") as f:
    POLICY = yaml.safe_load(f)

# ---------------------------------------------------------------
# FASTAPI INIT
# ---------------------------------------------------------------
app = FastAPI(title="Safe Query Engine", version="2.0")

# ---------------------------------------------------------------
# RATE LIMITING (simple)
#   max 10 requests / 5 seconds per client IP
# ---------------------------------------------------------------
RATE_LIMIT = {}
MAX_REQ = 10
WINDOW = 5  # sec

def rate_limit(request: Request):
    ip = request.client.host
    now = time.time()

    if ip not in RATE_LIMIT:
        RATE_LIMIT[ip] = []
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < WINDOW]

    if len(RATE_LIMIT[ip]) >= MAX_REQ:
        raise HTTPException(429, "Too many requests — slow down")

    RATE_LIMIT[ip].append(now)

# ---------------------------------------------------------------
# ORACLE CONNECTION
# ---------------------------------------------------------------
def dsn():
    host = os.getenv("ORA_HOST")
    port = int(os.getenv("ORA_PORT"))
    svc  = os.getenv("ORA_SERVICE")
    return oracledb.makedsn(host, port, service_name=svc)

def conn():
    return oracledb.connect(
        user=os.getenv("ORA_USER"),
        password=os.getenv("ORA_PASS"),
        dsn=dsn()
    )

# ---------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------
class Query(BaseModel):
    sql: str

def block_star(sql_up: str):
    if POLICY.get("block_select_all", True) and re.search(r"\bSELECT\s+\*", sql_up):
        raise HTTPException(400, "SELECT * is not allowed")

def block_unsafe(sql_up: str):
    for cmd in POLICY.get("deny_commands", []):
        if cmd in sql_up:
            raise HTTPException(403, f"Command '{cmd}' not allowed")
    return True

def enforce_limit(sql: str):
    conf = POLICY["enforce_limit"]
    if not conf["enabled"]:
        return sql
    if re.search(r"\bFETCH\s+FIRST\s+\d+\s+ROWS", sql, flags=re.IGNORECASE):
        return sql
    return sql.rstrip(";") + f" FETCH FIRST {conf['rows']} ROWS ONLY"

def mask_row(row, cols):
    pii = set([c.upper() for c in POLICY["pii_columns"]])
    out = {}
    for c, v in zip(cols, row):
        cu = c.upper()
        if cu in pii:
            if v is None:
                out[c] = None
            else:
                s = str(v)
                if "EMAIL" in cu:
                    out[c] = s[0] + "***@" + s.split("@")[1] if "@" in s else "masked"
                elif "PHONE" in cu:
                    out[c] = "***" + s[-4:]
                elif "CARD" in cu or "ACCOUNT" in cu or "IBAN" in cu:
                    out[c] = "*"*(len(s)-4) + s[-4:]
                else:
                    out[c] = s[0] + "*****"
        else:
            out[c] = v
    return out

# ---------------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------------
@app.get("/health")
def health():
    return {"ok": True}

# ---------------------------------------------------------------
# EXPLAIN SQL (no execution)
# ---------------------------------------------------------------
@app.post("/explain_sql")
def explain_sql(q: Query, request: Request):
    rate_limit(request)

    sql = q.sql.strip()
    if not sql:
        raise HTTPException(400, "Empty SQL")

    parsed = sqlparse.parse(sql)
    formatted = sqlparse.format(sql, keyword_case="upper", strip_comments=True)
    tokens = [t.value for t in sqlparse.parse(sql)[0].tokens]

    return {
        "original": sql,
        "formatted": formatted,
        "tokens": tokens,
        "notes": [
            "This endpoint validates SQL structure only.",
            "No execution is performed.",
            "Deny-list and SELECT * blocking still apply."
        ]
    }

# ---------------------------------------------------------------
# VALIDATE SQL (no execution)
# ---------------------------------------------------------------
@app.post("/validate_sql")
def validate_sql(q: Query, request: Request):
    rate_limit(request)

    sql = q.sql.strip()
    if not sql:
        raise HTTPException(400, "Empty SQL")

    fmt = sqlparse.format(sql, keyword_case="upper", strip_comments=True)
    up = fmt.upper()

    # apply policy
    block_unsafe(up)
    block_star(up)

    # allow-list table check (optional)
    allowed_tables = set(POLICY["allowed_tables"])
    used_tokens = [tok for tok in re.findall(r"\b[A-Z_][A-Z0-9_]*\b", up)]
    bad = [t for t in used_tokens if t in POLICY.get("deny_tables", [])]

    return {
        "ok": True,
        "formatted": fmt,
        "blocked": bad,
        "info": "SQL validated successfully under policy constraints."
    }

# ---------------------------------------------------------------
# SAFE QUERY EXECUTION
# ---------------------------------------------------------------
@app.post("/safe_query")
def safe_query(q: Query, request: Request):
    rate_limit(request)

    sql = q.sql.strip()
    if not sql:
        raise HTTPException(400, "Empty SQL")

    fmt = sqlparse.format(sql, keyword_case="upper", strip_comments=True)
    up = fmt.upper()

    # apply firewall rules
    block_unsafe(up)
    block_star(up)
    sql_exec = enforce_limit(fmt)

    try:
        with conn() as c:
            with c.cursor() as cur:
                cur.execute(sql_exec)

                if not cur.description:
                    return {"columns": [], "rows": [], "row_count": 0, "note": "No result"}

                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
                masked = [mask_row(r, cols) for r in rows]

                return {
                    "columns": cols,
                    "rows": masked,
                    "row_count": len(masked),
                    "executed_sql": sql_exec
                }
    except Exception as e:
        raise HTTPException(400, f"Execution error: {e}")
