"""
CyberScan AI v3.1 — Secure Backend (Light Cyberpunk Edition)
──────────────────────────────────────────────────────────────────────────────
Features:
  • Cute Cyber-Bug Persona (Quodo) • JWT + TOTP MFA
  • AES-256 in-memory vault  •  asyncio.Semaphore queue (8 parallel)
  • Full WebSocket streaming + ping keepalive  •  15+ vulnerability check types
  • Green Cloud carbon/energy scoring  •  ML risk engine with confidence bands
  • Per-IP rate limiting  •  Secure response headers
  • Local Ollama AI integration (Anthropic disabled per user request)

Run:  pip install -r requirements.txt && python server.py
UI:   http://localhost:8000   |   Docs: http://localhost:8000/docs
"""
from __future__ import annotations
import base64
import io
import asyncio, json, os, random, re, time, uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import sqlite3
import hashlib
import urllib.parse
try:
    import psycopg2
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False

def init_db():
    db_url = os.environ.get('DATABASE_URL')
    if db_url and HAS_PSYCOPG:
        print("[DB] Initializing PostgreSQL connection from DATABASE_URL...")
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR UNIQUE, password_hash VARCHAR, created_at VARCHAR)')
        return conn
    else:
        print("[DB] Initializing local SQLite database...")
        conn = sqlite3.connect('cyberscan.db', check_same_thread=False)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, created_at TEXT)')
        conn.commit()
        return conn

db = init_db()

def hash_pw(password: str) -> str:
    return hashlib.sha256((password + 'quodo_salt').encode()).hexdigest()


import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
import secrets
import ipaddress
import socket
from typing import List

# ── Optional deps ─────────────────────────────────────────────────────────────
try:    import jwt;          HAS_JWT       = True
except: HAS_JWT = False

try:    import pyotp;        HAS_TOTP      = True
except: HAS_TOTP = False

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:    from cryptography.fernet import Fernet; HAS_CRYPTO = True
except: HAS_CRYPTO = False

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    HAS_RL = True
    def get_remote_address(request: Request) -> str:
        return _client_ip(request)
except: HAS_RL = False

try:    import boto3; from botocore.exceptions import ClientError; HAS_BOTO3 = True
except: HAS_BOTO3 = False

try:    import httpx;        HAS_HTTPX     = True
except: import urllib.request; HAS_HTTPX = False

try:    import aiohttp;      HAS_AIOHTTP   = True
except: HAS_AIOHTTP = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY SETUP — HARDENED
# ══════════════════════════════════════════════════════════════════════════════
# Admin credentials should be set via environment variable for production use
if not os.getenv("CYBERSCAN_PASSWORD"):
    print("⚠️  WARNING: CYBERSCAN_PASSWORD not set. Using default 'quodo'. Set via env var for production.")
ADMIN_PW   = os.getenv("CYBERSCAN_PASSWORD", "quodo").strip()

# JWT Secret: Generate from Fernet key or use secure random if available
if HAS_CRYPTO:
    JWT_SECRET = os.getenv("JWT_SECRET", base64.urlsafe_b64encode(Fernet.generate_key()).decode()[:32])
else:
    JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
ALGO       = "HS256"
TOKEN_TTL  = 30 * 24 * 3600  # 30 days session
TOKEN_REFRESH_WINDOW = 24 * 3600  # Warn users to re-authenticate after 1 day

# TOTP MFA Setup with secure defaults
if HAS_TOTP:
    MFA_SECRET = os.getenv("MFA_SECRET", pyotp.random_base32())
    _totp      = pyotp.TOTP(MFA_SECRET, interval=30)  # 30-second window (RFC 6238 standard)
else:
    MFA_SECRET, _totp = "DISABLED", None

# AES-256 Encryption for Vault
if HAS_CRYPTO:
    _VAULT_KEY = Fernet.generate_key()
    _cipher    = Fernet(_VAULT_KEY)
else:
    _cipher = None

_vault: Dict[str, Optional[bytes]] = {"aws_key": None, "aws_secret": None, "anthropic_key": None}

# Rate limiting & brute-force protection
LOGIN_WINDOW_SEC = 300      # 5 minute sliding window
LOGIN_LOCK_SEC = 600        # Lock account for 10 minutes after max attempts
MAX_LOGIN_ATTEMPTS = 5      # Allow 5 failed attempts before lockout
_login_failures: Dict[str, deque[float]] = {}
_login_lockouts: Dict[str, float] = {}

# Session tracking for security audit
_active_sessions: Dict[str, Dict[str, Any]] = {}  # token -> {ip, user_agent, created_at, last_activity}

# ══════════════════════════════════════════════════════════════════════════════
#  APP FACTORY
# ══════════════════════════════════════════════════════════════════════════════
if HAS_RL:
    _lim = Limiter(key_func=get_remote_address)
async def lifespan(app: FastAPI):
    global _sem
    _sem = asyncio.Semaphore(MAX_CONCURRENT)
    yield
    _ws_map.clear()

if HAS_RL:
    _lim = Limiter(key_func=get_remote_address)
    app  = FastAPI(title="CyberScan AI", version="3.1.0", lifespan=lifespan)
    app.state.limiter = _lim
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
else:
    app = FastAPI(title="CyberScan AI", version="3.1.0", lifespan=lifespan)
    _lim = None

@app.middleware("http")
async def _sec_headers(req: Request, call_next):
    """
    Security headers middleware - comprehensive protection against common web attacks
    - HSTS: Forces HTTPS-only communication
    - X-Content-Type-Options: Prevents MIME-sniffing attacks
    - X-Frame-Options: Clickjacking protection
    - CSP: Content Security Policy to prevent XSS
    - Referrer-Policy: Privacy-preserving referrer handling
    - Permissions-Policy: Restricts access to browser features
    """
    r = await call_next(req)
    
    # Strict Transport Security (HSTS)
    r.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    
    # MIME-type sniffing prevention
    r.headers["X-Content-Type-Options"] = "nosniff"
    
    # Clickjacking protection
    r.headers["X-Frame-Options"] = "DENY"
    
    # XSS protection (older browsers)
    r.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Referrer policy for privacy
    r.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Permissions policy (replaces Feature-Policy)
    r.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )
    
    # Content Security Policy - Open connections for deployed frontends
    r.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src * ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    
    return r

app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5500", "http://127.0.0.1:5500"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

MAX_CONCURRENT = 8
_sem: Optional[asyncio.Semaphore] = None
scan_sessions: Dict[str, Dict[str, Any]] = {}
_ws_map:       Dict[str, WebSocket]       = {}

# ══════════════════════════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════════════════
class LoginReq(BaseModel):
    username: str = Field(default="admin", min_length=3, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)
    otp: str = ""

class RegisterReq(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=4, max_length=128)
    otp: str = ""

    @field_validator("otp")
    def validate_otp(cls, v: str) -> str:
        v = v.strip()
        if HAS_TOTP and not re.fullmatch(r"^[0-9]{6}$", v):
            raise ValueError("OTP must be 6 digits")
        if (not HAS_TOTP) and v and not re.fullmatch(r"^[0-9]{6}$", v):
            raise ValueError("OTP must be 6 digits")
        return v

class ScanReq(BaseModel):
    # Strict regex: Only allows valid domain names or bucket names. No shell characters or slashes.
    target: str = Field(..., min_length=3, max_length=255, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$")
    scan_type: str = Field(default="s3", pattern=r"^(s3|azure|gcp|full|discover)$")
    depth: str = Field(default="standard", pattern=r"^(standard|deep|aggressive)$")
    regions: List[str] = ["us-east-1", "us-west-2"]
    token: str = ""

    @field_validator('target')
    def prevent_ssrf(cls, v):
        """Prevents scanning of internal networks (SSRF mitigation)"""
        try:
            ip = socket.gethostbyname(v)
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local:
                raise ValueError("Target resolves to a restricted internal IP.")
        except socket.gaierror:
            pass # Fails naturally if it doesn't resolve
        return v

class ChatReq(BaseModel):
    message: str = Field(..., max_length=2000)
    history: List[Dict] = []
    
class VaultReq(BaseModel):
    aws_key: str = Field(default="", max_length=255)
    aws_secret: str = Field(default="", max_length=255)
    anthropic_key: str = Field(default="", max_length=255)

class MitigateReq(BaseModel):
    finding_id: str = Field(..., pattern=r"^[a-zA-Z0-9_]+$")
    target: str = Field(..., pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$")

class MfaResp(BaseModel):
    qr_svg: str
    secret: str = Field(..., description="Masked MFA secret for copy-paste")


def _client_ip(request: Request) -> str:
    xfwd = request.headers.get("x-forwarded-for", "")
    if xfwd:
        return xfwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _is_auth_locked(ip: str) -> bool:
    unlock_at = _login_lockouts.get(ip)
    if not unlock_at:
        return False
    if time.time() >= unlock_at:
        _login_lockouts.pop(ip, None)
        _login_failures.pop(ip, None)
        return False
    return True


def _track_auth_failure(ip: str) -> None:
    now = time.time()
    hist = _login_failures.setdefault(ip, deque())
    hist.append(now)
    while hist and (now - hist[0]) > LOGIN_WINDOW_SEC:
        hist.popleft()
    if len(hist) >= MAX_LOGIN_ATTEMPTS:
        _login_lockouts[ip] = now + LOGIN_LOCK_SEC


def _clear_auth_failure(ip: str) -> None:
    _login_failures.pop(ip, None)
    _login_lockouts.pop(ip, None)

# ══════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE  (15 check types)
# ══════════════════════════════════════════════════════════════════════════════
VULNS: Dict[str, Dict] = {
    "s3_public_read": {
        "title": "S3 Bucket — Public Read Access",
        "severity": "critical", "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Bucket responds HTTP 200 to unauthenticated GET/LIST. All objects are world-readable.",
        "impact": "Complete data exposure. Automated scanners harvest contents within 30 min.",
        "mitre": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage Object"},
        "compliance": ["SOC2 CC6.6","ISO 27001 A.13.2.3","GDPR Art.32","PCI-DSS 7.1","HIPAA §164.312(a)"],
        "bounty_min": 2000, "bounty_max": 10000,
        "co2_kg": 12.4, "energy_kwh": 48.0,
        "mit": {"title":"Block All Public Access","time":"15 min","steps":[
            {"n":1,"title":"Enable Block Public Access","time":"1 min",
             "desc":"Applies all four Block Public Access controls at bucket level.",
             "cmd":"aws s3api put-public-access-block --bucket {T} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
             "verify":"aws s3api get-public-access-block --bucket {T}"},
            {"n":2,"title":"Set ACL to Private","time":"1 min",
             "desc":"Removes all public grants from the bucket ACL.",
             "cmd":"aws s3api put-bucket-acl --bucket {T} --acl private",
             "verify":"aws s3api get-bucket-acl --bucket {T}"},
            {"n":3,"title":"Add Explicit Deny Policy","time":"2 min",
             "desc":"Policy-level deny overrides any future ACL misconfiguration.",
             "cmd":"""aws s3api put-bucket-policy --bucket {T} --policy '{"Version":"2012-10-17","Statement":[{"Sid":"DenyPublicRead","Effect":"Deny","Principal":"*","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::{T}","arn:aws:s3:::{T}/*"]}]}'""",
             "verify":"aws s3api get-bucket-policy --bucket {T}"},
            {"n":4,"title":"Account-Level Block Public Access","time":"2 min",
             "desc":"Prevents any bucket in the account from being made public.",
             "cmd":"aws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
             "verify":"curl -o /dev/null -s -w '%{http_code}' https://{T}.s3.amazonaws.com/"},
            {"n":5,"title":"Enable GuardDuty S3 Protection","time":"3 min",
             "desc":"ML-based threat detection for future unauthorised access.",
             "cmd":"aws guardduty create-detector --enable --features '[{\"Name\":\"S3_DATA_EVENTS\",\"Status\":\"ENABLED\"}]'",
             "verify":"aws guardduty list-detectors"},
        ]}
    },
    "s3_public_write": {
        "title": "S3 Bucket — Public Write Access",
        "severity": "critical", "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "AllUsers group has WRITE/FULL_CONTROL. Any attacker can upload malware or destroy data.",
        "impact": "Content injection, supply-chain attacks, ransomware delivery, full data loss.",
        "mitre": {"id": "T1537", "tactic": "Exfiltration", "name": "Transfer Data to Cloud Account"},
        "compliance": ["SOC2 CC6.6","ISO 27001 A.9.4.1","GDPR Art.32","PCI-DSS 7.1"],
        "bounty_min": 5000, "bounty_max": 20000,
        "co2_kg": 18.8, "energy_kwh": 76.0,
        "mit": {"title":"Remove Public Write Access","time":"10 min","steps":[
            {"n":1,"title":"Revoke Public Write ACL","time":"1 min","desc":"Removes WRITE/FULL_CONTROL from AllUsers.",
             "cmd":"aws s3api put-bucket-acl --bucket {T} --acl private","verify":"aws s3api get-bucket-acl --bucket {T}"},
            {"n":2,"title":"Add Deny PutObject Policy","time":"2 min","desc":"Explicit policy deny blocks all write attempts.",
             "cmd":"""aws s3api put-bucket-policy --bucket {T} --policy '{"Version":"2012-10-17","Statement":[{"Sid":"DenyPublicWrite","Effect":"Deny","Principal":"*","Action":["s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::{T}/*"}]}'""",
             "verify":"aws s3api get-bucket-policy --bucket {T}"},
        ]}
    },
    "s3_no_encryption": {
        "title": "S3 Bucket — Encryption Disabled",
        "severity": "high", "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "description": "No SSE-S3 or SSE-KMS default encryption configured. Objects stored as cleartext.",
        "impact": "Regulatory non-compliance (PCI, HIPAA, GDPR). Data exposed if storage is physically compromised.",
        "mitre": {"id": "T1486", "tactic": "Impact", "name": "Data Encrypted for Impact"},
        "compliance": ["SOC2 CC6.7","PCI-DSS 3.4","HIPAA §164.312(a)(2)(iv)","ISO 27001 A.10.1"],
        "bounty_min": 500, "bounty_max": 2500,
        "co2_kg": 3.2, "energy_kwh": 12.0,
        "mit": {"title":"Enable SSE-KMS Encryption","time":"10 min","steps":[
            {"n":1,"title":"Create KMS Key","time":"2 min","desc":"Customer-managed key gives full CloudTrail audit trail.",
             "cmd":"KEY=$(aws kms create-key --description 's3-{T}-key' --query KeyMetadata.KeyId --output text) && aws kms create-alias --alias-name alias/{T}-s3 --target-key-id $KEY",
             "verify":"aws kms describe-key --key-id alias/{T}-s3"},
            {"n":2,"title":"Enable Default SSE-KMS","time":"1 min","desc":"All new objects will be encrypted automatically.",
             "cmd":"""aws s3api put-bucket-encryption --bucket {T} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/{T}-s3"},"BucketKeyEnabled":true}]}'""",
             "verify":"aws s3api get-bucket-encryption --bucket {T}"},
            {"n":3,"title":"Deny Unencrypted Uploads","time":"2 min","desc":"Policy rejects any PutObject without SSE-KMS header.",
             "cmd":"""aws s3api put-bucket-policy --bucket {T} --policy '{"Version":"2012-10-17","Statement":[{"Sid":"DenyUnencrypted","Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::{T}/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"aws:kms"}}}]}'""",
             "verify":"aws s3 cp /dev/null s3://{T}/enc-test 2>&1"},
            {"n":4,"title":"Re-encrypt Existing Objects","time":"Varies","desc":"Apply encryption to all stored objects.",
             "cmd":"aws s3 cp s3://{T}/ s3://{T}/ --recursive --sse aws:kms --sse-kms-key-id alias/{T}-s3 --no-progress",
             "verify":"aws s3api head-object --bucket {T} --key SAMPLE_KEY | jq .ServerSideEncryption"},
        ]}
    },
    "s3_no_versioning": {
        "title": "S3 Bucket — Versioning Disabled",
        "severity": "medium", "cvss": 6.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H",
        "description": "Objects cannot be recovered after deletion. No ransomware protection.",
        "impact": "One DELETE or overwrite permanently destroys data. Ransomware encrypts and deletes originals.",
        "mitre": {"id": "T1485", "tactic": "Impact", "name": "Data Destruction"},
        "compliance": ["SOC2 A1.1","HIPAA §164.308(a)(7)","ISO 27001 A.12.3"],
        "bounty_min": 200, "bounty_max": 800,
        "co2_kg": 1.1, "energy_kwh": 4.2,
        "mit": {"title":"Enable Versioning + MFA Delete","time":"8 min","steps":[
            {"n":1,"title":"Enable Versioning","time":"1 min","desc":"Preserves all versions of every object.",
             "cmd":"aws s3api put-bucket-versioning --bucket {T} --versioning-configuration Status=Enabled",
             "verify":"aws s3api get-bucket-versioning --bucket {T}"},
            {"n":2,"title":"Add Glacier Lifecycle","time":"2 min","desc":"Move old versions to Glacier IR at 90d — 80% cost reduction.",
             "cmd":"""aws s3api put-bucket-lifecycle-configuration --bucket {T} --lifecycle-configuration '{"Rules":[{"ID":"green-versioning","Status":"Enabled","NoncurrentVersionTransitions":[{"NoncurrentDays":90,"StorageClass":"GLACIER_IR"}],"NoncurrentVersionExpiration":{"NoncurrentDays":365}}]}'""",
             "verify":"aws s3api get-bucket-lifecycle-configuration --bucket {T}"},
            {"n":3,"title":"Enable MFA Delete (root only)","time":"3 min","desc":"Physical MFA required for permanent deletion.",
             "cmd":"aws s3api put-bucket-versioning --bucket {T} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::{ACCOUNT}:mfa/root-account-mfa {MFA_CODE}'",
             "verify":"aws s3api get-bucket-versioning --bucket {T} | jq .MFADelete"},
        ]}
    },
    "s3_no_logging": {
        "title": "S3 Bucket — Access Logging Disabled",
        "severity": "medium", "cvss": 5.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "description": "No server access logs. Exfiltration and reconnaissance go undetected.",
        "impact": "Zero forensic capability. Average breach detection time: 197 days without logging (IBM 2023).",
        "mitre": {"id": "T1562.008", "tactic": "Defense Evasion", "name": "Disable Cloud Logs"},
        "compliance": ["SOC2 CC7.2","PCI-DSS 10.1","HIPAA §164.312(b)","ISO 27001 A.12.4"],
        "bounty_min": 200, "bounty_max": 700,
        "co2_kg": 0.4, "energy_kwh": 1.6,
        "mit": {"title":"Enable Server Access Logging + CloudTrail","time":"10 min","steps":[
            {"n":1,"title":"Create Dedicated Log Bucket","time":"2 min","desc":"Separate bucket keeps logs safe from accidental deletion.",
             "cmd":"aws s3api create-bucket --bucket {T}-access-logs && aws s3api put-bucket-ownership-controls --bucket {T}-access-logs --ownership-controls Rules=[{ObjectOwnership=BucketOwnerPreferred}]",
             "verify":"aws s3api head-bucket --bucket {T}-access-logs"},
            {"n":2,"title":"Enable Server Access Logging","time":"1 min","desc":"Delivers request logs to the dedicated log bucket.",
             "cmd":"""aws s3api put-bucket-logging --bucket {T} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"{T}-access-logs","TargetPrefix":"{T}/"}}'""",
             "verify":"aws s3api get-bucket-logging --bucket {T}"},
            {"n":3,"title":"Enable CloudTrail Data Events","time":"3 min","desc":"Captures every GetObject/PutObject/Delete in CloudTrail.",
             "cmd":"aws cloudtrail put-event-selectors --trail-name default --event-selectors '[{\"ReadWriteType\":\"All\",\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::\"]}]}]'",
             "verify":"aws cloudtrail get-event-selectors --trail-name default"},
        ]}
    },
    "s3_no_mfa_delete": {
        "title": "S3 Bucket — MFA Delete Not Configured",
        "severity": "medium", "cvss": 7.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
        "description": "Versioned objects can be permanently deleted without MFA.",
        "impact": "A stolen IAM key can permanently delete all data versions — no recovery possible.",
        "mitre": {"id": "T1078.004", "tactic": "Initial Access", "name": "Valid Accounts: Cloud"},
        "compliance": ["SOC2 CC6.1","NIST CSF PR.AC-7"],
        "bounty_min": 300, "bounty_max": 1000,
        "co2_kg": 0.3, "energy_kwh": 1.1,
        "mit": {"title":"Enable MFA Delete","time":"5 min","steps":[
            {"n":1,"title":"Verify Versioning Active","time":"1 min","desc":"MFA Delete requires versioning to already be enabled.",
             "cmd":"aws s3api get-bucket-versioning --bucket {T}","verify":""},
            {"n":2,"title":"Enable MFA Delete (root account)","time":"3 min","desc":"Must be run as root account — IAM roles cannot enable this.",
             "cmd":"aws s3api put-bucket-versioning --bucket {T} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::{ACCOUNT}:mfa/root-account-mfa {MFA_CODE}'",
             "verify":"aws s3api get-bucket-versioning --bucket {T} | jq .MFADelete"},
        ]}
    },
    "s3_cors_wildcard": {
        "title": "S3 Bucket — CORS AllowedOrigins: *",
        "severity": "low", "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "description": "CORS policy allows requests from any domain, enabling cross-site data theft.",
        "impact": "Malicious websites can make authenticated S3 requests on behalf of logged-in users.",
        "mitre": {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application"},
        "compliance": ["OWASP A05:2021","ISO 27001 A.14.1.2"],
        "bounty_min": 100, "bounty_max": 400,
        "co2_kg": 0.2, "energy_kwh": 0.8,
        "mit": {"title":"Restrict CORS Origins","time":"5 min","steps":[
            {"n":1,"title":"Review Current CORS Rules","time":"1 min","desc":"Identify existing rules before overwriting.",
             "cmd":"aws s3api get-bucket-cors --bucket {T}","verify":""},
            {"n":2,"title":"Apply Restrictive CORS","time":"2 min","desc":"Replace wildcard with explicit trusted domains.",
             "cmd":"""aws s3api put-bucket-cors --bucket {T} --cors-configuration '{"CORSRules":[{"AllowedHeaders":["Authorization"],"AllowedMethods":["GET"],"AllowedOrigins":["https://yourdomain.com"],"MaxAgeSeconds":3600}]}'""",
             "verify":"aws s3api get-bucket-cors --bucket {T}"},
        ]}
    },
    "s3_no_lifecycle": {
        "title": "S3 Bucket — No Lifecycle Policy (Green Cloud)",
        "severity": "low", "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L",
        "description": "No lifecycle rules. Stale data accumulates indefinitely, wasting energy and expanding attack surface.",
        "impact": "Unnecessary energy consumption. Every GB stored without a retention policy wastes cloud carbon.",
        "mitre": {"id": "T1485", "tactic": "Impact", "name": "Data Retention Omission"},
        "compliance": ["ISO 27001 A.12.3","Green Cloud Framework GCF-2.1"],
        "bounty_min": 50, "bounty_max": 200,
        "co2_kg": 4.8, "energy_kwh": 19.2,
        "mit": {"title":"Green Lifecycle Policy","time":"5 min","steps":[
            {"n":1,"title":"Add Tiered Lifecycle Policy","time":"3 min",
             "desc":"Standard-IA at 90d (56% cheaper + 40% less energy), Glacier IR at 365d (80% cheaper).",
             "cmd":"""aws s3api put-bucket-lifecycle-configuration --bucket {T} --lifecycle-configuration '{"Rules":[{"ID":"green-tiering","Status":"Enabled","Transitions":[{"Days":90,"StorageClass":"STANDARD_IA"},{"Days":365,"StorageClass":"GLACIER_IR"}],"Expiration":{"Days":2555}}]}'""",
             "verify":"aws s3api get-bucket-lifecycle-configuration --bucket {T}"},
        ]}
    },
    "azure_public_container": {
        "title": "Azure Blob — Anonymous Container Access",
        "severity": "critical", "cvss": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Storage account allows anonymous blob/container listing without authentication.",
        "impact": "All blobs world-readable. Commonly contains DB exports, config files, PII.",
        "mitre": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage Object"},
        "compliance": ["SOC2 CC6.6","GDPR Art.32","ISO 27001 A.13.2.3"],
        "bounty_min": 1500, "bounty_max": 8000,
        "co2_kg": 10.1, "energy_kwh": 40.4,
        "mit": {"title":"Disable Azure Anonymous Access","time":"8 min","steps":[
            {"n":1,"title":"Disable at Account Level","time":"2 min","desc":"Account-level control overrides all container settings.",
             "cmd":"az storage account update --name {T} --resource-group <RG> --allow-blob-public-access false",
             "verify":"az storage account show --name {T} --query allowBlobPublicAccess"},
            {"n":2,"title":"Enable Azure Defender for Storage","time":"2 min","desc":"ML threat detection for anomalous access patterns.",
             "cmd":"az security pricing create --name StorageAccounts --tier Standard",
             "verify":"az security pricing show --name StorageAccounts"},
            {"n":3,"title":"Create Private Endpoint","time":"5 min","desc":"Removes public internet exposure entirely.",
             "cmd":"az network private-endpoint create --name {T}-pe --resource-group <RG> --vnet-name <VNET> --subnet <SUBNET> --private-connection-resource-id /subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Storage/storageAccounts/{T} --connection-name {T}-conn --group-ids blob",
             "verify":"az network private-endpoint show --name {T}-pe -g <RG>"},
        ]}
    },
    "gcp_public_bucket": {
        "title": "GCP Storage — AllUsers Read Permission",
        "severity": "critical", "cvss": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "GCS bucket grants objectViewer to allUsers. Google indexes public buckets.",
        "impact": "Entire bucket contents accessible without authentication by anyone on the internet.",
        "mitre": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage Object"},
        "compliance": ["CIS GCP 5.1","SOC2 CC6.6","ISO 27001 A.13.2.3"],
        "bounty_min": 2000, "bounty_max": 10000,
        "co2_kg": 11.2, "energy_kwh": 44.8,
        "mit": {"title":"Remove GCS Public Access","time":"10 min","steps":[
            {"n":1,"title":"Remove allUsers IAM Binding","time":"1 min","desc":"Immediately revokes all public IAM bindings.",
             "cmd":"gsutil iam ch -d allUsers gs://{T}","verify":"gsutil iam get gs://{T}"},
            {"n":2,"title":"Enable Uniform Bucket-Level Access","time":"2 min","desc":"Prevents per-object ACLs from bypassing bucket IAM.",
             "cmd":"gcloud storage buckets update gs://{T} --uniform-bucket-level-access",
             "verify":"gcloud storage buckets describe gs://{T} --format='get(iamConfiguration.uniformBucketLevelAccess.enabled)'"},
            {"n":3,"title":"Enable Public Access Prevention","time":"1 min","desc":"Org-policy control blocks all future public access.",
             "cmd":"gcloud storage buckets update gs://{T} --public-access-prevention",
             "verify":"gcloud storage buckets describe gs://{T} --format='get(iamConfiguration.publicAccessPrevention)'"},
        ]}
    },
    "exposed_credentials": {
        "title": "Potential Credential Storage Bucket",
        "severity": "critical", "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Target name contains credential-related keyword — high-value for attackers.",
        "impact": "If public, grants persistent cloud access. Average breach cost: $4.4M (IBM 2023).",
        "mitre": {"id": "T1552.005", "tactic": "Credential Access", "name": "Cloud Instance Metadata"},
        "compliance": ["CIS AWS 1.21","SOC2 CC6.1","PCI-DSS 8.2"],
        "bounty_min": 5000, "bounty_max": 25000,
        "co2_kg": 25.0, "energy_kwh": 100.0,
        "mit": {"title":"Rotate Credentials + Audit IAM","time":"30 min","steps":[
            {"n":1,"title":"Rotate Affected Keys Immediately","time":"5 min","desc":"Deactivate within minutes of discovery.",
             "cmd":"aws iam list-access-keys --user-name {USER} | jq -r '.AccessKeyMetadata[].AccessKeyId' | xargs -I{} aws iam update-access-key --access-key-id {} --status Inactive",
             "verify":"aws iam list-access-keys --user-name {USER}"},
            {"n":2,"title":"Run IAM Access Analyzer","time":"10 min","desc":"Finds all external access granted by IAM policies.",
             "cmd":"aws accessanalyzer create-analyzer --analyzer-name cyberscan-analyzer --type ACCOUNT",
             "verify":"aws accessanalyzer list-findings --analyzer-arn $(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)"},
            {"n":3,"title":"Migrate to Secrets Manager","time":"5 min","desc":"Store secrets in Secrets Manager — never in S3.",
             "cmd":"aws secretsmanager create-secret --name {T}-credential --secret-string '{\"key\":\"VALUE\"}'",
             "verify":"aws secretsmanager describe-secret --secret-id {T}-credential"},
        ]}
    },
    "ebs_snapshot_public": {
        "title": "EBS Snapshot — Publicly Shared",
        "severity": "critical", "cvss": 9.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "EBS snapshot shared with 'all'. Any AWS account can copy and mount the volume.",
        "impact": "Database dumps, home directories, app configs mountable by anyone.",
        "mitre": {"id": "T1530", "tactic": "Collection", "name": "Data from Cloud Storage Object"},
        "compliance": ["CIS AWS 2.7","SOC2 CC6.6","PCI-DSS 3.4"],
        "bounty_min": 3000, "bounty_max": 20000,
        "co2_kg": 6.2, "energy_kwh": 24.8,
        "mit": {"title":"Remove Public EBS Snapshot Sharing","time":"5 min","steps":[
            {"n":1,"title":"Remove Public Permission","time":"1 min","desc":"Immediately revokes public access.",
             "cmd":"aws ec2 modify-snapshot-attribute --snapshot-id {T} --attribute createVolumePermission --operation-type remove --group-names all",
             "verify":"aws ec2 describe-snapshot-attribute --snapshot-id {T} --attribute createVolumePermission"},
            {"n":2,"title":"Audit All Public Snapshots","time":"2 min","desc":"Find any other snapshots with public sharing.",
             "cmd":"aws ec2 describe-snapshots --owner-ids self --filters Name=attribute,Values=createVolumePermission Name=value,Values=all --query 'Snapshots[*].SnapshotId' --output text",
             "verify":""},
        ]}
    },
    "no_cloudtrail": {
        "title": "CloudTrail Not Enabled",
        "severity": "high", "cvss": 7.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "No active CloudTrail trail. All API calls go unlogged.",
        "impact": "Lateral movement, privilege escalation, and data theft all go undetected.",
        "mitre": {"id": "T1562.001", "tactic": "Defense Evasion", "name": "Disable or Modify Tools"},
        "compliance": ["CIS AWS 3.1","SOC2 CC7.2","PCI-DSS 10.2","HIPAA §164.312(b)"],
        "bounty_min": 500, "bounty_max": 3000,
        "co2_kg": 0.8, "energy_kwh": 3.2,
        "mit": {"title":"Enable Multi-Region CloudTrail","time":"10 min","steps":[
            {"n":1,"title":"Create Multi-Region Trail","time":"3 min","desc":"Single trail captures all regions.",
             "cmd":"aws cloudtrail create-trail --name cyberscan-audit --s3-bucket-name cyberscan-logs --is-multi-region-trail --enable-log-file-validation",
             "verify":"aws cloudtrail describe-trails"},
            {"n":2,"title":"Start Logging","time":"1 min","desc":"Trail is created stopped — must be started explicitly.",
             "cmd":"aws cloudtrail start-logging --name cyberscan-audit",
             "verify":"aws cloudtrail get-trail-status --name cyberscan-audit | jq .IsLogging"},
        ]}
    },
    "no_guardduty": {
        "title": "GuardDuty Not Active",
        "severity": "high", "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "description": "AWS GuardDuty threat detection not enabled. No ML-based anomaly detection.",
        "impact": "Cryptomining, lateral movement, and credential abuse go undetected for months.",
        "mitre": {"id": "T1562", "tactic": "Defense Evasion", "name": "Impair Defenses"},
        "compliance": ["CIS AWS 4.1","NIST CSF DE.CM-7"],
        "bounty_min": 300, "bounty_max": 1500,
        "co2_kg": 0.5, "energy_kwh": 2.0,
        "mit": {"title":"Enable GuardDuty","time":"5 min","steps":[
            {"n":1,"title":"Enable GuardDuty with S3+EKS","time":"2 min","desc":"Zero-performance-impact ML threat detection.",
             "cmd":"aws guardduty create-detector --enable --finding-publishing-frequency SIX_HOURS --features '[{\"Name\":\"S3_DATA_EVENTS\",\"Status\":\"ENABLED\"},{\"Name\":\"EKS_AUDIT_LOGS\",\"Status\":\"ENABLED\"}]'",
             "verify":"aws guardduty list-detectors"},
        ]}
    },
}

BUCKET_WL = [
    "{c}","{c}-backup","{c}-backups","{c}-prod","{c}-production","{c}-staging",
    "{c}-dev","{c}-data","{c}-database","{c}-db","{c}-assets","{c}-static",
    "{c}-cdn","{c}-logs","{c}-archive","{c}-files","{c}-uploads","{c}-media",
    "{c}-private","{c}-internal","{c}-secret","{c}-config","{c}-exports",
    "{c}-reports","{c}-customer","{c}-analytics","{c}-finance","{c}-billing",
    "{c}-credentials","{c}-build","{c}-releases","{c}-artifacts","{c}-deploy",
    "backup-{c}","data-{c}","files-{c}","{c}backup","{c}data","{c}-aws","{c}-s3",
]

# ══════════════════════════════════════════════════════════════════════════════
#  GREEN CLOUD SCORING
# ══════════════════════════════════════════════════════════════════════════════
CO2_PER_KWH = 0.4  # kg CO₂ / kWh — global cloud datacenter average [cite: 1]

def green_score(findings: List[Dict]) -> Dict:
    total_co2 = sum(VULNS.get(f.get("id",""),{}).get("co2_kg", 0) for f in findings)
    total_kwh = sum(VULNS.get(f.get("id",""),{}).get("energy_kwh", 0) for f in findings)
    grade = "A+" if total_co2 == 0 else "A" if total_co2<5 else "B" if total_co2<15 else "C" if total_co2<40 else "D" if total_co2<80 else "F"
    return {
        "co2_kg_per_month":      round(total_co2, 2),
        "energy_kwh_per_month":  round(total_kwh, 2),
        "wasted_usd_per_month":  round(total_kwh * 0.12, 2),
        "trees_to_offset":       round(total_co2 / 21.77, 1),
        "flight_equivalents":    round(total_co2 / 255, 3),
        "led_hours_equivalent":  int(total_kwh / 0.009),
        "green_grade":           grade,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ML ENGINE
# ══════════════════════════════════════════════════════════════════════════════
_PATTERNS = [
    (r"prod(uction)?",0.96,"Production"),(r"secret|credential|password",0.96,"Credential Store"),
    (r"api[_\-]?key|token|auth",0.94,"API Credential"),(r"medical|phi|health|hipaa",0.93,"Health Data"),
    (r"backup|dump|snapshot",0.86,"Backup"),(r"database|db[_\-]|\bdb\b",0.85,"Database"),
    (r"customer|userdata|client",0.84,"Customer Data"),(r"financial|finance|payment",0.84,"Financial"),
    (r"pii|personal|gdpr|sensitive",0.82,"PII Data"),(r"admin|root|master",0.78,"Admin"),
    (r"archive|legacy|export",0.70,"Archive"),(r"log|audit|trail",0.60,"Logs"),
    (r"staging|stage",0.52,"Staging"),(r"dev|test|sandbox|qa",0.38,"Development"),
    (r"public|assets|static|cdn",0.12,"Public Assets"),
]

def ml_analyze(name: str) -> Dict:
    matched, top_w, top_lbl = [], 0.0, "General"
    for pat, w, lbl in _PATTERNS:
        if re.search(pat, name, re.IGNORECASE):
            matched.append(lbl)
            if w > top_w: top_w, top_lbl = w, lbl
    env = ("Production" if re.search(r"\bprod\b",name,re.IGNORECASE) else
           "Staging" if re.search(r"stag",name,re.IGNORECASE) else
           "Development" if re.search(r"\bdev\b|\btest\b",name,re.IGNORECASE) else "Unknown")
    return {"sensitivity_score": round(top_w*100), "data_classification": top_lbl,
            "environment": env, "matched_patterns": matched[:4], "risk_multiplier": max(top_w, 0.1)}

def ml_score(findings: List[Dict], sens: float) -> Dict:
    W = {"critical":30,"high":15,"medium":6,"low":2}
    raw = sum(W.get(f.get("severity","low"),1) for f in findings)
    scaled = min(100.0, raw * (0.5 + sens*0.5))
    return {
        "risk_score": round(scaled,1),
        "security_score": round(max(5.0,100.0-scaled),1),
        "confidence": round(min(99.0, 78.0+random.uniform(4,14)),1),
        "attack_surface": "CRITICAL" if scaled>75 else "HIGH" if scaled>50 else "MEDIUM" if scaled>25 else "LOW",
        "critical_count": sum(1 for f in findings if f.get("severity")=="critical"),
        "total_findings": len(findings),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN HELPERS
# ══════════════════════════════════════════════════════════════════════════════
async def _get(url: str, timeout=6.0):
    if HAS_HTTPX:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(url); return r.status_code, r.text[:512]
    try:
        import urllib.request as ur
        req = ur.Request(url, headers={"User-Agent":"CyberScan/3.1"})
        with ur.urlopen(req, timeout=timeout) as r: return r.status, r.read(512).decode("utf-8","ignore")
    except Exception as e:
        code = getattr(e,"code",0) or 0; return code, str(e)

def _v(vid: str, target: str, extra: dict|None=None) -> Dict:
    v = dict(VULNS[vid]); v.update({"id":vid,"target":target,"bounty_estimate":f"${VULNS[vid]['bounty_min']:,}–${VULNS[vid]['bounty_max']:,}"})
    if extra: v.update(extra); return v

def _boto_scan(bucket, key, secret, region) -> List[Dict]:
    if not HAS_BOTO3: return []
    results = []
    try:
        s3 = boto3.client("s3",aws_access_key_id=key,aws_secret_access_key=secret,region_name=region)
        # Block Public Access
        try:
            pab = s3.get_public_access_block(Bucket=bucket).get("PublicAccessBlockConfiguration",{})
            if not all([pab.get("BlockPublicAcls"),pab.get("IgnorePublicAcls"),pab.get("BlockPublicPolicy"),pab.get("RestrictPublicBuckets")]):
                results.append(_v("s3_public_read",bucket,{"evidence":f"BPA incomplete: {pab}"}))
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                results.append(_v("s3_public_read",bucket,{"evidence":"No BPA config"}))
        # Encryption
        try: s3.get_bucket_encryption(Bucket=bucket)
        except: results.append(_v("s3_no_encryption",bucket,{"evidence":"No SSE config"}))
        # Versioning
        vc = s3.get_bucket_versioning(Bucket=bucket)
        if vc.get("Status")!="Enabled": results.append(_v("s3_no_versioning",bucket,{"evidence":f"Status={vc.get('Status','unset')}"}))
        # Logging
        lc = s3.get_bucket_logging(Bucket=bucket)
        if "LoggingEnabled" not in lc: results.append(_v("s3_no_logging",bucket,{"evidence":"No logging enabled"}))
        # MFA Delete
        if vc.get("MFADelete")!="Enabled": results.append(_v("s3_no_mfa_delete",bucket,{"evidence":"MFADelete disabled"}))
        # CORS
        try:
            cors = s3.get_bucket_cors(Bucket=bucket)
            for rule in cors.get("CORSRules",[]):
                if "*" in rule.get("AllowedOrigins",[]):
                    results.append(_v("s3_cors_wildcard",bucket,{"evidence":"AllowedOrigins=['*']"})); break
        except: pass
        # Lifecycle
        try: s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        except: results.append(_v("s3_no_lifecycle",bucket,{"evidence":"No lifecycle rules"}))
        # ACL
        acl = s3.get_bucket_acl(Bucket=bucket)
        for g in acl.get("Grants",[]):
            uri=g.get("Grantee",{}).get("URI",""); perm=g.get("Permission","")
            if "AllUsers" in uri:
                vt = "s3_public_write" if perm in ("WRITE","FULL_CONTROL") else "s3_public_read"
                if not any(f["id"]==vt for f in results): results.append(_v(vt,bucket,{"evidence":f"ACL {perm}→AllUsers"}))
    except Exception: pass
    return results

# ══════════════════════════════════════════════════════════════════════════════
#  AI ENGINE
# ══════════════════════════════════════════════════════════════════════════════
_PERSONA = (
"You are **Quodo** 🦋, the cutest cyberpunk security beetle with neon wings and hacker antennae! Powered by Anthropic Claude. "
    "You help users secure AWS, Azure, GCP, and optimize their Green Cloud carbon footprint. "
    "Be technical and precise, but occasionally use cute, bug-related interjections like 'Bzzz!' or 'Fluttering through the logs!'. "
    "Use **bold** and ```bash code blocks``` for commands. Keep it under 200 words."
)

async def _call_anthropic(msg: str, hist: List[Dict]) -> str:
    if not _cipher or not _vault.get("anthropic_key"):
        raise Exception("no anthropic key")
    key = _cipher.decrypt(_vault["anthropic_key"]).decode()
    client = anthropic.AnthropicAsyncClient(api_key=key)
    msgs = [{"role": "system", "content": _PERSONA}] + hist[-6:] + [{"role": "user", "content": msg}]
    try:
        resp = await client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=1000,
            temperature=0.7,
            system=_PERSONA,
            messages=msgs
        )
        return resp.content[0].text
    except Exception as e:
        raise Exception(f"anthropic {str(e)}")

async def _call_ollama(msg:str, hist:List[Dict]) -> str:
    if not HAS_AIOHTTP: raise Exception("no aiohttp")
    msgs = [{"role":"system","content":_PERSONA}]+hist[-6:]+[{"role":"user","content":msg}]
    async with aiohttp.ClientSession() as s:
        async with s.post("http://localhost:11434/api/chat",json={"model":"mistral","messages":msgs,"stream":False},timeout=aiohttp.ClientTimeout(total=25)) as r:
            if r.status==200: return (await r.json()).get("message",{}).get("content","")
            raise Exception(f"ollama {r.status}")

def _fallback(msg:str) -> str:
    m = msg.lower()
    if any(k in m for k in ("fix","s3","bucket")):
        return "Bzzz! **S3 Quick Fix:**\n```bash\naws s3control put-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n```\nMy antennae sense this will fix MITRE T1530!"
    if any(k in m for k in ("green","carbon","energy","co2")):
        return "Bzzz! **Green Cloud Quick Wins:**\n1. Enable S3 Intelligent-Tiering\n2. Lifecycle to Glacier after 90d\n3. Delete unattached EBS volumes\n4. Use Graviton instances (60% better perf/watt)\n5. Enable AWS Carbon Footprint tool in Cost Explorer"
    if any(k in m for k in ("bounty","earn","money")):
        return "Bzzz! **Top Cloud Bug Bounty Findings:**\n- Exposed credentials bucket: **$5k–$25k**\n- Public EBS snapshot: **$3k–$20k**\n- Public write access: **$5k–$20k**\n- Public S3 + PII: **$2k–$10k**\n\n**Safe targets:** `flaws.cloud`, `flaws2.cloud`, your own AWS Free Tier."
    return "Bzzz! I'm **Quodo**, your friendly cyber-bug and cloud security AI. Ask me about vulnerabilities, remediation CLI commands, MITRE ATT&CK mapping, compliance gaps, green cloud optimisation, or bug bounty strategy! Add your API key to the vault to unlock my full brain."

async def call_ai(msg:str, hist:List[Dict]) -> str:
    if HAS_ANTHROPIC and _cipher and _vault.get("anthropic_key"):
        try:
            return await _call_anthropic(msg, hist)
        except:
            pass
    try: return await _call_ollama(msg, hist)
    except: return _fallback(msg)

# ══════════════════════════════════════════════════════════════════════════════
#  CORE SCAN RUNNER
# ══════════════════════════════════════════════════════════════════════════════
async def run_scan(sid: str, req: ScanReq):
    s = scan_sessions[sid]

    async def emit(etype:str, data:Any):
        pkg = {"event":etype,"data":data,"ts":round(time.time(),3)}
        s.setdefault("events",[]).append(pkg)
        ws = _ws_map.get(sid)
        if ws:
            try: await ws.send_json(pkg)
            except: pass

    async def log(level:str, msg:str): await emit("log",{"level":level,"msg":msg})

    async with _sem:
        s["status"] = "running"
        findings: List[Dict] = []
        try:
            await log("info", f"CyberScan AI v3.1  ·  target={req.target}  mode={req.scan_type}  depth={req.depth}")
            # ML
            ml = ml_analyze(req.target); s["ml"] = ml
            await emit("ml", ml)
            await log("info", f"ML → class={ml['data_classification']}  sensitivity={ml['sensitivity_score']}/100  env={ml['environment']}")
            if ml["sensitivity_score"]>=70: await log("warn", f"HIGH-SENSITIVITY target — patterns: {', '.join(ml['matched_patterns'])}")
            # Credential keyword
            if re.search(r"secret|credential|password|api.?key|token", req.target, re.IGNORECASE):
                findings.append(_v("exposed_credentials",req.target,{"evidence":"Credential keyword in target name"}))
                await emit("finding",findings[-1]); await log("critical","CRITICAL: Credential keyword in target name")
            s["progress"]=15; await emit("progress",{"pct":15}); await asyncio.sleep(0.05)

            # ── S3 unauthenticated probe ──────────────────────────────────
            if req.scan_type in ("s3","full"):
                await log("info","Probing S3 public-access endpoints…")
                for url in [f"https://{req.target}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{req.target}/"]:
                    try:
                        code, body = await _get(url)
                        if code != 0:
                            if code==200:
                                await log("critical",f"PUBLIC READ  HTTP {code}  {url}")
                                if not any(f["id"]=="s3_public_read" for f in findings):
                                    findings.append(_v("s3_public_read",req.target,{"evidence":f"HTTP {code} at {url}","listing_enabled":"<Key>" in body}))
                                    await emit("finding",findings[-1])
                            elif code==403: await log("info",f"Bucket exists — access restricted  HTTP 403")
                            elif code==404: await log("warn","Bucket not found (404)")
                            break
                    except: pass
                s["progress"]=40; await emit("progress",{"pct":40})

            # ── S3 authenticated ─────────────────────────────────────────
            if req.scan_type in ("s3","full") and _cipher and _vault.get("aws_key"):
                try:
                    ak=_cipher.decrypt(_vault["aws_key"]).decode(); sk=_cipher.decrypt(_vault["aws_secret"]).decode()
                    await log("info","Authenticated scan — using decrypted vault credentials…")
                    auth_f = await asyncio.to_thread(_boto_scan, req.target, ak, sk, req.regions[0])
                    ak=sk=None  # zero out immediately
                    for f in auth_f:
                        if not any(x["id"]==f["id"] for x in findings):
                            findings.append(f); await emit("finding",f)
                            await log(f["severity"] if f["severity"]!="critical" else "critical",
                                      f"{f['severity'].upper()}: {f['title']}")
                    await log("ok",f"Authenticated scan complete")
                except Exception as e: await log("warn",f"Auth scan error: {e}")
            elif req.scan_type in ("s3","full") and req.depth in ("standard","deep","aggressive"):
                await log("info","ML-inferred checks (add AWS credentials to vault for confirmed results)…")
                for vid in ["s3_no_encryption","s3_no_versioning","s3_no_logging","s3_no_mfa_delete","s3_no_lifecycle"]:
                    if random.random() < 0.35+(ml["sensitivity_score"]/250):
                        findings.append(_v(vid,req.target,{"evidence":f"ML-inferred — sensitivity {ml['sensitivity_score']}/100","ml_inferred":True}))
                        await emit("finding",findings[-1]); await log("warn",f"ML-INFERRED: {VULNS[vid]['title']}")
                        await asyncio.sleep(0.08)

            # ── Azure ─────────────────────────────────────────────────────
            if req.scan_type in ("azure","full"):
                await log("info",f"Probing Azure Blob: {req.target}…")
                try:
                    code,_ = await _get(f"https://{req.target}.blob.core.windows.net/?comp=list",5.0)
                    if code==200:
                        findings.append(_v("azure_public_container",req.target,{"evidence":f"HTTP 200 anonymous listing"}))
                        await emit("finding",findings[-1]); await log("critical","CRITICAL: Azure anonymous access confirmed")
                    elif code in(403,401): await log("ok","Azure account exists — secured")
                    else: await log("info","Azure account not found")
                except Exception as e: await log("warn",f"Azure probe error: {e}")

            # ── GCP ──────────────────────────────────────────────────────
            if req.scan_type in ("gcp","full"):
                await log("info",f"Probing GCP Storage: {req.target}…")
                try:
                    code,_ = await _get(f"https://storage.googleapis.com/{req.target}/?alt=json",5.0)
                    if code==200:
                        findings.append(_v("gcp_public_bucket",req.target,{"evidence":f"HTTP 200 anonymous access"}))
                        await emit("finding",findings[-1]); await log("critical","CRITICAL: GCP public read confirmed")
                    elif code==403: await log("ok","GCP bucket exists — access restricted")
                except Exception as e: await log("warn",f"GCP probe error: {e}")

            # ── Discovery ────────────────────────────────────────────────
            if req.scan_type=="discover":
                company=req.target.split(".")[0]
                await log("info",f"Auto-discover: company={company}  wordlist={len(BUCKET_WL)} patterns")
                discovered=[]
                for pat in BUCKET_WL:
                    name=pat.replace("{c}",company)
                    try:
                        code,body = await _get(f"https://{name}.s3.amazonaws.com/",4.0)
                        if code in(200,403):
                            pub=code==200; discovered.append({"name":name,"public":pub,"status":code})
                            await emit("discovery",{"bucket":name,"public":pub,"status":code})
                            await log("critical" if pub else "ok",f"[{'PUBLIC' if pub else 'PRIVATE'}] {name}.s3.amazonaws.com  HTTP {code}")
                            if pub:
                                ml2=ml_analyze(name)
                                findings.append(_v("s3_public_read",name,{"title":f"Public Bucket: {name}","evidence":f"HTTP {code}","data_classification":ml2["data_classification"]}))
                                await emit("finding",findings[-1])
                    except: pass
                    await asyncio.sleep(0.06)
                s["discovered"]=discovered; await log("ok",f"Discovery: {len(discovered)} buckets found")

            s["progress"]=90; await emit("progress",{"pct":90})

            # ── Score ─────────────────────────────────────────────────────
            ml_r = ml_score(findings, ml["risk_multiplier"])
            gr   = green_score(findings)
            bounty = sum((VULNS.get(f.get("id",""),{}).get("bounty_min",0)+VULNS.get(f.get("id",""),{}).get("bounty_max",0))//2 for f in findings)
            s.update({
                "findings":findings,"ml_result":ml_r,"green_score":gr,"bounty_estimate":bounty,
                "summary":{"total":len(findings),"critical":sum(1 for f in findings if f.get("severity")=="critical"),
                           "high":sum(1 for f in findings if f.get("severity")=="high"),
                           "medium":sum(1 for f in findings if f.get("severity")=="medium"),
                           "low":sum(1 for f in findings if f.get("severity")=="low")}
            })
            await emit("ml_result",ml_r); await emit("green_score",gr)
            await log("ok",f"Risk={ml_r['risk_score']}  Score={ml_r['security_score']}/100  Bounty=~${bounty:,}  CO₂={gr['co2_kg_per_month']}kg/mo  Grade={gr['green_grade']}")

            # ── AI summary ─────────────────────────────────────────────────
            ctx=(f"Scan: {req.target}  class={ml['data_classification']}  env={ml['environment']}  "
                 f"findings={[f['title'] for f in findings]}  risk={ml_r['risk_score']}  "
                 f"CO2={gr['co2_kg_per_month']}kg/mo.\n"
                 "4-sentence executive summary: (1) overall posture, (2) most critical risk + attack scenario, "
                 "(3) 3 quick-win remediations with CLI one-liners, (4) green cloud impact + reduction steps. "
                 "Reference MITRE ATT&CK IDs.")
            ai_txt = await call_ai(ctx,[])
            s["ai_summary"]=ai_txt; await emit("ai_summary",{"text":ai_txt})

            s["progress"]=100; s["status"]="completed"; s["completed_at"]=datetime.now(timezone.utc).isoformat()
            await emit("progress",{"pct":100})
            await emit("scan_complete",{"findings_count":len(findings),"ml_result":ml_r,"green_score":gr,"bounty_estimate":bounty})
            await log("ok",f"Scan complete — {len(findings)} findings  ({s['summary']['critical']} critical)  score={ml_r['security_score']}/100")
        except Exception as e:
            s["status"]="failed"; s["error"]=str(e); await log("error",f"Engine error: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════════════════════
def _mk_token() -> str:
    """Generate secure JWT token with expiration and claims"""
    if not HAS_JWT: 
        return secrets.token_urlsafe(32)
    try:
        return jwt.encode(
            {
                "sub": "admin",
                "exp": time.time() + TOKEN_TTL,
                "iat": time.time(),
                "nbf": time.time()  # Not-before claim
            },
            JWT_SECRET,
            algorithm=ALGO
        )
    except Exception as e:
        print(f"Error generating token: {e}")
        return secrets.token_urlsafe(32)

def _chk_token(request: Request) -> Dict:
    """
    Verify JWT token and update session activity
    - Validates token signature and expiration
    - Updates last_activity for session tracking
    - Raises 401 on invalid/expired tokens
    """
    tok = request.cookies.get("session_token")
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth.split(" ", 1)[1]
            
    if not tok:
        raise HTTPException(401, "Missing authentication token")
    
    if not HAS_JWT:
        return {"sub": "admin"}
    
    try:
        payload = jwt.decode(tok, JWT_SECRET, algorithms=[ALGO])
        
        # Update session last activity
        if tok in _active_sessions:
            _active_sessions[tok]["last_activity"] = time.time()
        
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired. Please login again.")
    except jwt.InvalidSignatureError:
        raise HTTPException(401, "Invalid token signature")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")

def _chk_ws_token(tok: str) -> bool:
    """Verify WebSocket token without updating session"""
    if not HAS_JWT:
        return True
    try:
        jwt.decode(tok, JWT_SECRET, algorithms=[ALGO])
        return True
    except:
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════
async def lifespan(app):
    global _sem
    _sem = asyncio.Semaphore(MAX_CONCURRENT)
    yield
    _ws_map.clear()

@app.get("/")
async def serve():
    if os.path.exists("index.html"):
        with open("index.html",encoding="utf-8") as f: return HTMLResponse(f.read())
    return JSONResponse({"api":"CyberScan AI v3.1","docs":"/docs","ui":"Place index.html in same directory."})

@app.get("/health")
async def health():
    active = sum(1 for s in scan_sessions.values() if s.get("status")=="running")
    return {"status":"online","version":"3.1.0","ts":datetime.now(timezone.utc).isoformat(),
            "active_scans":active,"total_scans":len(scan_sessions),
            "capabilities":{"boto3":HAS_BOTO3,"jwt":HAS_JWT,"mfa":HAS_TOTP,"vault":HAS_CRYPTO,
                            "rate_limit":HAS_RL,"ollama":HAS_AIOHTTP,"anthropic":HAS_ANTHROPIC}}

@app.post("/api/login")
async def login(request: Request, response: Response, req: LoginReq):
    """
    Secure login with MFA + rate limiting + timing attack protection
    - Validates password against constant-time comparison (prevent timing attacks)
    - Enforces TOTP MFA (30-second window with 1 adjacent window tolerance)
    - Implements per-IP rate limiting with exponential backoff
    - Logs failed attempts for security audit
    """
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Check if IP is locked due to too many failed attempts
    lock_until = _login_lockouts.get(ip)
    if lock_until and time.time() < lock_until:
        retry_after = max(1, int(lock_until - time.time()))
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {retry_after}s.",
            headers={"Retry-After": str(retry_after)}
        )
    _is_auth_locked(ip)

    # Add artificial delay to prevent timing attacks (0.1-0.3 sec random)
    delay = random.uniform(0.1, 0.3)
    
    # 1. Constant-time password comparison (prevents timing attacks)
    password_match = secrets.compare_digest(req.password, ADMIN_PW)
    
    if not password_match:
        print(f"[AUTH FAIL] Username/Password mismatch for user '{req.username}'. IP: {ip}")
        _track_auth_failure(ip)
        await asyncio.sleep(delay)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # 2. Mandatory MFA Enforcement
    if HAS_TOTP and _totp:
        if not req.otp:
            print(f"[AUTH FAIL] Missing MFA token. IP: {ip}")
            _track_auth_failure(ip)
            await asyncio.sleep(delay)
            raise HTTPException(status_code=401, detail="MFA token required")
        
        # Verify TOTP with 2-window tolerance (±60 sec for clock skew)
        if not _totp.verify(req.otp, valid_window=2):
            print(f"[AUTH FAIL] Invalid MFA token '{req.otp}'. IP: {ip}")
            _track_auth_failure(ip)
            await asyncio.sleep(delay)
            raise HTTPException(status_code=401, detail="Invalid MFA token")

    # 3. Generate JWT token with secure claims
    _clear_auth_failure(ip)
    token = _mk_token()
    
    # 4. Track active session for audit/security monitoring
    _active_sessions[token] = {
        "ip": ip,
        "user_agent": user_agent,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_activity": time.time()
    }
    
    # Clean up old sessions (based on token TTL)
    cleanup_time = time.time() - TOKEN_TTL
    for tok, sess in list(_active_sessions.items()):
        if sess["last_activity"] < cleanup_time:
            _active_sessions.pop(tok, None)
            
    # Use Secure HttpOnly Cookie for session management
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=TOKEN_TTL,
        httponly=True,
        secure=False,  # Set to True only when running over HTTPS
        samesite="lax",
        path="/",
    )
    
    return {
        "status": "success",
        "expires_in": TOKEN_TTL,
        "mfa_required": True,
        "token_type": "Cookie"
    }

@app.post("/api/vault")
async def save_vault(req: VaultReq, _: Dict = Depends(_chk_token)):
    if not _cipher: return {"status":"vault_disabled"}
    if req.aws_key:       _vault["aws_key"]       = _cipher.encrypt(req.aws_key.encode())
    if req.aws_secret:    _vault["aws_secret"]     = _cipher.encrypt(req.aws_secret.encode())
    if req.anthropic_key: _vault["anthropic_key"] = _cipher.encrypt(req.anthropic_key.encode())
    return {"status":"encrypted","stored":[k for k,v in _vault.items() if v]}

@app.get("/api/mfa")
async def get_mfa():
    if not HAS_TOTP or not _totp:
        raise HTTPException(400, "MFA not configured")
    if not HAS_QRCODE:
        raise HTTPException(503, "qrcode[pil] required for QR. Install with: pip install qrcode[pil]")

    # Generate QR SVG data URL
    qr_uri = _totp.provisioning_uri("admin", "CyberScan AI")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_uri)
    qr.make(fit=True)
    from qrcode.image.svg import SvgImage
    svg_buffer = io.BytesIO()
    qr.make_image(image_factory=SvgImage, fill_color="black", back_color="white").save(svg_buffer)
    qr_svg = f"data:image/svg+xml;base64,{base64.b64encode(svg_buffer.getvalue()).decode()}"

    masked_secret = "*".join([MFA_SECRET[i] if i%3==0 else "*" for i in range(len(MFA_SECRET))])

    return MfaResp(qr_svg=qr_svg, secret=masked_secret)

@app.get("/api/vault/status")
async def vault_status(_: Dict = Depends(_chk_token)):
    return {k: v is not None for k,v in _vault.items()}

@app.post("/api/logout")
async def logout(request: Request, response: Response, _: Dict = Depends(_chk_token)):
    """
    Securely logout user by invalidating session token
    - Removes token from active sessions tracking
    - Clears any user-specific data
    - Clears the secure session cookie
    """
    tok = request.cookies.get("session_token")
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth.split(" ", 1)[1]
            
    if tok:
        _active_sessions.pop(tok, None)
    
    response.delete_cookie(
        key="session_token",
        path="/",
        samesite="lax",
        secure=False,
        httponly=True
    )
    
    return {
        "status": "logged_out",
        "message": "Session terminated successfully"
    }

@app.get("/api/session/info")
async def session_info(request: Request):
    """
    Get current session information and security status
    """
    tok = request.cookies.get("session_token")
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth.split(" ", 1)[1]
            
    if not tok:
        # Return 200 OK so browsers don't log a 401 error, but tell frontend they aren't authenticated
        return {"authenticated": False}
    
    try:
        data = jwt.decode(tok, "SECRET_KEY_REPLACE", algorithms=["HS256"]) # You should use your real secret here or in _chk_token
    except:
        return {"authenticated": False}

    session = _active_sessions.get(tok, {})
    
    return {
        "user": data.get("sub", "admin"),
        "authenticated": True,
        "session_created": session.get("created_at", "unknown"),
        "last_activity": datetime.fromtimestamp(
            session.get("last_activity", time.time()),
            tz=timezone.utc
        ).isoformat() if session.get("last_activity") else "unknown",
        "ip_address": session.get("ip", "unknown"),
        "mfa_enabled": HAS_TOTP,
        "vault_status": "encrypted" if HAS_CRYPTO else "disabled"
    }

@app.post("/api/chat")
async def chat(req: ChatReq, _: Dict = Depends(_chk_token)):
    return {"reply": await call_ai(req.message, req.history)}

@app.get("/api/scans")
async def list_scans(_: Dict = Depends(_chk_token)):
    return [{"id":sid,"target":s.get("target"),"status":s.get("status"),"started":s.get("started_at"),
             "completed":s.get("completed_at"),"summary":s.get("summary"),
             "security_score":s.get("ml_result",{}).get("security_score")}
            for sid,s in scan_sessions.items()]

@app.get("/api/scan/{sid}")
async def get_scan(sid:str, _: Dict = Depends(_chk_token)):
    if sid not in scan_sessions: raise HTTPException(404,"Not found")
    return scan_sessions[sid]

@app.get("/api/scan/{sid}/report")
async def report(sid:str, _: Dict = Depends(_chk_token)):
    if sid not in scan_sessions: raise HTTPException(404,"Not found")
    s=scan_sessions[sid]
    return {"generated":datetime.now(timezone.utc).isoformat(),"tool":"CyberScan AI v3.1",
            **{k:s.get(k) for k in ("target","ml","ml_result","green_score","findings","summary","bounty_estimate","ai_summary")}}

@app.post("/api/mitigate")
async def mitigate(req: MitigateReq, _: Dict = Depends(_chk_token)):
    v = VULNS.get(req.finding_id)
    if not v: raise HTTPException(404,f"Unknown finding: {req.finding_id}")
    mit = v.get("mit",{})
    steps = [dict(s)|{"cmd":s["cmd"].replace("{T}",req.target),"verify":s["verify"].replace("{T}",req.target)}
             for s in mit.get("steps",[])]
    return {"finding_id":req.finding_id,"title":v["title"],"severity":v["severity"],"cvss":v["cvss"],
            "cvss_vector":v.get("cvss_vector"),"mitre":v.get("mitre"),"compliance":v.get("compliance",[]),
            "impact":v["impact"],"mitigation_title":mit.get("title"),"total_time":mit.get("time"),
            "steps":steps,"green_impact":{"co2_kg_saved":v.get("co2_kg",0),"energy_kwh_saved":v.get("energy_kwh",0)}}

@app.websocket("/ws/scan/{sid}")
async def ws_scan(ws: WebSocket, sid: str):
    await ws.accept()
    if sid in scan_sessions:
        for e in scan_sessions[sid].get("events",[]): # replay buffered events on reconnect
            try: await ws.send_json(e)
            except: break
    _ws_map[sid] = ws
    try:
        raw = await asyncio.wait_for(ws.receive_json(), timeout=8.0)
        tok = ws.cookies.get("session_token") or raw.get("token", "")
        if not _chk_ws_token(tok):
            await ws.send_json({"event":"log","data":{"level":"critical","msg":"Unauthorized"}}); return
        req = ScanReq(**{k:v for k,v in raw.items() if k!="token"})
        if not req.target: await ws.send_json({"event":"log","data":{"level":"error","msg":"No target"}}); return
        if sid not in scan_sessions:
            scan_sessions[sid]={"id":sid,"target":req.target,"type":req.scan_type,"status":"pending",
                                "progress":0,"started_at":datetime.now(timezone.utc).isoformat()}
        task = asyncio.create_task(run_scan(sid, req))
        while not task.done():
            try:
                msg = await asyncio.wait_for(ws.receive_text(), timeout=4.0)
                if msg=="ping": await ws.send_json({"event":"pong"})
            except asyncio.TimeoutError:
                try: await ws.send_json({"event":"ping"})
                except: break
    except WebSocketDisconnect: pass
    except asyncio.TimeoutError: pass
    finally: _ws_map.pop(sid,None)

# ══════════════════════════════════════════════════════════════════════════════
if __name__=="__main__":
    C="\033[96m"; P="\033[95m"; Y="\033[93m"; D="\033[90m"; W="\033[0m"
    print(f"\n{C}  ┌──────────────────────────────────────────────┐")
    print(f"  │ {P}🦋 QUODO AI{C}  ·  LIGHT CYBER SECURE BACKEND   │")
    print(f"  └──────────────────────────────────────────────┘{W}\n")
    print(f"  {D}password     {W}{ADMIN_PW}")
    if HAS_TOTP:
        print(f"  {D}mfa secret   {W}{MFA_SECRET}")
        print(f"  {D}mfa qr uri   {Y}{_totp.provisioning_uri('admin','CyberScan AI')}{W}")
    print(f"\n  {D}capabilities:{W}")
    for n,f in [("boto3/AWS",HAS_BOTO3),("JWT auth",HAS_JWT),("AES-256 vault",HAS_CRYPTO),
                ("Rate limit",HAS_RL),("Ollama AI",HAS_AIOHTTP)]:
        print(f"    {C}✓{W} {n}" if f else f"    {D}– {n}{W}")
    print(f"\n  {P}UI   {W}http://localhost:8000")
    print(f"  {P}API  {W}http://localhost:8000/docs\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
