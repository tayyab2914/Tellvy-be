from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, UploadFile, File, Query, Header, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import asyncio
import logging
import uuid
import bcrypt
import jwt as pyjwt
import requests
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
from typing import List, Optional
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_ALGORITHM = "HS256"
def get_jwt_secret():
    return os.environ["JWT_SECRET"]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {"sub": user_id, "email": email, "role": role, "exp": datetime.now(timezone.utc) + timedelta(minutes=60), "type": "access"}
    return pyjwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "refresh"}
    return pyjwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

# Object Storage
STORAGE_URL = "https://integrations.emergentagent.com/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = "tellvy"

# Gemini AI
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
# Outscraper
OUTSCRAPER_API_KEY = os.environ.get("OUTSCRAPER_API_KEY")
storage_key = None

def init_storage():
    global storage_key
    if storage_key:
        return storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
    resp.raise_for_status()
    storage_key = resp.json()["storage_key"]
    return storage_key

def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key, "Content-Type": content_type}, data=data, timeout=120)
    resp.raise_for_status()
    return resp.json()

def get_object(path: str):
    key = init_storage()
    resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")

# Auth helper
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = pyjwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(*roles):
    async def checker(request: Request):
        user = await get_current_user(request)
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker

# Audit helper
async def log_audit(user_id: str, user_name: str, action: str, details: str):
    audit_doc = {
        "id": str(uuid.uuid4()), "user_id": user_id, "user_name": user_name,
        "action": action, "details": details, "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.audit_logs.insert_one(audit_doc)

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ===================== OUTSCRAPER REVIEW IMPORT =====================

def _detect_source(url: str) -> str:
    lower = url.lower()
    if "booking.com" in lower:
        return "Booking.com"
    if "google.com/maps" in lower or "maps.google" in lower or "goo.gl/maps" in lower or "maps.app.goo.gl" in lower:
        return "Google Maps"
    return ""

def _fetch_outscraper_sync(endpoint: str, params: dict, api_key: str) -> dict:
    resp = requests.get(endpoint, params=params, headers={"X-API-KEY": api_key}, timeout=120)
    resp.raise_for_status()
    return resp.json()

async def import_outscraper_reviews(client_id: str, outscraper_url: str):
    if not OUTSCRAPER_API_KEY:
        logger.warning("OUTSCRAPER_API_KEY not set — skipping review import")
        return
    source = _detect_source(outscraper_url)
    if not source:
        logger.warning(f"Unrecognised Outscraper URL for client {client_id}: {outscraper_url}")
        return
    try:
        if source == "Google Maps":
            result = await asyncio.to_thread(
                _fetch_outscraper_sync,
                "https://api.outscraper.cloud/google-maps-reviews",
                {"query": outscraper_url, "reviewsLimit": 50, "async": "false"},
                OUTSCRAPER_API_KEY,
            )
        else:
            result = await asyncio.to_thread(
                _fetch_outscraper_sync,
                "https://api.outscraper.cloud/booking-reviews",
                {"query": outscraper_url, "limit": 50, "async": "false"},
                OUTSCRAPER_API_KEY,
            )

        if result.get("status") != "Success":
            logger.error(f"Outscraper returned non-success for client {client_id}: {result.get('status')}")
            return

        reviews_to_insert = []
        print("Outscraper result:", json.dumps(result, indent=2))  # Debug log
        print("Source detected:", source)  # Debug log
        if source == "Google Maps":
            for place in result.get("data", []):
                for rev in place.get("reviews_data", []):
                    text = (rev.get("review_text") or "").strip()
                    if not text:
                        continue
                    external_id = f"{rev.get('author_id', '')}_{rev.get('review_timestamp', '')}"
                    existing = await db.reviews.find_one({"client_id": client_id, "external_id": external_id})
                    if existing:
                        continue
                    try:
                        created_at = datetime.strptime(rev["review_datetime_utc"], "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
                    except Exception:
                        created_at = datetime.now(timezone.utc).isoformat()
                    reviews_to_insert.append({
                        "id": str(uuid.uuid4()),
                        "client_id": client_id,
                        "source": "Google Maps",
                        "rating": int(rev.get("review_rating", 5)),
                        "text": text,
                        "author": rev.get("author_title", "Anonymous"),
                        "external_id": external_id,
                        "created_at": created_at,
                    })

        else:  # Booking.com
            for batch in result.get("data", []):
                items = batch if isinstance(batch, list) else [batch]
                for rev in items:
                    liked = (rev.get("review_liked_text") or "").strip()
                    disliked = (rev.get("review_disliked_text") or "").strip()
                    text = liked
                    if liked and disliked:
                        text = f"{liked}\n\nDisliked: {disliked}"
                    elif disliked:
                        text = disliked
                    if not text:
                        continue
                    external_id = rev.get("review_id", "")
                    if external_id:
                        existing = await db.reviews.find_one({"client_id": client_id, "external_id": external_id})
                        if existing:
                            continue
                    raw = float(rev.get("review_score", 0))
                    if raw > 10:
                        raw = raw / 10
                    rating = max(1, min(5, round(raw / 2)))
                    reviews_to_insert.append({
                        "id": str(uuid.uuid4()),
                        "client_id": client_id,
                        "source": "Booking.com",
                        "rating": rating,
                        "text": text,
                        "author": rev.get("author_title", "Anonymous"),
                        "external_id": external_id,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
        print("Reviews to insert:", len(reviews_to_insert), reviews_to_insert)  # Debug log
        if reviews_to_insert:
            await db.reviews.insert_many(reviews_to_insert)
            logger.info(f"Imported {len(reviews_to_insert)} {source} reviews for client {client_id}")
        else:
            logger.info(f"No new reviews to import for client {client_id}")

    except Exception as e:
        logger.error(f"Outscraper import failed for client {client_id}: {e}")

# ===================== PYDANTIC MODELS =====================

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    business_name: str
    category: str = "General"
    city: str = ""

class CreateStaffRequest(BaseModel):
    email: str
    password: str
    name: str
    region: str = ""
    role: str = "sales_agent"

class CreateClientRequest(BaseModel):
    business_name: str
    email: str
    password: str
    contact_name: str
    category: str = "General"
    city: str = ""
    redirect_url: str = ""
    outscraper_url: str = ""
    is_active: bool = True

class UpdateRedirectRequest(BaseModel):
    redirect_url: str
    is_active: Optional[bool] = None
    outscraper_url: Optional[str] = None

class MagicWriteRequest(BaseModel):
    member_name: str
    tags: List[str]
    category: str = "General"

class ResponseAssistRequest(BaseModel):
    review_text: str
    rating: int = 5
    category: str = "General"

# ===================== AUTH ROUTES =====================

@api_router.post("/auth/register")
async def register(req: RegisterRequest, response: Response):
    email = req.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    client_id = str(uuid.uuid4())
    standee_id = f"A{str(uuid.uuid4())[:6].upper()}"
    user_doc = {"email": email, "password_hash": hash_password(req.password), "name": req.name, "role": "client", "client_id": client_id, "created_at": datetime.now(timezone.utc).isoformat()}
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    client_doc = {"id": client_id, "business_name": req.business_name.strip(), "email": email, "contact_name": req.name, "category": req.category, "city": req.city, "standee_id": standee_id, "redirect_url": "", "is_active": True, "created_by": "self_registration", "created_at": datetime.now(timezone.utc).isoformat()}
    await db.clients.insert_one(client_doc)
    access_token = create_access_token(user_id, email, "client")
    refresh_token = create_refresh_token(user_id)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    return {"id": user_id, "email": email, "name": req.name, "role": "client", "token": access_token}

@api_router.post("/auth/login")
async def login(req: LoginRequest, response: Response):
    email = req.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = str(user["_id"])
    role = user["role"]
    access_token = create_access_token(user_id, email, role)
    refresh_token = create_refresh_token(user_id)
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    resp = {"id": user_id, "email": user["email"], "name": user.get("name", ""), "role": role, "token": access_token}
    if user.get("region"):
        resp["region"] = user["region"]
    return resp

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    resp = {"id": user["_id"], "email": user["email"], "name": user.get("name", ""), "role": user["role"]}
    if user.get("region"):
        resp["region"] = user["region"]
    if user.get("client_id"):
        resp["client_id"] = user["client_id"]
    return resp

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out"}

@api_router.post("/auth/refresh")
async def refresh_token_endpoint(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = pyjwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user_id = str(user["_id"])
        access_token = create_access_token(user_id, user["email"], user["role"])
        response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
        return {"id": user_id, "email": user["email"], "name": user.get("name", ""), "role": user["role"], "token": access_token}
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# ===================== SUPER ADMIN ROUTES =====================

@api_router.get("/admin/stats")
async def admin_stats(user: dict = Depends(require_role("super_admin"))):
    total_clients = await db.clients.count_documents({})
    total_agents = await db.users.count_documents({"role": "sales_agent"})
    total_rms = await db.users.count_documents({"role": "regional_manager"})
    total_members = await db.team_members.count_documents({})
    total_intents = await db.intent_logs.count_documents({})
    active_clients = await db.clients.count_documents({"is_active": True})
    regions = await db.regions.distinct("name")
    return {"total_clients": total_clients, "total_agents": total_agents, "total_rms": total_rms, "total_members": total_members, "total_intents": total_intents, "active_clients": active_clients, "total_regions": len(regions), "regions": regions}

@api_router.get("/admin/regions")
async def admin_list_regions(user: dict = Depends(require_role("super_admin"))):
    regions = await db.regions.find({}, {"_id": 0}).to_list(100)
    for r in regions:
        r["agent_count"] = await db.users.count_documents({"role": "sales_agent", "region": r["name"]})
        r["rm_count"] = await db.users.count_documents({"role": "regional_manager", "region": r["name"]})
        r["client_count"] = await db.clients.count_documents({"region": r["name"]})
    return regions

@api_router.post("/admin/regions")
async def admin_create_region(data: dict, user: dict = Depends(require_role("super_admin"))):
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Region name is required")
    existing = await db.regions.find_one({"name": name})
    if existing:
        raise HTTPException(status_code=400, detail="Region already exists")
    region_doc = {"id": str(uuid.uuid4()), "name": name, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.regions.insert_one(region_doc)
    await log_audit(user["_id"], user.get("name", "Admin"), "created_region", f"Created region '{name}'")
    return {k: v for k, v in region_doc.items() if k != "_id"}

@api_router.delete("/admin/regions/{region_name}")
async def admin_delete_region(region_name: str, user: dict = Depends(require_role("super_admin"))):
    result = await db.regions.delete_one({"name": region_name})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Region not found")
    await log_audit(user["_id"], user.get("name", "Admin"), "deleted_region", f"Deleted region '{region_name}'")
    return {"message": "Deleted"}

@api_router.get("/admin/clients")
async def admin_list_clients(user: dict = Depends(require_role("super_admin"))):
    clients = await db.clients.find({}, {"_id": 0}).to_list(1000)
    return clients

@api_router.post("/admin/clients")
async def admin_create_client(req: CreateClientRequest, background_tasks: BackgroundTasks, user: dict = Depends(require_role("super_admin"))):
    client_id = str(uuid.uuid4())
    standee_id = f"A{str(uuid.uuid4())[:6].upper()}"
    existing = await db.users.find_one({"email": req.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    user_doc = {"email": req.email.lower().strip(), "password_hash": hash_password(req.password), "name": req.contact_name, "role": "client", "client_id": client_id, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.users.insert_one(user_doc)
    client_doc = {"id": client_id, "business_name": req.business_name, "email": req.email.lower().strip(), "contact_name": req.contact_name, "category": req.category, "city": req.city, "standee_id": standee_id, "redirect_url": req.redirect_url or "", "outscraper_url": req.outscraper_url or "", "is_active": req.is_active, "created_by": user["_id"], "created_at": datetime.now(timezone.utc).isoformat()}
    await db.clients.insert_one(client_doc)
    await log_audit(user["_id"], user.get("name", "Admin"), "created_client", f"Created client '{req.business_name}' (Standee: {standee_id})")
    if req.outscraper_url:
        background_tasks.add_task(import_outscraper_reviews, client_id, req.outscraper_url)
    return {k: v for k, v in client_doc.items() if k != "_id"}

@api_router.put("/admin/clients/{client_id}")
async def admin_update_client(client_id: str, req: UpdateRedirectRequest, user: dict = Depends(require_role("super_admin"))):
    update = {"redirect_url": req.redirect_url}
    if req.is_active is not None:
        update["is_active"] = req.is_active
    if req.outscraper_url is not None:
        update["outscraper_url"] = req.outscraper_url
    result = await db.clients.update_one({"id": client_id}, {"$set": update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"message": "Updated"}

@api_router.delete("/admin/clients/{client_id}")
async def admin_delete_client(client_id: str, user: dict = Depends(require_role("super_admin"))):
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    await db.clients.delete_one({"id": client_id})
    await db.users.delete_one({"client_id": client_id})
    await db.team_members.delete_many({"client_id": client_id})
    await log_audit(user["_id"], user.get("name", "Admin"), "deleted_client", f"Deleted client '{client_doc['business_name']}' (ID: {client_id})")
    return {"message": "Deleted"}

@api_router.put("/admin/clients/{client_id}/kill-switch")
async def toggle_kill_switch(client_id: str, user: dict = Depends(require_role("super_admin"))):
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    new_status = not client_doc.get("is_active", True)
    await db.clients.update_one({"id": client_id}, {"$set": {"is_active": new_status}})
    await log_audit(user["_id"], user.get("name", "Admin"), "kill_switch", f"{'Activated' if new_status else 'Deactivated'} client '{client_doc['business_name']}'")
    return {"is_active": new_status}

@api_router.post("/admin/staff")
async def admin_create_staff(req: CreateStaffRequest, user: dict = Depends(require_role("super_admin"))):
    existing = await db.users.find_one({"email": req.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    if req.role not in ("sales_agent", "regional_manager"):
        raise HTTPException(status_code=400, detail="Role must be sales_agent or regional_manager")
    doc = {"email": req.email.lower().strip(), "password_hash": hash_password(req.password), "name": req.name, "role": req.role, "region": req.region, "created_at": datetime.now(timezone.utc).isoformat()}
    result = await db.users.insert_one(doc)
    rid = str(result.inserted_id)
    label = "Sales Agent" if req.role == "sales_agent" else "Regional Manager"
    await log_audit(user["_id"], user.get("name", "Admin"), f"created_{req.role}", f"Created {label} '{req.name}' in region '{req.region}'")
    return {"id": rid, "email": req.email.lower().strip(), "name": req.name, "role": req.role, "region": req.region}

@api_router.get("/admin/staff")
async def admin_list_staff(user: dict = Depends(require_role("super_admin"))):
    staff = await db.users.find({"role": {"$in": ["sales_agent", "regional_manager"]}}, {"password_hash": 0}).to_list(500)
    for s in staff:
        s["id"] = str(s.pop("_id"))
        if s["role"] == "sales_agent":
            s["client_count"] = await db.clients.count_documents({"created_by": s["id"]})
    return staff

@api_router.delete("/admin/staff/{staff_id}")
async def admin_delete_staff(staff_id: str, user: dict = Depends(require_role("super_admin"))):
    result = await db.users.delete_one({"_id": ObjectId(staff_id), "role": {"$in": ["sales_agent", "regional_manager"]}})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Staff not found")
    await log_audit(user["_id"], user.get("name", "Admin"), "deleted_staff", f"Deleted staff member ID: {staff_id}")
    return {"message": "Deleted"}

@api_router.get("/admin/audit-logs")
async def admin_audit_logs(user: dict = Depends(require_role("super_admin"))):
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(500)
    return logs

@api_router.get("/admin/redirects")
async def admin_list_redirects(user: dict = Depends(require_role("super_admin"))):
    clients = await db.clients.find({}, {"_id": 0, "id": 1, "business_name": 1, "standee_id": 1, "redirect_url": 1, "is_active": 1}).to_list(1000)
    return clients

# ===================== REGIONAL MANAGER ROUTES =====================

@api_router.get("/regional/stats")
async def regional_stats(user: dict = Depends(require_role("regional_manager"))):
    region = user.get("region", "")
    agent_ids = []
    agents = await db.users.find({"role": "sales_agent", "region": region}, {"_id": 1}).to_list(500)
    agent_ids = [str(a["_id"]) for a in agents]
    total_agents = len(agent_ids)
    total_clients = await db.clients.count_documents({"created_by": {"$in": agent_ids}})
    active_clients = await db.clients.count_documents({"created_by": {"$in": agent_ids}, "is_active": True})
    # Also count clients in this region
    region_clients = await db.clients.count_documents({"region": region})
    total_clients = max(total_clients, region_clients)
    total_members = 0
    total_intents = 0
    client_docs = await db.clients.find({"created_by": {"$in": agent_ids}}, {"id": 1, "_id": 0}).to_list(1000)
    client_ids = [c["id"] for c in client_docs]
    if client_ids:
        total_members = await db.team_members.count_documents({"client_id": {"$in": client_ids}})
        total_intents = await db.intent_logs.count_documents({"client_id": {"$in": client_ids}})
    return {"region": region, "total_agents": total_agents, "total_clients": total_clients, "active_clients": active_clients, "total_members": total_members, "total_intents": total_intents}

@api_router.get("/regional/agents")
async def regional_list_agents(user: dict = Depends(require_role("regional_manager"))):
    region = user.get("region", "")
    agents = await db.users.find({"role": "sales_agent", "region": region}, {"password_hash": 0}).to_list(500)
    for a in agents:
        a["id"] = str(a.pop("_id"))
        a["client_count"] = await db.clients.count_documents({"created_by": a["id"]})
    return agents

@api_router.get("/regional/clients")
async def regional_list_clients(user: dict = Depends(require_role("regional_manager"))):
    region = user.get("region", "")
    agent_ids = [str(a["_id"]) for a in await db.users.find({"role": "sales_agent", "region": region}, {"_id": 1}).to_list(500)]
    clients = await db.clients.find({"created_by": {"$in": agent_ids}}, {"_id": 0}).to_list(1000)
    # Enrich with agent name
    for c in clients:
        agent = await db.users.find_one({"_id": ObjectId(c["created_by"])} if ObjectId.is_valid(c.get("created_by", "")) else {"_id": None}, {"name": 1, "_id": 0})
        c["agent_name"] = agent.get("name", "Unknown") if agent else "Admin/Self"
    return clients

@api_router.get("/regional/leaderboard/{client_id}")
async def regional_client_leaderboard(client_id: str, user: dict = Depends(require_role("regional_manager"))):
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    leaderboard = []
    for m in members:
        count = await db.intent_logs.count_documents({"member_id": m["id"]})
        leaderboard.append({"id": m["id"], "name": m["name"], "role_title": m.get("role_title", ""), "photo_path": m.get("photo_path", ""), "intent_count": count})
    leaderboard.sort(key=lambda x: x["intent_count"], reverse=True)
    return leaderboard

# ===================== SALES AGENT ROUTES =====================

class AgentCreateClientRequest(BaseModel):
    business_name: str
    email: str
    password: str
    contact_name: str
    category: str = "General"
    city: str = ""
    redirect_url: str = ""
    outscraper_url: str = ""

@api_router.get("/agent/clients")
async def agent_list_clients(user: dict = Depends(require_role("sales_agent"))):
    clients = await db.clients.find({"created_by": user["_id"]}, {"_id": 0}).to_list(100)
    return clients

@api_router.post("/agent/clients")
async def agent_create_client(req: AgentCreateClientRequest, background_tasks: BackgroundTasks, user: dict = Depends(require_role("sales_agent"))):
    existing = await db.users.find_one({"email": req.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    client_id = str(uuid.uuid4())
    standee_id = f"A{str(uuid.uuid4())[:6].upper()}"
    user_doc = {"email": req.email.lower().strip(), "password_hash": hash_password(req.password), "name": req.contact_name, "role": "client", "client_id": client_id, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.users.insert_one(user_doc)
    client_doc = {"id": client_id, "business_name": req.business_name, "email": req.email.lower().strip(), "contact_name": req.contact_name, "category": req.category, "city": req.city, "standee_id": standee_id, "redirect_url": req.redirect_url or "", "outscraper_url": req.outscraper_url or "", "is_active": True, "created_by": user["_id"], "region": user.get("region", ""), "created_at": datetime.now(timezone.utc).isoformat()}
    await db.clients.insert_one(client_doc)
    await log_audit(user["_id"], user.get("name", "Agent"), "created_client", f"Agent '{user.get('name')}' created client '{req.business_name}' (Standee: {standee_id})")
    if req.outscraper_url:
        background_tasks.add_task(import_outscraper_reviews, client_id, req.outscraper_url)
    return {k: v for k, v in client_doc.items() if k != "_id"}

@api_router.get("/agent/clients/{client_id}")
async def agent_get_client(client_id: str, user: dict = Depends(require_role("sales_agent"))):
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    return {"client": client_doc, "members": members}

@api_router.put("/agent/clients/{client_id}/redirect")
async def agent_update_redirect(client_id: str, data: dict, user: dict = Depends(require_role("sales_agent"))):
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found or not yours")
    await db.clients.update_one({"id": client_id}, {"$set": {"redirect_url": data.get("redirect_url", "")}})
    await log_audit(user["_id"], user.get("name", "Agent"), "updated_redirect", f"Agent '{user.get('name')}' updated redirect for '{client_doc.get('business_name')}'")
    return {"message": "Redirect URL updated"}

@api_router.post("/agent/clients/{client_id}/team")
async def agent_upload_staff(client_id: str, file: UploadFile = File(...), name: str = "", role_title: str = "", request: Request = None):
    user = await get_current_user(request)
    if user["role"] != "sales_agent":
        raise HTTPException(status_code=403, detail="Not authorized")
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found or not yours")
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    storage_path = f"{APP_NAME}/staff/{client_id}/{uuid.uuid4()}.{ext}"
    data = await file.read()
    try:
        result = put_object(storage_path, data, file.content_type or "image/jpeg")
        stored_path = result.get("path", storage_path)
    except Exception as e:
        logger.error(f"Storage upload failed: {e}")
        stored_path = storage_path
    member_id = str(uuid.uuid4())
    member_doc = {"id": member_id, "client_id": client_id, "name": name, "role_title": role_title, "photo_path": stored_path, "original_filename": file.filename, "content_type": file.content_type, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.team_members.insert_one(member_doc)
    await log_audit(user["_id"], user.get("name", "Agent"), "uploaded_staff", f"Agent '{user.get('name')}' uploaded staff '{name}' for '{client_doc.get('business_name')}'")
    return {k: v for k, v in member_doc.items() if k != "_id"}

@api_router.put("/agent/clients/{client_id}/team/{member_id}")
async def agent_update_member(client_id: str, member_id: str, data: dict, request: Request = None):
    user = await get_current_user(request)
    if user["role"] != "sales_agent":
        raise HTTPException(status_code=403, detail="Not authorized")
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found or not yours")
    update = {}
    if "name" in data:
        update["name"] = data["name"]
    if "role_title" in data:
        update["role_title"] = data["role_title"]
    if update:
        await db.team_members.update_one({"id": member_id, "client_id": client_id}, {"$set": update})
    return {"message": "Updated"}

@api_router.delete("/agent/clients/{client_id}/team/{member_id}")
async def agent_delete_member(client_id: str, member_id: str, request: Request = None):
    user = await get_current_user(request)
    if user["role"] != "sales_agent":
        raise HTTPException(status_code=403, detail="Not authorized")
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found or not yours")
    await db.team_members.delete_one({"id": member_id, "client_id": client_id})
    await log_audit(user["_id"], user.get("name", "Agent"), "deleted_staff", f"Agent '{user.get('name')}' removed staff from '{client_doc.get('business_name')}'")
    return {"message": "Deleted"}

@api_router.get("/agent/clients/{client_id}/leaderboard")
async def agent_client_leaderboard(client_id: str, user: dict = Depends(require_role("sales_agent"))):
    client_doc = await db.clients.find_one({"id": client_id, "created_by": user["_id"]}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    leaderboard = []
    for m in members:
        count = await db.intent_logs.count_documents({"member_id": m["id"]})
        leaderboard.append({"id": m["id"], "name": m["name"], "role_title": m.get("role_title", ""), "photo_path": m.get("photo_path", ""), "intent_count": count})
    leaderboard.sort(key=lambda x: x["intent_count"], reverse=True)
    return leaderboard

@api_router.get("/agent/clients/{client_id}/test-redirect")
async def agent_test_redirect(client_id: str, user: dict = Depends(require_role("sales_agent"))):
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    return {"client": client_doc, "members": members, "standee_id": client_doc.get("standee_id", ""), "redirect_works": True}

# Keep legacy rep endpoints for backward compat
@api_router.get("/rep/clients")
async def rep_list_clients(request: Request):
    user = await get_current_user(request)
    if user["role"] not in ("sales_agent", "account_rep"):
        raise HTTPException(status_code=403, detail="Not authorized")
    clients = await db.clients.find({"created_by": user["_id"]}, {"_id": 0}).to_list(100)
    return clients

@api_router.post("/rep/wizard/create-client")
async def rep_create_client(req: AgentCreateClientRequest, background_tasks: BackgroundTasks, request: Request):
    user = await get_current_user(request)
    if user["role"] not in ("sales_agent", "account_rep"):
        raise HTTPException(status_code=403, detail="Not authorized")
    existing = await db.users.find_one({"email": req.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    client_id = str(uuid.uuid4())
    standee_id = f"A{str(uuid.uuid4())[:6].upper()}"
    user_doc = {"email": req.email.lower().strip(), "password_hash": hash_password(req.password), "name": req.contact_name, "role": "client", "client_id": client_id, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.users.insert_one(user_doc)
    client_doc = {"id": client_id, "business_name": req.business_name, "email": req.email.lower().strip(), "contact_name": req.contact_name, "category": req.category, "city": req.city, "standee_id": standee_id, "redirect_url": req.redirect_url or "", "outscraper_url": req.outscraper_url or "", "is_active": True, "created_by": user["_id"], "region": user.get("region", ""), "created_at": datetime.now(timezone.utc).isoformat()}
    await db.clients.insert_one(client_doc)
    await log_audit(user["_id"], user.get("name", "Agent"), "created_client", f"Agent '{user.get('name')}' created client '{req.business_name}' (Standee: {standee_id})")
    if req.outscraper_url:
        background_tasks.add_task(import_outscraper_reviews, client_id, req.outscraper_url)
    return {k: v for k, v in client_doc.items() if k != "_id"}

@api_router.post("/rep/wizard/upload-staff/{client_id}")
async def rep_upload_staff(client_id: str, file: UploadFile = File(...), name: str = "", role_title: str = "", request: Request = None):
    user = await get_current_user(request)
    if user["role"] not in ("sales_agent", "account_rep"):
        raise HTTPException(status_code=403, detail="Not authorized")
    client_doc = await db.clients.find_one({"id": client_id})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    storage_path = f"{APP_NAME}/staff/{client_id}/{uuid.uuid4()}.{ext}"
    data = await file.read()
    try:
        result = put_object(storage_path, data, file.content_type or "image/jpeg")
        stored_path = result.get("path", storage_path)
    except Exception as e:
        logger.error(f"Storage upload failed: {e}")
        stored_path = storage_path
    member_id = str(uuid.uuid4())
    member_doc = {"id": member_id, "client_id": client_id, "name": name, "role_title": role_title, "photo_path": stored_path, "original_filename": file.filename, "content_type": file.content_type, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.team_members.insert_one(member_doc)
    await log_audit(user["_id"], user.get("name", "Agent"), "uploaded_staff", f"Agent '{user.get('name')}' uploaded staff '{name}' for '{client_doc.get('business_name')}'")
    return {k: v for k, v in member_doc.items() if k != "_id"}

@api_router.get("/rep/wizard/test-redirect/{client_id}")
async def rep_test_redirect(client_id: str, request: Request):
    user = await get_current_user(request)
    if user["role"] not in ("sales_agent", "account_rep"):
        raise HTTPException(status_code=403, detail="Not authorized")
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    return {"client": client_doc, "members": members, "standee_id": client_doc.get("standee_id", ""), "redirect_works": True}

# Re-import endpoints
@api_router.post("/admin/clients/{client_id}/import-reviews")
async def admin_import_reviews(client_id: str, background_tasks: BackgroundTasks, user: dict = Depends(require_role("super_admin"))):
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    redirect_url = client_doc.get("redirect_url", "")
    if not redirect_url:
        raise HTTPException(status_code=400, detail="No redirect URL configured for this client")
    await db.reviews.delete_many({"client_id": client_id, "source": {"$in": ["Google Maps", "Booking.com"]}})
    background_tasks.add_task(import_outscraper_reviews, client_id, redirect_url)
    return {"message": "Review import started"}

@api_router.post("/client/import-reviews")
async def client_import_reviews(background_tasks: BackgroundTasks, user: dict = Depends(require_role("client"))):
    client_id = user.get("client_id")
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    redirect_url = client_doc.get("redirect_url", "")
    if not redirect_url:
        raise HTTPException(status_code=400, detail="No redirect URL configured")
    await db.reviews.delete_many({"client_id": client_id, "source": {"$in": ["Google Maps", "Booking.com"]}})
    background_tasks.add_task(import_outscraper_reviews, client_id, redirect_url)
    return {"message": "Review import started"}

# ===================== CLIENT ROUTES =====================

@api_router.get("/client/profile")
async def client_profile(user: dict = Depends(require_role("client"))):
    client_doc = await db.clients.find_one({"id": user.get("client_id")}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client profile not found")
    return client_doc

@api_router.get("/client/team")
async def client_team(user: dict = Depends(require_role("client"))):
    return await db.team_members.find({"client_id": user.get("client_id")}, {"_id": 0}).to_list(100)

@api_router.get("/client/leaderboard")
async def client_leaderboard(user: dict = Depends(require_role("client"))):
    client_id = user.get("client_id")
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    leaderboard = []
    for m in members:
        count = await db.intent_logs.count_documents({"member_id": m["id"]})
        leaderboard.append({"id": m["id"], "name": m["name"], "role_title": m.get("role_title", ""), "photo_path": m.get("photo_path", ""), "intent_count": count})
    leaderboard.sort(key=lambda x: x["intent_count"], reverse=True)
    return leaderboard

@api_router.get("/client/reviews")
async def client_reviews(user: dict = Depends(require_role("client"))):
    client_id = user.get("client_id")
    reviews = await db.reviews.find({"client_id": client_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    if not reviews:
        reviews = [
            # {"id": str(uuid.uuid4()), "client_id": client_id, "source": "Google Maps", "rating": 5, "text": "Amazing service! Dr. Smith was very professional and caring.", "author": "John D.", "created_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
            # {"id": str(uuid.uuid4()), "client_id": client_id, "source": "Google Maps", "rating": 4, "text": "Very clean facility and friendly staff. Highly recommend!", "author": "Sarah M.", "created_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
            # {"id": str(uuid.uuid4()), "client_id": client_id, "source": "2GIS", "rating": 5, "text": "Best experience I've had. The team is wonderful.", "author": "Alex K.", "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()},
            # {"id": str(uuid.uuid4()), "client_id": client_id, "source": "Yelp", "rating": 5, "text": "Efficient and painless. Will definitely come back.", "author": "Maria L.", "created_at": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()},
            # {"id": str(uuid.uuid4()), "client_id": client_id, "source": "Google Maps", "rating": 3, "text": "Good service but long wait times.", "author": "Chris P.", "created_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()},
        ]
    return reviews

@api_router.post("/client/team")
async def client_add_member(file: UploadFile = File(...), name: str = "", role_title: str = "", request: Request = None):
    user = await get_current_user(request)
    if user["role"] != "client":
        raise HTTPException(status_code=403, detail="Not authorized")
    client_id = user.get("client_id")
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    storage_path = f"{APP_NAME}/staff/{client_id}/{uuid.uuid4()}.{ext}"
    data = await file.read()
    try:
        result = put_object(storage_path, data, file.content_type or "image/jpeg")
        stored_path = result.get("path", storage_path)
    except Exception as e:
        logger.error(f"Storage upload failed: {e}")
        stored_path = storage_path
    member_id = str(uuid.uuid4())
    member_doc = {"id": member_id, "client_id": client_id, "name": name, "role_title": role_title, "photo_path": stored_path, "original_filename": file.filename, "content_type": file.content_type, "created_at": datetime.now(timezone.utc).isoformat()}
    await db.team_members.insert_one(member_doc)
    return {k: v for k, v in member_doc.items() if k != "_id"}

# ===================== PUBLIC NFC/REDIRECT ROUTES =====================

@api_router.get("/s/{standee_id}")
async def nfc_redirect(standee_id: str):
    client_doc = await db.clients.find_one({"standee_id": standee_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Invalid NFC link")
    if not client_doc.get("is_active", True):
        return {"redirect": "suspended", "message": "Service Suspended", "client_id": client_doc["id"]}
    return {"redirect": "portal", "client_id": client_doc["id"], "business_name": client_doc["business_name"]}

@api_router.get("/portal/{client_id}")
async def get_portal_data(client_id: str):
    client_doc = await db.clients.find_one({"id": client_id}, {"_id": 0})
    if not client_doc:
        raise HTTPException(status_code=404, detail="Client not found")
    if not client_doc.get("is_active", True):
        return {"suspended": True, "business_name": client_doc["business_name"]}
    members = await db.team_members.find({"client_id": client_id}, {"_id": 0}).to_list(100)
    return {"business_name": client_doc["business_name"], "category": client_doc.get("category", ""), "members": members, "redirect_url": client_doc.get("redirect_url", ""), "suspended": False}

@api_router.post("/intent/log")
async def log_intent(data: dict):
    intent_doc = {"id": str(uuid.uuid4()), "client_id": data.get("client_id"), "member_id": data.get("member_id"), "member_name": data.get("member_name", ""), "timestamp": datetime.now(timezone.utc).isoformat(), "status": "intent"}
    await db.intent_logs.insert_one(intent_doc)
    return {k: v for k, v in intent_doc.items() if k != "_id"}

# ===================== FILE SERVING =====================

@api_router.get("/files/{path:path}")
async def serve_file(path: str, auth: str = Query(None)):
    try:
        data, content_type = get_object(path)
        return Response(content=data, media_type=content_type)
    except Exception as e:
        logger.error(f"File serve error: {e}")
        raise HTTPException(status_code=404, detail="File not found")

# ===================== AI ROUTES =====================

CATEGORY_TAGS = {
    "Medical": ["Professional", "Caring", "Thorough", "Painless", "Knowledgeable"],
    "Dental": ["Gentle", "Professional", "Painless", "Clean", "Efficient"],
    "Legal": ["Professional", "Knowledgeable", "Responsive", "Trustworthy", "Thorough"],
    "Restaurant": ["Delicious", "Friendly", "Quick Service", "Great Ambiance", "Fresh"],
    "Salon": ["Creative", "Professional", "Relaxing", "Skilled", "Friendly"],
    "General": ["Professional", "Efficient", "Friendly", "Helpful", "Excellent"],
}

@api_router.get("/ai/tags/{category}")
async def get_category_tags(category: str):
    return {"tags": CATEGORY_TAGS.get(category, CATEGORY_TAGS["General"])}

@api_router.post("/ai/magic-write")
async def magic_write(req: MagicWriteRequest):
    try:
        from google import genai
        from google.genai import types
        gemini = genai.Client(api_key=GEMINI_API_KEY)
        prompt = f"Write a natural 2-sentence positive Google review mentioning {req.member_name}. The review should touch on these qualities: {', '.join(req.tags)}. Category: {req.category}. Sound authentic and human."
        result = await gemini.aio.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are a helpful review writer. Generate short, natural-sounding Google reviews. Keep it to 2 sentences maximum. Sound like a real customer, not robotic. Do not use quotation marks around the review.",
            ),
        )
        return {"review_draft": result.text, "member_name": req.member_name, "tags": req.tags}
    except Exception as e:
        logger.error(f"AI Magic Write error: {e}")
        tags_str = " and ".join(req.tags[:2]) if req.tags else "professional"
        return {"review_draft": f"Had a wonderful experience with {req.member_name}. They were incredibly {tags_str} throughout the entire visit.", "member_name": req.member_name, "tags": req.tags}

@api_router.post("/ai/response-assist")
async def response_assist(req: ResponseAssistRequest):
    try:
        from google import genai
        from google.genai import types
        gemini = genai.Client(api_key=GEMINI_API_KEY)
        sentiment = "positive" if req.rating >= 4 else "mixed" if req.rating == 3 else "negative"
        prompt = f"Write a professional business response to this {sentiment} {req.rating}-star review: \"{req.review_text}\". Category: {req.category}. Remember: do NOT mention the reviewer's name or any specific services."
        result = await gemini.aio.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are a professional business response writer. Write brief, warm responses to customer reviews. IMPORTANT: Never repeat the reviewer's name or any specific service/medical details mentioned in the review to protect privacy (HIPAA/GDPR). Keep responses to 2-3 sentences.",
            ),
        )
        return {"response_draft": result.text}
    except Exception as e:
        logger.error(f"AI Response Assist error: {e}")
        return {"response_draft": "Thank you for taking the time to share your feedback. We truly value your experience and are committed to providing the best service possible."}

# ===================== STARTUP =====================

@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.clients.create_index("id", unique=True)
    await db.clients.create_index("standee_id", unique=True)
    await db.clients.create_index("created_by")
    await db.team_members.create_index("client_id")
    await db.intent_logs.create_index("client_id")
    await db.intent_logs.create_index("member_id")
    await db.regions.create_index("name", unique=True)
    # Migrate account_rep -> sales_agent
    await db.users.update_many({"role": "account_rep"}, {"$set": {"role": "sales_agent"}})
    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@tellvy.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "TellvyAdmin123!")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        await db.users.insert_one({"email": admin_email, "password_hash": hash_password(admin_password), "name": "Super Admin", "role": "super_admin", "created_at": datetime.now(timezone.utc).isoformat()})
        logger.info(f"Admin seeded: {admin_email}")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
    # Init storage
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error(f"Storage init failed: {e}")
    # Write test credentials
    os.makedirs("/app/memory", exist_ok=True)
    with open("/app/memory/test_credentials.md", "w") as f:
        f.write(f"# Test Credentials\n\n## Super Admin\n- Email: {admin_email}\n- Password: {admin_password}\n- Role: super_admin\n\n## Roles: super_admin, regional_manager, sales_agent, client\n\n## Key Endpoints\n- POST /api/auth/login\n- POST /api/auth/register\n- GET /api/auth/me\n- POST /api/admin/staff (create sales_agent or regional_manager)\n- GET /api/admin/regions\n- POST /api/admin/regions\n- GET /api/agent/clients\n- POST /api/agent/clients\n- GET /api/regional/stats\n- GET /api/regional/agents\n- GET /api/regional/clients\n")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
