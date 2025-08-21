# utils/firebase_auth.py
import os
import requests
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv
from typing import Optional, Dict

load_dotenv()

API_KEY = os.getenv("FIREBASE_API_KEY")
SERVICE_ACCOUNT = os.getenv("FIREBASE_SERVICE_ACCOUNT", "firebase_service_account.json")
PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")

# init firebase admin (idempotent)
def init_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate(SERVICE_ACCOUNT)
        firebase_admin.initialize_app(cred, {'projectId': PROJECT_ID})
    # returns firestore client
    return firestore.client()

# Sign up (email/password) via Firebase REST API
def signup_with_email(email: str, password: str, display_name: Optional[str] = "") -> Dict:
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    data = r.json()
    # Create profile doc in Firestore
    db = init_firebase()
    uid = data["localId"]
    db.collection("users").document(uid).set({
        "email": email,
        "displayName": display_name or "",
        "theme": "dark",
        "createdAt": firestore.SERVER_TIMESTAMP
    }, merge=True)
    return data

# Sign in (email/password) via Firebase REST API
def signin_with_email(email: str, password: str) -> Dict:
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    r.raise_for_status()
    return r.json()

# Verify idToken server-side and return decoded token
def verify_id_token(id_token: str) -> Optional[Dict]:
    try:
        init_firebase()
        decoded = auth.verify_id_token(id_token)
        return decoded  # contains uid, email, etc.
    except Exception:
        return None

# Firestore helpers: get and write user profile
def get_user_profile(uid: str) -> Optional[Dict]:
    db = init_firebase()
    doc = db.collection("users").document(uid).get()
    return doc.to_dict() if doc.exists else None

def save_user_profile(uid: str, data: Dict):
    db = init_firebase()
    db.collection("users").document(uid).set(data, merge=True)
