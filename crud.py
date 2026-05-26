from sqlalchemy.orm import Session
from models import User, UserCreate, RefreshToken
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone
import bcrypt  # <-- On utilise bcrypt directement ici

# Fonctions magiques pour hacher et vérifier les mots de passe proprement
def hash_password(password: str) -> str:
    # Génère un sel et hache le mot de passe, puis le convertit en texte (utf-8)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# --- CRÉATION DE L'UTILISATEUR ---
def create_user(db: Session, user: UserCreate):
    if get_user_by_username(db, user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nom d'utilisateur déjà pris"
        )
    if get_user_by_email(db, user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email déjà utilisé"
        )
    
    # On utilise notre nouvelle fonction de hachage
    hashed_password = hash_password(user.password)
    
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

# --- DURCISSEMENT : TIMING ATTACK ---
# On génère un faux hash propre via bcrypt qui ne buggera pas
DUMMY_HASH = hash_password("dummy_password")

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        # On simule la vérification pour consommer le même temps CPU
        verify_password(password, DUMMY_HASH)
        return False
    
    # On utilise notre nouvelle fonction de vérification
    if not verify_password(password, user.hashed_password):
        return False
    return user

# --- GESTION DES REFRESH TOKENS (Le reste de ton code inchangé) ---
def save_refresh_token(db: Session, user_id: int, token: str):
    db_token = RefreshToken(
        token=token,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.add(db_token)
    db.commit()

def invalidate_refresh_token(db: Session, token: str):
    db.query(RefreshToken).filter(RefreshToken.token == token).update({"is_revoked": True})
    db.commit()

def is_refresh_token_valid(db: Session, token: str) -> bool:
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token == token,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > datetime.now(timezone.utc)
    ).first()
    return db_token is not None