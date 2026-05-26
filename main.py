from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from sqlalchemy.orm import Session
from db import SessionLocal, engine, Base
from models import User, UserRoles, UserCreate, UserOut
import crud
from tokens import decode_token, create_access_token, create_refresh_token
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# --- CONFIGURATION DU LIMIT DE REQUÊTES (Rate-Limiting) ---
limiter = Limiter(key_func=get_remote_address)

# docs_url=None désactive l'affichage standard qui causait la page blanche
app = FastAPI(title="API Authentification Sécurisée", docs_url=None)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- CRÉATION DE LA BASE DE DONNÉES LOCALES ---
Base.metadata.create_all(bind=engine)

# Dépendance pour gérer la session de la base de données
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- INTERFACE DE DOCUMENTATION 100% AUTONOME (Sans fichier à télécharger) ---
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        oauth2_redirect_url="/docs/oauth2-redirect", 
        # Chargement dynamique via CDN alternatif pour éviter les blocages locaux
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )

# --- ROUTE 1 : INSCRIPTION D'UN UTILISATEUR ---
@app.post("/users/", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register_user(user: UserCreate, request: Request, db: Session = Depends(get_db)):
    return crud.create_user(db=db, user=user)

# --- ROUTE 2 : CONNEXION & GÉNÉRATION DES COOKIES (HttpOnly Tokens) ---
@app.post("/token")
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Génération des tokens sécurisés
    access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
    refresh_token = create_refresh_token(data={"sub": user.username})
    
    # Sauvegarde du refresh token dans la BDD
    crud.save_refresh_token(db, user_id=user.id, token=refresh_token)
    
    # Injection sécurisée des tokens directement dans les cookies du navigateur
    response = JSONResponse(content={"message": "Connexion réussie"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=False,  # Laisser à False en local (HTTP), passer à True en production (HTTPS)
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax"
    )
    return response

# --- FONCTION DE VÉRIFICATION DU COOKIE D'AUTHENTIFICATION ---
def get_current_user(request: Request, db: Session = Depends(get_db)):
    token_cookie = request.cookies.get("access_token")
    if not token_cookie or not token_cookie.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié (Cookie manquant ou invalide)"
        )
    
    token = token_cookie.split(" ")[1]
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expirée ou Token altéré"
        )
    
    username: str = payload.get("sub")
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur introuvable"
        )
    return user

# --- ROUTE 3 : RÉCUPÉRER MON PROFIL (Sécurisé par cookie) ---
@app.get("/users/me/", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# --- ROUTE 4 : DÉCONNEXION (Suppression des Cookies) ---
@app.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        crud.invalidate_refresh_token(db, token=refresh_token)
        
    response = JSONResponse(content={"message": "Déconnexion réussie"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response