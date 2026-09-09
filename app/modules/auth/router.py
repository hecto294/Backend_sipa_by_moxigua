from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    verify_password,
    create_access_token,
    get_current_user,
    get_password_hash,
)
from app.models import Usuario, Rol
from app.modules.auth import schemas, services
from app.modules.auth.crud import get_usuario_by_email, get_usuario_by_id, update_password

limiter = Limiter(key_func=get_remote_address)
router = APIRouter(prefix="/auth", tags=["auth"])


# ============================================================
# LOGIN
# ============================================================

@router.post("/login", response_model=schemas.TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, credentials: schemas.LoginRequest, db: Session = Depends(get_db)):
    """Autentica al usuario y retorna un token JWT"""
    usuario = get_usuario_by_email(db, credentials.email)
    if not usuario or not usuario.is_active or not verify_password(credentials.password, usuario.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )

    access_token = create_access_token(
        data={
            "sub": str(usuario.id),
            "rol": usuario.rol_id,
            "nombre": f"{usuario.nombre} {usuario.apellido}"
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "rol_id": usuario.rol_id,
        "usuario_id": usuario.id,
        "nombre": f"{usuario.nombre} {usuario.apellido}",
    }


# ============================================================
# REGISTRO
# ============================================================

@router.post("/register", response_model=schemas.UserInfoResponse, status_code=status.HTTP_201_CREATED)
def register(
    data: schemas.RegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registra un nuevo usuario en el sistema.
    """
    # Verificar si el email ya existe
    existing = db.query(Usuario).filter(Usuario.email == data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El email ya está registrado"
        )
    
    # Verificar documento único
    if data.documento_identidad:
        existing_doc = db.query(Usuario).filter(
            Usuario.documento_identidad == data.documento_identidad
        ).first()
        if existing_doc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El documento ya está registrado"
            )
    
    # Crear usuario
    new_user = Usuario(
        nombre=data.nombre,
        apellido=data.apellido,
        email=data.email,
        password_hash=get_password_hash(data.password),
        tipo_documento=data.tipo_documento,
        documento_identidad=data.documento_identidad,
        telefono=data.telefono,
        rol_id=data.rol_id if data.rol_id else 4
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Obtener nombre del rol
    rol = db.query(Rol).filter(Rol.id == new_user.rol_id).first()
    
    return schemas.UserInfoResponse(
        id=new_user.id,
        nombre=new_user.nombre,
        apellido=new_user.apellido,
        email=new_user.email,
        rol_id=new_user.rol_id,
        rol_nombre=rol.nombre if rol else None,
        tipo_documento=new_user.tipo_documento,
        documento_identidad=new_user.documento_identidad,
        telefono=new_user.telefono,
        is_active=new_user.is_active
    )


# ============================================================
# OBTENER USUARIO ACTUAL
# ============================================================

@router.get("/me", response_model=schemas.UsuarioMe)
def obtener_usuario_actual(current_user: Usuario = Depends(get_current_user)):
    """Retorna la información del usuario autenticado"""
    return current_user


# ============================================================
# CAMBIAR CONTRASEÑA
# ============================================================

@router.post("/cambiar-password")
@limiter.limit("5/minute")
def cambiar_password(
    request: Request,
    datos: schemas.PasswordChange,
    db: Session = Depends(get_db),
    current_user: Usuario = Depends(get_current_user)
):
    """Permite al usuario autenticado cambiar su contraseña"""
    if not verify_password(datos.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="La contraseña actual no es correcta")

    new_hash = get_password_hash(datos.new_password)
    update_password(db, current_user, new_hash)
    return {"mensaje": "Contraseña actualizada correctamente"}


# ============================================================
# RECUPERAR CONTRASEÑA
# ============================================================

@router.post("/recuperar-password")
@limiter.limit("3/minute")
def solicitar_recuperacion(
    request: Request,
    datos: schemas.PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """Solicita un enlace de recuperación de contraseña"""
    usuario = get_usuario_by_email(db, datos.email)
    if usuario and usuario.is_active:
        expire = datetime.utcnow() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        token = jwt.encode(
            {
                "sub": str(usuario.id),
                "type": "password_reset",
                "iat": datetime.utcnow(),
                "exp": expire,
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        reset_link = f"{settings.FRONTEND_URL}/restablecer-password?token={token}"
        try:
            services.send_password_reset_email(usuario.email, reset_link)
        except Exception:
            raise HTTPException(status_code=500, detail="Error al enviar el correo")

    return {"mensaje": "Si el correo existe, se ha enviado un enlace de recuperación"}


# ============================================================
# RESTABLECER CONTRASEÑA
# ============================================================

@router.post("/restablecer-password")
@limiter.limit("5/minute")
def confirmar_recuperacion(
    request: Request,
    datos: schemas.PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Restablece la contraseña usando un token de recuperación válido"""
    try:
        payload = jwt.decode(
            datos.token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        if payload.get("type") != "password_reset":
            raise JWTError("Token no es de recuperación")
        usuario_id = int(payload.get("sub"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=400, detail="Token inválido o expirado")

    usuario = get_usuario_by_id(db, usuario_id)
    if not usuario or not usuario.is_active:
        raise HTTPException(status_code=400, detail="Usuario no encontrado o inactivo")

    new_hash = get_password_hash(datos.new_password)
    update_password(db, usuario, new_hash)
    return {"mensaje": "Contraseña restablecida correctamente"}