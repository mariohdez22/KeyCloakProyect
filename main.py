from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from keycloak import KeycloakOpenID, KeycloakAdmin
from pydantic import BaseModel, EmailStr
import requests

app = FastAPI()

KEYCLOAK_SERVER_URL = "http://localhost:8080/"
KEYCLOAK_REALM = "HerzRealm"
KEYCLOAK_CLIENT_ID = "herz_cliente"
KEYCLOAK_CLIENT_SECRET = "LroVXYFJbeJBn4RCII0xex7Mrf3ZUh7R"
ALGORITHM = "RS256"

KEYCLOAK_USERNAME = "theslayeralpha"
KEYCLOAK_PASSWORD = "dragonXD123"

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    client_secret_key=KEYCLOAK_CLIENT_SECRET
)

token = keycloak_openid.token("theslayeralpha", "dragonXD123")
access_token = token["access_token"]

print("Access Token:")
print(access_token)

#-----------------------------------------------------------------------------------------------------------------------

bearer_scheme = HTTPBearer()

# Obtener la configuración del servidor
config_well_known = keycloak_openid.well_known()

# Obtener la clave pública
public_key = requests.get(
    f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
).json()

def get_public_key():
    # Obtener la clave pública en formato PEM
    public_key = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    return public_key

def decode_token(token: str):
    try:
        public_key = get_public_key()
        options = {"verify_aud": False}
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            options=options
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    payload = decode_token(token)
    return payload  # Puedes ajustar esto para devolver un objeto de usuario personalizado

#-----------------------------------------------------------------------------------------------------------------------

@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": "Esta es una ruta protegida", "user": current_user}

@app.get("/public")
async def public_route():
    return {"message": "Esta es una ruta pública"}

#-----------------------------------------------------------------------------------------------------------------------

keycloak_admin = KeycloakAdmin(
    server_url=KEYCLOAK_SERVER_URL,
    username=KEYCLOAK_USERNAME,
    password=KEYCLOAK_PASSWORD,
    realm_name=KEYCLOAK_REALM,
    client_id='admin-cli',
    verify=True
)

#-----------------------------------------------------------------------------------------------------------------------

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    password: str

def create_user(
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        password: str
):
    # Crear el usuario en Keycloak
    user_id = keycloak_admin.create_user({
        "username": username,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": True,
        "credentials": [{"value": password, "type": "password", "temporary": False}]
    })

    # Verificar si el usuario fue creado exitosamente
    if isinstance(user_id, dict) and 'error' in user_id:
        raise Exception(f"Error al crear el usuario: {user_id['errorMessage']}")

    #keycloak_admin.send_verify_email(user_id)

    return user_id

#-----------------------------------------------------------------------------------------------------------------------

@app.post("/register")
async def register_user(user: UserCreate):
    iduser = create_user(
        user.username,
        user.email,
        user.first_name,
        user.last_name,
        user.password
    )

    return {
        "message": "Usuario creado exitosamente",
        "ID User": iduser
    }

#-----------------------------------------------------------------------------------------------------------------------

class PasswordResetRequest(BaseModel):
    email: EmailStr

#-----------------------------------------------------------------------------------------------------------------------

def send_reset_password_email(email: str):
    # Obtener el Keycloak OpenID client
    keycloak_openid = KeycloakOpenID(
        server_url=KEYCLOAK_SERVER_URL,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM,
        client_secret_key=KEYCLOAK_CLIENT_SECRET,
        verify=True
    )

    # Construir la URL de acción
    reset_password_url = f"{KEYCLOAK_SERVER_URL}realms/{KEYCLOAK_REALM}/login-actions/reset-credentials"

    # Buscar al usuario por correo electrónico
    users = keycloak_admin.get_users(query={"email": email})
    if not users:
        raise Exception("Usuario no encontrado")

    user_id = users[0]['id']

    # Generar el enlace de restablecimiento de contraseña
    params = {
        "client_id": KEYCLOAK_CLIENT_ID,
        "tab_id": "password-reset",
        "response_type": "code",
        "user_id": user_id,
        "redirect_uri": "http://localhost:8000/password-reset-confirm"  # Cambia esto a tu URL de confirmación
    }

    # Enviar el correo electrónico
    keycloak_admin.send_update_account(user_id, ['UPDATE_PASSWORD'])

    return True


@app.post("/password-reset")
async def password_reset_request(data: PasswordResetRequest):
    try:
        send_reset_password_email(data.email)
        return {"message": "Se ha enviado un correo electrónico para restablecer su contraseña"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

