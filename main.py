from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

app = FastAPI()

# Chave secreta para assinar e verificar os tokens JWT
CHAVE_SECRETA = "chave_secreta"

# Classe de Usuário
class Login:
    def __init__(self, nome_de_usuario: str, senha: str, papel: str):
        self.nome_de_usuario = nome_de_usuario
        self.senha = senha
        self.papel = papel

# Lista para armazenar os usuários
usuarios = []

# Middleware para autenticação com JWT
esquema_autenticacao = HTTPBearer()

async def obter_usuario_atual(credentials: HTTPAuthorizationCredentials = Depends(esquema_autenticacao)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, CHAVE_SECRETA, algorithms=["HS256"])
        nome_de_usuario: str = payload.get("sub")
        usuario = next((usuario for usuario in usuarios if usuario.nome_de_usuario == nome_de_usuario), None)
        if not usuario:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
        return usuario
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except (jwt.DecodeError, jwt.InvalidTokenError):
        raise HTTPException(status_code=401, detail="Token inválido")

@app.post("/usuarios")
def criar_usuario(nome_de_usuario: str, senha: str):
    # Verificar se o usuário já existe na lista
    usuario_existente = next((usuario for usuario in usuarios if usuario.nome_de_usuario == nome_de_usuario), None)
    if usuario_existente:
        raise HTTPException(status_code=400, detail="Nome de usuário já existe")
    
    # Criar novo usuário e adicioná-lo à lista
    novo_usuario = Login(nome_de_usuario=nome_de_usuario, senha=senha, papel="admin")
    usuarios.append(novo_usuario)
    
    return {"message": "Usuário criado com sucesso"}

@app.post("/login")
def login(nome_de_usuario: str, senha: str):
    usuario = next((usuario for usuario in usuarios if usuario.nome_de_usuario == nome_de_usuario), None)
    if not usuario or usuario.senha != senha:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = jwt.encode({"sub": usuario.nome_de_usuario, "role": usuario.papel}, CHAVE_SECRETA, algorithm="HS256")
    return {"token": token}