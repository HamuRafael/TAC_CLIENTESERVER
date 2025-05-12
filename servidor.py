from http.server import HTTPServer, BaseHTTPRequestHandler
import json, bcrypt, jwt, datetime
from cryptography.hazmat.primitives import serialization

# Usuário exemplo (senha hash armazenada com bcrypt)
usuario_db = {
    "usuario1": bcrypt.hashpw("senha123".encode(), bcrypt.gensalt())
}

# Carrega a chave privada RSA
with open("chaves/private.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Carrega chave pública RSA
with open("chaves/public.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

class Handler(BaseHTTPRequestHandler):
    
    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers['Content-Length'])
            body = json.loads(self.rfile.read(length))
            user, senha = body["usuario"], body["senha"]

            # Valida usuário
            if user in usuario_db and bcrypt.checkpw(senha.encode(), usuario_db[user]):
                payload = {
                    "usuario": user,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
                }

                # Token JWT com RSA-PSS
                token = jwt.encode(payload, private_key, algorithm="PS256")

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"token": token}).encode())
            else:
                self.send_response(401)
                self.end_headers()

    def do_GET(self):
        if self.path == "/dados":
            auth_header = self.headers.get("Authorization")
            if auth_header:
                token = auth_header.split(" ")[1]
                try:
                    # Valida token JWT
                    jwt.decode(token, public_key, algorithms=["PS256"])
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps({"dados": "Segredo revelado!"}).encode())
                except jwt.ExpiredSignatureError:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'Token expirado')
                except jwt.InvalidTokenError:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'Token invalido')
            else:
                self.send_response(401)
                self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8000), Handler)
    print("Servidor rodando em http://localhost:8000")
    server.serve_forever()
