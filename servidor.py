from http.server import HTTPServer, BaseHTTPRequestHandler
import json, bcrypt, jwt, datetime
import sys

# Menu interativo para escolher o modo
print("Escolha o modo de assinatura do JWT:")
print("1 - HMAC (HS256)")
print("2 - RSA (PS256)")
opcao = input("Digite 1 ou 2 e pressione Enter: ")

if opcao == "1":
    MODO = "HMAC"
    segredo_hmac = "123321"
    print("\n[MODO] HMAC selecionado (HS256)")
elif opcao == "2":
    MODO = "RSA"
    from cryptography.hazmat.primitives import serialization
    try:
        with open("chaves/private.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        with open("chaves/public.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        print("\n[MODO] RSA selecionado (PS256)")
    except Exception as e:
        print("Erro ao carregar as chaves RSA:", e)
        sys.exit(1)
else:
    print("Opção inválida. Execute novamente e digite 1 ou 2.")
    sys.exit(1)

usuario_db = {
    "usuario1": bcrypt.hashpw("senha123".encode(), bcrypt.gensalt())
}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers['Content-Length'])
            body = json.loads(self.rfile.read(length))
            user, senha = body["usuario"], body["senha"]

            if user in usuario_db and bcrypt.checkpw(senha.encode(), usuario_db[user]):
                payload = {
                    "usuario": user,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
                }
                if MODO == "RSA":
                    token = jwt.encode(payload, private_key, algorithm="PS256")
                elif MODO == "HMAC":
                    token = jwt.encode(payload, segredo_hmac, algorithm="HS256")

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
                    if MODO == "RSA":
                        jwt.decode(token, public_key, algorithms=["PS256"])
                    elif MODO == "HMAC":
                        jwt.decode(token, segredo_hmac, algorithms=["HS256"])
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
    print(f"\nServidor rodando em http://localhost:8000 - MODO: {MODO}")
    server.serve_forever()
