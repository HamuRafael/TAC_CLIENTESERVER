import requests
import json
import time

# Função para autenticar e obter o token JWT
def autenticar(usuario, senha):
    dados = {
        "usuario": usuario,
        "senha": senha
    }
    resposta = requests.post("http://localhost:8000/login", json=dados)
    if resposta.status_code == 200:
        token = resposta.json()["token"]
        print("[CLIENTE] Token recebido:", token)
        return token
    else:
        print("[CLIENTE] Falha na autenticação:", resposta.text)
        return None

# Função para acessar recurso protegido com determinado token
def acessar_dados(token=None, descricao="Acesso"):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resposta = requests.get("http://localhost:8000/dados", headers=headers)
    print(f"[CLIENTE] {descricao}: {resposta.text}")

def main():
    print("=== Testes Cliente API ===")
    usuario = "usuario1"
    senha = "senha123"

    # 1. Autenticação normal
    token = autenticar(usuario, senha)
    if not token:
        return

    # 2. Acesso normal com token válido
    acessar_dados(token, "Acesso normal (token válido)")

    # 3. Acesso com token modificado (assinatura inválida)
    # Modificamos o último caractere do token para simular corrupção/ataque
    token_mod = token[:-1] + ("A" if token[-1] != "A" else "B")
    acessar_dados(token_mod, "Acesso com token modificado (assinatura inválida)")

    # 4. Acesso sem token (usuário não autenticado)
    acessar_dados(None, "Acesso sem token (não autenticado)")

    # 5. Acesso com token expirado (você precisa definir expiração curta no servidor para testar)
    print("[CLIENTE] Aguarde alguns segundos para o token expirar...")
    time.sleep(6)  # Ajuste este tempo de acordo com a expiração do servidor!
    acessar_dados(token, "Acesso com token expirado")

if __name__ == "__main__":
    main()
