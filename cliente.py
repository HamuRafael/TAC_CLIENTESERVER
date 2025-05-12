import requests, json

# Dados para autenticação
dados = {
    "usuario": "usuario1",
    "senha": "senha123"
}

# Autenticação e obtenção do token JWT
resposta = requests.post("http://localhost:8000/login", json=dados)

if resposta.status_code == 200:
    token = resposta.json()["token"]
    print("Token recebido:", token)

    # Requisição com token JWT
    headers = {"Authorization": f"Bearer {token}"}
    resposta = requests.get("http://localhost:8000/dados", headers=headers)

    if resposta.status_code == 200:
        print("Resposta protegida:", resposta.json())
    else:
        print("Erro ao acessar recurso:", resposta.text)
else:
    print("Falha na autenticação.")
