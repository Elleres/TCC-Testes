import time

from zapv2 import ZAPv2

# --- CONFIGURAÇÕES ---
ZAP_PROXY = "http://127.0.0.1:8080"
API_KEY = "12345"
TARGET_API = "http://host.docker.internal:8000"
OPENAPI_URL = f"{TARGET_API}/openapi.json"
TOKEN_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDdXB1YWN1TWFzdGVyIiwiZXhwIjoxNzY2NTQ5ODcyLjQ0MzIyN30.GlAoU3O1psa17E2kOqKlRr5TQcbZJs-BgxbMbzNcZ0g"
# --- 1. CONEXÃO ---
print(f"Conectando ao ZAP em {ZAP_PROXY}...")
zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY}, apikey=API_KEY)

# --- 2. AUTENTICAÇÃO ---
print("Configurando Autenticação...")
zap.replacer.remove_rule(description="AuthHeader")
zap.replacer.add_rule(
    description="AuthHeader",
    enabled=True,
    matchtype="REQ_HEADER",
    matchregex=False,
    matchstring="Authorization",
    replacement=f"Bearer {TOKEN_JWT}",
)

try:
    zap.openapi.import_url(OPENAPI_URL)
except Exception as e:
    print(f"Aviso na importação: {e}")

# 1. Desativa todos os scanners para limpar o ruído
zap.ascan.disable_all_scanners()

# 2. Ativa apenas os 5 IDs mais relevantes para APIs:
# 40018: SQL Injection (O mais crítico para bancos de dados)
# 90020: Remote OS Command Injection (Execução de comandos no servidor)
# 6: Path Traversal (Acesso indevido a arquivos do sistema)
# 40012: Reflected XSS (Embora comum em web, afeta APIs que retornam HTML/JSON mal manipulado)
# 90019: Server Side Request Forgery - SSRF (Crítico para APIs que fazem requisições externas)
IDS_ELITE = "40018,90020,6,40012,90019,40026"
zap.ascan.enable_scanners(IDS_ELITE)

NOME_POLITICA = "Estavel"

zap.ascan.add_scan_policy(
    scanpolicyname=NOME_POLITICA, alertthreshold="Low", attackstrength="High"
)

# --- 5. EXECUÇÃO ---
print(f"Iniciando Scan Estável em {TARGET_API}...")
scan_id = zap.ascan.scan(
    url=TARGET_API, recurse=True, inscopeonly=False, scanpolicyname=NOME_POLITICA
)

print(f"Scan iniciado (ID: {scan_id}). Monitorando...")

# --- 6. LOOP DE ESPERA COM TRATAMENTO DE ERRO ---
erros_consecutivos = 0
while True:
    try:
        # Pega o status como texto primeiro
        status_raw = zap.ascan.status(scan_id)

        # Verifica se o scan sumiu (sinal de crash do ZAP)
        if str(status_raw).lower() == "does_not_exist":
            print(
                "\n[ERRO CRÍTICO] O ZAP reiniciou e perdeu o scan. (Crash confirmado)"
            )
            break

        progresso = int(status_raw)
        erros_consecutivos = 0  # Sucesso, zera erros

        print(f"   Progresso: {progresso}%")

        if progresso >= 100:
            break

        time.sleep(5)

    except ValueError:
        print(f"   [!] Erro de leitura de status: {status_raw}")
        time.sleep(5)
    except Exception as e:
        erros_consecutivos += 1
        print(f"   [!] Falha de conexão ({erros_consecutivos}/5): {e}")
        if erros_consecutivos >= 5:
            print("Perda total de comunicação.")
            break
        time.sleep(10)

# --- 7. RELATÓRIO ---
print("\nGerando relatório...")
# Tenta pegar alertas mesmo se tiver crashado (pode vir vazio se o ZAP reiniciou)
alerts = zap.core.alerts(baseurl=TARGET_API)
print(f"Alertas recuperados: {len(alerts)}")

with open("relatorio_final.html", "w", encoding="utf-8") as f:
    f.write(zap.core.htmlreport())

print("Relatório salvo em 'relatorio_final.html'")
