from zapv2 import ZAPv2

zap = ZAPv2(
    # Proxies é onde está rodando o ZAP.
    proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
    apikey="12345",
)

# JSON da API que será analisada. Esse link é uma conveniência fornecida pelo Docker. Futuramente será necessário
# alterar para ser mais flexível.
api_url = "http://host.docker.internal:8000/openapi.json"
zap.openapi.import_url(api_url)

# Iniciar o Active Scan nos endpoints descobertos
print("Iniciando varredura de vulnerabilidades na API...")
scan_id = zap.ascan.scan(api_url)

# Pegar os resultados
print("Alertas encontrados:", zap.core.alerts())

print("Gerando relatório HTML...")
# Baixa o conteúdo HTML do relatório gerado pelo ZAP
relatorio_html = zap.core.htmlreport()

# Salva em um arquivo
with open("relatorio_seguranca_api.html", "w", encoding="utf-8") as f:
    f.write(relatorio_html)
