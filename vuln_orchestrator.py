
import json
import subprocess
import logging
import sys

# Debug por camadas: Log configurado para rastrear a orquestração
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("VulnOrchestrator")

def run_nuclei(target_url: str, has_waf: bool):
    """Camada de Lógica/Rede: Executa o Nuclei de forma programática e segura."""
    rate_limit = "10" if has_waf else "50"
    output_file = f"vuln_{target_url.replace('https://', '').replace('/', '')}.json"
    
    # Argumentos estruturados em lista evitam Command Injection
    cmd = [
        "nuclei",
        "-target", target_url,
        "-tags", "misconfig,exposure", # Foco em postura defensiva (sem exploits destrutivos)
        "-rate-limit", rate_limit,     # Adaptação ao WAF
        "-json-export", output_file
    ]
    
    logger.info(f"Iniciando scan no alvo: {target_url} (Rate-limit: {rate_limit}/s)")
    try:
        # Camada de Sistema: Executa o binário do Nuclei no host
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"Scan concluído. Resultados salvos em: {output_file}")
    except FileNotFoundError:
        logger.error("[ERRO de Dependência] Binário 'nuclei' não encontrado no PATH.")
        logger.info("Instale com: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    except subprocess.CalledProcessError as e:
        logger.error(f"[ERRO] Falha no motor de scan: {e.stderr}")

def main(json_file: str):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Erro ao ler arquivo de input: {e}")
        return

    # Pipeline: Filtra apenas hosts válidos para evitar gasto computacional em erros 404/500
    valid_targets = [item for item in data if item.get('status_code') == 200]
    
    if not valid_targets:
        logger.info("Nenhum alvo acionável (Status 200) encontrado no JSON.")
        return

    logger.info(f"Orquestrando {len(valid_targets)} alvos para análise de vulnerabilidades...")
    
    for item in valid_targets:
        target = item['url']
        # Verifica a presença de WAF (Cloudflare/Akamai/AWS) nos findings anteriores
        has_waf = any(
            "cloudflare" in str(finding).lower() or "waf" in str(finding).lower() 
            for finding in item.get('findings', [])
        )
        
        if has_waf:
            logger.warning(f"[WAF DETECTADO] Modificando assinatura de rede para o alvo: {target}")
            
        run_nuclei(target, has_waf)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 vuln_orchestrator.py <robust_exposure_report.json>")
        sys.exit(1)
    main(sys.argv[1])
