
import os
import json
from datetime import datetime
import sys

def create_engagement(client_name: str, domains: list):
    """Camada de Lógica: Inicializa um workspace isolado e auditável para o cliente."""
    date_stamp = datetime.now().strftime('%Y%m%d')
    base_dir = f"engagements/{client_name}_{date_stamp}"
    
    # Estrutura de pastas padronizada (PTES)
    folders = ['01_legal', '02_recon', '03_active_scans', '04_reports']
    
    for folder in folders:
        os.makedirs(os.path.join(base_dir, folder), exist_ok=True)

    # Gera o template do Rules of Engagement (RoE)
    roe_template = {
        "client_name": client_name,
        "authorized_scope": domains,
        "test_type": "Blackbox / EASM",
        "rules": {
            "dos_testing_allowed": False,
            "social_engineering_allowed": False,
            "testing_window": "24/7",
        },
        "legal_status": "PENDING_SIGNATURE"
    }
    
    with open(os.path.join(base_dir, "01_legal", "Rules_of_Engagement.json"), "w") as f:
        json.dump(roe_template, f, indent=4)

    # Popula os targets para a nossa engine diretamente na pasta correta
    with open(os.path.join(base_dir, "02_recon", "targets.txt"), "w") as f:
        f.write("\n".join(domains) + "\n")

    print(f"[SUCESSO] Workspace criado em: {base_dir}")
    print(f"[AÇÃO 1] Envie o RoE para assinatura do cliente.")
    print(f"[AÇÃO 2] Após autorização, copie o engine_easm.py para a pasta e rode contra {base_dir}/02_recon/targets.txt")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 init_client.py <NomeCliente> <dominio1.com> <dominio2.com>")
        sys.exit(1)
        
    client = sys.argv[1]
    scope = sys.argv[2:]
    create_engagement(client, scope)
