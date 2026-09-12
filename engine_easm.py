#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import logging
import re
import random
from urllib.parse import urlparse
from typing import List, Dict, Optional
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("EnterpriseRecon")

DOMAIN_REGEX = re.compile(r"^(?:https?://)?(?:[a-zA-Z0-9.-]+)(?::\d+)?(?:/.*)?$")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

@dataclass
class ScanConfig:
    timeout_seconds: int = 7
    max_retries: int = 2
    concurrency_limit: int = 30 # Limita conexões simultâneas para evitar DoS/Bans

class EngineEASM:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.concurrency_limit)

    async def _fetch_with_retry(self, session: aiohttp.ClientSession, url: str) -> Optional[aiohttp.ClientResponse]:
        """Camada de Rede: Implementa Exponential Backoff e Rotação de UA."""
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        
        for attempt in range(self.config.max_retries):
            try:
                # Retorna o response sem ler o body ainda para economizar memória
                response = await session.get(url, headers=headers, timeout=self.config.timeout_seconds, ssl=False, allow_redirects=True)
                return response
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == self.config.max_retries - 1:
                    return None
                await asyncio.sleep(2 ** attempt) # Exponential backoff: 1s, 2s, 4s...

    def _analyze_headers(self, headers: dict) -> List[str]:
        """Fingerprinting passivo e falhas de segurança em Headers."""
        alerts = []
        # Tech Stack Disclosure
        if "Server" in headers:
            alerts.append(f"[INFO] Tech Stack (Server): {headers['Server']}")
        if "X-Powered-By" in headers:
            alerts.append(f"[INFO] Tech Stack (Powered-By): {headers['X-Powered-By']}")
            
        # Security Headers ausentes (básico)
        if "Strict-Transport-Security" not in headers:
            alerts.append("[BAIXO] HSTS Ausente")
            
        return alerts

    async def scan_target(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Processa um alvo individualmente sob o controle do Semaphore."""
        if not DOMAIN_REGEX.match(url):
            return {"url": url, "error": "Input validation failed"}

        target = url if url.startswith("http") else f"https://{url}"
        
        async with self.semaphore: # Adquire o lock de concorrência
            response = await self._fetch_with_retry(session, target)
            
            if not response:
                logger.debug(f"Host inacessível após retries: {target}")
                return {"url": target, "status_code": 0}

            try:
                html = await response.text()
                title = self._extract_title(html)
                
                # Consolidar alertas (Body + Headers)
                alerts = self._apply_body_heuristics(target, response.status, title)
                alerts.extend(self._analyze_headers(response.headers))
                
                result = {
                    "url": target,
                    "status_code": response.status,
                    "title": title,
                    "findings": alerts
                }
                logger.info(f"Analisado: {target} [{response.status}] - {len(alerts)} findings")
                return result
            except Exception as e:
                logger.error(f"Erro processando body de {target}: {e}")
                return {"url": target, "status_code": response.status, "error": str(e)}

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"

    def _apply_body_heuristics(self, url: str, status: int, title: str) -> List[str]:
        alerts = []
        parsed = urlparse(url)
        subdomain = parsed.hostname.split('.')[0].lower() if parsed.hostname else ""

        if status == 200:
            if "Index of /" in title:
                alerts.append("[CRÍTICO] Directory Listing")
            if subdomain in ["dev", "stg", "test", "homolog"]:
                alerts.append("[ALERTA] Shadow IT exposto")
            if any(k in title.lower() for k in ["login", "admin", "dashboard"]):
                alerts.append("[ATENÇÃO] Painel Administrativo/Login")
        return alerts

async def main(target_file: str):
    config = ScanConfig()
    engine = EngineEASM(config)
    
    with open(target_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    # Limitador TCP em conjunto com o Semaphore para evitar esgotamento de file descriptors (ulimit)
    conn = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [engine.scan_target(session, t) for t in targets]
        results = await asyncio.gather(*tasks)

    # Filtrar resultados válidos
    valid_results = [r for r in results if r.get("status_code", 0) > 0]
    
    with open("robust_exposure_report.json", "w") as f:
        json.dump(valid_results, f, indent=2)
    logger.info("Scan finalizado de forma resiliente.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python3 engine_easm.py <targets.txt>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))