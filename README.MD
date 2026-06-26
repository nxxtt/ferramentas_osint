# MyTools v3.2.0

[![CI](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml/badge.svg)](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml)

Suite de ferramentas de auditoria e reconhecimento web/network para ambientes de laboratório e alvos autorizados.

> **AVISO:** Este projeto é destinado exclusivamente para fins educacionais e de teste em ambientes autorizados. O uso irresponsável pode ser ilegal. Use com responsabilidade.

---

## Instalação

### Pré-requisitos
- **Python 3.14+**

### Instalacao rapida (recomendado)
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint

# Windows
.\setup.ps1

# Linux/Mac
chmod +x setup.sh
./setup.sh
```

O script instala Poetry, dependencias e adiciona os comandos CLI ao PATH.

### Instalacao manual
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint
pip install poetry
poetry install --with dev
```

> **Nota:** Apos instalar manualmente, use `poetry run mytools` ou ative o venv com `poetry env activate`.

Isso instala os comandos CLI:

| Comando | Módulo |
|---------|--------|
| `mytools` | Painel interativo central |
| `mytools-audit` | Auditoria ofensiva/defensiva |
| `mytools-recon` | Reconhecimento passivo |
| `mytools-port` | Scanner de portas TCP |
| `mytools-dir` | Scanner de diretórios HTTP |
| `mytools-dnsxfer` | DNS Zone Transfer |
| `mytools-subenum` | Enumeração de subdomínios |
| `mytools-dnshistory` | Histórico DNS (OSINT) |
| `mytools-whoishistory` | Histórico WHOIS (OSINT) |
| `mytools-ipasn` | IP ASN/ISP enrichment |
| `mytools-techfp` | Technology Fingerprint |
| `mytools-oas` | OpenAPI/Swagger Discovery |
| `mytools-gql` | GraphQL Playground Exposure |
| `mytools-sm` | Source Map Discovery |
| `mytools-vcs` | VCS Leak Detection |
| `mytools-cred` | Gerenciador de credenciais |
| `mytools-reconall` | Recon completo (todos os módulos) |

> **Nota:** Após instalar, abra um novo terminal. Se o comando não for encontrado, adicione o diretório `Scripts` do Python ao PATH.

### Execução direta (sem instalar)
```bash
python main.py               # Painel unificado
python attackaudit.py --help # Ajuda individual
```

---

## Módulos

### 1. Painel Central (`mytools`)
Orquestrador do ecossistema com menu interativo colorido para alternar entre todas as subferramentas.

```bash
mytools
mytools --version
```

### 2. Network PortScanner (`mytools-port`)
Scanner de portas TCP com suporte a CIDR, banner grabbing e exportação JSON/CSV.

```bash
mytools-port 192.168.0.0/24 -p 22,80,443 -b
mytools-port scanme.nmap.org -p top100 -o resultado.json
mytools-port -l targets.txt -o results.json
mytools-port 10.0.0.0/30 -p 80 -w 100 --banner -o scan.csv
```

### 3. Web Directory Scanner (`mytools-dir`)
Fuzzing e descoberta de caminhos ocultos em servidores web com filtros de status code e extensões.

```bash
mytools-dir http://target.local -x php,txt,bak -s 200,403
mytools-dir http://127.0.0.1:8000 -w wordlist.txt
mytools-dir http://target.local --proxy http://proxy:8080 --delay 10
mytools-dir -l urls.txt --output-dir results/
```

### 4. Web Passive Recon (`mytools-recon`)
Reconhecimento passivo: headers de segurança, fingerprinting, robots.txt, sitemap.xml, WAF detection, email harvesting, WHOIS e lookup de CVEs.

```bash
mytools-recon https://example.com
mytools-recon https://example.com -o recon.json
mytools-recon https://example.com --proxy http://proxy:8080
mytools-recon -l targets.txt --output-dir results/
mytools-recon https://example.com --cve                    # Lookup de CVEs
mytools-recon https://example.com --cve --nvd-api-key KEY  # Com API key
mytools-recon https://example.com --deep                   # Email harvesting + crawl
mytools-recon https://example.com --deep --crawl-limit 20  # Limite de páginas crawleadas
```

### 5. Deep Attack & Vulnerability Audit (`mytools-audit`)
Auditoria red/blue com verificação de CORS, TLS, cookies, XSS, SQLi, CSRF, métodos HTTP perigosos e deep scan de arquivos sensíveis.

```bash
mytools-audit https://example.com --deep
mytools-audit https://example.com --deep -o audit.json
mytools-audit https://example.com --deep --proxy http://proxy:8080 --delay 5
mytools-audit -l targets.txt --output-dir results/
mytools-audit https://example.com --test-vulns                 # Testa XSS, SQLi e CSRF
mytools-audit https://example.com --paths-file sensitive.txt  # Paths customizados
mytools-audit https://example.com --test-methods              # Scan de métodos HTTP
```

### 6. DNS Zone Transfer (`mytools-dnsxfer`)
Tenta zone transfer (AXFR) em nameservers de um domínio para enumerar registros DNS.

```bash
mytools-dnsxfer example.com
mytools-dnsxfer example.com -o xfr.json
mytools-dnsxfer example.com -t 15
```

### 7. Subdomain Enumeration (`mytools-subenum`)
Brute-force DNS de subdomínios com wordlist embutida ou customizada.

```bash
mytools-subenum example.com
mytools-subenum example.com -o subs.json
mytools-subenum example.com -w wordlist.txt
mytools-subenum example.com -T 50
mytools-subenum -l domains.txt --output-dir results/
```

### 8. DNS History (`mytools-dnshistory`)
Consulta histórico DNS via fontes OSINT (DNSlytics, SecurityTrails, ViewDNS).

```bash
mytools-dnshistory example.com
mytools-dnshistory example.com -o dns-history.json
mytools-dnshistory example.com --sources dnslytics,viewdns
```

### 9. WHOIS History (`mytools-whoishistory`)
Consulta histórico WHOIS via fontes OSINT (SecurityTrails, WhoisXML).

```bash
mytools-whoishistory example.com
mytools-whoishistory example.com -o whois-history.json
mytools-whoishistory example.com --api-key KEY
```

### 10. IP ASN/ISP Info (`mytools-ipasn`)
Enriquece IPs com dados BGP: ASN, organização, ISP, país, cidade. Dual API (ipwho.is + ip-api.com), suporte batch.

```bash
mytools-ipasn 8.8.8.8
mytools-ipasn 8.8.8.8 1.1.1.1 1.0.0.1
mytools-ipasn -l ips.txt -o asn.json
```

### 11. Technology Fingerprint (`mytools-techfp`)
Fingerprinting tecnológico com 7 sinais: headers, meta tags, scripts, CSS, cookies, body HTML, headers de segurança. 40+ tecnologias, confidence scoring, categorias.

```bash
mytools-techfp https://example.com
mytools-techfp https://example.com -o tech.json
mytools-techfp -l urls.txt --output-dir results/
```

### 12. OpenAPI/Swagger Discovery (`mytools-oas`)
Busca specs OpenAPI/Swagger expostas em paths comuns, faz parse JSON/YAML, extrai endpoints, métodos, tags e schemas.

```bash
mytools-oas http://target.com
mytools-oas http://target.com --endpoints
mytools-oas -l urls.txt -o oas.json
```

### 13. GraphQL Playground Exposure (`mytools-gql`)
Descobre GraphQL playgrounds expostos (GraphiQL, Playground, Altair, Voyager, Apollo Sandbox) e opcionalmente executa introspection query para extrair schema.

```bash
mytools-gql http://target.com
mytools-gql http://target.com --introspect
mytools-gql http://target.com --schema
```

### 14. Source Map Discovery (`mytools-sm`)
Busca `.map` files de JavaScript expostos por duas abordagens: scan de `<script src>` + probing de paths comuns.

```bash
mytools-sm http://target.com
mytools-sm http://target.com --sources
mytools-sm http://target.com --no-scan-scripts
```

### 15. VCS Leak Detection (`mytools-vcs`)
Detecta repositórios versionados expostos (.git, .svn, .hg) com validação de conteúdo para evitar falsos positivos.

```bash
mytools-vcs http://target.com
mytools-vcs http://target.com --git-only
mytools-vcs -l urls.txt -o vcs.json
```

---

## Features v3.2.0

### Python 3.12+ Modernization
Código utilize as features modernas do Python 3.14+: `asyncio.TaskGroup` para concorrência segura, `match/case` para dispatch, `tomllib` para parsing TOML, `@override` para herança, PEP 758 `except` sem parênteses, e f-strings PEP 701.

### Multi-target
Execute qualquer ferramenta em múltiplos alvos a partir de um arquivo:

```bash
# Arquivo com um URL por linha (linhas com # são ignoradas)
mytools-recon -l targets.txt --output-dir results/
mytools-audit -l targets.txt --output-dir results/
mytools-dir -l urls.txt --output-dir results/
mytools-port -l hosts.txt -p 80,443
mytools-subenum -l domains.txt --output-dir results/
mytools-dnshistory -l domains.txt --output-dir results/
mytools-whoishistory -l domains.txt --output-dir results/
mytools-ipasn -l ips.txt -o asn.json
mytools-techfp -l urls.txt --output-dir results/
mytools-oas -l urls.txt -o oas.json
mytools-gql -l urls.txt -o gql.json
mytools-sm -l urls.txt -o sm.json
mytools-vcs -l urls.txt -o vcs.json
```

Cada alvo gera um arquivo individual (`hostname.json`) no `--output-dir`. Com `-o`, gera saída consolidada.

### Quiet Mode
Sem banner, sem mensagens de progresso — apenas erros no stderr. Requer `-o`:

```bash
mytools-recon https://example.com -q -o recon.json
mytools-audit https://example.com --deep -q -o audit.json
```

### Autenticação
Suporte a Basic Auth, Bearer Token, Cookies e Headers customizados:

```bash
# Basic Auth
mytools-audit https://internal.app --auth admin:senha123

# Bearer Token
mytools-recon https://api.target.com --bearer-token eyJhbGc...

# Cookie
mytools-dir http://app.local --cookie "session=abc123; token=xyz"

# Header customizado (pode usar mais de um)
mytools-recon https://target.com --header "X-Token: abc" --header "Authorization: Bearer xyz"
```

### Async HTTP (httpx)
Todos os módulos HTTP utilizam `httpx.AsyncClient` com `asyncio.TaskGroup` e `Semaphore` para concorrência nativa. Módulos independentes rodam em paralelo via `asyncio.gather` + `asyncio.to_thread`.

### CVE Lookup (NIST NVD)
Detecta versões de frameworks/servidores e busca CVEs associadas:

```bash
mytools-recon https://example.com --cve
mytools-recon https://example.com --cve --nvd-api-key YOUR_KEY
```

- Sem API key: 5 requests/30s
- Com API key: 50 requests/30s (solicite em https://nvd.nist.gov/developers/request-an-api-key)
- Fonte: NIST NVD API v2.0

### WHOIS Lookup
Consulta WHOIS automatica para domínios (retorna None para IPs):

```bash
mytools-recon https://example.com  # WHOIS sempre executado
```

### DNS History
Histórico DNS via fontes OSINT (DNSlytics, SecurityTrails, ViewDNS):

```bash
mytools-dnshistory example.com
mytools-dnshistory example.com --sources dnslytics,viewdns
```

### WHOIS History
Histórico WHOIS via fontes OSINT (SecurityTrails, WhoisXML):

```bash
mytools-whoishistory example.com
mytools-whoishistory example.com --api-key KEY
```

### IP ASN/ISP Enrichment
Enriquece IPs com dados BGP completos (ASN, organização, ISP, país):

```bash
mytools-ipasn 8.8.8.8
mytools-ipasn 8.8.8.8 1.1.1.1 1.0.0.1
mytools-ipasn -l ips.txt -o asn.json
```

Dual API: ipwho.is (individual) + ip-api.com (batch 100 IPs).

### Technology Fingerprint
Fingerprinting tecnológico avançado com 7 sinais e 40+ tecnologias:

```bash
mytools-techfp https://example.com
mytools-techfp https://example.com -o tech.json
```

Sinais analisados: headers HTTP, meta tags, scripts, CSS, cookies, body HTML, headers de segurança. Confidence scoring (high/medium/low) e categorias (server, language, framework, library, cms).

### OpenAPI/Swagger Discovery
Busca specs OpenAPI/Swagger expostas em 24 paths comuns, faz parse JSON/YAML, extrai endpoints, métodos, tags e schemas:

```bash
mytools-oas http://target.com
mytools-oas http://target.com --endpoints
```

### GraphQL Playground Exposure
Detecta 5 ferramentas GraphQL (GraphiQL, Playground, Altair, Voyager, Apollo Sandbox) e opcionalmente executa introspection query:

```bash
mytools-gql http://target.com
mytools-gql http://target.com --introspect
```

### Source Map Discovery
Busca `.map` files de JavaScript expostos via scan de `<script src>` + probing de 27 paths comuns:

```bash
mytools-sm http://target.com
mytools-sm http://target.com --sources
```

### VCS Leak Detection
Detecta repositórios versionados expostos (.git, .svn, .hg) com validação de conteúdo e HEAD pre-check:

```bash
mytools-vcs http://target.com
mytools-vcs http://target.com --git-only
```

### Email Harvesting
Coleta emails do alvo com crawl recursivo:

```bash
mytools-recon https://example.com --deep                # Ativa crawl
mytools-recon https://example.com --deep --crawl-limit 20  # Limite de páginas
```

### WAF Detection
Detecta Web Application Firewalls (Cloudflare, Akamai, AWS WAF, etc.) na resposta HTTP.

### HTTP Methods Scan
Testa métodos HTTP perigosos (PUT, DELETE, PATCH, TRACE):

```bash
mytools-audit https://example.com --test-methods
```

### Paths Customizados (attackaudit)
Carregue seus próprios paths para deep scan:

```bash
# Arquivo com um path por linha
mytools-audit https://example.com --paths-file sensitive.txt --deep
```

O argumento `--paths-file` ativa `--deep` automaticamente.

### Controle de Cores
```bash
mytools-recon https://example.com --no-color     # Sem cores
mytools-port 10.0.0.1 -p 80 --color              # Forçar cores (útil em pipes)
```

### Versão
```bash
mytools --version
mytools-recon --version
mytools-audit --version
mytools-port --version
mytools-dir --version
mytools-dnsxfer --version
mytools-subenum --version
mytools-dnshistory --version
mytools-whoishistory --version
mytools-ipasn --version
mytools-techfp --version
mytools-oas --version
mytools-gql --version
mytools-sm --version
mytools-vcs --version
```

---

## Uso

### Painel unificado
```bash
mytools
```
O menu oferece opções numéricas ou palavras-chave: `port`, `dir`, `recon`, `audit`, `dns/xfer`, `sub/subenum`, `dns-history`, `whois-history`, `ip-asn`, `tech`, `oas`, `gql`, `sourcemap`, `vcs`.

### Modo interativo
Cada módulo possui um shell interativo. Dentro dele, digite os argumentos normalmente:
```
scanner> 192.168.1.0/24 -p 80,443 -b -t 1
```
Use `help` para ver a ajuda, `exit` para voltar ao menu.

### Exemplos rápidos
| Comando | Descrição |
|---------|-----------|
| `mytools-port 127.0.0.1 -p 1-1024` | Scan TCP nas primeiras 1024 portas |
| `mytools-dir http://testphp.vulnweb.com -x php` | Busca por arquivos .php |
| `mytools-recon https://google.com` | Recon passivo rápido |
| `mytools-recon https://example.com --cve` | Recon com lookup de CVEs |
| `mytools-recon https://example.com --deep` | Recon com email harvesting + crawl |
| `mytools-audit https://example.com --deep` | Auditoria completa com deep scan |
| `mytools-audit https://example.com --test-vulns` | Auditoria com testes XSS, SQLi e CSRF |
| `mytools-audit https://example.com -q -o audit.json` | Audit silencioso com saída em arquivo |
| `mytools-audit https://example.com --test-methods` | Scan de métodos HTTP |
| `mytools-dnsxfer example.com` | DNS Zone Transfer scan |
| `mytools-subenum example.com` | Enumeração de subdomínios |
| `mytools-dnshistory example.com` | Histórico DNS via OSINT |
| `mytools-whoishistory example.com` | Histórico WHOIS via OSINT |
| `mytools-ipasn 8.8.8.8` | IP ASN/ISP enrichment |
| `mytools-techfp https://example.com` | Technology fingerprinting |
| `mytools-oas http://target.com` | OpenAPI/Swagger discovery |
| `mytools-gql http://target.com` | GraphQL playground discovery |
| `mytools-sm http://target.com` | Source map discovery |
| `mytools-vcs http://target.com` | VCS leak detection |
| `mytools-reconall https://example.com --deep` | Recon completo com todos os módulos |

### Proxy e Rate Limiting
Todos os módulos HTTP suportam proxy e rate limiting:

```bash
# Usar proxy
mytools-dir http://target.local --proxy http://proxy:8080

# Rate limiting (segundos entre requests)
mytools-dir http://target.local --delay 0.5

# Proxy + rate limiting
mytools-audit https://target.local --deep --proxy http://proxy:8080 --delay 5
```

### PortScanner — Workers
```bash
mytools-port 10.0.0.0/24 -w 500          # 500 threads
mytools-port 10.0.0.0/24 --threads 500   # alias deprecated
```

### Controle de Cores
```bash
# Desativar cores (padrão NO_COLOR — https://no-color.org/)
export NO_COLOR=1
mytools
```

---

## Estrutura do Projeto

```
MyTools-main/
├── main.py                 # Painel central
├── portscanner.py          # Scanner de portas TCP
├── dirscanner.py           # Scanner de diretórios HTTP
├── webrecon.py             # Reconhecimento passivo + CVE + WHOIS + emails
├── attackaudit.py          # Auditoria ofensiva/defensiva + métodos HTTP
├── reconall.py             # Wrapper: executa todos os módulos contra um alvo
├── dnstransfer.py          # DNS Zone Transfer
├── subdomainenum.py        # Enumeração de subdomínios
├── dnshistory.py           # Histórico DNS (OSINT)
├── whoishistory.py         # Histórico WHOIS (OSINT)
├── ipasninfo.py            # IP ASN/ISP enrichment
├── techfingerprint.py      # Technology Fingerprint (7 sinais)
├── openapidiscovery.py     # OpenAPI/Swagger Discovery
├── graphqlplayground.py    # GraphQL Playground Exposure
├── sourcemapdiscovery.py   # Source Map Discovery
├── vcsleak.py              # VCS Leak Detection (.git, .svn, .hg)
├── utils.py                # Código compartilhado (cores, helpers, HTTP async)
├── cred.py                 # Gerenciador de credenciais (keyring)
├── KNOW_ISSUES.txt         # Problemas conhecidos
├── ROADMAP.txt             # Roadmap de otimizações
├── tests/                  # Testes unitários (1277 testes)
├── pyproject.toml          # Configuração do projeto
└── README.MD
```

---

## Desenvolvimento

### Rodar testes
```bash
poetry run pytest tests/ -v
```

### Lint
```bash
poetry run ruff check .
poetry run basedpyright
```

### Adicionar dependências de dev
```bash
poetry install --with dev
```

---

## Dependências

### Runtime
- `httpx>=0.28.1` — HTTP client async com sessions, proxy, retry
- `beautifulsoup4>=4.15.0` — Parser HTML avançado
- `python-whois>=0.9.6` — Consulta WHOIS
- `dnspython>=2.8.0` — Resolução DNS, zone transfer e enumeração de subdomínios
- `pyyaml>=6.0.3` — Parse de YAML (OpenAPI specs)

### Dev
- `pytest>=9.1.1` — Framework de testes
- `pytest-asyncio>=1.4.0` — Testes async
- `respx>=0.23.1` — Mock de httpx para testes
- `ruff>=0.15.20` — Linter/formatter
- `basedpyright` — Type checker

---

## Aviso Legal

Este software é fornecido "como está", sem garantia de qualquer tipo. O autor não se responsabiliza pelo uso indevido destas ferramentas. Execute apenas em ambientes que você tenha autorização expressa para testar.

---

*nxt*
