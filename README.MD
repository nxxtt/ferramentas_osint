# MyTools v3.2.0

Suite de ferramentas de auditoria e reconhecimento web/network para ambientes de laboratório e alvos autorizados.

> **AVISO:** Este projeto é destinado exclusivamente para fins educacionais e de teste em ambientes autorizados. O uso irresponsável pode ser ilegal. Use com responsabilidade.

---

## Instalação

### Pré-requisitos
- **Python 3.10+**

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
mytools-audit https://example.com --paths-file sensitive.txt  # Paths customizados
mytools-audit https://example.com --test-methods              # Scan de métodos HTTP
```

### 6. DNS Zone Transfer (`mytools-dnsxfer`)
Tenta zone transfer (AXFR) em nameservers de um domínio para enumerar registros DNS.

```bash
mytools-dnsxfer example.com
mytools-dnsxfer example.com -o xfr.json
mytools-dnsxfer example.com --concurrency 5
```

### 7. Subdomain Enumeration (`mytools-subenum`)
Brute-force DNS de subdomínios com wordlist embutida ou customizada.

```bash
mytools-subenum example.com
mytools-subenum example.com -o subs.json
mytools-subenum example.com -w wordlist.txt
mytools-subenum example.com --concurrency 50
mytools-subenum -l domains.txt --output-dir results/
```

---

## Features v3.2.0

### Multi-target
Execute qualquer ferramenta em múltiplos alvos a partir de um arquivo:

```bash
# Arquivo com um URL por linha (linhas com # são ignoradas)
mytools-recon -l targets.txt --output-dir results/
mytools-audit -l targets.txt --output-dir results/
mytools-dir -l urls.txt --output-dir results/
mytools-port -l hosts.txt -p 80,443
mytools-subenum -l domains.txt --output-dir results/
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
Todos os módulos HTTP utilizam `httpx.AsyncClient` com `asyncio.gather()` para concorrência nativa, substituindo `requests` + `ThreadPoolExecutor`.

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

### Email Harvesting
Coleta emails do alvo com crawl recursivo:

```bash
mytools-recon https://example.com --deep                # Ativa crawl
mytools-recon https://example.com --deep --crawl-limit 20  # Limite de páginas
```

### WAF Detection
Detecta Web Application Firewalls (Cloudflare, Akamai, AWS WAF, etc.) na resposta HTTP.

### HTTP Methods Scan
Testa métodos HTTP perigosos (PUT, DELETE, OPTIONS, TRACE, etc.):

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
```

---

## Uso

### Painel unificado
```bash
mytools
```
O menu oferece opções numéricas ou palavras-chave: `port`, `dir`, `recon`, `audit`.

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
| `mytools-audit https://example.com -q -o audit.json` | Audit silencioso com saída em arquivo |
| `mytools-audit https://example.com --test-methods` | Scan de métodos HTTP |
| `mytools-dnsxfer example.com` | DNS Zone Transfer scan |
| `mytools-subenum example.com` | Enumeração de subdomínios |

### Proxy e Rate Limiting
Todos os módulos HTTP suportam proxy e rate limiting:

```bash
# Usar proxy
mytools-dir http://target.local --proxy http://proxy:8080

# Rate limiting (requests por segundo)
mytools-dir http://target.local --delay 10

# Proxy + rate limiting
mytools-audit https://target.local --deep --proxy http://proxy:8080 --delay 5
```

### PortScanner — Workers
```bash
mytools-port 10.0.0.0/24 -w 500          # 500 threads
mytools-port 10.0.0.0/24 --threads 500   # alias deprecated
```

---

## Estrutura do Projeto

```
MyTools-main/
├── main.py            # Painel central
├── portscanner.py     # Scanner de portas TCP
├── dirscanner.py      # Scanner de diretórios HTTP
├── webrecon.py        # Reconhecimento passivo + CVE + WHOIS + emails
├── attackaudit.py     # Auditoria ofensiva/defensiva + métodos HTTP
├── dnstransfer.py     # DNS Zone Transfer
├── subdomainenum.py   # Enumeração de subdomínios
├── utils.py           # Código compartilhado (cores, helpers, HTTP async)
├── KNOW_ISSUES.txt    # Problemas conhecidos
├── ROADMAP.txt        # Roadmap de otimizações
├── tests/             # Testes unitários (570 testes)
├── pyproject.toml     # Configuração do projeto
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
```

### Adicionar dependências de dev
```bash
poetry install --with dev
```

---

## Dependências

### Runtime
- `httpx>=0.28.0` — HTTP client async com sessions, proxy, retry
- `beautifulsoup4>=4.15.0` — Parser HTML avançado
- `python-whois>=0.9.6` — Consulta WHOIS
- `dnspython>=2.8.0` — Resolução DNS, zone transfer e enumeração de subdomínios

### Dev
- `pytest>=9.1.0` — Framework de testes
- `pytest-asyncio>=0.25.0` — Testes async
- `respx>=0.25.0` — Mock de httpx para testes
- `ruff>=0.15.17` — Linter/formatter

---

## Aviso Legal

Este software é fornecido "como está", sem garantia de qualquer tipo. O autor não se responsabiliza pelo uso indevido destas ferramentas. Execute apenas em ambientes que você tenha autorização expressa para testar.

---

*nxt*
