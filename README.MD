# MyTools v3.2.0

[![CI](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml/badge.svg)](https://github.com/nxxtt/ferramentas_osint/actions/workflows/ci.yml)

Suite de ferramentas de auditoria e reconhecimento web/network para ambientes de laboratório e alvos autorizados.

> **AVISO:** Este projeto é destinado exclusivamente para fins educacionais e de teste em ambientes autorizados. O uso irresponsável pode ser ilegal. Use com responsabilidade.

---

## Instalação

### Pré-requisitos
- **Python 3.14+**

### Instalação rápida (recomendado)
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint

# Windows
.\setup.ps1

# Linux/Mac
chmod +x setup.sh
./setup.sh
```

O script instala Poetry, dependências e adiciona os comandos CLI ao PATH.

### Instalação manual
```bash
git clone https://github.com/nxxtt/ferramentas_osint.git
cd ferramentas_osint
pip install poetry
poetry install --with dev
```

> **Nota:** Após instalar manualmente, use `poetry run mytools` ou ative o venv com `poetry env activate`.

Isso instala os comandos CLI:

| Comando | Módulo |
|---------|--------|
| `mytools` | Painel interativo central |
| `mytools-port` | Scanner de portas TCP |
| `mytools-dir` | Scanner de diretórios HTTP |
| `mytools-recon` | Reconhecimento passivo |
| `mytools-audit` | Auditoria ofensiva/defensiva |
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
| `mytools-cfg` | Config File Detection |
| `mytools-bak` | Backup File Detection |
| `mytools-dork` | Google Dorking |
| `mytools-breach` | Email Breach Check |
| `mytools-soceng` | Social Engineering Recon |
| `mytools-leak` | Paste/Leak Monitoring |
| `mytools-dark` | Dark Web Monitoring |
| `mytools-rebind` | DNS Rebinding Detection |
| `mytools-dwt` | DNS Water Torture |
| `mytools-amp` | DNS Amplification Detection |
| `mytools-tunnel` | DNS Tunnel Detection |
| `mytools-dnssec` | DNSSEC Validation |
| `mytools-nsec` | NSEC Walking |
| `mytools-caa` | CAA Record Check |
| `mytools-secemail` | Email Security (DMARC/SPF/DKIM) |
| `mytools-spoof` | Email Spoofing Analysis |
| `mytools-smtpinject` | SMTP Header Injection |
| `mytools-smtpdown` | SMTP Downgrade Attack |
| `mytools-templeti` | Email Template Injection |
| `mytools-attachbypass` | Email Attachment Bypass |
| `mytools-addrbypass` | Email Address Bypass |
| `mytools-linktrack` | Email Link Tracking |
| `mytools-nullbyte` | Null Byte Injection |
| `mytools-dblurl` | Double URL Encoding Bypass |
| `mytools-ptraversal` | Path Traversal via Encoding |
| `mytools-rtlo` | RTL Override Bypass |
| `mytools-overlong` | Overlong UTF-8 Encoding |
| `mytools-bominject` | BOM Injection |
| `mytools-charsetbypass` | Charset Detection Bypass |
| `mytools-openredirect` | Open Redirect Detection |
| `mytools-crlfinject` | CRLF Injection Detection |
| `mytools-sstdetect` | SSTI Detection |
| `mytools-ssrfdetect` | SSRF Detection |
| `mytools-cred` | Gerenciador de credenciais |
| `mytools-reconall` | Recon completo (todos os módulos) |

> **Nota:** Após instalar, abra um novo terminal. Se o comando não for encontrado, adicione o diretório `Scripts` do Python ao PATH.

### Execução direta (sem instalar)
```bash
python -m mytools.core.main                  # Painel unificado
python -m mytools.web.attackaudit --help     # Ajuda individual
python -m mytools.dns.dnstransfer --help     # DNS Zone Transfer
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
mytools-audit https://example.com --test-methods               # Scan de métodos HTTP
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

### 16. Config File Detection (`mytools-cfg`)
Detecta arquivos de configuração sensíveis expostos (.env, config.json, settings.py, .htpasswd) com validação por categoria.

```bash
mytools-cfg http://target.com
mytools-cfg http://target.com --category env
mytools-cfg http://target.com --sensitive-only
mytools-cfg -l urls.txt -o results.json
```

### 17. Backup File Detection (`mytools-bak`)
Detecta arquivos de backup expostos (.bak, .old, .swp, .sql, .zip) com validação de magic bytes para evitar falsos positivos.

```bash
mytools-bak http://target.com
mytools-bak http://target.com --type sql
mytools-bak http://target.com --type archive
mytools-bak -l urls.txt -o results.json
```

### 18. Google Dorking (`mytools-dork`)
Gera dorks Google para o alvo e busca via DuckDuckGo. 6 categorias de dorks + dorks customizados.

```bash
mytools-dork example.com
mytools-dork example.com --category filetype
mytools-dork example.com --category sensitive --search
mytools-dork example.com --custom-dork 'inurl:api v1'
mytools-dork -l domains.txt -o results.json
```

### 19. Email Breach Check (`mytools-breach`)
Verifica se emails apareceram em vazamentos de dados usando múltiplas fontes (XposedOrNot, LeakCheck, HIBP).

```bash
mytools-breach user@example.com
mytools-breach user1@test.com user2@test.com
mytools-breach user@example.com --source hibp --hibp-api-key KEY
mytools-breach -f emails.txt -o results.json
```

### 20. Social Engineering Recon (`mytools-soceng`)
Coleta emails, nomes e cargos de funcionários do alvo usando GitHub, Hunter.io e web scraping.

```bash
mytools-soceng example.com
mytools-soceng example.com --source github --source hunter
mytools-soceng example.com --hunter-api-key KEY
mytools-soceng -l domains.txt -o results.json
```

### 21. Paste/Leak Monitoring (`mytools-leak`)
Monitora pastes e repos públicos por credenciais e dados sensíveis do alvo (GitHub Gists, Pastebin RSS, GitLab Snippets).

```bash
mytools-leak example.com
mytools-leak example.com --source github_gists --source pastebin_rss
mytools-leak example.com --github-token ghp_xxx
mytools-leak -l domains.txt -o results.json
```

### 22. Dark Web Monitoring (`mytools-dark`)
Busca menções do domínio em sites .onion via APIs públicas (Ahmia, DarkSearch, Intelligence X).

```bash
mytools-dark example.com
mytools-dark example.com --source ahmia --source darksearch
mytools-dark example.com --intelx-key KEY
mytools-dark -l domains.txt -o results.json
```

### 23. DNS Rebinding (`mytools-rebind`)
Testa vulnerabilidade a DNS rebinding (TTL, IPs privados, wildcard, IP flip).

```bash
mytools-rebind example.com
mytools-rebind example.com -o rebind.json
```

### 24. DNS Water Torture (`mytools-dwt`)
Stress test DNS com subdomínios aleatórios para testar resiliência do servidor.

```bash
mytools-dwt example.com
mytools-dwt example.com --num-queries 1000
mytools-dwt example.com -o dwt.json
```

### 25. DNS Amplification (`mytools-amp`)
Detecta se servidor DNS pode ser usado para amplificação DDoS.

```bash
mytools-amp example.com
mytools-amp example.com -o amp.json
```

### 26. DNS Tunnel Detection (`mytools-tunnel`)
Detecta DNS tunneling via análise de entropia, comprimento de labels e padrões.

```bash
mytools-tunnel example.com
mytools-tunnel example.com -o tunnel.json
```

### 27. DNSSEC Validation (`mytools-dnssec`)
Valida configuração DNSSEC: cadeia de confiança, RRSIG, força de algoritmo.

```bash
mytools-dnssec example.com
mytools-dnssec example.com -o dnssec.json
```

### 28. NSEC Walking (`mytools-nsec`)
Enumera zonas DNSSEC via NSEC records em cadeia.

```bash
mytools-nsec example.com
mytools-nsec example.com -o nsec.json
```

### 29. CAA Record Check (`mytools-caa`)
Verifica registros CAA (Certificate Authority Authorization) de certificados.

```bash
mytools-caa example.com
mytools-caa example.com -o caa.json
```

### 30. Email Security (`mytools-secemail`)
Verifica configuração DMARC/SPF/DKIM de email.

```bash
mytools-secemail example.com
mytools-secemail example.com -o emailsec.json
```

### 31. Email Spoofing (`mytools-spoof`)
Análise de vulnerabilidade a spoofing via SPF/DKIM/DMARC.

```bash
mytools-spoof example.com
mytools-spoof example.com -o spoof.json
```

### 32. SMTP Injection (`mytools-smtpinject`)
Testa injeção CRLF em campos de email via SMTP.

```bash
mytools-smtpinject mail.example.com
mytools-smtpinject mail.example.com --port 25
mytools-smtpinject mail.example.com --from-addr admin@test.com
```

### 33. SMTP Downgrade (`mytools-smtpdown`)
Testa se servidor SMTP pode ser forçado a operar em plaintext (STARTTLS stripping).

```bash
mytools-smtpdown mail.example.com
mytools-smtpdown mail.example.com --port 25
mytools-smtpdown mail.example.com --from-addr admin@test.com
```

### 34. Email Template Injection (`mytools-templeti`)
Testa injeção de código em templates de email (Jinja2, Handlebars, Mako, Tornado).

```bash
mytools-templeti mail.example.com
mytools-templeti mail.example.com --port 25
mytools-templeti mail.example.com --from-addr admin@test.com
```

### 35. Email Attachment Bypass (`mytools-attachbypass`)
Testa bypass de filtros de anexos de email (tipos perigosos, extensões duplas).

```bash
mytools-attachbypass mail.example.com
mytools-attachbypass mail.example.com --technique double-extension
```

### 36. Email Address Bypass (`mytools-addrbypass`)
Testa bypass de blocklists de email usando técnicas de encoding e formatação.

```bash
mytools-addrbypass user@example.com
mytools-addrbypass user@example.com --technique unicode
mytools-addrbypass -f emails.txt -o results.json
```

### 37. Email Link Tracking (`mytools-linktrack`)
Detecta tracking pixels e rewrites de links em emails.

```bash
mytools-linktrack https://example.com
mytools-linktrack https://example.com --deep
```

### 38. Null Byte Injection (`mytools-nullbyte`)
Testa injecao de null bytes (%00) em URLs, headers e parâmetros HTTP.

```bash
mytools-nullbyte https://example.com
mytools-nullbyte https://example.com -c url
mytools-nullbyte https://example.com -c header
```

### 38. Double URL Encoding Bypass (`mytools-dblurl`)
Testa bypass de filtros via encoding duplo de URLs.

```bash
mytools-dblurl https://example.com
mytools-dblurl https://example.com -c param
```

### 39. Path Traversal via Encoding (`mytools-ptraversal`)
Testa path traversal via encoding de URLs.

```bash
mytools-ptraversal https://example.com
mytools-ptraversal https://example.com -c path
```

### 40. RTL Override Bypass (`mytools-rtlo`)
Usa Right-to-Left Override para confundir display de URLs.

```bash
mytools-rtlo https://example.com
mytools-rtlo https://example.com --type rtl
mytools-rtlo https://example.com --type zero-width
mytools-rtlo https://example.com --type combining
```

### 41. Overlong UTF-8 Encoding (`mytools-overlong`)
Usa overlong encoding para bypass de filtros.

```bash
mytools-overlong https://example.com
mytools-overlong https://example.com -c url
```

### 42. BOM Injection (`mytools-bominject`)
Injeta Byte Order Mark em início de arquivos/requests.

```bash
mytools-bominject https://example.com
mytools-bominject https://example.com -c url
```

### 43. Charset Detection Bypass (`mytools-charsetbypass`)
Força detecção de charset errada para bypass.

```bash
mytools-charsetbypass https://example.com
mytools-charsetbypass https://example.com -c meta
```

### 44. Open Redirect (`mytools-openredirect`)
Detecta redirecionamentos abusivos em web apps.

```bash
mytools-openredirect https://example.com
mytools-openredirect https://example.com -c param
mytools-openredirect https://example.com -c bypass
```

### 45. CRLF Injection (`mytools-crlfinject`)
Detecta injecao de headers via \r\n em HTTP.

```bash
mytools-crlfinject https://example.com
mytools-crlfinject https://example.com -c param
mytools-crlfinject https://example.com -c header
```

### 46. SSTI Detection (`mytools-sstdetect`)
Detecta Server-Side Template Injection em web apps.

```bash
mytools-sstdetect https://example.com
mytools-sstdetect https://example.com -c detect
mytools-sstdetect https://example.com -c exploit
```

### 47. SSRF Detection (`mytools-ssrfdetect`)
Detecta Server-Side Request Forgery em web apps.

```bash
mytools-ssrfdetect https://example.com
mytools-ssrfdetect https://example.com -c detect
mytools-ssrfdetect https://example.com -c cloud
mytools-ssrfdetect https://example.com -c bypass
```

### 48. ReconAll (`mytools-reconall`)
Executa todos os módulos contra um alvo de uma vez.

```bash
mytools-reconall https://example.com --deep
mytools-reconall example.com --skip dnstransfer --skip subenum
mytools-reconall example.com --deep --test-vulns --cve
```

---

## Features v3.2.0

### src/ Package Structure
Código organizado em `src/mytools/` com subpacotes por categoria: `core`, `network`, `web`, `dns`, `whois`, `osint`, `email`, `vcs`, `config`.

### Python 3.14+ Modernization
Código utiliza as features modernas do Python 3.14+: `asyncio.TaskGroup` para concorrência segura, `match/case` para dispatch, `tomllib` para parsing TOML, PEP 758 `except` sem parênteses, e f-strings PEP 701.

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
Consulta WHOIS automática para domínios:

```bash
mytools-recon https://example.com
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

### Config File Detection
Detecta arquivos de configuração sensíveis expostos em 6 categorias com 88 paths e validação de conteúdo:

```bash
mytools-cfg http://target.com
mytools-cfg http://target.com --category env
mytools-cfg http://target.com --sensitive-only
```

### Backup File Detection
Detecta arquivos de backup expostos com 6 categorias (.bak/.swp/.tilde/.sql/.archive/.orig_tmp) e validação de magic bytes:

```bash
mytools-bak http://target.com
mytools-bak http://target.com --type sql
```

### Google Dorking
Gera dorks Google em 6 categorias (filetype, directory, login, error, sensitive, subdomain) + dorks customizados + busca via DuckDuckGo:

```bash
mytools-dork example.com
mytools-dork example.com --category sensitive --search
```

### Email Breach Check
Verifica emails em vazamentos usando 3 fontes (XposedOrNot, LeakCheck, HIBP) com dedup por email+breach:

```bash
mytools-breach user@example.com
mytools-breach user@example.com --source hibp --hibp-api-key KEY
```

### Social Engineering Recon
Coleta emails, nomes e cargos de funcionários via GitHub API, Hunter.io e web scraping (/about, /team):

```bash
mytools-soceng example.com
mytools-soceng example.com --hunter-api-key KEY
```

### Paste/Leak Monitoring
Monitora pastes e repos públicos por credenciais com 10 padrões de detecção (AWS, GitHub, Slack, Stripe, etc.):

```bash
mytools-leak example.com
mytools-leak example.com --github-token ghp_xxx
```

### Dark Web Monitoring
Busca menções do domínio em sites .onion via Ahmia, DarkSearch e Intelligence X com classificação de severidade:

```bash
mytools-dark example.com
mytools-dark example.com --intelx-key KEY
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

### PortScanner — Workers
```bash
mytools-port 10.0.0.0/24 -w 500          # 500 threads
mytools-port 10.0.0.0/24 --threads 500   # alias deprecated
```

### Versão
```bash
mytools --version
mytools-port --version
mytools-dir --version
mytools-recon --version
mytools-audit --version
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
mytools-cfg --version
mytools-bak --version
mytools-dork --version
mytools-breach --version
mytools-soceng --version
mytools-leak --version
mytools-dark --version
mytools-rebind --version
mytools-dwt --version
mytools-amp --version
mytools-tunnel --version
mytools-dnssec --version
mytools-nsec --version
mytools-caa --version
mytools-secemail --version
mytools-spoof --version
mytools-smtpinject --version
mytools-smtpdown --version
mytools-templeti --version
mytools-attachbypass --version
mytools-addrbypass --version
mytools-linktrack --version
mytools-nullbyte --version
mytools-dblurl --version
mytools-ptraversal --version
mytools-rtlo --version
mytools-overlong --version
mytools-bominject --version
mytools-charsetbypass --version
mytools-openredirect --version
mytools-crlfinject --version
mytools-sstdetect --version
mytools-ssrfdetect --version
mytools-reconall --version
mytools-cred --version
```

---

## Uso

### Painel unificado
```bash
mytools
```
O menu oferece opções numéricas ou palavras-chave: `port`, `dir`, `recon`, `audit`, `dns/xfer`, `sub/subenum`, `dns-history`, `whois-history`, `ip-asn`, `tech`, `oas`, `gql`, `sourcemap`, `vcs`, `cfg`, `bak`, `dork`, `breach`, `soceng`, `leak`, `dark`, `rebind`, `dwt`, `amp`, `tunnel`, `dnssec`, `nsec`, `caa`, `secemail`, `spoof`, `smtpinject`, `smtpdown`, `templeti`, `attachbypass`, `addrbypass`, `linktrack`, `nullbyte`, `dblurl`, `ptraversal`, `rtlo`, `overlong`, `bominject`, `charsetbypass`, `openredirect`, `crlfinject`, `sstdetect`, `ssrfdetect`.

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
| `mytools-recon https://example.com` | Recon passivo rápido |
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
| `mytools-cfg http://target.com` | Config file detection |
| `mytools-bak http://target.com` | Backup file detection |
| `mytools-dork example.com` | Google dorking |
| `mytools-breach user@example.com` | Email breach check |
| `mytools-soceng example.com` | Social engineering recon |
| `mytools-leak example.com` | Paste/leak monitoring |
| `mytools-dark example.com` | Dark web monitoring |
| `mytools-rebind example.com` | DNS rebinding test |
| `mytools-dnssec example.com` | DNSSEC validation |
| `mytools-secemail example.com` | Email security (DMARC/SPF/DKIM) |
| `mytools-nullbyte https://example.com` | Null byte injection |
| `mytools-dblurl https://example.com` | Double URL encoding bypass |
| `mytools-ptraversal https://example.com` | Path traversal via encoding |
| `mytools-rtlo https://example.com` | RTL override bypass |
| `mytools-overlong https://example.com` | Overlong UTF-8 encoding |
| `mytools-bominject https://example.com` | BOM injection |
| `mytools-charsetbypass https://example.com` | Charset detection bypass |
| `mytools-openredirect https://example.com` | Open redirect detection |
| `mytools-crlfinject https://example.com` | CRLF injection detection |
| `mytools-sstdetect https://example.com` | SSTI detection |
| `mytools-ssrfdetect https://example.com` | SSRF detection |
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

### Controle de Cores
```bash
# Desativar cores (padrão NO_COLOR — https://no-color.org/)
export NO_COLOR=1
mytools
```

---

## Estrutura do Projeto

```
src/mytools/                    # Pacote principal
  __init__.py                   # __version__
  core/                         # Infraestrutura compartilhada
    utils.py                    # Cores, HTTP async, helpers, output
    cred.py                     # Gerenciador de credenciais (keyring)
    main.py                     # Menu interativo central
    reconall.py                 # Orquestrador: executa todos os módulos
  network/                      # Rede e portas
    portscanner.py              # Scanner de portas TCP
    dirscanner.py               # Scanner de diretórios HTTP
  web/                          # Web e HTTP
    webrecon.py                 # Reconhecimento passivo + CVE + WHOIS
    attackaudit.py              # Auditoria ofensiva/defensiva
    openapidiscovery.py         # OpenAPI/Swagger Discovery
    graphqlplayground.py        # GraphQL Playground Exposure
    sourcemapdiscovery.py       # Source Map Discovery
    techfingerprint.py          # Technology Fingerprint
    nullbyteinject.py           # Null Byte Injection
    doubleurlencode.py          # Double URL Encoding Bypass
    pathtraversal.py            # Path Traversal via Encoding
    rtloverride.py              # RTL Override + Zero-Width + Combining
    overlongencoding.py         # Overlong UTF-8 Encoding
    bominjection.py             # BOM Injection
    charsetbypass.py            # Charset Detection Bypass + Content-Type Mismatch
    openredirect.py             # Open Redirect Detection
    crlfinjection.py            # CRLF Injection Detection
    sstidetect.py               # SSTI Detection
    ssrfdetect.py               # SSRF Detection
  dns/                          # DNS e resolução
    dnstransfer.py              # DNS Zone Transfer
    subdomainenum.py            # Enumeração de subdomínios
    dnshistory.py               # Histórico DNS (OSINT)
    dnswatorture.py             # DNS Water Torture
    dnsamplification.py         # DNS Amplification Detection
    dnstunnel.py                # DNS Tunnel Detection
    dnssecvalidation.py         # DNSSEC Validation
    nsecwalking.py              # NSEC Walking
    caacheck.py                 # CAA Record Check
    dnsrebinding.py             # DNS Rebinding Detection
  whois/                        # WHOIS
    whoishistory.py             # Histórico WHOIS (OSINT)
  osint/                        # OSINT e reconhecimento
    emailbreachcheck.py         # Email Breach Check
    socialengrecon.py           # Social Engineering Recon
    pasteleak.py                # Paste/Leak Monitoring
    darkwebmonitor.py           # Dark Web Monitoring
    googledorking.py            # Google Dorking
    ipasninfo.py                # IP ASN/ISP Enrichment
  email/                        # Segurança de email
    emailsecurity.py            # DMARC/SPF/DKIM
    emailspoof.py               # Email Spoofing Analysis
    smtpinjection.py            # SMTP Header Injection
    smtpdowngrade.py            # SMTP Downgrade Attack
    emailtemplateinject.py      # Email Template Injection
    emailattachmentbypass.py    # Email Attachment Bypass
    emailaddressbypass.py       # Email Address Bypass
    emaillinktracking.py        # Email Link Tracking
  vcs/                          # Controle de versão
    vcsleak.py                  # VCS Leak Detection
  config/                       # Arquivos de configuração
    configfiledetect.py         # Config File Detection
    backupfiledetect.py         # Backup File Detection

tests/                          # Testes unitários (2604 testes)
  core/                         # test_utils, test_cred, test_reconall
  network/                      # test_portscanner, test_dirscanner
  web/                          # test_webrecon, test_attackaudit, ...
  dns/                          # test_dnstransfer, test_subdomainenum, ...
  whois/                        # test_whoishistory
  osint/                        # test_emailbreachcheck, ...
  email/                        # test_emailsecurity, ...
  vcs/                          # test_vcsleak
  config/                       # test_configfiledetect, ...

pyproject.toml                  # Configuração do projeto
```

---

## Desenvolvimento

### Rodar testes
```bash
poetry run pytest tests/ -v
```

### Lint
```bash
poetry run ruff check src/mytools/ tests/
poetry run basedpyright src/mytools/
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
- `pyreadline3>=3.5.6` — Readline para Windows (apenas Windows)

### Dev
- `pytest>=9.1.1` — Framework de testes
- `pytest-asyncio>=1.4.0` — Testes async
- `respx>=0.23.1` — Mock de httpx para testes
- `ruff>=0.15.20` — Linter/formatter
- `basedpyright>=1.39.8` — Type checker

---

## Aviso Legal

Este software é fornecido "como está", sem garantia de qualquer tipo. O autor não se responsabiliza pelo uso indevido destas ferramentas. Execute apenas em ambientes que você tenha autorização expressa para testar.

---

*nxt*
