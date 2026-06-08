# MyTools

Suite de ferramentas de auditoria e reconhecimento web/network para ambientes de laboratório e alvos autorizados.

> **AVISO:** Este projeto é destinado exclusivamente para fins educacionais e de teste em ambientes autorizados. O uso irresponsável pode ser ilegal. Use com responsabilidade.

---

## Módulos

### 1. Painel Central (`main.py`)
Orquestrador do ecossistema com menu interativo colorido para alternar entre todas as subferramentas.

```bash
python main.py
```

### 2. Network PortScanner (`portscanner.py`)
Scanner de portas TCP com suporte a CIDR, banner grabbing e exportação JSON/CSV.

```bash
python portscanner.py 192.168.0.0/24 -p 22,80,443 -b
python portscanner.py scanme.nmap.org -p top100 -o resultado.json
```

### 3. Web Directory Scanner (`dirscanner.py`)
Fuzzing e descoberta de caminhos ocultos em servidores web com filtros de status code e extensões.

```bash
python dirscanner.py http://target.local -x php,txt,bak -s 200,403
python dirscanner.py http://127.0.0.1:8000 -w wordlist.txt
python dirscanner.py http://target.local --proxy http://proxy:8080 --delay 10
```

### 4. Web Passive Recon (`webrecon.py`)
Reconhecimento passivo: headers de segurança, fingerprinting, robots.txt e sitemap.xml.

```bash
python webrecon.py https://example.com
python webrecon.py https://example.com -o recon.json
python webrecon.py https://example.com --proxy http://proxy:8080
```

### 5. Deep Attack & Vulnerability Audit (`attackaudit.py`)
Auditoria red/blue com verificação de CORS, TLS, cookies, métodos HTTP perigosos e deep scan de arquivos sensíveis.

```bash
python attackaudit.py https://example.com --deep
python attackaudit.py https://example.com --deep -o audit.json
python attackaudit.py https://example.com --deep --proxy http://proxy:8080 --delay 5
```

---

## Instalação

### Pré-requisitos
- **Python 3.10+**

### Instalação (desenvolvimento)
```bash
git clone https://github.com/nxt/MyTools.git
cd MyTools
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
pip install -e ".[dev]"
```

### Execução direta
```bash
python main.py               # Painel unificado
python portscanner.py --help # Ajuda individual
```

---

## Uso

### Painel unificado
```bash
python main.py
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
| `python portscanner.py 127.0.0.1 -p 1-1024` | Scan TCP nas primeiras 1024 portas |
| `python dirscanner.py http://testphp.vulnweb.com -x php` | Busca por arquivos .php |
| `python webrecon.py https://google.com` | Recon passivo rápido |
| `python attackaudit.py https://example.com --deep` | Auditoria completa com deep scan |

### Proxy e Rate Limiting
Todos os módulos HTTP suportam proxy e rate limiting:

```bash
# Usar proxy
python dirscanner.py http://target.local --proxy http://proxy:8080

# Rate limiting (requests por segundo)
python dirscanner.py http://target.local --delay 10

# Proxy + rate limiting
python attackaudit.py https://target.local --deep --proxy http://proxy:8080 --delay 5
```

---

## Estrutura do Projeto

```
MyTools/
├── main.py            # Painel central
├── portscanner.py     # Scanner de portas TCP
├── dirscanner.py      # Scanner de diretórios HTTP
├── webrecon.py        # Reconhecimento passivo
├── attackaudit.py     # Auditoria ofensiva/defensiva
├── utils.py           # Código compartilhado (cores, helpers, sessões HTTP)
├── tests/             # Testes unitários
├── pyproject.toml     # Configuração do projeto
└── README.MD
```

---

## Desenvolvimento

### Rodar testes
```bash
python -m pytest tests/ -v
```

### Adicionar dependências de dev
```bash
pip install -e ".[dev]"
```

---

## Dependências

### Runtime
- `requests>=2.31.0` — HTTP client com sessions, proxy, retry
- `beautifulsoup4>=4.12.0` — Parser HTML avançado

### Dev
- `pytest>=8.0` — Framework de testes
- `responses>=0.25` — Mock de requests para testes

---

## Aviso Legal

Este software é fornecido "como está", sem garantia de qualquer tipo. O autor não se responsabiliza pelo uso indevido destas ferramentas. Execute apenas em ambimentos que você tenha autorização expressa para testar.

---

*nxt*
