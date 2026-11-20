# 🛡️ SecScan Agent — Agente Inteligente de Revisión de Seguridad

## Descripción

**SecScan Agent** es un agente inteligente de seguridad que analiza repositorios de código y archivos de logs para detectar vulnerabilidades comunes. Utiliza un sistema de **tools** (herramientas) y **skills** (habilidades) para razonar sobre el código, ejecutar análisis automatizados, y generar reportes priorizados.

### Problemática que resuelve

En el desarrollo de software, los equipos frecuentemente introducen vulnerabilidades de seguridad sin darse cuenta: secretos hardcodeados (API keys, contraseñas), dependencias con CVEs conocidos, inyecciones SQL, XSS, y configuraciones inseguras. Las revisiones manuales son lentas y propensas a errores. **SecScan Agent** automatiza este proceso usando IA.

## 🏗️ Arquitectura Técnica

```
┌─────────────────────────────────────────────────┐
│              SecScan Agent (Orquestador)         │
│                                                   │
│  ┌─────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Planner │→ │ Executor │→ │ Report Builder │  │
│  │ (LLM)   │  │ (Tools)  │  │ (Aggregator)   │  │
│  └─────────┘  └──────────┘  └────────────────┘  │
│       ↓            ↓                              │
│  ┌─────────────────────────────────────────────┐  │
│  │              Tool Registry                   │  │
│  │                                               │  │
│  │  🔑 SecretScanner    — Detecta secretos      │  │
│  │  📦 DependencyAudit  — Audita dependencias   │  │
│  │  💉 SQLiDetector     — Detecta inyección SQL │  │
│  │  🌐 XSSDetector      — Detecta XSS           │  │
│  │  📋 LogAnalyzer      — Analiza logs           │  │
│  │  ⚙️  ConfigAuditor   — Audita configuración  │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## 🚀 Cómo ejecutar

### Prerrequisitos

- Python 3.10 o superior
- pip

### Instalación

```bash
# Clonar el repositorio
git clone <url-del-repo>
cd Agente

# Instalar dependencias
pip install -r requirements.txt
```

### Uso

```bash
# Analizar un directorio de código
python main.py --target ./test_project

# Analizar archivos de logs
python main.py --target ./test_project --logs ./test_project/logs

# Generar reporte en HTML
python main.py --target ./test_project --format html

# Generar reporte en JSON
python main.py --target ./test_project --format json

# Ver ayuda completa
python main.py --help
```

### Demo rápida (con proyecto de prueba incluido)

```bash
# Ejecutar con el proyecto de prueba vulnerable incluido
python main.py --target ./test_project --logs ./test_project/logs --format html
```

Esto generará un reporte completo en `reports/security_report.html`.

## 📁 Estructura del Proyecto

```
Agente/
├── main.py                  # Punto de entrada y CLI
├── requirements.txt         # Dependencias
├── README.md                # Este archivo
│
├── agent/                   # Núcleo del agente
│   ├── __init__.py
│   ├── orchestrator.py      # Orquestador principal (razonamiento + ejecución)
│   ├── planner.py           # Planificador basado en reglas
│   └── tool_registry.py     # Registro y gestión de herramientas
│
├── tools/                   # Herramientas (Tools) del agente
│   ├── __init__.py
│   ├── secret_scanner.py    # Detector de secretos expuestos
│   ├── dependency_audit.py  # Auditor de dependencias inseguras
│   ├── sqli_detector.py     # Detector de inyección SQL
│   ├── xss_detector.py      # Detector de Cross-Site Scripting
│   ├── log_analyzer.py      # Analizador de logs de seguridad
│   └── config_auditor.py    # Auditor de configuraciones
│
├── skills/                  # Skills de alto nivel
│   ├── __init__.py
│   └── security_review.py   # Skill: revisión de seguridad completa
│
├── report/                  # Generación de reportes
│   ├── __init__.py
│   └── generator.py         # Generador de reportes (texto, HTML, JSON)
│
└── test_project/            # Proyecto de prueba con vulnerabilidades intencionales
    ├── app.py               # App Flask con vulnerabilidades
    ├── config.py            # Configuración con secretos expuestos
    ├── database.py          # Código con inyección SQL
    ├── requirements.txt     # Dependencias desactualizadas
    ├── .env                 # Variables de entorno con secretos
    └── logs/
        └── access.log       # Logs con patrones sospechosos
```

## 🧠 Skills del Agente

| Skill | Descripción |
|-------|-------------|
| **full_security_review** | Ejecuta todas las herramientas, prioriza hallazgos y genera reporte |
| **quick_scan** | Escaneo rápido enfocado en secretos y SQLi |
| **dependency_check** | Solo revisa dependencias inseguras |

## 🔧 Tools del Agente

| Tool | Función | Detecta |
|------|---------|---------|
| `SecretScanner` | Escanea código buscando secretos | API keys, passwords, tokens, claves privadas |
| `DependencyAudit` | Revisa dependencias contra CVEs | Paquetes con vulnerabilidades conocidas |
| `SQLiDetector` | Analiza código por inyección SQL | Consultas SQL concatenadas, f-strings en queries |
| `XSSDetector` | Detecta vulnerabilidades XSS | HTML sin escapar, `innerHTML`, `document.write` |
| `LogAnalyzer` | Analiza logs de acceso | Fuerza bruta, path traversal, SQL injection attempts |
| `ConfigAuditor` | Revisa archivos de configuración | DEBUG=True, CORS *, SECRET_KEY débil |

## 📊 Ejemplo de Reporte

El agente genera un reporte priorizado con severidades:

- 🔴 **CRÍTICA** — Secretos expuestos, inyección SQL confirmada
- 🟠 **ALTA** — Dependencias con CVE conocido, XSS
- 🟡 **MEDIA** — Configuraciones inseguras, debug habilitado
- 🔵 **BAJA** — Mejores prácticas, sugerencias de hardening

## 👥 Equipo

- Proyecto Final — Inteligencia Artificial
- Línea 4: Agentes Inteligentes con Tools y Skills

## 📄 Licencia

Proyecto académico — Universidad
