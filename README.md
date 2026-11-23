# SecScan Agent - Agente Inteligente de Revisión de Seguridad

## Descripción

**SecScan Agent** es un agente inteligente de seguridad que analiza repositorios de código y archivos de logs para detectar vulnerabilidades comunes. Utiliza un sistema de **tools** (herramientas) y **skills** (habilidades) para razonar sobre el código, ejecutar análisis automatizados, y generar reportes priorizados.

### Problemática que resuelve

En el desarrollo de software, los equipos frecuentemente introducen vulnerabilidades de seguridad sin darse cuenta: secretos hardcodeados (API keys, contraseñas), dependencias con CVEs conocidos, inyecciones SQL, XSS, y configuraciones inseguras. Las revisiones manuales son lentas y propensas a errores. **SecScan Agent** automatiza este proceso usando IA.

## Cómo ejecutar

### Prerrequisitos

- Python 3.10 o superior
- pip

### Instalación

```bash
# Clonar el repositorio
git clone https://github.com/juanarzayus/AgentedeSeguridad.git
cd Agente

# Instalar dependencias
pip install -r requirements.txt

# Opcional: exportación a PDF (WeasyPrint)
pip install -r requirements-pdf.txt
```

> **PDF en Windows:** WeasyPrint necesita GTK3 instalado aparte
> ([instrucciones](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows)).
> Sin él, el reporte HTML funciona igual y desde el navegador se puede usar
> *Imprimir → Guardar como PDF*, que también está maquetado para A4.

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

# Generar reporte en PDF, en inglés
python main.py --target ./test_project --format pdf --lang en

# Ver ayuda completa
python main.py --help
```

### Demo rápida (con proyecto de prueba incluido)

```bash
# Ejecutar con el proyecto de prueba vulnerable incluido
python main.py --target ./test_project --logs ./test_project/logs --format html
```

Esto generará un reporte completo en `reports/security_report_<AAAAMMDD_HHMMSS>.html`.

### Interfaz gráfica local

```bash
python main.py --web
```

Abre en el navegador una interfaz para elegir la carpeta, el tipo de análisis y el idioma, y muestra en vivo
cómo el agente observa, planifica y ejecuta cada herramienta. Al terminar presenta el puntaje de riesgo, las
acciones prioritarias y permite abrir el reporte completo o descargarlo en PDF, JSON o HTML.

Opciones: `--port 8765` (puerto) y `--no-browser` (no abrir el navegador automáticamente).

La interfaz puede leer cualquier carpeta del equipo, así que está diseñada para que **solo la use quien la inició**:

| Control | Qué evita |
|---------|-----------|
| Escucha únicamente en `127.0.0.1` (no hay opción para exponerla) | Acceso desde otros equipos de la red |
| Token aleatorio en el enlace de la terminal → cookie `HttpOnly`, `SameSite=Strict` | Uso por otros usuarios o procesos del equipo |
| Validación del encabezado `Host` | Ataques de *DNS rebinding* desde páginas web maliciosas |
| Token CSRF obligatorio en cada `POST` | Que otra página lance análisis en tu nombre |
| CSP estricta sin scripts en línea; contenido insertado como texto | XSS a partir de rutas o hallazgos |
| Reportes servidos con `CSP: sandbox` | Que el JavaScript del reporte acceda a la API |
| Descargas por ID de análisis, nunca por ruta; selector que lista solo carpetas | Lectura arbitraria de archivos (*path traversal*) |
| Un análisis a la vez; sin subida de archivos | Abuso de recursos y archivos de terceros |
| Errores genéricos en el navegador (el detalle queda en la terminal) | Filtración de información interna |

### Formatos de reporte

| Formato | Para qué |
|---|---|
| `html` | Reporte interactivo: filtros por severidad y herramienta, búsqueda, tema claro/oscuro. Autocontenido (funciona sin internet). |
| `pdf` | El mismo reporte maquetado en A4, con encabezado, pie y numeración. Para entregar o archivar. |
| `json` | Integración con otras herramientas (incluye puntaje, veredicto y acciones prioritarias). |
| `text` | Texto plano para tickets o correos. |

Idiomas disponibles con `--lang`: `es` (por defecto) y `en`.

El reporte está pensado para tomar decisiones:

1. **Resumen ejecutivo** - puntaje de riesgo 0-100, veredicto ("No apto para producción", etc.) y distribución por severidad.
2. **Acciones prioritarias** - los hallazgos agrupados por la acción que los corrige (p. ej. "Rotar credenciales" resuelve 16 hallazgos), con severidad y esfuerzo estimado.
3. **OWASP Top 10 y archivos más afectados.**
4. **Actividad de amenazas** - los eventos de los logs se informan aparte de las vulnerabilidades del código: IPs atacantes, tipos de ataque y atacantes activos.
5. **Hallazgos detallados** - riesgo, corrección, CWE y el código con contexto. Los secretos aparecen siempre enmascarados, también en las líneas de contexto.
6. **Razonamiento del agente** - el plan que siguió y por qué eligió cada herramienta.

### Códigos de salida

| Código | Significado |
|--------|-------------|
| `0` | Sin hallazgos |
| `1` | Hallazgos de severidad ALTA, MEDIA o BAJA |
| `2` | Al menos un hallazgo CRÍTICO |
| `3` | Error de uso o de ejecución (argumento inválido, directorio inexistente, una herramienta falló, PDF no disponible) |

### Suprimir falsos positivos

- **En línea:** agregar `# secscan: ignore` (o `# nosec`) al final de la línea.
- **Por archivo o directorio:** crear un `.secscanignore` en la raíz del proyecto analizado, con un patrón glob por línea:

```
# fixtures de tests
tests/fixtures/
*.min.js
```

Además, el agente reduce falsos positivos por sí solo:

- **No analiza sus propios reportes** (llevan la marca `<meta name="generator" content="SecScan Agent">`): citan el código vulnerable que encontraron y se detectarían a sí mismos.
- **En Python entiende el contexto léxico** (`tools/source_context.py`): busca llamadas peligrosas (`eval(`, `render_template_string(`) solo en código, no en strings, comentarios o docstrings; y patrones de HTML/JS (`innerHTML`, `|safe`) solo dentro de strings que contienen HTML o plantillas.

Este repositorio incluye su propio `.secscanignore`, que excluye `test_project/` (vulnerable a propósito, se analiza por separado) y `tests/` (secretos falsos de prueba). Analizar el repositorio completo da **0 hallazgos**, y hay un test que lo verifica.

### Ejecutar los tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Estructura del proyecto

```
Agente/
├── main.py                  # Punto de entrada y CLI
├── requirements.txt         # Dependencias
├── requirements-pdf.txt     # Dependencia opcional para PDF (WeasyPrint)
├── requirements-dev.txt     # Dependencias de desarrollo (pytest)
├── README.md                # Este archivo
│
├── agent/                   # Núcleo del agente
│   ├── __init__.py
│   ├── orchestrator.py      # Orquestador principal (razonamiento + ejecución)
│   ├── findings.py          # Modelo Finding, enmascarado, deduplicación, supresiones
│   ├── ui.py                # Salida de terminal (rich) desacoplada del orquestador
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
│   ├── generator.py         # Punto de entrada: texto, JSON, HTML, PDF
│   ├── insights.py          # Puntaje de riesgo, veredicto, acciones, amenazas
│   ├── html_report.py       # Render Jinja2 → HTML / WeasyPrint → PDF
│   ├── i18n.py              # Textos del reporte (es, en)
│   ├── templates/           # Plantilla del reporte
│   └── assets/              # Fuentes (Inter, JetBrains Mono) e íconos (Lucide)
│
├── webapp/                  # Interfaz gráfica local (python main.py --web)
│   ├── server.py            # Servidor Flask/Waitress y controles de seguridad
│   ├── scans.py             # Ejecución en segundo plano y eventos en vivo
│   ├── i18n.py              # Textos de la interfaz (es, en)
│   ├── templates/           # Página principal y pantalla de sesión requerida
│   └── static/              # CSS y JavaScript (sin dependencias externas)
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

## Skills del agente

| Skill | Descripción |
|-------|-------------|
| **full_security_review** | Ejecuta todas las herramientas, prioriza hallazgos y genera reporte |
| **quick_scan** | Escaneo rápido enfocado en secretos y SQLi |
| **dependency_check** | Solo revisa dependencias inseguras |

Cada skill define qué herramientas puede usar; el planner omite (y lo deja registrado en el plan) las que no forman parte del skill.

## Tools del agente

| Tool | Función | Detecta |
|------|---------|---------|
| `SecretScanner` | Escanea código buscando secretos | API keys, passwords, tokens, claves privadas |
| `DependencyAudit` | Revisa dependencias contra CVEs | Paquetes con vulnerabilidades conocidas |
| `SQLiDetector` | Analiza código por inyección SQL (AST en Python, regex en otros lenguajes) | Consultas SQL concatenadas, f-strings, `.format()`, `%`; sigue variables y detecta input de `request.*` |
| `XSSDetector` | Detecta vulnerabilidades XSS | HTML sin escapar, `innerHTML`, `document.write` |
| `LogAnalyzer` | Analiza logs de acceso | Fuerza bruta, path traversal, SQL injection attempts |
| `ConfigAuditor` | Revisa archivos de configuración | DEBUG=True, CORS *, SECRET_KEY débil |

Cada hallazgo incluye su **CWE**, categoría **OWASP Top 10**, un nivel de **confianza** y, si varias herramientas detectaron lo mismo, cuáles (`also_detected_by`). Los secretos se enmascaran siempre antes de llegar al reporte.

## Reporte

El agente genera un reporte priorizado con severidades:

- **CRÍTICA** - Secretos expuestos, inyección SQL confirmada
- **ALTA** - Dependencias con CVE conocido, XSS
- **MEDIA** - Configuraciones inseguras, debug habilitado
- **BAJA** - Mejores prácticas, sugerencias de hardening

## Equipo

- Proyecto Final - Inteligencia Artificial
- Línea 4: Agentes Inteligentes con Tools y Skills

## Licencia

Proyecto académico - Universidad Santiago de Cali
