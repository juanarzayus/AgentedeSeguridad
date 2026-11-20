# 🎤 Guía de Presentación (Pitch) — SecScan Agent
**Asignatura:** Inteligencia Artificial  
**Línea:** 4. Agentes Inteligentes con Tools y Skills  
**Duración Máxima:** 8 minutos  
**Distribución del Tiempo:**

| Minutos | Sección | Objetivo |
| :--- | :--- | :--- |
| **0:00 - 1:30** (1.5 min) | **1. Contexto y Problema** | ¿Qué necesidad real resolvemos y por qué los métodos manuales fallan? |
| **1:30 - 3:30** (2.0 min) | **2. Arquitectura Técnica** | Explicar el ciclo del agente, Tool Registry, Planner y Skills. |
| **3:30 - 6:30** (3.0 min) | **3. Demostración en Vivo** | Ejecución en terminal/Colab, razonamiento paso a paso y reporte HTML. |
| **6:30 - 8:00** (1.5 min) | **4. Conclusiones y Mejoras** | Resultados obtenidos, métricas e impacto futuro. |

---

## 📌 Diapositiva por Diapositiva & Guion de Exposición

### Diapositiva 1: Portada (0:00 - 0:20)
- **Título:** SecScan Agent — Agente Inteligente de Revisión de Seguridad
- **Subtítulo:** Detección autónoma y priorizada de vulnerabilidades en código y logs mediante Tools & Skills
- **Integrantes:** [Nombres de los integrantes del equipo]
- **Qué decir:**
  > *"Buenos días profesor y compañeros. Hoy les presentamos SecScan Agent, una solución basada en Agentes Inteligentes diseñada para automatizar auditorías de ciberseguridad en repositorios y logs de servidores."*

---

### Diapositiva 2: Contexto y Problemática (0:20 - 1:30)
- **El Dolor del Negocio / Desarrolladores:**
  - El 80% de las brechas de datos se originan por credenciales expuestas en repositorios públicos/privados o fallas en dependencias de terceros.
  - El código se libera a un ritmo más rápido de lo que un equipo de seguridad manual puede auditar.
  - Las herramientas estáticas convencionales (SAST simples) generan cientos de alertas sin contexto ni orden de prioridad, saturando a los ingenieros.
- **Qué decir:**
  > *"En el desarrollo moderno, un desarrollador comete fácilmente el error de subir un archivo `.env` con claves de AWS o bases de datos, concatenar una consulta SQL o usar librerías desactualizadas. Las revisiones manuales son lentas y costosas. SecScan Agent interviene como un auditor virtual que no solo busca errores, sino que comprende el contexto de la aplicación, decide qué herramientas emplear y entrega un reporte priorizado por severidad."*

---

### Diapositiva 3: Arquitectura Técnica y Paradigma del Agente (1:30 - 2:30)
- **El Ciclo del Agente (Reasoning Loop):**
  1. **OBSERVAR:** Escanea la estructura del proyecto (detecta lenguajes como Python/JS, archivos de configuración, `.env`, `requirements.txt` y logs).
  2. **RAZONAR:** El **Planner** evalúa los hallazgos del contexto y formula un plan de acción ordenado por criticidad (ej. "Como hay `.env`, la prioridad #1 es SecretScanner").
  3. **ACTUAR:** Ejecuta herramientas especializadas a través de un **ToolRegistry** desacoplado.
  4. **REPORTAR:** Consolida hallazgos deduplicados y los clasifica en 4 niveles de riesgo (Crítica, Alta, Media, Baja).
- **Qué decir:**
  > *"Técnicamente, nuestro agente no es un script monolítico. Implementa el ciclo cognitivo 'Observar, Razonar, Actuar y Reportar'. Cuenta con un Planner que evalúa qué tipo de proyecto tiene enfrente y un Tool Registry donde desacoplamos cada motor de detección como una herramienta independiente."*

---

### Diapositiva 4: Tools y Skills Implementados (2:30 - 3:30)
- **Catálogo de Tools:**
  - `SecretScanner`: Detección con regex de alta precisión y enmascaramiento de tokens de AWS, GitHub, Stripe, DB URLs y contraseñas.
  - `DependencyAudit`: Comparador de versiones de librerías contra base de CVEs conocidos.
  - `SQLiDetector`: Análisis estático de consultas construidas con concatenación, f-strings y `.format()`.
  - `XSSDetector`: Identificación de renderizado inseguro (`innerHTML`, templates con `|safe`, `render_template_string`).
  - `LogAnalyzer`: Detección en registros web de ataques activos (ataques de fuerza bruta, escáneres como sqlmap y path traversal).
  - `ConfigAuditor`: Revisión de malas prácticas (`DEBUG=True`, CORS permisivo `*`, SECRET_KEY débil).
- **Skills de Alto Nivel:**
  - `full_security_review` (Revisión integral)
  - `quick_scan` (Escaneo rápido de críticos)
  - `dependency_check` (Auditoría de cadena de suministro)
- **Qué decir:**
  > *"Cumpliendo con la rúbrica de la línea 4, definimos formalmente 'Tools' y 'Skills'. Las Tools son las capacidades atómicas de análisis, mientras que los Skills son flujos de alto nivel que el agente orquesta según la necesidad del usuario."*

---

### Diapositiva 5: Demostración en Vivo (3:30 - 6:30)
- **Pasos a demostrar en pantalla:**
  1. Mostrar brevemente el proyecto vulnerable `test_project` (explicar que contiene una app Flask, `.env` con claves, dependencias desactualizadas y un log con ataques reales de `sqlmap` e intentos de fuerza bruta).
  2. Ejecutar el comando:
     ```bash
     python main.py --target ./test_project --logs ./test_project/logs --format html
     ```
  3. Resaltar en la consola la salida en colores donde se ve el **Razonamiento del Agente (Fase 1 y 2)**:
     - Cómo detectó que había archivos `.env` y programó `secret_scanner`.
     - Cómo detectó `requirements.txt` y activó `dependency_audit`.
     - Cómo detectó logs con actividad sospechosa y ejecutó `log_analyzer`.
  4. Abrir en el navegador el archivo `reports/security_report_*.html`:
     - Mostrar las tarjetas métricas (Total, Críticos, Altos, Medios, Bajos).
     - Mostrar la tabla de hallazgos con el código vulnerable y la **recomendación de mitigación**.
     - Mostrar el **Plan de Ejecución** registrado en el reporte.
- **Qué decir:**
  > *"Vamos a la ejecución en vivo. Lanzamos el agente. Observen la consola: el agente primero observa 6 archivos, razona que necesita 5 herramientas específicas, ejecuta cada una en milisegundos y compila 80 vulnerabilidades. Al abrir el reporte HTML interactivo, cualquier desarrollador o CISO puede ver de un vistazo qué arreglar primero."*

---

### Diapositiva 6: Conclusiones y Trabajo Futuro (6:30 - 8:00)
- **Conclusiones:**
  - Se logró un agente funcional, modular y extensible con 100% de cumplimiento de los criterios de evaluación.
  - La arquitectura basada en Registry permite agregar nuevas herramientas (ej. escáner de contenedores Docker) sin modificar el núcleo del agente.
  - Suite de 9 pruebas unitarias automatizadas (`unittest`) que garantizan la robustez y calidad del software.
- **Mejoras Futuras:**
  - Integración con LLMs vía API (OpenAI/Gemini/Anthropic) para generar parches y pull requests automáticos de corrección de código.
  - Conexión directa a bases de datos de vulnerabilidades en tiempo real (NVD / OSV.dev).
  - Integración como bot en pipelines de GitHub Actions (CI/CD).
- **Qué decir:**
  > *"En conclusión, SecScan Agent demuestra cómo la Inteligencia Artificial aplicada a través de agentes con Tools y Skills puede elevar la seguridad del software de forma inmediata. A futuro, el siguiente paso es conectar el agente a un LLM para que no solo detecte el problema, sino que cree automáticamente un Pull Request con el código corregido. Muchas gracias por su atención y quedamos atentos a sus preguntas."*

---

## ❓ Preguntas Frecuentes de Profesores y Cómo Responderlas

1. **¿Por qué esto califica como un Agente Inteligente y no simplemente como un script de bash o python?**
   - **Respuesta:** *"Un script tradicional ejecuta una secuencia fija y rígida de pasos sin importar la entrada. Nuestro agente implementa un ciclo de percepción y razonamiento: primero inspecciona el entorno (Observación), evalúa heurísticamente qué riesgos aplican al contexto encontrado (Razonamiento del Planner), selecciona dinámicamente qué herramientas del Registry disparar (Acción) y prioriza los resultados. Además, la arquitectura modular con Skills y Tools sigue exactamente el estándar de diseño de agentes inteligentes."*

2. **¿Cómo se manejan los falsos positivos en el escaneo de secretos?**
   - **Respuesta:** *"El `SecretScanner` utiliza expresiones regulares adaptadas a firmas oficiales (como claves de AWS `AKIA...` o tokens de GitHub `ghp_...`), y excluye deliberadamente comentarios con palabras clave como 'example' o estructuras de prueba. A futuro, un clasificador de entropía de Shannon o un LLM servirá como segundo filtro de validación."*

3. **¿Cómo se priorizan las vulnerabilidades?**
   - **Respuesta:** *"Utilizamos una escala estándar de severidad (Crítica, Alta, Media, Baja). Lo crítico engloba secretos expuestos con acceso inmediato a infraestructura e inyección SQL directa; lo alto corresponde a dependencias con CVEs comprobados y XSS; lo medio a configuraciones permisivas de debug; y lo bajo a buenas prácticas."*
