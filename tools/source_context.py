"""
Contexto léxico de archivos Python para reducir falsos positivos.

Un detector basado en regex no distingue entre `eval(x)` (código) y el texto
"eval() ejecuta código" dentro de un string o un docstring. Con `tokenize`
separamos tres vistas de cada archivo:

- `code`: el código con el contenido de los strings y comentarios borrado
  (cada literal se reemplaza por `""`). Sirve para patrones de llamadas.
- `markup_lines`: líneas que pertenecen a un string que parece HTML/plantilla
  (contiene `<`, `{{` o `{%`). Sirve para patrones de HTML/JS embebido.
- `doc_lines`: líneas de docstrings y comentarios: texto, no código.

Si el archivo no se puede tokenizar (sintaxis inválida), se devuelve None y el
detector analiza las líneas tal cual, como antes.
"""

from __future__ import annotations

import io
import tokenize
from dataclasses import dataclass, field

MARKUP_HINTS = ("<", "{{", "{%")
_SKIP_BEFORE_DOCSTRING = {tokenize.NEWLINE, tokenize.NL, tokenize.INDENT, tokenize.DEDENT,
                          tokenize.COMMENT, tokenize.ENCODING}


@dataclass
class PythonViews:
    code: list[str]
    markup_lines: set[int] = field(default_factory=set)
    doc_lines: set[int] = field(default_factory=set)


def _is_start(tok) -> bool:
    return tokenize.tok_name[tok.type].endswith("STRING_START")  # FSTRING_START, TSTRING_START


def _is_end(tok) -> bool:
    return tokenize.tok_name[tok.type].endswith("STRING_END")


def python_views(text: str) -> PythonViews | None:
    lines = text.splitlines(keepends=True)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return None

    grid = [list(line) for line in lines]
    spans: list[tuple[tuple[int, int], tuple[int, int], bool]] = []  # (inicio, fin, es_docstring)

    prev_significant = None
    depth, fstart = 0, None
    for idx, tok in enumerate(tokens):
        if _is_start(tok):
            if depth == 0:
                fstart = tok
            depth += 1
            continue
        if _is_end(tok):
            depth -= 1
            if depth == 0 and fstart is not None:
                spans.append((fstart.start, tok.end, False))
                prev_significant = tok
            continue
        if depth:
            continue
        if tok.type == tokenize.STRING:
            # Docstring = string que forma una sentencia por sí solo
            starts_statement = prev_significant is None or prev_significant.type in _SKIP_BEFORE_DOCSTRING
            j = idx + 1
            while j < len(tokens) and tokens[j].type in (tokenize.NL, tokenize.COMMENT):
                j += 1
            following = tokens[j] if j < len(tokens) else None
            is_doc = starts_statement and (following is None or following.type in (tokenize.NEWLINE, tokenize.ENDMARKER))
            spans.append((tok.start, tok.end, is_doc))
        elif tok.type == tokenize.COMMENT:
            row, col = tok.start
            grid[row - 1][col:col + len(tok.string)] = " " * len(tok.string)
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            prev_significant = tok

    views = PythonViews(code=[])
    for (srow, scol), (erow, ecol), is_doc in spans:
        source = "".join(lines[srow - 1:erow]) if srow != erow else lines[srow - 1][scol:ecol]
        rows = range(srow, erow + 1)
        if is_doc:
            views.doc_lines.update(rows)
        elif any(h in source for h in MARKUP_HINTS):
            views.markup_lines.update(rows)
        # Borrar el literal en la vista de código, dejando `""` en su lugar
        for row in rows:
            start = scol if row == srow else 0
            end = ecol if row == erow else len(lines[row - 1].rstrip("\r\n"))
            grid[row - 1][start:end] = list(" " * (end - start))
        if grid[srow - 1][scol:scol + 2] == [" ", " "]:
            grid[srow - 1][scol:scol + 2] = ['"', '"']

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            views.doc_lines.add(i)
    views.code = ["".join(chars) for chars in grid]
    return views
