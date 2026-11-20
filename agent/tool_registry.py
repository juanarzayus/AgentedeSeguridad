"""
Tool Registry — Registro y gestión de herramientas del agente.

Este módulo implementa el patrón Registry para las tools del agente.
Cada tool se registra con su nombre, descripción, y función ejecutable.
El agente puede consultar qué tools tiene disponibles y ejecutarlas.
"""

from dataclasses import dataclass, field
from typing import Callable, Any


@dataclass
class ToolDefinition:
    """Define una herramienta disponible para el agente."""
    name: str
    description: str
    category: str
    execute: Callable  # Función que ejecuta la herramienta
    parameters: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Representación como diccionario (para el LLM/planner)."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "parameters": self.parameters,
        }


class ToolRegistry:
    """
    Registro central de herramientas del agente.
    
    Permite registrar, listar y ejecutar tools de forma dinámica.
    El agente consulta este registro para decidir qué herramientas usar.
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Registra una nueva herramienta."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition | None:
        """Obtiene una herramienta por su nombre."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        """Lista todas las herramientas registradas (formato para el planner)."""
        return [t.to_dict() for t in self._tools.values()]

    def list_by_category(self, category: str) -> list[ToolDefinition]:
        """Lista herramientas por categoría."""
        return [t for t in self._tools.values() if t.category == category]

    def execute_tool(self, name: str, **kwargs) -> Any:
        """
        Ejecuta una herramienta por su nombre con los parámetros dados.
        
        Returns:
            Resultado de la ejecución de la herramienta.
        
        Raises:
            ValueError: Si la herramienta no está registrada.
        """
        tool = self._tools.get(name)
        if tool is None:
            raise ValueError(f"Herramienta '{name}' no encontrada en el registro.")
        return tool.execute(**kwargs)

    @property
    def tool_count(self) -> int:
        """Número de herramientas registradas."""
        return len(self._tools)

    def __repr__(self) -> str:
        names = ", ".join(self._tools.keys())
        return f"ToolRegistry(tools=[{names}])"
