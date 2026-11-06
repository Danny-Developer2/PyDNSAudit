# PyDNSAudit

Herramienta profesional de auditoría de seguridad DNS, escrita en Python puro.

PyDNSAudit evalúa los registros públicos de un dominio, las políticas de autenticacón de correo (SPF, DMARC y DKIM) y la exposición de subdominios e información interna. Está diseñada para auditorías autorizadas y **no realiza transferencia de zona ni técnicas invasivas**.

> ⚠️ **Uso exclusivo para auditorías autorizadas.** No utilices esta herramienta contra dominios sin autorización expresa y por escrito.

---

## Características

| Área | Comprobaciones |
| --- | --- |
| Registros | A, AAAA, MX, NS, TXT, CNAME y SOA |
| SPF | Política ausente, `+all` permisivo, límite de consultas DNS, delegación con `include` |
| DMARC | Política ausente, `p=none`, subdominios sin proteger, porcentaje parcial, informes |
| DKIM | Selectores habituales, clave vacía, clave corta, tipo de clave inusual |
| Subdominios | Enumeración con lista reducida de nombres habituales |
| Exposición | Entornos no productivos, servicios de administración, IP internas, DNS comodín |

Cada hallazgo incluye evidencia, recomendación y referencias técnicas.

## Niveles de severidad

| Nivel | Significado |
| --- | --- |
| `confirmado` | Problema verificado con evidencia directa |
| `probable` | Muy probable, pendiente de validación manual |
| `potencial` | Posible problema en determinados contextos |
| `indicio` | Dato observable que puede ser relevante |
| `recomendacion` | Mejora de endurecimiento, no es una vulnerabilidad |

## Requisitos

- Python 3.11 o superior
- Acceso de salida a los servidores DNS (puerto 53)
- Sin dependencias externas de sistema

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso rápido

```bash
# Auditoría completa
pydnsaudit scan ejemplo.com --confirm-authorized

# Con alcance definido en un fichero
pydnsaudit scan ejemplo.com --scope ./scope.json

# Generar informe HTML
pydnsaudit scan ejemplo.com --confirm-authorized -o informe --format html

# Omitir la enumeración de subdominios (más rápido)
pydnsaudit scan ejemplo.com --confirm-authorized --no-subdomains

# Probar selectores DKIM concretos
pydnsaudit scan ejemplo.com --confirm-authorized --dkim-selectors selector1,google

# Usar un resolver concreto
pydnsaudit scan ejemplo.com --confirm-authorized --nameserver 8.8.8.8
```

### Opciones principales

| Opción | Descripción |
| --- | --- |
| `--scope` | Fichero JSON con el alcance autorizado |
| `--confirm-authorized` | Declara que se dispone de autorización expresa |
| `--nameserver` | Resolver DNS concreto (por defecto, el del sistema) |
| `--timeout` / `-t` | Tiempo de espera por consulta |
| `--concurrency` / `-c` | Consultas simultáneas |
| `--rate-limit` | Consultas por segundo |
| `--dkim-selectors` | Selectores DKIM separados por comas |
| `--no-spf` | Omitir el análisis SPF |
| `--no-dmarc` | Omitir el análisis DMARC |
| `--no-subdomains` | Omitir la enumeración de subdominios |
| `--output` / `-o` | Ruta del informe (se añade la extensión) |
| `--format` / `-f` | `json`, `csv` o `html` |
| `--log-file` | Volcar el registro a fichero |
| `--verbose` / `-v` | Registro detallado |

## Control de autorización

La herramienta no ejecuta el análisis salvo que se cumpla una de estas dos condiciones:

1. Se proporciona `--confirm-authorized`.
2. Se proporciona `--scope` con un fichero JSON cuyo `authorized_targets` incluya el dominio o un dominio padre.

Formato del fichero de alcance:

```json
{
  "name": "Auditoría mensual",
  "authorized_targets": ["ejemplo.com"]
}
```

## Uso como biblioteca

```python
import asyncio
from pathlib import Path

from pydnsaudit.config import AuditConfig
from pydnsaudit.core.auditor import Auditor
from pydnsaudit.export import export_result


async def main():
    config = AuditConfig(target="ejemplo.com", confirm_authorized=True)
    result = await Auditor(config).run()

    if result.spf:
        print(f"SPF: {result.spf.raw or 'ausente'}")
    if result.dmarc:
        print(f"DMARC: {result.dmarc.policy or 'ausente'}")

    export_result(result, Path("informe"), "html")


asyncio.run(main())
```

## Formatos de salida

- **JSON**: esquema versionado (`pydnsaudit/audit-result`, versión 1).
- **CSV**: una fila por hallazgo, adecuado para hojas de cálculo.
- **HTML**: informe autónomo con SPF, DMARC, registros, subdominios y hallazgos.

## Calidad del proyecto

| Comprobación | Resultado |
| --- | --- |
| Pruebas (`pytest`) | 106 superadas |
| Cobertura | 85 % |
| Tipos (`mypy --strict`) | Sin errores |
| Estilo (`ruff`) | Sin avisos |

Las pruebas simulan el resolvedor DNS, por lo que no dependen de la red ni de dominios concretos.

## Estructura del proyecto

```
src/pydnsaudit/
├── core/            # Resolución, SPF, DMARC, DKIM, subdominios y exposición
├── export/          # Exportadores JSON, CSV y HTML
├── utils/           # Dominio, registro y validadores
├── cli.py           # Interfaz de línea de comandos (Typer + Rich)
├── config.py        # Configuración y catálogos
├── models.py        # Modelos de datos (Pydantic)
└── exceptions.py    # Excepciones propias

tests/
├── unit/            # Pruebas unitarias por módulo
└── integration/     # Pruebas con el resolvedor simulado
```

## Limitaciones

- La enumeración de subdominios usa una lista reducida de nombres habituales, no fuerza bruta.
- La detección de DKIM depende de los selectores indicados o de los habituales.
- La comprobación de DNS comodín realiza una única consulta con un nombre aleatorio.
- Los resultados son indicativos; los hallazgos `probable` y `potencial` requieren validación manual.

## Licencia

MIT. Consulta el fichero `LICENSE`.

## Aviso legal

Esta herramienta se distribuye con fines educativos y profesionales. El uso contra sistemas sin autorización es ilegal y es responsabilidad exclusiva de quien la ejecuta.
