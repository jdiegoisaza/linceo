# ADR-000: Arquitectura base y alcance del v0.1

- **Estado:** Aceptado
- **Fecha:** 2026-09-03
- **Mantenedor:** juan.diego-13@hotmail.com

## Resumen

Este documento fija el alcance del v0.1 de un orquestador de herramientas DevSecOps en
Python, licenciado Apache-2.0, y traduce cinco restricciones de portabilidad no
negociables en decisiones de arquitectura concretas y verificables. Referencia
conceptual: `bancolombia/devsecops-engine-tools` (AGPL-3.0). Este proyecto se diseña
desde cero, sin reutilizar su código — ver §12 (Procedencia y licencia).

Formato de cada decisión en este documento: opción elegida, alternativas descartadas,
motivo del descarte y, donde aplica, el mecanismo que la vuelve verificable en CI en
vez de aspiracional.

---

## §1. Alcance del v0.1 y no-objetivos

### En alcance

- Contratos (puertos): `ContextProvider`, `ToolExecutor`, `ToolIntegration`.
- Orquestación: ejecución de N herramientas en un run, con estado por ejecución.
- Normalización: modelo `Finding` propio, mapa de severidad versionado (§6).
- Gate: umbrales configurables + baseline con caducidad obligatoria (§8.1, §8.2).
- Reporting: consola, JSON canónico, SARIF 2.1.0 (§7).
- CLI (§8).
- Proveedores de contexto de referencia: `local` y `azure_devops` (§10).
- Integraciones de herramienta de referencia: Gitleaks y Trivy (§10).
- Imagen de contenedor como vía de distribución principal (§4, R4).

### Invariante de aceptación: N ejecuciones, un veredicto

El modelo de resultado y el gate nacen soportando **N ejecuciones de herramienta en un
mismo run, con un único veredicto agregado y un único código de salida** (detalle
completo en §5). El CLI del v0.1 sigue exponiendo una categoría por invocación
(`scan secrets`, `scan sca`), pero eso es una restricción de superficie, no del
núcleo.

Se declara como invariante de aceptación del v0.1: *ninguna ampliación futura del CLI
que permita correr más herramientas en un run puede exigir cambiar `RunResult`, la
firma del gate ni el esquema del reporte*. Si una ampliación así lo exige, el v0.1 se
diseñó mal.

Razón: con un exit code y un reporte por herramienta, el producto es un envoltorio de
`gitleaks` y quien lo consume reconcilia los resultados a mano. El orquestador empieza
a existir en el momento en que produce un veredicto único sobre evidencia de varias
fuentes — eso es lo que un pipeline no puede montar por sí mismo con un `&&` entre dos
comandos.

### Orden de construcción y criterio de release

| Paso | Entregable |
|---|---|
| 1 | Núcleo (contratos, orquestación de una ejecución, `RunResult`, gate, reporting) con adaptadores falsos (§11) |
| 2 | Integración Gitleaks + proveedor `local` |
| 3 | **Checkpoint de revisión de contrato** (ver abajo) |
| 4 | Integración Trivy (SCA) + proveedor `azure_devops` |
| 5 | v0.1 público |

El orden no cambia por ampliar el alcance a dos herramientas y dos proveedores: solo
se mueve la etiqueta del release. Un orquestador con un solo escáner no es publicable
como v0.1 — es un prototipo del núcleo.

**Checkpoint de revisión de contrato**, entre los pasos 2 y 4: entregable escrito que
responde explícitamente si `Finding`, `ToolExecutor`, el mapa de severidad y el
esquema de configuración quedaron modelados alrededor de las particularidades de
Gitleaks (que no emite severidad, no tiene CVSS, no referencia paquetes). Corregir
antes de que Trivy — el segundo consumidor — fosilice el error copiándolo.

#### Resultado del checkpoint, ejecutado tras la integración de Gitleaks (2026-09-13)

Respuesta explícita a la pregunta que este checkpoint exige responder: `Finding`, el
mapa de severidad y el esquema de configuración superan la revisión sin cambios — nada
en ellos asume que una herramienta carece de severidad nativa, ni codifica ninguna otra
particularidad de Gitleaks. El puerto `ToolExecutor` en sí tampoco arrastra sesgo
alguno: su firma (`argv`, `env`, `cwd` → `ProcessResult`) ya era neutral respecto a qué
binario se invoca. Donde sí aparecieron cuatro grietas, las cuatro en `core/` y las
cuatro por la misma causa — generalizar desde un único consumidor real —, fue en el
contrato de `ToolIntegration` y en las piezas que lo rodean: su doble de pruebas
(`FakeToolExecutor`) y el modelo de ejecución (`ToolExecution`). Corregidas aquí, antes
de que Trivy — el segundo consumidor — las fosilizara copiándolas:

1. **`ToolIntegration.name`/`version`/`category` como atributos asignables.** El
   `Protocol` los declaraba como atributos de instancia planos, lo que exige que toda
   implementación exponga un atributo mutable — y por tanto impide que una integración
   sea un dataclass congelado, el patrón que usa el resto del dominio (`ProcessResult`,
   `DataSource`, `ToolExecution`, `ExecutionContext`). Corregido: los tres se declaran
   ahora como propiedades de solo lectura en el `Protocol`; un dataclass congelado, un
   atributo mutable o una propiedad real lo satisfacen igual.
2. **`detect_version` fuera del contrato.** Gitleaks lo resolvió como un `staticmethod`
   propio, sin que el `Protocol` dijera nada sobre cuándo ni cómo se obtiene la versión
   de una herramienta antes de que exista una instancia de su integración — Trivy
   habría tenido que reinventar la misma solución sin garantía de que coincidiera en
   firma ni en semántica. Corregido: `detect_version(executor)` es ahora parte
   explícita de `ToolIntegration`, declarado como método estático del *tipo* — se
   invoca `NombreIntegration.detect_version(executor)` antes de construir la
   integración, nunca sobre una instancia — con su contrato de excepciones documentado
   en el propio `Protocol`.
3. **`FakeToolExecutor` indexaba solo por nombre de binario.** No distinguía dos
   invocaciones del mismo binario con propósitos distintos (`gitleaks version` frente a
   `gitleaks detect`), lo que obligaba a los tests de CLI a sustituir `detect_version`
   completo por un stub para sortear la limitación del fake, en vez de grabar cada
   invocación por separado. Corregido: `FakeToolExecutor` indexa ahora por patrón de
   argv — el prefijo de tokens que identifica la invocación, p. ej. `("gitleaks",
   "version")` frente a `("gitleaks", "detect")` —, con el patrón más específico que
   coincide ganando; los tests de CLI ya no necesitan sustituir `detect_version`.
4. **`ExecutionStatus.SKIPPED` sin un lugar para un mensaje accionable.** El CLI
   resolvía esto con un preflight propio que repetía, por su cuenta, la misma detección
   de binario ausente que `engine.run` ya hace internamente — dos caminos para el mismo
   hecho, uno de ellos silencioso. Corregido: `ToolExecution` lleva ahora un campo
   `message` opcional, y `ToolIntegration` declara `missing_binary_hint()` como parte
   de su contrato; `engine._execute_one` es el único lugar que decide cuándo un binario
   ausente produce un mensaje accionable, y el CLI se limita a mostrar
   `ToolExecution.message` cuando existe, sin conocer por su cuenta qué herramienta lo
   produjo ni por qué.

### No-objetivos explícitos del v0.1

Cada uno con la razón por la que queda fuera, no solo la lista:

| No-objetivo | Razón |
|---|---|
| Servidor, API HTTP o base de datos | Contradice R3 (sin estado compartido, sin backend propio) directamente. |
| Estado persistido entre ejecuciones | Cada ejecución es autocontenida (R3); persistencia es responsabilidad del sistema receptor. |
| Motor de política con DSL (Rego/CEL, plugins de política) | Es superficie de diseño que un mantenedor único no debe pagar sin usuarios que la pidan. El gate por umbrales + baseline (§8.1, §8.2) cubre el caso de uso real sin ese coste. |
| Telemetría o analítica de cualquier tipo | Restricción no negociable; cero telemetría (R2). |
| UI web | Fuera del criterio "CLI es el producto" (§8); sin servidor que la sirva (R3). |
| Publicación directa a DefectDojo | Ver nota abajo — se aplaza, no se descarta. |
| Escaneo de imágenes de contenedor con registries autenticados | Exige credenciales de red; contaminaría el caso de referencia offline (§10). |
| SonarQube, Checkov, Dependency-Check, Nuclei | Cobertura del stack del mantenedor; quedan fuera del v0.1 explícitamente para no repetir el riesgo de §13.1 (deriva de alcance) antes de validar el contrato con dos herramientas. |
| Auto-instalación o auto-actualización de binarios de herramienta | Rompería R2 (nunca se descarga nada en runtime) y R4 (la imagen es la unidad de compatibilidad, no un instalador). |
| Proveedores de GitHub Actions y GitLab CI | El contrato se valida con dos proveedores de máxima distancia entre sí (§10); añadir más plataformas es trabajo de adaptador, no de diseño, y se hace bajo demanda. |
| Multi-categoría en una sola invocación del CLI (`scan secrets sca`, `--all`) | Ver §8: restricción de superficie deliberada, no del núcleo. |

**Nota sobre DefectDojo y el resto del stack propio:** quedan fuera *del v0.1*, no del
proyecto. El `Finding` incluye una huella determinista (§5) precisamente para que un
sink de DefectDojo se implemente después sin cambiar el núcleo ni invalidar lo que ya
existe en el lado del cliente.

---

## §2. Nombre del proyecto — Decidido: `linceo`

> **Decisión registrada el 2026-09-03: el nombre del proyecto es `linceo`.** Condiciona
> el paquete de PyPI, el nombre de import, el binario, la imagen de contenedor, el
> grupo de entry points y el prefijo de variables de entorno (`LINCEO_*`). La tabla de
> candidatos y el criterio de las subsecciones que siguen se conservan íntegros: son el
> registro de por qué se descartó cada alternativa evaluada, no un borrador pendiente
> de completar. `linceo` no es uno de los cinco candidatos evaluados en esa tabla — se
> añade como entrada propia más abajo, con su verificación de namespace independiente.

### Criterios declarados

- Corto: binario de idealmente ≤7 caracteres; prefijo de variable de entorno
  soportable (`LINCEO_TOKEN_ENV`, etc.).
- Pronunciable y deletreable de oído.
- ASCII sin acentos.
- Fonemas sin trampa para hablantes no nativos de español (se evitan `j`, `ñ`, `ll`,
  `ce/ci`, `ge/gi`).
- Nombre de import válido como identificador Python (sin guiones).
- Sin colisión en PyPI, Docker Hub, GitHub, ni en el espacio de herramientas de
  seguridad existentes.
- Buscable — no un término genérico del dominio.
- Que signifique o evoque algo para un lector no hispanohablante, dado que README,
  código y público objetivo son en inglés.
- Que **no** sugiera derivación del proyecto de referencia: se descarta cualquier
  patrón `devsecops-*` o `*-engine-*`, que leería como fork y contradiría el
  protocolo de sala limpia de §12.

### El criterio de evocación en inglés se pondera, no se aplica como filtro

Catorce candidatos se comprobaron contra el índice de PyPI. Las cuatro palabras
españolas evaluadas estaban libres a la primera comprobación. Las diez palabras
inglesas evocadoras evaluadas estaban **todas** ocupadas — incluida `redoubt`, que
resultó ser un escáner de prompt-injection activo publicado en 2026, es decir,
competencia directa en el mismo espacio de producto. El namespace de palabra común
en inglés relacionada con seguridad/orquestación está, en la práctica, agotado.

La evidencia de mercado apunta en la misma dirección: `trivy`, `grype`, `syft`,
`checkov`, `snyk`, `falco`, `kyverno`, `semgrep` y `nikto` son todos nombres opacos o
de raíz no inglesa. El mercado de herramientas de seguridad premia *corto,
pronunciable, deletreable y único* — no que el nombre sea autoexplicativo. El
significado lo carga el tagline y el README, no el token del paquete. Por eso el
criterio de evocación en inglés entra como factor de desempate, no como filtro de
entrada: aplicado como filtro estricto habría dejado cero candidatos viables.

### Verificación ejecutada en PyPI

El namespace de PyPI es el más vinculante de los tres (PyPI, Docker Hub, GitHub)
porque es global y, en la práctica, no recuperable: PEP 541 (reclamación de nombres
abandonados) es un proceso lento y de resultado incierto, así que un paquete
abandonado cuenta como ocupado a efectos de esta decisión.

| Candidato | Estado en PyPI | Nota |
|---|---|---|
| `pauta` | **Libre** | Candidato |
| `cordel` | **Libre** | Candidato |
| `trenza` | **Libre** | Candidato |
| `assayline` | **Libre** | Candidato — criterio de evocación en inglés |
| `scanwright` | **Libre** | Candidato — criterio de evocación en inglés |
| `pista` | Libre | Reserva, no propuesto como candidato principal |
| `batuta` | Ocupado | Peor colisión posible: CLI de análisis estático de Android que *orquesta* apktool/jadx/adb — mismo dominio conceptual. |
| `redoubt` | Ocupado | Escáner de seguridad activo (prompt-injection, 2026). Mismo espacio de producto. |
| `muster`, `assay`, `cairn`, `bulwark`, `winnow`, `arbiter`, `plimsoll`, `assize`, `hallmark`, `waymark`, `tessera`, `gatecraft` | Ocupados | Varios abandonados desde hace años, pero no reclamables con garantía razonable (PEP 541). |

### Los cinco candidatos, con su contra honesta

- **`pauta`** (5 caracteres) — el más rico semánticamente: en español es a la vez
  norma/directriz (lo que hace el gate) y pentagrama (lo que hace la orquestación:
  poner en línea partes distintas). Contra: es también jerga publicitaria frecuente
  en español ("pauta publicitaria"), lo que ensucia la búsqueda en ese idioma; opaco
  para un lector en inglés.
- **`cordel`** (6) — el cordel que ata herramientas distintas en un solo haz. Fonética
  limpia (c dura, sin los fonemas problemáticos listados arriba). Es el que mejor
  cumple el criterio de evocación en inglés entre los tres candidatos originales: un
  lector angloparlante reconoce "cord" dentro de la palabra. Contra: no evoca
  seguridad por sí mismo.
- **`trenza`** (6) — trenzar N salidas de herramienta en un veredicto único es
  literalmente la decisión de §1 y §5. Contra: la `z` es el único fonema del conjunto
  con variación regional relevante (seseo/distinción); opaco en inglés — el cognado
  "tress" es demasiado remoto para funcionar como pista.
- **`assayline`** (9) — *assay* es en inglés el ensayo que determina la pureza de un
  metal; la "línea de ensayo" es por donde pasa cada muestra. Transparente para un
  lector angloparlante y coherente con §6 (determinar de qué está hecho un artefacto
  y con qué severidad). Contra: 9 caracteres, por encima del criterio de longitud
  declarado; el binario tendría que ser un alias más corto, lo que rompe la
  correspondencia directa nombre = binario que los otros candidatos sí tienen.
- **`scanwright`** (10) — el sufijo *-wright* (playwright, shipwright, wheelwright) es
  "el que fabrica/opera [algo]"; el artesano del escaneo. Inequívocamente inglés y sin
  ambigüedad de lectura. Contra: es el más largo del conjunto, y el prefijo "scan-" lo
  ata semánticamente a la acción de escanear cuando el producto real es orquestar y
  decidir sobre varios escaneos — es decir, describe una herramienta, no el orquestador.

### Recomendación del revisor

`cordel`, por ser el único candidato que satisface los dos criterios en tensión —
libre en los tres registros comprobables, corto, fonética sin trampa, y
semitransparente en inglés vía "cord" — sin pagar la longitud de los dos compuestos
ingleses. Segunda opción: `pauta`, si se prioriza la riqueza semántica en español
sobre la evocación en inglés.

### De la recomendación a la decisión final

Esta recomendación no se materializó. El motivo del giro hacia `linceo` fue
empírico, no un cambio de criterio: los cinco candidatos de la tabla no colisionaron
en PyPI — los cinco quedaron libres —, pero validar variantes adicionales dentro del
mismo registro vernáculo (palabras cortas de una sola raíz, en español o en inglés)
siguió topando con el mismo patrón de escasez ya documentado arriba con los doce
candidatos descartados. Combinado con el criterio, ya declarado en esta sección, de
que el nombre funcione tanto para un lector hispanohablante como para uno
angloparlante, ese patrón desplazó la búsqueda hacia raíces latinas y griegas
compartidas por ambos idiomas — de ahí `linceo`, cuya verificación de namespace
sigue abajo.

### Verificación de namespace ejecutada para `linceo`

Resultado literal de las comprobaciones ejecutadas por el mantenedor:

```
== linceo
  https://pypi.org/pypi/linceo/json            404
  https://api.github.com/users/linceo          200
  https://api.github.com/orgs/linceo           404
```

Complementado con tres registros adicionales comprobados al cerrar esta sección:

| Registro | Resultado | Nota |
|---|---|---|
| PyPI (`/pypi/linceo/json`) | `404` — libre | PyPI no reserva nombres sin publicar (normalización PEP 503: `-`, `_`, `.` colapsan; comparación case-insensitive). **Publicar un release real (aunque sea `0.0.1`) queda pendiente y es urgente una vez el repositorio se haga público**, porque el nombre queda expuesto en ese momento. |
| GitHub, cuenta de usuario (`/users/linceo`) | `200` — **ocupado** | Existe una cuenta de usuario con ese nombre exacto. |
| GitHub, organización (`/orgs/linceo`) | `404` — sin organización actual | No implica disponibilidad — ver nota abajo. |
| npm (`registry.npmjs.org/linceo`) | `404` — libre | |
| crates.io (`/api/v1/crates/linceo`) | `404` — libre | |
| Docker Hub (namespace `linceo`) | `404` / 0 repositorios — libre | |

**Nota técnica sobre el resultado de GitHub, porque el `404` de organización no debe
leerse como "disponible":** GitHub comparte un único espacio de nombres entre cuentas
de usuario y organizaciones — no se puede crear una organización con el mismo nombre
exacto que una cuenta de usuario ya existente. El `200` en `/users/linceo` significa
que **`github.com/linceo` está ocupado por esa cuenta de usuario**, sin relación
conocida con este proyecto; el `404` en `/orgs/linceo` solo confirma que hoy no existe
una organización con ese nombre, no que se pueda crear una. Consecuencia práctica: el
repositorio y la organización de GitHub del proyecto no podrán vivir en
`github.com/linceo` — vivirán bajo la cuenta personal del mantenedor o bajo una
organización con otro nombre, con el repositorio llamándose `linceo` dentro de esa
cuenta (`github.com/<cuenta>/linceo`). Esto no bloquea PyPI, el nombre de import, el
binario ni la imagen de contenedor (GHCR se resuelve igual, como
`ghcr.io/<cuenta>/linceo`, sin necesitar el namespace de nivel superior) — es
exclusivamente la URL de marca `github.com/linceo` la que queda fuera de alcance.

### Arte previo del nombre en otros idiomas y ecosistemas

`linceo` es, a diferencia de los cinco candidatos evaluados arriba, una palabra real
del diccionario de español (RAE): adjetivo que significa "agudo de vista" — de gran
capacidad para percibir detalles. No es jerga (a diferencia de `pauta`) ni un término
opaco inventado; la metáfora es directa para un lector hispanohablante: una
herramienta que detecta lo que otros pasan por alto.

El arte previo relevante y verificable no está en los registros de paquetes — todos
libres, según la tabla de arriba — sino en el propio significado de la palabra:
**la Accademia dei Lincei** ("Academia de los Linces", fundada en Roma en 1603, una de
las academias científicas más antiguas de Europa, con Galileo Galilei entre sus
miembros históricos) es, con alta probabilidad, el primer o segundo resultado al
buscar "linceo" o su raíz en cualquier buscador general, incluso para un lector en
inglés — su nombre inglés habitual, "Lyncean Academy", y el adjetivo raro pero
existente "Lyncean" derivan de la misma raíz (Linceo/Lynceus, la figura mitológica
griega de vista prodigiosa, uno de los Argonautas).

**El riesgo que se asume, dicho en voz alta:** buscar el nombre del proyecto en
cualquier motor de búsqueda general va a competir, en los primeros resultados, con
una institución académica centenaria y con recursos de indexación muy superiores a los
de un proyecto OSS de mantenedor único — contaminación real de búsqueda, no
hipotética. A esto se suma una limitación honesta ya declarada en el criterio original
de este documento: una búsqueda formal de marca registrada se consideró desproporcionada
para un proyecto OSS de mantenedor único, así que no se ha hecho una búsqueda
exhaustiva de uso de "Linceo" como marca comercial en industrias afines a la metáfora
del nombre (óptica, vigilancia, oftalmología) — el atractivo genérico de "vista
aguda" como metáfora de marca hace plausible que exista uso previo no descubierto en
esos sectores, sin relación con software.

**Por qué se considera aceptable de todos modos, sin pretender que el riesgo
desaparece:** a diferencia de `batuta` (descartado) y `redoubt` (descartado) — ambos
colisiones directas con herramientas de seguridad activas en el mismo espacio de
producto —, la Accademia dei Lincei no es software, no publica en PyPI, GitHub ni
Docker Hub, y no compite por la atención de la misma audiencia técnica que busca un
orquestador DevSecOps con intención de instalarlo. La contaminación de búsqueda es de
marca general, no de categoría de producto: quien busca "linceo pypi" o
"linceo devsecops" no encuentra la academia. El costo es de recuerdo de marca a largo
plazo (SEO, reconocimiento de un nombre googleado en solitario), no de confusión
funcional con un competidor ni de bloqueo de namespace — y ese costo ya se paga, en
cualquier nombre elegido, contra algo: los cinco candidatos evaluados tenían el suyo
propio (jerga publicitaria, opacidad en inglés, o longitud excesiva). Este documento
registra el costo elegido; no lo presenta como inexistente.

---

## §3. Gestor de dependencias y empaquetado

**Elegido: `uv` como gestor de dependencias y entorno, `hatchling` como backend de
construcción.**

Motivos:
- Binario estático, sin necesidad de un Python de arranque preinstalado — simplifica
  la etapa de build de la imagen multi-etapa (R4) y reduce el tiempo de build a
  segundos.
- `uv.lock` es un lockfile universal multiplataforma: una sola resolución cubre Linux,
  macOS y Windows, lo cual importa porque el proyecto se distribuye también vía PyPI
  para desarrollo local (R4).
- `uv sync --frozen` es determinista: falla si el lockfile no coincide con
  `pyproject.toml`, en vez de re-resolver silenciosamente.
- Gestiona también las versiones de intérprete Python necesarias para la matriz de CI,
  sin herramienta adicional.
- Metadatos 100% PEP 621 en `pyproject.toml`, sin campos de configuración propietarios
  de la herramienta.

**Descartado: Poetry.** Llegó tarde a PEP 621 — el formato nativo `[tool.poetry]` fue
el único soportado hasta la serie 2.0 —, su formato de lockfile ha introducido
cambios incompatibles entre versiones que han roto cachés de CI en otros proyectos, es
sensiblemente más lento en resolución, y exige un intérprete Python más un paso de
instalación explícito dentro de la imagen de build. Su ventaja histórica —madurez del
ecosistema y flujo de publicación integrado— ya no es diferencial frente a `uv`.

**Descartado: PDM.** Técnicamente sólido y nativo en PEP 621 desde el principio, pero
sin ventaja concreta sobre `uv` para las necesidades de este proyecto, y con una base
de contribuyentes y de adopción sensiblemente menor. Para un proyecto que depende de
contribuciones externas de un ecosistema de mantenedor único, la familiaridad del
contribuyente potencial con la herramienta es en sí misma una característica a
optimizar, y `uv` la tiene mejor.

**Riesgo asumido, explícito:** `uv` es una herramienta joven, desarrollada por una
empresa con capital de riesgo (Astral). Un cambio de licencia, de modelo de negocio, o
el abandono del proyecto son escenarios concebibles a mediano plazo. El coste de
salida se mantiene bajo *por diseño*, no por confianza en el proveedor: todos los
metadatos de dependencias y build viven en `pyproject.toml` estándar, sin ningún campo
específico de `uv`; `hatchling` como backend de construcción para que el empaquetado
tampoco dependa de `uv`. El único punto de anclaje real es el formato del lockfile, y
es regenerable con pip-tools, PDM o Poetry en una tarde de trabajo si `uv` deja de ser
viable.

---

## §4. Las cinco restricciones traducidas a arquitectura

Cada restricción se traduce como: invariante → decisión de arquitectura →
**mecanismo de verificación**. Esta es la sección más importante del documento.

### R1 — Agnóstico de plataforma de CI

**Invariante:** ningún código que resuelva "en qué contexto estoy corriendo" puede
vivir fuera de un punto de extensión explícito.

**Decisión:** `ExecutionContext` como objeto de valor inmutable — repositorio, rama,
commit, identificador de PR/MR si aplica, identificador de build, URL de origen, ruta
del workspace, plataforma detectada — resuelto por un puerto `ContextProvider` con
adaptadores concretos: `local` (obligatorio) y `azure_devops` (referencia; ver §10).

Invariante duro derivado: **ningún módulo del núcleo lee `os.environ` directamente**;
solo los proveedores lo hacen, y solo dentro de su propio paquete.

**Verificación:** test que recorre el AST de todo el paquete del núcleo (excluyendo
`providers/`) y falla si encuentra una referencia a `os.environ`. Detección `auto` de
plataforma con un orden de comprobación declarado y determinista (documentado, no
implícito en el orden de los `if`), siempre sobreescribible explícitamente con
`--platform`.

### R2 — Funciona sin salida a internet

**Invariante:** el camino feliz de una ejecución no realiza ninguna llamada de red.

**Decisión:** cero telemetría se implementa por *ausencia de capacidad*, no por un
interruptor que pueda quedar mal configurado: no existe ningún cliente HTTP en las
dependencias base del paquete. La configuración remota opcional (mencionada en el
contexto original del proyecto, implementada en la enmienda de §8.4 "Fuente remota de
la política") vive en un extra instalable aparte (`pip install linceo[remote-config]`);
si la descarga falla, el comportamiento es `WARN` y continuar con la configuración
local resuelta — degradación, nunca error
fatal. Los binarios de herramienta (Gitleaks, Trivy) **nunca se descargan en runtime**
bajo ninguna circunstancia: si faltan, es un error accionable (ver R4), no un intento
de resolución automática.

**Punto concreto donde la restricción muerde de verdad, documentado explícitamente
porque es donde un diseño ingenuo fallaría:** Trivy actualiza su base de datos de
vulnerabilidades por red por defecto en cada invocación. La imagen de referencia (R4)
hornea la base de datos en build time; la integración invoca Trivy con
`--skip-db-update` y apuntando a esa caché local. El modo por defecto de la
integración es el offline; actualizar la base de datos es un acto explícito del
operador, nunca un efecto secundario de correr un escaneo (desarrollo completo del
manejo de frescura de datos en §5).

**Verificación:** la suite de tests del núcleo corre con el módulo `socket` envenenado
(monkeypatch que lanza excepción en cualquier intento de conexión), de modo que
cualquier llamada de red accidental introducida en el núcleo rompe el CI
inmediatamente, sin depender de que alguien la note en code review.

### R3 — Sin estado compartido ni backend propio

**Invariante:** una ejecución no puede depender de lo que dejó una ejecución anterior,
ni dejar algo de lo que dependa una futura.

**Decisión:** entrada = contexto + configuración resuelta + workspace en disco;
salida = artefactos de reporte en disco + código de salida del proceso. Sin base de
datos, sin caché con efecto semántico sobre el resultado (una caché de rendimiento
puro, como la BD de Trivy, no cuenta como estado compartido porque no cambia el
resultado, solo la velocidad). La deduplicación de hallazgos es intra-ejecución
únicamente; la deduplicación entre ejecuciones distintas es responsabilidad explícita
del sistema receptor (DefectDojo u otro), habilitada — no implementada — por la huella
determinista de cada `Finding` (§5).

**Corolario de diseño, verificable:** misma entrada produce los mismos bytes de
salida. Esto exige que el reloj del sistema y cualquier fuente de aleatoriedad o de
identificador único (UUID de run, por ejemplo) queden detrás de un puerto inyectable,
nunca llamados directamente (`datetime.now()`, `uuid.uuid4()` prohibidos fuera de la
implementación de ese puerto).

**Verificación:** test de determinismo que ejecuta el mismo run dos veces contra los
mismos fixtures (con el reloj y el generador de id fijados vía el fake) y compara
bytes de salida.

### R4 — Contenedor como vía de distribución principal, PyPI para desarrollo local

**Invariante:** la compatibilidad entre el orquestador y las versiones de herramienta
que invoca no puede depender del entorno del usuario.

**Decisión:** la imagen de contenedor es la unidad de compatibilidad: orquestador +
binarios de herramienta anclados a una versión específica + imagen base anclada por
digest (no por tag) + manifiesto de versiones embebido y consultable (`doctor`, ver
§8). Vía PyPI, las herramientas son *bring your own*: si un binario requerido no está
en `PATH`, el CLI falla con un error accionable que nombra qué falta, qué versión se
espera, y cómo instalarla — y **nunca intenta instalarla por su cuenta**, lo cual
además violaría R2.

**Verificación:** comando `doctor` que reporta, para cada herramienta configurada, si
está presente, su versión detectada y si coincide con el rango soportado; se ejecuta
también como smoke test de la imagen en CI.

### R5 — Ninguna configuración de cliente puede vivir en este repositorio

**Invariante:** el repositorio del orquestador, en ningún commit de su historia,
contiene un valor de configuración específico de un cliente.

**Decisión:** orden de resolución de configuración, y ninguno de sus pasos apunta
dentro del repositorio del orquestador:

```
flags de línea de comandos
  > variables de entorno
    > --config (ruta explícita)
      > rutas convenidas DENTRO del workspace escaneado (ej. .devsecops/config.toml
        en el repo del cliente, nunca en este)
        > defaults compilados en el paquete (genéricos, sin datos de cliente)
```

El repositorio de este proyecto contiene únicamente: el esquema de configuración,
defaults genéricos no vinculados a ningún cliente, y ficheros `*.example` que el
cargador de configuración tiene **prohibido** leer como fuente válida.

**Verificación:** test que instancia el cargador de configuración con distintas
combinaciones de entrada y afirma que ninguna ruta candidata que resuelve puede
apuntar dentro del directorio del paquete instalado. Refuerzo operativo, no solo de
test: `gitleaks` como hook de pre-commit desde el commit #1 (dogfooding del propio
producto sobre su propio repositorio).

**Por qué esto se trata con el mismo rigor que un requisito de seguridad, y no como
higiene de repositorio:** el repositorio es privado hoy, pero se hace público en el
momento del release v0.1, y **la historia de git es permanente** — un secreto o una
configuración de cliente commiteados hoy, aunque se eliminen mañana, siguen presentes
en la historia después de que el `git push` los haga públicos. La restricción R5, leída
así, no es solo una preferencia de diseño: es lo que evita que un descuido de hoy se
convierta en una fuga permanente el día del release.

---

## §5. Modelo de resultado: N ejecuciones, un veredicto

### Estructura

- **`RunResult`:** identificador de run, `ExecutionContext`, lista `executions[]`,
  hallazgos agregados, un único `Verdict`.
- **`ToolExecution`:** herramienta, versión detectada, categoría, línea de comandos
  invocada (redactada, ver §9), tiempos de inicio/fin, código de salida nativo de la
  herramienta, estado (`completed | failed | skipped | skipped_by_policy`), hallazgos
  producidos, `data_sources[]` (ver frescura, abajo).

**El gate recibe siempre un `RunResult` completo, nunca la salida cruda de una sola
herramienta.** Esto se fuerza en la firma del tipo, no solo en la documentación: no
existe una función de gate que acepte una lista de `Finding` sueltos.

### Fallo parcial

Una ejecución de herramienta que no corre (binario ausente, timeout, crash) no es "cero
hallazgos" — es *ausencia de evidencia*, y tratarla como lo primero produce un gate
verde engañoso. `RunResult.status = partial` cuando alguna ejecución no completó, y por
defecto **el run entero falla con código 3** en vez de reportar un veredicto positivo
sobre evidencia incompleta. `--continue-on-tool-error` permite optar explícitamente por
lo contrario. Es la misma clase de mentira, estructuralmente, que un reporte "limpio"
producido con una base de datos de vulnerabilidades desactualizada (ver frescura, abajo)
— y se trata con el mismo principio: nunca declarar limpio sin declarar también qué tan
completa es la evidencia detrás de esa declaración.

**Excepción deliberada: la omisión sancionada por política.** Un `ToolSkip` configurado
(§8.4) — herramienta, motivo, responsable, fecha límite obligatoria — produce una
ejecución `skipped_by_policy`, no `skipped`. La distinción no es cosmética: `skipped`
(binario ausente) y `failed` (crash) son ausencia de evidencia *accidental*, y por eso
vuelven el run `partial`; `skipped_by_policy` es una ausencia *declarada*, con nombre,
responsable y vencimiento, exactamente lo contrario de lo que esta subsección castiga.
Un run con solo ejecuciones `completed` y `skipped_by_policy` es `RunStatus.completed`,
el gate se evalúa con normalidad, y el reporte destaca la omisión por su nombre (§7) en
vez de fallar en silencio o fallar el pipeline por una decisión que el propio pipeline
declaró de antemano. Vencido el `ToolSkip`, la herramienta vuelve a ejecutarse sin
intervención adicional — la caducidad no es un caso de error, es el mecanismo normal de
recuperación.

### Deduplicación

Intra-run, por huella (ver abajo): agrupa hallazgos equivalentes y **conserva la
procedencia** — qué herramienta(s) lo reportaron — en vez de descartar silenciosamente.
Sin esto, dos herramientas que detectan el mismo CVE por rutas distintas inflarían el
conteo del run.

Un único reporte por run, con `executions[]` como lista — desde el día uno, aunque hoy
tenga longitud 1 con Gitleaks únicamente. Nunca un fichero de reporte por herramienta:
eso es exactamente el patrón "envoltorio, no orquestador" que §1 descarta.

### Huella determinista, versionada en el valor

Formato: `v1:<hex>`. La versión del algoritmo de huella va **dentro** de la cadena, no
en un campo hermano del `Finding`. Un campo hermano se pierde con facilidad al
atravesar consumidores externos que solo persisten el identificador (por ejemplo, un
baseline de cliente que solo guarda el string de huella); embebida en el valor,
`v1:abc123` nunca puede compararse por accidente con `v2:abc123` producido por un
algoritmo distinto — la comparación falla de forma ruidosa (huellas distintas, string
distinto) en vez de en silencio (coincidencia falsa entre versiones incompatibles).

Ingredientes por categoría, fijados explícitamente junto con lo que **no** entra —
número de línea, marcas de tiempo, rutas absolutas del entorno de escaneo — para que
mover código de sitio o correr el mismo escaneo en dos máquinas distintas no produzca
churn de huellas:

- **Secretos:** `rule_id` + ruta relativa dentro del repositorio + hash del secreto
  detectado (**nunca el valor del secreto en claro**).
- **SCA:** nombre de paquete + versión + identificador de vulnerabilidad (CVE/GHSA) +
  ruta del manifiesto que lo declara.

Subir la versión del algoritmo de huella es un cambio incompatible, con nota de
migración obligatoria en el registro de cambios del proyecto.

### Decisión: la herramienta no entra en la huella, en ninguna categoría

La primera redacción de este modelo incluía el nombre de la herramienta como
ingrediente de la huella de secretos pero no de la de SCA — una asimetría no
deliberada. Resolverla hacia "excluir la herramienta en ambas" no lo exige un
argumento externo de ergonomía de CLI: lo exige **esta misma sección**, que ya declara
deduplicación intra-run para que dos herramientas sobre el mismo hallazgo no inflen el
conteo. Si la herramienta formara parte de la huella, dos herramientas que detectan lo
mismo producirían huellas distintas por construcción, y esa deduplicación sería
imposible en principio, no solo en la práctica. Incluir la herramienta contradice el
propósito que la propia sección declara para la huella.

El argumento decisivo es una asimetría de consecuencias, no de elegancia: incluir la
herramienta **garantiza** el fallo de coincidencia entre fuentes distintas para el
mismo hecho; excluirla solo **permite** la coincidencia, y esta ocurre cuando el resto
de los ingredientes realmente coinciden. Una falsa precisión (huellas siempre distintas
entre herramientas, aunque describan lo mismo) se cambia por una posibilidad real de
coincidencia correcta.

**El precio de esta decisión, sin adornos:**

1. **Riesgo de colisión** si dos herramientas usan el mismo `rule_id` para conceptos
   distintos. En SCA es prácticamente nulo: los identificadores de vulnerabilidad
   (CVE, GHSA) tienen namespace global e inequívoco. En secretos es plausible pero
   mayormente benigno: una coincidencia de nombre de regla entre dos escáneres de
   secretos suele implicar coincidencia semántica real (ambos llaman "aws-access-key"
   a lo mismo), no una colisión arbitraria.
2. **Una supresión deja de estar atada al escáner que la originó.** Suprimir un
   hallazgo reportado por la herramienta A también lo suprime si la herramienta B
   reporta el mismo hecho después. Esto se acepta deliberadamente, no como efecto
   secundario tolerado: **una supresión es un juicio sobre el artefacto que se está
   escaneando, no sobre el escáner que lo encontró.** Quien decide "esta cadena en
   esta ruta es un falso positivo" no está opinando sobre Gitleaks específicamente.
3. **Limitación honesta que se deja abierta, no oculta:** en secretos, `rule_id`
   pertenece al vocabulario local de cada herramienta (los nombres de regla de
   Gitleaks no coinciden con los de otro escáner de secretos). La coincidencia de
   huella *entre herramientas distintas* para la misma categoría queda habilitada
   por el diseño, pero no entregada de facto, hasta que exista una taxonomía de
   reglas normalizada entre herramientas. Se registra como trabajo futuro explícito
   en §14, con el disparador que lo reabriría (incorporar una tercera herramienta de
   la misma categoría).

`Finding.tool` sigue existiendo como campo del modelo — la procedencia se conserva
siempre, según lo declarado arriba en Deduplicación. Simplemente no es ingrediente de
la identidad del hallazgo.

**Contra qué no es estable la huella**, dicho explícitamente porque de ello depende
directamente la durabilidad del baseline de cliente (§8.2): es estable frente al
movimiento de código dentro del repositorio (no lleva número de línea ni ruta
absoluta), pero **no** es estable frente a que una herramienta renombre sus `rule_id`
entre versiones — ese caso produce entradas huérfanas en un baseline existente,
exactamente igual que una subida de versión del algoritmo de huella, y se trata con el
mismo mecanismo de recuperación (§8.2).

### Frescura de las fuentes de datos

Tratada como un problema general del núcleo, no como un parche específico para Trivy:
toda `ToolIntegration` declara `data_sources()` — nombre, versión, fecha de
construcción de cada fuente de datos que usa (base de vulnerabilidades, lista de
reglas, etc.) — y el núcleo aplica la política de caducidad de forma uniforme sobre
esa declaración, sin conocer los detalles de cada herramienta.

Decisiones concretas:

- Los metadatos de salida del reporte **siempre** incluyen la fecha de cada fuente de
  datos usada, sin excepción — incluso cuando el reporte no tiene hallazgos.
- Umbral de caducidad configurable, con default de 7 días. Superado el umbral: `WARN`
  prominente en la salida de consola y una bandera `stale_data = true` en el reporte
  estructurado; `--max-db-age` permite convertir la caducidad en un error explícito.
- La imagen de contenedor registra la fecha de construcción de cada base de datos
  horneada como etiqueta OCI, de modo que una imagen desactualizada se detecte por
  metadatos externos, sin necesidad de arrancarla.
- Camino de refresco documentado explícitamente, con tres vías: (1) reconstruir o
  repullear la imagen — la vía principal y recomendada; (2) `--update-db` como flag
  explícito que sí toca la red para esa invocación puntual; (3) `TRIVY_DB_REPOSITORY`
  apuntando a un mirror OCI interno, que es la respuesta realista para organizaciones
  con entornos de red aislados que necesitan actualizar sin salir a internet público.

`--update-db` es, por diseño, el **único** punto de todo el v0.1 donde una herramienta
integrada toca la red, y es estrictamente opt-in — coherente con R2, que exige que el
camino feliz no haga red, no que ninguna acción explícita del operador pueda hacerla.

Principio que resume esta subsección: *un reporte no puede declararse limpio sin
declarar también la edad de la evidencia sobre la que se basa esa declaración.*

---

## §6. Normalización de severidad

De esta sección depende el gate (§8.1): sin un mapeo explícito y auditable,
`--fail-on HIGH` significa cosas distintas según qué herramienta produjo el hallazgo,
y el gate deja de ser un contrato que el usuario pueda razonar.

### El problema, dicho explícitamente

Gitleaks no emite severidad — todo hallazgo es, sintácticamente, "un secreto
detectado", sin distinción de gravedad nativa. Trivy emite una escala nativa
(`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) más, por separado, un puntaje CVSS
que puede provenir de varias fuentes (NVD, el advisory del vendor de la distro, GHSA)
y no siempre coincide con la severidad nativa que Trivy reporta.

### Escala normalizada del proyecto

`CRITICAL | HIGH | MEDIUM | LOW | INFO`, definida por la **acción esperada** que
provoca cada nivel — no por adjetivos de gravedad, que son ambiguos entre categorías:

| Nivel | Definición operativa |
|---|---|
| CRITICAL | Explotable ya, en este artefacto tal como está. Se corrige antes de mezclar. |
| HIGH | Serio; exige acción dentro del ciclo actual. Bloquea por defecto en ramas protegidas cuando el gate está activo. |
| MEDIUM | Real, pero acotado en impacto o mitigado por contexto conocido. Se registra, no bloquea por defecto. |
| LOW | Higiene; corrección de bajo costo, sin urgencia. |
| INFO | Informativo. Nunca bloquea el gate, bajo ninguna configuración de umbral. |

### La matriz de mapeo es un artefacto de datos versionado, no lógica dispersa

Fichero declarativo distribuido junto con el paquete —
`linceo/data/severity_map.toml`, con un campo `map_version` propio — que define la
clave `(herramienta, valor_nativo) → severidad_normalizada`. Los parsers de cada
integración emiten el valor nativo crudo tal cual en `Finding.raw_severity` y **no
normalizan nada por su cuenta**; un único componente `SeverityNormalizer`, compartido
por todas las integraciones, aplica el mapa.

Dos consecuencias buscadas deliberadamente con este diseño: el mapeo completo se
revisa como un diff legible en un pull request, en vez de estar disperso en la lógica
de cada parser; y cambiar el mapeo es un evento versionado y visible, no un efecto
secundario silencioso de tocar un parser. El `map_version` viaja en los metadatos del
run, de modo que un reporte declara con qué versión del mapa se produjeron sus
severidades — necesario para que dos runs con el mismo hallazgo pero mapas distintos
sean comparables.

`Finding` lleva tres campos relacionados con severidad: `raw_severity` (el valor
crudo, sin tocar), `severity` (normalizada) y **`severity_source`**
(`native | cvss | category_default | override | fallback`). Este tercer campo es lo
que hace el gate auditable en la práctica: permite responder "¿por qué este hallazgo
es HIGH?" señalando exactamente qué regla de precedencia se aplicó, sin tener que
reconstruir la cadena de decisión a mano.

### Precedencia cuando hay varias señales de severidad disponibles

Orden fijo, documentado, y aplicado en este orden exacto — nunca "lo que esté
disponible primero":

1. **Override del cliente.** Decisión humana explícita sobre un `(herramienta,
   rule_id)` concreto; gana siempre sobre cualquier señal automática. Vive en la
   configuración de cliente (R5), nunca en este repositorio — modelado en código
   desde el primer `SeverityNormalizer` (`overrides`), pero sin todavía un camino
   real desde `.devsecops/config.toml` hasta ese campo; aplazado explícitamente
   en §14, junto con la pregunta más amplia de si `severity_map.toml` completo
   debería poder extenderse o sobrescribirse desde ese mismo documento.
2. **Severidad nativa de la herramienta**, si existe y no es `UNKNOWN`. Se prefiere
   sobre CVSS porque suele codificar contexto de advisory específico del proveedor
   —severidad ajustada por distro, backports de parches ya aplicados aguas arriba—
   que un CVSS crudo no captura. En el caso concreto de Trivy, su campo `Severity` ya
   es el resultado de su propia cadena interna de resolución de fuentes, así que
   volver a derivarlo desde CVSS puro sería tirar información.
3. **CVSS base**, mapeado a los cubos cualitativos estándar de CVSS v3.1: `0.0` →
   INFO; `0.1–3.9` → LOW; `4.0–6.9` → MEDIUM; `7.0–8.9` → HIGH; `9.0–10.0` →
   CRITICAL. Cuando hay varias fuentes de CVSS disponibles para el mismo hallazgo, el
   **orden de preferencia entre fuentes se declara explícitamente en el propio
   fichero de mapa** (por ejemplo: NVD antes que advisory de distro, o al revés,
   según lo que el mantenedor decida) — sin esa declaración explícita, el resultado
   dependería del orden de iteración de un diccionario en memoria, lo cual rompería
   el determinismo exigido por R3.
4. **Default por categoría.** Ver abajo.

### Herramientas que no emiten severidad nativa (caso Gitleaks)

La severidad se asigna **por regla, no globalmente**, desde una tabla `defaults`
dentro del mismo fichero de mapa versionado. El default de la categoría `secrets` es
**HIGH**, escalable por `rule_id` individual (una regla que detecta, por ejemplo,
claves privadas de infraestructura crítica puede escalarse a CRITICAL en el mapa).

Razonamiento explícito de por qué HIGH y no otro valor: asignar CRITICAL a todo
hallazgo de Gitleaks vuelve inútil `--fail-on CRITICAL` como umbral — todo pasa por
ahí siempre — y entrena al equipo a subir el umbral hasta ignorarlo. Asignar MEDIUM
significa que una fuga real de secreto, con `--fail-on HIGH` (el valor que se
recomienda en el quickstart, ver §8.1), no bloquea nada. HIGH con posibilidad de
escalado por regla es el default honesto: bloquea por defecto donde importa, sin
saturar el nivel más alto de la escala.

### `UNKNOWN` nunca llega al gate como un nivel propio

Se resuelve siempre a través de la cadena de precedencia de arriba; si todas las
señales fallan, cae en un fallback explícito, `unknown_severity`, cuyo valor por
defecto es **MEDIUM**, con `severity_source = fallback` y **conteo visible en el
resumen del run** ("N hallazgos con severidad inferida por fallback"). Se documenta
también la contra de este default, explícitamente: MEDIUM no bloquea con
`--fail-on HIGH`, así que un operador que prefiera fallar cerrado ante severidad
desconocida debe subir el valor de fallback en su configuración — es configurable a
propósito, no un descuido. Mapear el fallback a LOW escondería el problema real
detrás de ruido de baja prioridad; mapearlo a CRITICAL produciría fatiga de alertas
sobre casos que pueden ser benignos.

### La escala normalizada es el espacio de claves de los umbrales del gate

El gate (§8.1) no tiene su propio vocabulario de severidad: sus umbrales —el
`--fail-on` plano, la tabla `[thresholds]` de un archivo de política, y cualquier
tabla `[thresholds.<categoría>]` que especialice una categoría concreta (§8.1,
§8.4)— se declaran exclusivamente sobre los cinco niveles de esta sección, sin
excepción para ninguna de las tres formas. Eso hace concreta, y verificable en carga
en vez de solo aspiracional, la frase ya escrita arriba: **`INFO` nunca bloquea el
gate, bajo ninguna configuración de umbral**. Antes de esta revisión del contrato,
`--fail-on info` se aceptaba en el CLI sin producir jamás un incumplimiento — una
promesa que dependía de que nadie probara el caso. Ahora, `INFO` como cutoff o como
clave de `[thresholds]` — global o de una categoría — es directamente **error de
configuración** (código de salida 2, §8): la única forma de que la garantía de esta
sección deje de ser una promesa y pase a ser un invariante comprobado. Especializar
los umbrales por categoría generaliza *dónde* se declara un umbral, nunca *sobre qué
vocabulario* se declara — introducir una sexta clave, o una escala paralela propia de
una categoría, habría roto esta sección precisamente donde más importa que no se
rompa: la razón por la que `--fail-on HIGH` significa lo mismo sin importar qué
herramienta produjo el hallazgo (motivo de apertura de esta sección) se aplicaría
distinto según la categoría si cada una tuviera su propio vocabulario de severidad,
en vez de solo su propio umbral sobre el vocabulario compartido.

### Verificación

- **Test dirigido por tabla** que enumera el dominio nativo completo y declarado de
  cada herramienta integrada, y exige una salida normalizada válida para cada valor
  de ese dominio, sin excepción.
- **Test de completitud:** cada integración registrada en el sistema de plugins debe
  declarar su dominio nativo íntegro; el test falla si una integración no lo declara.
- **Valor nativo no mapeado: estricto en el CI del propio proyecto, resiliente en
  runtime del usuario final** — deliberadamente distinto según el contexto. En el CI
  del proyecto, donde las versiones de herramienta están ancladas y controladas, un
  valor nativo fuera del dominio conocido **falla el build**: es la señal de que el
  mantenedor necesita actualizar el mapa antes de anclar una nueva versión de Trivy o
  Gitleaks. En runtime del usuario, el mismo caso cae al fallback documentado arriba
  con `WARN` y conteo visible, y `--strict-normalization` permite convertirlo en error
  si el operador lo prefiere. Sin este par de comportamientos, un cambio silencioso en
  el CLI de Trivy podría convertir hallazgos CRITICAL en MEDIUM sin que nadie —ni el
  mantenedor, ni el usuario— lo note nunca.
- **Test dorado:** fixtures reales capturados de cada herramienta (ver §11) mapeados a
  su severidad normalizada esperada, de modo que tocar el fichero de mapa se vea como
  un diff explícito en la salida de test, no como un cambio silencioso de
  comportamiento.
- **Test de determinismo** específico sobre la elección de fuente CVSS cuando hay
  varias disponibles para el mismo hallazgo.

---

## §7. Reporting y formatos de salida

Formatos en alcance del v0.1: **consola** (legible por humanos), **JSON** (formato
canónico del proyecto, sin pérdida de información respecto al modelo `Finding`
interno) y **SARIF 2.1.0** (formato de intercambio).

### Por qué SARIF entra en alcance del v0.1, no se aplaza

Es lo que permite que los resultados lleguen a una interfaz que alguien realmente
mira — el panel de Azure DevOps y GitHub Code Scanning consumen SARIF nativamente —
en vez de morir en un fichero JSON que nadie abre fuera de un script de CI. Sin el
exportador SARIF, el valor práctico del adaptador de referencia de Azure DevOps queda
a medias: el contexto se resuelve correctamente, pero el resultado no se integra a la
experiencia de revisión donde el equipo de desarrollo efectivamente trabaja.

El argumento más fuerte, sin embargo, no es de reporting sino de modelo de datos:
SARIF exige que cada resultado referencie una regla declarada en
`tool.driver.rules`, con un id estable, indexada por posición. Eso **obliga a que
`Finding` lleve `rule_id` y metadatos de regla suficientes desde su diseño**, no como
una traducción que se pueda añadir después sin tocar nada. Aplazar SARIF a v0.2
significaría descubrir esta obligación después de haber publicado el modelo `Finding`
del v0.1, lo cual habría forzado un cambio incompatible del contrato central del
proyecto en su segunda versión. Meterlo en alcance ahora es lo que evita ese
escenario.

### Arista conocida, documentada explícitamente en vez de descubierta tarde

SARIF modela mal los hallazgos de tipo SCA. El formato no tiene campos de primera
clase para paquete, versión instalada ni versión corregida — los hallazgos de Trivy se
exportan con `locations` apuntando al fichero de manifiesto (`requirements.txt`,
`package-lock.json`, etc.) más un bloque `properties` de extensión propietaria para
transportar el resto. El reporte JSON nativo del proyecto es el que no pierde
información en ningún caso; SARIF es, por diseño, un formato de intercambio con
pérdida controlada para el caso SCA. Esta es precisamente la razón, ya fijada en el
supuesto 2 de este documento, por la que SARIF es formato de intercambio y no el
modelo canónico interno del proyecto.

**Verificación:** validación del SARIF producido contra el esquema JSON oficial de
SARIF 2.1.0, **vendorizado dentro del repositorio**. Validar contra una URL remota del
esquema rompería R2 en la propia suite de tests del proyecto.

### Tabla normalizada de hallazgos en consola

Antes de esta revisión del contrato, el reporte de consola imprimía un volcado de
conteos por severidad sin una sola línea por hallazgo. Fijado aquí: **una tabla de
texto plano por categoría**, con un contrato de columnas idéntico para toda categoría
presente y futura, para que añadir Trivy (o cualquier otra herramienta de una
categoría ya cubierta) nunca exija tocar el reporter.

**Columnas base, en este orden, iguales para toda categoría:**

| Columna | Contenido |
|---|---|
| `SEVERITY` | La severidad normalizada (§6) del hallazgo. |
| `ID` | `rule_id` en `secrets`; identificador de vulnerabilidad (CVE/GHSA) en `sca`. |
| `LOCATION` | Forma específica de categoría — ver abajo. |
| `TOOL` | `Finding.tool`, la procedencia (§5). |
| `FP` | Prefijo corto de la huella, único dentro del run — ver abajo. |

`LOCATION` es, de las cinco, la única columna base cuyo contenido varía por categoría:
`ruta:línea` en `secrets`, `paquete@versión_instalada` en `sca`. Cada categoría declara
columnas extra que se imprimen después de las cinco base, en el orden declarado —
`sca` añade `MANIFEST` (la ruta del manifiesto que declara la dependencia, ingrediente
de su huella en §5, y que de otro modo desaparecería de la tabla) y `FIXED` (la versión
que corrige el problema, o `(none)` si la herramienta no reporta ninguna). No se añade
`INSTALLED`: ya es visible en `LOCATION`, y repetirla sería ruido.

**El reporter no tiene un solo condicional por herramienta ni por categoría.** El
contrato de columnas se declara como *dato* — un `ReportSchema` con una `Column` por
columna (cabecera, campos de `Finding` a resolver, separador, ancho máximo, lado de
truncado) — que cada `ToolIntegration` expone (`report_schema()`, junto a
`native_severity_domain()` en el mismo puerto). El componente de render recorre ese
dato genéricamente: no existe, en ningún punto del núcleo, una rama que pregunte "¿es
esto `sca`?". Añadir una segunda herramienta de una categoría cubierta, o una tercera
categoría, es declarar su `ReportSchema` — nunca tocar el renderizador.

**Orden y determinismo (R3):** una tabla por categoría, ordenada por severidad
descendente y, dentro de la misma severidad, por `LOCATION` y luego por huella completa
— el tercer criterio garantiza orden total incluso ante un empate exacto en los dos
primeros. Los anchos de columna se derivan del propio contrato y de las filas que se
están imprimiendo, nunca del terminal: el módulo de render no consulta
`shutil.get_terminal_size`, `os.get_terminal_size` ni `isatty` en ningún punto — ese es,
literalmente, el mecanismo de verificación (un test comprueba que el módulo no importa
`shutil`, `os` ni `sys` en absoluto). "Ancho fijo" significa fijo *para esa tabla*, no
una constante universal: se recalcula a partir del contenido en cada render, pero el
resultado no cambia si se ejecuta dos veces sobre los mismos datos, con o sin TTY.

**Rutas largas se truncan por la izquierda**, conservando el final — nombre de archivo
y línea en `secrets`, la ruta del manifiesto en `sca` — con un prefijo `...` visible.
Truncar por la derecha, el caso general de una columna sin una cola significativa (como
una descripción larga), conserva en cambio el inicio.

**El secreto nunca se imprime.** No por una regla de redacción en el reporter, sino
porque `Finding` no tiene, en ningún campo, el valor en claro (§5, §9) — la propia
forma del modelo hace la fuga estructuralmente imposible en esta capa, sin depender de
que nadie recuerde redactarla.

**`FP` — el prefijo corto de huella:** `v1:` más los primeros N caracteres hexadecimales
de la huella completa, con N el mínimo (desde 8) que mantiene único cada prefijo *dentro
de las huellas del run actual* — suprimidas incluidas, para que dos hallazgos que
difieren solo en si están suprimidos nunca compartan el mismo `FP` visible. Es
exactamente lo que alguien copia para poner un hallazgo en una exclusión (§8.4): el
esquema de exclusiones acepta la huella completa o un prefijo, y si un prefijo
configurado resulta ambiguo contra los hallazgos de un run concreto —cosa que solo
puede saberse en ese run, nunca en el momento en que se escribió la exclusión—, es
error de configuración explícito, nunca una supresión silenciosa del hallazgo
equivocado. La unicidad de `FP` es una garantía de *este run*, no de todos los runs
futuros: un prefijo corto copiado hoy podría, en teoría, dejar de ser único cuando
aparezca un hallazgo nuevo con el mismo prefijo — el mismo mecanismo de ambigüedad lo
detecta entonces, en vez de fallar en silencio.

### Volumen del reporte de consola

- **Sin hallazgos activos en una categoría:** una sola línea (`secrets: No findings.`),
  nunca una tabla vacía con solo cabecera.
- **Más hallazgos que el límite configurado:** se muestran los primeros N (`--max-rows`,
  default 20), ya ordenados por severidad descendente, y una línea final indica cuántos
  quedan fuera (`... 37 more secrets findings (showing 20 of 57)`).
- **`--max-rows` es exclusivamente una opción de consola.** El JSON canónico —y el
  futuro exportador SARIF, cuando exista— llevan siempre la evidencia completa, sin
  excepción: recortar hallazgos en el formato que efectivamente consume un pipeline
  convertiría una comodidad de lectura humana en una pérdida silenciosa de evidencia,
  exactamente la clase de fallo que este documento trata en todas partes con el mismo
  rigor que un defecto de seguridad. `render_json` no tiene, ni tendrá, un parámetro de
  límite de filas.
- **Run con `RunResult.status = partial`:** el gate nunca imprime `PASSED`, sin
  excepción — literalmente `Gate: NOT EVALUATED — evidence is incomplete (1 of 2
  executions did not complete)`, en vez de un veredicto positivo sobre evidencia que el
  propio run declara incompleta (§5). Si además hay incumplimientos calculables sobre
  la evidencia disponible, se listan igual, marcados explícitamente como evaluados
  *a pesar de* la evidencia incompleta — nunca como el veredicto final del run.
- **Suprimidos y exclusiones vencidas:** sus conteos se imprimen siempre,
  incluso en cero — es precisamente el run más limpio donde más importa poder confiar
  en que nada se barrió en silencio (§8.4). Las omisiones de herramienta activas por
  política (§5, §8.4) se destacan en su propia línea, con herramienta, responsable y
  fecha límite.
- **Desvío de política:** cuando un flag o variable de entorno reemplaza por completo
  la tabla `[thresholds]` declarada en el archivo de política —o cualquier
  `[thresholds.<categoría>]`— (§8.1, §8.4), el reporte lo anuncia en una línea
  explícita, antes del veredicto, nombrando cada tabla reemplazada — nunca en
  silencio. Cuando el gate sí está activo, el reporte nombra además, para cada
  categoría que corrió, de qué tabla salió el umbral que se le aplicó — su propia
  `[thresholds.<categoría>]` o el `[thresholds]` por defecto (§8.1).

---

## §8. Diseño del CLI

El CLI es el producto — no un envoltorio delgado sobre una librería que sea lo que
realmente importa. Su ergonomía es requisito de este documento, no una consecuencia
que se resuelve después de diseñar el núcleo.

### Forma general

```
linceo scan <categoría> [opciones]
```

Con la **categoría** (`secrets`, `sca`) como sustantivo primario del comando, y la
herramienta concreta que la implementa como detalle intercambiable vía `--tool`.
Razón: el pipeline de un cliente declara una intención ("quiero saber si hay secretos
expuestos"), no la elección de un proveedor concreto; cambiar de escáner de secretos
mañana no debería exigir tocar la definición del pipeline. Esa es la propuesta de
valor central del proyecto frente a invocar Gitleaks directamente, y ponerla en la
gramática del propio comando la hace visible en el primer contacto con la herramienta,
en vez de dejarla como un detalle de implementación que solo se descubre leyendo
documentación.

### Flags: nada es obligatorio salvo la categoría

| Flag | Default | Inferencia / notas |
|---|---|---|
| `--platform` | `auto` | Detecta desde variables de entorno del runner (solo dentro de los proveedores, ver R1); cae a `local` si ninguna coincide. |
| `--tool` | default de la categoría | Un único default por categoría en v0.1 (Gitleaks para `secrets`, Trivy para `sca`). |
| `--path` | directorio actual | — |
| `--config` | rutas convenidas dentro del workspace | Ver R5 — nunca resuelve dentro del paquete del orquestador. Un único archivo cubre umbrales, exclusiones y omisión de herramientas (§8.4), además de los ajustes escalares de esta tabla. |
| `--output-dir` / `--format` | JSON + consola | SARIF disponible explícitamente vía `--format sarif`. |
| `--fail-on` | sin valor (no reemplaza la política) | Justificación completa en §8.1. Nunca acepta `info` (§6). Dado, reemplaza por completo la tabla `[thresholds]` del archivo de política (§8.1, §8.4) — se anuncia en el reporte cuando ocurre. |
| `--max-rows` | 20 | Filas por tabla en el reporte de consola (§7); nunca afecta a JSON ni, en el futuro, a SARIF. |
| `--token-env` / `--token-file` | convención documentada por adaptador | Ver §9 — nunca `--token VALOR`. |
| `--continue-on-tool-error` / `--no-continue-on-tool-error` | desactivado, sin valor propio (viene del archivo si no se pasa) | Ver §5 (fallo parcial). |
| `--max-db-age` | umbral de §5 (7 días) | Ver §5 (frescura de datos). |
| `--strict-normalization` / `--no-strict-normalization` | desactivado, sin valor propio (viene del archivo si no se pasa) | Ver §6. |
| `--dry-run` | — | Imprime la línea de comandos completa que se ejecutaría, sin secretos (ver §9), y sin ejecutar nada. |
| `--log-level` / `--log-format` | — | — |

Nota sobre `--continue-on-tool-error` y `--strict-normalization`, porque su forma
cambió en esta revisión del contrato: antes eran flags booleanos que el CLI pasaba
*siempre* a la resolución de configuración, con lo que el archivo de política nunca
podía ganar aunque la cadena de §5/R5 dijera lo contrario — un defecto real, no una
decisión de diseño. Ahora son pares `--flag/--no-flag` de tres estados: no mencionados
en absoluto, mencionados en verdadero, o mencionados en falso; solo cuando el operador
los menciona explícitamente entran en la capa CLI de la cadena de precedencia, y en su
ausencia el archivo (o el default) decide, tal como exige §5/R5.

Comandos auxiliares:

- **`doctor`** — disponibilidad, versión y compatibilidad de cada herramienta
  configurada, más el estado de frescura de sus fuentes de datos (§5).
- **`context`** — imprime el `ExecutionContext` resuelto, en JSON. Es lo que hace
  depurable un adaptador de contexto ajeno cuando no se tiene acceso directo al runner
  que lo produjo: alguien puede pegar la salida de `context` en un reporte de bug sin
  necesitar credenciales del pipeline.
- **`version`** — versión del orquestador y del esquema de `Finding`/`RunResult`.

### §8.1. Default de `--fail-on`: `none`, y por qué

**Elegido: `none` por defecto.** El `Verdict` se calcula siempre, en todo run, y viaja
íntegro en el reporte estructurado, independientemente del valor de `--fail-on`; el
flag decide únicamente si ese veredicto se traduce en un código de salida `1`. La
salida por consola, incluso en modo no bloqueante, **siempre** termina con la llamada
a la acción explícita: por ejemplo, *"con `--fail-on HIGH` este run habría fallado: 3
CRITICAL, 12 HIGH"*. El modo no bloqueante por defecto no es silencioso sobre lo que
habría pasado si estuviera activado.

**Precisión de mecanismo, sin cambio de comportamiento en el caso "nada configurado":**
el CLI ya no inyecta `none` en la capa de flags de forma incondicional — `--fail-on`
ausente significa, literalmente, ausente de esa capa, dejando que el archivo o el
default compilado decidan, tal como exige la cadena de §5/R5 (§8.4 documenta el defecto
real que esto corrige). El resultado cuando nada está configurado en ninguna capa sigue
siendo exactamente el descrito aquí: sin gate, permisivo. Lo único que cambió es que
ahora un archivo de política puede, sin necesidad de ningún flag, activar el gate por
sí solo — el CLI ya no se interpone forzando "ninguno" delante de él.

**Descartado: `HIGH` bloqueante por defecto.** Sobre un repositorio con historia real,
la primera ejecución pone el build en rojo de inmediato, y la reacción más probable de
un equipo que acaba de adoptar la herramienta es desinstalarla ese mismo día. El
mecanismo de baseline (§8.2) existe exactamente para este caso, pero exige un paso
deliberado previo (`baseline init`) — y el usuario que integra el CLI en su pipeline y
ve rojo en el primer intento nunca llega a descubrir que ese paso existe: el fallo
ocurre antes de que la mitigación esté siquiera a la vista.

**Descartado: default dependiente del contexto** (bloqueante en CI, permisivo en
local). Rompería la propiedad de que el mismo comando produce el mismo veredicto tanto
en el portátil de un desarrollador como en el runner de CI — que es precisamente lo
que permite reproducir localmente un fallo visto en el pipeline sin tener que conocer
una regla de comportamiento oculta y no documentada. Contradice directamente el
espíritu de determinismo exigido por R3, aunque R3 hable formalmente de estado y no de
configuración implícita.

El criterio que decide entre las tres opciones es una asimetría de recuperabilidad, no
una preferencia estética: un default demasiado laxo falla en la dirección de "todavía
no entregué valor de bloqueo", y se corrige con una sola acción explícita del usuario
(activar el gate). Un default demasiado estricto falla en la dirección de "me
desinstalaron", que no tiene corrección posible una vez ocurre. Para un proyecto cuyo
mayor riesgo identificado es precisamente no llegar nunca a un usuario real (§13.3),
esta asimetría fuerza la elección hacia el lado permisivo. La compensación es que el
quickstart del proyecto y el snippet de pipeline recomendado en la documentación
muestran `--fail-on HIGH` de forma explícita desde el primer ejemplo, de modo que el
estado final deseado quede visible de inmediato — el default permisivo es solo la
rampa de entrada, no la recomendación final del proyecto.

Aclaración necesaria porque de otro modo es ambigua: el modo no bloqueante **no**
significa que el proceso siempre termine en `0`. Un fallo de ejecución de herramienta o
un run con evidencia incompleta (§5) sigue produciendo código `3` sin importar el
valor de `--fail-on`. "No bloqueo por hallazgos encontrados" y "no aviso de que algo
salió mal" son dos afirmaciones distintas, y solo la primera depende de este flag. Es
además contrato público cubierto por semver (junto con el resto de flags y códigos de
salida): cambiar el default en una versión futura es un cambio incompatible.

#### `--fail-on` es el caso simple de un mecanismo más general: umbrales por severidad

Esta revisión del contrato generaliza el gate de "un único punto de corte" a "un
conteo máximo permitido por severidad" (`[thresholds]`, detallado en §8.4), porque un
punto de corte no puede expresar, por ejemplo, "cero CRITICAL, hasta cinco HIGH,
hasta veinticinco MEDIUM sin bloquear" — un patrón de adopción real, no hipotético,
donde un equipo quiere presión decreciente por severidad en vez de un único muro. La
decisión explícita es que **`--fail-on` no queda descartado ni se le pide al operador
que aprenda una sintaxis nueva para el caso común**: sigue siendo la forma de escribir
"cero permitido en esta severidad y en todas las más graves" (`thresholds_from_fail_on`
lo traduce mecánicamente), así que el contrato público de §8 —el propio flag, sus
valores, el código de salida que produce— no cambia. Lo que cambia es que ahora existe,
además, una forma más rica de decir lo mismo cuando la política lo necesita, declarada
en archivo, nunca solo en flags (§8.4).

**Precedencia entre `--fail-on` y `[thresholds]`: el flag gana entero, nunca se
mezclan por severidad.** Si `--fail-on` (o su variable de entorno, `LINCEO_FAIL_ON`)
llega desde una capa por encima del archivo en la cadena de §5/R5, reemplaza la tabla
`[thresholds]` completa — no rellena solo las severidades que el flag no menciona.
Alternativa descartada: fusionar por severidad (el flag fija unas, el archivo conserva
el resto). Se descarta porque el resultado efectivo del gate dejaría de leerse en una
sola fuente: alguien depurando un pipeline tendría que reconstruir mentalmente qué
severidad vino de dónde. Con el flag reemplazando entero, una sola pregunta —"¿hay un
`--fail-on` o un `LINCEO_FAIL_ON` activos?"— basta para saber si el archivo importa en
absoluto para el gate de este run. El precio de esta simplicidad, pagado a propósito:
**el reemplazo se anuncia siempre en el reporte** (§7), antes del veredicto, nombrando
el mecanismo que ganó y lo que la política del archivo declaraba y perdió — un gate
que se desvía en silencio de la política que un repositorio declaró perdería la
confianza de quien la escribió, y ese costo es estrictamente mayor que el de una línea
de aviso.

#### Umbrales por categoría: `[thresholds.<categoría>]`

**El problema, encontrado en uso real:** `[thresholds]` es una única tabla, aplicada
igual a cualquier categoría que corra en el run. Cuatro secretos expuestos es grave;
ocho CVE `HIGH` en dependencias transitivas es un martes cualquiera para muchos
equipos. Con una sola tabla, el operador elige entre ser demasiado estricto con `sca`
o demasiado laxo con `secrets` — o mantener dos documentos de política distintos
(rompiendo la premisa de §8.5 de que es "un documento por repositorio, no por
invocación"), o sobrescribir con `--fail-on` en cada paso del pipeline, perdiendo con
ello la tabla `[thresholds]` entera en vez de solo el ajuste que quería hacer (ver
más arriba en esta misma sección).

**Decisión: `[thresholds.<categoría>]` convive con `[thresholds]`, sin fusión de
campos entre ambos — full esquema en §8.4.**

```toml
[thresholds]             # aplica a cualquier categoría sin tabla propia
high = 5

[thresholds.secrets]     # reemplaza [thresholds] por completo para "secrets"
critical = 0
high = 0

[thresholds.sca]         # reemplaza [thresholds] por completo para "sca"
high = 5
medium = 25
```

En este ejemplo, `secrets` nunca ve el `high = 5` de `[thresholds]` — su propia
tabla dice `high = 0` y esa es toda la historia para esa categoría. `sca` declara
también su propia tabla, así que tampoco consulta `[thresholds]`; el bloque global
solo entra en juego para una categoría que no declaró ninguna tabla propia.

**Precedencia elegida: reemplazo del bloque entero, nunca merge campo por campo —
con un criterio explícito, no una elección arbitraria entre los dos precedentes que
ya existen en este documento:**

- `--fail-on` ya reemplaza `[thresholds]` por completo (más arriba en esta misma
  sección): un flag no edita parcialmente la intención declarada de un archivo.
- `[tool_defaults]` frente a `[tools.<nombre>]` (§8.5), en cambio, sí mezclan campo
  por campo: cada uno de los cuatro campos de nivel 1 (`exclude_paths`,
  `scan_history`, `custom_rules_path`, `timeout`) es una perilla de comportamiento
  independiente, sin relación entre sí — fijar `timeout` en `[tools.gitleaks]` no
  dice nada sobre qué debería pasar con `exclude_paths`, así que no hay pérdida de
  legibilidad en dejar que cada campo se resuelva por su cuenta.

Una tabla de umbrales no tiene esa propiedad: sus claves — las severidades de §6 —
no son perillas independientes, son las piezas de un mismo perfil de riesgo
declarado como conjunto. Si `[thresholds.secrets]` fijara solo `high = 0` y heredara
`medium` de `[thresholds]` por mezcla campo por campo, quien lee
`[thresholds.secrets]` no podría responder "¿qué bloquea a `secrets`?" mirando solo
ese bloque — tendría que revisar `[thresholds]` también, exactamente el problema que
el párrafo anterior ya resolvió una vez para `--fail-on` frente a `[thresholds]`
("alguien depurando un pipeline tendría que reconstruir mentalmente qué severidad
vino de dónde"). Copiar el criterio de §8.5 aquí reintroduciría, para categorías, el
mismo defecto que copiar el criterio de `--fail-on` evita — de ahí que la elección
correcta no sea "aplicar siempre merge" ni "aplicar siempre reemplazo", sino mirar si
las claves del bloque son perillas independientes (§8.5) o un perfil declarado como
conjunto (aquí y en `--fail-on`/`[thresholds]`). Por eso el reemplazo entero: la
respuesta a "qué bloquea a `secrets`" siempre está completa en un único bloque — el
suyo propio si existe, o si no, `[thresholds]`.

**El precio, dicho explícitamente:** un documento que declara `[thresholds.secrets]`
con solo `high = 0` dice, para `secrets`, que `medium` es *ilimitado* — no hereda el
`medium = 25` de `[thresholds]` aunque a primera vista pudiera parecer razonable que
lo hiciera. Quien escribe una tabla de categoría se compromete a declarar en ella
todo lo que quiere limitar para esa categoría, sin dar nada por sentado del bloque
global. Se acepta este precio por la misma razón que se acepta en `--fail-on` frente
a `[thresholds]`: una respuesta completa en una sola fuente vale más que ahorrarse
repetir una clave.

**`--fail-on` (CLI o `LINCEO_FAIL_ON`) sigue reemplazando todo — ahora "todo" incluye
las tablas de categoría.** El flag es, por diseño, ciego a la categoría — el mismo
punto de corte para cualquier hallazgo — así que cuando gana, reemplaza tanto
`[thresholds]` como cualquier `[thresholds.<categoría>]` que el archivo declarara;
nunca dejaría, por ejemplo, la tabla de `secrets` vigente mientras reemplaza solo la
de `sca`. El reporte anuncia el reemplazo nombrando cada tabla reemplazada por
separado (`[thresholds]` y cada `[thresholds.<categoría>]` con contenido propio),
extendiendo el mismo mecanismo de anuncio que este documento ya exige para el caso
de una sola tabla.

**Una categoría no registrada (`Category`, ADR §5) bajo `[thresholds.<nombre>]` es
error de configuración, nunca una tabla ignorada en silencio** — el mismo principio
que ya rige un campo desconocido en cualquier otro punto de este documento (§8.4,
§8.5): un typo en `[thresholds.secret]` (sin la "s") no debe traducirse en "esta
categoría queda sin gate", indistinguible en el reporte de un operador que decidió a
propósito no ponerle umbral.

**El motor no conoce categorías por nombre.** `core.gate` cuenta hallazgos activos
por categoría y busca, para cada una, la tabla que le corresponde mediante un único
método (`ThresholdResolution.thresholds_for`) — nunca un condicional por nombre de
categoría. Añadir una tercera categoría al catálogo de integraciones (§14) no exige
tocar `core.gate` ni `core.policy`: la categoría nueva obtiene un gate correcto por
construcción en cuanto existe en `Category`, exactamente como el reporter ya declara
para sus tablas de columnas (§7, "El reporter no tiene un solo condicional por
herramienta ni por categoría").

**Cambio de comportamiento, dicho en voz alta:** antes de esta revisión, el gate
contaba los hallazgos activos de *todas* las categorías de un run agrupados en un
único conteo por severidad, evaluado contra una sola tabla — dos categorías
competían por el mismo cupo. Con umbrales por categoría, cada categoría se cuenta y
se evalúa por separado, incluso cuando ambas caen bajo el mismo `[thresholds]`
global sin tabla propia. Esto no cambia ningún comportamiento observable del CLI del
v0.1 hoy — que solo corre una categoría por invocación (§8, "Una categoría por
invocación en v0.1"), así que nunca hay dos categorías en el mismo run que puedan
competir por el mismo cupo — pero sí es el comportamiento correcto para cuando esa
restricción de superficie se levante (§1): un run con `secrets` y `sca` a la vez debe
evaluar cada categoría contra su propio perfil de riesgo, nunca sumarlas en un
contador compartido.

**Verificación:** los mismos tests dirigidos por tabla que ya cubren
`parse_policy_document` (§8.4) se extienden con una tabla de categoría, una categoría
desconocida, y el caso de reemplazo por `--fail-on`; `core.gate.find_breaches` se
prueba con dos categorías con tablas distintas en el mismo run para confirmar que
ninguna interfiere con la otra.

### §8.2. Baseline y supresiones

> **Nota de esta revisión del contrato:** lo que esta sección llama "entrada de
> baseline" se modela en código como `Exclusion` — el mismo mecanismo, generalizado
> con un campo de alcance (ver abajo) y cargado desde el documento de política único
> de §8.4 en vez de un fichero de baseline aparte. Cada regla descrita aquí sigue
> vigente sin cambios; lo único que cambia es de dónde se lee la entrada.

Sin un mecanismo de baseline, activar el gate sobre un repositorio con historia real
produce, de forma predecible, cientos de hallazgos el primer día, y la reacción del
equipo es desactivarlo — el mismo riesgo que motiva el default de §8.1, atacado desde
el otro lado. Se resuelve con un único mecanismo que sirve a la vez para la adopción
inicial masiva y para supresiones puntuales continuas: el baseline de adopción es la
forma *generada* del mismo esquema de exclusiones (§8.4), no un concepto de diseño
distinto.

- **Referenciado por huella (§5), nunca por ruta y número de línea.** Una supresión
  atada a ruta+línea se rompe con el primer reformateo o refactor del fichero
  afectado, y en la práctica el equipo aprende a desconfiar de un mecanismo que se
  desincroniza solo.
- **Caducidad obligatoria.** Una entrada de supresión sin `expires_at` es **error de
  configuración** (código de salida `2`), no un default permisivo silencioso: una
  supresión sin fecha de vencimiento es deuda técnica que nunca vuelve a revisarse.
  Una entrada **vencida vuelve a contar activamente para el gate**, y aparece
  destacada en el resumen del run con los días de retraso sobre su vencimiento y su
  responsable declarado, de modo que el reporte nombre explícitamente a quien le
  corresponde tomar la decisión pendiente. Adicionalmente, existe un **horizonte
  máximo de vencimiento, configurable, con default de 90 días**: un `expires_at`
  fijado arbitrariamente lejos en el futuro (`2099-01-01`) es deuda eterna con pasos
  extra, así que excederlo también es error de configuración, no solo la ausencia del
  campo.
- **Metadatos obligatorios de justificación:** `reason` (motivo declarado de la
  supresión) y `owner` (responsable). Una entrada sin ambos campos es inválida y el
  cargador la rechaza. Una supresión anónima y sin motivo es, en la práctica,
  indistinguible de un descuido que nadie va a poder auditar después.
- **Es configuración de cliente, sujeta a R5:** las exclusiones viven en el mismo
  documento de política que los umbrales (§8.4), resuelto por convención o por
  `--config` explícito — no existe un `--baseline` separado: un único archivo, una
  única cadena de precedencia. **Nunca en este repositorio**, ni siquiera como ejemplo
  con datos ficticios cargables por accidente.
- **Alcance (`repositories`), añadido en esta revisión.** Una exclusión sin `repositories`
  (o con la lista vacía) es global: aplica a cualquier repositorio que la cargue.
  Con `repositories` no vacío, aplica únicamente cuando `ExecutionContext.repository`
  coincide con alguno de los declarados. El caso que lo motiva es real: una
  organización con un documento de política compartido entre varios repositorios
  necesita poder decir "esta cadena de prueba es un falso positivo en el repositorio
  `X`" sin suprimir accidentalmente el mismo patrón en `Y`, donde podría ser un
  secreto real. Una exclusión fuera de alcance para el repositorio actual no cuenta
  ni como supresión ni como vencida — es, simplemente, silenciosa para ese run.
- **`baseline init`** genera el fichero completo a partir de un run real sobre el
  estado actual del repositorio: usa un `reason` compartido que declara "adopción
  inicial", un `owner` correspondiente a quien ejecuta el comando, y un vencimiento
  por defecto más corto que el manual. El objetivo explícito de este diseño es que el
  baseline masivo **caduque por oleadas y fuerce un triaje real** a lo largo del
  tiempo, en vez de congelar permanentemente el estado del repositorio en el momento
  de la adopción. Exigir una justificación individual y específica para, digamos,
  cuatrocientas entradas generadas de una sola vez volvería el mecanismo inutilizable
  en la práctica — esa es una concesión deliberada, no un descuido de rigor.
- **Entradas huérfanas por subida de versión de huella.** Como la versión del
  algoritmo va embebida en el propio valor de la huella (`v1:…`, ver §5), un run
  detecta cuándo una entrada del baseline referencia una versión de huella que ya no
  es la vigente, y la reporta como **huérfana, con conteo propio y visible en el
  resumen** — nunca la suprime en silencio bajo el supuesto de que sigue siendo
  válida; se falla cerrado y de forma visible. La recuperación de este caso exige una
  decisión de formato tomada desde ahora, no añadida después: **cada entrada de
  baseline guarda, junto a la huella, los campos de identidad legibles que la
  originaron** (ruta, regla o identificador de vulnerabilidad, paquete, versión, según
  la categoría). Sin esos campos, una subida de versión del algoritmo de huella sería
  irrecuperable, y todo cliente con un baseline existente lo perdería de golpe en el
  mismo momento. Con ellos, un comando `baseline migrate` reejecuta la resolución
  contra el estado actual del workspace y vuelve a indexar las entradas por esos
  campos legibles en vez de por la huella vieja. El mismo mecanismo cubre, sin
  necesidad de un caso especial adicional, el renombrado de `rule_id` entre versiones
  de una herramienta, ya mencionado como limitación en §5.

### §8.3. Framework de CLI — Decidido: Typer

**Elegido: Typer**, anclado `>=0.12,<1.0` — rango original; ver la enmienda de
2026-09-17 más abajo, que lo reemplaza por un pin exacto sobre `typer-slim` sin
alterar el resto de esta decisión. Motivo específico de este proyecto: `--fail-on`
y `--strict-normalization` validan contra la escala de severidad de §6, y Typer valida un
argumento contra un `Enum` de Python de forma nativa. En argparse esa validación se
escribe y se mantiene sincronizada a mano — exactamente la duplicación que desalinea el
CLI respecto del núcleo cada vez que §6 cambia. Con §8 declarando que el CLI es el
producto, pagar esa plomería a mano no se justifica.

**Descartado: argparse.** Sus argumentos a favor son reales y se registran, no se
descartan por debilidad: menos superficie de cadena de suministro que auditar en una
herramienta de seguridad, y cero riesgo de que una actualización de una dependencia
rompa un contrato ya cubierto por semver (flags y códigos de salida, §8). Se descarta
específicamente por el coste recurrente de mantener a mano la validación de argumentos
sincronizada con la escala de §6, no porque esos argumentos sean inválidos.

**Descartado: Click.** Mismo coste de dependencia que Typer — Typer se construye sobre
Click — sin el tipado derivado de anotaciones que es el motivo concreto por el que se
elige Typer.

**Relación con R2, explícita para que esta decisión no se lea como un debilitamiento de
esa restricción:** ni Typer ni su árbol de dependencias abren conexión de red. La decisión
de R2 —no existe cliente HTTP en las dependencias base del paquete— sigue vigente sin
cambios, y su mecanismo de verificación sigue siendo, únicamente, el test de socket
envenenado descrito en §4. La lista de dependencias del paquete nunca fue, y no pasa a
ser con esta decisión, el mecanismo que hace a R2 verificable.

Restricciones que acompañan la decisión:

1. Typer vive únicamente en `cli/`. Nunca se importa desde `core/`, `adapters/` ni
   `providers/`; el test de AST descrito en §4 para la frontera de `core/` cubre también
   esta regla.
2. La capa de CLI traduce argumentos de línea de comandos a objetos del dominio y no
   contiene lógica propia. Un run completo debe poder ejecutarse desde Python sin pasar
   por Typer en ningún punto.
3. Anclada por rango de versión mayor (`<1.0`) y auditada en el lockfile — una subida de
   versión mayor de Typer pasa por el mismo escrutinio que cualquier otro cambio
   incompatible cubierto por semver en este documento. Para `typer-slim`
   específicamente, ese escrutinio ahora se aplica también a un salto de versión
   *menor*: ver la enmienda inmediatamente abajo.

#### Enmienda (2026-09-17): `typer-slim` invirtió su relación con `typer`; el pin pasa de rango a versión exacta

La elección de Typer se implementa en `pyproject.toml` a través del paquete
`typer-slim`, no `typer` directamente, precisamente para obtener la API de Typer sin
arrastrar su árbol de dependencias completo. Hasta la versión `0.21.1`, esa
distribución dependía únicamente de `click` y `typing-extensions` en su base —
`rich` y `shellingham` quedaban detrás del extra `standard`, nunca instalados por
defecto —, cumpliendo la superficie mínima que motiva esta sección. A partir de la
versión `0.22.0`, `typer-slim` invirtió esa relación: su única dependencia base pasó
a ser `typer>=0.22.0`, es decir, el paquete completo, que arrastra `rich`,
`shellingham`, `pygments`, `markdown-it-py`, `mdurl` y `annotated-doc`. El rango
original (`<1.0`) no excluía nada de esto, y así se publicó `v0.1.0` en PyPI: nueve
paquetes instalados en el entorno base en vez de tres, contradiciendo directamente la
restricción de superficie de dependencia que esta sección declara. **PyPI no permite
republicar `v0.1.0`**; la corrección se distribuye como `v0.1.1`.

El pin pasa de rango a versión exacta — `typer-slim==0.21.1`, la última versión cuya
dependencia base, verificada contra `requires_dist` en el índice de PyPI, es
exactamente `click>=8.0.0` + `typing-extensions>=3.7.4.3`, sin `typer` en ningún
camino de resolución del entorno base. Un rango, aunque más estrecho que `<1.0`,
seguiría dejando que un bump rutinario de dependencias cruzara ese límite de
inversión sin que nadie lo decidiera explícitamente — exactamente lo que ya ocurrió
una vez. Un pin exacto exige una edición deliberada y revisada de
`pyproject.toml` para moverse, coherente con la restricción 3 de esta sección.

El invariante es verificable, no solo documentado — mismo estándar de
verificabilidad que §4 exige para las cinco restricciones: `tests/unit/test_dependency_surface.py`
falla si `typer`, `rich`, `shellingham`, `pygments`, `markdown-it-py`, `mdurl` o
`annotated-doc` aparecen en el cierre transitivo de las dependencias de *runtime* de
`linceo` dentro de `uv.lock` (deliberadamente distinto de comprobar qué es importable
en el entorno de desarrollo activo, donde herramientas como `pytest` traen su propio
`pygments` sin que eso viole nada de lo declarado aquí).

**Disparador para reconsiderar este pin exacto**: únicamente si una versión de
`typer-slim` publicada después de `0.21.1` vuelve a declarar una dependencia base sin
`typer` — verificado contra `requires_dist` en el índice de PyPI antes de mover el
pin, nunca asumido por el número de versión —, o si el equipo decide explícitamente
aceptar el árbol de dependencias completo de `typer` como parte de la superficie del
paquete base, lo que exigiría revisar también la relación con R2 registrada arriba.
Hasta entonces, `typer-slim` permanece anclado exactamente en `0.21.1`.

### Una categoría por invocación en v0.1, y por qué no contradice §1

El límite es deliberadamente de superficie de CLI, no del núcleo: el modelo de
resultado y el código de salida ya hablan en términos de *run*, no de *invocación de
herramienta* (§5), así que ampliar el CLI en el futuro para aceptar
`scan secrets sca` en una sola invocación, o un flag `--all`, debe ser un cambio
aditivo sobre la capa de parsing de argumentos — nunca un cambio sobre `RunResult`, el
gate o el esquema del reporte. Se registra explícitamente como criterio de aceptación
del v0.1: si añadir esa capacidad de CLI en el futuro exige tocar cualquiera de esos
tres, el diseño de esta versión falló en su propio objetivo declarado.

### Códigos de salida como contrato público, cubierto por semver

**Decisión registrada explícitamente, no un cambio silencioso introducido durante la
redacción de este documento:**

| Código | Significado |
|---|---|
| `0` | El run se ejecutó completo y el gate pasó (o `--fail-on none`). |
| `1` | El run se ejecutó completo y el gate falló por hallazgos que superan el umbral. |
| `2` | Error de uso del CLI **o** error de configuración. |
| `3` | Fallo de ejecución de una herramienta, o evidencia incompleta (`RunResult.status = partial` sin `--continue-on-tool-error`). |
| `4+` | Reservado para uso futuro. |

Se registra explícitamente la **fusión de error de uso y error de configuración en el
código `2`**, en vez de mantenerlos separados: desde el punto de vista de quien
escribe la definición de un pipeline, ambos casos significan lo mismo en la práctica —
"me invocaste mal, no llegó a correr ningún escaneo" — y ambos se corrigen de la misma
forma, editando la definición del pipeline o del fichero de configuración. Separarlos
en dos códigos distintos añadiría un valor más al contrato sin cambiar la reacción
correcta de ningún consumidor automatizado, así que no se justifica el costo de
superficie adicional.

**Regla de precedencia entre códigos**, consecuencia directa del modelo de §5: si
alguna ejecución de herramienta falló y no está activo `--continue-on-tool-error`, el
código `3` gana sobre el `1` aunque el gate también hubiera fallado de haber tenido
evidencia completa — "el orquestador está roto" debe dominar sobre "el orquestador
encontró hallazgos", porque son dos mensajes que un pipeline necesita poder reaccionar
de forma distinta, y confundirlos lleva en la práctica a que se acabe ignorando a
ambos por igual.

### §8.4. Política de gate configurable en archivo

Antes de esta revisión, los umbrales solo se configuraban por flag (`--fail-on`) y el
baseline vivía, conceptualmente, en un fichero aparte nunca llegado a conectar al CLI.
Esta sección fija un único documento — el mismo `.devsecops/config.toml` (o `--config`
explícito) que ya resuelve la cadena de §5/R5 — que cubre tres mecanismos
relacionados pero distintos: **umbrales** (§8.1), **exclusiones** (§8.2, generalización
del baseline) y **omisión temporal de herramienta** (§5). Los tres se validan por
completo **al cargar la configuración**, antes de invocar ninguna herramienta: un
documento inválido falla con código `2` de inmediato, nunca a mitad de un run.

**Esquema, con datos íntegramente sintéticos (R5):**

```toml
version = 1                      # versión del esquema del documento; solo 1 es válida hoy

fail_on = "high"                 # ver §8.1 — capa "file" de la cadena de precedencia
continue_on_tool_error = false
strict_normalization = false
max_expiry_horizon_days = 90     # horizonte máximo para expires_at, exclusiones y omisiones

[report]
max_rows = 20                    # solo consola (§7); JSON y SARIF llevan todo siempre

[thresholds]                     # default: aplica a cualquier categoría sin tabla propia (§8.1)
high = 0
medium = 25
# `info` aquí es error de configuración (§6) — nunca un nivel de umbral válido.

[thresholds.secrets]             # reemplaza [thresholds] por completo para "secrets" (§8.1)
critical = 0
high = 0

[thresholds.sca]                 # reemplaza [thresholds] por completo para "sca" (§8.1)
high = 5
medium = 25
# `[thresholds.bogus]` sería error de configuración: "bogus" no es una categoría (§5).

[[exclusions]]
fingerprint = "v1:9c4e0a71…"     # huella completa o prefijo inequívoco (§7, "FP")
reason = "Synthetic credential in the parser test corpus"
owner = "team-atlas"
expires_at = 2026-11-30          # obligatorio; sin él, error de configuración

[[exclusions]]
fingerprint = "v1:1b77de02…"
reason = "Upstream fix pending release"
owner = "team-atlas"
expires_at = 2026-10-15
repositories = ["orion-web", "orion-api"]   # ausente/vacío = alcance global (§8.2)

[[skipped_tools]]
tool = "gitleaks"
reason = "Rollout paused while the team triages the initial backlog"
owner = "team-atlas"
expires_at = 2026-10-01          # vencida, la herramienta vuelve a ejecutarse (§5)
```

**Umbrales.** Ver §8.1 para la relación completa con `--fail-on`, y su subsección
"Umbrales por categoría" para la relación entre `[thresholds]` y
`[thresholds.<categoría>]`: el archivo puede declarar `[thresholds]` directamente
—como default para cualquier categoría sin tabla propia—, especializar una categoría
concreta con `[thresholds.<nombre>]` —que reemplaza `[thresholds]` por completo para
esa categoría, nunca lo mezcla campo por campo—, o dejar que un `fail_on` plano
(misma capa, archivo) se traduzca vía `thresholds_from_fail_on` cuando no se declara
ninguna tabla. Si un documento declara `fail_on` junto con `[thresholds]` y/o alguna
`[thresholds.<nombre>]`, cualquiera de estas tablas gana sobre el `fail_on` plano —es
la declaración más rica del mismo documento, no una capa distinta, así que no cuenta
como el reemplazo que §8.1 exige anunciar. El reporte, en todo caso, nombra de qué
tabla salió el umbral efectivamente aplicado a cada categoría que corrió (§7, §8.1).

**Exclusiones.** Los campos son exactamente los que §8.2 ya exigía —`fingerprint`,
`reason`, `owner`, `expires_at` obligatorio— más `repositories` para el alcance,
opcional y global por defecto. El `fingerprint` acepta la huella completa o un prefijo
inequívoco (§7): si un prefijo configurado coincide con más de un hallazgo del run
actual, es error de configuración explícito por ambigüedad — nunca una supresión
silenciosa del hallazgo equivocado. Los hallazgos suprimidos **no cuentan para los
umbrales** (el gate solo ve los hallazgos activos); el reporte siempre indica cuántos
se suprimieron y cuántas exclusiones están vencidas, valgan cero (§7).

**Omisión temporal de herramienta.** Mismos cuatro campos que una exclusión, pero
sobre `tool` en vez de `fingerprint`: mientras la omisión esté vigente, esa herramienta
no se invoca en absoluto (`ExecutionStatus.skipped_by_policy`, §5) y el run no se
vuelve `partial` por ello — es ausencia declarada, no accidental. Vencida la fecha
límite, la herramienta se ejecuta de nuevo automáticamente, sin ningún paso manual; la
omisión vencida se reporta igual, para que quede visible que la herramienta volvió a
correr.

**Precedencia flag/archivo, coherente con §5/R5.** Los ajustes escalares (`fail_on`,
`continue_on_tool_error`, `strict_normalization`, `max_expiry_horizon_days`,
`report.max_rows`) siguen la cadena completa: CLI > variable de entorno > archivo >
default compilado, campo por campo — una capa que no menciona un campo nunca oculta el
valor de una capa inferior. Corrección de un defecto real detectado al construir esta
revisión: antes, el CLI pasaba `continue_on_tool_error` y `strict_normalization` a la
resolución de configuración *siempre*, con lo que el archivo nunca podía ganar aunque
la cadena dijera lo contrario; ahora son pares `--flag/--no-flag` de tres estados
(mencionado en verdadero, en falso, o no mencionado) y solo entran en la cadena cuando
el operador los menciona explícitamente. **Exclusiones y omisión de herramienta son
exclusivamente de archivo** — no existe un flag ni una variable de entorno equivalente:
expresar una lista de exclusiones o de herramientas omitidas como flags individuales
no escala más allá de un puñado de entradas, y el archivo ya es, por diseño, el lugar
donde vive esta configuración de cliente (R5).

**Diseño para una fuente remota futura, sin construirla ahora.** La función que valida
y construye la política (`parse_policy_document`) opera sobre un mapeo ya decodificado
— hoy, el resultado de parsear TOML — y no sabe nada sobre de dónde vino ese mapeo. Una
fuente remota futura (mencionada como configuración remota opcional en R2, §4) solo
necesita producir la misma forma de mapeo; el esquema, la validación de horizonte, el
emparejamiento de huella por prefijo y todo lo demás de esta sección se reutilizan sin
cambios. El campo `version` en la cabecera del documento existe precisamente para ese
futuro: hoy solo `1` es válido, y cualquier otro valor es error de configuración
explícito — la plomería de una fuente remota es trabajo posterior deliberadamente
aplazado (§14); el esquema difícil de acertar es este.

#### Enmienda (2026-09-19): fuente remota de la política, implementada (R2)

La plomería aplazada arriba ya existe: `linceo.core.remote_policy`,
`linceo.providers.azure_devops.AzureDevOpsPolicySource`, y un nuevo extra
opcional `linceo[remote-config]`. Cubre el caso real que motivó el diseño
original: seguridad mantiene el documento de política en un repositorio
propio, y cada pipeline que escanea un repositorio distinto lo hereda sin
copiar nada.

**Separación por gobierno, no por mecanismo de archivo.** El documento remoto
declara únicamente lo que seguridad decide centralmente y cambia pocas veces
al año — `fail_on`, `[thresholds]`/`[thresholds.<categoría>]`, y
`[tool_defaults]`/`[tools.<nombre>]` —; nunca `[[exclusions]]` ni
`[[skipped_tools]]`, que cada equipo declara en su propio
`.devsecops/config.toml` y cambia cada semana. Si el documento remoto declara
cualquiera de estas dos últimas secciones, es **error de configuración**, no
un aviso silenciosamente ignorado: un documento remoto que las declarara sería
un error de quien lo escribió (seguridad, gobernando algo que no le
corresponde gobernar centralmente), y este proyecto ya trata sistemáticamente
cualquier campo mal ubicado como error explícito con mensaje específico (el
precedente exacto es el aviso de `[tool_defaults]`/`[tools.<nombre>]` que
`_validate_top_level_keys` ya daba para `exclude_paths` en la raíz del
documento, §8.5 abajo) — nunca como una degradación silenciosa que dejaría a
todo pipeline consumidor con una supresión que ningún equipo local pidió. La
misma regla rechaza cualquier otra clave fuera de ese conjunto gobernado
(`linceo.core.remote_policy.validate_remote_document`), así el documento
remoto nunca se convierte, sin que nadie lo decida explícitamente, en el
lugar donde también viven `continue_on_tool_error` o el horizonte de
caducidad.

Las claves gobernadas que el documento remoto sí declara **reemplazan
enteramente** la declaración del archivo local para esa clave — nunca se
mezclan campo a campo, el mismo principio de "reemplaza, nunca mezcla" que ya
regía `[thresholds.<categoría>]` sobre `[thresholds]` y un `--fail-on` de CLI
sobre el archivo. Una clave gobernada que el documento remoto no menciona en
absoluto conserva el valor del archivo local, si lo hay — el mismo principio
de "una capa que no menciona un campo nunca oculta el valor de una capa
inferior" que ya gobierna la cadena CLI/entorno/archivo (`merge_remote_into_local`).

**Referencia por nombre, nunca por URL.** El repositorio escaneado declara,
en su propio `.devsecops/config.toml` (nunca en este repositorio, R5), una
nueva sección `[remote_policy]`:

```toml
[remote_policy]
repository = "security-baseline"     # nombre del repositorio de política
path = "policy.toml"                 # opcional; default: "policy.toml"
project = "platform-security"        # opcional; default: el proyecto del propio build
token_env = "LINCEO_POLICY_TOKEN"    # opcional; default: "SYSTEM_ACCESSTOKEN" (§9, enmienda de ergonomía)
```

Ninguno de estos cuatro campos es un secreto ni una URL — son nombres, y por
eso viven en el archivo versionado del repositorio como cualquier otro dato
no sensible de configuración (R5), exactamente igual que `[tool_defaults]`.
`repository` es obligatorio; los demás son opcionales. Quien resuelve el
nombre a una ubicación real es el proveedor de plataforma —
`AzureDevOpsPolicySource`, dentro de `providers/` (el único paquete que lee
`os.environ`) — leyendo `SYSTEM_COLLECTIONURI` y `SYSTEM_TEAMPROJECT`, las
mismas variables que Azure Pipelines inyecta en **todo** job, incluso uno sin
repositorio propio, a diferencia de `BUILD_REPOSITORY_NAME` (§10). `project`
sólo hace falta declararlo cuando el repositorio de política vive en un
proyecto de Azure DevOps distinto del que se está escaneando — el caso
realista de un proyecto dedicado a seguridad/plataforma; por defecto se
asume el mismo proyecto del build.

**No se implementa un cliente git.** Azure DevOps sirve el contenido crudo de
un archivo por HTTP (`GET .../_apis/git/repositories/{repo}/items?path=...&download=true`)
con el token en la cabecera `Authorization`. Frente a clonar el repositorio
completo, esta petición no necesita resolver el historial, no necesita
manejar submódulos, y no necesita ninguna credencial más allá de la que ya
autentica peticiones REST — su superficie de fallo y de código es
comparable a la de cualquier otra llamada HTTP de este proyecto, no a la de
un cliente git embebido. Clonar además traería consigo exactamente el tipo
de dependencia pesada que R2 existe para evitar en el paquete base.

**Autenticación por variable de entorno, coherente con §9.** El campo
`token_env` nombra la variable — nunca el valor — y `AzureDevOpsPolicySource`
la lee sólo dentro de `providers/`, enviándola como
`Authorization: Bearer <token>`, nunca como parte de una URL o de un
argumento de línea de comandos. El caso frecuente en Azure DevOps, y el
default de `token_env` desde la enmienda de ergonomía más abajo, es
`SYSTEM_ACCESSTOKEN` — el token OAuth de la propia ejecución del build,
disponible una vez habilitado "Allow scripts to access the OAuth token"; un
Personal Access Token clásico funciona igual, con `token_env` apuntando a
la variable que lo guarde. Cuando esa variable no existe en el entorno en
absoluto (o `token_env` se declara explícitamente vacío), no se envía
cabecera de autenticación — el caso de un repositorio de política legible
anónimamente. El valor leído se mantiene envuelto en `linceo.core.secret.Secret`
(§9, implementado por primera vez en esta revisión — ver la enmienda de
endurecimiento más abajo) desde que sale del entorno hasta el único punto
donde se necesita en texto plano, y `fetch` instala además un filtro de
redacción sobre los loggers de `httpx`/`httpcore` como segunda capa.

**Degradación visible, nunca error fatal — el mismo principio que
`stale_data` de §5.** Cada intento de descarga produce un
`PolicySourceStatus` con tres estados posibles, siempre declarado en el
reporte (consola y JSON), nunca sólo en un log:

- `fresh` — la descarga de este run tuvo éxito; se usa su contenido y se
  sobrescribe la caché local.
- `cached` — la descarga falló (red, autenticación, un documento remoto que
  no pasa TOML o el límite de gobierno) y se usó la última copia buena
  conocida en caché, con su antigüedad declarada (`age_days`) y marcada
  `stale` una vez supera `DEFAULT_MAX_POLICY_CACHE_AGE_DAYS` (7 días,
  idéntico al umbral que §5 ya usa para la base de datos de Trivy) — sin
  umbral duro que la invalide, el mismo criterio de §5: una copia vieja se
  sigue usando, sólo se declara más alto que una fresca.
- `unavailable` — la descarga falló y no había ninguna copia en caché; el
  run continúa únicamente con lo que el archivo local declare (sin gate
  gobernado remotamente, nunca un fallo del proceso). Es exactamente el
  mismo tratamiento que ya recibía la ausencia total de archivo local antes
  de esta revisión (`{}`, defaults permisivos) — nunca un error de
  configuración.

Un documento remoto que sí se descarga pero no pasa la validación de
gobierno (por ejemplo, declara `[[exclusions]]`) se trata exactamente igual
que una descarga fallida por red: degrada a caché o a `unavailable`, nunca
detiene el run — un typo de seguridad en su propio repositorio no puede
convertirse en un fallo duro para cada pipeline que lo hereda.

**Caché local.** Vive bajo `${LINCEO_POLICY_CACHE_DIR:-${XDG_CACHE_HOME:-~/.cache}/linceo/remote-policy}`,
un archivo por ubicación real — no por declaración: la clave es
`PolicySource.cache_key()` (organización, proyecto, repositorio y ruta,
hasheados juntos por `AzureDevOpsPolicySource`, resolviendo organización y
proyecto exactamente como `fetch` para que ambos nunca puedan discrepar),
nunca algo derivado solo de `RemotePolicyDeclaration` — ver la enmienda de
endurecimiento más abajo para el porqué. El directorio y el archivo se
crean con permisos exclusivos del propietario (`0700`/`0600`, fijados al
crearlos, nunca aflojados). **No hay caducidad que bloquee el
intento de descarga**: cada run con `[remote_policy]` declarado intenta
refrescar siempre, sin ninguna ventana de reutilización que retrase cuándo
un cambio de política llega a un pipeline — es precisamente lo que "todos
los pipelines la heredan" exige: propagación en el siguiente run, no en el
siguiente día. La caché existe únicamente como respaldo para cuando esa
descarga falla, con su propia antigüedad declarada como se describe arriba.
**No existe un mecanismo para "forzar un refresco"** porque no hace falta
uno: la descarga ya se intenta siempre; lo único que un operador podría
forzar es el uso de la caché en sí, que se soluciona borrando el archivo
(o el directorio completo) — no se ha añadido ningún flag para eso, por ser
una operación de archivo trivial y de uso excepcional, en línea con
"no construyas lo que no se necesita todavía" (`--max-policy-age`
configurable, análogo al `--max-db-age` de §5, queda igual de aplazado).

**Qué pasa cuando no hay ni remota ni local.** Sin `[remote_policy]`
declarado, el comportamiento es exactamente el de antes de esta revisión —
sin cambios. Con `[remote_policy]` declarado pero la descarga fallando y sin
caché (primera vez que este runner intenta este repositorio de política, por
ejemplo), y el archivo local sin sus propias tablas de umbral o
configuración de herramienta: el run continúa sin gate configurado, con
`stale_data`-como-`unavailable` declarado prominentemente — el mismo
tratamiento permisivo, nunca un error, que un `.devsecops/config.toml`
enteramente ausente ya recibía.

**El extra opcional.** `pip install linceo[remote-config]` instala `httpx`
— el paquete base sigue sin ganar ninguna dependencia de red (R2): importar
`linceo.providers.azure_devops` o construir `AzureDevOpsPolicySource` nunca
requiere el extra; sólo `fetch()` lo necesita, y su ausencia se traduce en
el mismo `RemotePolicyFetchError` accionable que cualquier otro fallo de
descarga, degradando exactamente igual.

**Verificación:** `tests/unit/test_remote_policy.py` cubre el límite de
gobierno (documentos remotos con `exclusions`/`skipped_tools`/claves no
gobernadas rechazados; claves gobernadas fusionadas campo a campo, nunca
mezcladas), la caché (lectura, escritura, corrupción tratada como ausencia,
antigüedad, bandera `stale`, aislamiento entre ubicaciones distintas y
permisos) y las cuatro rutas de degradación
(`fresh`/`cached`/`unavailable`/documento inválido). `tests/unit/test_azure_devops_policy_source.py`
cubre la resolución de ubicación (organización y proyecto desde el entorno,
`project` explícito ganando sobre el del build), `cache_key` (determinista,
distinto por organización y por proyecto, de acuerdo con `fetch` sobre cuál
proyecto gana), la cabecera de autenticación (el token nunca aparece en la
URL ni en los parámetros capturados), la redacción de un log hipotético que
sí incluyera cabeceras, y el extra ausente. `tests/unit/test_secret.py`
cubre `Secret` contra cada vía de exposición accidental que §9 nombra, y
`SecretRedactingFilter` de forma aislada. `tests/unit/test_cli_scan.py`
añade dos escenarios de extremo a extremo: un documento remoto gobernando
el gate, y una descarga fallida sin caché degradando con advertencia
visible sin romper el exit code.

#### Enmienda (2026-09-19, revisión de seguridad): clave de caché por ubicación real, y `Secret` puesto en práctica

Dos defectos encontrados en revisión antes de fusionar lo anterior, ambos
corregidos aquí:

**1. La clave de caché no incluía la organización, y el proyecto solo
entraba cuando se declaraba explícitamente.** La primera versión derivaba
la clave únicamente de `RemotePolicyDeclaration` (`repository`/`project`/`path`,
con `project` vacío cuando no se declaraba). Dos equipos distintos en un
mismo agente compartido — el caso real que motiva "runner compartido" —
pueden perfectamente declarar el mismo `[remote_policy]` (`repository =
"security-baseline"`, sin `project` explícito, que es el caso común): sus
declaraciones son idénticas, así que la clave derivada también lo era, y el
primero en descargar con éxito dejaba su copia donde el segundo la leería
como propia en cuanto su propia descarga fallara — exactamente "un agente
que sirve a dos equipos les daría la política del otro".

**Corrección:** la clave de caché ya no se deriva de la declaración. Se
añadió `cache_key()` al puerto `PolicySource`
(`linceo.core.ports.PolicySource.cache_key`) — cada fuente concreta resuelve
su propia identidad real. `AzureDevOpsPolicySource.cache_key` hashea
organización + proyecto + repositorio + ruta, resolviendo organización y
proyecto con la misma función que usa `fetch` (`_resolve_organization_and_project`),
de modo que ambas nunca pueden apuntar a ubicaciones distintas. Una fuente
que no puede resolver su propia ubicación (por ejemplo, `SYSTEM_COLLECTIONURI`
ausente) tampoco tiene una clave de caché segura: se trata como "sin caché
en absoluto", nunca como una clave adivinada con menos información de la
que la fuente realmente tiene.

Complemento: `write_cached_policy` ahora crea el archivo y su directorio
exclusivos del propietario (`0600`/`0700`), fijado en la propia llamada de
creación — nunca por un `chmod` posterior, que dejaría una ventana breve
con el permiso por defecto del sistema (típicamente legible por cualquier
otro usuario u proceso local). Un documento de política no es en sí mismo
una credencial, pero sigue siendo el dato de un equipo que ningún otro
inquilino de un runner compartido debería poder leer.

**2. El tipo `Secret` de §9 existía solo como diseño, nunca como código —
esta es la primera vez que un secreto real fluye por este proyecto en
tiempo de ejecución.** (`ToolExecutor.run` recibe `env={}` siempre hoy:
ningún adaptador de herramienta pasa credenciales todavía.) El token leído
de `token_env` viajaba como `str` normal desde `env.get(...)` hasta la
cabecera `Authorization`. Nada en el código lo registraba ni lo imprimía,
pero esa garantía dependía de que siguiera siendo así — exactamente lo que
§9 dice que la regla no debe depender.

**Corrección:** `linceo.core.secret.Secret` (nuevo módulo, sin dependencias
de terceros, dentro de `core/`) — `__str__`/`__repr__`/`__format__` devuelven
siempre `"***"`, y `.reveal()` es el único punto que da el valor real.
`AzureDevOpsPolicySource.fetch` envuelve el token en `Secret` en cuanto lo
lee del entorno y llama a `.reveal()` exactamente una vez, al construir la
cabecera — cerrando la ventana entre "leído" y "usado" en la que una línea
de depuración añadida después podría imprimirlo por accidente.

Verificado por lectura del código de `httpx`/`httpcore` (versión que este
proyecto fija): ni `Request.__repr__`/`__str__`, ni los mensajes de
`httpx.HTTPError` y sus subclases, ni el trazado interno a nivel `DEBUG` de
`httpcore` incluyen las cabeceras de la petición (solo método, URL, y las
cabeceras de la *respuesta* del servidor) — confirmado con un script contra
la versión instalada, no asumido de memoria. Aun así, ese es un detalle de
implementación de una librería de terceros, no un contrato que este
proyecto controle ni que se sostenga necesariamente en todo el rango
`>=0.27,<1.0` que el extra permite. Por eso se añadió igualmente la segunda
capa que §9 ya diseñaba: `linceo.core.secret.SecretRedactingFilter`, un
`logging.Filter` que redacta cualquier valor de secreto registrado que
aparezca en un mensaje de log — `fetch` lo adjunta a los loggers `httpx` y
`httpcore` antes de cada petición autenticada. `tests/unit/test_azure_devops_policy_source.py::test_fetch_installs_a_redaction_filter_that_catches_a_hypothetical_header_log`
simula el escenario que hoy no ocurre y confirma que, si ocurriera, la
segunda capa lo detendría igual.

La caché nunca corrió riesgo por esta vía: lo que se escribe en ella es el
contenido de la *respuesta* (el documento de política), nunca la petición —
el token no tiene ningún camino hacia el archivo cacheado, con o sin
`Secret`.

#### Enmienda (2026-09-19, ergonomía): identidad del build por defecto, sin configuración manual

Hasta aquí, usar la fuente remota exigía conocer y declarar `token_env`
a mano incluso en el caso común — un repositorio de política en la misma
organización — y la plantilla de referencia no reenviaba ninguna de las
variables que ese caso necesita. Corregido en tres frentes, todos en
`AzureDevOpsPolicySource` y en `azure-pipelines/templates/linceo-scan.yml`:

**1. `token_env` tiene ahora un valor por defecto: `DEFAULT_TOKEN_ENV_VAR`
(`SYSTEM_ACCESSTOKEN`).** Antes, `None` significaba "sin autenticación" —
inútil para el caso real, donde casi ningún repositorio de política
verdadero es legible sin autenticar, así que en la práctica `token_env` era
obligatorio declarar aunque el tipo dijera lo contrario. El nuevo default
es inofensivo incluso cuando la variable no existe en el entorno (se
resuelve a "sin token", exactamente como antes) y correcto quirúrgicamente
cuando sí existe: la identidad OAuth de la propia ejecución del build,
sin PAT que nadie tenga que crear ni rotar. Un `token_env = ""` explícito
sigue siendo la vía para optar por no autenticar en absoluto, incluso con
la variable por defecto presente en el entorno.

**2. La plantilla de referencia mapea y reenvía todo lo que este caso
necesita, por defecto.** `System.AccessToken` es la única variable de
Azure Pipelines que este proyecto lee y que la plataforma *no* expone
automáticamente en el entorno de un step — exige un bloque `env:` propio
(`SYSTEM_ACCESSTOKEN: $(System.AccessToken)`) antes de que exista algo que
reenviar al contenedor. `SYSTEM_COLLECTIONURI`/`SYSTEM_TEAMPROJECT` (que
`AzureDevOpsPolicySource.cache_key`/`fetch` también necesitan para
resolver organización y proyecto) sí llegan automáticamente al entorno del
step, pero nunca cruzaban hacia el contenedor — ninguna de las tres
variables estaba en el `docker run` de la plantilla antes de esta
revisión. Un pipeline que use la plantilla ya no necesita saber que
`[remote_policy]` existe para que funcione: `REMOTE_POLICY_ENV_ARGS`, un
segundo allowlist independiente del que ya cubre `ContextProvider`,
reenvía las tres siempre, inofensivo cuando el repositorio escaneado no
declara `[remote_policy]` en absoluto — la fuente remota simplemente nunca
se construye, igual que `BUILD_REPOSITORY_URI` ya viaja sin usarse en un
scan de solo `secrets`. El nuevo parámetro `policyRepoToken` de la
plantilla, junto con la variable fija `LINCEO_POLICY_TOKEN`, extiende lo
mismo al caso de un PAT para un repositorio fuera de la organización —
ver docs/ADOPTION.md, "Fuente remota de la política", para ambos modos
completos con ejemplos.

**3. Un 401/403 con la identidad por defecto nombra la causa más probable.**
`AzureDevOpsPolicySource.fetch` ya distinguía cualquier `httpx.HTTPError`
del mismo modo; ahora, específicamente para `httpx.HTTPStatusError` con
estado 401 o 403 y `token_env` todavía en su valor por defecto, el mensaje
nombra explícitamente que la identidad del build probablemente carece de
permiso de lectura sobre el repositorio de política, dónde concederlo
(*Project Settings → Repositories → (repositorio) → Security*), y qué
revisar si el repositorio de política vive en otro proyecto (*Organization
Settings → Pipelines → Settings → Limit job authorization scope*). Cuando
`token_env` es un valor distinto del default — un PAT que el operador ya
eligió deliberadamente — esta pista no aparece: atribuir la causa a "la
identidad del build" sería engañoso ahí, y solo quien generó ese PAT puede
saber si expiró o le falta alcance.

**Verificación:** `tests/unit/test_azure_devops_policy_source.py` cubre el
nuevo default (con y sin la variable presente en el entorno, y el opt-out
explícito con `token_env = ""`), la pista de 401/403 (para el default, para
un `token_env` propio — donde no debe aparecer — y para un código de
estado no relacionado), y dos comprobaciones anti-drift que leen
`azure-pipelines/templates/linceo-scan.yml` como texto plano: que reenvía
`-e` para cada variable en `REMOTE_POLICY_ENV_VARS`, y que mapea
`SYSTEM_ACCESSTOKEN` vía su propio bloque `env:` — el mismo patrón que
`tests/unit/test_cli_context.py` ya aplicaba a `ENV_VARS`.

#### Enmienda (2026-09-19, canal principal): la imagen de referencia instala `[remote-config]`

Tercer caso encontrado del mismo patrón que ya había aparecido dos veces
antes en esta misma revisión (las variables de entorno que la plantilla no
reenviaba; la clave de caché sin organización): una función existe en el
código y no llega al canal por el que la mayoría de quienes usan este
proyecto realmente lo corren. Aquí, el canal es la propia imagen de
contenedor — R4 la declara vía de distribución **principal**, y la
resolución de política remota es, por definición, una función de
*pipeline*: exactamente donde la imagen corre.

**El bug real, reportado con el mensaje exacto que produjo:** `Dockerfile`
construía el wheel de `linceo` y lo instalaba en el venv de la imagen sin
ningún extra (`uv pip install ... /dist/*.whl`, sin `[remote-config]`). Un
repositorio con `[remote_policy]` declarado, corriendo la imagen de
referencia dentro de un pipeline de Azure DevOps — el caso que este
proyecto existe para servir primero — degradaba a `unavailable` en **todo**
run, sin excepción: `httpx` nunca estaba instalado, así que `fetch` fallaba
con `ImportError` antes de siquiera intentar la red.

**Corrección:** la etapa `python-build` del `Dockerfile` instala el wheel
con el extra: `uv pip install --python ... "${1}[remote-config]"` (`$1`
resuelto vía `set -- /dist/*.whl`, no vía interpolar el glob directamente
en la expresión de extras, que el shell leería como una clase de
caracteres en vez de un sufijo literal). **El invariante de R2/§8.3 sobre
el paquete base no cambia en absoluto:** `uv build --wheel` sigue
construyendo el mismo wheel, sin extras, con la misma única dependencia de
terceros (`typer-slim`) — `pip install linceo` a secas, fuera de esta
imagen, sigue sin ganar ningún cliente HTTP. Lo que cambia es una decisión
distinta y posterior: qué instala *esta* distribución concreta de ese
wheel, ejerciendo exactamente la libertad que R2 ya le dejaba explícita
("vive en un extra instalable aparte") sin tocar el propio wheel. Verificado
construyendo la etapa `python-build` de forma aislada
(`docker build --target python-build`) e importando `httpx` desde el venv
resultante.

**El mensaje de error, revisado en el mismo movimiento.** Antes de esta
enmienda, el `ImportError` de `httpx` producía siempre "pip install
'linceo[remote-config]'" — instrucción imposible de seguir dentro de un
contenedor que corre como `USER 1000:1000`, sin venv escribible por ese
usuario, y sin ninguna expectativa de que alguien entre a una shell dentro
de un contenedor en ejecución para instalar algo ahí. Con la imagen ya
corrigiendo el caso común, este mensaje debería ser prácticamente
inalcanzable en la imagen de referencia de aquí en adelante — pero seguía siendo
alcanzable para quien instale `linceo` con `pip install linceo` a secas
(README, "pip install"), donde esa misma instrucción sí es correcta y
ejecutable. En vez de intentar detectar en tiempo de ejecución "¿estoy
dentro del contenedor de referencia?" — una pregunta que este proyecto no
tiene hoy ningún mecanismo para responder, y que añadirlo solo para este
mensaje sería una pieza de acoplamiento nueva y desproporcionada frente al
problema — el mensaje ahora nombra ambos contextos explícitamente: la
instrucción `pip install` para quien instaló así, y "esto indica una
imagen desactualizada; actualiza o reconstruye" para quien lo vea dentro
de la imagen de referencia. Cualquiera de los dos lectores encuentra su
propio siguiente paso; ninguno recibe instrucción imposible de seguir.

**Tercer caso del mismo patrón, revisado explícitamente — no hay un
cuarto.** `[remote-config]` es, a la fecha de esta revisión, el único
extra que este proyecto declara (`pyproject.toml`,
`[project.optional-dependencies]`), y el `import httpx` dentro de
`AzureDevOpsPolicySource.fetch`/`cache_key` es el único punto de todo
`src/` protegido por un `try`/`except ImportError` — confirmado por
inspección exhaustiva, no por muestreo. No hay otra función que dependa de
un extra y quede fuera de la imagen por el mismo motivo, porque no hay otro
extra del que pudiera quedar fuera.

**Hallazgo adyacente, documentado pero deliberadamente no resuelto aquí:**
la caché local de la política remota (§8.4 arriba) vive bajo `$HOME` (o
`$LINCEO_POLICY_CACHE_DIR`) dentro del contenedor — un filesystem que un
`docker run` efímero, el patrón más común en CI, descarta al terminar el
paso. En ese patrón, la "última copia buena conocida" nunca sobrevive de
un run al siguiente: una descarga fallida ahí siempre degrada directo a
`unavailable` (local-only), nunca a `cached`, sin importar cuántas veces
haya funcionado antes. Esto no es un defecto de esta implementación — la
caché sigue haciendo exactamente su trabajo dentro de un mismo proceso, y
degradar a `unavailable` en vez de fallar el run sigue siendo la conducta
correcta (§5, "degradación, nunca error fatal") — es una propiedad del
*despliegue* que vale la pena que quien opera un pipeline conozca:
si quiere que la caché sobreviva entre runs, `$LINCEO_POLICY_CACHE_DIR`
debe apuntar a un volumen montado que persista entre invocaciones del
contenedor, no al filesystem efímero por defecto. Documentado en
docs/ADOPTION.md, "Fuente remota de la política"; no es el mismo patrón
que motiva esta enmienda (ninguna función falta aquí, la caché ya hace lo
que se le pidió) y por eso no se trata como un cuarto caso.

### §8.5. Configuración por integración: dos niveles

Hasta esta revisión, `GitleaksIntegration.build_command` construía un argv fijo y no
aceptaba ningún parámetro: ni una ruta a excluir, ni una regla propia, ni un timeout.
Cerrar esto antes de Trivy —el segundo consumidor del contrato— es la misma lógica
del checkpoint de §1: lo que hoy parece "Gitleaks no necesita más" fosiliza como "el
contrato no soporta más" en cuanto una segunda herramienta lo copia.

**Elegido: un contrato de configuración en dos niveles**, ninguno de los dos con
equivalente en flag ni en variable de entorno — exactamente la misma excepción a la
cadena de §5/R5 que §8.4 ya declaró para exclusiones y omisión de herramienta, y por
el mismo motivo: ninguna de las formas involucradas (una lista de patrones, una ruta
local, una tabla arbitraria por herramienta) cabe mejor en un flag escalar de lo que
ya cabían las exclusiones. Ambos niveles se resuelven exclusivamente desde el mismo
documento de política.

#### Dónde vive nivel 1: dos secciones, con precedencia declarada

Una primera versión de este diseño dejó nivel 1 sin una sección propia en el
documento: `exclude_paths` en la raíz se rechazaba como campo desconocido, y dentro
de `[tools.<nombre>]` cualquier clave no reconocida —incluidas, por descuido de
diseño, las de nivel 1 si se hubieran tratado igual que el resto— habría caído en
passthrough opaco en vez de en un parámetro validado. Corregido aquí, evaluando las
tres formas concretas de resolverlo:

- **(a) Solo `[tool_defaults]`, con alcance a todas las integraciones del run.**
  Resuelve el caso común —"excluir `node_modules/` de todo"— con una sola
  declaración. No resuelve el caso específico: si una herramienta necesita un
  `timeout` distinto, no hay dónde decirlo sin que afecte a las demás.
- **(b) Solo `[tools.<nombre>]`, con las cuatro claves de nivel 1 reconocidas ahí y
  el resto como passthrough.** Es lo que esta revisión tenía antes de este cambio.
  Resuelve el caso específico de forma directa, pero obliga a repetir el caso común
  en cada bloque `[tools.<nombre>]` configurado.
- **(c) Ambas, con `[tools.<nombre>]` ganando campo por campo sobre
  `[tool_defaults]`.** Cubre los dos casos sin que ninguno pague el costo del otro.

**Elegido: (c).** El argumento decisivo no es solo que cubre más casos — es que el
caso común de (a) es real *hoy*, no solo en un futuro con Trivy integrado. El límite
de "una categoría por invocación de CLI" (§8, "Una categoría por invocación en v0.1")
no implica "una herramienta por documento de política": el mismo
`.devsecops/config.toml` de un repositorio se reutiliza entre invocaciones distintas
de `scan secrets` y, más adelante, `scan sca` contra ese mismo repositorio — es un
documento por repositorio, no por invocación. Sin `[tool_defaults]`, excluir
`node_modules/` para cualquier herramienta que llegue a correr contra ese
repositorio exigiría repetir la misma lista en cada `[tools.<nombre>]` que se
configure, y mantenerlas sincronizadas a mano cada vez que una cambie — exactamente
el tipo de duplicación que el resto de este documento evita en cualquier otro punto
de configuración compartida.

El costo de (c) frente a (b) —una regla de precedencia más que explicar— se paga con
un mecanismo que este documento ya tiene que justificar en otro punto, no con uno
nuevo: **`[tools.<nombre>]` gana sobre `[tool_defaults]`, campo por campo, nunca el
bloque entero** — la misma regla "una capa que no menciona un campo nunca oculta el
valor de una capa inferior" que §8.4 ya usa para `continue_on_tool_error` y
`strict_normalization` entre CLI, variable de entorno y archivo — aplicada aquí con
dos capas (`[tool_defaults]` y `[tools.<nombre>]`) en vez de cuatro, porque ambas son
exclusivamente de archivo (mismo motivo de §8.4). `linceo.core.tool_config
.resolve_tool_config` implementa esta mezcla: para cada uno de los cuatro campos,
gana el valor de `[tools.<nombre>]` si lo declaró, si no el de `[tool_defaults]`, si
tampoco el default neutro de la propia integración. Un `[tools.<nombre>]` que solo
fija `timeout` sigue heredando `exclude_paths` de `[tool_defaults]` sin más — nunca
hace falta repetir lo que no se está cambiando.

**`[tool_defaults]` nunca acepta passthrough.** A diferencia de nivel 1, un nombre de
flag crudo no tiene significado compartido entre herramientas por definición — no
existe un "valor por defecto razonable" de `redact` que tenga sentido fuera de
Gitleaks. `parse_tool_defaults` rechaza cualquier clave de `[tool_defaults]` que no
sea una de las cuatro de nivel 1, con un mensaje que señala que el passthrough vive
en `[tools.<nombre>]`, nunca ahí.

#### Nivel 1 — parámetros normalizados

Cuatro campos, con el mismo nombre y el mismo significado para cualquier
integración, declarados en `core/` (`linceo.core.tool_config.ToolConfig`), y
reconocidos en las dos ubicaciones descritas arriba — nunca en la raíz del
documento, donde no existe ninguno de los dos como sección propia:

| Campo | Significado |
|---|---|
| `exclude_paths` | Rutas o patrones que la herramienta no debe escanear. |
| `scan_history` | `true` cubre el historial completo, `false` solo el árbol de trabajo, ausente (`None`) deja el default propio de la integración (Gitleaks: historial completo, ver §10). |
| `custom_rules_path` | Ruta local a reglas propias de la herramienta. |
| `timeout` | Segundos antes de matar la ejecución — ver el apartado dedicado, abajo. |

**Regla dura: una integración que no puede honrar un campo lo dice, nunca lo ignora
en silencio.** `build_command` traduce cada campo que su herramienta soporta
realmente a un flag propio, y levanta `UnsupportedToolConfigError` —nunca construye
un comando que en la práctica escanea de más o de menos sin decirlo— en cuanto el
campo se aparte de su valor neutro. El caso real, no hipotético, que motiva esta
regla: Gitleaks **no tiene ningún flag de línea de comandos para excluir rutas** —
solo una tabla `[allowlist]` dentro de su propio fichero `--config`, que esta
integración no genera. `GitleaksIntegration.build_command` levanta
`UnsupportedToolConfigError` en cuanto `exclude_paths` no está vacío, en vez de
construir un `gitleaks detect` que en realidad escanea el árbol entero igual.
Verificado contra el binario 8.30.1 instalado (el mismo con el que están grabados
los fixtures dorados de §11) con `gitleaks detect --help`, no contra documentación de
terceros.

`scan_history`, para una categoría sin ninguna noción de historial —un escaneo de
manifiestos de dependencias, que solo puede reflejar el árbol tal como está en un
momento dado— no tiene nada que alternar: una integración así deja el campo en su
default (`None`, "no se pidió nada") sin levantar error, pero levanta
`UnsupportedToolConfigError` en cuanto un documento lo fija explícitamente a `true` o
a `false`, porque ninguno de los dos valores puede honrarse con honestidad.

#### `timeout`: por qué nunca es un flag de la herramienta, ni siquiera cuando existe uno

**Elegido: `timeout` nunca se traduce a un flag — se aplica una sola vez, en el
puerto `ToolExecutor.run`, matando el proceso del sistema operativo al vencer el
plazo, igual para cualquier herramienta.**

**Alternativa descartada, comprobada y no solo asumida: traducirlo al flag nativo de
cada herramienta cuando exista uno.** Gitleaks sí tiene uno —`--timeout`, confirmado
en el binario 8.30.1 instalado—, así que la alternativa no se descarta por
inexistente, sino a pesar de existir. El flag propio de una herramienta es una
garantía *blanda*: depende de que esa herramienta note el vencimiento en todos sus
caminos de código internos, y no toda herramienta tiene uno — normalizar un campo
para que signifique cosas distintas, con fiabilidad distinta, según qué integración
lo lea, es exactamente lo que "normalizado" no debería permitir. El límite del propio
`ToolExecutor` es una garantía *dura*: el proceso se mata, siempre, sin depender de
que la herramienta coopere. Ejecutar ambos a la vez —el flag propio y el límite del
executor— tampoco se adopta: cuál de los dos dispara primero depende del arranque de
cada binario, y produciría un `ExecutionStatus` distinto (fallo capturado por la
propia herramienta frente a `TimeoutExpired` del executor) de forma no determinista
para el mismo `timeout` configurado, violando el corolario de determinismo de R3.

#### Nivel 2 — passthrough específico de herramienta

Bajo el mismo bloque `[tools.<nombre>]`, cualquier clave que no sea una de las cuatro
de nivel 1 se trata como passthrough: se valida solo su *forma* (un escalar de TOML,
o una lista homogénea de cadenas para un flag repetible — nunca una tabla anidada) y
se entrega a `build_command` tal cual, sin que `core/` interprete su significado.

**Esto rompe deliberadamente la portabilidad entre escáneres de la misma categoría,
que es la propuesta de valor central declarada en §8** ("cambiar de escáner de
secretos mañana no debería exigir tocar la definición del pipeline"). Un documento
que solo usa nivel 1 escanea de forma idéntica sin importar qué `--tool` resuelva la
categoría; uno que usa `passthrough` no, por construcción, porque sus claves solo
significan algo para la herramienta nombrada en ese bloque — cambiar de escáner deja
ese bloque entero sin efecto o, peor, con un efecto distinto si la nueva herramienta
por casualidad reconoce las mismas claves con otro significado. Se ofrece de todos
modos porque la alternativa —un nivel 1 que intente anticipar cada flag de cada
herramienta presente y futura— es exactamente la superficie sin límite natural que
§13.1 ya descarta como riesgo de deriva de alcance. El costo se paga explícitamente,
a cambio de no bloquear a un operador que necesita, hoy, un flag que el nivel 1
todavía no contempla.

#### Construcción de argv controlada: ningún valor inyecta argumentos por concatenación

**Invariante duro:** un documento de política no puede convertirse en ejecución de
comandos arbitraria, ni siquiera si el propio documento es malicioso o está
comprometido. Como ya vale para el resto del proyecto (§9), no hay shell involucrado
— `argv` es siempre una lista pasada directamente a `exec`, nunca una cadena
interpretada — así que el riesgo real no es inyección de shell, sino inyección de
*argumentos*: un valor de passthrough que, mal construido, se divida o se concatene
en más tokens de los que declara, colando flags que el operador nunca pidió dentro de
la invocación de la herramienta.

`linceo.core.tool_config.render_passthrough_flags` es el mecanismo compartido —no
cada integración reinventando su propio manejo de cadenas— que hace esa garantía
mecánica: cada entrada `(clave, valor)` produce exactamente un token de flag y, si el
valor no es booleano, exactamente un token de valor por elemento — nunca más, sea lo
que sea que el valor contenga. Un valor nunca se divide (`.split()` o equivalente);
nunca se concatena dentro de un token existente. La clave, además, se valida contra
un patrón de nombre de flag (`^[A-Za-z][A-Za-z0-9-]*$`) antes de usarse, así que una
clave de TOML entre comillas con espacios u otros caracteres no válidos falla de
forma ruidosa en vez de producir un flag con forma extraña. `GitleaksIntegration` usa
esta función para su propio `passthrough`; se espera que Trivy haga lo mismo.

Passthrough se añade siempre al final del argv, después de los flags que nivel 1 ya
tradujo — así que puede sobrescribir un flag derivado de nivel 1 si el mismo flag
subyacente coincide (por ejemplo, `custom_rules_path` y un `passthrough.config` de
Gitleaks compiten por `--config`; la mayoría de los CLI basados en `cobra`/`pflag` —
Gitleaks incluido— toman la última ocurrencia). Es el costo aceptado de usar la
válvula de escape de nivel 2, documentado aquí, no un caso especial que el código
detecte o impida.

#### Visibilidad: `--dry-run` siempre muestra el argv efectivo

El CLI resuelve el `ToolConfig` de la herramienta activa antes de decidir si
`--dry-run` está activo, y usa exactamente ese mismo objeto tanto para imprimir el
argv como para el run real — nunca hay un segundo camino que reconstruya el argv por
separado para uno de los dos casos. `--dry-run` no es una aproximación de lo que
correría: es literalmente la misma llamada a `build_command`, con la misma
configuración resuelta, sin ejecutarla.

#### Validación antes de invocar, extendida a nivel de herramienta

§8.4 ya exige que un documento de política inválido falle con código 2 **antes** de
invocar ninguna herramienta. `UnsupportedToolConfigError` es la misma clase de fallo
— una petición del operador que no puede honrarse — así que se sujeta al mismo
principio: `engine.run` calcula, para cada integración no omitida por política, su
`ToolConfig` ya mezclado (`resolve_tool_config(defaults=..., override=...)`, arriba)
y construye su argv con él — para **todas** las herramientas del run, antes de
ejecutar ninguna. Con dos herramientas en un mismo run (la invariante de §1: N
ejecuciones, un veredicto), que la segunda rechace su configuración nunca deja a la
primera ya ejecutada de verdad — la ejecución real solo empieza una vez que cada
`build_command` de este run ya tuvo su oportunidad de fallar.

Un peldaño antes que eso, `[tool_defaults]` y cada `[tools.<nombre>]` ya se validaron
por completo al cargar la configuración (`load_config`, §8.4): un campo de nivel 1
con el tipo equivocado, o un `[tool_defaults]` con una clave de passthrough, es
`ConfigurationError` (código 2) antes de que exista siquiera un `ToolIntegration`
construido — `UnsupportedToolConfigError` es estrictamente posterior, porque
solo una integración concreta sabe si puede honrar un valor por lo demás
sintácticamente válido.

#### Mensaje de error específico cuando un campo de nivel 1 queda en el lugar equivocado

Antes de que existieran `[tool_defaults]` y `[tools.<nombre>]` como las dos
ubicaciones válidas, un documento con `exclude_paths` en la raíz —el error más
esperable, alguien migrando configuración de otra herramienta o simplemente
asumiendo que el campo es global— caía en el mensaje genérico de campo
desconocido: cierto, pero mudo sobre dónde sí va. `_validate_top_level_keys`
(`linceo.core.config`) distingue este caso: si alguna de las claves rechazadas
coincide con `LEVEL_1_FIELD_NAMES` (el mismo conjunto de cuatro nombres que
`linceo.core.tool_config` ya expone, no una lista repetida a mano y expuesta a
desincronizarse), el mensaje señala explícitamente las dos secciones válidas:

```
configuration file '.../config.toml' declares unknown field(s): ['exclude_paths']
— ['exclude_paths'] look like per-tool configuration (ADR §8.5): declare them
inside [tool_defaults] (applies to every configured tool) or [tools.<name>]
(applies to just that one tool), never at the document root
```

Un campo desconocido que no coincide con ninguno de los cuatro —un typo genuino,
por ejemplo— conserva el mensaje genérico sin este añadido: la pista solo aparece
cuando de verdad apunta a algo accionable.

#### Esquema

Documento sintético completo (R5), con los dos niveles y las dos ubicaciones de
nivel 1 en juego a la vez:

```toml
version = 1

[tool_defaults]                  # nivel 1, alcance: toda integración de este run
exclude_paths = ["node_modules/", ".venv/", "dist/"]
scan_history = true              # explícito aquí; el default de Gitleaks ya es este

[tools.gitleaks]                 # nivel 1 específico + nivel 2 (passthrough), solo Gitleaks
custom_rules_path = ".gitleaks-custom.toml"   # --config
timeout = 45                     # gana sobre cualquier timeout de [tool_defaults]
# exclude_paths = ["vendor/"]    # si se pusiera aquí, ganaría sobre el de [tool_defaults]
                                  # para Gitleaks — pero Gitleaks lo rechazaría igual:
                                  # UnsupportedToolConfigError, no tiene flag (ver arriba)

# Nivel 2: passthrough — cualquier clave de [tools.gitleaks] que no sea una de las
# cuatro de nivel 1. Rompe portabilidad entre escáneres de secretos (§8) — documentado,
# no oculto.
redact = 25
no-color = true

# Rechazado con el mensaje específico de arriba, nunca "campo desconocido" a secas:
# exclude_paths = ["build/"]     # pertenece a [tool_defaults] o [tools.<nombre>], no a la raíz
```

Con este documento, la integración `gitleaks` recibe, ya mezclado por
`resolve_tool_config`: `exclude_paths=("node_modules/", ".venv/", "dist/")` (heredado
de `[tool_defaults]`, `[tools.gitleaks]` no lo menciona), `scan_history=True`,
`custom_rules_path=".gitleaks-custom.toml"` y `timeout=45.0` (los tres últimos, de
`[tools.gitleaks]`), más el passthrough `{"redact": 25, "no-color": True}` — y
`build_command` la rechaza de todos modos por `exclude_paths`, exactamente como sin
`[tool_defaults]` en absoluto: heredar un valor no vuelve honrable lo que la
integración ya no puede honrar declarado directamente.

`Config.tool_defaults` es un único `ToolConfig` (nunca indexado por nombre —
`[tool_defaults]` no lo está en el documento tampoco); `Config.tool_configs` es un
`Mapping[str, ToolConfig]` indexado por `ToolIntegration.name`, igual que
`skip_by_tool` en `engine.run` ya indexa `ToolSkip` por nombre de herramienta — una
herramienta sin bloque `[tools.<nombre>]` propio sigue recibiendo `[tool_defaults]`
íntegro vía `resolve_tool_config`, nunca un error por ausencia de su propio bloque.

---

## §9. Credenciales: el flag nombra el origen, nunca el valor

**Ningún secreto viaja como valor de un argumento de línea de comandos.** Un argumento
es visible en la tabla de procesos del sistema operativo (`ps aux` desde cualquier
otro proceso del mismo host), queda persistido en el historial del shell, y aparece
tal cual en los logs de ejecución del pipeline de CI, que casi siempre son menos
controlados de lo que su nombre sugiere. El CLI expone `--token-env NOMBRE` y
`--token-file RUTA`, más una convención documentada específica por cada adaptador de
contexto o de herramienta que la necesite. **No existe, bajo ninguna circunstancia,
un flag `--token VALOR`.**

### Refuerzo estructural, para que la regla no dependa solo de la disciplina de quien escribe código nuevo

Un tipo `Secret` cuyo `__str__` y `__repr__` devuelven siempre `***`, y cuyo valor real
solo se obtiene mediante `.reveal()`, llamado explícitamente en el único punto donde
de verdad se necesita el valor. Esto hace que una interpolación accidental de un
`Secret` dentro de un mensaje de log, una excepción no controlada, o una f-string de
depuración sea inofensiva *por construcción del tipo*, no por revisión de código.
Segunda capa independiente: un filtro de logging que redacta activamente cualquier
valor de secreto conocido que aparezca en un mensaje registrado, como defensa en
profundidad si la primera capa se elude de algún modo no previsto.

Al invocar una herramienta externa, los secretos se pasan siempre por el entorno del
proceso hijo, **nunca como parte de `argv`** — lo que permite adicionalmente que
`--dry-run` imprima la línea de comandos completa que se ejecutaría sin ningún riesgo
de fuga, y que `ToolExecution.argv` (§5) se persista íntegro en el reporte del run sin
necesidad de una lógica de redacción especial en ese punto: el secreto simplemente
nunca estuvo ahí.

**Verificación:** test que instancia un `Secret` con un valor de prueba y lo formatea
por todas las vías habituales de exposición accidental — `str()`, `repr()`,
interpolación en f-string, serialización a JSON por defecto, mensaje de una excepción
que lo capturó — y afirma en cada caso que el valor real no aparece en la salida.

---

## §10. Adaptadores de referencia: criterio y elección

El criterio para elegir el segundo adaptador de cada eje no es cobertura funcional del
mundo real: es servir como **prueba del contrato del puerto**. Un puerto con una sola
implementación concreta es una indirección sin evidencia de que generaliza — no hay
forma de saber si quedó modelado, sin querer, alrededor de las particularidades de esa
única implementación hasta que una segunda, deliberadamente distinta, intenta
llenarlo. Por eso el segundo adaptador de cada eje se elige por *máxima distancia*
razonable a la primera implementación, al mínimo coste de construcción posible.

### Eje de contexto: `local` + `azure_devops`

`local` es obligatorio en cualquier alcance posible del proyecto, no una elección
entre varias — la herramienta debe poder correr en el portátil de un desarrollador sin
ningún pipeline de por medio, así que este proveedor existe siempre, independientemente
de qué otro se elija. `azure_devops` llena el mismo `ExecutionContext` desde una fuente
completamente distinta a la del proveedor local — variables inyectadas por el runner en
el entorno del proceso, en vez de interrogar directamente al repositorio git presente
en disco — por un costo de implementación de aproximadamente 40 líneas de mapeo de
variables de entorno a los campos del contexto. Es, además, la plataforma de CI real
del stack del mantenedor (contexto del proyecto), así que la elección no es solo
teórica: se valida contra un caso de uso real desde el primer adaptador de plataforma.

### Eje de herramienta: Gitleaks + Trivy

Elegidas de categorías deliberadamente distintas dentro del dominio de seguridad.
Gitleaks produce hallazgos con ubicación en el código y un identificador de regla, y
**no produce severidad nativa en absoluto**. Trivy, en modo SCA, produce nombre de
paquete, versión instalada, versión que corrige el problema, identificador CVE y
puntaje CVSS. Ese segundo tipo de hallazgo es exactamente el que un modelo diseñado
mirando solo a Gitleaks no soportaría sin cambios — es la razón directa por la que la
sección de normalización de severidad (§6) necesita existir con la complejidad que
tiene, en vez de asumir que toda herramienta emite un valor de severidad utilizable
directamente.

Dentro de Trivy, se elige específicamente el modo `trivy fs` (análisis de dependencias
sobre el sistema de ficheros del workspace) y explícitamente **no** el escaneo de
imágenes de contenedor. El escaneo de imágenes exige una referencia a un registry y,
en el caso general, credenciales de red para acceder a él — eso contaminaría la
implementación de referencia del proyecto con precisamente el caso menos alineado con
R2 (funciona sin salida a internet) de todo el catálogo de Trivy, cuando el objetivo
de este adaptador es demostrar el contrato en su forma más limpia, no cubrir la mayor
superficie posible de la herramienta.

### Decisiones tomadas durante la implementación de Gitleaks

Dos decisiones concretas, tomadas al escribir el adaptador y no anticipadas en el
diseño previo de este documento, registradas aquí porque afectan qué evidencia produce
el escaneo y qué significa `repository`/`commit` en un run local:

- **Gitleaks escanea el historial completo de git, no solo el árbol de trabajo.** La
  integración invoca `gitleaks detect` en su modo por defecto — sin `--no-git` — en vez
  de restringir el escaneo al estado actual del checkout. Un secreto commiteado y luego
  eliminado del árbol de trabajo sigue siendo un secreto expuesto en el historial
  público del repositorio desde el momento del `git push`; es exactamente el caso que
  justifica tener un escáner de secretos en primer lugar, y limitarse al árbol de
  trabajo lo dejaría fuera por completo. El coste es un escaneo más lento en
  repositorios con historiales largos, aceptado sin reservas: un secreto no detectado
  por rapidez es la peor clase de falso negativo posible en esta categoría.
- **`ExecutionContext.workspace_path` conserva el `--path` del usuario; `repository` y
  `commit` se resuelven contra la raíz del checkout.** Escanear un subdirectorio de un
  repositorio más grande debe escanear únicamente ese subdirectorio — `workspace_path`
  nunca se reescribe hacia la raíz que `git rev-parse --show-toplevel` reporta. Pero
  `repository` (el nombre derivado del remoto `origin`, o del directorio de nivel
  superior si no hay remoto) y `commit` (`git rev-parse HEAD`) identifican el
  repositorio como un todo, no el subdirectorio escaneado, así que se resuelven contra
  la raíz del checkout — resolverlos contra `workspace_path` produciría de todos modos
  el mismo `commit` (un repositorio tiene un único `HEAD`), pero un `repository`
  potencialmente distinto y engañoso si alguna vez se derivara del propio subdirectorio
  en lugar del remoto configurado.

---

## §11. Estrategia de pruebas: los fakes son permanentes

Los adaptadores falsos del núcleo no son andamiaje temporal que se descarta una vez
existen implementaciones reales: se distribuyen dentro del propio paquete
(`linceo.testing`), se versionan junto con el contrato que implementan, y forman
parte de la superficie de API pública del proyecto, con la misma seriedad de
compatibilidad hacia atrás que cualquier otro módulo público.

- **`FakeContextProvider`** y **`FakeToolExecutor`** — este último reproduce salidas
  previamente grabadas de una herramienta real, en vez de simular su comportamiento
  desde cero, para minimizar la deriva entre lo que el fake permite y lo que la
  herramienta real produce.
- **Reloj y generador de identificadores inyectables**, requeridos por el corolario de
  determinismo de R3 (§4).
- **Fixtures dorados:** salidas reales, capturadas literalmente de cada herramienta
  integrada, con la versión exacta de la herramienta que las produjo anotada junto al
  fixture. El documento distingue esto explícitamente de la restricción R5: son datos
  de prueba propios del proyecto, versionados junto con su código, no configuración de
  ningún cliente — la distinción importa porque a primera vista un fixture con datos
  realistas podría confundirse con lo que R5 prohíbe.
- **Suite de tests de contrato reutilizable**, escrita contra los puertos
  (`ContextProvider`, `ToolExecutor`, `ToolIntegration`) y no contra ninguna
  implementación concreta, de modo que sea ejecutable sin modificación contra
  cualquier adaptador de terceros que alguien quiera aportar. Es el mecanismo concreto
  que permite añadir una herramienta o una plataforma de CI nueva sin tocar el núcleo,
  y la contrapartida técnica directa de la mitigación descrita para el riesgo de
  deriva de alcance (§13.1).
- **Marcador `integration`** para el conjunto reducido de tests que sí requieren
  binarios reales presentes en el sistema, deseleccionado por defecto en la ejecución
  local de la suite; en el CI del propio proyecto corren siempre, contra las versiones
  de herramienta explícitamente ancladas que también sostienen la verificación
  estricta de normalización de severidad (§6).

---

## §12. Procedencia y licencia

Protocolo de sala limpia aplicado frente al proyecto de referencia AGPL-3.0: el diseño
de este proyecto parte de documentación pública y de comportamiento observable de
herramientas de la categoría (qué hace un orquestador DevSecOps, qué forma tienen sus
entradas y salidas), nunca de la lectura del código fuente del proyecto de referencia.
Sin copiar su estructura de módulos, sin nombres de símbolos que sugieran derivación
directa — de ahí, en parte, el criterio explícito de §2 de descartar cualquier nombre
de proyecto con patrón `devsecops-*` o `*-engine-*`. Fichero `NOTICE` limpio desde el
primer commit, y la procedencia de cada decisión de diseño registrada en documentos
como este.

Esto se aplica desde el commit #1, no se pospone para "antes del release público",
porque la historia de git es permanente y auditable por cualquiera una vez el
repositorio se abre: una promesa de licencia Apache-2.0 que la propia historia del
repositorio contradice — por ejemplo, con un commit temprano que copia una estructura
reconocible del proyecto de referencia y luego la reescribe — es objetivamente peor
para la credibilidad del proyecto que no haber hecho esa promesa desde el principio.

---

## §13. Los tres riesgos de muerte del proyecto

### 1. Deriva de alcance por número de herramientas

El mantenedor se convierte, sin haberlo decidido explícitamente, en integrador no
pagado de N escáneres cuyos CLIs y formatos de salida cambian por su cuenta en cada
versión, y el núcleo se pudre bajo el peso de casos especiales acumulados.

**Mitigación en el diseño:** frontera de plugin formal vía entry points de Python, no
un mecanismo de registro ad hoc. Integraciones deliberadamente delgadas — invocar el
binario y parsear su salida, sin lógica adicional, ni siquiera la de severidad, que
vive centralizada en el mapa versionado de §6 y no en cada parser individual. Suite de
tests de contrato publicada (§11) para que añadir una herramienta o una plataforma no
exija entender ni tocar el núcleo. Plugins fuera del árbol del repositorio principal
tratados como ciudadanos de primera clase desde el diseño, no como una idea añadida
después. La barra mínima de release para el v0.1 es explícitamente "núcleo + dos
herramientas de categorías distintas que prueban el contrato" — nunca "cobertura de
todo el stack del mantenedor", que es un objetivo sin límite natural.

### 2. Agotamiento del mantenedor por carga operativa

**Mitigación:** las decisiones ya tomadas en este documento son, en conjunto, la
mitigación principal de este riesgo, más que cualquier proceso adicional. Sin backend
(R3) no hay nada que operar en producción fuera del propio código. Sin telemetría (R2)
no hay incidentes de privacidad que gestionar ni datos de terceros que migrar o
proteger. Sin estado persistido (R3) no hay corrupción de datos que depurar entre
ejecuciones. Sin servidor expuesto, la superficie de divulgación de seguridad del
propio proyecto se reduce al código del CLI y sus dependencias directas. Y como cada
run es autocontenido y determinista por diseño (R3, §5), un reporte de bug de un
usuario se reproduce en la práctica con la salida de `context --json` más el fixture
correspondiente — la diferencia real, medida en tiempo del mantenedor, entre media
hora de trabajo y media tarde perdida intentando reconstruir un entorno ajeno. Los
comandos `doctor` y `--dry-run` (§8) existen específicamente para que buena parte de
los problemas de un usuario los resuelva el propio usuario, sin necesidad de abrir un
issue.

### 3. Irrelevancia: no llegar nunca a tener un usuario real

Un núcleo con un solo escáner integrado es, para cualquier evaluador externo, una
demo — no una herramienta que alguien apostaría a introducir en un pipeline de
producción. El nicho de mercado lo pueden cerrar antes tanto el proyecto de referencia
AGPL-3.0 como las capacidades de seguridad cada vez más nativas de las propias
plataformas de CI.

**Mitigación:** la barra de aceptación del v0.1, tal como queda fijada en este
documento, es explícitamente "usable en un pipeline real" — dos herramientas de
categorías distintas, dos plataformas de contexto, un veredicto único sobre evidencia
agregada, códigos de salida con contrato semántico claro, y salida SARIF que
efectivamente se ve en la interfaz de revisión de código del equipo, no solo en un
JSON archivado. Diseño CLI-first (§8) para que el valor del proyecto sea inmediato sin
exigir adoptar un framework completo ni escribir código de integración propio.
Apache-2.0 como diferenciador real frente a la licencia AGPL del proyecto de
referencia, específicamente relevante para adopción en entornos corporativos donde
AGPL suele bloquear la evaluación por política legal antes de que alguien llegue a
probar la herramienta. Distribución por contenedor (R4) para que evaluar el proyecto
cueste, en la práctica, un único `docker run` sin instalación previa de nada.

---

## §14. Consecuencias y trabajo aplazado deliberadamente

### Qué se vuelve fácil con este diseño

- Añadir una herramienta nueva de una categoría ya cubierta: implementar
  `ToolIntegration`, declarar su dominio de severidad nativa en el mapa (§6), y pasar
  la suite de contrato (§11) — sin tocar el núcleo.
- Añadir una plataforma de CI nueva: implementar `ContextProvider` contra el mismo
  `ExecutionContext` ya validado por dos implementaciones de máxima distancia entre sí
  (§10).
- Reproducir cualquier bug reportado por un usuario, dado el determinismo de R3 y el
  comando `context` (§8, §13.2).
- Integrar el sink de un sistema receptor externo (DefectDojo u otro) más adelante,
  apoyándose en la huella determinista y versionada de cada `Finding` (§5), sin
  necesidad de rediseñar el modelo central.

### Qué se vuelve caro, aceptado a propósito

- Cambiar el nombre del proyecto después del release público (§2) — por eso se cierra
  antes de la Fase 1, no durante ella.
- Cambiar el algoritmo de huella sin subir su versión (§5) — deliberadamente
  imposible de hacer de forma silenciosa; siempre exige nota de migración.
- Añadir un segundo código de salida distinguiendo error de uso de error de
  configuración más adelante — es un cambio incompatible de un contrato ya cubierto
  por semver (§8), no una corrección sin costo.

### Trabajo aplazado, con su disparador explícito de reapertura

| Aplazado | Disparador que lo reabre |
|---|---|
| Taxonomía de reglas normalizada entre herramientas de secretos, para que la huella coincida entre escáneres distintos de la misma categoría (§5) | Incorporar una tercera herramienta de categoría `secrets` al catálogo de integraciones. |
| Motor de política pluggable (Rego/CEL) en vez del gate por umbrales + baseline (§1, §8.1) | Que el gate por umbrales demuestre ser insuficiente para un caso de uso real y concreto de un usuario, no una anticipación especulativa. |
| Sink de publicación a DefectDojo u otro sistema receptor (§1) | Que exista al menos un usuario real con esa integración como bloqueante de adopción. |
| Proveedores de contexto para GitHub Actions y GitLab CI (§1, §10) | Demanda concreta de un usuario en esa plataforma; el contrato ya está validado con dos proveedores de máxima distancia, así que el trabajo restante es de adaptador, no de diseño. |
| Escaneo de imágenes de contenedor en la integración de Trivy (§10) | Que el caso de uso offline-first quede suficientemente probado en producción como para justificar introducir el primer camino con credenciales de red del proyecto. |
| Obtención remota del documento de política (§8.4) | Un usuario real con más de un repositorio necesitando compartir el mismo documento sin copiarlo a mano — el esquema ya está diseñado para que esta pieza sea plomería, no rediseño. |
| Sobrescribir o extender `severity_map.toml` (mapa nativo, defaults por categoría/regla) desde el documento de política del cliente (§6, §8.4) — distinto de `SeverityNormalizer.overrides` (tier 1, por `(herramienta, rule_id)`), que ya existe en el modelo pero tampoco tiene todavía un camino desde `.devsecops/config.toml` hasta él | Un usuario real necesitando ajustar la severidad de un valor nativo o de una regla concreta sin esperar un release de linceo que actualice el fichero empaquetado. |
