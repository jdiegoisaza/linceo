# Adopción de linceo en un pipeline

Este documento es para quien ya decidió meter `linceo` en un pipeline de Azure
DevOps y necesita responder dos preguntas concretas: **¿en qué orden se activan
los controles sin que el equipo lo desactive el primer día?** y **¿qué hace mi
pipeline con cada código de salida?** No repite el contrato de
`docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md` — lo aplica.

La plantilla reutilizable (`azure-pipelines/templates/linceo-scan.yml`) y el
pipeline de ejemplo completo (`azure-pipelines/examples/two-stage-scan.yml`)
son el material de referencia para todo lo que sigue.

## Las tres etapas

Un mismo mecanismo — el parámetro `blocking` de la plantilla, más el archivo
`.devsecops/config.toml` del propio repositorio que se escanea (ADR §5/R5,
§8.4) — implementa las tres. Ninguna etapa exige tocar la plantilla ni el
pipeline; todas se mueven cambiando ese archivo y ese parámetro.

### 1. Observación — no bloquea, solo reporta

**Mecanismo:** `blocking: false` en cada invocación de la plantilla, sin
`failOn`. El paso corre siempre, publica su SARIF siempre, y nunca rompe el
build — Azure DevOps lo muestra como "succeeded with issues" (naranja), nunca
como fallo rojo. No hace falta que exista todavía un `.devsecops/config.toml`
en el repositorio escaneado: sin él, linceo cae a sus defaults compilados
(sin gate activo, ADR §8.1) y el paso sigue siendo puramente informativo.

**Objetivo de esta etapa:** que el equipo vea, sin ningún riesgo para su
propio pipeline, cuántos hallazgos activos existen hoy y de qué severidad —
el insumo que la siguiente etapa necesita para congelarlos.

**Cuánto dura:** lo que tarde alguien en efectivamente mirar al menos una
corrida completa. Días, no sprints — no hay motivo para alargarla una vez que
existe una corrida limpia de leer.

### 2. Baseline — se congela lo existente, bloquea solo lo nuevo

**Mecanismo:** generar `.devsecops/config.toml` en el repositorio escaneado
con una entrada `[[exclusions]]` por cada hallazgo activo que la corrida de
observación reportó, y recién entonces cambiar `blocking: true` en la
plantilla.

`linceo baseline init` (ADR §8.2) hace exactamente esto: corre gitleaks y
trivy de verdad sobre el estado actual del repositorio, y **añade** una
entrada nueva por cada hallazgo activo que todavía no esté cubierto por
ninguna exclusión existente — no requiere que exista una corrida de
observación previa, ni copiar fingerprints a mano, ni que el repositorio
parta de cero.

```bash
linceo baseline init --owner team-atlas
```

```
Wrote 4 new exclusion(s) to .devsecops/config.toml (0 finding(s) already
covered, left unchanged), expiring between 2026-10-22 and 2026-11-06,
staggered by severity.
```

`--owner` es obligatorio y deliberadamente nunca se infiere (nunca del
usuario de git ni de variables del entorno) — declara explícitamente quién
responde por este baseline, casi siempre un equipo, no una persona
(`owner = "team-atlas"`, no `owner = "jperez"`). Cada entrada generada:

```toml
[[exclusions]]
fingerprint = "v1:7c2f9a10c4e0b8a1..."
reason = "Initial adoption baseline — pending real triage"
owner = "team-atlas"
expires_at = 2026-10-22
category = "secrets"
rule_id = "generic-api-key"
path = "src/config.py"

[[exclusions]]
fingerprint = "v1:e41b6d3c9f2a5d77..."
reason = "Initial adoption baseline — pending real triage"
owner = "team-atlas"
expires_at = 2026-11-06
category = "sca"
rule_id = "CVE-2023-37920"
path = "requirements.txt"
package = "certifi"
package_version = "2015.4.28"
```

`category`, `rule_id`, `path`, y (para `sca`) `package`/`package_version`
viajan junto al `fingerprint` — no los escribe una persona, los genera el
comando — porque el ADR (§8.2) los exige para que `linceo baseline migrate`
(ver más abajo, "Manteniendo el baseline") pueda reindexar cada entrada tras
una subida de versión del algoritmo de huella o un cambio de `rule_id` en
una herramienta, en vez de que la entrada quede huérfana e irrecuperable.

#### El vencimiento se escalona por severidad, nunca es una sola fecha

Un baseline generado de una sola vez con **una única fecha de vencimiento**
para las setenta y tantas entradas que una corrida real sobre un repositorio
con historia puede producir tiene un defecto de diseño concreto: ese día, el
repositorio entero vuelve a estar en rojo de golpe, y la reacción previsible
del equipo — bajo presión, sin tiempo de triar setenta hallazgos en una
sesión — es regenerar el baseline por otros 30 días. Eso no es lo que el ADR
§8.2 pide ("caduque por oleadas y fuerce un triaje real"): es exactamente la
deuda eterna que ese diseño existe para evitar, solo que pospuesta.

`baseline init` reparte los vencimientos en dos ejes, deterministas los dos
(ADR R3 — el mismo hallazgo, en cualquier corrida, cae en la misma fecha):

1. **Eje principal: severidad.** Los hallazgos `CRITICAL` vencen primero, en
   `--expires-in-days` (30 por defecto); los `INFO` vencen último, en el
   `max_expiry_horizon_days` de la política (90 por defecto); `HIGH`,
   `MEDIUM` y `LOW` quedan repartidos entre esos dos extremos. Lo más grave
   fuerza una decisión primero — lo menos grave tiene más margen.
2. **Eje secundario: un reparto pequeño y determinista dentro de cada
   severidad**, derivado del propio `fingerprint` del hallazgo — nunca de
   su posición en la lista ni de qué otros hallazgos haya en la misma
   corrida, porque eso sí cambiaría entre corridas. Sin este segundo eje,
   un repositorio cuyos hallazgos se concentran mucho en una sola severidad
   (pongamos, sesenta `MEDIUM`) seguiría volcándolos todos en un único día
   — solo que un día distinto al de antes.

El resultado: `CRITICAL` sigue siendo lo primero en vencer y sigue siendo el
valor que `--expires-in-days` controla directamente, pero ninguna severidad
entera cae en un solo día, y una severidad nunca vence después que la
siguiente más grave — eso se garantiza por construcción, no en promedio.

**No sobrescribe un `.devsecops/config.toml` existente — nunca lo
reemplaza, solo le añade entradas.** `[thresholds]`, `[tool_defaults]` /
`[tools.<nombre>]`, las exclusiones ya existentes (vencidas o no) y
cualquier comentario en el archivo sobreviven intactos: el comando lee el
archivo, calcula qué hallazgos activos todavía no están cubiertos por
ninguna exclusión, y añade solo eso. Si el destino ya existe y hay algo
nuevo que añadir, pide confirmación explícita antes de tocarlo — nombrando
qué hay ya (cuántas exclusiones, si hay gate configurado) y qué se va a
añadir, nunca "Overwrite?" — o `--force` para saltarse la pregunta en un
script. Si no hay nada nuevo que añadir (todo lo activo ya está cubierto),
no toca el archivo en absoluto.

**Una exclusión vencida no se renueva en silencio.** Si una entrada ya
existente cubre un hallazgo pero su `expires_at` ya pasó, `baseline init`
no genera una entrada nueva para el mismo hallazgo — eso reiniciaría el
reloj exactamente sobre la señal que el ADR §8.2 diseñó para forzar una
decisión real. La entrada vencida se deja tal cual, y el comando avisa
cuántas hay para que alguien las revise directamente.

**Si algún tool falla o su binario no está en `PATH`, el comando se niega a
escribir nada** — un baseline generado a partir de evidencia incompleta
(por ejemplo, sin haber podido correr gitleaks) sería sistemáticamente
incompleto en la categoría que faltó, exactamente el "gate verde
engañoso" que el ADR §5 existe para evitar. Corre `linceo doctor` primero
si esto ocurre.

Por esto mismo, `linceo baseline init` puede correrse más de una vez sobre
el mismo repositorio sin miedo — para el primer adoptante que arranca de
cero, o más adelante para recoger hallazgos genuinamente nuevos aparecidos
desde la última corrida — sin duplicar entradas ni perder nada de lo que
ya había.

**Lo que cambia de comportamiento en el momento del `blocking: true`:**
cualquier hallazgo cubierto por una entrada `[[exclusions]]` vigente no
cuenta para el gate (ADR §8.4) — el repositorio arranca en verde aunque el
código detrás no haya cambiado una línea. Cualquier hallazgo **nuevo**, no
cubierto por ninguna entrada, sí bloquea desde el primer commit que lo
introduzca. Esa es la propiedad que hace útil esta etapa: la deuda
histórica queda visible y con fecha de revisión, pero deja de crecer.

### 3. Aplicación — bloquea según política

**Mecanismo:** declarar `[thresholds]` reales en `.devsecops/config.toml`
(o pasar `failOn` en la plantilla para el caso simple de un único corte, ADR
§8.1) según la severidad que el equipo acordó bloquear, y dejar que las
exclusiones de baseline sigan venciendo por oleadas sin renovarlas en bloque
— cada vencimiento es una decisión real pendiente («¿esto ya se corrigió, o
merece una exclusión nueva con su propio `reason`?»), no un trámite.

```toml
version = 1

[thresholds]
critical = 0
high = 0
medium = 25
```

Esta es la configuración final que un repositorio adoptante mantiene en el
tiempo. Las dos etapas anteriores no se "cierran" formalmente — simplemente
dejan de ser necesarias una vez que el archivo de política expresa la
intención real del equipo en vez de ser un artefacto de transición.

## Manteniendo el baseline: `linceo baseline migrate`

**El problema que resuelve.** El `fingerprint` de un hallazgo lleva la
versión del algoritmo que lo produjo embebida en el propio valor
(`v1:...`, ADR §5) — a propósito: así una huella `v2` nunca puede coincidir
por accidente con una `v1`. La contraparte de esa decisión es que, el día
que esa versión suba — un cambio incompatible, documentado con nota de
migración obligatoria, nunca silencioso —, cada entrada `[[exclusions]]`
de cada repositorio que usa `linceo` queda huérfana de golpe: su
`fingerprint` deja de coincidir con nada, y sin un mecanismo de
recuperación la única salida sería regenerar el baseline entero desde
cero, perdiendo el `reason`/`owner`/`expires_at` que cada entrada ya tenía
y volviendo a poner en pantalla, de golpe, toda la deuda que el baseline
existía para mantener ordenada. `linceo baseline migrate` (ADR §8.2)
existe exactamente para evitar eso — y, sin proponérselo como un
mecanismo aparte, también recupera el caso en que una herramienta
simplemente le cambia el nombre a una regla entre versiones (ADR §5): el
`fingerprint` de esa entrada seguiría siendo técnicamente "v1", pero ya no
coincidiría con ningún hallazgo real, exactamente el mismo síntoma que
una subida de versión.

Igual que `baseline init` frente a un destino que ya existe, pide
confirmación explícita antes de tocar el archivo — mostrando primero un
**plan**, en futuro, de lo que va a hacer:

```bash
linceo baseline migrate
```

```
.devsecops/config.toml: 6 exclusion(s) already on v1, 2 would be
reindexed, 1 unresolved, 0 out of scope for this repository.

Would reindex:
  - v0:9c4e0a71cc31 -> v1:2b6f5a10e488 owner=team-atlas
    expires_at=2026-11-06
  - v0:1b77de02a94f -> v1:e41b6d3c9f2a (rule_id renamed:
    'generic-api-key' -> 'aws-access-token') owner=team-atlas
    expires_at=2026-10-22

Unresolved — no current finding's identity matches theirs. The finding
behind one may have been genuinely fixed, or its identity drifted in a way
this cannot recover automatically either way — left untouched; review and
remove, or re-baseline, by hand:
  - v0:44ffee0012ab category=secrets rule_id='old-rule'
    path='legacy/config.py' owner=team-atlas reason='Initial adoption
    baseline — pending real triage' expires_at=2026-10-30

Rewrite these fingerprint(s) in place? [y/N]:
```

Y, tras confirmar y escribir, un **resultado** distinto, en pasado, que
nombra el archivo efectivamente modificado — nunca el mismo texto del plan
repetido:

```
Reindexed 2 exclusion(s) in .devsecops/config.toml (6 already on v1, left
unchanged), 1 unresolved, 0 out of scope for this repository.

Reindexed:
  - v0:9c4e0a71cc31 -> v1:2b6f5a10e488 owner=team-atlas
    expires_at=2026-11-06
  - v0:1b77de02a94f -> v1:e41b6d3c9f2a (rule_id renamed:
    'generic-api-key' -> 'aws-access-token') owner=team-atlas
    expires_at=2026-10-22

Unresolved — no current finding's identity matches theirs. [...]
```

`--force` (para un script o un paso de pipeline) salta la pregunta y el
plan por completo — solo imprime el resultado, una vez.

**Cómo reindexa.** Para cada entrada cuyo `fingerprint` no está en la
versión vigente, corre gitleaks y trivy de verdad contra el estado actual
del repositorio (el mismo run que usa `baseline init`) y busca, entre los
hallazgos activos de esa corrida, uno cuya identidad legible coincida —
primero por identidad completa (`category`, `rule_id`, `path`, y para
`sca` `package`/`package_version`), y solo si eso no encuentra nada, por
esa misma identidad sin `rule_id`, que es lo que recupera el caso de
renombrado. Si más de un hallazgo activo comparte esa identidad reducida
— dos CVE distintos sobre el mismo paquete y versión, por ejemplo — el
comando **no adivina**: dejar la entrada huérfana y visible en el reporte
es preferible a reindexarla sobre el hallazgo equivocado. `reason`,
`owner`, `expires_at`, y el alcance (`repositories`) de la entrada
original viajan intactos a la entrada migrada — migrar no es renovar la
deuda, es mantenerla apuntando a donde corresponde.

**Las "Unresolved" no se descartan — se reportan para que alguien
decida.** Una entrada que no encuentra correspondencia puede significar
dos cosas muy distintas, y el comando no intenta adivinar cuál: que el
hallazgo detrás ya se corrigió de verdad (buena noticia — la entrada ya
no hace falta, se puede borrar a mano), o que su identidad cambió de una
forma que este mecanismo no puede recuperar solo (por ejemplo, el
archivo se movió de sitio además de que la regla cambió de nombre). El
reporte imprime la identidad completa de cada una — huella, categoría,
regla, ruta, dueño, motivo, vencimiento — con exactamente los datos que
hacen falta para decidir a mano sin tener que ir a buscar el archivo.

**El alcance por repositorio se respeta también aquí.** Una entrada con
`repositories` que no incluye el repositorio actual (ADR §8, "Alcance de
las exclusiones") se deja intacta y aparece como "out of scope" en vez de
intentarse — este run no tiene evidencia de ningún otro repositorio
contra la cual reindexarla, y adivinar sería exactamente el tipo de
adivinanza que el resto del comando se niega a hacer.

**Mismo patrón atómico y el mismo respeto por lo demás que ya vive en el
archivo, que `baseline init`.** Solo se reescriben, en el propio texto
crudo del archivo, los valores de `fingerprint` (siempre) y `rule_id`
(solo cuando el renombrado es lo que recuperó la entrada) de las entradas
efectivamente migradas — nunca una re-renderización completa del
documento: `[thresholds]`, `[tool_defaults]`/`[tools.<nombre>]`,
cualquier comentario, y toda entrada que no cambió (incluidas las que
quedan sin resolver) sobreviven byte a byte. La escritura pasa por un
archivo temporal, se valida releyéndola con el mismo cargador de
configuración que usa cualquier otro comando, y solo entonces se mueve al
destino final — si algo falla a mitad de camino, el archivo original
queda exactamente como estaba, nunca a medio escribir.

**Cuándo correrlo.** No es parte del flujo normal de adopción de las tres
etapas de arriba — hace falta únicamente cuando el registro de cambios
del propio `linceo` anuncia una subida de la versión del algoritmo de
huella, o cuando alguien nota que una herramienta integrada renombró una
de sus reglas entre dos versiones ancladas. `linceo baseline migrate` sin
argumentos, contra el mismo `.devsecops/config.toml` que ya usa el
repositorio, es el único paso que hace falta.

## Por qué encender el modo bloqueante desde el día uno es la forma más rápida de perder el scanner

Este es exactamente el mismo argumento que el ADR ya usa para justificar que
`--fail-on` no bloquee por defecto en el propio CLI (§8.1) — aquí se repite
porque a nivel de pipeline es todavía más fácil ignorarlo por accidente:
alguien copia un ejemplo con `blocking: true` sin haber pasado por la etapa
de observación primero.

Gitleaks escanea el historial completo de git por diseño (ADR §10) — no
solo el árbol de trabajo actual. Sobre un repositorio con historia real, eso
significa que la primera corrida encuentra, de forma predecible, docenas o
cientos de hallazgos que llevan meses o años ahí, nunca antes reportados por
nada. Si esa primera corrida ya es bloqueante:

1. El pull request de quien active el scanner se pone rojo — por hallazgos
   que esa persona no introdujo y probablemente no puede triar todos en una
   sesión.
2. La reacción disponible, bajo presión de entregar, no es "vamos a revisar
   esto con calma": es "vamos a sacar este paso del pipeline hasta que
   alguien tenga tiempo" — y ese "hasta que" rara vez llega, porque no hay
   una fecha ni un dueño asociados a esa decisión, a diferencia de una
   exclusión con `expires_at` y `owner`.
3. La segunda vez que alguien propone activar un scanner de secretos en ese
   mismo equipo, la conversación ya no parte de cero: parte de "la última
   vez rompió todo y lo sacamos" — un costo de adopción mayor que el que
   tenía la primera vez, pagado por decisión de diseño, no por necesidad.

El mecanismo de baseline (etapa 2) existe exactamente para este caso, pero
solo ayuda si alguien lo usa **antes** de que el build se ponga rojo — un
operador que ve rojo en el primer intento nunca llega a enterarse de que el
mecanismo existe, porque ya está buscando cómo quitar el paso del pipeline,
no cómo configurarlo. La secuencia observación → baseline → aplicación no es
burocracia: es la única secuencia en la que el equipo ve el mecanismo de
escape (`--fail-on none` / `blocking: false`) antes de necesitar usarlo por
frustración.

## El contrato de exit codes, para quien escribe el pipeline

`linceo scan <categoría>` termina con exactamente uno de estos códigos —
contrato público cubierto por semver (ADR §8), nunca cambia de significado
entre versiones menores o de parche:

| Código | Qué significa | Qué debería hacer el pipeline |
|---|---|---|
| `0` | La corrida terminó completa y el gate pasó (o no hay threshold configurado — nada bloquea). | Continuar. Nada que decidir. |
| `1` | La corrida terminó completa y el gate **falló**: hay hallazgos activos que superan el threshold configurado. | Esto es exactamente lo que `blocking: true` existe para convertir en un paso rojo. Con `blocking: false`, el paso queda "succeeded with issues" — visible, no bloqueante. |
| `2` | Error de uso del CLI o de configuración — el flag pasado, o `.devsecops/config.toml`, están mal formados. | **No es un hallazgo de seguridad.** No hay SARIF que publicar (el proceso nunca llegó a escanear nada). Tratarlo como un paso roto del propio pipeline, igual que cualquier otro error de configuración — el diagnóstico está en el mensaje de error impreso a stderr, no en ningún reporte. |
| `3` | Una herramienta falló al ejecutarse, o la evidencia quedó incompleta (por ejemplo, el binario no estaba disponible) y `--continue-on-tool-error` no estaba activo. | El scanner no corrió limpio — puede haber un SARIF parcial o ninguno. Tratarlo como infraestructura rota, no como "sin hallazgos": un `3` silencioso que un pipeline ignora es exactamente el escenario que ADR §5 llama "gate verde engañoso". |
| `4+` | Reservado para uso futuro. | Tratar como fallo desconocido — no asumir que es inofensivo solo porque hoy no está documentado qué significa. |

**Precedencia que importa para cualquier lógica de pipeline más elaborada
que "¿el step falló sí o no?":** si una herramienta falló en la misma
corrida en la que el gate también habría fallado, gana el `3`, nunca el `1`
(ADR §8) — "el orquestador está roto" tiene que dominar sobre "el
orquestador encontró hallazgos", porque ambos merecen una reacción distinta
de quien opera el pipeline. Si un paso de linceo devuelve `1`, se puede
confiar en que la corrida sí terminó completa y el SARIF publicado sí
refleja evidencia íntegra — no hace falta revisar el log para descartar que
en realidad fue una ejecución rota.

### `blocking` no es lo mismo que el gate de linceo

Son dos decisiones independientes, deliberadamente:

- **El gate de linceo** (`[thresholds]`/`fail_on` en `.devsecops/config.toml`,
  o `failOn` en la plantilla) decide **si existe algo que bloquear** — es la
  política de severidad, y vive en el repositorio que se escanea (ADR
  §5/R5), no en el pipeline.
- **`blocking`** decide **si ese resultado efectivamente rompe el build**
  hoy — es una decisión de etapa de rollout, y vive en el pipeline.

Que sean independientes es lo que permite tener, en la etapa de baseline, un
threshold real configurado (`fail_on = "high"`) con `blocking: false`: el
paso calcula el veredicto real y lo publica en el SARIF y en la consola —
"esto fallaría si estuviera bloqueando" — sin que nadie tenga que
adivinarlo el día que `blocking` pase a `true`.

### La salida `exitCode` para lógica de pipeline más allá de bloquear o no

Cada invocación de la plantilla expone su código de salida como variable de
salida del propio step (`name` en la plantilla es el `stepName` que se le
pasó), consultable desde un paso posterior en el mismo job:

```yaml
- bash: |
    echo "El paso de secretos salió con código: $(linceo_secrets.exitCode)"
  displayName: 'Leer el exit code del scan de secretos'
  condition: succeededOrFailed()
```

Esto es lo que permite, por ejemplo, decidir enviar una notificación distinta
para un `3` (algo está roto) que para un `1` (hay hallazgos reales que
revisar) — sin necesitar parsear el SARIF publicado solo para eso.

## Cómo la plantilla resuelve el contexto de Azure Pipelines dentro del contenedor

`docker run` no hereda el entorno del proceso que lo invoca — nada de lo que
el agente de Azure Pipelines sabe (nombre del repositorio, commit, branch, id
de pull request, id del build) llega al contenedor a menos que se pase de
forma explícita. La plantilla (`azure-pipelines/templates/linceo-scan.yml`)
ya hace esto por defecto, sin que quien la usa tenga que saberlo ni tocar
nada: pasa `-e VAR` para cada variable que `linceo` necesita para que
`--platform auto` (el default; la plantilla nunca lo cambia) resuelva
`azure_devops` en vez de caer, en silencio, a `local`.

**Por qué un listado explícito de variables y no heredar el entorno completo
del agente.** El proceso de un job real de Azure Pipelines carga, en su
propio entorno, bastante más que las variables `BUILD_*`/`SYSTEM_*` que
`linceo` necesita: credenciales de feeds de paquetes, variables secretas
mapeadas explícitamente al entorno, exports de pasos anteriores del mismo
job. Nada de eso le sirve a `linceo`, y heredar el entorno completo del
agente significaría meter todo eso dentro de un contenedor que corre una
herramienta de seguridad — exactamente lo que ese paso no debería hacer. La
plantilla pasa, por nombre, únicamente las variables que
`linceo.providers.azure_devops.ENV_VARS` declara, más `TF_BUILD` (el
sentinel que usa la detección `auto`) — listado canónico en
`src/linceo/providers/azure_devops.py`; tabla completa de qué resuelve cada
una en `README.md`, "Container image".

**El bug real que motivó este arreglo, para que quede claro qué se estaba
rompiendo:** sin este passthrough, `--platform auto` no encuentra `TF_BUILD`
dentro del contenedor, cae a `local`, y la corrida "funciona" — pero contra
el remote de git montado, no contra lo que el agente realmente sabe de ese
run. `repository` sale de la URL del remote en vez de
`BUILD_REPOSITORY_NAME`, y `build_id`/`pull_request_id` quedan
silenciosamente ausentes del reporte. Nada falla ruidosamente — eso es
precisamente lo que lo hace difícil de notar sin mirar con atención el
encabezado `platform=...` del reporte de consola.

**Diagnosticarlo sin correr un scan completo:** `linceo context` (dentro del
contenedor, con las mismas variables que la plantilla ya pasa) muestra qué
plataforma se seleccionó, por qué, y el valor — o ausencia — de cada
variable relevante, antes de correr ninguna herramienta. Si alguna vez una
organización invoca la imagen directamente en un paso propio, sin pasar por
esta plantilla, `linceo context` es la forma más rápida de confirmar si el
problema es exactamente este.

## Fuente remota de la política

Cuando el repositorio escaneado declara `[remote_policy]` en su propio
`.devsecops/config.toml` (ADR R2, §8.4), los umbrales y la configuración de
herramientas dejan de decidirse solo con ese archivo local: se descargan de
un repositorio de política que seguridad mantiene aparte, y este mismo
repositorio hereda cualquier cambio ahí en su siguiente run, sin tocar
nada. Hay exactamente dos formas de autenticar esa descarga, y cuál usar
depende de una sola pregunta: **¿el repositorio de política vive en la
misma organización de Azure DevOps que el repositorio que se está
escaneando, o en otra?**

### Modo 1 — identidad del build, misma organización (el caso común)

Nada que declarar más allá del nombre del repositorio:

```toml
# .devsecops/config.toml, en el repositorio escaneado
[remote_policy]
repository = "security-baseline"
```

`token_env` tiene por defecto `SYSTEM_ACCESSTOKEN` — la identidad OAuth de
la propia ejecución del build, con vida limitada al job, que no exige que
nadie cree ni rote un PAT. La plantilla reutilizable
(`azure-pipelines/templates/linceo-scan.yml`) ya mapea
`$(System.AccessToken)` a esa variable y la reenvía al contenedor por
defecto — un pipeline que use la plantilla no necesita saber que esto
existe. Esta identidad solo puede leer repositorios de la **misma
organización** (y, según el permiso concedido, del mismo proyecto o de
otro); nunca cruza a una organización distinta, sin importar qué permisos
se le concedan ahí.

**Lo único que sí requiere una acción manual, una sola vez:** conceder
permiso de lectura sobre el repositorio de política a la identidad del
build. En Azure DevOps: *Project Settings → Repositories → (repositorio de
política) → Security*, y ahí buscar la identidad
`<Proyecto> Build Service (<Organización>)` — concederle **Read** alcanza,
no hace falta **Contribute**. Si el repositorio de política vive en un
proyecto distinto del que se escanea (el caso realista de un proyecto
dedicado a seguridad/plataforma), declarar ese proyecto explícitamente:

```toml
[remote_policy]
repository = "security-baseline"
project = "platform-security"
```

y revisar además *Organization Settings → Pipelines → Settings → Limit job
authorization scope*: con ese límite activado por proyecto, la identidad
del build puede no alcanzar recursos de otro proyecto aunque el
repositorio ya le conceda permiso de lectura.

**Si la descarga falla con 401 o 403 usando este modo**, el mensaje de
error nombra esta causa explícitamente — "the build identity behind
SYSTEM_ACCESSTOKEN has no Read permission on..." — y dónde concederlo,
para no dejar a quien lo lee adivinando desde un código HTTP desnudo.

### Modo 2 — Personal Access Token, fuera de esa organización

`System.AccessToken` no puede alcanzar una organización distinta de la que
ejecuta el build, sin importar qué permisos se configuren del otro lado —
es una limitación de la propia identidad OAuth, no de este proyecto. Para
un repositorio de política en otra organización, la credencial correcta es
un Personal Access Token (PAT) con permiso de lectura sobre ese
repositorio, guardado como variable secreta del pipeline (nunca como texto
plano en ningún archivo del repositorio, ADR R5/§9).

Tres pasos:

1. Crear el PAT en la organización *de destino* (donde vive el repositorio
   de política), con el alcance mínimo — `Code (Read)` — y guardarlo como
   variable secreta del pipeline (o en un `variable group` / Azure Key
   Vault vinculado), nunca como texto plano en el YAML.
2. Declarar, en el repositorio *escaneado*, qué variable de entorno llevará
   ese token:

   ```toml
   [remote_policy]
   repository = "security-baseline"
   token_env = "LINCEO_POLICY_TOKEN"
   ```

3. Pasar esa variable secreta a la plantilla, vía el parámetro
   `policyRepoToken` — una referencia a la variable, nunca su valor
   (ADR §9):

   ```yaml
   steps:
     - template: ../templates/linceo-scan.yml
       parameters:
         category: secrets
         imageRepository: contoso.azurecr.io/linceo
         imageTag: '0.3.0'
         policyRepoToken: $(MyOrgSecurityBaselinePat)
   ```

`LINCEO_POLICY_TOKEN` es el nombre fijo que la plantilla reenvía al
contenedor cuando se usa `policyRepoToken` — no es necesario, ni está
soportado, elegir un nombre distinto sin modificar la propia plantilla.

**Si la descarga falla con 401 o 403 usando este modo**, el mensaje de
error no atribuye la causa a la identidad del build — un `token_env`
distinto del valor por defecto significa que el operador ya eligió una
credencial concreta, y solo quien la generó puede saber si expiró, si le
falta el alcance `Code (Read)`, o si el PAT es del todo el correcto para
ese repositorio.

### Ninguno de los dos modos afecta las exclusiones del propio equipo

Ambos modos gobiernan exactamente lo mismo — `[thresholds]`/`[tool_defaults]`/`[tools.<nombre>]`
del documento remoto — y nunca las secciones `[[exclusions]]` /
`[[skipped_tools]]`, que siempre se declaran en el `.devsecops/config.toml`
*local* del repositorio escaneado, sin importar cuál de los dos modos de
autenticación esté en uso (ADR §8.4: "un equipo no debería necesitar un
pull request al repositorio de seguridad para suprimir su propio falso
positivo").

### La caché local, y por qué la plantilla monta un volumen para ella

La imagen de referencia ya trae instalado lo necesario para descargar la
política (`[remote-config]`, horneado en la imagen — ADR, "la imagen de
referencia instala `[remote-config]`"), y cada run intenta refrescar
siempre, sin ninguna ventana de caducidad que lo retrase. Lo que la imagen
*no* resuelve por sí sola es dónde vive la copia de respaldo: por defecto,
bajo `$HOME` dentro del propio contenedor — un filesystem que un
`docker run --rm` (el patrón que toda invocación de esta plantilla usa, y
el más común en cualquier pipeline de CI) descarta por completo al
terminar el paso.

Sin nada más, en ese patrón una descarga fallida **nunca** encontraría una
copia en caché que usar como respaldo, sin importar cuántas veces la
descarga hubiera funcionado en runs anteriores: cada `docker run`
empezaría con una caché vacía, así que el estado `cached` de
`PolicySourceStatus` (ADR §8.4) sencillamente no ocurriría bajo este
patrón de despliegue — una falla de red degradaría directo a `unavailable`
(solo el documento local), nunca a "la última copia buena conocida",
justo donde esa copia más hace falta.

**Por eso la plantilla de referencia ya monta, por defecto, un directorio
bajo `$(Agent.ToolsDirectory)`** — el único directorio de Azure Pipelines
explícitamente documentado como *no* limpiado entre jobs del mismo agente
(a diferencia de `$(Agent.TempDirectory)`, que sí lo es) — como el
`$LINCEO_POLICY_CACHE_DIR` del contenedor. Nada que configurar para
beneficiarse de esto: cualquier pipeline que use la plantilla ya lo tiene.

**Este mecanismo solo ayuda de verdad en un agente self-hosted** — el caso
habitual para un pipeline que de por sí necesita Docker. En un agente
hospedado por Microsoft, cada job corre en una VM nueva, así que ese
directorio también empieza vacío en cada run; el mount no lo empeora (es
exactamente el mismo comportamiento que sin él), simplemente no puede
ayudar ahí donde no hay ninguna máquina que se reutilice entre runs.

**Sobre el directorio compartido en sí:** la plantilla lo crea con permisos
abiertos (`chmod 0777`) porque el contenedor corre siempre con un uid fijo
no privilegiado (1000, ADR R4) que casi nunca coincide con el usuario del
propio agente, y un bind mount comparte los permisos del host tal cual,
sin ningún remapeo de uid. El documento de política cacheado no es en sí
mismo un secreto (ADR §9 — el token que lo descargó nunca llega a ese
archivo); `write_cached_policy` sigue creando cada archivo individual
exclusivo del propietario (`0600`) en cada escritura, así que ese permiso
abierto del directorio solo afecta quién puede listar o crear entradas
ahí, nunca quién puede leer una ya escrita por otro uid.

### Diagnosticando un 404 al descargar la política

Azure DevOps devuelve el mismo `404 Not Found` para al menos cuatro causas
distintas, indistinguibles entre sí a partir de solo la respuesta:

1. El repositorio de política no existe — o no en la organización/proyecto
   que esta descarga resolvió (revisar `repository` y, si aplica,
   `project` en `[remote_policy]`).
2. El archivo no existe en la ruta declarada (`path`, default
   `"policy.toml"`).
3. El archivo existe, pero no en la rama por defecto del repositorio — esta
   descarga siempre lee la rama por defecto, nunca una específica.
4. La identidad que hace la petición no tiene permiso de lectura sobre el
   repositorio. Azure DevOps devuelve deliberadamente 404, no 403, cuando
   el permiso falta — para no revelar la existencia de un repositorio
   privado a quien no tiene acceso — así que esta causa es indistinguible
   de las otras tres sin descartarlas una por una.

El mensaje de error de `linceo` ya nombra las cuatro explícitamente, en vez
de repetir el error crudo de `httpx` sin más contexto — no hace falta
descartarlas a mano una por una como sí hizo falta antes de esta revisión.
