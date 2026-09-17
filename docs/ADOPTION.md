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

**Mecanismo:** crear (o completar) `.devsecops/config.toml` en el
repositorio escaneado con una entrada `[[exclusions]]` por cada hallazgo
activo que la corrida de observación reportó, y recién entonces cambiar
`blocking: true` en la plantilla.

El ADR (§8.2) describe un comando `baseline init` que generaría este archivo
automáticamente a partir de una corrida real. **Ese comando no existe
todavía en este release** — hoy el baseline se arma a mano, copiando el
`fingerprint` (columna `FP` en la consola, `partialFingerprints` en el SARIF,
`fingerprint` en el JSON) de cada hallazgo activo. Es mecánico pero no
ambiguo: cada hallazgo activo de la corrida de observación se vuelve una
entrada.

```toml
version = 1

[[exclusions]]
fingerprint = "v1:7c2f9a10"           # prefijo inequívoco alcanza (ADR §7 "FP")
reason = "Baseline de adopción — pendiente de triage real"
owner = "team-atlas"
expires_at = 2026-10-17                # corto a propósito, ver abajo

[[exclusions]]
fingerprint = "v1:e41b6d3c"
reason = "Baseline de adopción — pendiente de triage real"
owner = "team-atlas"
expires_at = 2026-10-17
```

**El vencimiento va corto a propósito — 30 días, no los 90 que
`max_expiry_horizon_days` permite como máximo.** El propio ADR es explícito
sobre esto para el `baseline init` que todavía no existe: el objetivo es que
el baseline "caduque por oleadas y fuerce un triaje real... en vez de
congelar permanentemente el estado del repositorio". Un vencimiento largo
logra exactamente lo que esta etapa existe para evitar — deuda que nunca se
revisa. Armado a mano, ese mismo criterio sigue aplicando: mejor un
vencimiento corto que un `reason` motivador.

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
