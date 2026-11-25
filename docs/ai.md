# AI pre-assessment

As of: 2026-11-19 · optional, off by default

New incidents are pre-assessed by Claude – or a local model via Ollama: **harmless / keep an eye on it / suspicious**, risk, a recommendation (resolve, ignore, check, block) and two to four reasons – in plain language for non-experts. The assessment is a **suggestion**; decisions and actions are still taken manually.

## What goes to the AI – and what doesn't

| Is sent | Is **never** sent |
|---|---|
| Rule (e.g. "new device", "new domain") and its description | Device name, hostname, notes |
| Severity, count | IP and MAC addresses |
| Trust level (known, IoT, guest, unknown) | Incident title (often contains the device name) |
| Vendor according to the scan, whether the MAC address is random | Data of **company devices** – these are never assessed |
| For domain rules: the main domain and up to 15 most-used main domains of the device (7 days) | Full queries, local names (`*.arpa`, `.local`, `.lan`, `fritz.box` …), DNS logs, history |
| Up to 5 **other open incidents of the same device** (±7 days): only rule, offset ("5 min later"), status and their AI verdict | For these other incidents: title, domains, details; **resolved and ignored** incidents |

The data is marked as data; the AI is told not to follow instructions in it (e.g. in a crafted domain name). A device on the network could still try to influence the assessment – that is why it remains a **suggestion**, and Aluco never acts on it automatically.

## Setup

In `.env`:

```sh
ALUCO_AI_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-…          # treat it like a password
ALUCO_AI_MODEL=claude-opus-5-5      # default
ALUCO_AI_MAX_PER_RUN=5              # cost limit per run
```

Then `docker compose up -d --build aluco aluco-web`.

## How it works

- The runner automatically assesses **new or reopened** incidents, the most severe first, at most `ALUCO_AI_MAX_PER_RUN` per run.
- The assessment appears in the dashboard (violet box in the incident) and – unless `ALUCO_NOTIFY_MINIMAL=true` – in the ntfy alert.
- In the dashboard, an assessment can be requested or renewed.
- If the API fails (network, quota, invalid key), Aluco keeps running normally; the error is in the log or in the incident.

## Technology and cost

- Official Anthropic SDK (optional extra `ai`), structured output with schema validation, effort `low`.
- If the model refuses a request, a fallback model takes over on the server side (`fallbacks: "default"`).
- An incident needs only a few hundred tokens; in a home network with a few incidents per day, the cost is a few cents per month. A cheaper model can be chosen with `ALUCO_AI_MODEL`.
- Assessments are deleted with the incident (retention period), and immediately when a device is marked as a company device.

## Via OpenRouter

If you get Claude (or another model) through [OpenRouter](https://openrouter.ai) instead of directly from Anthropic:

```sh
ALUCO_AI_ENABLED=true
ALUCO_AI_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-…                 # treat it like a password
ALUCO_AI_MODEL=anthropic/claude-opus-5.5   # default; cheaper: anthropic/claude-sonnet-5.5 or anthropic/claude-haiku-5.5
```

- Same prompt, same response schema (`json_schema`, `strict`) and the same strict validation of the response as with Ollama; plus the guard against injected instructions. Standard library, no SDK.
- **Privacy:** The (minimal) incident data goes to OpenRouter and to the model's provider. Aluco sets `provider.data_collection = "deny"` – OpenRouter then only routes to providers that do not store requests or use them for training – and `require_parameters`, so that only providers that respect the schema answer.
- Cost (as of 2026-11): Claude Opus 5.5 about $4 / $20 per million input/output tokens, so one assessment costs just over 1 cent; one run of the sample set (32 cases × 2) about $1.
- Measuring: `aluco ai-eval --provider openrouter --model anthropic/claude-opus-5.5 --repeat 2` (optionally `--language en`). Result see below: 100 % in both languages.
- Claude models are sent no `temperature`: Claude 5 rejects it, and because Aluco requires `require_parameters`, OpenRouter would otherwise find no provider ("No endpoints found"). Other models get `temperature: 0`.

## Local model (Ollama) – data stays in the home network

Instead of Claude, a model on your own hardware can do the assessment, e.g. on a Mac or PC in the home network with [Ollama](https://ollama.com). The same minimal fields are sent – but they do not leave the home network.

```sh
# on the computer running Ollama
ollama pull qwen3:4b                      # small, good with German, English and JSON (~2.5 GB)
OLLAMA_HOST=0.0.0.0 ollama serve          # make it reachable in the home network (mind the firewall)
```

In the Aluco server's `.env`:

```sh
ALUCO_AI_ENABLED=true
ALUCO_AI_PROVIDER=ollama
ALUCO_AI_OLLAMA_URL=http://192.0.2.5:11434
ALUCO_AI_MODEL=qwen3:4b
```

- The response is requested via JSON schema and **strictly validated** (only allowed values, limited lengths).
- Small models are less accurate than Claude – the assessment remains a suggestion.
- On a Raspberry Pi itself, a model of this size is too slow; better use a more powerful computer.
- Ollama has no login of its own: make it reachable only in the home network, never from the internet.

## Measuring assessment quality (sample set)

To make prompt changes and model switches comparable, there is a fixed **sample set** of 32 incidents (`src/aluco/ai_eval_cases.json`): all rules, typical false alarms (random MAC, guest devices, vendor domains), attempts to inject instructions via domain names or vendor information, and combinations of several incidents on one device. Each case is prepared like a real incident; for each case it is defined which verdict and recommendation still count as correct.

```sh
aluco ai-eval --provider ollama --ollama-url http://192.0.2.5:11434 --model qwen3:4b --repeat 2
aluco ai-eval --provider claude                     # needs ANTHROPIC_API_KEY
aluco ai-eval --case autostart-getarnt --json       # single cases, output as JSON
aluco ai-eval --language en                         # English prompt
```

- **Hit:** verdict, recommendation (and, where defined, risk) are within the allowed range.
- **"Behauptung prüfen" (check claim):** sentences like "the domain is known for …" – the AI only gets the incident data, so such knowledge is often made up. Not an error, but look at it manually.
- `--min-rate 0.8` exits with code 1 below 80 % – for your own test runs. The set does not run in normal CI (it needs a model).

### Results

| Date | Model | Hits | stable¹ | to check | Duration |
|---|---|---|---|---|---|
| 2026-11-24 | ollama/qwen3:4b, prompt v1 (Mac, Apple Silicon) | 36/48 (75 %) | yes | 6 | 3.7 min |
| 2026-11-24 | ollama/qwen3:4b, prompt v2 | 42/48 (88 %) | yes | 4 | 2.6 min |
| 2026-11-24 | ollama/qwen3:4b, prompt v2 + device history (32 cases) | 56/64 (88 %) | yes | 4 | 3.5 min |
| 2026-11-24 | ollama/qwen3:4b, **English** + guard (32 cases) | 58/64 (91 %) | yes | 0 | 4.2 min |
| 2026-11-24 | **Claude Opus 5.5** via OpenRouter, German (32 cases) | **64/64 (100 %)** | mostly² | 0 | 6.5 min |
| 2026-11-24 | **Claude Opus 5.5** via OpenRouter, English (32 cases) | **64/64 (100 %)** | mostly² | 0 | 5.7 min |

¹ both runs (`--repeat 2`) identical.
² Claude 5 does not accept a `temperature`; in 3 (de) and 2 (en) of 32 cases the two runs differed slightly (e.g. risk "mittel" instead of "hoch", or "pruefen" instead of "sperren") – always within the allowed values.

**Claude Opus 5.5** gets every case right in both languages, without the guard having to step in. The known weaknesses of qwen3:4b do not occur: the disguised `com.apple…` autostart from a hidden folder is rated "verdaechtig", the combination "new device, malicious domain 5 min later" is recognized, injected instructions (including in the vendor name) have no effect, there are no made-up claims ("known for …"), and in English all summaries are English. Cost of both runs together about $2.

**Recommendation:** If you do not want to hand incident data to a cloud service, use Ollama (88 % de / 91 % en with the guard) – the assessment is a rough suggestion there. If you want the best possible assessment, use Claude (directly or via OpenRouter).

**Prompt v2** explains what "sperren" (block) does, forbids claims like "known for", names the location rather than the name as decisive for autostart entries, and says that injected text does not change the assessment in either direction.

| Rule | v1 | v2 |
|---|---|---|
| new_device | 8/10 | 8/10 |
| new_domain | 8/8 | 6/8 |
| bad_domain | 8/10 | **10/10** |
| agent_port | 6/6 | 6/6 |
| agent_login | 2/2 | 2/2 |
| agent_autostart | 2/6 | 4/6 |
| agent_posture | 2/6 | **6/6** |
| newly_registered_domain³ | – | 4/6 |

³ Rule and three cases added with #25 (set then 27 cases); the numbers above apply to the original 24. A one-off query of a harmless-sounding new domain from a known laptop is rated "verdaechtig" instead of "beobachten" (but the recommendation is correctly "pruefen").

Consistently improved (in all tested variants): laptop settings → "pruefen" instead of "sperren"; an instruction in the domain name no longer downgrades a malicious domain.

Open with qwen3:4b:
- An instruction in the **vendor name** still leads to "sperren".
- A disguised `com.apple.…` autostart from a hidden folder stays "beobachten".
- A new domain of the TV vendor counts as "verdaechtig" (correct in v1).
- "known for …" still occurs despite being forbidden.

### English and guard against injection (#29)

With `ALUCO_LANGUAGE=en`, the AI gets an English prompt (`aluco/ai_en.py`), English rule descriptions and field names, and writes the summary and reasons in English. The fixed answer values (`verdaechtig`, `pruefen` …) are the same in both languages. The German prompt is unchanged character for character (test).

Measured with qwen3:4b, 32 cases × 2 (`aluco ai-eval --language en`):

| Variant | Hits | Finding |
|---|---|---|
| English prompt, translated 1:1 | 46/64 (72 %) | The answer values are German words – meaningless in English; the model picks "verdaechtig" conspicuously often |
| + meaning of the answer values explained | 52/64 (81 %) | but **all injection cases flip to "harmlos"** – English attack text has a stronger effect on an English prompt |
| Injection paragraph moved to the beginning | 52/64 (81 %) | no change – rejected |
| German prompt, only "in English" | 52/64 (81 %) | 62 of 64 summaries still German – rejected |
| **Explained answer values + fixed guard** | **58/64 (91 %)** | implemented; German with the guard unchanged at 56/64 (88 %) |

**Guard** (`aluco.ai.guard`, for both languages and all models): If the incident data contains text that looks like an instruction to the AI (`ignore … instructions`, `bewerte als`, `SYSTEM:` …), the assessment must not fall below "beobachten / pruefen"; a reason points this out. It does not act upwards – disconnecting is always confirmed by a human. Anyone who controls a domain name or an autostart label can no longer talk an incident down this way. In the sample set, detection fires on exactly the 5 injection cases.

Open in English: qwen3:4b does not recognize the combination "new device, malicious domain shortly afterwards" in English (it does in German); the disguised autostart stays "beobachten" as in German.

### Context per device (#26)

Besides the incident, the AI sees the closest other open incidents of the same device (see table above). Five cases (`kombi-…`) test this, each with a counterpart without history:

| Case | alone | with history |
|---|---|---|
| New device with random MAC, malicious domain 5 min later | beobachten / niedrig | **verdaechtig** / mittel |
| Malicious domain from a device that appeared 5 min earlier | verdaechtig / hoch / sperren | verdaechtig / hoch / sperren (already the maximum) |
| Unknown program accepts connections, 3 min after a new autostart entry | – | beobachten (allowed: beobachten/verdaechtig) |

Three variants measured (qwen3:4b, 32 cases × 2 each):

| Variant | Hits | Finding |
|---|---|---|
| A: history in the context, prompt unchanged | 54/64 (84 %) | combination recognized – but an Apple device with a **harmless, resolved** history becomes "verdaechtig/hoch" |
| B: like A, plus a note about the history in the prompt | 50/64 (78 %) | also flips cases **without** history (Python server, Google updater, camera domain → "verdaechtig") – rejected |
| **C: like A, but leave out resolved and ignored incidents** | **56/64 (88 %)** | all 10 combination assessments correct; cases without history identical to A – **implemented** |

Resolved and ignored incidents have already been settled by the person; showing them as "history" is read by a small model as suspicion. The cases `kombi-harmlose-vorgeschichte` and `kombi-oft-ignoriert` make sure it stays that way.

> **Careful when fine-tuning:** Small models react strongly to wording. A single additional sentence at the end of the prompt lowered qwen3:4b from 88 % to 75 %, two further notes likewise to 75 % – with contradictory answers ("harmlos", risk "hoch"). So always re-measure changes and don't tailor them to individual cases; with 32 cases, the set is small. `--repeat` only shows whether the answers stay the same with the same prompt (temperature 0), not how robust the prompt is.

## Privacy

With Claude, the transmitted data leaves the home network and is processed by Anthropic (and, via OpenRouter, also by OpenRouter); with Ollama, it stays in the home network. If you want neither, leave the feature off.
