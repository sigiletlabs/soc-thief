# Models

## The rule that comes first

**A model in Soc Thief is advisory only. It can never suppress, hide, delay or downgrade an
alert.** Every group a model reviews is still delivered, whatever the model says. If the model is
down, slow or returns something invalid, the group is delivered anyway with a health failure. Your
tuning file is the only thing that suppresses alerts. See [POLICY.md](POLICY.md#the-model-cannot-suppress)
for the measurement behind this rule.

So choosing a model changes how your digest is ordered and annotated. It does not change what you
are shown.

## Pick your backend

| Backend | Where data goes | Status |
| --- | --- | --- |
| Local Ollama (default, `qwen3:4b`) | Stays on the host, over loopback | The default and the most tested |
| OpenAI-compatible chat API | Loopback by default; a remote endpoint only if you opt in | Being added for the first release |
| Jev (TypeSafe), hosted | Leaves the host, pseudonymised | Experimental, opt-in, never run as the live default |

### The privacy trade-off

A local model sees alert group summaries and nothing leaves the machine. A hosted model sees
pseudonymised summaries, and they leave your network every day. Pseudonymisation replaces host
names with tokens and masks IP addresses, URLs and obvious secrets, but rule descriptions, decoder
names and log locations still go out, and they can say a lot about your environment. Decide
whether that is acceptable before you point Soc Thief at a remote endpoint. If in doubt, stay
local.

## Local Ollama (default)

The default adapter is `OllamaTriage` in `src/soc_thief/model.py`. Install
[Ollama](https://ollama.com) on the same host and pull the model:

```sh
ollama pull qwen3:4b
```

Settings (plain values, not secrets):

| Setting | Default | Meaning |
| --- | --- | --- |
| `MODEL_BASE_URL` | `http://127.0.0.1:11434` | Must be a bare loopback HTTP origin (IPv4 or IPv6). Anything else is refused. |
| `MODEL_NAME` | `qwen3:4b` | Any model your Ollama has pulled |
| `MODEL_TIMEOUT_SECONDS` | `60` | 1 to 120 |

How it calls the model:

- Preflight runs first. Protected, critical, breach and tuned groups never reach the model.
- One non-streaming `/api/chat` request per group, temperature 0, thinking disabled, a fixed JSON
  schema, proxies ignored, redirects refused.
- The group goes in its own user message as data, under a fixed system instruction, so alert text
  cannot rewrite the prompt.
- The answer must be exactly `classification`, `confidence`, `rationale` and `analyst_action`.
  Duplicate keys, non-finite numbers and malformed envelopes are rejected.
- Only the model's reported identity (for example `qwen3:4b`) is stored, on the audit row. The
  prompt, response, rationale and endpoint are never stored or rendered.

In the systemd units, the container reaches the host's Ollama through rootless Podman's `pasta`
port forwarding (`SOC_THIEF_MODEL_PORT`), so no external network access is needed.

### What we know about qwen3:4b

It is small enough for a home server and fast enough for a daily window. It does not give a usable
confidence: in measurement it reported only 0.95 or 0.85, and the same group could flip between
benign and suspicious across identical requests at temperature 0. Treat its classification as a
hint for ordering, not a verdict.

## OpenAI-compatible chat API

This backend speaks the OpenAI chat-completions format. That covers local servers such as
Ollama, LM Studio, llama.cpp's server and vLLM, and hosted APIs such as OpenRouter. It asks for
a strict JSON schema in the response, so the server or model must support structured output.

| Setting | Value |
| --- | --- |
| `SOC_THIEF_MODEL_BACKEND` | `openai` (the default is `ollama`) |
| `SOC_THIEF_OPENAI_BASE_URL` | The API base, for example `http://127.0.0.1:1234/v1` or `https://openrouter.ai/api/v1` |
| `SOC_THIEF_OPENAI_MODEL` | The model name the server expects |
| `SOC_THIEF_OPENAI_API_KEY_FILE` | Path to a file holding the key, if the server needs one |
| `SOC_THIEF_OPENAI_TIMEOUT_SECONDS` | 1 to 120, default 60 |
| `SOC_THIEF_OPENAI_ALLOW_REMOTE` | `1` to allow an endpoint that isn't on this machine |

Keys are only read from a file. Never from a plain environment variable or a flag.

Plain `http` is only allowed to a loopback IP address such as `127.0.0.1`. Anything else needs
`https` and `SOC_THIEF_OPENAI_ALLOW_REMOTE=1`. Even `localhost` counts as remote, because a name
can resolve somewhere you didn't expect. Setting that opt-in is your decision that alert
summaries may leave the host. What's sent is the rule ID, level, event count, decoder and the
rule description. In the description, the group's agent and manager names are replaced with
`[host]`, and addresses, URLs and secret-looking values are masked. Agent IDs, timestamps and
locations are not sent. Some Wazuh rules put event text into their description, so other
details, such as a user name, can still get through. Read a few of your own descriptions before
you turn a remote model on.

A hosted example, using OpenRouter:

```sh
SOC_THIEF_MODEL_BACKEND=openai
SOC_THIEF_OPENAI_BASE_URL=https://openrouter.ai/api/v1
SOC_THIEF_OPENAI_MODEL=<a model that supports structured output>
SOC_THIEF_OPENAI_API_KEY_FILE=/run/secrets/openrouter_key
SOC_THIEF_OPENAI_ALLOW_REMOTE=1
```
- Host egress: a remote endpoint also needs a rule in your host egress policy for that one
  destination. See [DEPLOYMENT.md](DEPLOYMENT.md#egress-policy).

The same rules apply as for Ollama: strict JSON answer, one request per group, failures deliver
with a health failure, and the answer cannot suppress anything.

## Jev (experimental)

TypeSafe's Jev is a hosted model that returns typed judgements and
probabilities rather than chat text. Soc Thief can ask it two things about each group:

- an attention score: the probability that the group warrants an analyst's attention;
- a threat tag from a fixed list: `routine`, `possible_auth_abuse`, `possible_malware`,
  `possible_privilege_misuse`, `possible_policy_violation`, `other_concern`,
  `insufficient_context`.

Both are used only to order groups within a severity level and to show in the digest and the
attachment. They never enter `policy.decide()` or tuning. An unknown or malformed answer fails
closed for that group with a health failure.

### What the evidence says

- In one measurement on real alert groups, Jev's score separated groups within the same severity
  level, where the chat models did not.
- A later comparison used 40 groups labelled by investigating each one in the logs. Every one of
  the 40 turned out to be routine, so the comparison could not rank the models. Accuracy on real
  findings is unmeasured.
- Jev has not been run as the live default anywhere. Treat it as an experiment.

### Turning it on

Bring your own key. Soc Thief calls one fixed route, `_JEV_URL` in `src/soc_thief/model.py`
(Jev through the Vercel AI Gateway), so the key must be one that route accepts.

1. Save the key in a root-owned `0600` file, `/etc/soc-thief/secrets/jev_key`.
2. Install the drop-in `deploy/systemd/soc-thief-runner-jev-trial.conf` as
   `/etc/systemd/system/soc-thief-runner.service.d/jev-trial.conf`. It loads the key as a
   credential and sets `SOC_THIEF_JEV_TRIAL=1` and `SOC_THIEF_JEV_KEY_FILE` for the daily runner.
3. Allow HTTPS egress to the Jev endpoint for the service account.
   `python -m soc_thief.jev_egress --source <your nft policy file> --output <new file>` writes a
   proposed policy with one narrowly scoped HTTPS rule inserted before the drop rule. It never
   applies anything; review it and load it yourself.
4. `systemctl daemon-reload`.

Remove the drop-in and reload to switch back to the local model.

What Jev receives: capped group summaries only. Before any request, host and manager names for the
whole window are replaced with tokens such as `host-01`, and IP addresses, URLs and secret-looking
values are masked. The endpoint and model ID are fixed in the code and cannot be changed by
configuration or alert data. A deadline and a repeated-failure cut-off leave the runner time to
finish its report if Jev is slow or down.

`soc_thief.jev_evaluation` and `soc_thief.model_comparison` compare model output against a private
worksheet of labelled groups, if you want to run your own comparison.

## Follow-up investigation model

The fast path's optional follow-up uses the local Ollama adapter with a different, closed schema.
See [INVESTIGATION.md](INVESTIGATION.md#automatic-follow-up-on-a-breach-page).
