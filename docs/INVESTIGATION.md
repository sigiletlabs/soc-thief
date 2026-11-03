# Investigation briefs

Soc Thief can gather context on one case into a short local text file, so you do not start every
investigation with a blank Wazuh search. There are two ways: on demand from your shell, and
automatically after a fast-path breach page.

Neither path uses Discord, writes to Wazuh, changes state or opens a network listener. Neither can
change, delay or withdraw an alert.

## On-demand brief

`python -m soc_thief.investigate` takes the opaque case ID from the daily digest attachment (or
from `soc_thief.cases list`, see [TUNING.md](TUNING.md#case-review)). It looks up that case's rule
and agent IDs in the state store, then runs two bounded read-only searches:

1. the newest 20 alerts for that rule and agent in the last seven days;
2. the newest 10 alerts from other rules on the same agent within 15 minutes of the latest match.

Counts cover the whole query at the time it ran. The listed events are samples. The two searches
are separate, so they are not one atomic snapshot.

The case lookup runs as the service account through `sudo -u soc-thief`, so it may ask for your
sudo password. The indexer searches run as you, with your own copy of the read-only indexer
credential. This keeps the indexer credential with your account and the case store with the
service account. The running container gets no extra access.

```sh
mkdir -p -m 700 "$HOME/.config/soc-thief/investigations"
export WAZUH_INDEXER_URL_FILE="$HOME/.config/soc-thief/wazuh-indexer-url"
export WAZUH_INDEXER_USERNAME_FILE="$HOME/.config/soc-thief/wazuh-indexer-username"
export WAZUH_INDEXER_PASSWORD_FILE="$HOME/.config/soc-thief/wazuh-indexer-password"
export WAZUH_INDEXER_CA_FILE="$HOME/.config/soc-thief/wazuh-indexer-ca.pem"
PYTHONPATH=/opt/soc-thief/src python3 -m soc_thief.investigate \
  --case-id CASE_ID \
  --output "$HOME/.config/soc-thief/investigations/brief-01.txt"
```

`CASE_ID` is the 64-character ID. `--days` takes 1 to 30 (default 7). The output directory must be
yours and mode `0700`. The file is created mode `0600` and never overwritten, so use a new name each
time. The command prints only fixed success or failure text, and the brief never contains raw event
JSON or command lines.

Check the source alerts in Wazuh before you record a verdict, and delete the brief when you no
longer need it. A case older than the 90-day case retention cannot be resolved.

## Automatic follow-up on a breach page

When enabled, the fast path runs the same two searches for each breach page it sent, after the page
has gone out and its checkpoint is saved. It already has the rule and agent IDs, so there is no case
lookup and no sudo. The searches use the fast path's own reader credential and a seven-day window.

It is off until you set `SOC_THIEF_FASTPATH_MODEL_BASE_URL` (see
[DEPLOYMENT.md](DEPLOYMENT.md#follow-up-investigation)).

The local model (the same Ollama adapter and validation as daily triage) receives rule IDs, levels,
redacted rule descriptions and counts. It never receives a host name, path, address or user field.
It must answer a closed schema:

- `assessment`: `likely_benign_admin_tool`, `suspicious`, `likely_malicious` or `undetermined`;
- `urgency`: an ntfy priority, `min` to `urgent`;
- `rmm_possible`: true or false, asked only when you list trusted remote management tools.

Any other key, value or type is an invalid answer. The model's own words are never kept or sent.

### Trusted remote management tools

Remote monitoring and management (RMM) agents often run PowerShell and cmd scripts that look exactly
like an attacker's. If your hosts run one, list it in `SOC_THIEF_RMM_MARKERS` as comma-separated
product names or process or path markers (at most 16, each at most 128 characters). The model is
then told about them and answers `rmm_possible`, which the follow-up shows as "RMM possible: yes"
or "no". That answer is context only and changes nothing. Unset, no RMM is assumed and the question
is not asked.

### What the follow-up page says

The follow-up carries only the signal, agent ID, case token, the model's typed answers, the two
search counts as buckets (`0`, `1-9`, `10-99`, `100+`) and whether the local brief was written. Its
priority is the higher of the original page's and the model's (`autoinvestigate.raise_only`), so a
breach follow-up is always `urgent`. Every follow-up ends "The breach page still stands. Nothing
was dismissed, retracted or downgraded." A `likely_benign_admin_tool` answer also says it is not a
dismissal.

Every page sent in the run gets one follow-up, never silence:

| Situation | Follow-up |
| --- | --- |
| Searches and a valid model answer | `Soc Thief investigation: <signal>` with the values above |
| A search failed, the model failed or timed out, or the answer was invalid | `Soc Thief investigation failed: <signal>` with a fixed reason |
| More than 3 in one run, or too little time left before the 300-second deadline | One combined `Soc Thief investigation skipped` page |
| No model configured | No follow-up. The breach page stands alone. |
| Model endpoint invalid (not a bare loopback HTTP origin) | One combined `Soc Thief investigation failed` page |

At most 3 pages are investigated per run (`autoinvestigate.MAX_INVESTIGATIONS`). One starts only
if its worst case (two searches with retries, the 30-second model timeout and one page) still fits
in the deadline. A follow-up that cannot be sent makes the run exit `1`. It is not retried, because
the breach page itself went out.

When one page covers several cases, only the first is investigated and the follow-up says how many
were not. Cases covered only by the fast path's overflow summary page get the skipped notice.

The full brief, including the model's typed answer, is written only to
`/var/lib/soc-thief/fastpath/investigations/<UTC time>-<case prefix>.txt`: mode `0600` in a `0700`
directory, at most 32 KiB, newest 50 kept. Read it as the service account or root on the host.
