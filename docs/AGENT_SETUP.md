# Setting up Wazuh and Soc Thief with an AI coding agent

The prompt below asks an AI coding agent (Claude Code, Codex, Cursor or similar) to install Soc
Thief, and a lab Wazuh if you don't have one, then prove they work together. Run it on a lab or
test machine first, never straight onto a production host. The agent asks you questions before
it starts, keeps secrets out of the chat, and stops to ask before it changes a firewall, enables
a timer or sends anything.

The prompt holds no install steps of its own. It sends the agent to the repository's docs and to
Wazuh's documentation, so it stays correct when they change.

## What you'll need

- Everything in [DEPLOYMENT.md, "What you need"](DEPLOYMENT.md#what-you-need).
- Python 3.12 or later on the Soc Thief host, for the checks the agent runs outside the
  container.
- If you have no Wazuh yet: a lab machine that meets the requirements on Wazuh's
  [Quickstart](https://documentation.wazuh.com/current/quickstart.html) page. If Wazuh, Ollama
  and Soc Thief will share it, give it more memory than that page asks for.
- Optional: a disposable test host with a Wazuh agent, for the attack simulations in
  [DETECTION.md](DETECTION.md#measuring-detection).
- Sudo on the hosts involved, and a terminal of your own for typing secrets.

## The prompt

Copy everything inside the block into your agent, started from the Soc Thief repository root.

````text
You are helping me install Soc Thief (this repository) and connect it to a Wazuh indexer.

## How to use the docs

The repository docs are the only source of truth. This prompt gives you the order, the
questions, the rules and the points where you stop and ask me. For every step it names a file
and section: open it, read it in full and follow it as written. Do not copy steps from memory.
If a doc and this prompt disagree, the doc wins; tell me about the disagreement. If something
you need is in neither the docs nor Wazuh's official documentation, say so and ask me. Do not
invent commands, settings, paths or unit names.

Read these before you run anything: README.md, docs/DEPLOYMENT.md, docs/COLLECTOR.md,
docs/MODELS.md, docs/TUNING.md, docs/DETECTION.md, docs/STATE_STORE.md, CONTRIBUTING.md,
.env.example, Containerfile, deploy/systemd/ and simulations/.

## Hard rules

1. Never ask me to paste a secret into this chat, and never print one: passwords, the Discord
   webhook URL, the ntfy URL and token, API keys, the identity key, or anything in Wazuh's
   generated password file. Never put a secret on a command line, in an environment variable,
   in a log or in git. Secrets live only in the files docs/DEPLOYMENT.md "4. Secrets" lists.
   When I have to supply one, give me a command to run in my own terminal that reads it from
   my keyboard into the file with a restrictive umask, then check the file's owner and mode
   with stat. Never read the contents back.
2. Soc Thief gets read-only access to Wazuh and nothing more. Its indexer user has exactly the
   role docs/COLLECTOR.md "The read-only indexer user" describes. Never widen it to make a check
   pass, and never use the Wazuh admin account as Soc Thief's account.
3. Never weaken the policy. A model only advises (docs/MODELS.md "The rule that comes first").
   Do not add model-based suppression or a confidence gate, do not edit policy or tuning code,
   and do not try to tune protected groups. I write the tuning entries.
4. Alert data stays on this host unless I explicitly opt in. Do not set
   SOC_THIEF_OPENAI_ALLOW_REMOTE, enable the Jev drop-in or open egress to a hosted model until
   you have walked me through docs/MODELS.md "The privacy trade-off" and I have said yes in this
   conversation.
5. Stop and ask me before you:
   - change any firewall or nftables rule;
   - create any gate file under /etc/soc-thief/, or enable or start any timer or service;
   - run anything that sends to Discord or ntfy;
   - change any Wazuh setting, role, user, role mapping or cluster setting;
   - do anything at all on a host I have said is production.
6. If a check fails, do not edit, skip or work around it. Report it and wait.
7. At the end, tell me what you verified by running it and what you assumed.

## Step 0: ask me

Ask these in one message and wait for my answers:

1. Do I already have Wazuh? If so, which version, and is the indexer on the Soc Thief host or
   elsewhere? (I may answer with placeholders such as <wazuh-host>.)
2. Which host runs Soc Thief, and is it a lab machine or production?
3. Is a Discord webhook for a private channel ready?
4. Do I want breach pages through ntfy, and is the ntfy server public or private?
5. Which model: local Ollama, another local OpenAI-compatible server, a hosted model, or none?
   Before I answer, summarise docs/MODELS.md "Pick your backend", and tell me what happens to
   a group when no model is reachable, citing the doc that says so.
6. My timezone, as an IANA name.
7. Do I have a push monitor for the hourly heartbeat?
8. Do I have a disposable test host with a Wazuh agent for the simulations?

Then compare the host with the tested setup at the top of docs/DEPLOYMENT.md and its "What you
need" section. Tell me every difference before going on.

## Step 1: the demo

Follow README.md "Try it without Wazuh" as my normal user. Show me the digest file it writes.
Also run the synthetic tests from CONTRIBUTING.md "Development setup" and report the result.

## Step 2: Wazuh

Path A, Wazuh already exists:

1. Show me the role and user you plan to create, built from docs/COLLECTOR.md "The read-only
   indexer user", and wait for my yes. Create them with the Wazuh dashboard as Wazuh's RBAC page
   shows: https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html.
   That page's worked example adds permissions Soc Thief must not have (an index `*`
   permission, document-level security and a tenant permission). Take only the screens from it,
   and take the permissions from COLLECTOR.md. I type the new user's password myself.
2. Report on the own_index default as that COLLECTOR.md section describes. Do not change it.
3. Prove the checks listed in that section from the new user's side: what must succeed and
   what must be refused, a write included. Use curl with the indexer CA and a root-only,
   mode 0600 curl config file for the credentials, never a -u flag. For the write probe, use a
   scratch index that is neither wazuh-alerts-* nor named after the user. If anything that
   should be refused succeeds, stop and tell me. Delete the curl config afterwards.

Path B, no Wazuh, lab only:

1. Fetch https://documentation.wazuh.com/current/quickstart.html now and follow it as it reads
   today. Take the version and installer from that page, not from memory. Tell me the version,
   and check the host against the page's requirements, before you run anything.
2. The installer writes the generated passwords to a file the Quickstart names. Do not open or
   print it. Tell me where it is.
3. Find where the indexer listens and which host names its TLS certificate carries. Soc Thief
   needs one of those names (docs/DEPLOYMENT.md "5. The environment file" and "Networking"). If
   the certificate has no usable name, stop and ask me. Never turn off certificate or hostname
   checks.
4. Then do all of path A.

## Step 3: Soc Thief's own access check

Run the verifier as docs/COLLECTOR.md "Verifying access" describes, plain and with --snapshot,
against the reader's secret files. If it fails the way COLLECTOR.md "Point-in-time snapshots"
describes, tell me. The fix there is an admin change to Wazuh, so it needs my yes.

## Step 4: install, in the order docs/DEPLOYMENT.md gives

Follow these DEPLOYMENT.md sections in this order: "1. Service account", "2. Install the source
tree", "3. Build the image", "4. Secrets", "5. The environment file", "Timezone", "Networking",
"Egress policy", "The approval file". Things those sections leave to you or to me:

- "3. Build the image": show me the base image digest you resolved before building, and the
  built image's digest after.
- "4. Secrets": you may write the non-secret files yourself and generate the identity key
  straight into its file as docs/STATE_STORE.md "Opaque identifiers" shows. Remind me to back
  the key up. Every other value I type myself (hard rule 1).
- "Timezone": edit the copies under /etc/systemd/system/. The status unit
  (soc-thief-status.service) sets its own SOC_THIEF_TIMEZONE and has no EnvironmentFile, so
  tell me it will show UTC unless I ask for a drop-in.
- "Networking": if the indexer is not on host loopback, stop and talk me through that section
  before changing anything.
- "Egress policy": the repository has no unit that loads the policy at boot. Write the policy
  and that oneshot unit, show me both, and load nothing without my yes. Mind the section's note
  about builds.
- Model: if I chose something other than local Ollama, read the matching docs/MODELS.md
  section, show me the runner drop-in you would add, and remember hard rule 4.
- "The approval file": ask me whether I want a dated approval or "never".

## Step 5: turn it on, one item at a time, asking each time

Follow docs/DEPLOYMENT.md "6. Turn it on" in its order, with my yes before each numbered item.

- Item 1 (verifier): before creating its gate file, compare the ExecStart= line of
  soc-thief.service with the arguments docs/COLLECTOR.md "Verifying access" says the verifier
  requires. If the unit cannot pass as written, tell me and leave its timer off; your manual run
  in step 3 stands in for it.
- Item 3 (daily runner) is the first real window. Read "The daily runner" first. Afterwards,
  check its journal and ask me to look at the digest in Discord before anyone enables the timer.
- Item 6 (fast path): follow "The fast path" and docs/DETECTION.md "Silent agents" in full,
  only if I want ntfy pages.
- Items 7 and 8 (reconcile, backfill): do not do them now. The section says when they make
  sense, and that is my call later.

## Step 6 (optional): measure detection

Only if I have a disposable test host, and only with my yes. Read docs/DETECTION.md "Measuring
detection" through "Known gaps", explain to me what each scenario does to the test host, and let
me run the simulation script there myself. Then score the run as "Running it" describes and
show me the results.

## Finish: fill in this checklist

Mark each line VERIFIED (you ran it and saw the result), ASSUMED (not tested), SKIPPED (I said
no, or it does not apply) or FAILED, with a short note.

- [ ] Host compared with the tested setup; differences reported
- [ ] Demo and synthetic tests ran
- [ ] Wazuh present, or lab Wazuh installed from the current Quickstart (version: ...)
- [ ] Read-only role and user created exactly as COLLECTOR.md says
- [ ] Allowed and refused checks from COLLECTOR.md, write probe included
- [ ] own_index reported
- [ ] Verifier passed, plain and with --snapshot
- [ ] DEPLOYMENT.md steps 1 to 5 done, in order
- [ ] Image pinned by digest
- [ ] Secret files: owner, mode and no symlinks checked; no secret in chat, logs or flags
- [ ] Timezone set, and timer zones match
- [ ] Egress policy and its boot unit reviewed by me; loaded or not
- [ ] Approval file written (dated or never)
- [ ] Verifier unit checked against the arguments it needs
- [ ] Webhook test message arrived
- [ ] First real window ran; journal and digest checked
- [ ] Timers enabled, each with my yes (list them)
- [ ] Fast path, status check and backup: state of each
- [ ] Simulations run, or skipped
- [ ] Temporary files (curl config, scratch files) removed
- [ ] Doc gaps or disagreements found
````
