from contextlib import closing
import contextlib
import gc
import importlib.machinery
import importlib.util
import io
from pathlib import Path
import sqlite3
import tempfile
import unittest
import warnings


ROOT = Path(__file__).resolve().parents[1]


class DeploymentArtifactsTests(unittest.TestCase):
    def test_jev_trial_override_changes_only_model_selection_and_credential(self):
        base = (ROOT / "deploy/systemd/soc-thief-runner.service").read_text()
        override = (ROOT / "deploy/systemd/soc-thief-runner-jev-trial.conf").read_text()
        start = next(line for line in base.splitlines() if line.startswith("ExecStart="))
        expected = start.replace("--env SOC_THIEF_TUNING_FILE=/run/secrets/tuning ",
                                 "--env SOC_THIEF_TUNING_FILE=/run/secrets/tuning "
                                 "--env SOC_THIEF_JEV_TRIAL=1 --env SOC_THIEF_JEV_KEY_FILE=/run/secrets/jev_key "
                                 "--env SOC_THIEF_JEV_ENDPOINT=${SOC_THIEF_JEV_ENDPOINT} "
                                 "--env SOC_THIEF_JEV_MODEL=${SOC_THIEF_JEV_MODEL} ")
        body = "".join(line + "\n" for line in override.splitlines() if not line.startswith("#"))
        self.assertEqual(body, "[Service]\n"
                         "LoadCredential=jev_key:/etc/soc-thief/secrets/jev_key\n"
                         "Environment=SOC_THIEF_JEV_ENDPOINT=typesafe\n"
                         "Environment=SOC_THIEF_JEV_MODEL=\n"
                         "ExecStart=\n" + expected + "\n")
        # The unit's environment file is read after these defaults and overrides them.
        self.assertIn("EnvironmentFile=/etc/soc-thief/environment", base)
        self.assertNotIn("LoadCredential=jev_key:", base)

    def test_openai_dropins_change_only_model_selection_credential_and_forwarded_port(self):
        added = ("--env SOC_THIEF_MODEL_BACKEND=openai "
                 "--env SOC_THIEF_OPENAI_BASE_URL=${SOC_THIEF_OPENAI_BASE_URL} "
                 "--env SOC_THIEF_OPENAI_MODEL=${SOC_THIEF_OPENAI_MODEL} "
                 "--env SOC_THIEF_OPENAI_API_KEY_FILE=/run/secrets/openai_key "
                 "--env SOC_THIEF_OPENAI_TIMEOUT_SECONDS=${SOC_THIEF_OPENAI_TIMEOUT_SECONDS} "
                 "--env SOC_THIEF_OPENAI_ALLOW_REMOTE=${SOC_THIEF_OPENAI_ALLOW_REMOTE} ")
        # The daily run and the late-alert pass review groups through the same
        # triage_from_environment, so both get the drop-in and one window never mixes models.
        for name in ("runner", "reconcile"):
            with self.subTest(unit=name):
                base = (ROOT / "deploy/systemd" / f"soc-thief-{name}.service").read_text()
                override = (ROOT / "deploy/systemd" / f"soc-thief-{name}-openai.conf").read_text()
                start = next(line for line in base.splitlines() if line.startswith("ExecStart="))
                anchor = "--env SOC_THIEF_TUNING_FILE=/run/secrets/tuning "
                # The loopback forward moves from the Ollama port to the OpenAI server's port.
                expected = start.replace(",-T,${SOC_THIEF_MODEL_PORT} ", ",-T,${SOC_THIEF_OPENAI_PORT} ") \
                    .replace(anchor, anchor + added)
                self.assertNotEqual(expected, start)
                settings = "".join(line + "\n" for line in override.splitlines() if not line.startswith("#"))
                # Without these defaults an unset value reaches the container as "" and is refused.
                # The environment file overrides both; it alone can set ALLOW_REMOTE=1.
                self.assertEqual(settings, "[Service]\n"
                                 "Environment=SOC_THIEF_OPENAI_TIMEOUT_SECONDS=60\n"
                                 "Environment=SOC_THIEF_OPENAI_ALLOW_REMOTE=0\n"
                                 "LoadCredential=openai_key:/etc/soc-thief/secrets/openai_key\n"
                                 "ExecStart=\n" + expected + "\n")
                # Without the drop-in nothing about the model changes.
                for absent in ("SOC_THIEF_MODEL_BACKEND", "SOC_THIEF_OPENAI", "openai_key"):
                    self.assertNotIn(absent, base)
        # The backfill builds OllamaTriage directly, so a drop-in there would change nothing.
        self.assertNotIn("triage_from_environment", (ROOT / "src/soc_thief/backfill.py").read_text())
        self.assertFalse(list((ROOT / "deploy/systemd").glob("soc-thief-backfill-openai*")))

    def test_status_reads_the_report_timezone_from_the_environment_file(self):
        unit = (ROOT / "deploy/systemd/soc-thief-status.service").read_text()
        settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
        # EnvironmentFile= overrides Environment=, so UTC stays only as the default.
        self.assertIn("EnvironmentFile=/etc/soc-thief/environment", settings)
        self.assertIn("Environment=SOC_THIEF_TIMEZONE=UTC", settings)
        # Still a host process with no container, no state and no write access.
        for absent in ("podman", "ReadWritePaths", "StateDirectory", "/var/lib/soc-thief"):
            self.assertFalse([line for line in settings if absent in line], absent)

    def test_egress_policy_loads_before_and_gates_every_network_unit(self):
        unit = (ROOT / "deploy/systemd/soc-thief-egress.service").read_text()
        settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
        guide = (ROOT / "docs/DEPLOYMENT.md").read_text()
        self.assertIn("/etc/soc-thief/egress.nft", guide)
        self.assertIn("deploy/systemd/soc-thief-egress.service", guide)
        self.assertIn("ExecStart=/usr/sbin/nft -f /etc/soc-thief/egress.nft", settings)
        self.assertIn("ExecReload=/usr/sbin/nft -f /etc/soc-thief/egress.nft", settings)
        for line in ("Type=oneshot", "RemainAfterExit=yes", "DefaultDependencies=no",
                     "Before=network-pre.target shutdown.target", "Wants=network-pre.target"):
            self.assertIn(line, settings)
        # Stopping the unit must never open egress.
        self.assertFalse([line for line in settings if line.startswith("ExecStop")])
        # Every unit that starts a container is ordered after the policy and requires it once
        # enabled, so a policy that fails to load stops them from starting at all.
        network = sorted(path.name for path in (ROOT / "deploy/systemd").glob("*.service")
                         if "/usr/bin/podman " in path.read_text())
        self.assertEqual(len(network), 5)
        ordered = " ".join(line[len("Before="):] for line in settings if line.startswith("Before=")).split()
        required = next(line for line in settings if line.startswith("RequiredBy=")).split("=", 1)[1].split()
        self.assertEqual(sorted(required), network)
        self.assertLessEqual(set(network), set(ordered))
        self.assertIn("WantedBy=multi-user.target", settings)

    def test_runtime_is_gated_and_hardened(self):
        unit = (ROOT / "deploy/systemd/soc-thief.service").read_text()
        self.assertIn("ConditionPathExists=/etc/soc-thief/enable-schedule", unit)
        self.assertIn("User=soc-thief", unit)
        self.assertIn("--read-only", unit)
        self.assertIn("--cap-drop=ALL", unit)
        self.assertIn("--security-opt=no-new-privileges", unit)
        self.assertIn("--userns=keep-id", unit)
        self.assertIn("--network pasta:-T,${SOC_THIEF_INDEXER_PORT} ", unit)
        self.assertIn("--mount type=bind,src=%d,dst=/run/secrets,ro=true", unit)
        self.assertIn("LoadCredential=wazuh_indexer_password:", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertNotIn("UNPINNED", unit)

    def test_container_units_carry_the_hardening_rootless_podman_can_start_under(self):
        # Measured on the deployment host by running each setting alone through the runner unit
        # with the pause process killed first. These three stop rootless Podman from starting at
        # all; re-adding one makes every run fail, and after a reboot NoNewPrivileges does too.
        for name in ("soc-thief", "soc-thief-runner", "soc-thief-reconcile", "soc-thief-backfill"):
            unit = (ROOT / "deploy/systemd" / f"{name}.service").read_text()
            settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
            for absent in ("NoNewPrivileges=", "ProtectKernelTunables=", "ProtectHostname="):
                self.assertFalse([line for line in settings if line.startswith(absent)], (name, absent))
            for present in ("PrivateDevices=yes", "BindPaths=/dev/net/tun", "DeviceAllow=/dev/net/tun rw",
                            "ProtectSystem=strict", "PrivateTmp=yes",
                            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"):
                self.assertIn(present, settings, (name, present))
            self.assertIn("--security-opt=no-new-privileges", unit)
        backup = (ROOT / "deploy/systemd/soc-thief-backup.service").read_text()
        self.assertIn("NoNewPrivileges=yes", backup)

    def test_units_reach_host_loopback_without_host_network(self):
        for name in ("soc-thief.service", "soc-thief-runner.service", "soc-thief-reconcile.service"):
            unit = (ROOT / "deploy/systemd" / name).read_text()
            self.assertIn("--network pasta:-T,${SOC_THIEF_INDEXER_PORT}", unit)
            self.assertIn("--add-host ${SOC_THIEF_INDEXER_ALIAS}:127.0.0.1", unit)
            self.assertNotIn("slirp4netns", unit)
            self.assertNotIn("--network host", unit)
            self.assertNotIn("--network=host", unit)
            self.assertNotIn("docker.sock", unit)
            self.assertNotIn("--privileged", unit)
            self.assertIn("STATE_PATH=/var/lib/soc-thief/state ", unit)

    def test_container_units_never_pull_an_image_at_run_time(self):
        """An enabled timer must only run the image approved during host validation."""
        for name in (
            "soc-thief.service",
            "soc-thief-runner.service",
            "soc-thief-reconcile.service",
            "soc-thief-backfill.service",
        ):
            with self.subTest(unit=name):
                unit = (ROOT / "deploy/systemd" / name).read_text()
                self.assertIn(" run --pull=never --rm ", unit)

    def test_runner_services_are_separately_gated_and_hardened(self):
        verifier = (ROOT / "deploy/systemd/soc-thief.service").read_text()
        self.assertNotIn("SOC_THIEF_MODEL_PORT", verifier)
        units = {name: (ROOT / "deploy/systemd" / f"soc-thief-{name}.service").read_text() for name in ("runner", "reconcile")}
        for mode, marker, name in (("--daily", "enable-runner", "runner"), ("--reconcile", "enable-reconcile", "reconcile")):
            with self.subTest(unit=name):
                self.assert_runner_unit(units[name], mode, marker, name)
        self.assertNotIn("--daily", units["reconcile"])
        self.assertNotIn("enable-runner", units["reconcile"])
        # Apart from mode, marker and names, the reconcile unit mirrors the runner exactly.
        normalized = units["runner"].replace("--daily", "--reconcile").replace("enable-runner", "enable-reconcile") \
            .replace("--name soc-thief-runner", "--name soc-thief-reconcile") \
            .replace("SyslogIdentifier=soc-thief-runner", "SyslogIdentifier=soc-thief-reconcile") \
            .replace("TimeoutStartSec=3900s", "TimeoutStartSec=1800s")
        # Only the daily runner pages on a tuned spike, so only it carries the ntfy credential.
        # The credential is an optional drop-in: a required one would stop every daily run until a
        # route exists. Without it the page fails and the spike is delivered with a health failure.
        self.assertNotIn("LoadCredential=ntfy", units["runner"])
        dropin = (ROOT / "deploy/systemd/soc-thief-runner-ntfy.conf").read_text()
        self.assertIn("[Service]\nLoadCredential=ntfy:/etc/soc-thief/secrets/ntfy\n", dropin)
        self.assertEqual(units["runner"].count("--env SOC_THIEF_NTFY_FILE=/run/secrets/ntfy "), 1)
        self.assertNotIn("ntfy", "".join(l for l in units["reconcile"].splitlines() if not l.startswith("#")))
        normalized = normalized.replace("LoadCredential=ntfy:/etc/soc-thief/secrets/ntfy\n", "") \
            .replace("--env SOC_THIEF_NTFY_FILE=/run/secrets/ntfy ", "") \
            .replace("--add-host ${SOC_THIEF_NTFY_ALIAS}:${SOC_THIEF_NTFY_ADDR} ", "")
        # The ntfy hosts entry and its defaults are runner-only, like the credential.
        normalized = "\n".join(l for l in normalized.splitlines()
                                if not l.startswith("Environment=SOC_THIEF_NTFY_"))
        strip = lambda text: [line for line in text.splitlines() if line and not line.startswith(("#", "Description="))]
        self.assertEqual(strip(normalized), strip(units["reconcile"]))

    def assert_runner_unit(self, unit, mode, marker, name):
        self.assertIn(f"ConditionPathExists=/etc/soc-thief/{marker}", unit)
        self.assertEqual(unit.count("ConditionPathExists="), 1)
        self.assertNotIn("enable-schedule", unit)
        self.assertIn(f"--name soc-thief-{name} ", unit)
        self.assertIn(f"SyslogIdentifier=soc-thief-{name}\n", unit)
        self.assertIn("--entrypoint python", unit)
        self.assertIn(f"-m soc_thief.runner {mode}\n", unit)
        self.assertIn(",-T,${SOC_THIEF_MODEL_PORT}", unit)
        for flag in ("User=soc-thief", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--userns=keep-id", "--mount type=bind,src=%d,dst=/run/secrets,ro=true", "ProtectSystem=strict",
                     "PrivateDevices=yes", "MemoryDenyWriteExecute=yes", "UMask=0077",
                     "PrivateTmp=yes", "ProtectHome=yes", "RestrictSUIDSGID=yes", "KillMode=control-group"):
            self.assertIn(flag, unit)
        for credential in ("wazuh_indexer_url", "wazuh_indexer_username", "wazuh_indexer_password",
                           "wazuh_indexer_ca", "discord_webhook_url", "identity_key", "runner_approval", "tuning"):
            self.assertIn(f"LoadCredential={credential}:/etc/soc-thief/secrets/{credential}\n", unit)
        self.assertEqual(unit.count("LoadCredential=tuning:"), 1)
        self.assertEqual(unit.count("SOC_THIEF_TUNING_FILE="), 1)
        for variable in ("DISCORD_WEBHOOK_URL_FILE=/run/secrets/discord_webhook_url",
                         "SOC_THIEF_IDENTITY_KEY_FILE=/run/secrets/identity_key",
                         "SOC_THIEF_RUNNER_APPROVAL_FILE=/run/secrets/runner_approval",
                         "SOC_THIEF_TUNING_FILE=/run/secrets/tuning",
                         "MODEL_BASE_URL=http://127.0.0.1:${SOC_THIEF_MODEL_PORT}"):
            self.assertIn(f"--env {variable}", unit)
        # Runner deadline 1500s + 60s worker grace + bounded parent health delivery. Only the daily
        # runner catches up missed days, so only it needs room for a second window.
        self.assertIn("TimeoutStartSec=3900s" if name == "runner" else "TimeoutStartSec=1800s", unit)
        self.assertNotIn("TimeoutStartSec=480s", unit)

    def test_fast_path_unit_is_gated_minimal_and_cannot_touch_runner_state(self):
        unit = (ROOT / "deploy/systemd/soc-thief-fastpath.service").read_text()
        timer = (ROOT / "deploy/systemd/soc-thief-fastpath.timer").read_text()
        settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
        self.assertIn("ConditionPathExists=/etc/soc-thief/enable-fastpath", settings)
        self.assertEqual(unit.count("ConditionPathExists="), 1)
        self.assertIn("-m soc_thief.fastpath\n", unit)
        self.assertIn(" run --pull=never --rm ", unit)
        # The indexer, plus the loopback Ollama port for the optional follow-up investigation.
        self.assertIn("--network pasta:-T,${SOC_THIEF_INDEXER_PORT},-T,${SOC_THIEF_MODEL_PORT} ", unit)
        # Only its own state directory is mounted; the runner database is out of reach.
        self.assertIn("--volume /var/lib/soc-thief/fastpath:/var/lib/soc-thief/fastpath:Z ", unit)
        self.assertNotIn("--volume /var/lib/soc-thief:", unit)
        self.assertIn("STATE_PATH=/var/lib/soc-thief/fastpath ", unit)
        self.assertIn("--env SOC_THIEF_RUNNER_APPROVAL_FILE=/run/secrets/runner_approval", unit)
        self.assertIn("LoadCredential=ntfy:/etc/soc-thief/secrets/ntfy", settings)
        # No tuning or Discord on the paging path, and no wait on the daily run's lock.
        for absent in ("tuning", "discord", "priority.lock", "systemctl stop"):
            self.assertFalse([line for line in settings if absent in line], absent)
        # The model is optional and operator-set. The unit never hard-codes an endpoint, so an
        # unset SOC_THIEF_FASTPATH_MODEL_BASE_URL means no follow-up at all, and the
        # follow-up keeps its own short model timeout inside the fast path deadline.
        self.assertIn("--env MODEL_BASE_URL=${SOC_THIEF_FASTPATH_MODEL_BASE_URL} ", unit)
        # Its only default is empty, which the environment file overrides.
        self.assertEqual([line for line in settings if line.startswith("Environment=SOC_THIEF_FASTPATH_MODEL")],
                         ["Environment=SOC_THIEF_FASTPATH_MODEL_BASE_URL="])
        self.assertLess(unit.index("EnvironmentFile=/etc/soc-thief/environment"),
                        unit.index("Environment=SOC_THIEF_FASTPATH_MODEL_BASE_URL="))
        self.assertIn("--env MODEL_TIMEOUT_SECONDS=30 ", unit)
        self.assertNotIn("LoadCredential=model", unit)
        # 300s deadline + pages/container 120s + one late follow-up 30s + agent liveness 120s.
        self.assertIn("TimeoutStartSec=570s\n", unit)
        for absent in ("NoNewPrivileges=", "ProtectKernelTunables=", "ProtectHostname="):
            self.assertFalse([line for line in settings if line.startswith(absent)], absent)
        for present in ("User=soc-thief", "PrivateDevices=yes", "ProtectSystem=strict", "PrivateTmp=yes",
                        "ProtectHome=yes", "UMask=0077", "KillMode=control-group"):
            self.assertIn(present, settings)
        for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--userns=keep-id"):
            self.assertIn(flag, unit)
        self.assertIn("Unit=soc-thief-fastpath.service", timer)
        self.assertIn("OnUnitInactiveSec=10m", timer)
        # The expected-agent inventory is a credential read through a *_FILE path.
        self.assertIn("LoadCredential=agent_inventory:/etc/soc-thief/secrets/agent_inventory", settings)
        self.assertIn("--env SOC_THIEF_AGENT_INVENTORY_FILE=/run/secrets/agent_inventory ", unit)

    def test_paging_units_resolve_ntfy_without_dns(self):
        # Public DNS cannot resolve a tailnet ntfy host, so each paging unit carries a fixed hosts
        # entry. Its defaults are harmless and overridden by /etc/soc-thief/environment, so a unit
        # installed before ntfy is configured still starts.
        for name in ("soc-thief-fastpath.service", "soc-thief-runner.service", "soc-thief-runner-jev-trial.conf"):
            text = (ROOT / "deploy/systemd" / name).read_text()
            self.assertEqual(text.count("--add-host ${SOC_THIEF_NTFY_ALIAS}:${SOC_THIEF_NTFY_ADDR} "), 1, name)
        for name in ("soc-thief-fastpath.service", "soc-thief-runner.service"):
            text = (ROOT / "deploy/systemd" / name).read_text()
            self.assertIn("Environment=SOC_THIEF_NTFY_ALIAS=ntfy.invalid\n", text, name)
            self.assertIn("Environment=SOC_THIEF_NTFY_ADDR=127.0.0.1\n", text, name)
            self.assertLess(text.index("EnvironmentFile=/etc/soc-thief/environment"),
                            text.index("Environment=SOC_THIEF_NTFY_ALIAS"), name)
        for name in ("soc-thief-reconcile.service", "soc-thief-backfill.service"):
            self.assertNotIn("NTFY", (ROOT / "deploy/systemd" / name).read_text(), name)

    def test_status_proves_fast_path_coverage_without_new_access(self):
        # Coverage and liveness come from the fast path's journal lines, which the status
        # account already reads; it gets no fast path state, indexer, inventory or ntfy access.
        unit = (ROOT / "deploy/systemd/soc-thief-status.service").read_text()
        settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
        for absent in ("fastpath", "agent_inventory", "ntfy", "wazuh", "ReadOnlyPaths", "BindReadOnlyPaths"):
            self.assertFalse([line for line in settings if absent in line], absent)
        # Expecting the fast path is a separate drop-in at activation, never staged here.
        self.assertFalse([line for line in settings if "SOC_THIEF_EXPECT_FASTPATH" in line])
        self.assertIn("SupplementaryGroups=systemd-journal", settings)

    def test_shared_runtime_directory_survives_a_sharing_unit_stopping(self):
        """The priority lock and the Podman runroot live in a RuntimeDirectory four units share.

        systemd removes a RuntimeDirectory when a unit deactivates unless it is preserved, and it
        does not reference-count across units. Measured on systemd 255: with the default
        (RuntimeDirectoryPreserve=no) a sharing unit that exits - including the backfill's own
        designed refusal path, where the nonblocking flock is denied and the unit fails - deletes
        /run/soc-thief while another unit is still running. That unlinks the priority.lock inode
        the running unit holds, so the next flock creates a new inode and acquires the "exclusive"
        lock immediately, and it destroys the running container's Podman runroot.

        The application state lock is unaffected - it lives in StateDirectory, which systemd
        keeps - so state integrity still fails closed. What breaks is the documented priority
        guarantee and the running container's runtime state.
        """
        sharing = ("soc-thief.service", "soc-thief-runner.service",
                   "soc-thief-reconcile.service", "soc-thief-backfill.service",
                   "soc-thief-fastpath.service")
        for name in sharing:
            with self.subTest(unit=name):
                unit = (ROOT / "deploy/systemd" / name).read_text()
                self.assertIn("RuntimeDirectory=soc-thief\n", unit)
                self.assertIn("RuntimeDirectoryPreserve=yes\n", unit)
                # The fast path keeps its Podman runroot inside the shared directory (see below).
                runroot = "/run/soc-thief/fastpath/podman" if name == "soc-thief-fastpath.service" else "/run/soc-thief/podman"
                self.assertIn(f"--runroot {runroot} ", unit)
        # Any future unit that shares the directory must preserve it too, or it re-arms the defect.
        for path in sorted((ROOT / "deploy/systemd").glob("*.service")):
            with self.subTest(unit=path.name):
                unit = path.read_text()
                if "RuntimeDirectory=soc-thief\n" in unit:
                    self.assertIn("RuntimeDirectoryPreserve=yes\n", unit)
                    self.assertIn(path.name, sharing)

    def test_fast_path_never_shares_a_podman_namespace_with_another_unit(self):
        """Rootless Podman runs a store's commands in the namespace of whichever unit started first.

        It joins the pause process named under XDG_RUNTIME_DIR, or a running container's conmon
        from the store's database. systemd mounts /run/credentials/<unit> only in that unit's own
        namespace, so with one shared store the fast path failed with "statfs
        /run/credentials/soc-thief-fastpath.service" whenever it started during the daily run,
        and a runner starting during a fast path run fails
        the same way. Reproduced on Ubuntu 24.04, Podman 4.9.3, systemd 255: a separate
        XDG_RUNTIME_DIR alone still failed, because of the conmon join; a separate store passed in
        both directions. The fast path takes no priority lock, so it alone needs this.
        """
        unit = (ROOT / "deploy/systemd/soc-thief-fastpath.service").read_text()
        settings = [line for line in unit.splitlines() if line and not line.startswith("#")]
        self.assertIn("Environment=XDG_RUNTIME_DIR=/run/soc-thief/fastpath", settings)
        self.assertIn("RuntimeDirectory=soc-thief/fastpath", settings)
        self.assertLess(settings.index("RuntimeDirectory=soc-thief"), settings.index("RuntimeDirectory=soc-thief/fastpath"))
        start = next(line for line in settings if line.startswith("ExecStart="))
        self.assertIn("--root /var/lib/soc-thief/podman-fastpath --runroot /run/soc-thief/fastpath/podman ", start)
        # The image comes read-only from the runner's store, so the deploy builds once and the
        # environment's image digest resolves for both.
        self.assertIn("--storage-opt additionalimagestore=/var/lib/soc-thief/podman ", start)
        self.assertIn(" ${SOC_THIEF_IMAGE} ", start)
        # No other unit may use the fast path's store or runtime directory.
        for path in sorted((ROOT / "deploy/systemd").glob("*.service")):
            if path.name != "soc-thief-fastpath.service":
                with self.subTest(unit=path.name):
                    other = path.read_text()
                    self.assertNotIn("podman-fastpath", other)
                    self.assertNotIn("/run/soc-thief/fastpath", other)

    def test_status_timeout_covers_every_inspection_command_and_the_heartbeat(self):
        from soc_thief import status
        unit = (ROOT / "deploy/systemd/soc-thief-status.service").read_text()
        # 2 runner systemctl reads, the runner journal, the fast path timer and journal, then curl.
        budget = 5 * status.COMMAND_TIMEOUT_SECONDS + 20
        limit = int(next(line for line in unit.splitlines() if line.startswith("TimeoutStartSec="))[16:-1])
        self.assertGreaterEqual(limit, budget)
        self.assertIn("--max-time 20 ", unit)
        self.assertGreaterEqual(status.COMMAND_TIMEOUT_SECONDS, 60)

    def test_runner_timeout_covers_the_last_catch_up_window(self):
        from soc_thief import runner
        unit = (ROOT / "deploy/systemd/soc-thief-runner.service").read_text()
        window = runner.RunnerLimits().deadline_seconds + runner.WORKER_GRACE_SECONDS + 240
        self.assertIn(f"TimeoutStartSec={runner.CATCH_UP_START_LIMIT_SECONDS + window}s\n", unit)

    def test_runner_timer_follows_boundary_and_lateness_margin(self):
        timer = (ROOT / "deploy/systemd/soc-thief-runner.timer").read_text()
        self.assertIn("OnCalendar=*-*-* 08:20:00 UTC", timer)
        self.assertIn("Unit=soc-thief-runner.service", timer)
        self.assertIn("RandomizedDelaySec=5m", timer)

    def test_reconcile_timer_avoids_the_daily_runner_lock(self):
        timer = (ROOT / "deploy/systemd/soc-thief-reconcile.timer").read_text()
        # The daily runner starts by 08:25 and may hold the state lock for its 1800s unit timeout.
        self.assertIn("OnCalendar=*-*-* 10:30:00 UTC", timer)
        self.assertIn("Unit=soc-thief-reconcile.service", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=5m", timer)

    def test_timer_and_backup_have_safety_contracts(self):
        timer = (ROOT / "deploy/systemd/soc-thief.timer").read_text()
        backup = (ROOT / "deploy/systemd/soc-thief-backup.service").read_text()
        helper = (ROOT / "deploy/bin/soc-thief-backup").read_text()
        self.assertIn("08:00:00 UTC", timer)
        self.assertIn("ConditionPathIsMountPoint=/var/backups/soc-thief", backup)
        self.assertIn("sqlite3", helper)
        self.assertIn("RETENTION_DAYS = 7", helper)
        # StateStore(STATE_PATH) keeps its database inside the configured directory.
        self.assertIn('SOURCE = Path("/var/lib/soc-thief/state/state.sqlite3")', helper)

    def test_status_heartbeat_is_sent_only_after_a_healthy_check(self):
        unit = (ROOT / "deploy/systemd/soc-thief-status.service").read_text()
        timer = (ROOT / "deploy/systemd/soc-thief-status.timer").read_text()
        # The heartbeat is chained with && after the check, which exits 0 only when healthy.
        execs = [line for line in unit.splitlines() if line.startswith("Exec")]
        self.assertEqual(execs, ["ExecStart=/bin/sh -c '/usr/bin/python3 -m soc_thief.status && exec "
                                 "/usr/bin/curl --fail --silent --show-error --max-time 20 "
                                 "--output /dev/null --config %d/status_push'"])
        self.assertNotIn("/api/push", unit)
        self.assertIn("Environment=SOC_THIEF_RUNNER_APPROVAL_FILE=%d/runner_approval\n", unit)
        # A dynamic uid cannot reach systemctl over Ubuntu's dbus-daemon; see deploy/sysusers.d.
        self.assertNotIn("DynamicUser", unit.replace("not DynamicUser", ""))
        sysusers = (ROOT / "deploy/sysusers.d/soc-thief-status.conf").read_text()
        self.assertIn("\nu soc-thief-status - ", sysusers)
        self.assertIn("\nm soc-thief-status systemd-journal\n", sysusers)
        for line in ("User=soc-thief-status", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
                     "ProtectSystem=strict", "RemoveIPC=yes"):
            self.assertIn("\n" + line + "\n", unit)
        self.assertNotIn("discord_webhook_url", unit)
        self.assertIn("Unit=soc-thief-status.service", timer)

    def test_container_is_non_root_and_has_bounded_entrypoint(self):
        containerfile = (ROOT / "Containerfile").read_text()
        self.assertIn("USER 65532:65532", containerfile)
        self.assertIn('ENTRYPOINT ["python", "-m", "soc_thief.verify"]', containerfile)

    def test_final_container_removes_and_checks_shell_tooling(self):
        containerfile = (ROOT / "Containerfile").read_text()
        install = containerfile.index("python -m pip install")
        remove = containerfile.index('RUN ["python", "-c", "import os, pathlib, shutil;')
        verify = containerfile.index('RUN ["python", "-c", "import pathlib;')
        non_root = containerfile.index("USER 65532:65532")
        self.assertLess(install, remove)
        self.assertLess(remove, verify)
        self.assertLess(verify, non_root)
        for forbidden in ("/bin/sh", "/bin/dash", "/bin/bash", "/usr/bin/apt",
                          "/usr/bin/dpkg", "/usr/bin/su", "/usr/local/bin/pip"):
            self.assertIn(forbidden, containerfile)
        self.assertIn("shell or package-management tooling remains", containerfile)
        # RestrictSUIDSGID=yes forbids the ID-mapped copy restoring these bits on a new image.
        strip = containerfile.index("setuid or setgid bits remain")
        self.assertLess(verify, strip)
        self.assertLess(strip, non_root)

    def test_backup_helper_creates_valid_private_copy(self):
        loader = importlib.machinery.SourceFileLoader(
            "backup_helper", str(ROOT / "deploy/bin/soc-thief-backup"))
        spec = importlib.util.spec_from_loader("backup_helper", loader)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "state.sqlite3"
            destination = base / "backups"
            destination.mkdir(mode=0o700)
            with closing(sqlite3.connect(source)) as database:
                database.execute("CREATE TABLE synthetic (value TEXT)")
                database.execute("INSERT INTO synthetic VALUES ('safe')")
            source.chmod(0o600)
            old_source, old_destination = helper.SOURCE, helper.DESTINATION
            helper.SOURCE, helper.DESTINATION = source, destination
            try:
                # Collect earlier tests' garbage first, or its finalisers' warnings land in this
                # block whenever automatic collection has not yet run.
                gc.collect()
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always", ResourceWarning)
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(helper.main(), 0)
                    gc.collect()
                self.assertFalse([item for item in caught if item.category is ResourceWarning])
            finally:
                helper.SOURCE, helper.DESTINATION = old_source, old_destination
            copies = list(destination.glob("state-*.sqlite3"))
            self.assertEqual(len(copies), 1)
            self.assertEqual(copies[0].stat().st_mode & 0o777, 0o600)
            with closing(sqlite3.connect(copies[0])) as database:
                self.assertEqual(database.execute("PRAGMA quick_check").fetchall(), [("ok",)])


if __name__ == "__main__":
    unittest.main()
