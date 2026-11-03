ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.revision=${SOURCE_COMMIT}

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && addgroup --system --gid 65532 soc-thief \
    && adduser --system --uid 65532 --ingroup soc-thief --no-create-home soc-thief

# The Python base is retained for TLS and timezone support, but its interactive
# administration surface is not part of the runtime. Use exec-form RUN after
# this point: /bin/sh is deliberately absent from the resulting image.
RUN ["python", "-c", "import os, pathlib, shutil; targets=('/bin/sh','/bin/dash','/bin/bash','/usr/bin/sh','/usr/bin/dash','/usr/bin/bash','/usr/bin/apt','/usr/bin/apt-get','/usr/bin/apt-cache','/usr/bin/dpkg','/usr/bin/dpkg-deb','/usr/bin/su','/usr/bin/runuser','/usr/bin/login','/usr/local/bin/pip','/usr/local/bin/pip3','/usr/local/bin/pip3.12'); [(pathlib.Path(p).unlink()) for p in targets if pathlib.Path(p).is_file() or pathlib.Path(p).is_symlink()]; shutil.rmtree('/usr/local/lib/python3.12/site-packages/pip', ignore_errors=True); shutil.rmtree('/usr/local/lib/python3.12/site-packages/pip-24.0.dist-info', ignore_errors=True)"]
RUN ["python", "-c", "import pathlib; targets=('/bin/sh','/bin/dash','/bin/bash','/usr/bin/sh','/usr/bin/dash','/usr/bin/bash','/usr/bin/apt','/usr/bin/apt-get','/usr/bin/apt-cache','/usr/bin/dpkg','/usr/bin/dpkg-deb','/usr/bin/su','/usr/bin/runuser','/usr/bin/login','/usr/local/bin/pip','/usr/local/bin/pip3','/usr/local/bin/pip3.12','/usr/local/lib/python3.12/site-packages/pip'); remaining=[p for p in targets if pathlib.Path(p).exists() or pathlib.Path(p).is_symlink()]; remaining and (_ for _ in ()).throw(RuntimeError('shell or package-management tooling remains'))"]

# No setuid or setgid bit anywhere. The runtime is a fixed non-root user with no privilege
# escalation, so nothing needs one, and rootless Podman's first ID-mapped copy of a new image
# must restore such bits - which RestrictSUIDSGID=yes in every unit forbids (measured:
# the first run after a rebuild failed on usr/bin/chage).
RUN ["python", "-c", "import os, stat\nskip = ('/proc', '/sys', '/dev')\ndef walk():\n    for root, dirs, files in os.walk('/'):\n        dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip]\n        for name in dirs + files:\n            path = os.path.join(root, name); mode = os.lstat(path).st_mode\n            if not stat.S_ISLNK(mode) and mode & 0o6000: yield path, mode\nfor path, mode in list(walk()): os.chmod(path, stat.S_IMODE(mode) & ~0o6000)\nif list(walk()): raise RuntimeError('setuid or setgid bits remain')\n"]

USER 65532:65532
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "soc_thief.verify"]
