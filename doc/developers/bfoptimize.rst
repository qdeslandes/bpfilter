bfoptimize
==========

``tools/bfoptimize`` is a self-iterating tool that asks Claude to propose
optimizations to the BPF bytecode generator in ``src/libbpfilter/cgen/``,
applies each proposal in an isolated git worktree, builds and tests it, then
benchmarks the result against the current baseline. Improvements are kept and
become the new baseline; regressions and broken builds are discarded. The
loop runs headlessly from the CLI, or behind a local web UI when invoked with
``--serve``.

Architecture of one iteration
-----------------------------

1. **Proposal** — every ``.c``/``.h`` file under
   ``src/libbpfilter/cgen/`` is concatenated and passed to the model along
   with a summary of previous attempts. The model returns one specific,
   actionable optimization plan.
2. **Worktree** — a detached git worktree is created at the baseline SHA
   under ``{cache_dir}/worktrees/attempt-N``. Failures and signal handling
   never dirty the parent checkout.
3. **Apply, build, test** — the agent SDK runs inside the worktree with
   permission to read, edit, write, and run shell commands. It is
   constrained to modify files under ``src/libbpfilter/cgen/`` and is
   instructed to commit on green tests or to revert and exit otherwise.
4. **Benchmark gate** — when the worktree HEAD has advanced, the commit is
   anchored under ``refs/bfoptimize/<id>`` so destroying the worktree
   cannot orphan it. ``bfbencher.compare()`` then runs the benchmark
   suite against both the baseline and the new commit, returning per-
   benchmark deltas. A baseline-runtime-weighted mean decides keep vs.
   discard:

   * negative weighted delta (faster) → ``status='kept'``,
     ``baseline_sha`` advances;
   * non-negative → ``status='rejected_benchmark'``.

5. **Cleanup** — the worktree is destroyed regardless of outcome.

Prerequisites
-------------

* ``ANTHROPIC_API_KEY`` must be set in the environment. ``bfoptimize`` calls
  the Anthropic API for the planning step and shells out to the Claude
  Agent SDK for the apply step; both authenticate via this key.
* Python dependencies, installable with:

  .. code-block:: shell

      pip install -r tools/bfoptimize.requirements.txt

  ``--dry-run`` parses the CLI and reads history without requiring these
  dependencies, so it is safe to use on an unprovisioned host.
* Benchmarks must build (they do unconditionally after the move to
  ``tests/benchmarks/``). The bytecode benchmark binary requires root to
  attach BPF programs; ``bfbencher`` handles privilege escalation in its
  own process.

CLI reference
-------------

.. code-block:: shell

    tools/bfoptimize [--iterations N] [--sources DIR] [--build-dir DIR] \
                     [--cache-dir DIR] [--model ID] [--effort low|medium|high] \
                     [--hint TEXT] [--propose-only] [--dry-run] \
                     [--serve [--port PORT]]

* ``--iterations`` (default ``10``) — number of optimization attempts.
* ``--sources`` (default ``.``) — path to the bpfilter source checkout.
* ``--build-dir`` (default ``build``) — cmake build directory.
* ``--cache-dir`` (default ``.cache/bfoptimize``) — state and worktree
  scratch directory.
* ``--model`` (default ``claude-opus-4-7``) — Anthropic model id used for
  both planning and execution.
* ``--effort`` (default ``high``) — maps to a thinking-token budget:
  ``low`` = 4k, ``medium`` = 16k, ``high`` = 32k.
* ``--hint`` — optional free-text steer passed to the planning prompt.
* ``--propose-only`` — write the first proposal to history and stop.
  Useful for inspecting model output without spending time on apply or
  benchmark steps.
* ``--dry-run`` — parse arguments, load history, print state, exit.
* ``--serve``, ``--port`` — see below.

Web UI (``--serve``)
--------------------

``tools/bfoptimize --serve --port 8080`` starts an HTTP server bound to
``0.0.0.0`` so it is reachable from any interface on the host. The same
process drives the optimization loop in a daemon thread when triggered
through the UI. Endpoints:

* ``GET /`` — the index page with a settings form, the attempts table,
  and a live log pane.
* ``GET /api/history`` — current ``history.json`` contents.
* ``GET /api/state`` — ``{"running": bool}``.
* ``POST /api/run`` — JSON body mirroring the CLI flags
  (``iterations``, ``model``, ``effort``, ``hint``, ...). Returns
  ``202`` on success, ``409`` if a run is already in progress.
* ``DELETE /api/run`` — sets the cancellation flag. The loop exits at the
  next iteration boundary with worktree cleanup intact.
* ``GET /api/stream`` — Server-Sent Events. Every ``console.log()`` call
  in the run thread is mirrored to a shared buffer and streamed to all
  connected clients with at most ~500ms latency.

The UI is single-user and has no authentication. Since it binds to
``0.0.0.0``, any host on the local network can reach it and trigger
runs — confine access at the firewall layer if that matters.

How attempts are scored
-----------------------

The fitness signal is provided by
``tests/benchmarks/bfbencher.compare(base, ref)`` (see
:doc:`tests`). It returns one ``CompareRow`` per benchmark with
``delta_time_pct`` and ``delta_insn`` fields. ``bfoptimize`` reduces these
to a single number:

.. code-block:: python

    weighted_delta = sum(r.delta_time_pct * r.base_time_ns for r in rows) \
                     / sum(r.base_time_ns for r in rows)

The weighting deliberately favours slow benchmarks: a 10% regression on a
microsecond-scale workload outweighs a 10% improvement on a 100ns
workload, matching the project's goal of squeezing the hot per-packet
path.

State and inspection
--------------------

All state lives under ``--cache-dir`` (default ``.cache/bfoptimize/``):

* ``history.json`` — the persistent record of attempts. Each attempt has
  ``id``, ``status`` (``proposed``, ``rejected_tests``, ``applied``,
  ``kept``, ``rejected_benchmark``), ``description``, ``plan``,
  ``baseline_sha``, ``worktree_sha``, and ``delta_time_pct``.
* ``worktrees/attempt-N/`` — created and destroyed per attempt.
* ``bfbencher/`` — the diskcache directory ``bfbencher`` uses to memoise
  per-commit benchmark results.

Every commit produced by the agent (kept or rejected) is anchored under
``refs/bfoptimize/<id>``. To inspect them:

.. code-block:: shell

    git for-each-ref refs/bfoptimize/
    git show refs/bfoptimize/3            # inspect attempt #3
    git diff refs/bfoptimize/3^..refs/bfoptimize/3

The optimizer does **not** advance ``feature/optimizer`` (or any other
branch) automatically. To incorporate a chain of accepted optimizations,
fast-forward your branch to the current baseline:

.. code-block:: shell

    git merge --ff-only $(jq -r .baseline_sha .cache/bfoptimize/history.json)
