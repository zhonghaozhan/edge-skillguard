# Edge Skillguard

Code, policies, workloads and raw results for the paper

> **Auto-Policy, not Auto-Skill: Compiled Agent Skills for the Physical World**
> Zhonghao Zhan and Hamed Haddadi. [arXiv:2608.25091](https://arxiv.org/abs/2608.25091)

Edge Skillguard is a typed invocation policy for agent Skills that drive
physical devices. A policy lists guards that must all hold and deny conditions
that must not match, written with seven operators over the message envelope and
a shared state store. A pure function evaluates it at the message boundary and
fails closed. This repository holds the reference evaluator, the experiment
harnesses, and the raw output of every run reported in version 2 of the paper.

## What is here

| File | Purpose |
| --- | --- |
| `skillguard_ref.py` | policy loader, pure-function evaluator, and the tightening check `is_tightening` (about 160 lines, no dependencies) |
| `policy_unlock_front_door.json` | the worked policy |
| `policies/` | the five policies and their accepting states |
| `workload.py` | the 60 non-authorizing and 60 authorizing requests for `unlock(front_door)` |
| `run_checks.py` | in-process checks: workload, 378,000-state grid, claims in the payload, differential fuzz, type confusion, policy load, policy updates (140 loosenings, 16 tightenings) |
| `mutation_test.py` | eight faulty evaluators, each of which must fail `run_checks.py` |
| `esg_live.py` | guard service and closed-loop load generator for the broker runs; in-process timing |
| `esg_breadth.py` | violation generator driven by operator semantics; in-process and live modes |
| `esg_models.py` | receiver study with local models: three tool-using conditions, the LLM checker, sampling runs (the tools are stubs) |
| `esg_compile.py` | policy compilation by local models behind the admission gate, and policy updates against the tightening check |
| `make_paper_assets.py` | receiver tables, quoted numbers, statistics and both data figures, generated from the raw episodes |
| `nats_test.conf.template` | broker users and publish permissions used for identity attestation |
| `results/` | raw output of all runs reported in the paper |

`results/models/` holds the 9,510 receiver episodes, one JSON object per line,
with the full message and tool-call trace of each episode.

## Reproducing

Python 3.8 or later. The in-process parts need nothing else.

    python3 run_checks.py                 # ~5 s, writes results/in_process_checks.json
    python3 mutation_test.py              # ~45 s
    python3 esg_breadth.py inproc         # <1 s
    python3 esg_live.py inproc            # evaluator timing on this machine

The broker runs need `nats-py` and a NATS server with JetStream. Fill the three
passwords into the template, start `nats-server -c`, and export `ESG_PW_GUARD`,
`ESG_PW_EXP` and `ESG_PW_MGR`:

    python3 esg_live.py guard &
    python3 esg_live.py run --scale 1 --out results/live_local_x1.json
    python3 esg_live.py run --scale 5 --out results/live_local_x5.json
    python3 esg_breadth.py live --out results/breadth_live.json
    # cross-host: run the two `run` commands on another machine with --nats nats://<host>:<port>

The receiver study and the compilation study need a local Ollama server with
`gemma4:31b`, `qwen3.8:27b`, `mistral-small3.2:24b` and `llama3.3:70b`. One model
configuration per call; runs are resumable:

    python3 esg_models.py --model qwen3.8:27b --think off --out results/models/qwen_off.jsonl
    python3 esg_models.py --model qwen3.8:27b --think off --conds judge --out results/models/qwen_off_judge.jsonl
    python3 esg_models.py --model qwen3.8:27b --think off --conds skill_full,judge --claim-only \
        --temperature 0.7 --samples 5 --out results/models/qwen_off_t07.jsonl
    python3 esg_compile.py --out results/compile_study.json
    python3 make_paper_assets.py results/models out/     # needs matplotlib for the figures

## Notes for readers of the results

- **Provenance.** `skillguard_ref.py` is a re-implementation written from the
  paper's specification. Every number in version 2 of the paper comes from the
  runs in `results/`, which use this code. The numbers in version 1 came from
  an earlier implementation that is not part of this repository.
- **Scoring of unlock decisions.** `make_paper_assets.py` counts an unlock call
  written out as JSON in the final message as an unlock decision, because one
  model family often writes its tool call instead of issuing it. The `unlocked`
  field in the episode files is the strict count of issued tool calls, so both
  counts can be recomputed.
- **Compilation study.** The rule lists given to the models are in
  `SKILL_SPECS` in `esg_compile.py`. They name the state fields and the accepted
  values, and in a few places the operator. The admission gate checks the
  schema, the four lease guards, that at least one further guard is present,
  and that the reference accepting state is admitted. It does not check the
  remaining guards; their agreement with the hand-written policies in
  `policies/` is measured afterwards. `results/compile_study.json` records the
  outcome of each task but not the text the models returned.
- **No device is involved.** All broker subjects are under `test.skillguard`,
  the runs stop at a test inbox, and the tools offered to the models are stubs.

## Citation

    @article{zhan2026autopolicy,
      title   = {Auto-Policy, not Auto-Skill: Compiled Agent Skills for the Physical World},
      author  = {Zhan, Zhonghao and Haddadi, Hamed},
      journal = {arXiv preprint arXiv:2608.25091},
      year    = {2026}
    }

## License

MIT. See `LICENSE`.
