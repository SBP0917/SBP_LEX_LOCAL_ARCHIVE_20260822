# Video Studio Desktop V1 Integration Report

Date: 2026-08-10  
Application: SBP Video Studio 0.2  
Integration target: SBP-LEX Dual V6 Desktop V1 UI Cockpit

## Outcome

The previously stashed general-purpose Video Studio foundation has been recovered,
hardened, and integrated into the normal Desktop V1 UI Cockpit. It is not limited
to Cockpit animations: its deterministic manifest and editor construct arbitrary
objects, environments, scene graphs, materials, cameras, lights, animation,
particles/VFX, text/HUD/data graphics, audio timing hooks, imported assets, and
render/export jobs.

The canonical runtime serves the editor page and a **Video Studio** Cockpit
navigation control. Scene operations run in a separate loopback-only companion
process. The normal `scripts\run_desktop_runtime.bat` launcher manages and
smoke-checks both processes.

## Runtime isolation

- `sbp_video` imports no `sbp_lex` module.
- The companion binds only to loopback and accepts browser origins only from
  loopback hosts.
- Projects, builds, imports, and cached assets are confined to the Video Studio
  workspace.
- Cockpit integration reads `/desktop/latest` and passes a detached JSON copy to
  the adapter.
- The editor exposes no traversal, replay, governance, or execution POST path.
- Every manifest/service result declares `runtime_authority: "NONE"` and
  `canonical_runtime_mutation: false`.

The preserved Cockpit presentation layers are:

1. Slower rehearsal / learning traversal for assessors, operators, regulators,
   deployment enterprise, and similar stakeholders.
2. Full-speed traversal using recorded timing where available.
3. Constructed scenario mode for assessors, regulators, insurers, deployment
   enterprise, and other relevant parties, visibly marked non-authoritative.

## Installed and verified dependencies

- Blender 5.2.0 LTS (`BlenderFoundation.Blender`)
- FFmpeg 9.0 (`Gyan.FFmpeg`)
- Python 3.12.10 normal launcher environment
- `pytest` 9.1.1, `cryptography` 50.0.0, and `packaging` 26.3 from the declared
  Desktop V1 requirements

Discovery supports explicit executable arguments, environment overrides, PATH,
packaged tool directories, WinGet links/packages, and standard Windows install
locations.

## Verification completed

- Python syntax compilation: passed.
- Video package runtime-boundary scan: `VIDEO_BOUNDARY_OK`, zero findings.
- Focused Video Studio/Desktop UI suite: 43 passed.
- Adjacent Video Studio, Desktop, API security, and measured-startup suite:
  106 passed.
- In-app browser verification: service/tool status, project creation, scene-tree
  editing, material/object/camera/light/VFX/HUD/animation construction,
  deterministic validation, save, full-speed adapter, constructed-scenario
  adapter, and Blender compile all passed.
- Real backend render: Blender emitted six PNG frames at 320 x 180 and 12 fps;
  FFmpeg encoded H.264 MP4, duration 0.5 seconds, with six frames.

Actual Blender testing identified and closed two backend defects: Blender 5.2's
Eevee engine identifier change and Blender returning exit code zero after a
Python traceback. The backend now maps supported Eevee identifiers, detects
tracebacks, and refuses encoding when no expected frame sequence exists.

## Operator activation boundary

Pass 9 intentionally fails closed when the owner-authorised ML-DSA signing seed,
public trust anchor, fingerprint, migration approval, key lifecycle, and
revocation registry are absent. No secret was generated, embedded, logged, or
weakened for this integration. A temporary isolated test-trust baseline was used
only for browser route verification.

Normal canonical runtime activation therefore remains subject to the existing
owner-secure provisioning and trust-refresh runbook. This is a pre-existing
Pass 9 operator-authority gate, not Video Studio authority and not a reason to
attach Video Studio to the runtime control path.

## Later enhancements

The completed 0.2 integration is usable. Later product increments may add a
WebGL viewport and gizmos, richer Blender node/compositing support, waveform and
multi-shot editing, and an optional prompt-to-manifest constructor behind the
same deterministic validator.
