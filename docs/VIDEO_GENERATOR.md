# SBP Video Studio

## Purpose

SBP Video Studio is a standalone, general-purpose local video construction
application. The SBP-LEX cockpit is its first integration target, not its scene
model. A project can construct arbitrary environments, primitives, imported
models, text, cameras, lights, shaders, animation, particle effects, overlays,
data graphics, audio timing, and rendered sequences.

The application owns the deterministic project manifest. Blender is a replaceable
render backend, and FFmpeg is an encoding/compositing backend. Neither backend is
the source of project truth.

## Authority boundary

The complete `sbp_video` package is outside the canonical runtime package.

- It does not import `sbp_lex`.
- It accepts detached JSON cockpit snapshots and deep-copies them before use.
- It does not call traversal, governance, admissibility, execution, replay, or
  audit runtime functions.
- It cannot issue a governance decision or execution authorization.
- It cannot mutate canonical runtime state.
- Every manifest and result declares `runtime_authority: "NONE"` and
  `canonical_runtime_mutation: false`.
- `python -m sbp_video boundary-check --repository-root .` statically verifies
  that the video package has not attached to runtime imports or authority names.

This application visualizes supplied observations. Visual appearance, colour,
timing, labels, scenario outcomes, and generated video are presentation content,
not runtime evidence or authority.

## Architecture

```text
UI Cockpit page / Tk editor / CLI / Python API
                |
                v
 Loopback-only companion service
                |
                v
  Confined local project workspace
                |
                v
     Versioned scene manifest
                |
       +--------+---------+
       |                  |
       v                  v
 Scene graph         Asset cache
       |                  |
       +--------+---------+
                |
                v
       Blender scene compiler
                |
         PNG frame sequence
                |
                v
      FFmpeg video/audio export
                |
        MP4 / WebM / MOV

Detached cockpit JSON snapshot
                |
                v
    Read-only cockpit adapter
                |
                v
        Ordinary scene manifest
```

The modules are deliberately small and replaceable:

| Module | Responsibility |
| --- | --- |
| `manifest.py` | Versioned manifest, validation, canonical JSON, SHA-256 identity |
| `editor.py` | Standalone project and scene editor model |
| `desktop.py` | Local Tk desktop editor over the same model |
| `workspace.py` | Confined projects, builds, imports, asset cache, and single render worker |
| `service.py` | Loopback-only JSON service used by the UI Cockpit page |
| `scene_graph.py` | Parent/child graph, cycle checks, deterministic ordering |
| `assets.py` | Content-addressed local import/cache and digest verification |
| `backends/blender.py` | Blender Python scene construction and frame rendering |
| `backends/ffmpeg.py` | Frame encoding, audio delay/gain/loop/mix and muxing |
| `pipeline.py` | Compile/render/export orchestration and render plans |
| `cockpit.py` | Detached snapshot-to-scene adapter for the three cockpit layers |
| `samples.py` | General-purpose and cockpit sample project generation |
| `boundary.py` | Static runtime-isolation check |

The canonical runtime serves only the static editor page at
`/desktop/video-studio`. Scene construction and rendering run in a separate
companion process on `127.0.0.1:8765`; the runtime process never imports
`sbp_video`. The page may read `/desktop/latest` and pass that detached JSON to
the companion. It has no runtime POST path and no execution or governance
control. Browser origins are restricted to loopback addresses.

## Start from Desktop V1

Use the normal Desktop V1 launcher:

```text
scripts\run_desktop_runtime.bat
```

It verifies the release, starts the canonical runtime and the isolated Video
Studio companion, smoke-checks both, and leaves them running. Open the UI Cockpit
at `http://127.0.0.1:8000/dashboard` and select **Video Studio**. The editor lives
inside the normal Cockpit navigation; operators do not need to start it from the
repository command line.

Projects, imported assets, and render builds default to:

```text
%LOCALAPPDATA%\SBP-LEX\VideoStudio
```

`SBP_VIDEO_WORKSPACE`, `SBP_VIDEO_PORT`, `SBP_VIDEO_BLENDER_PATH`,
`SBP_VIDEO_FFMPEG_PATH`, and `SBP_VIDEO_ASSET_CACHE` provide explicit local
configuration overrides. The launcher and companion bind only to loopback.

## Standalone application alternatives

The editor UI uses Python's bundled Tk interface and has no additional Python
package dependency:

```text
python -m sbp_video desktop
python -m sbp_video desktop examples/video_generator/general-orbital.scene.json
```

The desktop application provides:

- project creation, open, save, and save-as;
- a scene/project hierarchy;
- JSON inspectors for the entire project or an individual scene item;
- addition and deletion of objects, text, materials, cameras, lights, particles,
  HUD overlays, and animation tracks;
- timeline track inspection;
- validation and stable manifest digest display;
- local compile, render, tool-status, and sample-generation actions.

The UI Cockpit editor adds a responsive manifest preview, project/scene tree,
timeline/sequencer view, object/material/camera/light/VFX/HUD/animation creation,
content-addressed asset upload, project save/load, compile/render controls, and
the three read-only Cockpit presentation-layer constructors.

The JSON inspector remains available because it exposes the full deterministic
model without hiding backend capabilities behind an incomplete property panel.
A saved or rendered project must pass validation.

## Command-line workflows

Create and validate a project:

```text
python -m sbp_video new my-scene.scene.json --name "My Scene" --duration 12 --fps 30
python -m sbp_video validate my-scene.scene.json
python -m sbp_video inspect my-scene.scene.json
```

Generate the checked-in examples:

```text
python -m sbp_video samples examples/video_generator
```

Compile a manifest without rendering:

```text
python -m sbp_video compile my-scene.scene.json --build-dir runtime_artifacts/my-scene-build
```

The build directory contains:

- `scene.manifest.canonical.json` — exact deterministic scene input;
- `build_scene.py` — generated Blender construction/render program;
- `render-plan.json` — tool commands, paths, output, and source digest;
- `frames/` — populated by Blender during render;
- `output/` — populated by FFmpeg during export.

Render and export when Blender and FFmpeg are available:

```text
python -m sbp_video tools
python -m sbp_video render my-scene.scene.json --build-dir runtime_artifacts/my-scene-build
```

Explicit executable paths can be supplied with `--blender` and `--ffmpeg`.

## Deterministic scene manifest

The schema identifier is `sbp-video-scene/v1`. Its JSON Schema is stored at
`sbp_video/schemas/scene-manifest-v1.schema.json`. Application validation also
checks cross-references, unique identifiers, hierarchy cycles, active camera,
asset and material references, animation targets, keyframe ordering and timing,
audio references, and the authority boundary.

The major manifest sections are:

```json
{
  "schema_version": "sbp-video-scene/v1",
  "project": {"id": "my-scene", "name": "My Scene", "seed": 1},
  "render": {
    "duration_seconds": 12,
    "fps": 30,
    "resolution": {"width": 1920, "height": 1080, "percentage": 100},
    "engine": "BLENDER_EEVEE_NEXT",
    "samples": 64,
    "transparent": false
  },
  "assets": [],
  "scene": {
    "environment": {},
    "materials": [],
    "objects": [],
    "cameras": [],
    "active_camera": null,
    "lights": [],
    "effects": [],
    "overlays": []
  },
  "timeline": {"tracks": [], "markers": []},
  "audio": {"sample_rate": 48000, "tracks": []},
  "output": {},
  "metadata": {
    "runtime_authority": "NONE",
    "canonical_runtime_mutation": false
  }
}
```

Canonical JSON uses sorted keys, UTF-8, no insignificant whitespace, and rejects
non-finite numbers. Its SHA-256 digest is the stable scene identity recorded in
every render plan.

## Construction capabilities

### Objects and scene graph

The model supports primitive cubes, planes, UV spheres, cylinders, cones, and
tori; empty hierarchy nodes; curves; 3D text; and imported model assets. Objects
can be parented, transformed, material-bound, validated, and topologically
ordered. Current Blender import hooks cover `.blend`, `.fbx`, `.glb`, `.gltf`,
`.obj`, `.stl`, and `.ply` files.

### Environment, cameras, lighting, and shaders

Projects declare world colour and strength, active cameras and targets, focal
length, point/sun/spot/area lights, and principled or emission materials. The
manifest keeps these settings backend-neutral enough for another compiler while
the current compiler maps them to Blender nodes and objects.

### Animation and timeline

Tracks target objects, cameras, lights, materials, effects, overlays, or the
environment. Keyframes use seconds and support constant, linear, and Bezier
interpolation declarations. The current Blender compiler implements location,
rotation, scale, visibility, focal length, light energy, text, and material colour
channels. Timeline markers are transferred to Blender.

### Particles, VFX, text, HUD, and data graphics

Particle effects are deterministically seeded and generated as animated Blender
objects for consistent results across supported Blender versions. Fog maps to a
world volume. Glow/trail declarations and curve construction provide extension
points for richer compositing. Text, HUD, and data overlays are camera-attached
emission text that remains separate from scene authority or state.

### Audio synchronization

Audio tracks reference imported assets and declare start time, gain, and looping.
FFmpeg commands apply millisecond delay, volume, optional looping, multi-track
mixing, sample rate, codec, and duration trimming before muxing with the rendered
frames.

## Asset import and cache

Import is local and content-addressed:

```text
python -m sbp_video asset-import music.wav --cache .local-video-assets --kind audio --id music
```

The command returns a manifest-ready record. Files are stored under a SHA-256
cache key, verified after copy, and verified again on resolution. Relative project
asset paths cannot escape the project root. Absolute asset URIs are rejected to
keep manifests portable.

## Cockpit visualization layers

The adapter preserves the three presentation layers exactly:

1. **Slower rehearsal / learning traversal** — deliberately slowed for assessors,
   operators, regulators, deployment enterprises, and similar stakeholders to
   examine and learn the recorded traversal.
2. **Full-speed traversal** — uses recorded elapsed timing when available and
   otherwise uses a compact full-speed presentation cadence.
3. **Constructed scenario** — builds an explicitly hypothetical scenario for
   assessors, regulators, insurers, deployment enterprises, and other relevant
   parties. The video is visibly marked `NOT A RUNTIME DECISION`.

Create cockpit scenes from a detached snapshot:

```text
python -m sbp_video cockpit snapshot.json rehearsal.scene.json --layer rehearsal
python -m sbp_video cockpit snapshot.json full-speed.scene.json --layer full-speed
python -m sbp_video cockpit snapshot.json scenario.scene.json --layer constructed-scenario --scenario scenario.json
```

The source snapshot digest and presentation layer are recorded in manifest
metadata. The adapter verifies that the source mapping remains unchanged.

## Dependencies and verification status

The manifest, editor model, desktop shell, cache, sample generator, compiler, and
tests use the Python standard library. Rendering and encoding are external local
capabilities:

- Blender: required to create `.blend` files and render frame sequences;
- FFmpeg: required to encode/mix/mux MP4, WebM, or MOV output;
- `pytest`: repository development/test dependency already declared in
  `requirements.txt`.

The completed Windows desktop environment was verified with:

- Blender 5.2.0 LTS from `BlenderFoundation.Blender`;
- FFmpeg 9.0 from `Gyan.FFmpeg`;
- Python 3.12 with the declared `requirements.txt` dependencies.

Tool discovery checks explicit arguments, the `SBP_VIDEO_*_PATH` overrides,
`PATH`, packaged tool directories, WinGet links/packages, and standard Windows
install locations. A real 320×180, 12 fps, six-frame scene was rendered by
Blender and encoded as H.264 MP4 by FFmpeg. Blender 5.2 Eevee identifier
compatibility and Blender's zero-exit traceback behaviour are explicitly handled;
the pipeline also refuses encoding unless the expected frames exist.

Focused verification:

```text
python -m compileall -q sbp_video
python -m pytest -p no:cacheprovider -q tests/video
python -m sbp_video boundary-check --repository-root .
python -m sbp_video render examples/video_generator/render-smoke.scene.json --build-dir runtime_artifacts/video_studio_smoke
```

## Next implementation steps

Version 0.2 is integrated and functional. Useful later increments are:

1. add an interactive WebGL 3D viewport and direct manipulation gizmos to the desktop
   editor while keeping the manifest authoritative;
2. extend Blender compilation for image/video planes, texture-node graphs,
   compositing nodes, motion blur, depth of field, richer trails, and simulations;
3. add waveform display, scrubbing, clip trimming, transitions, subtitles, and
   multi-shot nonlinear sequencing;
4. add optional prompt-to-manifest construction behind the same validator, with
   no direct runtime or backend authority;
5. retain visual golden frames for the larger general and Cockpit sample scenes.
