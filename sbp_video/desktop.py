from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import threading
from typing import Any

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from sbp_video.editor import transform
from sbp_video.manifest import SceneManifest, default_manifest, validate_manifest
from sbp_video.pipeline import VideoPipeline
from sbp_video.samples import write_samples


SCENE_COLLECTIONS = ("materials", "objects", "cameras", "lights", "effects", "overlays")


class VideoStudioDesktop(tk.Tk):
    """Dependency-free local desktop shell over the deterministic editor model."""

    def __init__(self, manifest_path: str | Path | None = None) -> None:
        super().__init__()
        self.title("SBP Video Studio — Local Scene Editor")
        self.geometry("1440x900")
        self.minsize(1000, 650)
        self._path: Path | None = None
        self._data = default_manifest("Untitled Scene")
        self._tree_targets: dict[str, tuple[str, str | int | None]] = {}
        self._build_ui()
        if manifest_path is not None:
            self.open_path(Path(manifest_path))
        else:
            self._refresh_tree()
            self._show_manifest()

    def _build_ui(self) -> None:
        self.option_add("*tearOff", False)
        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.pack(fill=tk.X)
        for label, command in (
            ("New", self.new_project),
            ("Open", self.open_project),
            ("Save", self.save_project),
            ("Save As", self.save_project_as),
            ("Validate", self.validate_project),
            ("Compile", self.compile_project),
            ("Render", self.render_project),
            ("Samples", self.generate_samples),
            ("Tools", self.show_tools),
        ):
            ttk.Button(toolbar, text=label, command=command).pack(side=tk.LEFT, padx=2)
        ttk.Label(toolbar, text="  Add:").pack(side=tk.LEFT)
        self.add_kind = tk.StringVar(value="primitive object")
        ttk.Combobox(
            toolbar,
            textvariable=self.add_kind,
            state="readonly",
            width=18,
            values=("primitive object", "text object", "material", "camera", "light", "particle effect", "HUD overlay", "animation track"),
        ).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="Add", command=self.add_item).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Delete", command=self.delete_item).pack(side=tk.LEFT, padx=2)

        panes = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        hierarchy_frame = ttk.Labelframe(panes, text="Project / Scene Graph", padding=6)
        inspector_frame = ttk.Labelframe(panes, text="JSON Inspector", padding=6)
        panes.add(hierarchy_frame, weight=1)
        panes.add(inspector_frame, weight=3)

        self.tree = ttk.Treeview(hierarchy_frame, show="tree", selectmode="browse")
        tree_scroll = ttk.Scrollbar(hierarchy_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        inspector_toolbar = ttk.Frame(inspector_frame)
        inspector_toolbar.pack(fill=tk.X, pady=(0, 4))
        self.selection_label = tk.StringVar(value="Complete manifest")
        ttk.Label(inspector_toolbar, textvariable=self.selection_label).pack(side=tk.LEFT)
        ttk.Button(inspector_toolbar, text="Apply JSON", command=self.apply_json).pack(side=tk.RIGHT)
        ttk.Button(inspector_toolbar, text="Show Manifest", command=self._show_manifest).pack(side=tk.RIGHT, padx=4)

        text_frame = ttk.Frame(inspector_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.inspector = tk.Text(text_frame, wrap=tk.NONE, undo=True, font=("Consolas", 10))
        y_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.inspector.yview)
        x_scroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self.inspector.xview)
        self.inspector.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.inspector.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        lower = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        lower.pack(fill=tk.X, padx=8, pady=(0, 6))
        timeline_frame = ttk.Labelframe(lower, text="Timeline", padding=6)
        log_frame = ttk.Labelframe(lower, text="Local Build / Render Status", padding=6)
        lower.add(timeline_frame, weight=2)
        lower.add(log_frame, weight=3)
        self.timeline = ttk.Treeview(timeline_frame, columns=("target", "property", "keys"), show="headings", height=7)
        for key, label, width in (("target", "Target", 180), ("property", "Property", 140), ("keys", "Keyframes", 80)):
            self.timeline.heading(key, text=label)
            self.timeline.column(key, width=width, stretch=True)
        self.timeline.pack(fill=tk.BOTH, expand=True)
        self.log = tk.Text(log_frame, height=7, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 9))
        self.log.pack(fill=tk.BOTH, expand=True)
        self.status = tk.StringVar(value="Ready — runtime authority: NONE")
        ttk.Label(self, textvariable=self.status, anchor=tk.W, padding=(8, 2)).pack(fill=tk.X)

    def _log(self, message: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, message.rstrip() + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)
        self.status.set(message.splitlines()[0] if message else "Ready")

    def _next_id(self, prefix: str) -> str:
        used: set[str] = set()
        for collection in self._data["scene"].values():
            if isinstance(collection, list):
                used.update(str(item.get("id")) for item in collection if isinstance(item, dict))
        used.update(str(item.get("id")) for item in self._data["timeline"]["tracks"])
        index = 1
        while f"{prefix}-{index:02d}" in used:
            index += 1
        return f"{prefix}-{index:02d}"

    def _refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._tree_targets.clear()
        root = self.tree.insert("", tk.END, iid="manifest", text=self._data["project"]["name"], open=True)
        self._tree_targets[root] = ("manifest", None)
        for key in ("project", "render", "assets"):
            category = self.tree.insert(root, tk.END, text=key.replace("_", " ").title(), open=True)
            self._tree_targets[category] = (key, None)
            if key == "assets":
                for index, item in enumerate(self._data["assets"]):
                    child = self.tree.insert(category, tk.END, text=str(item.get("id", f"asset {index + 1}")))
                    self._tree_targets[child] = ("assets", index)
        environment = self.tree.insert(root, tk.END, text="Environment")
        self._tree_targets[environment] = ("environment", None)
        for collection in SCENE_COLLECTIONS:
            category = self.tree.insert(root, tk.END, text=collection.title(), open=True)
            self._tree_targets[category] = (collection, None)
            for index, item in enumerate(self._data["scene"][collection]):
                label = str(item.get("id", f"{collection} {index + 1}"))
                child = self.tree.insert(category, tk.END, text=label)
                self._tree_targets[child] = (collection, index)
        timeline = self.tree.insert(root, tk.END, text="Timeline", open=True)
        self._tree_targets[timeline] = ("timeline", None)
        for index, item in enumerate(self._data["timeline"]["tracks"]):
            child = self.tree.insert(timeline, tk.END, text=str(item.get("id", f"track {index + 1}")))
            self._tree_targets[child] = ("tracks", index)
        for key in ("audio", "output", "metadata"):
            child = self.tree.insert(root, tk.END, text=key.title())
            self._tree_targets[child] = (key, None)
        self._refresh_timeline()

    def _refresh_timeline(self) -> None:
        self.timeline.delete(*self.timeline.get_children())
        for track in self._data["timeline"]["tracks"]:
            self.timeline.insert("", tk.END, values=(track.get("target"), track.get("property"), len(track.get("keyframes", []))))

    def _target_value(self, target: tuple[str, str | int | None]) -> Any:
        collection, index = target
        if collection == "manifest":
            return self._data
        if collection in SCENE_COLLECTIONS:
            value = self._data["scene"][collection]
            return value if index is None else value[int(index)]
        if collection == "environment":
            return self._data["scene"]["environment"]
        if collection == "assets":
            return self._data["assets"] if index is None else self._data["assets"][int(index)]
        if collection == "tracks":
            return self._data["timeline"]["tracks"][int(index)]
        return self._data[collection]

    def _replace_target(self, target: tuple[str, str | int | None], value: Any) -> None:
        collection, index = target
        if collection == "manifest":
            if not isinstance(value, dict):
                raise ValueError("complete manifest must be a JSON object")
            self._data = value
        elif collection in SCENE_COLLECTIONS:
            if index is None:
                self._data["scene"][collection] = value
            else:
                self._data["scene"][collection][int(index)] = value
        elif collection == "environment":
            self._data["scene"]["environment"] = value
        elif collection == "assets":
            if index is None:
                self._data["assets"] = value
            else:
                self._data["assets"][int(index)] = value
        elif collection == "tracks":
            self._data["timeline"]["tracks"][int(index)] = value
        else:
            self._data[collection] = value

    def _display_json(self, value: Any, label: str) -> None:
        self.selection_label.set(label)
        self.inspector.delete("1.0", tk.END)
        self.inspector.insert("1.0", json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))

    def _show_manifest(self) -> None:
        self.tree.selection_set("manifest") if self.tree.exists("manifest") else None
        self._display_json(self._data, "Complete manifest")

    def _on_select(self, _event: object = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        target = self._tree_targets[item]
        self._display_json(self._target_value(target), self.tree.item(item, "text"))

    def apply_json(self) -> None:
        selection = self.tree.selection()
        target = self._tree_targets.get(selection[0], ("manifest", None)) if selection else ("manifest", None)
        try:
            value = json.loads(self.inspector.get("1.0", tk.END))
            candidate = deepcopy(self._data)
            current = self._data
            self._data = candidate
            try:
                self._replace_target(target, value)
            except Exception:
                self._data = current
                raise
            self._refresh_tree()
            self._log("JSON applied. Validate before rendering.")
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            messagebox.showerror("Invalid JSON", str(error), parent=self)

    def new_project(self) -> None:
        name = simpledialog.askstring("New project", "Project name:", initialvalue="Untitled Scene", parent=self)
        if name is None:
            return
        self._data = default_manifest(name)
        self._path = None
        self._refresh_tree()
        self._show_manifest()
        self._log("Created a new local scene project.")

    def open_path(self, path: Path) -> None:
        manifest = SceneManifest.load(path)
        self._data = manifest.to_dict()
        self._path = path.resolve()
        self._refresh_tree()
        self._show_manifest()
        self._log(f"Opened {self._path}")

    def open_project(self) -> None:
        path = filedialog.askopenfilename(parent=self, filetypes=(("Scene manifests", "*.json"), ("All files", "*.*")))
        if not path:
            return
        try:
            self.open_path(Path(path))
        except (OSError, ValueError) as error:
            messagebox.showerror("Open failed", str(error), parent=self)

    def _save_to(self, path: Path) -> None:
        manifest = SceneManifest.from_dict(self._data)
        manifest.save(path)
        self._path = path.resolve()
        self._log(f"Saved valid scene {self._path}\nDigest: {manifest.digest}")

    def save_project(self) -> None:
        if self._path is None:
            self.save_project_as()
            return
        try:
            self._save_to(self._path)
        except (OSError, ValueError) as error:
            messagebox.showerror("Save blocked", str(error), parent=self)

    def save_project_as(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".scene.json", filetypes=(("Scene manifests", "*.scene.json"), ("JSON", "*.json")))
        if not path:
            return
        try:
            self._save_to(Path(path))
        except (OSError, ValueError) as error:
            messagebox.showerror("Save blocked", str(error), parent=self)

    def validate_project(self) -> bool:
        errors = validate_manifest(self._data)
        if errors:
            self._log("Validation failed:\n- " + "\n- ".join(errors))
            messagebox.showwarning("Scene is not valid", "\n".join(errors[:20]), parent=self)
            return False
        manifest = SceneManifest.from_dict(self._data)
        self._log(f"Scene is valid.\nDigest: {manifest.digest}\nRuntime authority: NONE")
        return True

    def add_item(self) -> None:
        kind = self.add_kind.get()
        if kind == "primitive object":
            target = "objects"
            item = {"id": self._next_id("object"), "type": "primitive", "primitive": "cube", "transform": transform()}
        elif kind == "text object":
            target = "objects"
            item = {"id": self._next_id("text"), "type": "text", "text": "New text", "transform": transform()}
        elif kind == "material":
            target = "materials"
            item = {"id": self._next_id("material"), "shader": {"type": "principled", "base_color": [0.3, 0.5, 0.8, 1], "metallic": 0, "roughness": 0.5}}
        elif kind == "camera":
            target = "cameras"
            item = {"id": self._next_id("camera"), "transform": transform([0, -8, 4]), "focal_length": 50}
            if self._data["scene"]["active_camera"] is None:
                self._data["scene"]["active_camera"] = item["id"]
        elif kind == "light":
            target = "lights"
            item = {"id": self._next_id("light"), "type": "area", "transform": transform([0, -3, 5]), "color": [1, 1, 1], "energy": 1000, "size": 5}
        elif kind == "particle effect":
            target = "effects"
            item = {"id": self._next_id("particles"), "type": "particles", "count": 32, "seed": 1, "start": 0, "end": self._data["render"]["duration_seconds"], "speed": 1, "spread": 1, "size": 0.03}
        elif kind == "HUD overlay":
            target = "overlays"
            item = {"id": self._next_id("hud"), "type": "hud", "content": "New HUD label", "position": [0.05, 0.9], "font_size": 0.25}
        else:
            target = "tracks"
            objects = self._data["scene"]["objects"]
            if not objects:
                messagebox.showinfo("Add an object first", "An animation track needs an existing target object.", parent=self)
                return
            item = {"id": self._next_id("track"), "target": f"object:{objects[0]['id']}", "property": "location", "keyframes": [{"time": 0, "value": [0, 0, 0]}, {"time": self._data["render"]["duration_seconds"], "value": [1, 0, 0]}]}
        if target == "tracks":
            self._data["timeline"]["tracks"].append(item)
        else:
            self._data["scene"][target].append(item)
        self._refresh_tree()
        self._log(f"Added {kind}. Edit its complete properties in the JSON inspector.")

    def delete_item(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        target = self._tree_targets[selection[0]]
        collection, index = target
        if index is None:
            messagebox.showinfo("Select an item", "Select a specific object, camera, light, effect, overlay, asset, or track.", parent=self)
            return
        if not messagebox.askyesno("Delete item", f"Delete {self.tree.item(selection[0], 'text')}?", parent=self):
            return
        if collection in SCENE_COLLECTIONS:
            removed = self._data["scene"][collection].pop(int(index))
            if collection == "cameras" and self._data["scene"]["active_camera"] == removed.get("id"):
                cameras = self._data["scene"]["cameras"]
                self._data["scene"]["active_camera"] = cameras[0]["id"] if cameras else None
        elif collection == "assets":
            self._data["assets"].pop(int(index))
        elif collection == "tracks":
            self._data["timeline"]["tracks"].pop(int(index))
        self._refresh_tree()
        self._log("Item deleted. References are not silently rewritten; run Validate.")

    def _ensure_saved_manifest(self) -> SceneManifest | None:
        if not self.validate_project():
            return None
        return SceneManifest.from_dict(self._data)

    def compile_project(self) -> None:
        manifest = self._ensure_saved_manifest()
        if manifest is None:
            return
        directory = filedialog.askdirectory(parent=self, title="Choose local build directory")
        if not directory:
            return
        try:
            plan = VideoPipeline(project_root=self._path.parent if self._path else Path.cwd()).compile(manifest, directory)
            self._log(f"Scene compiled.\nBlender program: {plan.blender_script}\nRender plan: {Path(plan.build_directory) / 'render-plan.json'}")
        except (OSError, ValueError) as error:
            messagebox.showerror("Compile failed", str(error), parent=self)

    def render_project(self) -> None:
        manifest = self._ensure_saved_manifest()
        if manifest is None:
            return
        directory = filedialog.askdirectory(parent=self, title="Choose local render build directory")
        if not directory:
            return
        pipeline = VideoPipeline(project_root=self._path.parent if self._path else Path.cwd())
        status = pipeline.tool_status()["tools"]
        unavailable = [name for name, info in status.items() if not info["available"]]
        if unavailable:
            messagebox.showerror("Render tools unavailable", "Install or configure: " + ", ".join(unavailable) + ". You can still Compile a portable Blender build program.", parent=self)
            return
        self._log("Rendering locally in the background…")

        def run() -> None:
            try:
                result = pipeline.render(manifest, directory)
                self.after(0, lambda: self._log(f"Render complete.\nOutput: {result.output_file}"))
            except Exception as error:  # display backend process errors in the UI
                self.after(0, lambda: messagebox.showerror("Render failed", str(error), parent=self))

        threading.Thread(target=run, daemon=True).start()

    def show_tools(self) -> None:
        status = VideoPipeline().tool_status()
        self._log(json.dumps(status, indent=2, sort_keys=True))

    def generate_samples(self) -> None:
        directory = filedialog.askdirectory(parent=self, title="Choose sample project directory")
        if not directory:
            return
        try:
            files = write_samples(directory)
            self._log("Generated sample scenes:\n" + "\n".join(files.values()))
        except (OSError, ValueError) as error:
            messagebox.showerror("Sample generation failed", str(error), parent=self)


def launch(manifest_path: str | Path | None = None) -> int:
    app = VideoStudioDesktop(manifest_path)
    app.mainloop()
    return 0
