#!/usr/bin/env python3
"""Install the original VGen provider and minimal hooks into a Toonflow source checkout."""

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "// VGen integration (installed by VGen integrations/toonflow/install.py)."


def install(root: Path):
    package = json.loads((root / "package.json").read_text())
    if package.get("name") != "toonflow":
        raise ValueError("Target is not a Toonflow-app source checkout")
    updates = {}
    ai_path = root / "src/utils/ai.ts"
    source = ai_path.read_text()
    if 'from "@/utils/vgenRecovery"' not in source:
        source = MARKER + '\nimport { vgenContext } from "@/utils/vgenRecovery";\n' + source
        start = source.index("class AiVideo {")
        before, video = source[:start], source[start:]
        anchor = "this.result = await fn(input);"
        if anchor not in video:
            raise ValueError("Unsupported AiVideo provider interface; no files changed")
        video = video.replace(
            anchor,
            'this.result = await fn(mn.startsWith("vgen:") ? vgenContext(input, taskRecord) : input);',
            1,
        )
        source = before + video
    source = source.replace(
        'import { vgenContext } from "@/utils/vgenRecovery";',
        'import { vgenContext, generateVgenVideo } from "@/utils/vgenRecovery";',
    )
    source = source.replace(
        'this.result = await fn(mn.startsWith("vgen:") ? vgenContext(input, taskRecord) : input);',
        'this.result = mn.startsWith("vgen:") ? await generateVgenVideo(vgenContext(input, taskRecord), { modelName: mn.split(/:(.+)/)[1], ...(fn as any).__vgenModel }) : await fn(input);',
    )
    source = source.replace(
        'this.result = mn.startsWith("vgen:") ? await generateVgenVideo(vgenContext(input, taskRecord), { modelName: mn.split(/:(.+)/)[1] }) : await fn(input);',
        'this.result = mn.startsWith("vgen:") ? await generateVgenVideo(vgenContext(input, taskRecord), { modelName: mn.split(/:(.+)/)[1], ...(fn as any).__vgenModel }) : await fn(input);',
    )
    updates[ai_path] = source
    app_path = root / "src/app.ts"
    source = app_path.read_text()
    if 'import { startVgenRecovery } from "@/utils/vgenRecovery";' not in source:
        anchor = "await router.default(app);"
        if anchor not in source:
            raise ValueError("Unsupported app startup; no files changed")
        source = MARKER + '\nimport { startVgenRecovery } from "@/utils/vgenRecovery";\n' + source
        source = source.replace(anchor, anchor + "\n  startVgenRecovery();", 1)
    updates[app_path] = source
    if "server.listen(port, async () => {" in source:
        updates[app_path] = source.replace(
            "server.listen(port, async () => {",
            'server.listen(port, "127.0.0.1", async () => {',
            1,
        )
    fix_path = root / "src/lib/fixDB.ts"
    source = fix_path.read_text()
    if 'await tempOnsert(vendorData["vgen.ts"]);' not in source:
        anchor = '  const toonflowVer = await u.vendor.getVendor("toonflow").version;'
        if anchor not in source:
            raise ValueError("Unsupported provider initialization; no files changed")
        source = (
            MARKER
            + "\n"
            + source.replace(anchor, '  await tempOnsert(vendorData["vgen.ts"]);\n' + anchor, 1)
        )
    migration = '  await knex("o_vendorConfig").where("id", "vgen").update({ inputValues: "{}" });'
    if migration not in source:
        source = source.replace(
            '  await tempOnsert(vendorData["vgen.ts"]);',
            '  await tempOnsert(vendorData["vgen.ts"]);\n' + migration,
        )
    updates[fix_path] = source
    vendors_path = root / "src/lib/vendor.json"
    vendors = json.loads(vendors_path.read_text())
    vendors["vgen.ts"] = (HERE / "provider.ts").read_text()
    updates[vendors_path] = json.dumps(vendors, ensure_ascii=False, indent=2) + "\n"
    updates[root / "src/utils/vgenLocal.ts"] = (HERE / "vgenLocal.ts").read_text()
    # Refresh the runtime provider as well as the bundled source on reinstall.
    if (root / "data/vendor").is_dir():
        updates[root / "data/vendor/vgen.ts"] = (HERE / "provider.ts").read_text()
    cancel_path = root / "src/routes/production/workbench/cancelVideoGenerate.ts"
    if cancel_path.parent.exists():
        updates[cancel_path] = (HERE / "cancelVideoGenerate.ts").read_text()
    retry_path = root / "src/routes/production/workbench/retryVideoGenerate.ts"
    if retry_path.parent.exists():
        updates[retry_path] = (HERE / "retryVideoGenerate.ts").read_text()
    state_path = root / "src/routes/production/workbench/checkVideoStateList.ts"
    if state_path.exists():
        state_source = state_path.read_text()
        state_source = state_source.replace(
            'select("id", "state", "errorReason", "filePath")',
            'select("id", "state", "errorReason", "filePath", "vgenProgress")',
        )
        if "progress: s.vgenProgress" not in state_source:
            state_source = state_source.replace(
                'src: s.filePath ? await u.oss.getFileUrl(s.filePath) : "",',
                'src: s.filePath ? await u.oss.getFileUrl(s.filePath) : "",\n            progress: s.vgenProgress ? JSON.parse(s.vgenProgress) : null,',
            )
        state_source = state_source.replace(
            '.whereIn("state", ["生成成功", "生成失败"])',
            '.whereIn("state", ["生成中", "生成成功", "生成失败"])',
        )
        updates[state_path] = state_source
    router_path = root / "src/router.ts"
    if router_path.exists():
        router_source = router_path.read_text()
    else:
        router_source = ""
    if router_source and "cancelVideoGenerate" not in router_source:
        router_source = router_source.replace(
            'import route79 from "./routes/production/workbench/checkVideoPrompt";',
            'import route79 from "./routes/production/workbench/checkVideoPrompt";\nimport route170 from "./routes/production/workbench/cancelVideoGenerate";\nimport route171 from "./routes/production/workbench/retryVideoGenerate";',
        )
        router_source = router_source.replace(
            '  app.use("/api/production/workbench/checkVideoPrompt", route79);',
            '  app.use("/api/production/workbench/checkVideoPrompt", route79);\n  app.use("/api/production/workbench/cancelVideoGenerate", route170);\n  app.use("/api/production/workbench/retryVideoGenerate", route171);',
        )
    updates[router_path] = router_source
    updates[root / "src/utils/vgenRecovery.ts"] = (HERE / "vgenRecovery.ts").read_text()
    ignore_path = root / ".gitignore"
    ignored = ignore_path.read_text() if ignore_path.exists() else ""
    if "/data/vgen/" not in ignored.splitlines():
        updates[ignore_path] = (
            ignored.rstrip() + "\n\n# Private VGen tasks and media\n/data/vgen/\n"
        )
    for target, text in updates.items():
        if target.exists() and target.read_text() == text:
            continue
        target.write_text(text)
    print(
        f"VGen integration installed in {root}; start Toonflow and select VGen 本地生成 (no connection settings)."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("toonflow_checkout", type=Path)
    args = parser.parse_args()
    install(args.toonflow_checkout.expanduser().resolve())
