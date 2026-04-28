from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class JSCoverageScanner(Scanner):
    scanner_name = "js_coverage"
    supported_languages = ["javascript", "typescript"]

    def is_available(self) -> bool:
        return shutil.which("node") is not None

    def build_command(self, project_path: Path) -> list[str]:
        script = (
            "const fs=require('fs');"
            "const candidates=['coverage/coverage-summary.json','coverage/summary.json'];"
            "let payload=null;"
            "for (const p of candidates){if (fs.existsSync(p)){payload=JSON.parse(fs.readFileSync(p,'utf8'));break;}}"
            "if(!payload){console.log('{}');process.exit(0);}"
            "console.log(JSON.stringify(payload));"
        )
        return ["node", "-e", script, *self.extra_args]
