"""The ATT&CK heat matrix is an SVG image. A visually hidden list names every technique."""

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"


def read(name):
    return (STATIC / name).read_text()


def function_body(source, name):
    match = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", source, re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


class MatrixTextTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.source = read("dashboard.js")

    def call(self, names, expression, payload):
        script = "\n".join(function_body(self.source, name) for name in names) + f"""
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify({expression}));
"""
        out = subprocess.run(
            [self.node, "-e", script], input=json.dumps(payload),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def lines(self, columns):
        return self.call(
            ["coverageLevel", "matrixTextRows", "matrixTextLine"],
            "matrixTextRows(input).map(matrixTextLine)",
            columns)

    def test_each_cell_names_id_tactic_and_evidence_level(self):
        lines = self.lines([
            {"name": "Initial Access", "short": "Init", "cells": [
                {"id": "T1190", "name": "Exploit Public-Facing Application",
                 "covered": False, "level": "mapped", "rules": ["web_scanner"]},
                {"id": "T1078", "covered": True, "level": "validated", "rules": ["success_after_failures"]},
            ]},
            {"name": "Impact", "short": "Impact", "cells": [
                {"id": "T1486", "covered": False, "rules": []},
            ]},
        ])
        self.assertEqual(lines, [
            "T1190, Initial Access, mapped",
            "T1078, Initial Access, validated",
            "T1486, Impact, gap",
        ])

    def test_disabled_stays_disabled_and_an_unleveled_cover_is_validated(self):
        lines = self.lines([
            {"name": "Persistence", "cells": [
                {"id": "T1136.003", "level": "disabled", "covered": False, "rules": ["old_rule"]},
                {"id": "T1059", "covered": True},
            ]},
        ])
        self.assertEqual(lines, [
            "T1136.003, Persistence, disabled",
            "T1059, Persistence, validated",
        ])

    def test_clipped_cells_and_a_second_tactic_stay_in_the_list(self):
        cells = [{"id": f"T100{i}", "level": "validated", "covered": True} for i in range(5)]
        lines = self.lines([
            {"name": "Initial Access", "cells": cells},
            {"name": "Resource Development", "cells": []},
            {"short": "Unmapped", "cells": [{"id": "T9999", "level": "gap", "covered": False}]},
        ])
        self.assertEqual(lines[4], "T1004, Initial Access, validated")
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[-1], "T9999, Unmapped, gap")
        self.assertNotIn("Resource Development", "\n".join(lines))

    def test_a_blank_id_is_skipped(self):
        lines = self.lines([
            {"name": "Discovery", "cells": [
                {"id": "", "level": "gap"},
                {"id": None, "level": "gap"},
                {"level": "gap"},
                {"id": "T1087", "level": "validated", "covered": True},
            ]},
            None,
        ])
        self.assertEqual(lines, ["T1087, Discovery, validated"])

    def test_the_dashboard_mounts_the_list_after_the_svg(self):
        start = self.source.index("renderMatrix()")
        chunk = self.source[start:self.source.index("// --- incident board")]
        ok = chunk[chunk.index('if (cov.state === "ok")'):chunk.index("if (legend) legend.replaceChildren();")]
        self.assertLess(ok.index("mountSvg(box,"), ok.index("mountMatrixText(box, columns)"))
        mount = function_body(self.source, "mountMatrixText")
        self.assertIn('class: "sr-only"', mount)
        self.assertIn('id: "attack-text"', mount)
        self.assertIn("matrixTextLine(row)", mount)
        self.assertIn(".sr-only", read("style.css"))
        pending = chunk[chunk.index("if (legend) legend.replaceChildren();"):]
        self.assertIn("box.replaceChildren(", pending)
        self.assertNotIn("mountMatrixText", pending)


if __name__ == "__main__":
    unittest.main()
