"""When the event stream falls back to polling, the feed says how often."""

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


class FeedPollNoteTests(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if self.node is None:
            self.skipTest("node is not installed")
        self.dash = read("dashboard.js")

    def note(self, mode):
        const_line = re.search(r"^const STREAM_POLL_MS = \d+;$", self.dash, re.M)
        self.assertIsNotNone(const_line)
        script = const_line.group(0) + "\n" + function_body(self.dash, "feedPollNote") + """
const input = JSON.parse(require("fs").readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(feedPollNote(input.mode)));
"""
        out = subprocess.run(
            [self.node, "-e", script],
            input=json.dumps({"mode": mode}),
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_polling_names_the_three_second_interval(self):
        self.assertIn("const STREAM_POLL_MS = 3000;", self.dash)
        self.assertEqual(self.note("poll"), "polling every 3s")

    def test_a_live_stream_adds_no_feed_sentence(self):
        for mode in ("live", "reconnecting", "off", "", None, "POLL"):
            with self.subTest(mode=mode):
                self.assertEqual(self.note(mode), "")

    def test_the_feed_shows_the_sentence_and_the_badge_stays_short(self):
        start = self.dash.index('panel("p-feed"')
        header = self.dash[start:self.dash.index("panel(\"p-timeline\"", start)]
        self.assertIn('id: "feed-poll"', header)
        self.assertLess(header.index('id: "feed-poll"'), header.index('id: "feed-rate"'))
        poll = self.dash[self.dash.index("startPolling() {"):self.dash.index("stopPolling() {")]
        self.assertIn("setInterval(poll, STREAM_POLL_MS)", poll)
        self.assertNotIn("setInterval(poll, 3000)", poll)
        mode = self.dash[self.dash.index("setMode(mode) {"):self.dash.index("onEvents(events, count)")]
        self.assertIn('poll: "POLLING 3s"', mode)
        self.assertIn("this.paintFeedPoll()", mode)
        paint = mode[mode.index("paintFeedPoll() {"):]
        self.assertIn("feedPollNote(this.mode)", paint)
        self.assertIn("note.hidden = !text", paint)
        mount = self.dash[self.dash.index("mount() {"):self.dash.index("unmount() {")]
        self.assertLess(mount.index('id: "feed-poll"'), mount.index("Live.paintFeedPoll()"))


if __name__ == "__main__":
    unittest.main()
