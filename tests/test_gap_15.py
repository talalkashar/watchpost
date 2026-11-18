"""_refusal refuses a suppression that hides confirmed-malicious activity.

A suppression_add that would miss a labeled attack the rule detects today, or
that matches a group key already closed as a true positive, returns the
cannot-be-excepted string. A rule_update that only disables the rule returns
None: that loss is named by _detection_loss and acknowledged at approval.
"""

import unittest

from watchpost import improve

CANNOT = "confirmed-malicious activity cannot be excepted"
ATTACK = "brute_force"


def _suppression(detected, missed, ever_true_positive=0):
    return {
        "before": {"detected": list(detected)},
        "after": {"missed": list(missed)},
        "live_impact": {"ever_true_positive": ever_true_positive},
    }


class RefusalTests(unittest.TestCase):
    def test_suppression_that_misses_a_labeled_attack_cannot_be_excepted(self):
        # Detected today and missed after the exception. A name only in missed was never detected.
        evaluation = _suppression([ATTACK, "baseline"], [ATTACK, "password_spray"])
        self.assertEqual(improve._detection_loss(evaluation), [ATTACK])
        self.assertEqual(
            improve._refusal("suppression_add", evaluation),
            "this exception would make the rule miss a labeled attack it detects today "
            f"({ATTACK}); {CANNOT}",
        )

    def test_suppression_of_a_true_positive_group_key_cannot_be_excepted(self):
        # No labeled loss: the refusal is the group key's true-positive history.
        evaluation = _suppression([ATTACK], [], ever_true_positive=1)
        self.assertEqual(improve._detection_loss(evaluation), [])
        self.assertEqual(
            improve._refusal("suppression_add", evaluation),
            "an alert of this rule with this group key has been closed as a true positive; "
            f"{CANNOT}",
        )

    def test_rule_update_that_only_disables_is_not_refused(self):
        # Disabling moves every labeled detection into missed and adds no ignore entry.
        evaluation = {
            "before": {"detected": [ATTACK], "missed": []},
            "after": {"detected": [], "missed": [ATTACK]},
            "ignore_additions": [],
        }
        self.assertEqual(improve._detection_loss(evaluation), [ATTACK])
        self.assertIsNone(improve._refusal("rule_update", evaluation))
