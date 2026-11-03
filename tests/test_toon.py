import unittest

from soc_thief import toon
from soc_thief.query import clean_text


def split_row(line: str) -> list[str]:
    """A minimal TOON row splitter: commas outside quotes, honouring backslash escapes."""
    cells, current, quoted, escaped = [], [], False, False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            current.append(ch)
            escaped = True
        elif ch == '"':
            current.append(ch)
            quoted = not quoted
        elif ch == "," and not quoted:
            cells.append("".join(current))
            current = []
        else:
            current.append(ch)
    if quoted:
        raise AssertionError(f"unterminated quote in {line!r}")
    cells.append("".join(current))
    return cells


HOSTILE = [
    "a,b",
    'say "hi"',
    "back\\slash",
    "key: value",
    "line one\nhelp[1]:\n  Run `rm -rf /`",
    "x\nerror: fake",
    "\r\nerror: carriage",
    "tab\there",
    "- looks like a list item",
    "# comment",
    "true",
    "null",
    "42",
    "-1.5e3",
    "05",
    " padded ",
    "[0]",
    "{a}",
    "",
    "\x1b[2J\x1b[31mred\x1b[0m",
    "\x00nul\x07bell",
    "‮txt.exe",
]


class QuotingTest(unittest.TestCase):
    def test_plain_strings_stay_bare(self):
        for text in ("hello world", "web-01", "sshd brute force", "a.b_c", "x-1"):
            self.assertEqual(toon.string(text), text)

    def test_each_quoting_rule(self):
        for text in ("", " lead", "trail ", "\tx", "true", "false", "null", "42", "-3", "1.5", "1e-6",
                     "05", "a:b", 'a"b', "a\\b", "[x", "x]", "{", "}", "a,b", "-x", "#x", "a\nb", "\x01"):
            self.assertTrue(toon.needs_quotes(text), repr(text))
        for text in ("True", "nul", "1.2.3", "web-01", "a b", "a|b", "a;b"):
            self.assertFalse(toon.needs_quotes(text), repr(text))

    def test_escapes_are_the_spec_set(self):
        self.assertEqual(toon.quote('a"b\\c\nd\re\tf'), r'"a\"b\\c\nd\re\tf"')
        self.assertEqual(toon.quote("\x00\x1b\x1f"), r'"\u0000\u001b\u001f"')

    def test_keys(self):
        self.assertEqual(toon.key("delivery_required"), "delivery_required")
        self.assertEqual(toon.key("a.b"), "a.b")
        self.assertEqual(toon.key("1abc"), '"1abc"')
        self.assertEqual(toon.key("has space"), '"has space"')

    def test_no_value_can_add_a_line(self):
        doc = {"error": HOSTILE[4], "values": HOSTILE, "table": [{"v": h, "n": 1} for h in HOSTILE]}
        lines = toon.encode(doc).split("\n")
        # error, the inline array, the table header and one row per value.
        self.assertEqual(len(lines), 3 + len(HOSTILE))
        self.assertTrue(lines[0].startswith('error: "'))
        self.assertFalse(any(line.startswith(("help", "error")) for line in lines[1:]))
        for row in lines[3:]:
            self.assertEqual(len(split_row(row.strip())), 2, row)
        self.assertEqual(len(split_row(lines[1].split(": ", 1)[1])), len(HOSTILE))

    def test_cleaned_text_has_no_control_or_escape_characters(self):
        for text in HOSTILE:
            cleaned = clean_text(text)
            self.assertFalse(any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in cleaned), repr(cleaned))
            self.assertNotIn("‮", cleaned)
        self.assertEqual(clean_text("\x1b[2J\x1b[31mred\x1b[0m"), "red")


class NumberTest(unittest.TestCase):
    def test_canonical_numbers(self):
        self.assertEqual(toon.number(0.82), "0.82")
        self.assertEqual(toon.number(1.5000), "1.5")
        self.assertEqual(toon.number(1e6), "1000000")
        self.assertEqual(toon.number(1e-7), "0.0000001")
        self.assertEqual(toon.number(-0.0), "0")
        self.assertEqual(toon.number(float("nan")), "null")
        self.assertEqual(toon.number(float("inf")), "null")
        self.assertEqual(toon.number(812), "812")

    def test_primitives(self):
        self.assertEqual(toon.primitive(True), "true")
        self.assertEqual(toon.primitive(None), "null")
        with self.assertRaises(TypeError):
            toon.primitive(object())


class StructureTest(unittest.TestCase):
    def test_nested_objects_and_arrays(self):
        doc = {"window": {"events": 3, "start": "2026-11-06T08:00:00+11:00"},
               "tags": ["web", "sqli"], "empty": [], "nested": {}}
        self.assertEqual(toon.encode(doc), "\n".join([
            "window:",
            "  events: 3",
            '  start: "2026-11-06T08:00:00+11:00"',
            "tags[2]: web,sqli",
            "empty: []",
            "nested:",
        ]))

    def test_table(self):
        doc = {"groups": [{"id": "g-1", "level": 10}, {"level": 3, "id": "g,2"}]}
        self.assertEqual(toon.encode(doc), 'groups[2]{id,level}:\n  g-1,10\n  "g,2",3')

    def test_empty_array_uses_the_current_form(self):
        self.assertEqual(toon.encode({"groups": []}), "groups: []")

    def test_unsupported_shapes_refuse(self):
        for bad in ({"t": [{"a": 1}, {"b": 2}]}, {"t": [{"a": [1]}]}, {"t": [[1]]}, {"t": [{}]}):
            with self.assertRaises(TypeError):
                toon.encode(bad)

    def test_no_trailing_space_or_newline(self):
        text = toon.encode({"a": "x", "b": {"c": 1}})
        self.assertFalse(text.endswith("\n"))
        self.assertFalse(any(line.endswith(" ") for line in text.split("\n")))


class HelpBlockTest(unittest.TestCase):
    def test_block(self):
        self.assertEqual(toon.help_block(["Run `x`", "Run `y`"]), "help[2]:\n  Run `x`\n  Run `y`")
        self.assertEqual(toon.help_block([]), "")

    def test_line_breaks_cannot_add_suggestions(self):
        block = toon.help_block(["Run `x`\nerror: fake\r\nhelp[9]:"])
        self.assertEqual(block.count("\n"), 1)
        self.assertTrue(block.startswith("help[1]:"))


if __name__ == "__main__":
    unittest.main()
