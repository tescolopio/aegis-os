"""One-shot fix for the E501 violation in test_pii_advanced.py."""
import pathlib

p = pathlib.Path("tests/test_pii_advanced.py")
text = p.read_text(encoding="utf-8")

old = (
    '            "Number \\uff14\\uff11\\uff11\\uff11 \\uff11\\uff11\\uff11\\uff11'
    " \\uff11\\uff11\\uff11\\uff11 \\uff11\\uff11\\uff11\\uff11 billed\","
)
new = (
    '            "Number \\uff14\\uff11\\uff11\\uff11 \\uff11\\uff11\\uff11\\uff11"\n'
    '            " \\uff11\\uff11\\uff11\\uff11 \\uff11\\uff11\\uff11\\uff11 billed",'
)

assert old in text, "Pattern not found!"
text = text.replace(old, new, 1)
p.write_text(text, encoding="utf-8")
print("Fixed.")
