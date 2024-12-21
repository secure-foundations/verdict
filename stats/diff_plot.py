"""
Generate a table to show the differential testing results
"""

import subprocess

results = [
    ("CT", (
        ("Chrome", "../frontend/diff-results/chrome-v2.txt", "../frontend/diff-results/verdict-chrome-v11.txt"),
        ("Firefox", "../frontend/diff-results/firefox-no-required-tls-features.txt", "../frontend/diff-results/verdict-firefox-v6.txt"),
        ("OpenSSL", "../frontend/diff-results/openssl-v3.txt", "../frontend/diff-results/verdict-openssl-v5.txt"),
    )),

    ("Limbo", (
        ("Chrome", "../frontend/limbo-results/chrome.txt", "../frontend/limbo-results/verdict-chrome-v12.txt"),
        ("Firefox", "../frontend/limbo-results/firefox.txt", "../frontend/limbo-results/verdict-firefox-v2.txt"),
        ("OpenSSL", "../frontend/limbo-results/openssl-v3-has-domain.txt", "../frontend/limbo-results/verdict-openssl-v3-has-domain.txt"),
    )),
]

diff_command = ["../frontend/target/release/frontend", "diff-results"]

print("\\begin{tabular}{clrrrr}")
print("Test & Impl. & A/A & A/R & R/A & R/R \\\\")
print("\\hline")

for i, (suite, impls) in enumerate(results):
    if i != 0:
        print("\\hline")

    for j, (name, original_impl, our_impl) in enumerate(impls):
        res = subprocess.run(diff_command + [ original_impl, our_impl ], capture_output=True, text=True)

        class_tt = 0
        class_tf = 0
        class_ft = 0
        class_ff = 0

        matching_true_prefix = "matching class Singleton(\"true\"): "
        matching_false_prefix = "matching class Singleton(\"false\"): "

        for line in res.stdout.splitlines():
            if line.endswith("true vs false"):
                class_tf += 1
            elif line.endswith("false vs true"):
                class_ft += 1
            elif line.startswith(matching_true_prefix):
                class_tt = int(line[len(matching_true_prefix):])
            elif line.startswith(matching_false_prefix):
                class_ff = int(line[len(matching_false_prefix):])
            else:
                assert False, f"failure to diff {original_impl} and {our_impl}: unknown line {line}"

        # total = class_tt + class_tf + class_ft + class_ff

        prefix = f"\\multirow{{{len(impls)}}}{{*}}{{{suite}}} "
        print(f"{prefix if j == 0 else ''}& {name} & {class_tt:,} & {class_tf:,} & {class_ft:,} & {class_ff:,} \\\\")

print("\\end{tabular}")
