import re
with open('/Users/ekans/payguard/payguard_unified.py', 'r') as f:
    code = f.read()

# Let's remove _run_inline_text_checks from phase 2 execution
new_code = re.sub(
    r'phase2\[self\.executor\.submit\(self\._run_inline_text_checks, text\)\] = \'inline_text\'',
    r'# inline text checks removed to avoid false positives\n                # self.executor.submit(self._run_inline_text_checks, text)',
    code
)

with open('/Users/ekans/payguard/payguard_unified.py', 'w') as f:
    f.write(new_code)
