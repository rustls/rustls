"""
This script post-processes bogo pass/fail logs to help
maintain config.json.

Run:

    $ ./runme | python check.py
"""

import re
import json
import fnmatch
import sys

config = json.load(open('config.json'))
test_error_set = set(config['TestErrorMap'].keys())
test_local_error_set = set(config['TestLocalErrorMap'].keys())
obsolete_disabled_tests = set()

all_tests = set()
failing_tests = set()
unimpl_tests = set()
disabled_tests = set()
passed_tests = set()

for line in sys.stdin:
    m = re.match(r'^(PASSED|UNIMPLEMENTED|FAILED|DISABLED) \((.*)\)$', line.strip())
    if m:
        status, name = m.groups()
        if name in test_error_set:
            test_error_set.remove(name)
        if name in test_local_error_set:
            test_local_error_set.remove(name)
        all_tests.add(name)
        if status == 'FAILED':
            failing_tests.add(name)
        elif status == 'UNIMPLEMENTED':
            unimpl_tests.add(name)
        elif status == 'DISABLED':
            disabled_tests.add(name)
        elif status == 'PASSED':
            passed_tests.add(name)

if disabled_tests:
    for disabled_glob in sorted(config['DisabledTests'].keys()):
        tests_matching_glob = fnmatch.filter(disabled_tests, disabled_glob)
        if not tests_matching_glob:
            print('DisabledTests glob', disabled_glob, 'matches no tests')
else:
    # to check DisabledTests, apply patch below to bogo
    print('(DisabledTests unchecked)')

print(len(all_tests), 'total tests')
print(len(passed_tests), 'passed')
print(len(failing_tests), 'tests failing')
print(len(unimpl_tests), 'tests not supported')

if test_error_set:
    print('unknown TestErrorMap keys', list(sorted(test_error_set)))
if test_local_error_set:
    print('unknown TestLocalErrorMap keys', list(sorted(test_local_error_set)))

MENTION_DISABLED_TESTS_PATCH = """
diff --git a/ssl/test/runner/runner.go b/ssl/test/runner/runner.go
index eb6cc53..e51649a 100644
--- a/ssl/test/runner/runner.go
+++ b/ssl/test/runner/runner.go
@@ -20830,6 +20830,7 @@ func main() {
                                }

                                if isDisabled {
+                                       fmt.Printf("DISABLED (%s)\n", testCases[i].name)
                                        matched = false
                                        break
                                }
"""
