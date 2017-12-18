import re
import json

config = json.load(open('config.json'))
test_error_set = set(config['TestErrorMap'].keys())

all_tests = set()
failing_tests = set()
unimpl_tests = set()
passed_tests = set()

for line in open('out'):
    m = re.match('^(PASSED|UNIMPLEMENTED|FAILED) \((.*)\)$', line.strip())
    if m:
        status, name = m.groups()
        if name in test_error_set:
            test_error_set.remove(name)
        all_tests.add(name)
        if status == 'FAILED':
            failing_tests.add(name)
        elif status == 'UNIMPLEMENTED':
            unimpl_tests.add(name)
        elif status == 'PASSED':
            passed_tests.add(name)

print len(all_tests), 'total tests'
print len(passed_tests), 'passed'
print len(failing_tests), 'tests failing'
print len(unimpl_tests), 'tests not supported'

if test_error_set:
    print 'unknown TestErrorMap keys', test_error_set

