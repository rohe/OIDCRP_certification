import os
import sys

response_type = sys.argv[1]

files = [f for f in os.listdir('.') if os.path.isfile(f)]

for f in files:
    namn,typ = f.split('.')
    if typ == "log":
        _new_name = namn + '-' + response_type
        os.rename(f, _new_name + '.log')