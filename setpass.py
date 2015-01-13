#!/usr/bin/env python
import sys
import uuid
import hashlib

def main(argv):
    args = argv[1:]
    username = args.pop(0)
    password = args.pop(0)
    s = uuid.uuid4().hex
    h = hashlib.sha1()
    h.update(username+s+password)
    v = h.hexdigest()
    print s, v
    return 0

if __name__ == '__main__': sys.exit(main(sys.argv))
