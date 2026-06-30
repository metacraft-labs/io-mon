import sys
_log = open('/tmp/r4_real/py_audit_opens.txt','w')
def hook(event, args):
    if event == 'open':
        try: _log.write(str(args[0])+'\n'); _log.flush()
        except Exception: pass
sys.addaudithook(hook)
# now do the real work
import json, re, collections, hashlib, base64, textwrap, argparse
print("done", hashlib.sha256(b"x").hexdigest()[:6])
