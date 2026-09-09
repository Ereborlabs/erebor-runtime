import sys

status = int(sys.argv[1])
message = sys.argv[2]
print(message, file=sys.stderr, flush=True)
raise SystemExit(status)

