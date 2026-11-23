#!/bin/bash
S=$1; shift
for d in "$@"; do
  n=$(echo "$d" | tr / _)
  docker run --rm -e GOMAXPROCS=4 -v $S/src/$d:/hsroot -v $S/hs:/out horuszup/horusec-cli:v2.8.0 horusec start -p /hsroot -D -o json -O /out/$n.json --disable-docker -t 10800 -i "**/.horusec/**,*tmp*,**/.vscode/**,**/__tests__/**,**/*.test.ts,**/*.test.tsx,**/*.spec.ts,**/*.test.mjs,**/*.stories.tsx,**/node_modules/**" > $S/hs/$n.log 2>&1
  echo "$d exit=$? $(grep -ac 'thread exhaustion' $S/hs/$n.log) $(grep -a 'level=error' $S/hs/$n.log | head -1 | cut -c1-200)"
  rm -rf $S/src/$d/.horusec
done
