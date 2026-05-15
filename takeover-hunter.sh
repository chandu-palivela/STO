#!/usr/bin/env bash

set -e

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

mkdir -p "$DOMAIN"
cd "$DOMAIN"

echo "[+] Enumerating subdomains"

subfinder -d "$DOMAIN" -silent | sort -u > subs.txt

echo "[+] Resolving DNS"

dnsx -l subs.txt \
    -resp \
    -a \
    -aaaa \
    -cname \
    -silent \
    > dns.txt

cat dns.txt | awk '{print $1}' | sort -u > resolved.txt

echo "[+] Probing HTTP services"

httpx -l resolved.txt \
    -silent \
    -title \
    -tech-detect \
    -status-code \
    -follow-redirects \
    -cname \
    -json \
    > httpx.json

cat httpx.json | jq -r '
[
    .url,
    .status_code,
    .title,
    .cname
] | @tsv
' > httpx.tsv

echo "[+] Running Subjack"

subjack \
    -w resolved.txt \
    -ssl \
    -timeout 30 \
    -v \
    -a \
    > subjack.txt

echo "[+] Running tko-subs"

python3 ~/tools/tko-subs/tko-subs.py \
    -domains=resolved.txt \
    -data=~/tools/tko-subs/providers-data.csv \
    -threads=20 \
    > tko.txt

echo "[+] Detecting takeover fingerprints"

cat httpx.tsv | grep -Eiv '^$' | grep -Ei \
"NoSuchBucket|No such app|Fastly error|unknown domain|project not found|repository not found|The specified bucket does not exist|shop is currently unavailable|There's nothing here|Heroku|GitHub Pages|Bitbucket|ghost|pantheon|readme|statuspage" \
> fingerprints.txt || true

echo "[+] Extracting suspicious CNAMEs"

cat dns.txt | grep -Ei \
"amazonaws|herokuapp|github.io|fastly|azurewebsites|trafficmanager|cloudfront|pantheonsite|bitbucket|zendesk|readme.io|statuspage|shopify|surge.sh" \
> cnames.txt || true

echo "[+] Consolidating findings"

cat fingerprints.txt subjack.txt tko.txt cnames.txt \
| sort -u \
> possible_takeovers.txt

echo
echo "[+] DONE"
echo
echo "Files:"
echo "subs.txt"
echo "resolved.txt"
echo "dns.txt"
echo "httpx.json"
echo "httpx.tsv"
echo "subjack.txt"
echo "tko.txt"
echo "fingerprints.txt"
echo "cnames.txt"
echo "possible_takeovers.txt"
echo
echo "[+] Potential Takeovers:"
cat possible_takeovers.txt
