## parse bind zone file into format expected by this app

```bash
awk -v OFS="," '{sub(/\r$/,""); sub(/\.$/,"",$1); v=""; s=($4=="MX"?6:5); for(i=s;i<=NF;i++) v=(v==""?$i:v" "$i); if($4=="CNAME" || $4=="MX") sub(/\.$/,"",v); print $1,$4,($4=="MX"?$5:""),v}' bind_file.txt
```

## Usage

```bash
go build -o dns-tester src/main.go

./dns-tester dns-test.csv adns05.bigpond.com kay.ns.cloudflare.com
```