# Net Prowler
A very simple port scanner written in rust. 

## Usage
See what commands can be run `cargo run --bin=net_prowler_cli -- -h`

For example, scan all ports on your local machine: `cargo run --bin=net_prowler_cli -- --cidr  127.0.0.1 --from-port 0 --to-port 65535 --batch-size 5000 --timeout 1500`
```
Scanning 127.0.0.1 with port range 0:65535
ScanResult { ip: V4(127.0.0.1/32), port: 22, open: true }
ScanResult { ip: V4(127.0.0.1/32), port: 445, open: true }
ScanResult { ip: V4(127.0.0.1/32), port: 8080, open: true }
ScanResult { ip: V4(127.0.0.1/32), port: 23413, open: true }
Finished scanning 127.0.0.1 with port range 0:65535. Elapsed time: 1.63s
```