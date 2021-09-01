# asa-to-srx-converter

 Convert an Cisco ASA configuration to Juniper SRX  

Inspired by the opposite version of this project written in Python2 [SRX-to-ASA-Converter](https://github.com/glennake/SRX-to-ASA-Converter) this project seeks to convert a Cisco ASA configuration to the Junos set commands for Juniper SRX devices. This project is designed to help speed up the migration to SRX, but does not completely convert the configuration.  

> You will need to validate all set statements before running them on your SRX device. I cannot provide support for your migration and code is provided as-is

Design requirements and features:  

- It was written to only convert Object Network, Object Service, Object-Group, and Access-Lists statements
- allows you to override the asa interfaces to new names
- provides logging on which lines were missed or skipped in the asa config
- Creates application-sets if there are over 8 applications in a object service
- Keeps applications together where the source and destination where the same on ASA
- It ignores any `nat` and `crypto ca` statements
- It ignores `deny` and `any any` access-lists
- It creates zones based on interfaces, but doesn't assign reth numbers

## Requirements

- Python 3.9.5

## Dependencies

Uses the following Builtin modules

- argparse
- ipaddress
- re
- csv
- logging
- IPv4Address, IPv4Network, ip_network from ipaddress
- getservbyname from socket
- sha1 from hashlib

## Examples

---
Outputs the converted configuration to the specified filed. Logging is returned to stdout  
`python3 ./convert.py path/to/asa_run_config path/to/output`  

---
Returns both config and logging to stdout  
`python3 ./convert.py path/to/asa_run_config path/to/output --passthrough`  

---
Overrides the interfaces in the asa with a CSV consisting of zone and network.  

zones.csv:  

```csv
zone,network
default_zone,0.0.0.0/0
dmz,10.9.8.0/24
internal,192.168.0.0/24
```

`python3 ./convert.py path/to/asa_run_config path/to/srx_output -zo zones.csv`  

---

Set the logging level to info (which shows the lines skipped in the asa config) and save to a file.  

`python3 ./convert.py path/to/asa_run_config path/to/srx_output --log info --logFile path/to/log_file`