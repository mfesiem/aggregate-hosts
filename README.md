# Aggregate hosts

Create and automatically maintain a list of hosts records, with **`SrcMac` as the unique key**, based on querying McAfee SIEM logs.

Will generate a JSON file (`hosts.json` by default) containing list of dictionnary with host record infos : `user`, `host`, `macaddress`, `seen`, `ip`.

Use [manuf](https://github.com/coolbho3k/manuf) to resolve vendors Mac addresses and [msiempy](https://github.com/mfesiem/msiempy) to query McAfee SIEM logs.

### Install

```bash
git clone https://github.com/mfesiem/aggregate-hosts
cd track-host
pip install -r requirements.txt
```

### Configure

Setup [msiempy config file](https://github.com/mfesiem/msiempy#authentication-and-configuration-setup)


### Usage

The script is design to query Windows Server DHCP logs (Windows DHCP data source model) and Cisco RADIUS logs (Secure ACS data source model). But yo can specify any event signature IDs. It might not work thought.

Find and keep updated a list of all Apple devices from events specific Signature IDS (Wi-Fi related signature ids): RADIUS_START ('268-2239707159'), DHCP_NEW ('272-10'), DHCP_RENEW ('272-11').  

Additionnaly exclude mobiles devices based on some hostname matches.

```
python3 ./agg-hosts.py -t last_24_hours -v Apple -s 268-2239707159 272-10 272-11 -n iPhone iPad Phone Teleph Mobile iPod
```

### More infos

```
python3 ./agg-hosts.py --help
```