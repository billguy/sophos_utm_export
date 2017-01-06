# Sophos UTM Firewall Configuration Exporter
A collection of perl scripts that currently extract the following from a Sophos UTM Firewall (version ~ 9).

1. Packetfilter rules
2. NAT Rules 
3. Network Objects
4. DNS hosts

### exportSophos.pl

To extract the packetfilter, nat and network objects: copy 'exportSophos.pl' to the firewall and run (as root):

```perl
perl exportSophos.pl
```

This will generate 3 JSON files: 'packet_filter_rules.json', 'nat_rules.json' and 'network_objects.json' in the current directory of the firewall.

### exportSophosDNSHosts.pl
To extract the DNS hosts: copy 'exportSophosDNSHosts.pl' to the UTM and run (as root):

```perl
perl exportSophosDNSHosts.pl
```

This will generate 'dns_hosts.json' in the current directory of the firewall.