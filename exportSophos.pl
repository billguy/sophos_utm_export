#!/usr/bin/perl
# Export Sophos Firewall packet filter, NAT & network objects to JSON
# Usage: perl exportSophos.pl (run this on the Sophos Firewall)

use Astaro::ConfdPlRPC; # Sophos Firewalls already have this preinstalled
use JSON qw( encode_json );
use strict;

my $fw = new Astaro::ConfdPlRPC();
my $packetfilterRefs = $fw->get('packetfilter');
my $ruleNatRefs = $fw->get('nat','rules');
my $networkObjects = $fw->get_objects('network');
my @excludedKeys = ('lock','ref','auto_type','auto_pf_svc_src','auto_pf_svc_dst','autoname','nodel','time','source_mac_addresses','resolved','reverse_dns','resolved6','address6','duids','macs','auto','to6','from6','netmask6');

sub parseValue {
  my $val = shift;
  if (ref $val eq 'ARRAY'){
   foreach my $v ( @$val ) {
     $v = parseValue($v);
   }
  } elsif (ref$val eq 'HASH') {
    for my $key (keys %$val) {
     if (grep( /^$key$/, @excludedKeys )){
       delete $val->{$key};
       next;
     } else {
       $val->{$key} = parseValue($val->{$key});
     }
    }
  } elsif ($val =~ /^REF_/) {
    my $v = $fw->get_object($val);
    $val = parseValue($v);
  }
  return $val;
}
my @allRules = ( @{$packetfilterRefs->{'rules'}}, @{$packetfilterRefs->{'rules_auto'}} );
my $config ={
  'packet_filter_rules' => \@allRules,
  'nat_rules' => $ruleNatRefs,
  'network_objects' => $networkObjects
};
foreach my $component (keys %$config) {
  my @objects;
  foreach my $ref ( @{$config->{$component}} ) {
    if (ref $ref eq 'SCALAR'){
                my $object = $fw->get_object($ref);
                push @objects, parseValue($object);
        } else {
                push @objects, parseValue($ref);
        }
  }
  my $json = JSON->new;
  my $formatted = $json->pretty->encode(\@objects);
  open my $fh, ">", "$component.json";
  print $fh $formatted;
  close $fh;
  print "Exported ".@objects. " to $component.json\n";
}

