#!/usr/bin/perl
# Export Sophos Firewall DNS hosts to JSON
# Usage: perl exportSophosDNSHosts.pl (run this on the Sophos Firewall)

use Astaro::ConfdPlRPC; # Sophos Firewalls already have this preinstalled
use JSON qw( encode_json );

my $fw = new Astaro::ConfdPlRPC();
my $networkObjects = $fw->get_objects('network');
my @objects;

foreach my $networkObject ( @$networkObjects ) {
  if (exists $networkObject->{'data'}{'members'}) {
        my @newMembers;
        foreach my $ref ( @{ $networkObject->{'data'}{'members'} } ) {
                my $member = $fw->get_object($ref);
                push @newMembers, $member;
        }
        $networkObject->{'data'}{$members} = \@newMembers;
  }
  next if $networkObject->{'type'} ne 'dns_host';
  push @objects, $networkObject
}

my $json = JSON->new;
my $formatted = $json->pretty->encode(\@objects);
my $filename = "dns_hosts.json";
open my $fh, ">", $filename;
print $fh $formatted;
close $fh;
print "Exported ".@objects." to $filename\n";
