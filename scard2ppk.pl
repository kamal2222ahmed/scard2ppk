#!/usr/bin/env perl
use strict;
use Data::Dumper;

my $pkcs15tool = "/cygdrive/c/Program\ Files/OpenSC/pkcs15-tool.exe";
my $openssl = "/cygdrive/c/OpenSSL-Win32/bin/openssl.exe";

# interesting attributes of certs, keys and pins
my %cert_interesting = ('ID' => 1, 'Path' => 1, 'Flags' => 1);
my %key_interesting  = ('ID' => 1, 'Path' => 1, 'Key ref' => 1, 'Auth ID' => 1, 'Usage' => 1);
my %pin_interesting  = ('ID' => 1, 'Path' => 1, 'Reference' => 1, 'Tries left' => 1);

# temp items while they are being parsed
my ($cert, $key, $pin);

# empty hashes that collect the parsed items by their IDs as keys
my (%certs, %keys, %pins);

# result array of valid certs
my @valid_certs;

# parse the output of 'pkcs15-tool -D', that is, a full dump of the card
open(my $fd, '-|', $pkcs15tool, "-D") or die "Cannot execute $pkcs15tool: $!\n";
foreach my $line (readline($fd)) {
    $line =~ tr/\r\n//d;
    if ($line =~ /^X\.509 Certificate \[(.*)\]/) {
        # this is the beginning of a new certificate -> create a new hash item for it
        $cert = {'Name' => $1};
    }
    elsif ($line =~ /^Private RSA Key \[(.*)\]/) {
        # this is the beginning of a new key
        $key = {'Name' => $1};
    }
    elsif ($line =~ /^PIN \[(.*)\]/) {
        # this is the beginning of a new pin
        $pin = {'Name' => $1};
    }
    elsif ($line =~ /^\s*(.*?)\s*:\s*(.*?)\s*$/) {
        # this is a 'name : value'  line -> if the attribute is interesting for the
        # item being parsed, then add the name+value pair to its hash item

        if ($cert and $cert_interesting{$1}) {
            $cert->{$1} = $2;
        }
        elsif ($key and $key_interesting{$1}) {
            $key->{$1} = $2;
        }
        elsif ($pin and $pin_interesting{$1}) {
            $pin->{$1} = $2;
        }
    }
    elsif ($line =~ /^\s*$/) {
        # this is an empty line -> the item being parsed is complete
        if ($cert and $cert->{'Flags'} != 0) {
            # this is a valid cert -> add it to the certs' collector hash
            delete $cert->{'Flags'};
            $certs{$cert->{'ID'}} = $cert;
            undef $cert;
        }
        elsif ($key and $key->{'Usage'} =~ /encrypt/) {
            # this is a key
            delete $key->{'Usage'};
            $keys{$key->{'ID'}} = $key;
            undef $key;
        }
        elsif ($pin) {
            # this is a pin
            $pins{$pin->{'ID'}} = $pin;
            undef $pin;
        }
    }
    else {
        die "This is something weird: $line\n";
    }
}
close($fd);

# process the certs
while (my ($id, $cert) = each %certs) {
    # add the attibutes of their keys and their pins to the cert hash
    $key = $keys{$id};
    if ($key) {
        $cert->{'KeyPath'} = $key->{'Path'};
        $cert->{'KeyRef'} = $key->{'Key ref'};
        $pin = $pins{$key->{'Auth ID'}};
        if ($pin) {
            $cert->{'PinPath'} = $pin->{'Path'};
            if ($pin->{'Tries left'} == 0) {
                $cert->{'PinRef'} = 0;
            }
            else {
                $cert->{'PinRef'} = $pin->{'Reference'};
            }
        }
    }

    # check if the cert has everything that is needed
    if (defined $cert->{'PinRef'}) {
        # check whether the prefix of Path, KeyPath and PinPath is the same
        my $certpath = substr($cert->{'Path'}, 0, 4);
        my $keypath = substr($cert->{'KeyPath'}, 0, 4);
        my $pinpath = substr($cert->{'PinPath'}, 0, 4);
        if ($certpath eq $keypath and $keypath eq $pinpath) {
            # prepare the .ppk line items
            my $keyref = sprintf("%02x", $cert->{'KeyRef'});
            my $pinref = sprintf("%02x", $cert->{'PinRef'});
            my $certsuffix  = substr($cert->{'Path'}, 4, 4);
            # assemble the .ppk line
            $cert->{'ppk'} = "$certpath,$keyref,$pinref,$certsuffix";
            push @valid_certs, $cert;
        }
    }
}

foreach $cert (@valid_certs) {
    (my $esc_pt = $pkcs15tool) =~ s/ /\\ /g;
    (my $esc_os = $openssl) =~ s/ /\\ /g;
    my $subject = `$esc_pt -r $cert->{'ID'} 2>/dev/null | $esc_os x509 -noout -subject 2>/dev/null`;
    $subject =~ s!^.*emailAddress=([^/]*).*!$1!;
    $subject =~ tr/@.\r\n/__/d;
    my $filename = "SC_$subject.ppk";
    print "Generating file $filename\n";
    my $content = "PuTTYcard,PuTTYiso7816.dll,$cert->{'ppk'}\n";
    open($fd, ">", $filename) or die "Cannot create $filename: $!\n";
    print $fd $content;
    close($fd);
}
# vim:ft=perl:ai:si:ts=4:sw=4:et
