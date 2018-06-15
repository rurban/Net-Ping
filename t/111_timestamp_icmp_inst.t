# Test to make sure object can be instantiated for icmp protocol.
# Root access is required to actually perform icmp testing.

use strict;
use Config;

BEGIN {
    unless (eval "require Socket") {
        print "1..0 \# Skip: no Socket\n";
        exit;
    }
    unless ($Config{d_getpbyname}) {
        print "1..0 \# Skip: no getprotobyname\n";
        exit;
    }
}

use Test::More tests => 2;
BEGIN {use_ok('Net::Ping::TimeStamp')};

SKIP: {
    skip "icmp timestamp ping requires root privileges.", 1
        unless &Net::Ping::_isroot;
    my $p = new Net::Ping::TimeStamp "icmp";
    isa_ok($p, 'Net::Ping::TimeStamp', 'object can be instantiated for timestamp type icmp protocol');
}
