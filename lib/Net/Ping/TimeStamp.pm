package Net::Ping::TimeStamp;

use strict;
use warnings;

use parent qw(Net::Ping);

use constant ICMP_TIMESTAMP         => 13;
use constant ICMP_TIMESTAMP_REPLY   => 14;
use constant ICMP_STRUCT            => "C2 n3 N3"; # Structure of a minimal timestamp ICMP packet

# Just overide ping_icmp method to implement TimeStamp ICMP query and
# TimeStamp ICMP reply support as specified in RFC 792
# The method is a simplified version of the original Echo ICMP support from Net::Ping
# It only supports IPv4 at this time
sub ping_icmp
{
    my ($self,
      $ip,                # Hash of addr (string), addr_in (packed), family
      $timeout            # Seconds after which ping times out
      ) = @_;

    my ($saddr,             # sockaddr_in with port and ip
        $checksum,          # Checksum of ICMP packet
        $msg,               # ICMP packet to send
        $len_msg,           # Length of $msg
        $rbits,             # Read bits, filehandles for reading
        $nfound,            # Number of ready filehandles found
        $finish_time,       # Time ping should be finished
        $done,              # set to 1 when we are done
        $ret,               # Return value
        $recv_msg,          # Received message including IP header
        $from_saddr,        # sockaddr_in of sender
        $from_port,         # Port packet was sent from
        $from_ip,           # Packed IP of sender
        $from_type,         # ICMP type
        $from_subcode,      # ICMP subcode
        $from_pid,          # ICMP packet id
        $from_seq,          # ICMP packet sequence
    );

    $ip = $self->{host} if !defined $ip and $self->{host};
    $timeout = $self->{timeout} if !defined $timeout and $self->{timeout};

    socket($self->{fh}, $ip->{family}, Net::Ping::SOCK_RAW, $self->{proto_num}) ||
        croak("icmp socket error - $!");

    if (defined $self->{local_addr} &&
        !CORE::bind($self->{fh}, _pack_sockaddr_in(0, $self->{local_addr}))) {
        croak("icmp bind error - $!");
    }
    $self->_setopts();

    $self->{seq} = ($self->{seq} + 1) % 65536; # Increment sequence
    $checksum = 0;                          # No checksum for starters
    $msg = pack(
        ICMP_STRUCT, ICMP_TIMESTAMP, Net::Ping::SUBCODE,
        $checksum, $self->{pid}, $self->{seq}, 0, 0, 0
        );

    $checksum = Net::Ping->checksum($msg);
    $msg = pack(
        ICMP_STRUCT, ICMP_TIMESTAMP, Net::Ping::SUBCODE,
        $checksum, $self->{pid}, $self->{seq}, 0, 0, 0
    );

    $len_msg = length($msg);
    $saddr = Net::Ping::_pack_sockaddr_in(Net::Ping::ICMP_PORT, $ip);
    $self->{from_ip} = undef;
    $self->{from_type} = undef;
    $self->{from_subcode} = undef;
    send($self->{fh}, $msg, Net::Ping::ICMP_FLAGS, $saddr); # Send the message

    $rbits = "";
    vec($rbits, $self->{fh}->fileno(), 1) = 1;
    $ret = 0;
    $done = 0;
    $finish_time = &Net::Ping::time() + $timeout;      # Must be done by this time
    while (!$done && $timeout > 0)          # Keep trying if we have time
    {
        $nfound = Net::Ping::mselect((my $rout=$rbits), undef, undef, $timeout); # Wait for packet
        $timeout = $finish_time - &Net::Ping::time();    # Get remaining time
        if (!defined($nfound))                # Hmm, a strange error
        {
            $ret = undef;
            $done = 1;
        }
        elsif ($nfound)                     # Got a packet from somewhere
        {
            $recv_msg = "";
            $from_pid = -1;
            $from_seq = -1;
            $from_saddr = recv($self->{fh}, $recv_msg, 1500, Net::Ping::ICMP_FLAGS);
            ($from_port, $from_ip) = Net::Ping::_unpack_sockaddr_in($from_saddr, $ip->{family});
            ($from_type, $from_subcode) = unpack("C2", substr($recv_msg, 20, 2));
            if ($from_type == ICMP_TIMESTAMP_REPLY) {
                ($from_pid, $from_seq) = unpack("n3", substr($recv_msg, 24, 4))
                    if length $recv_msg >= 28;
            } else {
                ($from_pid, $from_seq) = unpack("n3", substr($recv_msg, 52, 4))
                    if length $recv_msg >= 56;
            }
            $self->{from_ip} = $from_ip;
            $self->{from_type} = $from_type;
            $self->{from_subcode} = $from_subcode;
            next if ($from_pid != $self->{pid});
            next if ($from_seq != $self->{seq});
            if ($self->ntop($from_ip) eq $self->ntop($ip)) { # Does the packet check out?
                if ($from_type == ICMP_TIMESTAMP_REPLY) {
                    $ret = 1;
                    $done = 1;
                } elsif ($from_type == Net::Ping::ICMP_UNREACHABLE) {
                    $done = 1;
                } elsif ($from_type == Net::Ping::ICMP_TIME_EXCEEDED()) {
                    $ret = 0;
                    $done = 1;
                }
            }
        } else {     # Oops, timed out
            $done = 1;
        }
    }
    return $ret;
}

1;
__END__

=head1 NAME

Net::Ping::TimeStamp - check a remote host for reachability

=head1 SYNOPSIS

    use Net::Ping::TimeStamp;

    $p = Net::Ping::TimeStamp->new("icmp");
    $p->bind($my_addr); # Specify source interface of pings
    foreach $host (@host_array)
    {
        print "$host is ";
        print "NOT " unless $p->ping($host, 2);
        print "reachable.\n";
        sleep(1);
    }
    $p->close();

=head1 DESCRIPTION

This module provides a Net::Ping derivated class which makes TimeStamp
ICMP pings for icmp protocol ping.

For not "icmp" type, this class does exactly what Net::Ping class would do.

If the "icmp" protocol is specified, the ping() method sends an icmp
timestamp message to the remote host, which is what the UNIX nmap program
can do while -PP option is used.  If the echoed message is received from
the remote host and the echoed information is correct, the remote host is
considered reachable.  Specifying the "icmp" protocol requires that the
program be run as root or that the program be setuid to root.

=head2 Functions

=over 4

=item $p->ping_icmp([$host, $timeout, $family])
X<ping_icmp>

The X<ping> method used with the icmp protocol using timestamp message type.

=back

=head1 BUGS

For a list of known issues, visit:

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Ping>
and
L<https://github.com/rurban/Net-Ping/issues>

To report a new bug, visit:

L<https://github.com/rurban/Net-Ping/issues>

=head1 AUTHORS

  Original Net::Ping::TimeStamp author:
    gbougard  at teclib.com (Guillaume Bougard)

=head1 COPYRIGHT

Copyright (c) 2018, Guillaume Bougard.  All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

=cut
