package Parse::Netstat;

use 5.010001;
use strict;
use warnings;

use Exporter::Lite;
our @EXPORT_OK = qw(parse_netstat);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    summary => 'Parse the output of net-tools "netstat" command',
    args => {
        output => ['str*' => {
            arg_pos => 0,
            summary => 'Output of netstat command',
            description => <<'_',

This function only parses program's output. You need to invoke "netstat -anp" and capture the output on your
own.

_
        }],
        tcp => ['bool' => {
            summary => 'Whether to parse tcp connections',
            default => 1,
        }],
        udp => ['bool' => {
            summary => 'Whether to parse udp connections',
            default => 1,
        }],
        unix => ['bool' => {
            summary => 'Whether to parse unix connections',
            default => 1,
        }],
    },
};

sub parse_netstat {
    my %args = @_;
    my $output = $args{output} or return { status => '400', msg => "Please supply the output of netstat -anp"};
    my $tcp    = $args{tcp} // 1;
    my $tcp6    = $args{tcp6} // 1;
    my $udp    = $args{udp} // 1;
    my $udp6    = $args{udp6} // 1;
    my $unix   = $args{unix} // 1;

    my @conns;
    my $i = 0;
    for my $line (split /^/, $output) {
        $i++;
        my %k;
        if ($line =~ /^tcp / && $tcp) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #tcp        0      0 0.0.0.0:8898                0.0.0.0:*                   LISTEN      5566/daemon2.pl [pa
            $line =~ m!^(?<proto>tcp) \s+
                        (?<recvq>\d+) \s+ 
                        (?<sendq>\d+)\s+
                        (?<local_host>\S+?):(?<local_port>\w+)\s+
                        (?<foreign_host>\S+?):(?<foreign_port>\w+|\*)\s+
                        (?<state>\S+) (?: \s+ (?:
                        (?<pid>\d+)/(?<program>.+?) |
                               -
                       ))? \s*$!x
                           or return { status => 400, msg => "Invalid tcp line (#$i): $line"};
            %k = %+;
        } elsif ($line =~ /^tcp6 / && $tcp6) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #tcp6       0      0 :::111                  :::*                    LISTEN      1779/rpcbind    
            #tcp6       0      0 :::57201                :::*                    LISTEN      -               
            $line =~ m!^(?<proto>tcp6) \s+
                        (?<recvq>\d+) \s+ 
                        (?<sendq>\d+)\s+
                        (?<local_host>\S+?):(?<local_port>\w+)\s+
                        (?<foreign_host>\S+?):(?<foreign_port>\w+|\*)\s+
                        (?<state>\S+) (?: \s+ (?:
                        (?<pid>\d+)/(?<program>.+?) |
                               -
                       ))? \s*$!x
                           or return { status => 400,  msg => "Invalid tcp line (#$i): $line"};
            %k = %+;
        } elsif ($line =~ /^udp / && $udp) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #udp        0      0 0.0.0.0:631                 0.0.0.0:*                        2769/cupsd
            $line =~ m!^(?<proto>udp) \s+ 
                        (?<recvq>\d+) \s+
                        (?<sendq>\d+)\s+
                        (?<local_host>\S+?):(?<local_port>\w+)\s+
                        (?<foreign_host>\S+?):(?<foreign_port>\w+ | \* )\s+
                        (?: \s+ (?:(?<pid>\d+)/(?<program>.+?) | - ))? \s*$!x
                           or return { status => 400,  msg => "Invalid udp line (#$i): $line"};
            %k = %+;
        } elsif ($line =~ /^udp6 / && $udp6) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #udp6       0      0 :::682                  :::*                                1779/rpcbind    
            #udp6       0      0 :::52155                :::*                                -               
            $line =~ m!^(?<proto>udp6) \s+ 
                        (?<recvq>\d+) \s+ 
                        (?<sendq>\d+)\s+
                        (?<local_host>\S+?):(?<local_port>\w+)\s+
                        (?<foreign_host>\S+?):(?<foreign_port>\w+|\*)\s+
                        (?: \s+ (?: (?<pid>\d+)/(?<program>.+?) | - ))? \s*$!x
                           or return { status => 400,  msg => "Invalid udp6 line (#$i): $line"};
            %k = %+;
        } elsif ($line =~ /^unix/ && $unix) {
            #Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
            #    unix  2      [ ACC ]     STREAM     LISTENING     650654 30463/gconfd-2      /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
            $line =~ m!^(?<proto>unix) \s+ (?<refcnt>\d+) \s+
                       \[\s*(?<flags>\S*)\s*\] \s+ (?<type>\S+) \s+
                       (?<state>\S+|\s+) \s+ (?<inode>\d+) \s+
                       (?: (?: (?<pid>\d+)/(?<program>.+?) | - ) \s+)?
                       (?<path>.*?)\s*$!x
                           or return { status => 400, mgs => "Invalid unix line (#$i): $line"};
            %k = %+;
        } else {
            next;
        }
        push @conns, \%k;
    }

    { status => 200, msg => "OK", active_conns => \@conns };
}

1;
# ABSTRACT: Parse the output of net-tools "netstat" command


=pod

=head1 NAME

Parse::Netstat - Parse the output of net-tools "netstat -anp" command from the net-tools project
http://sourceforge.net/projects/net-tools/

BSD Unix netstat at least as found on OSX doesn't supply the name of the program using the port expected by this module


=head1 VERSION

# version

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);

 my $output = `netstat -anp`;
 my $res = parse_netstat( output => $output );

Sample result:

 {
  status => 200,
  msg => 'OK',
  active_conns => 
    [
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "127.0.0.1",
        local_port => 1027,
        proto => "tcp",
        recvq => 0,
        sendq => 0,
        state => "LISTEN",
      },
      ...
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "192.168.0.103",
        local_port => 56668,
        proto => "udp",
        recvq => 0,
        sendq => 0,
      },
      ...
      {
        flags   => "ACC",
        inode   => 15631,
        path    => "\@/tmp/dbus-VS3SLhDMEu",
        pid     => 4513,
        program => "dbus-daemon",
        proto   => "unix",
        refcnt  => 2,
        state   => "LISTENING",
        type    => "STREAM",
      },
    ],
 }

OR

my $res = parse_netstat( output => $output, tcp6 => 1, tcp => 1, udp6 => 1, udp => 1 );

$res would contain information like the above sample output but the array referenced by active_conns would not include any of the entries where the key proto contains "unix",


=head1 DESCRIPTION

This module provides parse_netstat().

=head1 SEE ALSO

=head1 FUNCTIONS

=head2 parse_netstat(%args) -> {status => $int, msg => $str, active_conns => [ %h1, %h2, %h3, ... ]}

Parse the output of Unix "netstat -anp" command.

Arguments ('*' denotes required arguments):

=over 4

=item * B<output>* => I<str>

The output of netstat as a string.

This function only parses program's output. You need to invoke "netstat -anp" on your
own.

=item * B<tcp> => I<bool> (default: 1)

Whether to parse tcp connections.

=item * B<tcp6> => I<bool> (default: 1)

Whether to parse tcp6 connections.

=item * B<udp> => I<bool> (default: 1)

Whether to parse udp connections.

=item * B<udp6> => I<bool> (default: 1)

Whether to parse udp6 connections.

=item * B<unix> => I<bool> (default: 1)

Whether to parse unix connections.

=back

Return value:

Returns an enveloped result (a hash). Key status is an integer containing HTTP status code (200 means OK, 4xx caller error, 5xx function error). Key msg is a string containing error message, or 'OK' if status is 200. Key active_conns is optional, contains an array of hashes of the parsed netstat items.

=head1 AUTHOR

Steven Haryanto <stevenharyanto@gmail.com>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by Steven Haryanto.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


__END__
