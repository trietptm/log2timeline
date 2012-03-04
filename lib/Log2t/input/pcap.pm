#################################################################################################
#    PCAP
#################################################################################################
# This is a PCAP parser, that is a parser that reads a pacp file to produce a timeline
# data extracted from the traffic
#
# In Debian install the package
#  libnet-pcap-perl
#
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 04/05/11
#
# Copyright 2009-2011 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
#
#  This file is part of log2timeline.
#
#    log2timeline is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    log2timeline is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.

package Log2t::input::pcap;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.5';

sub new {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # add to the self object
    $self->{'flags'} = {
                         0x01 => 'FIN',
                         0x02 => 'SYN',
                         0x04 => 'RESET',
                         0x08 => 'PUSH',
                         0x10 => 'ACK',
                         0x20 => 'URGENT',
                         0x40 => 'ECN-ECHO',
                         0x80 => 'CWR'
                       };

    $self->{'file_access'} =
      1;    # do we need to parse the actual file or is it enough to get a file handle

    bless($self, $class);

    return $self;
}

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number

sub get_version() {
    return $VERSION;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a PCAP file";
}

#       init
# This subroutine starts by ..
#
#
# @params One parameter is defined, the path to the Prefetch directory
# @return An integer is returned to indicate whether the file preparation was
#       successful or not.
sub init {
    my $self = shift;
    my $err;
    my ($filter, $filter_c);

    # open the access file and read all the lines
    $self->{'packets'} = Net::Pcap::open_offline(${ $self->{'name'} }, \$err);
    if (defined $err) {
        print STDERR '[ERROR] Unable to read the PCAP file: ', $err, "\n";
        return 0;
    }

    if (defined $filter) {

        # create the filter
        Net::Pcap::setfilter($self->{'packets'}, $filter_c);
        Net::Pcap::compile($self->{'packets'}, \$filter_c, $filter, 1, undef);
    }

    return 1;
}

#       end
# A subroutine that closes the file, after it has been parsed
# @return An integer indicating that the close operation was successful
sub end {
    my $self = shift;

    # close the network file (since we have finished our processing)
    Net::Pcap::close($self->{'packets'}) if defined $self->{'packets'};

    return 1;
}

#       get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file

sub get_time {
    my $self = shift;

    my %t_line;
    my ($ether, $ip, $trans);
    my $fcheck;
    my $text = '';
    my %hdr;
    my $packet;

    # get the next packet
    return undef unless $packet = Net::Pcap::next($self->{'packets'}, \%hdr);

    # we have a packet ($packet) to examine
    $ether = NetPacket::Ethernet->decode($packet);
    $ip    = NetPacket::IP->decode($ether->{'data'});

    # check if TCP or UDP
    if ($ip->{'proto'} eq 6) {

        # TCP
        $trans = NetPacket::TCP->decode($ip->{'data'});

        # we don't care about ECN bits
        $fcheck = $trans->{'flags'} & 0x3f;

        # check if we have a SYN packet
        if ($fcheck == 0x02) {
            $text .= 'TCP SYN packet';
        }
        else {
            $text .= 'TCP packet flags [' . sprintf("0x%x", $trans->{'flags'}) . ': ';

            foreach (keys %{ $self->{'flags'} }) {
                $text .= $self->{'flags'}->{$_} . ' ' if (($trans->{'flags'} & $_) == $_);
            }
            $text .= '] ';
        }

        $text .=
            $ip->{'src_ip'} . ':'
          . $trans->{'src_port'} . ' -> '
          . $ip->{'dest_ip'} . ':'
          . $trans->{'dest_port'}
          . ' seq ['
          . $trans->{'seqnum'} . ']';

    }
    elsif ($ip->{'proto'} eq 17) {

        # UDP
        $trans = NetPacket::UDP->decode($ip->{'data'});
        $text .=
            'UDP packet '
          . $ip->{'src_ip'} . ':'
          . $trans->{'src_port'} . ' -> '
          . $ip->{'dest_ip'} . ':'
          . $trans->{'dest_port'};
    }
    elsif ($ip->{'proto'} eq 1) {
        $text .= 'ICMP packet ' . $ip->{'src_ip'} . ' -> ' . $ip->{'dest_ip'};
    }
    else {
        $text .=
          'IP packet protocol ' . $ip->{'proto'} . ' ' . $ip->{'src_ip'} . '->' . $ip->{'dest_ip'};
    }

    # content of array t_line ([optional])
    # %t_line {        #       time
    #               index
    #                       value
    #                       type
    #                       legacy
    #       desc
    #       short
    #       source
    #       sourcetype
    #       version
    #       [notes]
    #       extra
    #               [filename]
    #               [md5]
    #               [mode]
    #               [host]
    #               [user]
    #               [url]
    #               [size]
    #               [...]
    # }

    # create the t_line variable
    %t_line = (
         'time' => { 0 => { 'value' => $hdr{'tv_sec'}, 'type' => 'Time Written', 'legacy' => 15 } },
         'desc'       => $text,
         'short'      => $text,
         'source'     => 'NEt',
         'sourcetype' => 'PCAP file',
         'version'    => 2,
         'extra' =>
           { 'host' => $ip->{'src_ip'}, 'src-ip' => $ip->{'src_ip'}, 'dst-ip' => $ip->{'dst_ip'} }
    );

    return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This plugin parses a PCAP file and displays timeline data extracted from the file.
What the parser does is to display timeline data from every packet that it sees.\n";

#What the parser does is to display timeline data about all non-TCP packets as well as all TCP SYN
#packets (displaying in the content whether or not the connection was successful (full TCP handshake) or
#just an attempt to create a connection.\n";

}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $magic;
    my $temp;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    return \%return unless -f ${ $self->{'name'} };

    # try to read from the file
    eval {
        seek($self->{'file'}, 0, 0);
        read($self->{'file'}, $temp, 4);
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    # now we have one line of the file, let's read it and verify
    # and here we have an error checking routine... (witch success = 1 if we are able to verify)
    $magic = unpack("V", $temp);

    # verify the magic value
    $return{'success'} = 1 if $magic eq 0xa1b2c3d4;
    $return{'msg'} = 'Wrong magic value, not really a pcap file' unless $return{'success'};

    return \%return;
}

1;

__END__

=pod

=head1 NAME

lesa inn alla TCP SYN (0x02) pakka og svo adra sem eru ekki TCP

nota next til ad lesa pakkana

ef um er ad raeda TCP pakka, tha skoda adeins tenginguna (bara SYN,  eda TOKST tenging)

