#################################################################################################
#    XP Firewall
#################################################################################################
# this script is a part of the log2timeline program.
#
# It implements a parser for Windows XP firewall logs
#
# Author: Kristinn Gudjonsson
# Version : 0.4
# Date : 03/03/10
#
# Copyright 2009-2010 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::input::xpfirewall;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use DateTime;              # to modify time stamp
use Log2t::Numbers;
use Log2t::Network;
use Log2t::BinRead;
use Log2t::Common ':binary';
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.4';

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose
# just the way it is defined right now.
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a XP Firewall log";
}

#  get_time
# This is the main "juice" of the input module. It parses the input file
# and produces a timestamp object that get's returned
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time() {
    my $self = shift;

    # log file variables
    my @date_t;
    my @date_m;
    my @fields;
    my @words;
    my %li;
    my %date;
    my $date_e;
    my $date_s;

    # the timestamp object
    my %t_line;
    my $text;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh>;
    if (not $line) {
        print STDERR "[FIREWALL] No more lines to read in.\n" if $self->{'debug'};
        return undef;
    }

    #print "READING LINE: $line\n" if $self->{'debug'};

    # check line, to see if there are any comments or other such non-related stuff
    if ($line =~ m/^#/) {

        # comment, let's skip that one
        return \%t_line;
    }
    elsif ($line =~ m/^$/ or $line =~ m/^\s+$/) {
        return \%t_line;
    }

    # substitute multiple spaces with one for splitting the string into variables
    $line =~ s/\s+/ /g;

    @fields = @{ $self->{'fields'} };

    #
    # the log file consists of the following fields
    #
    # Date  date  The date on which the activity occurred.  Y
    # Time  time  The time, as defined in the header , at which the activity occurred.  Y
    # action
    # protocol
    # src-ip
    # dst-ip
    # src-port
    # dst-port
    # size
    # tcpflags
    # tcpsyn
    # tcpack
    # tcpwin
    # icmptype
    # icmpcode
    # info
    #
    # Default value of non-used fields is the value -

    # split the string into variables
    @words = split(/\s/, $line);

    if ($#fields ne $#words) {
        print STDERR "Error, not correct structure\n";
    }

    # build the text output
    for (my $i = 0; $i < $#words; $i++) {
        $li{ $fields[$i] } = $words[$i];
    }

    # fix the timestamp variable
    # date is of the form YYYY-MM-DD
    # time is of the form HH:MM, HH:MM:SS or HH:MM:SS.S (times provided in GMT)
    @date_t = split(/:/, $li{time});
    @date_m = split(/-/, $li{date});

    # construct a hash of the date
    %date = (
        year      => $date_m[0],
        month     => $date_m[1],
        day       => $date_m[2],
        hour      => $date_t[0],
        minute    => $date_t[1],
        time_zone => $self->{
            'zone'}    # XP Firewall uses UTC as the timestamp, unless otherwise defined in header
    );

    # check the format of the date_t (time) variable, for additional information
    if ($#date_t eq 2) {
        $date{second} = Log2t::Numbers::roundup($date_t[2]);
    }
    else {
        print STDERR "[WIN FIREWALL] Missing seconds, accuracy is therefore up to the minute ("
          . $li{'time'} . ")\n"
          if $self->{'debug'};
    }

    $date_s = DateTime->new(\%date) or return '';
    $date_e = $date_s->epoch;

    # start constructing the text
    $text = $li{'action'};

    # check the protocol
    if ($li{'protocol'} eq 'ICMP') {

        # ICMP
        $text .= ' ' . $li{'protocol'};

        # get the result
        my $res = Log2t::Network::get_icmp_text($li{'icmptype'}, $li{'icmpcode'});

        $text .= ' '
          . $res->{type} . ' - '
          . $res->{code}
          . ' SRC: '
          . $li{'src-ip'} . ' > '
          . $li{'dst-ip'};

    }
    elsif ($li{'protocol'} eq 'TCP') {

        # TCP
        $text .=
          ' ' . $li{'protocol'} . ' flags [' . $li{'tcpflags'} . '] window size: ' . $li{'tcpwin'};
        $text .= ' '
          . $li{'src-ip'} . ':'
          . $li{'src-port'} . ' > '
          . $li{'dst-ip'} . ':'
          . $li{'dst-port'}
          . ' TCP seq ['
          . $li{'tcpsyn'} . ']';
    }
    else {

        # UDP
        $text .= ' '
          . $li{'protocol'} . ' '
          . $li{'src-ip'} . ':'
          . $li{'src-port'} . ' > '
          . $li{'dst-ip'} . ':'
          . $li{'dst-port'};
    }

    if ($li{'info'} ne '-') {
        $text .= ' [' . $li{'info'} . ']';
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
               'time' => { 0 => { 'value' => $date_e, 'type' => 'Time Written', 'legacy' => 15 } },
               'desc'       => $text,
               'short'      => $li{'action'} . ' from: ' . $li{'src-ip'},
               'source'     => 'LOG',
               'sourcetype' => 'XP Firewall Log',
               'version'    => 2,
               'extra'      => {
                            'user'   => $li{'src-ip'},
                            'src-ip' => $li{'src-ip'},
                            'host'   => $li{'src-ip'},
                            'size'   => $li{'size'},
                            'dst-ip' => $li{'dst-ip'}
                          }
              );

    return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the XP firewall log.";
}

#  verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# The correct format of a Squid access file (with httpd_emulate equal to off) is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#  string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $tag;
    my $src_ip = 5;
    my $temp;
    my @fields;

# defines the maximum amount of lines that we read until we determine that we do not have a IIS file
    my $max = 15;
    my $i   = 0;

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # set the default time zone
    $self->{'zone'} = 'UTC';

    my $ofs = 0;

    # open the file (at least try to open it)
    eval {
        unless ($self->{'quick'})
        {

            # a firewall log file should start with a comment, or #, let's verify that
            seek($self->{'file'}, 0, 0);
            read($self->{'file'}, $temp, 1);
            $return{'msg'} = 'Wrong magic value';
            return \%return unless $temp eq '#';
        }

        $tag = 1;

        # begin with finding the line that defines the fields that are contained
        while ($tag) {
            $tag = 0
              unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);
            $tag = 0 if $i++ eq $max;    # check if we have reached the end of our attempts
            next unless $tag;

            $line =~ s/\n//;
            $line =~ s/\r//;

            if ($line =~ m/^#Fields/) {
                $tag = 0;

                # read the line to get the number of fields
                $line =~ s/\s+/ /g;

                @fields = split(/\s/, $line);

                # first word is the #Fields: line, let's skip that
                $temp = shift(@fields);

                # define the number of fields
                $self->{'count'} = $#fields;

                # find the c-ip field
                for (my $i = 0; $i < $#fields; $i++) {
                    $src_ip = $i if ($fields[$i] =~ m/^src-ip$/);
                }
            }
            elsif ($line =~ m/#Time Format/) {
                my $a;
                ($a, $self->{'zone'}) = split(/:/, $line);
                $self->{'zone'} =~ s/\s//g;

                if (lc($self->{'zone'}) eq 'local') {

                    # get the local timezone
                    $self->{'zone'} = $self->{'tz'};
                }
            }
        }

        # the structure is here, let's include it
        $self->{'fields'} = \@fields;

        # reset tag
        $tag = 1;

        # find a line that is not a comment or an empty line
        while ($tag) {
            $tag = 0
              unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);
            $line =~ s/\s+/ /g;
            next if ($line =~ m/^#/ or $line =~ m/^$/ or $line =~ m/^ $/);
            $tag = 0;
        }
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file ($@)";

        return \%return;
    }

    # now we have one line of the file, let's read it and verify
    # remove unneeded spaces
    $line =~ s/\s+/ /g;
    @words = '';
    @words = split(/\s/, $line);

    # word count should be equal to the number of fields
    if ($#words eq $self->{'count'}) {

        # verify one variable in the log file, the IP address
        if ($words[$src_ip] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

            # the IP address is correctly formed, let's assume other fields are too
            $return{'success'} = 1;
        }
        else {
            $return{'msg'} = "IP address field [" . $words[$src_ip] . "] not correctly formatted\n";
            $return{'success'} = 0;
        }
    }
    else {
        $return{'msg'} =
          "There should be " . $self->{'count'} . " words per line, instead there are $#words\n";
        $return{'success'} = 0;
    }

    return \%return;
}

1;
