#################################################################################################
#    BlueCoat
#################################################################################################
# this script is a part of the log2timeline program.
#
# This is an input mdoule that implements a parser for BlueCoat log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# This module is based on the iis.pm module.
#
# http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/be22e074-72f8-46da-bb7e-e27877c85bca.mspx
#
# W3C Extended Log File Fields
# http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/676400bc-8969-4aa7-851a-9319490a9bbb.mspx
#
# Format:
# http://www.loganalyzer.net/log-analyzer/w3c-extended.html
# http://www.w3.org/TR/WD-logfile.html
#
# In Debian install:
#   apt-get install libdatetime-perl
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 25/04/12
#
# Copyright 2009-2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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
package Log2t::input::iis;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use DateTime;              # to modify time stamp
use Log2t::Common ':binary';
use Log2t::BinRead;
use Text::CSV;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

my %struct;

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a Bluecoat log file";
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose
# just the way it is defined right now.
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#  parse_line
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time {
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
    my $uri;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh> or return undef;

    # check line
    if ($line =~ m/^#/) {

        # comment, let's skip that one
        return \%t_line;
    }
    elsif ($line =~ m/^$/) {

        # empty line, skip that one as well
        return \%t_line;
    }

    # substitute multiple spaces with one for splitting the string into variables
    $line =~ s/\s+/ /g;

    @fields = @{ $struct{fields} };
    # The following fields are available:
    # 0: date
    # 1: time
    # 2: time-taken
    # 3: c-ip
    # 4: cs-username
    # 5: cs-auth-group
    # 6: x-exception-id
    # 7: sc-filter-result
    # 8: cs-categories
    # 9: cs(Referer)
    # 10: sc-status
    # 11: s-action
    # 12: cs-method
    # 13: rs(Content-Type)
    # 14: cs-uri-scheme
    # 15: cs-host
    # 16: cs-ip
    # 17: cs-uri-port
    # 18: cs-uri-path
    # 19: cs-uri-query
    # 20: cs-uri-extension
    # 21: cs(User-Agent)
    # 22: s-ip
    # 23: sc-bytes
    # 24: cs-bytes
    # 25: x-virus-id

    # split the string into variables
    @words = split(/,/, $line);

    if ($#fields ne $#words) {
        print STDERR "Error, not correct structure\n";
        return \%t_line;
    }

    # build the text output
    for (my $i = 0; $i < $#words; $i++) {
        $li{ $fields[$i] } = $words[$i];
    }

    # date is of the form YYYY-MM-DD
    # time is of the form HH:MM:SS in GMT

    if (defined $li{'time'}) {
        @date_t = split(/:/, $li{'time'});
    }
    else {
        return \%t_line;
    }

    # check for the date field
    if (defined $li{'date'}) {
        @date_m = split(/-/, $li{'date'});
    }
    else {
        return \%t_line;
    }

    # construct a hash of the date
    %date = (
             year      => $date_m[0],
             month     => $date_m[1],
             day       => $date_m[2],
             hour      => $date_t[0],
             minute    => $date_t[1],
             second    => $date_t[2],
             time_zone => 'UTC'         # BlueCoat is always recorded in UTC
            );

    $date_s = DateTime->new(\%date);
    $date_e = $date_s->epoch;

    #0 2011-11-04
    #1 10:14:02
    #2 12
    #3 172.16.132.77
    #4 -
    #5 -
    #6 -
    #7 OBSERVED
    #8 Computers/Internet
    #9 -
    #10 304
    #11 TCP_HIT
    #12 GET
    #13 application/pkix-crl
    #14 http
    #15 crl.microsoft.com
    #16 63.97.94.40
    #17 80
    #18 /pki/crl/products/tspca.crl
    #19 -
    #20 crl
    #21 Microsoft-CryptoAPI/6.0
    #22 165.224.254.228
    #23 450
    #24 259
    #25 -

    #x 0: date
    #x 1: time
    # 2: time-taken
    # 3: c-ip
    # 4: cs-username
    # 5: cs-auth-group
    # 6: x-exception-id
    # 7: sc-filter-result
    # 8: cs-categories
    # 9: cs(Referer)
    # 10: sc-status
    # 11: s-action
    # 12: cs-method
    # 13: rs(Content-Type)
    # 14: cs-uri-scheme
    # 15: cs-host
    # 16: cs-ip
    # 17: cs-uri-port
    # 18: cs-uri-path
    # 19: cs-uri-query
    # 20: cs-uri-extension
    # 21: cs(User-Agent)
    # 22: s-ip
    # 23: sc-bytes
    # 24: cs-bytes
    # 25: x-virus-id


    # construct the full URL
    $uri = $li{'cs-uri-stem'};
    if (exists $li{'cs-uri-query'}) {
        if ($li{'cs-uri-query'} ne '-') {
            $uri .= '?' . $li{'cs-uri-query'};
        }
    }

    # start constructing the text
    if (exists $li{'s-computername'}) {
        $text .= '<' . $li{'s-computername'} . '> ';
    }

    $text .= $li{'c-ip'} . " connect to '" . $li{'s-ip'} . ":" . $li{'s-port'} . "'";

    if (exists $li{'cs-host'}) {
        $text .= " [host " . $li{'cs-host'} . "]";
    }

    $text .=
        " URI: "
      . $li{'cs-method'} . ' '
      . $uri
      . " using "
      . $li{'cs(User-Agent)'}
      . ', status code '
      . $li{'sc-status'};

    if (exists $li{'cs-username'}) {
        if ($li{'cs-username'} ne '-') {
            $text .= ' Authentiacted user: ' . $li{'cs-username'};
        }
    }

    if (exists $li{'cs(Referer)'}) {
        $text .= ' Came from site: ' . $li{'cs(Referer)'};
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
               'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
               'desc'       => $text,
               'short'      => 'URL: ' . $uri,
               'source'     => 'IIS',
               'sourcetype' => 'IIS Log File',
               'version'    => 2,
               'extra'      => {
                            'user'   => $li{'c-ip'},
                            'host'   => $li{'s-ip'},
                            'src-ip' => $li{'s-ip'},
                            'dst-ip' => $li{'c-ip'},
                            'size'   => $li{'cs-bytes'}
                          }
              );

    return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the IIS W3C log file. To see the definition of the 
log format, please see:
http://www.w3.org/TR/WD-logfile.html
Use with the FILE option as the W3C log file\n
\t$0 -f iis ex...log

This format file depends upon the library
  DateTime
for converting date variables to epoch time. Possible to install using
perl -MCPAN -e shell
(when loaded)
install DateTime\n";

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
    my $cs_ip = 16;
    my $temp;
    my @fields;

    %struct = undef;    # initialize the struct hash

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    return \%return unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    unless ($self->{'quick'}) {

        # we know that a bluecoat file starts with d, so let's start with that
        seek($self->{'file'}, 0, 0);
        read($self->{'file'}, $temp, 1);
        $return{'msg'} = 'Not the correct magic value';
        return \%return unless $temp eq 'd';
    }

    # now we need to continue testing our file
    $tag = 1;
    $ofs = 0;

    # read in a single line (the header)
    $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 350);

    return \%return unless $line;

    # check the header value
    $return{'msg'} = "Wrong magic value";
    return \%return unless $line =~ m/^date,time,time-taken,c-ip,cs-username,cs-auth-group,x-exception-id,sc-/;

    @fields = split(/,/, $line);

    # define the number of fields
    $struct{count} = $#fields;

    # find the c-ip field
    for (my $i = 0; $i < $#fields; $i++) {
      $cs_ip = $i if ($fields[$i] =~ m/^x-virus-id$/);
    }

    # the structure is here, let's include it
    $struct{fields} = \@fields;

    # read in one more line (actual data this time)
    $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 350);

    # now we have one line of the file, let's read it and verify
    @words = '';
    @words = split(/,/, $line);

    # word count should be equal to the number of fields
    if ($#words eq $struct{count}) {

        # verify one variable in the log file, the IP address
        if ($words[$cs_ip] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

            # the IP address is correctly formed, let's assume other fields are too
            $return{'success'} = 1;
        }
        else {
            $return{'msg'} = "IP address field [" . $words[$cs_ip] . "] not correctly formatted\n";
            $return{'success'} = 0;
        }
    }
    else {
        $return{'msg'} =
          "There should be $struct{count} words per line, instead there are $#words\n";
        $return{'success'} = 0;
    }

    return \%return;
}

1;
