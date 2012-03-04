#################################################################################################
#    ISATXT
#################################################################################################
# this script is a part of the log2timeline program.
#
# This is a format file that implements a parser for ISA text export.  In the ISA interface
# after constructing a query in the history to find particular events the user can choose to
# copy all the results to clipbooard, then to open a text editor, such as notepad, and paste
# the content into a file.  This file can then be parsed using log2timeline.
#
# Author: Kristinn Gudjonsson
# Version : 0.4
# Date : 30/04/11
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
package Log2t::input::isatxt;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Time;
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.4';

# version number
my %struct;

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a ISA text export log file";
}

#  init
# This subroutine prepares the log file.  It opens the log file and gives the
# script a handle to the file for further processing.
# @return An integer is returned to indicate whether the file preparation was
#  successful or not.
sub init {
    my $self = shift;
    my $line;
    my @fields;

    # assume that we have UK dates
    # "Using UK style formatting for dates (DD.MM.YYYY) - use with -- -us to modify\n";
    $self->{'uk'} = 1;

# if US then "Using US style formatting for dates (MM.DD.YYYY) - use with --uk (or --nous) to modify \n";

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    $line = <$fh> or return undef;

    # start by finding out the structure
    $line =~ s/\n//g;
    $line =~ s/\r//g;
    @fields = split(/\t/, $line);

    # build the structure
    $struct{count}  = $#fields;
    $struct{fields} = \@fields;

    return 1;
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

#  get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time {
    my $self = shift;

    # log file variables
    my @fields;
    my @words;
    my %li;
    my $date;
    my $date_string;

    # timestamp object
    my %t_line;
    my $text;
    my $uri;
    my @date_split;
    my ($a, $b, $c);
    my $user;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh> or return undef;

    # check line (skip lines containing comments)
    if ($line =~ m/^#/) {

        # comment, let's skip that one
        return \%t_line;
    }
    elsif ($line =~ m/^$/) {

        # empty line
        return \%t_line;
    }

    # remove end of line characters
    $line =~ s/\n//g;
    $line =~ s/\r//g;

    @fields = @{ $struct{fields} };

    #
    # the log file consists of the following fields
    #  Original Client IP
    #  Client Agent
    #  Authenticated Client
    #   Service Server Name
    #  Referring Server
    #  Destination
    #  Host Name
    #  Transport
    #  MIME Type
    #  Object Source
    #  Source Proxy
    #  Destination Proxy
    #  Bidirectional
    #  Client Host Name
    #  Filter Information
    #  Network Interface
    #  Raw IP Header
    #  Raw Payload
    #  GMT Log Time
    #  Source Port
    #  Processing Time Bytes Sent
    #  Bytes Received
    #  Result Code
    #  HTTP Status Code
    #  Cache Information
    #  Error Information
    #  Log Record Type
    #  Authentication Server
    #  Log Time
    #  Destination IP
    #  Destination Port
    #  Protocol
    #  Action
    #  Rule
    #  Client IP
    #  Client Username
    #  Source Network
    #  Destination Network
    #  HTTP Method
    #  URL

    #

    # split the string into variables
    @words = split(/\t/, $line, -1);

    if ($#fields ne $#words) {

        # modify line so that it is divided by | not tab (for easier reading)
        $line =~ s/\t/\|/g;
        print STDERR
          "Error, not correct structure\nMismatch between number of fields in line compared to number of supposed fields in log line\n";
        print STDERR
          "Supposed fields are $#fields yet the line only contains $#words - there might be some disrepencies in the output line\n";
        print STDERR "Logline in question is:\n$line\n";
    }

    # build the text output
    for (my $i = 0; $i < $#words + 1; $i++) {
        $li{ $fields[$i] } = $words[$i];
    }

    # fix the timestamp variable
    # date is of the form YYYY-MM-DD
    # time is of the form HH:MM, HH:MM:SS or HH:MM:SS.S (times provided in GMT)
    # Date is build up like this
    # UK version : D.M.YYYY
    # US version : M.D.YYYY
    @date_split = split(/\s/, $li{'GMT Log Time'});
    ($a, $b, $c) = split(/\./, $date_split[0]);

    if ($self->{uk}) {

        $date_string = sprintf "%4d-%02d-%02dT%sG", $c, $b, $a, $date_split[1];
    }
    else {
        $date_string = sprintf "%4d-%02d-%02dT%sG", $c, $a, $b, $date_split[1];
    }

    # construct the date
    $date = Log2t::Time::iso2epoch($date_string, $self->{'tz'});

    # construct the full URL
    #$text = $li{'Client IP'};

    # create the user name
    if ($li{'Client Username'} ne '-' and $li{'Client Username'} ne '') {
        $user = $li{'Client Username'} . ' (' . $li{'Client IP'} . ')';
    }
    else {
        $user = $li{'Client IP'};
    }
    $user = 'unknown' if $user eq '';

    $text .= 'Connected to ';

    if (($li{'Host Name'} ne '') and ($li{'Host Name'} ne '-')) {
        $text .= $li{'Host Name'} . ' - ';
    }
    else {
        $text .= 'unknown host';
    }

    $text .= ' [' . $li{'Destination IP'} . ':' . $li{'Destination Port'} . ']';

    if (($li{'URL'} ne '') and ($li{'URL'} ne '-')) {
        $text .= ' with URL: ' . $li{'URL'};
    }

    if (($li{'Destination'} ne '') and ($li{'Destination'} ne '-')) {
        $text .= ' destination {' . $li{'Destination'} . '}';
    }

    if (($li{'Referring Server'} ne '') and ($li{'Referring Server'} ne '-')) {
        $text .= ' from referring {' . $li{'Referring Server'} . '}';
    }

    if (($li{'HTTP Method'} ne '') and ($li{'HTTP Method'} ne '-')) {
        $text .= ' using  ' . $li{'HTTP Method'};
    }

    if (($li{'HTTP Status Code'} ne '') and ($li{'HTTP Status Code'} ne '-')) {
        $text .= ' [' . $li{'HTTP Status Code'} . ']';
    }

    $text .= ' - ' . $li{'Action'};

    if (($li{'Client Agent'} ne '') and ($li{'Client Agent'} ne '-')) {
        $text .= ' - ' . $li{'Client Agent'};
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
        'time' => { 0 => { 'value' => $date, 'type' => 'Entry written', 'legacy' => 15 } },
        'desc' => $text,
        'short'      => 'Connecting to: ' . $li{'URL'},
        'source'     => 'ISA',
        'sourcetype' => 'ISA text export',
        'version'    => 2,
        'extra' => { 'user' => $user, 'host' => $li{'Client IP'}, 'size' => $li{'Bytes Received'} }
              );

    return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the log file that is produced by copying a query result
in ISA server 2006 into a text file.  That is first execute a query in ISA, then select to copy
all result to the clipboard, open a text editor (such as notepad) and paste in the result. 
This log file can then be parsed using this format file.

The format file accepts as a parameter
  -uk | -nouk
  -us
    Where uk means UK time, that is DD.MM.YYYY in the date format while
    -us or -nouk means US format, that is MM.DD.YYYY of the resulting log
    file

Be warned that this format file has not been thourougly tested, so please bear that in mind
when using this format file.  Any bug reports are welcome (kristinn ( a t ) log2timeline ( d o t ) net \n";

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
    my $verify_line;
    my $format_line;
    my @words;
    my $tag;
    my $temp;
    my @fields;
    my $c_ip = 0;

    # the default exit value
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    my $ofs = 0;

    #unless( $self->{quick} )
    #{
    #  # do some "prelimenery testing"
    #  seek($self->{file},0,0);
    #  read($self->{file},$temp,1);
    #
    #  # the first line starts with the "original client ip"
    #  return \%return unless $temp eq 'O';
    #}

    # let's continue down the road
    $tag = 1;

    # find a line that is not a comment or an empty line
    while ($tag) {
        $tag = 0
          unless $format_line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 600);
        next if ($format_line =~ m/^#/ or $format_line =~ m/^$/);
        $tag = 0;
    }
    $verify_line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 600);

    # now we have one line of the file, let's read it and verify
    @words = split(/\t/, $format_line);

    for (my $i = 0; $i < $#words; $i++) {
        $c_ip = $i if ($words[$i] =~ m/^Client IP$/);
    }

    # now we examine the first line
    @words = split(/\t/, $verify_line);

    # word count should be equal to the number of fields
    if ($#words eq 40) {

        # verify one variable in the log file, the IP address
        if ($words[$c_ip] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

            # the IP address is correctly formed, let's assume other fields are too
            $return{'success'} = 1;
        }
        else {
            $return{'msg'} = "IP address field [" . $words[$c_ip] . "] not correctly formatted\n";
            $return{'success'} = 0;
        }
    }
    else {
        $return{'msg'}     = "There should be 40 words per line, instead there are $#words\n";
        $return{'success'} = 0;
    }

    return \%return;
}

1;
