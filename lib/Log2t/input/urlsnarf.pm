#################################################################################################
#     URLSNARF
#################################################################################################
# this script is a part of the log2timeline program.
#
# This is a format file that implements a parser for URLSnarf access log files. URLSnarf
# is one of many useful utilities from the dsniff package found here:
# http://monkey.org/~dugsong/dsniff/
# It parses the file and provides the main script with enough information to provide
# a body file that can be used in a timeline analysis
#
# Standard Format:
#
# URLSnarf uses the Common Log Format as defined here:
# http://httpd.apache.org/docs/2.2/logs.html#accesslog
#
# Author: Dan Deighton
# Version: 0.1
# Date: 21/02/12
#
#
# 21/02/12 - Dan: Modifed version 0.3 of apache2_access.pm to handle URLSnarf logs.
# URLSnarf logs do not include 3-digit server status codes, so the RegEx needed to
# be modified to account for this. I also modified the module to reference URLSnarf
# instead of Apache.
#
# Copyright 2012 Dan Deighton (ddeighton ( a t ) aplura (d o t) com)
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

package Log2t::input::urlsnarf;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use DateTime;              # to modify time stamp
use Log2t::Common ':binary';
use Log2t::BinRead;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

my %struct;

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
    return "Parse the content of an URLSnarf log file";
}

#  get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time() {
    my $self = shift;

    # log file variables
    my @date_t;
    my @date_m;
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
    $line =~ s/\s+/ /g;

    # empty lines, skip them
    if ($line =~ m/^$/ or $line =~ m/^\s+$/) {
        return \%t_line;
    }

#
# the log file consists of the following fields
#
# Client IP Address  c-ip  The IP address of the client that made the request.  Y
# User Name  cs-username  The name of the authenticated user who accessed your server. Anonymous users are indicated by a hyphen.  Y # RFC 1413 identity of client.
# Userid userid The userid/REMOTE_USER environment variable of the person requesting document.
# Date  date  The date on which the activity occurred.  Y
# Time  time  The time, in coordinated universal time (UTC), at which the activity occurred.  Y
# Method  cs-method  The requested action, for example, a GET method.  Y
# URI Stem  cs-uri-stem  The target of the action, for example, Default.htm.  Y
# URI Query  cs-uri-query  The query, if any, that the client was trying to perform. A Universal Resource Identifier (URI) query is necessary only for dynamic pages.  Y
# HTTP Status  sc-status  The HTTP status code.  Y
# Bytes Sent  sc-bytes  The number of bytes that the server sent.  N
# Bytes Received  cs-bytes  The number of bytes that the server received.  N
# Referrer  cs(Referrer)  The site that the user last visited. This site provided a link to the current site.  N
# User Agent  cs(User-Agent)  The browser type that the client used.  Y

# The default variables are therefore:
#
#   c-ip
#   cs-username
#  userid
#   date
#   time
#  cs-request
#   cs-method
#   cs-uri-stem
#  cs-uri-query
#  sc-status
#  sc-bytes
#  cs-bytes
#  cs(Referrer)
#  cs(User-Agent)
#
#        ip     id    aid     day   month   year    hr  min sec           tz       req    code  sz   ref     usrag
#  /^[0-9\.]+ [^\s]+ [^\s]+ \[\d\d\/\w\w\w\/\d\d\d\d:\d\d:\d\d:\d\d [\+\-]\d\d\d\d\] "[^"]+" \d\d\d \d+ "[^"]+" "[^"]+".*/

#print "parsing line\n";
#$line =~ m/^$w $w $w \[$w:$w $w\] "$w $w $w" $w $w "$w" "$w"/;
# 127.0.0.1 - - [24/Jun/2010:22:02:28 -0400] "GET /pagead/test_domain.js HTTP/1.1" 404 336 "http://docstore.mik.ua/orelly/perl/cookbook/ch20_13.htm" "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.19) Gecko/2010040118 Ubuntu/8.10 (intrepid) Firefox/3.0.19"

    if ($line =~
        /^([0-9\.]+) ([^\s]+) ([^\s]+) \[(\d+)\/(\w\w\w)\/(\d+):(\d+):(\d+):(\d+) ([\+\-]\d+)\] "([^"]+)" ([\d-]+) ([\d-]+) "([^"]+)" "([^"]+)".*/
       )
    {
        $li{'c-ip'}           = $1;
        $li{'cs-username'}    = $2;
        $li{'userid'}         = $3;
        $li{'day'}            = $4;
        $li{'month'}          = lc($5);
        $li{'year'}           = $6;
        $li{'hour'}           = $7;
        $li{'min'}            = $8;
        $li{'sec'}            = $9;
        $li{'tz'}             = $10;
        $li{'cs-request'}     = $11;
        $li{'sc-status'}      = $12;
        $li{'sc-bytes'}       = $13;
        $li{'cs(Referer)'}    = $14;
        $li{'cs(User-Agent)'} = $15;

        print STDERR "[URLSNARF] IP:", $li{'c-ip'}, ' USERNAME:', $li{'cs-username'}, ' USERID:',
          $li{'userid'}, ' DAY:', $li{'day'}, ' M:[', $li{'month'}, '] Y:', $li{'year'}, ' H:',
          $li{'hour'}, ' M:', $li{'min'}, ' S:', $li{'sec'}, ' TZ:', $li{'tz'}, ' Request:',
          $li{'cs-request'}, ' Status:', $li{'sc-status'}, ' Bytes:', $li{'sc-bytes'}, ' REF:',
          $li{'cs(Referer)'}, ' UA:', $li{'cs(User-Agent)'}, "\n"
          if $self->{'debug'};

        #                            GET "/home/index.html" HTTP/1.1
        #                             |           |
        #                             V           V
        if ($li{'cs-request'} =~ m/^([^\s]+)\s+([^\s]+)\s+.*$/) {
            $li{'cs-method'} = $1;
            $li{'cs-uri'}    = $2;

            #                               /home/dir/index.html?param=value
            #                                 |            |       |
            #                                 V            V       V
            if ($li{'cs-uri'} =~ m/^(([^\/]*\/)+)?([^\?\/]+)(\?.*)?$/) {
                $li{'cs-uri-dir'}      = $1;
                $li{'cs-uri-basename'} = $3;
                $li{'cs-uri-stem'}     = $1;
                $li{'cs-uri-query'}    = $4;
            }
        }

        # TODO
        #$li{'sec'} = Log2t::roundup( $li{'sec'} );\

        if ($li{'month'} eq 'jan') {
            $li{'month'} = 1;
        }
        elsif ($li{'month'} eq 'feb') {
            $li{'month'} = 2;
        }
        elsif ($li{'month'} eq 'mar') {
            $li{'month'} = 3;
        }
        elsif ($li{'month'} eq 'apr') {
            $li{'month'} = 4;
        }
        elsif ($li{'month'} eq 'may') {
            $li{'month'} = 5;
        }
        elsif ($li{'month'} eq 'jun') {
            $li{'month'} = 6;
        }
        elsif ($li{'month'} eq 'jul') {
            $li{'month'} = 7;
        }
        elsif ($li{'month'} eq 'aug') {
            $li{'month'} = 8;
        }
        elsif ($li{'month'} eq 'sep') {
            $li{'month'} = 9;
        }
        elsif ($li{'month'} eq 'oct') {
            $li{'month'} = 10;
        }
        elsif ($li{'month'} eq 'nov') {
            $li{'month'} = 11;
        }
        elsif ($li{'month'} eq 'dec') {
            $li{'month'} = 12;
        }
        else {

            # no valid month
            print STDERR "[APACHE ACCESS] Not a valid month: $li{'month'}\n" if $self->{'debug'};
            return \%t_line;
        }

        # construct a hash of the date
        %date = (
            year      => $li{'year'},
            month     => $li{'month'},
            day       => $li{'day'},
            hour      => $li{'hour'},
            minute    => $li{'min'},
            time_zone => $li{'tz'}
            , # timezone is given in local timezone with the indication of how to get the GMT/UTC time from them
            second => $li{'sec'}
                );

        $date_s = DateTime->new(\%date);
        $date_e = $date_s->epoch;

        print STDERR "[URLSNARF] Date after calculation (epoch) $date_e - month: $li{'month'}\n"
          if $self->{'debug'};

        # construct the full URL
        $uri = $li{'cs-uri'};

        # start constructing the text
        if (exists $li{'s-computername'}) {
            $text .= '<' . $li{'s-computername'} . '> ';
        }

        $text .= "Connect to '";

        if (exists $li{'cs-host'}) {
            $text .= " [host " . $li{'cs-host'} . "]";
        }

        $text .=
            $uri
          . "' using "
          . $li{'cs-method'}
          . ".  User agent: ["
          . $li{'cs(User-Agent)'}
          . '], status code '
          . $li{'sc-status'};

        if (exists $li{'cs-username'}) {
            if ($li{'cs-username'} ne '-') {
                $text .= ' Authenticated user: ' . $li{'cs-username'};
            }
        }

        if (exists $li{'cs(Referer)'} && $li{'cs(Referer)'} ne '-') {
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
               'source'     => 'URLSnarf',
               'sourcetype' => 'URLSnarf Log File',
               'version'    => 2.4,
               'extra'      => {
                            'user'   => $li{'userid'},
                            'host'   => $li{'c-ip'},
                            'src-ip' => $li{'c-ip'},
                            'dst-ip' => $li{'s-ip'},
                            'size'   => $li{'cs-bytes'}
                          }
                  );

        return \%t_line;
    }
    else {
        print STDERR "Error, not correct structure ($line)\n" if $self->{'debug'};
    }
    return;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the URLSnarf log file. URLSnarf uses the common log 
format, however the 3-digit server response code is replaced by a " - ". To see the 
definition of the log format, please see:
http://httpd.apache.org/docs/2.2/logs.html#accesslog
Use with the FILE option as the URLSnarf log file\n
\t$0 -f urlsnarf ex...log

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
# The correct format of an URLSnarf file can be found at:
# http://httpd.apache.org/docs/2.2/logs.html#accesslog
# which  is
# ip/userid/authorized-user/date/request/code/size/referer/useragent
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#  string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $tag;
    my $c_ip = 2;
    my $temp;
    my @fields;

# defines the maximum amount of lines that we read until we determine that we do not have an URLSnarf file
    my $max = 15;
    my $i   = 0;

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%return unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # now we need to continue testing our file
    $tag = 1;
    $ofs = 0;

    # begin with finding the line that defines the fields that are contained
    while ($tag) {

        # 200 letters are not enough for each line, make it 400
        $tag = 0 unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);
        next if ($line =~ m/^#/ or $line =~ m/^$/);
        $tag = 0 if $i++ eq $max;    # check if we have reached the end of our attempts
        next unless $tag;

# corrected the regular expression a bit, to make it more accurate
#if ($line =~ /^([0-9\.]+) ([^\s]+) ([^\s]+) \[(\d\d)\/(\w\w\w)\/(\d\d\d\d):(\d\d):(\d\d):(\d\d) ([\+\-]\d\d\d\d)\] "([^"]+)" (\d\d\d) (\d+) "([^"]+)" "([^"]+)".*/ )
        if ($line =~
            /^([0-9\.]+) ([^\s]+) ([^\s]+) \[(\d+)\/(\w\w\w)\/(\d+):(\d+):(\d+):(\d+) ([\+\-]\d+)\] "([^"]+)" ([\d-]+) ([\d-]+) "([^"]+)" "([^"]+)".*/
           )
        {
            $return{'success'} = 1;
            return \%return;
        }
    }
    $return{'msg'}     = "None of the first $max lines fit the format of URLSnarf logs.";
    $return{'success'} = 0;

    return \%return;
}

1;
