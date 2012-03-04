#################################################################################################
#    MSSQL_ERRLOG
#################################################################################################
# This script parses the MS SQL ERRLOG files
#
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
#
# Author: Kristinn Gudjonsson
# Version : 0.2
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
package Log2t::input::mssql_errlog;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;           # to manipulate time

#use Log2t::Win;  # Windows specific information
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;    # methods to read binary files (it is preferable to always load this library)

#use Log2t::Network;  # information about network traffic
use DateTime;

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# indicate the version number of this input module
$VERSION = '0.2';

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of an ERRORLOG file produced by MS SQL server";
}

#       init
#
# The purpose of this subfunction is to prepare the log file or artifact for parsing
# Usually this involves just opening the file (if plain text) or otherwise building a
# structure that can be used by other functions
#
# This function also accepts parameters for processing (for changing some settings in
# the input module)
#
# @params A path to the artifact/log file/directory to prepare
# @params The rest of the ARGV array containing parameters to be passed to the input module
# @return An integer is returned to indicate whether the file preparation was
#       successful or not.
sub init {

    # read the paramaters passed to the script
    my $self = shift;

    # default values
    # variable to store the line we are reading
    my $vline;

    # initialize the old_date and other variables
    $self->{'old_date'}    = undef;
    $self->{'line_loaded'} = 0;
    $self->{'ofs'}         = 0;

    # read the next line in the log file (and until we hit an empty line)
    $vline = Log2t::BinRead::read_unicode_until($self->{'file'}, \$self->{'ofs'}, "\n", 400);

    $vline =~ s/\n//g;
    $vline =~ s/\r//g;

    # go through the lines until we hit an empty line, and stop there
    while ($vline ne "") {
        $self->{'server'}->{'extra'} .= $vline . ' ';

        print STDERR "[PREPARE MSSQL] Pre-reading line ($vline)\n" if $self->{'debug'};

        # read another line from the log file
        $vline = Log2t::BinRead::read_unicode_until($self->{'file'}, \$self->{'ofs'}, "\n", 400);
        $vline =~ s/\n//g;
        $vline =~ s/\r//g;
    }

    print STDERR "[PREPARE MSSQL] Extra information about server: "
      . $self->{'server'}->{'extra'} . "\n"
      if $self->{'debug'};

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

#       get_time
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
#
# @return Returns a reference to a hash containing the needed values to print a body file
sub get_time {
    my $self = shift;

    # timestamp object
    my %t_line;
    my $text  = '';
    my $title = '';
    my $date  = undef;
    my $d     = undef;
    my $s;
    my $info;
    my $line;

    # check if there is a line already loaded up and ready to be parsed
    if ($self->{'line_loaded'}) {
        $self->{'line_loaded'}  = 0;
        $line                   = $self->{'line_content'};
        $self->{'line_content'} = undef;
    }
    else {

        # read the line until we hit the end
        return undef
          unless $line =
              Log2t::BinRead::read_unicode_until($self->{'file'}, \$self->{'ofs'}, "\n", 400);
    }

# an example line
# 2010-12-16 13:32:03.76 Server      SQL Server is starting at normal priority base (=7). This is an informational message only. No user action is required.

    # we might have several lines containing the same timestamps, so let's parse them all

# parse the line, get the timestamps, etc. (start with the first line that got passed on to this function
#  if( $line =~ m/^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2})\.\d{1-4}\s([a-zA-Z0-9\-_]+)\s+(\.+)$/ )
    if ($line =~
        m/^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2}).\d{1,6}\s(\w+)\s+(.+)$/)
    {

        # get the date
        $d = new DateTime(
                          'year'      => $1,
                          'month'     => $2,
                          'day'       => $3,
                          'hour'      => $4,
                          'minute'    => $5,
                          'second'    => $6,
                          'time_zone' => $self->{'tz'}
                         );

        # set the old date to the current one
        $self->{'old_date'} = "$1-$2-$3 $4:$5:$6";
        $date = $d->epoch;

        $s     = $7;
        $info  = $8;
        $title = "($7) $8";

        print STDERR "[PARSE MSSQL] Date ($date) - $title\n" if $self->{'debug'};
    }
    else {
        print STDERR "[MSSQL] Line did not pass requirements ($line)\n" if $self->{'debug'};
        return \%t_line;
    }

    my $same = 1;
    while ($same) {

        # now go through the rest of the lines (read in a new one)
        $line = Log2t::BinRead::read_unicode_until($self->{'file'}, \$self->{'ofs'}, "\n", 400);

        # check if we have reached the end of the file
        $same = 0 unless defined $line;
        next unless $same;

        print STDERR "[PARSE MSSQL] Reading and comparing ($line)\n" if $self->{'debug'};

#if( $line =~ m/^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2})\.\d{1-4}\s([a-zA-Z0-9\-_]+)\s+(\.+)$/ )
        if ($line =~
            m/^(\d{4})-(\d{1,2})-(\d{1,2}) (\d{1,2}):(\d{1,2}):(\d{1,2}).\d{1,6}\s(\w+)\s+(.+)$/)
        {

            # check if date is the same as the old one, and if so then read more lines
            if ($self->{'old_date'} eq "$1-$2-$3 $4:$5:$6") {

                # the date is the same, so we have a new line to process
                # add to the information
                $info .= $8;

                if ($s !~ m/$7/) {
                    $s .= ' (' . $7 . ')';
                }

            }
            else {

                # we have a new date, that we are going to process during our next run
                $same                   = 0;
                $self->{'line_loaded'}  = 1;
                $self->{'line_content'} = $line;
            }
        }
        else {
            print STDERR "[MSSQL] Additional line did not pass requirements ($line)\n"
              if $self->{'debug'};
            $same = 0;
        }

    }

    # check if we have a valid date
    return \%t_line unless defined $date;

    $text = 'Database: ' . $s . ' Information: ' . $info;

    $text =~ s/\n//g;
    $text =~ s/\r//g;
    $text =~ s/\s+/ /g;

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
        'time'   => { 0 => { 'value' => $date, 'type' => 'Entry written', 'legacy' => 15 } },
        'desc'   => $text,
        'short'  => $title,
        'source' => 'LOG',
        'sourcetype' => 'MSSQL ErrorLog',
        'version'    => 2,
        'extra'      => { 'database' => $s }
              );

    return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help() {
    return "This module parses the MS-SQL errorlog, not much more to say really\n" . '
sql server "reportserverservice" log files
path= c:\Program Files\Microsoft SQL Server\MSRS10.MSSQLSERVER\Reporting Services\LogFiles

sql ERRORLOG log files logation.
path= c:\Program Files\Microsoft SQL Server\MSSQL10.MSSQLSERVER\MSSQL\Log
  ';
}

#       verify
#
# This function takes as an argument the file name to be parsed (file/dir/artifact) and
# verifies it's structure to determine if it is really of the correct format.
#
# This is needed since there is no need to parse the file if this file/dir is not the file
# that this input module is designed to parse
#
# It is also important to validate the file since the scanner function will try to
# parse every file it finds, and uses this verify function to determine whether or not
# a particular file/dir/artifact is supported or not. It is therefore very important to
# implement this function and make it verify the file structure without false positives and
# without taking too long time
#
# @return A reference to a hash that contains an integer indicating whether or not the
#  file/dir/artifact is supporter by this input module as well as a reason why
#  it failed (if it failed)
sub verify {
    my $self = shift;
    my $temp;

    # define an array to keep
    my %return;
    my $vline;
    my @words;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';
    $self->{ofs}       = 0;           # return the offset to zero (initialize)

    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(BIG_E);

    # read the first two bytes
    $vline = Log2t::BinRead::read_16($self->{'file'}, \$self->{'ofs'});

    # check for magic value: 0x fffe
    if ($vline eq 0xfffe) {
        printf STDERR "[MAGIC] 0x%x\n", $vline if $self->{'debug'};
        $vline = Log2t::BinRead::read_unicode_until($self->{'file'}, \$self->{'ofs'}, "\n", 400);

        printf STDERR "[FIRST LINE] %s\n", $vline if $self->{'debug'};

        # check the first line, it should correspond to:
        # 2010-12-16 13:32:03.29 Server      Microsoft SQL Server 2008 (SP1) - 10.0.2531.0 (X64)
        # YYYY-MM-DD HH:MM:SS.MS Server       MSSQL SERVER VERSION

        if ($vline =~ m/^\d{4}-\d{1,2}-\d{1,2}\s.+SQL.+/) {
            $return{'success'} = 1;
            $return{'msg'}     = 'Correct format';

            # now we need to build the server information variable
            if ($vline =~
                m/(\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})\.\d{1,4}\sServer\s+(\w+)$/)
            {
                $self->{'server'}->{'log_date'} = $1;
                $self->{'server'}->{'info'}     = $2;
            }
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'First line not correctly formed [' . $vline . ']';
        }
    }

    return \%return;
}

1;

__END__

=pod

=head1 NAME

B<structure> - an input module B<log2timeline> that parses X 

=head1 SYNOPSIS

  my $format = structure;
  require $format_dir . '/' . $format . ".pl" ;

  $format->verify( $log_file );
  $format->prepare_file( $log_file, @ARGV )

        $line = $format->load_line()

  $t_line = $format->parse_line();

  $format->close_file();

=head1 DESCRIPTION

An input module 

=head1 SUBROUTINES

=over 4

=item get_version()

Return the version number of the input module

=item get_description()

Returns a string that contains a short description of the functionality if the input module.  When a list of all available input modules is printed using B<log2timeline> this string is used.  So this string should be a very short description, mostly to say which type of log file/artifact/directory this input module is designed to parse.

=item prepare_file( $file, @ARGV )

The purpose of this subfunction is to prepare the log file or artifact for parsing. Usually this involves just opening the file (if plain text) or otherwise building a structure that can be used by other functions.

This function accepts the path to the log file/directory/artifact to parse as well as an array containing the parameters passed to the input module. These parameters are used to adjust settings of the input module, such as to provide a username and a hostname to include in the timeline.

The function returns an integer indicating whether or not it was successful at preparing the input file/directory/artifact for further processing.

=item load_line()

This function starts by checking if there are any lines in the log file/artifacts that have a date variable inside that needs to be parsed.  It then loads the line (or an index value) in a global variable that can be read by the function parse_line and returns the value 1 to the main script, indicating that a line has been loaded.

When all of the lines in the log file/directory/artifact have been parsed a zero is returned to the main script, indicating that there are no more lines to parse

=item close_file()

A subroutine that closes the file, after it has been parsed and performs any additional operations needed to close the file/directory/artifact that was parsed (such as to disconnect any database connections)

The subroutine returns an integer indicating whether or not it was successful at closing the file.

=item parse_line()

This is the main subroutine of the format file (or often it is).  It depends on the subroutine load_line that loads a line of the log file into a global variable and then parses that line to produce the hash t_line, which is read and sent to the output modules by the main script to produce a timeline or a bodyfile.

The content of the hash t_line is the following:

  %t_line {
    md5,    # MD5 sum of the file
    name,    # the main text that appears in the timeline
    title,    # short description used by some output modules
    source,    # the source of the timeline, usually the same name or similar to the name of the package
    user,    # the username that owns the file or produced the artifact
    host,    # the hostname that the file belongs to
    inode,    # the inode number of the file that contains the artifact
    mode,    # the access rights of the file
    uid,    # the UID of the user that owns the file/artifact
    gid,    # the GID of the user that owns the file/artifact
    size,    # the size of the file/artifact
    atime,    # Time in epoch representing the last ACCESS time
    mtime,    # Time in epoch representing the last MODIFICATION time
    ctime,    # Time in epoch representing the CREATION time (or MFT/INODE modification time)
    crtime    # Time in epoch representing the CREATION time
  }

The subroutine return a reference to the hash (t_line) that will be used by the main script (B<log2timeline>) to produce the actual timeline.  The hash is processed by the main script before forwarding it to an output module for the actual printing of a bodyfile.

=item get_help()

A simple subroutine that returns a string containing the help message for this particular input module. This also contains a longer description of the input module describing each parameter that can be passed to the subroutine.  It sometimes contains a list of all dependencies and possibly some instruction on how to install them on the system to make it easier to implement the input module.

=item verify( $log_file )

This subroutine takes as an argument the file name to be parsed (file/dir/artifact) and verifies it's structure to determine if it is really of the correct format.

This is needed since there is no need to try to parse the file/directory/artifact if the input module is unable to parse it (if it is not designed to parse it)

It is also important to validate the file since the scanner function will try to parse every file it finds, and uses this verify function to determine whether or not a particular file/dir/artifact is supported or not. It is therefore very important to implement this function and make it verify the file structure without false positives and without taking too long time

This subroutine returns a reference to a hash that contains two values
  success    An integer indicating whether not the input module is able to parse the file/directory/artifact
  msg    A message indicating the reason why the input module was not able to parse the file/directory/artifact

=back

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009-2011

=head1 SEE ALSO

L<log2timeline>

=cut

