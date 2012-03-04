#################################################################################################
#    volatility
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This is a format file that implements a parser for some volatility output files.  It parses the files
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Author: Julien Touche
# Updated by Kristinn Gudjonsson so that it works with the 0.50+ structure of the timestamp object
# Version : 0.2
# Date : 13/04/11
# <!> on SIFT v2, need to manually install DateTime::Format::Strptime perl module.
#
# 13/04/11 Kristinn - updated the module so that it fits into the new log2timeline engine
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
package Log2t::input::volatility;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Data::Dumper;
use Log2t::Common ':binary';
use Log2t::Time;           # to manipulate time

#use Log2t::Win;  # Windows specific information
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;    # methods to read binary files (it is preferable to always load this library)

#use Log2t::Network;  # information about network traffic

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# indicate the version number of this input module
$VERSION = '0.2';

sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

   # indicate that this is a text based file, with one line per call to get_time
   #       This option determines the behaviour of the engine. If this variable is set
   #       to 0 it means that we return a single hash that contains multiple timstamp objects
   #       Setting it to 1 means that we return a single timesetamp object for each line that
   #       contains a timestamp in the file.
   #
   #       So if this is a traditional log file, it is usually better to leave this as 1 and
   #       process one line at a time.  Otherwise the tool might use too much memory and become
   #       slow (storing all the lines in a large log file in memory might not be such a good idea).
   #
   #       However if you are parsing a binary file, or a file that you know contains few timestamps
   #       in it, it might make more sense to just parse the entire file and return a single value
   #       instead of making the engine call the module in a loop.
    $self->{'psscan2'} = undef;

    bless($self, $class);

    return $self;
}

# Perl trim function to remove whitespace from the start and end of the string
sub _trim($) {
    my $string = shift;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return 'Parse the content of a Volatility output files (psscan2, sockscan2, ...)';
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
sub get_time() {
    my $self = shift;

    # log file variables
    my $pid;
    my $ppid;
    my $offset;
    my $label;
    my $atime = undef;    # Time Created
    my $btime = undef;    # Time Exited
    my $d;                # the date
    my $line;

    # the timestamp object
    my %t_line = undef;

    my $fh = $self->{'file'};
    $line = <$fh> or return undef;

    print STDERR "[PARSE VOLATILITY] Parsing line $line\n" if $self->{'debug'};

    if ($line =~ m/^#/) {

        # comment, let's skip that one
        return \%t_line;
    }
    elsif ($line =~ m/^$/ or $line =~ m/^\s+$/) {
        return \%t_line;
    }
    elsif ($line =~ m/^----/ or $line =~ m/^PID\s+PPID/) {
        return \%t_line;
    }

    # check which version we are dealing with
    if ($self->{'psscan2'}) {

        # we have psscan2 output (verify line)
        if ($line =~ m/^\s+(\d+)\s+(\d+)\s+(.*?)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(.*?)$/) {
            $pid    = $1;
            $ppid   = $2;
            $offset = '0x' . $4;
            $label  = _trim($6);

# the date object is five words (each date), so we have either 5 or 10 dates
# One date object is (may be repeated twice or only one instance) [Day Month Day Hour:Minute:Second Year]
            $d = $3;
        }
        else {
            return \%t_line;
        }
    }
    else {

        # we have psscan output
        if ($line =~ m/^\s+\d+\s+(\d+)\s+(\d+)\s+(.*?)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(.*?)$/) {
            $pid    = $1;
            $ppid   = $2;
            $offset = '0x' . $4;
            $label  = _trim($6);

# the date object is five words (each date), so we have either 5 or 10 dates
# One date object is (may be repeated twice or only one instance) [Day Month Day Hour:Minute:Second Year]
            $d = $3;
        }
        else {
            return \%t_line;
        }
    }

    # and now to continue with the common processing
    my $count = $d =~ s/((^|\s)\S)/$1/g;

    # count is either 5 (one date - Time Created or two dates - Time Exited as well)
    if ($count == 5) {

        # now we have one date, just the Time Created
        $atime = Log2t::Time::text2epoch(_trim($d), $self->{'tz'});
    }
    elsif ($count == 10) {

        # There are two dates, we also have the Time Exited value

        # create a small array to store words
        my @tmp = split(/\s/, _trim($d));

        $atime = Log2t::Time::text2epoch(
                            $tmp[0] . ' ' . $tmp[1] . ' ' . $tmp[2] . ' ' . $tmp[3] . ' ' . $tmp[4],
                            $self->{'tz'});
        $btime = Log2t::Time::text2epoch(
                            $tmp[5] . ' ' . $tmp[6] . ' ' . $tmp[7] . ' ' . $tmp[8] . ' ' . $tmp[9],
                            $self->{'tz'});
    }
    else {

        # try this
        $atime = Log2t::Time::text2epoch(_trim($d), $self->{'tz'});
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
               'desc'    => "Process: $label, PID: $pid, PPID: $ppid, Offset: '$offset'",
               'short'   => "Process '$label' launched (PID $pid)",
               'source'  => 'RAM',
               'version' => 2,
              );

    # check and verify the source and use the appropriate text
    $t_line{'sourcetype'} = 'Volatility PSSCAN2' if $self->{'psscan2'};
    $t_line{'sourcetype'} = 'Volatility PSSCAN' unless $self->{'psscan2'};

    # and add the time values
    if (defined $btime) {

        # we have two timestamps
        $t_line{'time'}->{0} = {
                                 'value'  => $atime,
                                 'type'   => 'Time Created',
                                 'legacy' => 12
                               };

        $t_line{'time'}->{1} = {
                                 'value'  => $btime,
                                 'type'   => 'Time Exited',
                                 'legacy' => 3
                               };
    }
    else {

        # only one date
        $t_line{'time'}->{0} = {
                                 'value'  => $atime,
                                 'type'   => 'Time Created',
                                 'legacy' => 15
                               };
    }

    return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help() {
    return "----------------------------------------------------
  VOLATILITY OUTPUT FILES PARSER
----------------------------------------------------
Read some output of volatility memory framework.\n
The input module reads the output from both the psscan and psscan2 commands.\n
\t$0 -f volatility -z local psscan2_output
Format of the Volatility file (psscan2) is:
PID    PPID   Time created             Time exited              Offset     PDB        Remarks
------ ------ ------------------------ ------------------------ ---------- ---------- ----------------

Format of the Volatility file (psscan) is:
No.  PID    PPID   Time created             Time exited              Offset     PDB        Remarks
---- ------ ------ ------------------------ ------------------------ ---------- ---------- ----------------

(TODO)
\t$0 -f volatility psscan2_output sockscan2_output file3 ...
OR
\t$0 -f volatility -ps psscan2_output -socks sockscan2_output -reg file3 ...

The format file accepts the following options
  --host HOST\n
  --user USER\n";

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

    # define an array to keep
    my %return;
    my $vline;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    my $ofs = 0;

    # open the file (at least try to open it)
    eval {

        # read a line from the file as it were a binary file
        # it does not matter if the file is ASCII based or binary,
        # lines are read as they were a binary one, since trying to load up large
        # binary documents using <FILE> can cause log2timeline/timescanner to
        # halt for a long while before dying (memory exhaustion)
        $vline = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 100);

        ## TODO eventually, if input concerns multiple file, could place some
        ## structure check here with a global var %struct

        # added by Kristinn add a check
        # the default MSG
        $return{'msg'} = 'Not the correct magic value';

        if ($vline =~ m/^No.\s+PID\s+PPID\s+Time created/) {

            # we have a PSSCAN output
            $return{'success'} = 1;
            $self->{'psscan2'} = 0;
        }
        elsif ($vline =~ m/^PID\s+PPID\s+Time created/) {

            # we have a PSSCAN2 output
            $return{'success'} = 1;
            $self->{'psscan2'} = 1;
        }
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
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

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009.

=head1 SEE ALSO

L<log2timeline>

=cut

