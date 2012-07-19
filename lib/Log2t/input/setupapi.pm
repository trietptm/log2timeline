#################################################################################################
#    setupapi
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing the setupapi.log file
# found in Windows XP (among others).  According to information from Microsoft the purpose of the
# file is to:
#
#   This plain-text file maintains the information that SetupAPI records about device
#  installation, service-pack installation, and hotfix installation. Specifically,
#  the file maintains a record of device and driver changes, as well as major system
#  changes, beginning from the most recent Windows installation.
#
# For further reading of the setupapi log file format:
#  http://www.microsoft.com/whdc/driver/install/setupapilog.mspx
#
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 30/03/11
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
package Log2t::input::setupapi;

use strict;
use Log2t::base::input;    # the SUPER class or parent

#use Log2t::Time;  # to manipulate time
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;        # methods to read binary files
use Log2t::Common ':binary';
use DateTime;              # for date manipulatio
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.6';

my %structure;
my $line_loaded;

my %msg_codes;             # list of message codes

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of the SetupAPI log file in Windows XP";
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

sub init() {
    my $self = shift;

    # initialize the first line variable
    $self->{'first_line'} = 1;

    # prepare the message codes
    %msg_codes = (
        11  => 'Installation in progress',
        18  => 'Reported compatible identifiers from device parent bus',
        19  => 'Reported hardware ID(s) from device parent bus',
        22  => 'Compatible INF file found',
        23  => 'Install section',                                        # watch the rank "Rank: NR"
        24  => 'Copy in progress',
        121 => 'Device successfully setup',
        124 => 'Copy-only installation',
        140 => 'GUID of device-setup class',
        141 => 'Class install completed (no errors)',
        142 => 'Class install failed (error)',
        166 => 'Processing a DIF_SELECTBESTCOMPATDRV request',
        167 => 'SPFILENOTIFY_NEEDMEDIA: SYS file found in Windows driver cabinet',
        168 => 'SPFILENOTIFY_NEEDMEDIA callback not called',
        198 => 'Driver install entered (through services.exe)',

# more on the -199 code. there are three possible scenarios
# setup -newsetup => GUI mode during setup phase of Windows, newdev.dll => client side setup, 3rd is application driven install
# then a UpdateDriverForPlugAndPlayDevices function called - the only indication is that the name of the executable is called
        199 => 'Driver install entered',
        290 => 'Processing section',
        336 => 'File copied',
        340 => 'File extracted',
        406 => 'Obtaining rollback information'

                 );

    return 1;
}

#
sub _read_header($) {
    my $fh = shift;
    my $line = <$fh>;
    if (not $line) {
        print STDERR "[SETUPAPI] Unable to read in a new line (trying to read header).\n";
        return 0;
    }

    # fill the structure
    $structure{'magic'} = $line;

    #print STDERR "[HEADER] The magic, $line\n";

    # read the next six lines which are part of the header
    for (my $i = 0; $i < 6; $i++) {
        $_ = <$fh>;
        next unless $_;

        # split the line
        /(.+)\s\=\s(.+)/;
        $structure{$1} = $2;

        #print STDERR "\t[$_]\n";
    }

    return 1;
}

#       parse_line
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
#
# @return Returns a reference to a hash containing the needed values to print a body file
sub get_time() {
    my $self = shift;
    my $fh   = $self->{'file'};

    #print STDERR "CALLING get_time\n";

    # check if we are parsing the first lines
    if ($self->{'first_line'}) {

        #print STDERR "READING THE HEADER\n";
        $self->{'first_line'} = 0;
        print STDERR "[ERROR WHILE PARSING HEADER]\n" unless _read_header($self->{'file'});
    }

    # timestamp object
    my %t_line;
    my $date;
    my ($pid_part, $msg_desc, $pid, $instance);
    my $text;
    my %temp;
    my $title;
    my $line;

    # check if a line has already been loaded by parse_line function
    if ($line_loaded) {
        $line_loaded = 0;
        $line        = $self->{'line_loaded'};
    }
    else {

        # line hasn't been loaded yet, so let's read in a new line
        $line = <$fh>;
        if (not $line) {
            print STDERR "[SetupAPI] Unable to read in new line [End of file]\n" if $self->{'debug'};
            return undef;
        }

        # check if we have a section marker or a message
        # possibilites are that the line starts with:
        #  [ - new section
        #  @ - detailed message (used in more verbose settings) followed by a data
        #  # - a message (followed by a message code)
        if ($line !~ m/^\[\d{4}\/\d{2}\//) {

            #print STDERR "<LINE> $line\n";
            #print STDERR "[LINE NOT CORRECT] Not the correct structure, let's call myself again\n";
            return $self->get_time();
        }

    }

    $msg_desc = '';

    # now the line variable contains the date, transform it into a usable date
    if ($line =~ /\[(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}) (.+)\]/) {
        $date = DateTime->new(
                              year      => $1,
                              month     => $2,
                              day       => $3,
                              hour      => $4,
                              minute    => $5,
                              second    => $6,
                              time_zone => $self->{'tz'}
                             );

#print STDERR "[SETUPAPI] YEAR $1 MONTH $2 DAY $3 HOUR $4 MINUTE $5 SECOND $6 TIME ZONE $timezone\n";
#print STDERR "\tOriginal: $line\n";

        ($pid_part, $msg_desc) = split(/\s/, $7);
        ($pid,      $instance) = split(/\./, $pid_part);
    }
    else {

        #print STDERR "Wrongly formed section marker\n";
        return undef;
    }

    # now we need to decipher the msg_type_id

    # now we need to read the following lines for more information
    $text = '';

    $text  .= $msg_desc if $msg_desc ne '';
    $title .= $msg_desc if $msg_desc ne '';

    # and to add more context we need to read ahead (read all messages)
    $_ = <$fh>;
    if (not $_) {
        print STDERR "[SetupAPI] No more lines to parse.\n" if $self->{'debug'};
        return undef;
    }
    while (/^#/) {

        # msg format
        #  message_type_ID message_text
        # or
        #  timestamp message_type_ID message_text
        /^#(.)(\d{3})(.+)/;
        if ($1 eq '-') {

            # context
            $text .= 'Context: ';
            $text .= $msg_codes{ int($2) } || '(code ' . $2 . ')';

            $title .= 'Contextual information. ';

            # check for 199
        }
        elsif ($1 eq 'E') {

            # error
            $text .= 'Error: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' Error msg ' . $2 . '. ';
        }
        elsif ($1 eq 'W') {

            # warning
            $text .= 'Warning: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' Warning msg ' . $2 . '. ';
        }
        elsif ($1 eq 'I') {

            # information
            $text .= 'Information: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' Information msg ' . $2 . '. ';
        }
        elsif ($1 eq 'V') {
            $text .= 'Verbose: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' Verbose msg ' . $2 . '. ';
        }
        elsif ($1 eq 'T') {

            # timing
            $text .= 'Timing: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' Timing msg ' . $2 . '. ';
        }
        else {

            # unknown
            $text .= 'unknown [' . $1 . ']: ' . $msg_codes{ int($2) } || '(code ' . $2 . ')';
            $title .= ' unknown msg ' . $2 . '.';
        }

        if ($3 =~ m/.+install.+"(.+)".+/i) {
            $text .= " [$1]";
        }

        $text .= '. ';

        # processing key words
        #  device
        #  driver
        #  date
        #  c:\windows
        #  ID(s)

#    if( ($line =~ m/device/i ) && ( $line !~ m/device install function/i ) && ( $line !~ m/device install of/i ))
#    {
#      if( $line =~ m/#.+Found.+Device: "(.+)"; Driver: "(.+)"; Provider: "(.+)"; Mfg: "(.+)"; Section name: "(.+)".+/ )
#      {
#        # now we need to print
#        $text .= 'Device ' . $1 . ' using driver ' . $2 . ' from provider ' . $3 . '. Mfg: ' . $4 . ' and section name ' . $5;
#      }
#
#      if( $line =~ m/Effective driver date: (\d{2}\/\d{2}\/\d{4})/ )
#      {
#        $text .= ' Driver date: ' . $1;
#      }
#      if( $line =~ m/.+Class GUID of device remains: \{(.+)\}/ )
#      {
#        $text .= ' GUID: ' . $1;
#      }
#
#
#      if( $line =~ m/required reboot:/ )
#      {
#        $text .= ' reboot required after installation';
#      }
#
#
#    }

        #    if( $line =~ m/Executing "(.+)" with command line:(.+)$/ )
        #    {
        #      $text .= 'Cmd executed ' . $1 . ' cmd options: ' . $2;
        #    }
        #
        #    if( $line =~ m/Obtaining rollback information for device "(.+)"/ )
        #    {
        #      $text .= ' rollback for device: ' . $1;
        #    }
        #
        #    if( $line =~ m/Command line processed: (.+)$/ )
        #    {
        #      $text .= ' Cmd processed: ' . $1;
        #    }
        #
        #    if( $line =~ m/Selected driver installs from section \[(.+)\] in "(.+)"/ )
        #    {
        #      $text .= 'Driver install, section: ' . $1 . ' loc: ' . $2 ;
        #    }
        #

        # load new line
        $_ = <$fh>;    #or return undef;
    }

    # check if we have reached the next time settings
    if (/^\[/) {
        $line_loaded = 1 if (/^\[/);
        $self->{'line_loaded'} = $_;
    }

    $text =~ s/\n//g;
    $text =~ s/\r//g;
    $text =~ s/[[:cntrl:]]//g;

#print STDERR "\t$text\nDATE: [" . Log2t::Time::epoch2text( $date->epoch ) . "]\n<" . $date->epoch . ">\n\n";

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
    $text = $self->{'detailed_time'} ? $text : $title;

    # create the t_line variable
    %t_line = (
        'time' => { 0 => { 'value' => $date->epoch, 'type' => 'Entry written', 'legacy' => 15 } },
        'desc' => $text,
        'short'      => $title,
        'source'     => 'LOG',
        'sourcetype' => 'SetupAPI Log',
        'version'    => 2,
        'extra'      => {}
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
    return "This input module implements a parser for the Windows SetupAPI log file";

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
sub verify($$) {

    # define an array to keep
    my %return;
    my $line;

    my $self = shift;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'not really a file';

    # if it isn't a file, then we do not bother reading further
    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);
    my $ofs = 0;

    # open the file (at least try to open it)
    eval {

        #unless( $detail )
        #{
        #  # a SetupAPI log file starts with [
        #  seek(FILE,0,0);
        #  read(FILE,$line,1);
        #  $return{'msg'} = 'Wrong magic value';
        #
        #  close(FILE) unless $line eq '[';
        #  return \%return unless $line eq '[';
        #}

        # read a line
        $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 40);

        # remove control characters from it
        $line =~ s/[[:cntrl:]]//g;

        #print STDERR "[DEBUG] Verify line is ($line)\n" if $self->{'debug'};
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";

        return \%return;
    }

    # verify that we are dealing with a setupAPI log file
    if ($line eq '[SetupAPI Log]') {
        $return{'success'} = 1;
    }
    else {
        $return{'success'} = 0;
        $return{'msg'}     = 'Wrong magic value: [' . $line . ']';
    }

    return \%return;
}

1;

__END__

=pod

=head1 NAME

B<setupapi> - an input module B<log2timeline> that parses SetupAPI log file in Windows XP

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

