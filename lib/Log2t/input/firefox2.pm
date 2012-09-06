#################################################################################################
#    FIREFOX2
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a history file for the
# Firefox 2 and older browsers.
#
# Firefox 2 (and older) used the Mork file format to store the browser history file.
# To get further information about the Mork structure, please refer to this link:#
#   https://developer.mozilla.org/en/Mork_Structure
#
# And for a brief discussion about the history.dat file that stores the actual history
#   http://kb.mozillazine.org/History.dat
#
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 27/04/11
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
package Log2t::input::firefox2;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';

#use Log2t::Time;  # to manipulate time
#use Log2t::Win;  # Windows specific information
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;    # methods to read binary files (it is preferable to always load this library)

#use Log2t::Network;  # information about network traffic
use Encode;
use File::Mork;

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# indicate the version number of this input module
$VERSION = '0.3';

# other global variables that are needed for this input module
my @keys;    # an array that stores the keys, or the keys to the stored records

# the default constructor
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we are dealing with a binary file (only one entry returned)
    $self->{'file_access'} =
      1;     # do we need to parse the actual file or is it enough to get a file handle

    bless($self, $class);

    return $self;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a Firefox 2 browser history";
}

#       init
#
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
    my $self = shift;

    # open the file (or return 0 if unable)
    # a variable to store a "mork" object, or a reference to the parsed information
    eval {
        $self->{'mork'} = File::Mork->new(${ $self->{'name'} }, verbose => $self->{'debug'});
    };
    if($@) {
        print STDERR "Error while parsing Mork database: $@\n";
        return 0;
    }

    unless ($self->{'mork'}) {
        print STDERR "Error while parsing ("
          . ${ $self->{'name'} } . "): "
          . $File::Mork::ERRO . "\n";
        return 0;
    }

    # try to guess the username
    $self->{'username'} = Log2t::Common::get_username_from_path(${ $self->{'name'} });

    # an index to the current record we are examining
    # reset the index
    $self->{'index'} = 0;

    # and get the count, that is total number of events
    @keys = $self->{'mork'}->entries;

    # a variable that stores the total amount of records stored in the file
    $self->{'count'} = $#keys + 1;

    # check debug
    print STDERR "[FIREFOX2] Number of entries: " . $self->{'count'} . "\n" if $self->{'debug'};

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
    my %t_line;    # the timestamp object
    my $text;
    my $title;

    # check if we have reached the end
    return undef unless $self->{'index'} < $self->{'count'};

    printf STDERR "[FIREFOX2] Parsing record: %d out of %d\n", $self->{'index'} + 1,
      $self->{'count'}
      if $self->{'debug'};

    # substitute multiple spaces with one for splitting the string into variables
    my $entry = $keys[ $self->{'index'} - 1 ];

    # update the index
    $self->{'index'}++;

    $text .= 'Visited ' unless (defined $entry->Typed) and ($entry->Typed eq 1);
    $text .= 'Typed the URL ' if (defined $entry->Typed) and ($entry->Typed eq 1);
    $text .= $entry->URL . ' (' . $entry->Hostname . ')';
    $text .= ' total visits ' . $entry->VisitCount if defined $entry->VisitCount;
    $text .= ' referred from: ' . $entry->Referrer if defined $entry->Referrer;
    $text .= ' [URL hidden from user]' if (defined $entry->Hidden) and ($entry->Hidden eq 1);
    $title = ' [URL hidden from user]' if (defined $entry->Hidden) and ($entry->Hidden eq 1);

    $text .= ' Title: (' . $entry->Name . ')' if defined $entry->Name;

    # content of the timestamp object t_line
    # optional fields are marked with []
    #
    # %t_line {
    #       time
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
               'desc'       => $text,
               'short'      => $entry->URL . $title,
               'source'     => 'WEBHIST',
               'sourcetype' => 'Firefox 2',
               'version'    => 2,
               'extra'      => { 'user' => $self->{'username'}, }
              );

    # check the existence of a default browser for this particular user
    if (defined $self->{'defbrowser'}->{ lc($self->{'username'}) }) {
        $t_line{'notes'} =
          $self->{'defbrowser'}->{ $self->{'username'} } =~ m/firefox/i
          ? 'Default browser for user'
          : 'Not the default browser (' . $self->{'defbrowser'}->{ $self->{'username'} } . ')';
    }
    elsif ($self->{'defbrowser'}->{'os'} ne '') {

        # check the default one (the OS)
        $t_line{'notes'} =
          $self->{'defbrowser'}->{'os'} =~ m/firefox/
          ? 'Default browser for system'
          : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
    }

    # and assign the time variable
    if ($entry->LastVisitDate == $entry->FirstVisitDate) {

        # the same, only one timestamp
        $t_line{'time'} =
          { 0 => { 'value' => $entry->LastVisitDate, 'type' => 'Only Visit', 'legacy' => 15 }, };
    }
    else {

        # different timestamps
        $t_line{'time'} = {
                 0 => { 'value' => $entry->LastVisitDate,  'type' => 'Last Visit',  'legacy' => 7 },
                 1 => { 'value' => $entry->FirstVisitDate, 'type' => 'First Visit', 'legacy' => 8 },
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
    return "This is an input module that parses the contents of the history.dat file, 
that contains the browser history from a Firefox 2 or older browsers, that are using the 
Mork file format to store the browser history.";

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
        $vline = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 50);
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    # check if this is a mork file
    if ($vline =~ m/mdb:mork:z/) {
        $return{'success'} = 1;
    }
    else {
        $return{'success'} = 0;
        $return{'msg'}     = 'Wrong magic value';
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

