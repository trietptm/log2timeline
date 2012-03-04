#################################################################################################
#    EVT (event log)
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
#
# This parser is based on the evtparse.pl script that Harlan Carvey wrote to parse
# Windows 2000/XP/2003 Event Log files.
#
# The original script, written by Harlan Carvey is called evtparse.pl and was published as
# a part of the timeline toolkit he is developing at win4n6.
#
# copyright 2009 H. Carvey, keydet89@yahoo.com
#
# Author: Kristinn Gudjonsson
# Version : 0.2
# Date : 07/03/10
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
#
# copyright 2009 H. Carvey, keydet89@yahoo.com
package Log2t::input::evt;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';

#use Log2t::Time;  # to manipulate time
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;        # methods to read binary files

#use Log2t::Network;  # information about network traffic

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# indicate the version number of this input module
$VERSION = '0.2';

sub new {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    # indicate that this is a text based file, with one line per call to get_time
    $self->{'multi_line'} = 0;
    $self->{'type'}       = 'file';    # it's a file type, not a directory

    # the types
    $self->{'types'} = {
                         0x0001 => "Error",
                         0x0010 => "Failure",
                         0x0008 => "Success",
                         0x0004 => "Info",
                         0x0002 => "Warn"
                       };

    return $self;
}

sub init {
    my $self = shift;

    # initialize the file size
    $self->{'ofs'} = 0;
    seek($self->{'file'}, 0, 0);

    return 1;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a Windows 2k/XP/2k3 Event Log";
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

#       parse_line
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
#
# @return Returns a reference to a hash containing the needed values to print a body file
sub get_time {
    my $self = shift;

    # the container of timestamp object
    my %container;
    my $cont_counter = 0;    # the counter into the container

    my $data;
    my ($l, $f);
    my (%r, $r_ofs);
    my $desc;
    my $suc = 0;
    my $source;
    my $user;

    # find out the size of the file
    $self->{'size'} = (stat(${ $self->{'name'} }))[7];

    # go through all of the events in the event log
    while ($self->{'ofs'} < $self->{'size'}) {

        # initialize for each event
        %r = undef;

        seek($self->{'file'}, $self->{'ofs'}, 0);
        read($self->{'file'}, $data, 4);

        if (unpack("V", $data) == 0x654c664c) {
            seek($self->{'file'}, $self->{'ofs'} - 4, 0);
            read($self->{'file'}, $data, 4);
            $l = unpack("V", $data);

            seek($self->{'file'}, $self->{'ofs'} - 4, 0);
            read($self->{'file'}, $data, $l);
            $f = unpack("V", substr($data, $l - 4, 4));

#printf STDERR "Record located at offset 0x%08x; Length = 0x%x, Final Length = 0x%x\n",$ofs - 4,$l,$f;
            if ($l == $f) {

                #print STDERR "\t-> Valid record\n";
                #print STDERR "\t**HDR Record\n" if ($l == 0x30);
                #print STDERR "\t**EOF Record\n" if ($l == 0x28);

                if ($l > 0x38) {
                    %r = $self->_parseRec($data);
                    $r_ofs = sprintf "0x%08x", $self->{'ofs'};

#print STDERR $r_ofs."|".$r{rec_num}."|".$r{evt_id}."|".$r{source}."|".$r{computername}."|".$r{sid}."|".$r{strings}."\n";

                    $desc =
                        $r{source} . "/"
                      . $r{evt_id} . ";"
                      . $self->{'types'}->{ $r{evt_type} } . ";"
                      . $r{strings};

                    # Time|Source|Host|User|Description
                    #print STDERR $r{time_gen}."|EVT|".$r{computername}."|".$r{sid}."|".$desc."\n";
                    $suc = 1;    # we have a succesful record
                }

                $self->{'ofs'} += $l;
            }
            else {

                # If this check ($l == $f) fails, then the record isn't valid
                $self->{'ofs'} += 4;
            }
        }
        else {
            $self->{'ofs'} += 4;
        }

        $source = $r{source};
        $source =~ s/\s/%20/g;

        $user = $r{'sid'};

        $user = 'unknown' if $user eq 'N/A';

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
        #   version
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
        $container{$cont_counter} = {
                                      'desc'       => $desc,
                                      'short'      => $desc,
                                      'source'     => 'EVT',
                                      'sourcetype' => 'Event Log',
                                      'version'    => 2,
                                      'extra'      => {
                                                   'host' => $r{'computername'},
                                                   'user' => $user,
                                                   'uid'  => $r{'sid'},
                                                   'size' => $self->{'size'}
                                                 },
                                    };

        # check the times
        if ($r{time_gen} == $r{time_wrt}) {
            $container{$cont_counter}->{'time'} =
              { 1 =>
                { 'value' => $r{time_gen}, 'type' => 'Time generated/written', 'legacy' => 15 },
              };
        }
        else {
            $container{$cont_counter}->{'time'} = {
                       1 => { 'value' => $r{time_gen}, 'type' => 'Time generated', 'legacy' => 14 },
                       2 => { 'value' => $r{time_wrt}, 'type' => 'Time written',   'legacy' => 1 }
                                                  };
        }

        # now to add the URL field
        $container{$cont_counter}->{'extra'}->{'url'} =
          'http://eventid.net/display.asp?eventid=' . $r{evt_id} . '&source=' . $source;

        # check if there are any references to a knowledgebase article
        if (defined $r{'kb'}) {

            # we need to walk through the kb fields and add them to the URL string
            foreach (keys %{ $r{'kb'} }) {
                $container{$cont_counter}->{'extra'}->{'url'} .=
                  ', http://support.microsoft.com/kb/' . $r{'kb'}->{$_};
            }
        }

        #printf STDERR "Ofs: 0x%x not successful, ...\n",$ofs unless $suc;

        # just to make sure we have a valid record
        $container{$cont_counter}->{'desc'} = '' unless $suc;

        # increment the counter
        $cont_counter++;
    }

    return \%container;
}

#       get_help
#
# A simple subroutine that returns a string containing the help
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help() {
    return "This input module parses the Windows Event Log and extracts
each available record from the file";

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
    my $magic;
    my $ofs = 0;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'Not a file';

    return \%return unless -f ${ $self->{'name'} };
    $return{'msg'} = 'A directory cannot be a event log file';

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # read the magic value
    $magic = Log2t::BinRead::read_32($self->{'file'}, \$ofs);

    # magic: 3000 0000 - 4c66 4c65
    if ($magic eq 0x30) {

        # ready for next step
        $magic = Log2t::BinRead::read_32($self->{'file'}, \$ofs);
        if ($magic eq 0x654c664c) {
            $return{'success'} = 1;
        }
    }

    # rewin to the beginning
    seek($self->{'file'}, 0, 0);

    $return{'msg'} = 'Not the correct magic value';

    return \%return;
}

#---------------------------------------------------------------------
# parseRec()
# Parse the binary Event Record
# References:
#   http://msdn.microsoft.com/en-us/library/aa363646(VS.85).aspx
#---------------------------------------------------------------------
# Unmodified funcion, taken directly from evtparse.pl
# copyright 2009 H. Carvey, keydet89@yahoo.com
sub _parseRec {
    my $self = shift;
    my $data = shift;
    my %rec;
    my $hdr = substr($data, 0, 56);
    (
     $rec{length},   $rec{magic},    $rec{rec_num},  $rec{time_gen},
     $rec{time_wrt}, $rec{evt_id},   $rec{evt_id2},  $rec{evt_type},
     $rec{num_str},  $rec{category}, $rec{c_rec},    $rec{str_ofs},
     $rec{sid_len},  $rec{sid_ofs},  $rec{data_len}, $rec{data_ofs}
    ) = unpack("V5v5x2V6", $hdr);

    # Get the end of the Source/Computername field
    my $src_end;
    ($rec{sid_len} == 0) ? ($src_end = $rec{str_ofs}) : ($src_end = $rec{sid_ofs});
    my $s = substr($data, 0x38, $src_end);
    ($rec{source}, $rec{computername}) = (split(/\x00\x00/, $s))[ 0, 1 ];
    $rec{source}       =~ s/\x00//g;
    $rec{computername} =~ s/\x00//g;

    # Get SID
    if ($rec{sid_len} > 0) {
        my $sid = substr($data, $rec{sid_ofs}, $rec{sid_len});
        $rec{sid} = _translateSID($sid);
    }
    else {
        $rec{sid} = "unknown";
    }

    # Get strings from event record
    my $strs = substr($data, $rec{str_ofs}, $rec{data_ofs} - $rec{str_ofs});
    my @str = split(/\x00\x00/, $strs, $rec{num_str});

    # added by Kristinn
    my $i = 0;
    foreach (@str) {

# start by fixing the string, that is to remove the "unicode" aspect, convert to ASCII the simple way
        s/\x00//g;

        # and now to test if we have a KB article
        while (/KB(\d{6,8})/g) {

            # add the KB to the field
            $rec{'kb'}->{ $i++ } = $1;
        }
    }

    # end added code

    $rec{strings} = join(' - ', @str);    # changed , to -
    $rec{strings} =~ s/\x00//g;
    $rec{strings} =~ s/\x09//g;
    $rec{strings} =~ s/\n/ /g;
    $rec{strings} =~ s/\x0D//g;
    $rec{strings} =~ s/- $//;             # added by Kristinn, remove the last occurance of ' - '

    return %rec;
}

#---------------------------------------------------------------------
# translateSID()
# Translate binary data into a SID
# References:
#   http://blogs.msdn.com/oldnewthing/archive/2004/03/15/89753.aspx
#   http://support.microsoft.com/kb/286182/
#   http://support.microsoft.com/kb/243330
#---------------------------------------------------------------------
# Unmodified funcion, taken directly from evtparse.pl
# copyright 2009 H. Carvey, keydet89@yahoo.com
sub _translateSID {
    my $sid = $_[0];
    my $len = length($sid);
    my $revision;
    my $dashes;
    my $idauth;
    if ($len < 12) {

        # Is a SID ever less than 12 bytes?
        return "SID less than 12 bytes";
    }
    elsif ($len == 12) {
        $revision = unpack("C",  substr($sid, 0, 1));
        $dashes   = unpack("C",  substr($sid, 1, 1));
        $idauth   = unpack("H*", substr($sid, 2, 6));
        $idauth =~ s/^0+//g;
        my $sub = unpack("V", substr($sid, 8, 4));
        return "S-" . $revision . "-" . $idauth . "-" . $sub;
    }
    elsif ($len > 12) {
        $revision = unpack("C",  substr($sid, 0, 1));
        $dashes   = unpack("C",  substr($sid, 1, 1));
        $idauth   = unpack("H*", substr($sid, 2, 6));
        $idauth =~ s/^0+//g;
        my @sub = unpack("V*", substr($sid, 8, ($len - 2)));
        my $rid = unpack("v", substr($sid, 24, 2));
        my $s = join('-', @sub);
        return "S-" . $revision . "-" . $idauth . "-" . $s;

        #    return "S-".$revision."-".$idauth."-".$s."-".$rid;
    }
    else {

        # Nothing to do
    }
}

1;

__END__

=pod

=head1 NAME

B<structure> - an input module B<log2timeline> that parses Windows 2000/XP/2003 Event Log files.

=head1 SYNOPSIS

  my $format = structure;
  require $format_dir . '/' . $format . ".pl" ;

  $format->verify( $log_file );
  $format->prepare_file( $log_file, @ARGV )

        $line = $format->load_line()

  $t_line = $format->parse_line();

  $format->close_file();

=head1 DESCRIPTION

An input module that parses the Windows Event Log files.  This input module is mostly based on the script evtparse.pl, originally written by H. Carvey, and is part of his timeline toolkit.

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

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program. This input module came however mostly from H. Carvey's evtparse.pl Perl script that is a part of his timeline toolkit and is available through the win4n6 yahoo group.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009.

=head1 SEE ALSO

L<log2timeline>

=cut


