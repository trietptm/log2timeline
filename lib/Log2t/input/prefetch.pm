# ------------------------------------------------------------------------------ #
#         prefetch
# ------------------------------------------------------------------------------ #
# This script is a part of the log2timeline program used to parse a log file and
# output a body file that can be imported into scripts such as the mactime from the
# TSK package to provide a timeline analsysis.
#
# This script reads and parses the prefetch directory that can be found in Microsoft
# Windows (some versions) and output the content found in a body file
#
# The specification of the body file can be found here:
#  http://wiki.sleuthkit.org/index.php?title=Body_file
#
# Author: Kristinn Gudjonsson
# Version : 0.8
# Date : 01/05/11
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
#
#
# Borrowed code from pref.pl written by H. Carvey
# copyright 2007 H. Carvey keydet89@yahoo.com
package Log2t::input::prefetch;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Time;
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.7';

# default constructor
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we return a single object
    $self->{'multi_line'} = 0;
    $self->{'type'}       = 'dir';    # it's a directory, not a file that we are about to parse
    $self->{'file_access'} =
      1;    # do we need to parse the actual file or is it enough to get a file handle

    bless($self, $class);

    return $self;
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

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of the Prefetch directory";
}

#      init
# This subroutine starts by reading the content of the Layout.ini file, a file that
# contains information about each of the files found in the Prefetch directory.  The
# content of the file is stored in a global array that can be used in other functions.
#
# The script then reads all the content of the Prefetch directory and stores it in
# an array that is global.
# @params One parameter is defined, the path to the Prefetch directory
# @return An integer is returned to indicate whether the file preparation was
#       successful or not.
sub init {
    my $self = shift;

    # define needed local variables
    my $layout;
    my $return = 1;

    # reset variables
    $self->{'vista'} = 0;
    $self->{'exes'}  = undef;

    print STDERR "[PREFETCH] The number of files inside the folder: " . $self->{'count'} . "\n"
      if $self->{'debug'};

    # open up the layout file and read it's content
    $layout = ${ $self->{'name'} } . $self->{'sep'} . "Layout.ini";
    open(LAYOUT, "$layout") or $return = 0;

    return 0 unless $return;

    if ($self->{'debug'}) {
        print STDERR "[PREFETCH] Examining a Vista or newer operating system (superfetch)\n"
          if $self->{'vista'};
    }

    # read the layout file
    while (<LAYOUT>) {

        # change to ascii
        s/\x00//g;
        s/\n//g;
        s/\r//g;

        if (/([a-zA-Z0-9_\-\.]+)\.EXE$/i) {
            $self->{'exes'}->{ lc($1) } = $_ unless $1 eq '';
        }
    }

    # close the file
    close(LAYOUT);

    return 1;
}

#       get_time
# The main juice of the module
sub get_time {
    my $self       = shift;
    my %container  = undef;    # the container that stores all the timestamp objects
    my $cont_index = 0;        # index into the container
    my $magic;
    my $version;
    my $ofs;
    my $l;
    my $path = '<path not found in Layout.ini>';
    my $runcount;
    my $runtime;
    my $exe;
    my $fpath = undef;
    my $text;

    foreach my $key (keys %{ $self->{'files'} }) {
        if (   ($self->{'files'}->{$key} =~ m/^\.$/)
            or ($self->{'files'}->{$key} =~ m/^\.\.$/)
            or ($self->{'files'}->{$key} =~ m/Layout.ini/i))
        {
            print STDERR "[PREFETCH] Not parsing the file " . $self->{'files'}->{$key} . "\n"
              if $self->{'debug'};

            # skip this one
            next;
        }
        else {

            # now we need to parse the file
            # get metadata from file
            $fpath = undef;
            ($runcount, $runtime, $exe, $fpath) =
              $self->_getMetaData(${ $self->{'name'} } . $self->{'sep'} . $self->{'files'}->{$key});

            # check the content of the Layout.ini file to find the full path of the executable
            if ($self->{'files'}->{$key} =~ m/(.+)\.EXE/i) {
                $path = $self->{'exes'}->{ lc($1) } if defined $self->{'exes'}->{ lc($1) };
            }

            # check to see if we were able to read the file
            next unless defined $runtime;

            # now we need to fix this fpath variable
            $fpath =~ s/\\DEVICE\\HARDDISKVOLUME\d\\/\n/g;

            # don't want to add this, unless we are using the detailed option
            if ($self->{'detailed_time'}) {
                $text = ' - DLLs loaded: {';

                while ($fpath =~ m/(^.+DLL$)/gm) {
                    $text .= $1 . ' - ';
                }

                # fix the last one
                $text =~ s/ - $//;
                $text .= '}';
            }
            else {
                $text = '';
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

            my $st;
            $st = 'Vista/Win7' if $self->{'vista'};
            $st = 'XP' unless $self->{'vista'};

            # create the t_line variable
            $container{ $cont_index++ } = {
                  'time' => { 0 => { 'value' => $runtime, 'type' => 'Last run', 'legacy' => 15 } },
                  'desc' => $self->{'files'}->{$key} . ' - [' 
                    . $exe
                    . '] was executed - run count ['
                    . $runcount
                    . '], full path: ['
                    . $path . ']',
                  'short'      => $self->{'files'}->{$key} . ': ' . $exe . ' was executed',
                  'source'     => 'PRE',
                  'sourcetype' => $st . ' Prefetch',
                  'version'    => 2,
                  'extra' => { 'filename' => ${ $self->{'name'} } . "/" . $self->{'files'}->{$key} }
            };
        }
    }

    return \%container;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This format file parses the content of the Windows prefetch directory,
%SYSTEMROOT%/Prefetch 
It both parses the .pf files it finds as well as the Layout.ini file to return values
found inside the Prefetch folder
  ";

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
    my $file;
    my $line;
    my $ok_pf     = 0;
    my $ok_layout = 0;
    my %file_hash = undef;
    $self->{'files'} = undef;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'Not a folder';

    # verify if we have a folder
    return \%return unless -d ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # rewind the directory to the beginning
    seekdir $self->{'file'}, 0;

    # let the fun begin
    eval {
        # initialize variables
        $self->{'files'} = undef;
        $self->{'count'} = 0;

        # read the content of the directory and store it in a hash
        %file_hash = map { $self->{'count'}++ => $_ } readdir($self->{'file'});

        # now to store a reference to that hash inside self
        $self->{'files'} = \%file_hash;

        # check all files in the directory
        foreach $file (keys %{ $self->{'files'} }) {
            if ($self->{'files'}->{$file} =~ m/\.pf$/i) {
                if ($self->{'debug'}) {
                    print STDERR "Found a Prefetch file (" . $self->{'files'}->{$file} . ")\n"
                      unless $ok_pf;
                }
                $ok_pf = 1;
            }

            if (lc($self->{'files'}->{$file}) eq 'layout.ini') {
                if ($self->{'debug'}) {
                    print STDERR "Found a layout file (" . $self->{'files'}->{$file} . ")\n";
                }
                $ok_layout = 1;
            }
        }
    };
    if ($@) {
        $return{'msg'}     = "Unable to open folder: (" . ${ $self->{'name'} } . ") - $@\n";
        $return{'success'} = 0;
    }

    if ($ok_layout) {
        eval {
            open(LAYOUT, ${ $self->{'name'} } . $self->{'sep'} . "Layout.ini");
            $line = <FILE>;
            close(LAYOUT);
        };
        if ($@) {
            $return{'success'} = 0;
            $return{'msg'} .= ' Unable to open Layout file. ';
        }
    }
    else {
        print STDERR "Unable to find a layout file\n" if $self->{'debug'};
    }

    if ($ok_pf && $ok_layout) {
        $return{'success'} = 1;
    }

    return \%return;
}

#   _getMetaData
# get metadata from .pf files
# copyright 2007 H. Carvey keydet89@yahoo.com
sub _getMetaData {
    my $self = shift;

    # 64
    my $file = shift;
    my $data;
    my ($runcount, $runtime);
    my $exe;    # added by Kristinn
    my $dll_ofs;
    my $dll_length;
    my $drive_info;
    my $filepath;
    my ($volume_path, $volume_length, $volume_serial);

    open(FH, "<", $file) || return (undef, undef, undef, undef);
    binmode(FH);

    # addition by kristinn, check if this is prefetch or superfetch
    my $ofs     = 0;
    my $version = Log2t::BinRead::read_16(\*FH, \$ofs);
    $ofs     = 0x4;
    my $magic   = Log2t::BinRead::read_ascii(\*FH, \$ofs, 4);

    if ($magic eq 'SCCA') {
        print STDERR "[PREFETCH] Parsing file $file\n" if $self->{'debug'} > 1;

        $self->{'vista'} = 1 if ($version eq 0x17);
        $self->{'vista'} = 0 if ($version eq 0x11);
    }
    else {

        # not the correct magic value, incorrect file
        printf STDERR "[PREFETCH] Not parsing the file %s, wrong magic value (%s)\n", $file, $magic
          if $self->{'debug'} > 1;
        close(FH);
        return (undef, undef, undef, undef);
    }

    # end of check

    seek(FH, 0x78, 0) unless $self->{'vista'};
    seek(FH, 0x80, 0) if $self->{'vista'};    # if Vista/Win7

    read(FH, $data, 8);
    my @tvals = unpack("VV", $data);
    $runtime = Log2t::Time::Win2Unix($tvals[0], $tvals[1]);

    seek(FH, 0x90, 0) unless $self->{'vista'};
    seek(FH, 0x98, 0) if $self->{'vista'};    # if Vista/Win 7
    read(FH, $data, 4);
    $runcount = unpack("V", $data);

    # what follows was added by Kristinn
    $ofs = 0x10;                           # start of name part
    $exe = Log2t::BinRead::read_unicode_end(\*FH, \$ofs, 100);

    # get the offset for the DLL path
    $ofs = 0x64;
    $dll_ofs = Log2t::BinRead::read_32(\*FH, \$ofs);

    #printf STDERR "[PREFETCH] OFS %s - 0x%x\n",$file, $dll_ofs;
    # get the length of the filename path
    $dll_length = Log2t::BinRead::read_32(\*FH, \$ofs);

    #printf STDERR "[PREFETCH] LENGTH 0x%x\n",$dll_length;

    #$drive_info = Log2t::BinRead::read_32( \*FH, \$ofs );
    #printf STDERR "[PREFETCH] DRIVE INFO 0x%x\n",$drive_info;

    $ofs = $dll_ofs;
    $filepath = Log2t::BinRead::read_unicode(\*FH, \$ofs, $dll_length / 2);

    # get the volume information
    #$ofs = $drive_info;
    #$volume_path = Log2t::BinRead::read_16(\*FH, \$ofs );
    #$ofs = $drive_info + 4;
    #$volume_length = Log2t::BinRead::read_32( \*FH,\$ofs );

    #printf STDERR "[PREFETCH] LENGTH 0x%x PATH 0x%x\n",$volume_length,$volume_path;

    close(FH);
    return ($runcount, $runtime, $exe, $filepath);
}

1;

