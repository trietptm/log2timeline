#################################################################################################
#    restore
#################################################################################################
# This input module reads the rp.log files found inside the restore point folder of a
# Windows XP system to parse the timestamps of when the restore point was created.
#
# A small script that reads the rp.log file created during restore point creation
# and prints out information from the file
#
# Author: Kristinn Gudjonsson
# Version : 0.9
# Date : 04/05/11
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

package Log2t::input::restore;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Fcntl ':mode';         # for permission reading

use Encode;
use Log2t::Time;
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.9';

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

    $self->{'encoding'} = 'UTF-8';

    bless($self, $class);

    return $self;
}

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of the restore point directory";
}

#       get_time
# This is the main "juice" of the format file.  It takes the name of a restore point
# directory and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing the name of a restore point directory
# @return Returns a array containing the needed values to print a body file
sub get_time {
    my $self = shift;

    my $dev;
    my $inode;
    my $mode;
    my $nlink;
    my $uid;
    my $gid;
    my $rdev;
    my $size;
    my $atime;
    my $mtime;
    my $ctime;
    my $blksize;
    my $blocks;
    my $rpinfo;
    $self->{'cont_index'} = 0;    # zero the container

    foreach my $key (keys %{ $self->{'files'} }) {
        next unless $self->{'files'}->{$key} =~ m/^RP/;

# find information about the file (that is the RP directory itself)
#($dev,$inode,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$rp_dir/$dir");

        # next to find information from the restore point itself
        # read the content of the log file (rp.log)
        $self->{'rp_file'} =
            ${ $self->{'name'} }
          . $self->{'sep'}
          . $self->{'files'}->{$key}
          . $self->{'sep'}
          . 'rp.log';
        eval { $rpinfo = $self->_read_rpfile; };
        if ($@) {
            print STDERR "[RP] Problems reading the restore point "
              . $self->{'files'}->{$key}
              . ". Skipping it...\n";
            next;
        }

        ##  JLR - 10/11/2010 - return undef if $rpinfo is undef
        ##    fix for non-existant rp.log file
        next unless (defined $rpinfo);

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
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
            'time' =>
              { 0 => { 'value' => $rpinfo->{'date'}, 'type' => 'Created', 'legacy' => 15 } },
            'desc' => 'Restore point '
              . $self->{'files'}->{$key}
              . ' created - '
              . $rpinfo->{'name'},
            'short'      => 'Restore point ' . $self->{'files'}->{$key} . ' created',
            'source'     => 'RP',
            'sourcetype' => 'Restore Point',
            'version'    => 2,
            'extra'      => {}

              #'extra' => { 'uid' => $uid, 'gid' => $gid, 'mode' => $mode, 'size' => $size }
        };
    }

    return $self->{'container'};
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This format file reads the content of a restore point directory
and parses the rp.log file found inside each restore point directory to find information
about the restore point.  

To use this format file point to the directory that contains the restore point, such as
cd /mnt/analyze/System\ Volume\ Information\_restore{.....}/
log2timeline -f restore .
  ";

}

#       verify
# A subroutine that verifies if we are examining a restore point directory so it can be further
# processed.
# The correct format is a directory that consists of a at least one folder which begins with the letters
# RP followed by a number.  Inside this directory is a file called rp.log which is parsed.
#
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my @folders;
    my $found = 0;
    my $rp;
    my @words;
    my %file_hash = undef;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = '';

    my $class  = shift;
    my $dir    = shift;
    my $detail = shift;

    return \%return unless -d ${ $self->{'name'} };

    # open the file (at least try to open it)
    eval {
        $self->{'count'} = 0;    # initialize
        %file_hash =
          map { $self->{'count'}++ => $_ }
          grep { /^RP/ && -d ${ $self->{'name'} } . $self->{'sep'} . $_ } readdir($self->{'file'});
        $self->{'files'} = \%file_hash;
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open the restore point directory. ";
    }

    # now we have one line of the file, let's read it and verify
    foreach (keys %file_hash) {
        next if $found;

        if ($file_hash{$_} =~ m/^RP/) {
            $found = 1
              if -f ${ $self->{'name'} }
                  . $self->{'sep'}
                  . $file_hash{$_}
                  . $self->{'sep'}
                  . 'rp.log';
            $rp = $_;
        }
    }

    if ($found) {

        # there is a RP directory, see if there is a rp.log file inside
        if (-f ${ $self->{'name'} } . $self->{'sep'} . $file_hash{$rp} . $self->{'sep'} . 'rp.log')
        {

            # no error
            $return{'success'} = 1;
        }
        else {
            $return{'success'} = 0;
            $return{'msg'} .=
              'No rp.log file inside restore point, perhaps not a restore point directory?. ';
        }
    }
    else {
        $return{'msg'} .= 'Unable to find a restore point directory. 
Are there any restore points in the directory in question? (did you check the registry to see if restore point creation is disabled?) ';
        $return{'success'} = 0;
    }

    return \%return;
}

#  read_rpfile
#
# This function reads a rp (restore point) file and displays the
# name of the restore point as well as the date of creation
#
# @params  rp.log
# @return  array containing the name and date of restore point
sub _read_rpfile() {
    my $self = shift;

    # define variables needed
    my @name;
    my $i;    # a buffer
    my $offset;
    my $tag;
    my @dates;
    my %return;

    # and then we have a rp.log file underneath

    # read the rp.log file
    ##open( FILE, "$rp_file" ) || die("Could not open file: $rp_file");
    ##  JLR - 10/11/2010 - change to return undef if can't open file rather than die
    unless (open(FILE, $self->{'rp_file'})) {
        print STDERR "Could not open the restore point file: " . $self->{'rp_file'} . "\n";
        return undef;
    }

    # this is a binary file
    binmode(FILE);

    # read the name, starts in byte 16
    $offset = 0x10;

    # read the name, byte by byte
    $tag = 1;
    while ($tag) {

        # go to offset of file (starts in byte 16)
        seek(FILE, $offset, 0);

        # read 2 bytes, since we are reading a unicode text
        read(FILE, $i, 2);

        if (unpack("v", $i) == 0) {

            # '00' means the end of the name
            $tag = 0;
        }
        else {

            # not yet at the end, let's continue and push the value into the array
            push(@name, $i);
        }

        # increase the offset
        $offset += 2;
    }

    $return{'name'} = decode('utf16le', join('', @name));

    # read the date value
    seek(FILE, -0x8, 2);
    read(FILE, $i, 8);

    # correct format
    @dates = unpack("VV", $i);

    # find the actual date, using the date function from ptfinder.pl
    $return{'date'} = Log2t::Time::Win2Unix($dates[0], $dates[1]);

    # close the file
    close(FILE);

    # and now we are ready to return the values found
    return \%return;
}

1;
