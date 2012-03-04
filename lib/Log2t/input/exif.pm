#################################################################################################
#    EXIF
#################################################################################################
# This script is a part of the log2timeline project and provides a parser for exif information
# found inside various media files, such as JPEG,PNG,and others
#
# Author: Kristinn Gudjonsson
# Version : 0.4
# Date : 18/03/10
#
# Copyright 2009,2010 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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
package Log2t::input::exif;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Image::ExifTool qw(:Public);
use Log2t::Common qw/LITTLE_E BIG_E/;
use Log2t::Time;           # to manipulate time

#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;        # methods to read binary files

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = '0.4';

sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we would like to return only a single value
    $self->{'multi_line'} = 0;
    $self->{'type'}       = 'file';    # it's a file type, not a directory

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
#
# @return A string containing a description of the format file's functionality
sub get_description {
    return "Extract metadata information from files using ExifTool";
}

#       parse_line
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file

sub get_time {
    my $self = shift;

    my %container;    # the container of timestamp objects
    my $count_index = 0;    # index to the container
    my $value;
    my $etext = '';         # extra text

    foreach my $i (keys %{ $self->{'info'} }) {

        # just to check if this is the file modification
        next if $self->{'info'}->{$i}->{'key'} eq 'FileModifyDate';

        # otherwise we will just continue on

        $value = $self->{'info'}->{$i}->{'key'};

        #if ( $meta->{'FileType'} =~ m/EXE|DLL/ )  # unable to do since we do not receive File tags
        if ((${ $self->{'name'} } =~ m/\.dll|exe|sys/i))  # || ( $info{'file_name'} =~ m/\.exe/i ) )
        {

            # we have an executable, let's check if we have the timestamp "TimeStamp"
            if (lc($value) eq 'timestamp') {

                # modify the timestamp value to a more descriptive value
                $etext = 'PE header TimeDate Stamp (when application was linked/compiled)';
            }
            else {

                # we are still left with a PE header, so let's make it more descriptive
                $etext = 'PE Header: ' . $self->{'info'}->{$i}->{'key'};
            }
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
        $container{$count_index} = {
                                  'time' => {
                                      0 => {
                                          'value' => $self->{'info'}->{$i}->{'time'},
                                          'type' => $self->{'info'}->{$i}->{'group'} . '/' . $value,
                                          'legacy' => 15
                                      }
                                  },
                                  'desc'       => $value . ' ' . $etext,
                                  'short'      => $value,
                                  'source'     => 'EXIF',
                                  'sourcetype' => 'EXIF metadata',
                                  'version'    => 2,
        };

        # we sometimes get empty lines, check for that (and ignore)
        $container{$count_index}->{'desc'} = '' unless defined $self->{'info'}->{$i}->{'time'};
        $count_index++;
    }

    return \%container;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return
      "This input module parses files to search for metadata information embedded in the file.  All metadata information that contains date values is then processes.
The format file extracts all metadata information that the library Image::ExifTool is capable of reading.  That means that not only JPG or other image formats can be read, ExifTool is capable of reading metadata from various sources.";

}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {

    # define an array to keep
    my %return;
    my $self = shift;
    my @tags;
    my $count;
    my $meta;

    my $exif;

    # this needs to be a file to be included
    return \%return unless -f ${ $self->{'name'} };

    # create an exif object
    $exif = new Image::ExifTool;

    $return{'success'} = 0;
    $return{'msg'}     = 'unable to open file';

    # check if this is a XML file, we don't want to spend time parsing them
    unless ($self->{'quick'}) {

        # check the name (does it end with a .xml)
        return \%return if ${ $self->{'name'} } =~ m/\.xml$/i;

        # check to see if it is a XML file nonetheless

        # start by setting the endian correctly
        Log2t::BinRead::set_endian(LITTLE_E);

        # read the temporary value
        my $ofs = 0;
        my $temp = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 10);

        # we don't want to parse XML files (even if they are called manifest or xib)
        if (lc($temp) =~ m/<\?xml/) {
            $return{'msg'} = 'Parsing XML files using ExifTools takes too long time';
            return \%return;
        }
    }

    # let's rewind the file to the beginning, since we now need to read it again
    seek($self->{'file'}, 0, 0);

    # set the date variable
    $exif->Options(DateFormat => "%Y:%m:%d %H:%M:%S");

    # processing would be considerably easier using Epoch from the gecko
    #$exif->Options( DateFormat => "%s" );

    # we don't care about filesystem timestamps
    $exif->Options(Group0 => [ '-File', '-ZIP' ]);

    # reset the info hash (since we could be recursively going through)

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'Did not find any valid dates (except filesystem modification date)';

    # try to get metadata information from the file
    eval {

        #print STDERR "[EXIF] Trying to read metadata information from file\n";
        $meta = $exif->ImageInfo($self->{'file'});

        #print STDERR "[EXIF] Successfully read the metadata, now moving on to parsing it\n";
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to obtain metadata information";
    }

    # now we need to verify that meta is of the correct format
    # since we can read metadata information from all files, this will
    # always return 1, even though the file will not produce any valid data

    # we therefore start by constructing the file for later use ( instead of
    # using the prepare function )
    # since we want to know if there are any time values that we can use

    # initialize the info hash
    $self->{'info'} = undef;

    # set the counter up
    $count = 0;

    # get all the tags (just interested in Group0 information
    @tags = $exif->GetTagList($meta, 'Group0');

    # find all dates inside the meta
    foreach my $t (@tags) {

        #print STDERR "[EXIF] Parsing tag $t\n";

        # verify that we have a valid date
        if ($meta->{$t} =~ m/\d+:\d+:\d+/) {

            #print STDERR "[EXIF] Perhaps a date\n";

            # try to parse
            if (Log2t::Time::is_date($meta->{$t})) {

                #print STDERR "[EXIF] We have a date ($t) " . $meta->{$t} . "\n";

                $self->{'info'}->{ $count++ } = {
                                  'time'  => Log2t::Time::exif_to_epoch($meta->{$t}, $self->{'tz'}),
                                  'key'   => $t,
                                  'org'   => $meta->{$t},
                                  'group' => $exif->GetGroup($t,                     0)
                                                };
            }
        }
    }

    # now we've got the structure up and running, let's find out
    # if we have a valid file that we would like to examine
    $return{'success'} = 1 if $count > 0;

    return \%return;
}

1;
