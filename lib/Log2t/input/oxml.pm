#################################################################################################
#    OXML
#################################################################################################
# this script reads a log file and produces a bodyfile containing the timeline information
# that can be used directly with the script mactime from TSK collection.
# The specification of the body file can be found here:
#  http://wiki.sleuthkit.org/index.php?title=Body_file
# This script reads a document that is written in the OpenXML format, such
# as Microsoft Office documents and displays the metadata information that
# are contained in it according to the documentation that Microsoft provides
#
# See further information about the structure here:
#   http://msdn.microsoft.com/en-us/library/aa338205.aspx
#
# This script requires both Archive::Zip and LibXML,
# to install the dependencies using Ubuntu, issue the following commands:
#   apt-get install libarchive-any-perl
#   apt-get install libxml-libxml-perl
#
# According to the standard OpenXML documents are compressed using ZIP
# and therefore it is required to unzip the documents that contain the
# metadata information before processing them further.
# The metadata is then stored in a XML documents.  The file
# _rels/.rels defines the relationships that the document contains
# and therefore it should be the first file that is to be read.
# From there you can find any additional files that contain metadata
# information, most files will contain two metadata information files:
#  DOC.ENDING/docProps/app.xml
#  DOC.ENDING/docProps/core.xml
#
# This script will read the _rels/.rels file, parse it's input, search
# for any XML file that contains property information of the file and
# then parse that document and print out the metadata information found
# in it.
#
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 03/05/11
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

package Log2t::input::oxml;

# check to see if the script is running on Win or *NIX
#BEGIN{ if ( $^O =~ /MSWin32/ ) { use Win32::API;} };

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;
use Log2t::BinRead;
use Archive::Zip qw( :ERROR_CODES );
use XML::LibXML;
use XML::LibXML::Common;
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.4';

my $done;

# the constructor
sub new() {
    my $class = shift;

    # inherit from the base class
    my $self = $class->SUPER::new();

    # indicate that we would like to parse this file in one attempt, and return it in a single hash
    $self->{'multi_line'} = 0;

    # TEMPORARY - remove when FH is accepted through ZIP
    $self->{'file_access'} =
      1;    # do we need to parse the actual file or is it enough to get a file handle

    bless($self, $class);

    return $self;
}

sub init {
    my $self = shift;

    # set the default values
    $self->{'username'} = 'unknown';
    $self->{'lines'}    = undef;

    return 1;
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
    return "Parse the content of an OpenXML document (Office 2007 documents)";
}

#  get_time
#
# This is the main function of the tool, the one that parses the file and
# extracts timestamps
#
# It returns a reference to a hash that contains all the timestamp objects
sub get_time {
    my $self = shift;

    # define the needed variables
    my $doc;
    my $status;
    my $metadata;
    my $property;
    my $propertylist;
    my @properties;
    my @relationships;
    my $relationship;
    my $parent;
    my @list;
    my $attrib;
    my @targets;
    my $return = 1;
    my $error  = undef;
    my $xml;

    # initialize some variables
    $self->{'con_index'} = 0;
    $self->{'container'} = undef;

    $done = 0;

    # create a ZIP object
    $self->{'zip'} = Archive::Zip->new();

    # the filehandle (and rewind)
    #my $fh = $self->{'file'};
    #seek $fh,0,0;

    # read the Word document, that is the ZIP file

    # HERE WE ARE USING DIRECT FILE ACCESS, THAT IS WE ARE READING THE FILE ITSELF
    # THIS IS SOMETHING WE DO NOW WANT TO DO .... SO WHEN FILEHANDLE ACCESS IS FIXED THEN
    # WE NEED TO FIX THIS, UNTIL THEN THIS WILL HAVE TO DO
    $self->{'zip'}->read(${ $self->{'name'} }) == AZ_OK or $error = "Unable to open Office file\n";

    #$error = $z->readFromFileHandle( $fh, ${$self->{'name'}} );
    #$error = $self->{'zip'}->readFromFileHandle( $fh );

    unless ($error == AZ_OK) {
        print STDERR "[OXML] Error while trying to open file.  Message: $error\n";
        return undef;
    }

    # extract document information
    $status =
      $self->{'zip'}->extractMember('_rels/.rels', $self->{'temp'} . $self->{'sep'} . 'rels.xml');
    print STDERR "Unable to extract schema from file ["
      . ${ $self->{'name'} }
      . "], is it really a Office 2007 document (openXML)?\n"
      if $status != AZ_OK;
    return undef if $status != AZ_OK;

    # read the rels file
    $xml = XML::LibXML->new();

    # try to read inn the relationship file
    eval { $metadata = $xml->parse_file($self->{'temp'} . $self->{'sep'} . 'rels.xml'); };
    if ($@) {

# if we are unable to properly parse the relationship file, we cannot continue parsing the file, so let's gracefully exit
        print STDERR
          "[OXML] Unable to parse the relationship file (_rels/.rels)\n. Is this truly an OpenXML file, please verify manually.\nError message given: $@\n";
        return 0;
    }

    # get all the Relationship nodes
    $propertylist = $metadata->getDocumentElement();
    @properties   = $propertylist->childNodes;

    # get the encoding of the document
    $self->{'encoding'} = $metadata->encoding();

    # examine each one
    foreach $property (@properties) {

        # property is a node
        if ($property->nodeType == ELEMENT_NODE) {

            # now we are inside the Relationship tag, find the type
            @relationships = $property->attributes();

            # examine each attribute that is defined for the relationshp
            foreach $relationship (@relationships) {

                # we are trying to find nodes which contain property values for the file
                if ($relationship->toString =~ /.*Type.*prop.*/) {

                    # now we have a property that consists of a property file
                    # examine each attribute that is assigned to the parent node
                    $parent = $relationship->getOwnerElement();

                    @list = $parent->attributes();
                    foreach $attrib (@list) {

                        # need to find the attribute Target, since that defines
                        # the location of the XML document that describes the
                        # metadata information from the document
                        if ($attrib->toString =~ /Target/) {
                            print STDERR "[OXML] Pushing a target, " . $attrib->value . "\n"
                              if $self->{'debug'};

                            # push the name of the metadata document into the array targets
                            push(@targets, $attrib->value);
                        }
                    }
                }
            }
        }
    }

    # we no longer need the rels.xml file, so we delete it
    unlink($self->{'temp'} . $self->{'sep'} . 'rels.xml');

    # examine all the targets
    foreach $attrib (@targets) {

        # let's make an attempt of parsing the file
        eval {
            print STDERR "[OXML] Processing file $attrib\n" if $self->{'debug'};
            unless ($self->_process_file($attrib)) {
                print STDERR "Unable to read document metadata\n";
                return 0;
            }
        };
        if ($@) {
            print STDERR
              "[OXML] Unable to properly parse one of the OpenXML metadata XML files.  The file $attrib was the cause of all this trouble.
Please review this file manually.  The error message given is:\n$@\n";
            return 0;
        }
    }

    foreach (keys %{ $self->{'lines'} }) {

        # check if there is a date in this line
        if ($self->{'lines'}->{$_} =~ m/\d{4}-\d{2}-\d{2}/) {

            # we have a date
            print STDERR "[OXML] A date object " . $_ . " = [" . $self->{'lines'}->{$_} . "]\n"
              if $self->{'debug'};
            $self->{'timekey'} = $_;

            # process the timestamp
            $self->_process_timestamp
              or print STDERR "[OXML] Error while processing timestamp for $_ ("
              . $self->{'lines'}->{$_} . "\n";
        }
    }

    return $self->{'container'};
}

sub _process_timestamp {
    my $self = shift;

    # the timestamp object
    my $date;
    my $text;

    $date = Log2t::Time::iso2epoch($self->{'lines'}->{ $self->{'timekey'} }, $self->{'tz'});

    # construct the text field
    $text .= ' (' . $self->{'lines'}->{'title'} . ')'
      if (defined $self->{'lines'}->{'title'})
      and ($self->{'lines'}->{'title'} ne '');
    $text .= ' - ' . $self->{'lines'}->{'subject'} . ' - '
      if (defined $self->{'lines'}->{'subject'})
      and ($self->{'lines'}->{'subject'} ne '');
    $text .= ' - ' . $self->{'lines'}->{'description'} . ' - '
      if (defined $self->{'lines'}->{'description'})
      and ($self->{'lines'}->{'description'} ne '');
    $text .= ' - Application: ' . $self->{'lines'}->{'application'}
      if defined $self->{'lines'}->{'application'};
    $text .= ' - Company: ' . $self->{'lines'}->{'company'}
      if defined $self->{'lines'}->{'company'} and $self->{'lines'}->{'company'} ne '';
    $text .= ' - AppVersion: ' . $self->{'lines'}->{'appversion'}
      if defined $self->{'lines'}->{'appversion'} and $self->{'lines'}->{'appversion'} ne '';

    if (exists $self->{'lines'}->{'creator'}) {
        if ($self->{'username'} eq 'unknown') {
            $self->{'username'} = $self->{'lines'}->{'creator'};
        }
        elsif ($self->{'username'} eq $self->{'lines'}->{'creator'}) {

            # really no action here
            print STDERR "[OXML] The username is the same as the document's creator\n"
              if $self->{'debug'};
        }
        else {
            $self->{'username'} = $self->{'username'} . ' (' . $self->{'lines'}->{'creator'} . ')';
        }
    }

    if (exists $self->{'lines'}->{'description'} and $self->{'lines'}->{'description'} ne '') {
        $text .= ' - Desc: ' . $self->{'lines'}->{'description'};
    }

    $self->{'username'} = 'unknown' if $self->{'username'} eq '';
    $self->{'username'} = 'unknown' if $self->{'username'} eq ' ()';

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
        'time' => { 0 => { 'value' => $date, 'type' => $self->{'timekey'}, 'legacy' => 15 } },
        'desc' => $text,
        'short'      => $self->{'lines'}->{'description'},
        'source'     => 'OXML',
        'sourcetype' => 'Open XML Metadata',
        'version'    => 2,
        'extra'      => { 'user' => $self->{'username'}, }
                                                        };

    return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This plugin parses OpenXML documents, such as docx, pptx, xlsx and other
documents created using this standard (Office 2007 documents).  The parser relies upon the
following libraries:
  Archive::Zip 
  XML::LibXML
  XML::LibXML::Common
  Encode

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
    my @words;
    my $ofs = 0;

    # fix the endian
    #Log2t::BinRead::set_endian( Log2t::Common::LITTLE_E );
    Log2t::BinRead::set_endian(LITTLE_E);

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'unknown';

    return \%return unless -f ${ $self->{'name'} };

    # open the file (at least try to open it)
    eval {
        $self->{'info'}->{'magic'} = Log2t::BinRead::read_32($self->{'file'}, \$ofs);

        # check if this is truly an ZIP file (a la openXML)
        if ($self->{'info'}->{'magic'} eq 0x04034b50) {

            # then we would like to continue our reading
            $self->{'info'}->{'version'}       = Log2t::BinRead::read_16($self->{'file'}, \$ofs);
            $self->{'info'}->{'general'}       = Log2t::BinRead::read_16($self->{'file'}, \$ofs);
            $self->{'info'}->{'comp_method'}   = Log2t::BinRead::read_16($self->{'file'}, \$ofs);
            $self->{'info'}->{'last_mod_time'} = Log2t::BinRead::read_16($self->{'file'}, \$ofs);
            $self->{'info'}->{'last_mod_date'} = Log2t::BinRead::read_16($self->{'file'}, \$ofs);

            $self->{'info'}->{'crc2'}       = Log2t::BinRead::read_32($self->{'file'}, \$ofs);
            $self->{'info'}->{'compr_size'} = Log2t::BinRead::read_32($self->{'file'}, \$ofs);
            $self->{'info'}->{'size'}       = Log2t::BinRead::read_32($self->{'file'}, \$ofs);
            $self->{'info'}->{'filename_length'} = Log2t::BinRead::read_16($self->{'file'}, \$ofs);
            $self->{'info'}->{'extra_length'}    = Log2t::BinRead::read_16($self->{'file'}, \$ofs);

            $self->{'info'}->{'filename'} = Log2t::BinRead::read_ascii($self->{'file'}, \$ofs,
                                                              $self->{'info'}->{'filename_length'});

        }
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    #
    if ($self->{'info'}->{'magic'} eq 0x04034b50) {

        # this is an ZIP archive, now we need to confirm that this is an OpenXML document
        if ($self->{'info'}->{'filename'} =~ m/Content_Types/) {
            $return{'success'} = 1;
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'The file is a ZIP file but not an OpenXML document';
        }
    }
    else {
        $return{'success'} = 0;
        $return{'msg'}     = 'Wrong magic value';
    }

    return \%return;
}

# ------------------------------------------------------------------------------------------------------------
#  process_file
# ------------------------------------------------------------------------------------------------------------
# This function reads a XML file that contains metadata
# information from a OpenXML file and prints out all the
# tags that are defined within it.
#
# @param xmlfile A string that contains the path within the ZIP archive that contains metadata information
# @param title A title for the file to be printed out before the metadata is printed
# @return Return false if unsuccessful, else true
sub _process_file {
    my $self = shift;
    my @splits;
    my $xmlfile;
    my $status;
    my $metadata;
    my $propertylist;
    my @properties;
    my $property;
    my $xml;

    # assign the xmlfile
    $xmlfile = shift;

    $status =
      $self->{'zip'}->extractMember($xmlfile, $self->{'temp'} . $self->{'sep'} . 'file.xml');
    if ($status != AZ_OK) {
        print STDERR
          "[OXML ERROR] Unable to extract MetaData from file, is it really a Office 2007 document?\n";
        return 0;
    }

    # we can now read the file

    # create a XML parser
    $xml = XML::LibXML->new();

    # read inn all the XML
    $metadata = $xml->parse_file($self->{'temp'} . $self->{'sep'} . "file.xml");

    $propertylist = $metadata->getDocumentElement();
    @properties   = $propertylist->childNodes;

    foreach $property (@properties) {

        # property is a node
        if ($property->nodeType == ELEMENT_NODE) {
            @splits = split(':', $property->nodeName);

            # print the MetaData information
            if ($#splits eq 1) {
                print STDERR "[OXML] Pushing key " . lc($splits[1]) . " into lines\n"
                  if $self->{'debug'};
                $self->{'lines'}->{ lc($splits[1]) } =
                  encode($self->{'encoding'}, $property->textContent);
            }
            else {
                print STDERR "[OXML] Pushing key " . lc($splits[0]) . " into lines\n"
                  if $self->{'debug'};
                $self->{'lines'}->{ lc($splits[0]) } =
                  encode($self->{'encoding'}, $property->textContent);
            }

        }
    }

    unlink($self->{'temp'} . $self->{'sep'} . 'file.xml');

    return 1;
}

1;
