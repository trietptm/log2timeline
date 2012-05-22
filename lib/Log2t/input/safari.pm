#!/usr/bin/perl
# Safari
#
# This script handles Safari History.plist files.  Frankly, most of the heavy
# lifting is done by Brian D. Foy's Mac::PropertyList module (available from
# the CPAN).  This module just reports out using the log2timeline API.
#
# Author: Hal Pomeranz (hal.pomeranz@mandiant.com)
# Version: 0.3
# Date: 2011-04-30
#
# Distributed with and under the same licensing terms as log2timeline
#
# Updated by Kristinn to make it fit into the 0.6x API
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
# For errors with Mac::Propertylist, see: https://rt.cpan.org/Public/Bug/Display.html?id=63683
package Log2t::input::safari;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Mac::PropertyList;
use Log2t::Common;
use Log2t::Time;
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = '0.3';

# the default constructor
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we would like to parse this file in one attempt, and return it in a single hash
    $self->{'multi_line'} = 0;

    bless($self, $class);

    return $self;
}

sub get_description {
    return "Parse the contents of a Safari History.plist file";
}

sub get_help {
    return "Usage: $0 -f safari ... -- [-u username] [-h hostname]

This plugin parses the content of History.plist, a binary property
list file containing Safari browsing history.  On Mac OS X systems,
this file is typically in /User/<username>/Library/Safari";
}

# Check the preamble of the file to see if we're looking at the right thing.
sub verify {
    my $self = shift;
    my $buf  = undef;

    my %return = ('success' => 0, 'msg' => 'No such file or directory');
    return \%return unless (-f ${ $self->{'name'} });

    read($self->{'file'}, $buf, 32);

    unless ($buf =~ /^bplist00.*WebHistoryFile/) {
        $return{'msg'} = 'Does not appear to be a History.plist file';
        return \%return;
    }

    $return{'success'} = 1;
    $return{'msg'}     = 'Success';
    return \%return;
}

sub init {
    my $self = shift;

    # Try really hard to get a user name
    unless (defined($self->{'username'})) {
        $self->{'username'} = Log2t::Common::get_username_from_path(${ $self->{'name'} });
    }

    return 1;
}

# Use Mac::PropertyList::parse_plist_file() to scarf in the plist file.
# Then convert the object hierarchy returned by parse_plist_file() into
# a Perl data structure using the $objects->as_perl() method.
#
# Also attempt to figure out the username and hostname-- from the command
# line if possible, but otherwise using get_username_from_path()
#
sub get_time {
    my $self       = shift;
    my $Data       = undef;    # Perl data structure produced from plist file
    my %container  = undef;    # the container that stores all the timestamp data
    my $cont_index = 0;        # index into the container

    my $objects;

    eval { $objects = Mac::PropertyList::parse_plist_file($self->{'file'}); };
    if ($@) {
        print STDERR "[Safari] Error $@\n";
        return undef;
    }
    if (ref($objects) ne 'Mac::PropertyList::dict') {
        print STDERR "[Safari] Error.  Object reference is not of type Mac::PropertyList::dict\n";
        return undef;
    }

    eval { $Data = $objects->as_perl; };
    if ($@) {
        print STDERR "[Safari] Error occured.  Error message: $@\n";
        return (undef);
    }

    return (undef) unless (ref($$Data{'WebHistoryDates'}));

    # Get a new history record (go through all of them)
    foreach my $ref (@{ $$Data{'WebHistoryDates'} }) {

        # New %t_line structure.  Most of the basic information is fixed.
###  this syntax seems to be broken for 0.60.  Breaking this out into
###   individual components (edited by John Ritchie)
        #  $container{$cont_index} =  ('source' => 'WEBHIST',
        #      'sourcetype' => 'Safari history',
        #      'version' => 2,
        #      'extra' => { 'user' => $self->{'username'}, },
        #  );
        $container{$cont_index}->{'source'}     = 'WEBHIST';
        $container{$cont_index}->{'sourcetype'} = 'Safari history';
        $container{$cont_index}->{'version'}    = 2;
        $container{$cont_index}->{'extra'}      = { 'user' => $self->{'username'}, };

        # check the existence of a default browser for this particular user (added by Kristinn)
        if (defined $self->{'defbrowser'}->{ lc($self->{'username'}) }) {
            $container{$cont_index}->{'notes'} =
              $self->{'defbrowser'}->{ $self->{'username'} } =~ m/safari/
              ? 'Default browser for user'
              : 'Not the default browser (' . $self->{'defbrowser'}->{ $self->{'username'} } . ')';
        }
        elsif ($self->{'defbrowser'}->{'os'} ne '') {

            # check the default one (the OS)
            $container{$cont_index}->{'notes'} =
              $self->{'defbrowser'}->{'os'} =~ m/safari/
              ? 'Default browser for system'
              : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
        }

        # Populate fields of %t_list structure from history record
        $container{$cont_index}->{'short'} = encode('utf-8', "URL: $$ref{''}");
        $container{$cont_index}->{'desc'} =
          "$$ref{''} ($$ref{'title'}) [Visit Count: $$ref{'visitCount'}]";
        $container{$cont_index}->{'desc'} .=
          " (redirected from " . join(', ', @{ $$ref{'redirectURLs'} }) . ")"
          if (ref($$ref{'redirectURLs'}));
        $container{$cont_index}->{'desc'} .= " [Non-GET request]"
          if ($$ref{'lastVisitWasHTTPNonGet'} eq 'true');
        $container{$cont_index}->{'desc'} = encode('utf-8', $container{$cont_index}->{'desc'});

        $container{$cont_index}->{'time'}{0} = {
                                        'value' => Log2t::Time::mac2epoch($$ref{'lastVisitedDate'}),
                                        'type'  => 'Last visited',
                                        'legacy' => 15
        };
        $cont_index++;
    }

    return \%container;
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

1;
