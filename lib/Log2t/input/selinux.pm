#################################################################################################
#    SELINUX
#################################################################################################
# This script is a part of the log2timeline program.
#
# It implements a parser for Linux SELinux audit logs
#
# Author: Francesco Picasso
# Version : 0.1
# Date : 26/06/12
# Copyright 2012 Francesco Picasso (francesco.picasso ( a t ) gmail (d o t) com)
#
# Distributed with and under the same licensing terms as log2timeline
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

=pod

=head1 NAME

selinux - a parser for SELinux audit files

=head1 DESCRIPTION

SELinux Audit files could provide relevant information to analysts.
This module parses the audit.log files extracting timestamp and message
from log's lines.

=head1 METHODS

=cut

package Log2t::input::selinux;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

# by default these are the global varibles that get passed to the module
# by the engine.
# These variables can therefore be used in the module without needing to
# do anything to initalize them.
#
#  $self->{'debug'}  - (int) Indicates whether or not debug is turned on or off
#  $self->{'quick'}   - (int) Indicates if we will like to do a quick verification
#  $self->{'tz'}    - (string) The timezone that got passed to the tool
#  $self->{'temp'}    - (string) The name of the temporary directory that can be used
#  $self->{'text'}    - (string) The path that is possible to add to the input (-m parameter)
#  $self->{'sep'}     - (string) The separator used (/ in Linux, \ in Windows for instance)
#

=head2 C<new>

Module constructor.

=head3 Returns:

=head4 An instance of the class.

=cut

sub new() {
    my $class = shift;

    # now we call the SUPER class's new function, since we are inheriting all the
    # functions from the SUPER class (input.pm), we start by inheriting it's calls
    # and if we would like to overwrite some of its subroutines we can do that, otherwise
    # we don't need to include that subroutine
    my $self = $class->SUPER::new();

    bless($self, $class);
    return $self;
}

=head2 C<get_version>

A simple subroutine that returns the version number of the input module.

=head3 Returns:

=head4 A string representing the version number.

=cut

sub get_version() {
    return $VERSION;
}

=head2 C<get_description>

A simple subroutine that returns a string containing a description of
the funcionality of the input module. This string is used when a list of
all available input modules is printed out.

=head3 Returns:

=head4 A string containing a description of the input module.

=cut

sub get_description() {
    return "Parse the content of SELinux audit log files";
}

=head2 C<get_time>

The subroutine parses a single log line, extracting the timestamp
and the message part. It tries to fill some other fields like
user, application and so on.
(TODO: a better explanation is required).

=cut

sub get_time() {
    my $self = shift;

    # the timestamp object
    my %t_line;
    my $type;
    my $timestamp;
    my $desc;
    my $user = '';

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh> or return undef;

    if ($line =~ m/^type=([^ ]+)[ ]+msg=audit\(([0-9]+)\.[0-9]+:[0-9]+\):[ ]+([^\n]+)/) {

        # ' msg=audit(1337845321.228:94998): '
        # as a timestamp it's considered only the part until dot
        $type      = $1;
        $timestamp = $2;
        $desc      = $3;
    }
    else {
        print STDERR "ERROR: unable to find type and msg fields!\n";
        return \%t_line;
    }

    if ($desc =~ m/ acct="([^"]+)" /) {
        $user = $1;
    }

    # create the t_line variable
    %t_line = (
        'time' => { 0 => { 'value' => $timestamp, 'type' => 'Time Written', 'legacy' => 15 } },
        'desc'       => "type=$type " . $desc,
        'short'      => $type,
        'source'     => 'LOG',
        'sourcetype' => 'SELinux audit log',
        'version'    => 2,
        'extra'      => { 'user' => $user }
              );
    return \%t_line;
}

=head2 C<get_help>

A simple subroutine that returns a string containing the help 
message for this particular input module.

=head3 Returns:

=head4 A string containing a help description for this input module.

=cut

sub get_help() {
    return "SELinux Audit files could provide relevant information to analysts.
This module parses the audit.log files extracting timestamp and message
from log's lines.";
}

=head2 C<verify>

The module verify subroutine makes these checks to understand if it's
the right file:
- check if input it's a file (correct) or a directory (wrong)
- check name: if the name includes 'audit*.log'
  Note that renamed files and ARCHIVED files (tgz) will be skipped!
- check the first 5 bytes if they contain "type="
- check if the " msg=audit(1337845201.174:94983):" is present

=head3 Returns:

=head4 A reference to a hash that contains two keys/values.

success -> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
msg     -> A short description why the verification failed (if the value of success is zero that is).

=cut

sub verify() {
    my $self = shift;

    # define an array to keep
    my %return;
    my $file_size;
    my $tag;
    my $file_name = ${ $self->{'name'} };

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # file/directory check
    return \%return unless -f $file_name;

    # name check
    if (not $file_name =~ m/audit[^.]*\.log/) {
        $return{'msg'} = "Wrong file name [$file_name]";
        return \%return;
    }

    # content checks (2 checks)
    eval {
        my $ofs = 0;
        Log2t::BinRead::set_endian(LITTLE_E);
        my $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "=", 5);

        if ($line ne 'type') {
            $return{'msg'} = "First 4 bytes are not 'type' [$line]";
            return \%return;
        }

        $ofs = 0;

        # seek( $self->{'file'}, 0, 0 );
        $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 1024);
        if ($line =~ m/(.*msg=audit\()(\d+)(\.\d+:\d+.*)\)/) {
            $return{'success'} = 1;
            return \%return;
        }
        else {
            $return{'msg'} = "First log line does not contain a valid msg field";
            return \%return;
        }
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to process file ($@)";
        return \%return;
    }
    return \%return;
}

1;

__END__
