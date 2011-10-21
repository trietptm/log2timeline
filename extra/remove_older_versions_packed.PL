#!/usr/bin/perl
##########################################################################################
#	remove_older_version
##########################################################################################
# This is a very simple script designed to remove the older version of the tool before
# installing the new one.
#
# This is done just to make sure there are no conflicts with older versions.
#
# Built on the script found here: http://search.cpan.org/~yves/ExtUtils-Install-1.54/lib/ExtUtils/Packlist.pm
# Original author: Alan Burlison <Alan.Burlison@uk.sun.com> (of the above module and script associated to it)
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
use strict;
use IO::Dir;
use ExtUtils::Packlist;
use ExtUtils::Installed;

sub emptydir($) {
        my ($dir) = @_;
        my $dh = IO::Dir->new($dir) || return(0);
        my @count = $dh->read();
        $dh->close();
        return(@count == 2 ? 1 : 0);
}

# start by creating a new object of ExtUtils::old_version
my $old_version = ExtUtils::Installed->new();

# Now find all the associated files with the Log2t library
foreach my $file ( sort( $old_version->files("Log2t") ) )
{
	unlink( $file );
}

my $pf = $old_version->packlist("Log2t")->packlist_file();
unlink( $pf );

foreach my $dir ( sort($old_version->directory_tree("Log2t")))
{
	if( emptydir( $dir ) )
	{
		rmdir( $dir );
	}
}

exit 0;
