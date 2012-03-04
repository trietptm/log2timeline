#!/usr/bin/perl
#########################################################################################
#                       Numbers
#########################################################################################
# This is a small library to assist with number manipulation
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 30/08/09
#
# Copyright 2009 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::Numbers;

use vars qw($VERSION);

$VERSION = "0.1";

sub join_numbers($$) {
    my $lo = shift;
    my $hi = shift;
    my $number;

    if ($hi eq 0) {
        $number = $lo;
    }
    else {

        # need to join numbers
        $number = int($lo + $hi * 65536);
    }

    return $number;
}

# a small routine to round up an integer (to fix the dates)
sub roundup($) {
    my $n = shift;
    return (($n == int($n)) ? $n : int($n + 1));
}

1;

__END__

=pod

=head1 NAME

Log2t::Numbers - A library to manipulate numbers for the log2timeline tool

=head1 METHODS

=over 4

=item join_numbers ( low, high )

A function that takes two numbers and joins them together.  That is it takes as an argument two four bit numbers and returns an eight bit number combined of the two

=item roundup( number )

A function that takes as an argument a number (can be fractal) and returns an integer that is rounded up to the nearest integer.

=back

=cut

