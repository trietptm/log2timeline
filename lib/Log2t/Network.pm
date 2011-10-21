#!/usr/bin/perl
#########################################################################################
#                       Network
#########################################################################################
# This is a small library that is a part of the tool log2timeline. It's purpose is to 
# provide information regarding network
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 07/09/09
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

package Log2t::Network;

use strict;

use vars qw($VERSION);

$VERSION = "0.1";

# taken from IANA
my %icmp_type = (
  0 =>    'Echo Reply',
  1 =>    'Unassigned',
  2 =>    'Unassigned',
  3 =>    'Destination Unreachable',
  4 =>    'Source Quench',
  5 =>    'Redirect',
  6 =>    'Alternate Host Address',
  7 =>    'Unassigned',
  8 =>    'Echo',
  9 =>    'Router Advertisement',
 10 =>    'Router Solicitation',
 11 =>    'Time Exceeded',
 12 =>    'Parameter Problem',
 13 =>    'Timestamp',
 14 =>    'Timestamp Reply',
 15 =>    'Information Request',
 16 =>    'Information Reply',
 17 =>    'Address Mask Request',
 18 =>    'Address Mask Reply',
 19 =>    'Reserved (for Security)',
 20 =>  'Reserved (for Robustness Experiment)',
 21 => 'Reserved (for Robustness Experiment)',
 22 => 'Reserved (for Robustness Experiment)',
 23 => 'Reserved (for Robustness Experiment)',
 24 => 'Reserved (for Robustness Experiment)',
 25 => 'Reserved (for Robustness Experiment)',
 26 => 'Reserved (for Robustness Experiment)',
 27 => 'Reserved (for Robustness Experiment)',
 28 => 'Reserved (for Robustness Experiment)',
 29 => 'Reserved (for Robustness Experiment)',
 30 =>    'Traceroute',
 31 =>    'Datagram Conversion Error',
 32 =>    'Mobile Host Redirect',
 33 =>    'IPv6 Where-Are-You',
 34 =>    'IPv6 I-Am-Here',
 35 =>    'Mobile Registration Request',
 36 =>    'Mobile Registration Reply',
 37 =>    'Domain Name Request',
 38 =>    'Domain Name Reply',
 39 =>    'SKIP',
 40 =>    'Photuris',
 41 =>    'ICMP messages utilized by experimental'
);

# type 3
my %icmp_error_code = (
	0 => 'Net Unreachable',
	1 => 'Host Unreachable',
	2 => 'Protocol Unreachable',
	3 => 'Port Unreachable',
	4 => 'Fragmentation Needed and Don\'t Fragment was Set',
	5 => 'Source Route Failed',
	6 => 'Destination Network Unknown',
	7 => 'Destination Host Unknown',
	8 => 'Source Host Isolated',
	9 => 'Communication with Destination Network is Administratively Prohibited',
	10 => 'Communication with Destination Host is Administratively Prohibited',
	11  => 'Destination Network Unreachable for Type of Service',
	12  => 'Destination Host Unreachable for Type of Service',
	13  => 'Communication Administratively Prohibited',
	14  => 'Host Precedence Violation',
	15  => 'Precedence cutoff in effect'
);

# type  5
my %icmp_redirect_code = (
            0  => 'Redirect Datagram for the Network (or subnet)',
            1  => 'Redirect Datagram for the Host',
            2  => 'Redirect Datagram for the Type of Service and Network',
            3  => 'Redirect Datagram for the Type of Service and Host'
);

# type 11
my %icmp_time_exceeded = (
            0  => 'Time to Live exceeded in Transit',
            1  => 'Fragment Reassembly Time Exceeded'
);

# type 12
my %icmp_parameter_problem = (
            0  => 'Pointer indicates the error',
            1  => 'Missing a Required Option',
            2  => 'Bad Length'
);

sub get_icmp_text($$)
{
	my $type = shift;
	my $code = shift;

	my %result;

	$result{type} = $icmp_type{ $type };

	# check the type
	if( $type eq 3 )
	{
		$result{code} = $icmp_error_code{$code };
	}
	elsif( $type eq 5 )
	{
		$result{code} = $icmp_redirect_code{$code};
	}
	elsif( $type eq 11 )
	{
		$result{code} = $icmp_time_exceeded{$code};
	}
	elsif( $type eq 12 )
	{
		$result{code} = $icmp_parameter_problem{$code};
	}
	else
	{
		$result{code} = $code;
	}
		

	return \%result;
}

1;
