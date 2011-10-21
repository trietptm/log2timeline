#!/usr/bin/perl
#########################################################################################
#			binread
#########################################################################################
# This is a small library to assist with the reading of binary files
#
# Author: Kristinn Gudjonsson
# Version : 0.6
# Date : 12/01/10
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
# Few lines of code have been borrowed from a CPAN module called Parse::Flash::Cookie
#  Copyright 2007 Andreas Faafeng, all rights reserved.


package Log2t::BinRead;

use Encode;
use Log2t::Common ':binary';

my $VERSION = "0.6";

# The following constants were taken from the file Cookie.pm
# (a CPAN module, called Parse::Flash::Cookie)
#  Copyright 2007 Andreas Faafeng, all rights reserved.
# The below constants are little-endian.  Adobe flash cookies are
# little-endian even on big-endian platforms.
use constant POSITIVE_INFINITY => "\x7F\xF0\x00\x00\x00\x00\x00\x00";
use constant NEGATIVE_INFINITY => "\xFF\xF0\x00\x00\x00\x00\x00\x00";
use constant NOT_A_NUMBER      => "\x7F\xF8\x00\x00\x00\x00\x00\x00";


# temporary data, storing read data
my $temp;
my $endian = LITTLE_E;

# a small subroutine that sets the endian of the reader
sub set_endian($)
{
	my $end = shift;
	$endian = LITTLE_E if $end eq LITTLE_E;
	$endian = BIG_E if $end eq BIG_E;

	return 1;
}

#       read_ascii
#
# A small function to read x bytes from the $fh packet, as defined in a parameter
# to the function
#
# Example usage in script:
# $string = Log2t::BinRead::read_ascii(\*FH, \$ofs, 4 );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       for_length      An integer indicating the number of bytes to read
# @return       A concentrated string that contains x bytes (for_length many bytes)
sub read_ascii($$$)
{
	my $fh = shift;
	my $ofs = shift;
        my $for_length = shift;

        my @l;

        for( my $i=0 ; $i < $for_length; $i++ )
        {
                seek($fh,$$ofs,0);
                read($fh,$temp,1) or return 0;

                $$ofs++;
		next if $temp eq "\0";
                push( @l, $temp );
        }

	return 0 if $#l eq -1;

        return join('',@l );
}

#       read_raw_until
#
#
# Example usage in script:
# $string = Log2t::BinRead::read_raw_until(\*FH, \$ofs, \@byte_sequence );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       max	An integer, indicating the length to read
# @params       cp   	A reference to an array that contains the bytes that mark the end
# @return       A concentrated string that contains x bytes (for_length many bytes)
sub read_raw_until($$$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $max = shift;
	my $cp = shift;

	my $tag = 1;
	my $index = 0;

	my $line;
	my @line_a;

	while( $tag )
	{
		seek($fh,$$ofs,0);
		read($fh,$temp,1) or return 0;
		$temp = unpack( "c", $temp );
		$$ofs++;

		#printf STDERR "%s (0x%x) ",$temp,$temp;

		if( $temp == ${$cp}[$index] )
		{
			# check if we have reached the end
			if( $#{$cp} eq $index )
			{
				# reached the end
				$tag = 0;
			}
			else
			{
				# increase the index
				$index++;
			}
		}
		else
		{
			$index = 0;
		}

		$tag = 0 unless $$ofs < $max;

		next unless $tag;
		push( @line_a, $temp );
	}

	print STDERR "\n";

	# we have a new line, let's print it out
	$line = join('',@line_a);
	$line =~ s/\0//g;
	$line =~ s/[[:cntrl:]]//g;
	
	return $line;			
}

#       read_ascii_end
#
# A function to read an ascii string until we reach the end of string
# or the null character
#
# Example usage in script:
# $string = Log2t::BinRead::read_ascii_end(\*FH, \$ofs, 50 );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       max     An integer indicating the max length of a string 
# @return       A concentrated string that contains x bytes (for_length many bytes)
sub read_ascii_end($$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $max = shift;

	my $i = 0;
	my $tag = 1;

	my $line;
	my @line_a;

	while( $tag )
	{
		seek($fh,$$ofs,0);
		read($fh,$temp,1) or return 0;
		$$ofs++;

		$tag = 0 if $temp eq "\0";
		$tag = 0 if  $i == $max; 

		$i++;
		next unless $tag;
		push( @line_a, $temp );
	}

	# we have a new line, let's print it out
	$line = join('',@line_a);
	$line =~ s/\0//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}


#       read_ascii_until
#
# A function to read an ascii string until we reach the user supplied end marker
# or the null character
#
# Example usage in script:
# $string = Log2t::BinRead::read_ascii_until(\*FH, \$ofs, $marker, \$max );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       marker	A string referring to the ASCII symbol we are searching for
#			or a reference to an array with multiple markers
# @params       max     An integer indicating the max length of a string 
# @return       A concentrated string that contains x bytes (for_length many bytes)
sub read_ascii_until($$$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $marker = shift;
	my $max = shift;

	my $i = 0;
	my $tag = 1;

	my $line;
	my @line_a;

	while( $tag )
	{
		seek($fh,$$ofs,0);
		read($fh,$temp,1) or return 0;
		$$ofs++;

		$tag = 0 if $temp eq "\0";
		if( ref( $marker ) eq 'ARRAY' )
		{
			foreach( @{$marker} )
			{
				$tag = 0 if $temp eq $_;
			}
		}
		else
		{
			$tag = 0 if $temp eq $marker;
		}
		$tag = 0 if  $i == $max; 

		$i++;
		next unless $tag;
		push( @line_a, $temp );
	}

	
	# we have a new line, let's print it out
	$line = join('',@line_a);
	$line =~ s/\0//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}

#       read_ascii_magic
#
# A function to read an ascii string until we reach the user supplied end magic
# value or maximum amount of characters
#
# Example usage in script:
# $string = Log2t::BinRead::read_ascii_until(\*FH, \$ofs, \$max, \$marker );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       max     An integer indicating the max length of a string 
# @params       marker	A string referring to the magic value we are searching for
#			or a reference to an array with multiple markers
# @return       A concentrated string that contains x bytes (for_length many bytes)
#
sub read_ascii_magic($$$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $max = shift;
	my $marker = shift;	# either a reference to an array or a single string

	my $i = 0;
	my $tag = 1;

	my $line;
	my $length;
	my $tl;

	while( $tag )
	{
		# start to check if we have an array or a single value
		if( ref( $marker ) eq 'ARRAY' )
		{
			# go through each marker
			foreach( @{$marker} )
			{
				# get the length of the magic value to search for
				$length = length( $_ );
	
				# read the string to match
				$tl = '';
				for( my $j = 0; $j < $length; $j++ )
				{
					seek( $fh, $$ofs+$j, 0 );
					read( $fh, $temp, 1 ) or return 0;
	
					$tl .= $temp;
				}
				
				# compare the string
				$tag = 0 if $tl eq $_;
			}
		}
		else
		{
			$length = length( $marker );

			$tl = '';
			for( my $j = 0; $j < $length; $j++ )
			{
				# read the string to match
				seek( $fh, $$ofs+$j, 0 );
				read( $fh, $temp, 1 ) or return 0;

				$tl .= $temp;
			}

			# compare the string
			$tag = 0 if $tl eq $marker;
		}
	
		# check if we've reached the end, or the magic value has come up
		next unless $tag;

		# no we are about to read a single character (no magic value yet)
		seek($fh,$$ofs,0);
		read($fh,$temp,1) or return 0;
		$$ofs++;
	
		# check if we have reached the end of string			
		$tag = 0 if $temp eq "\0";
		$tag = 0 if  $i == $max; 
		$i++;

		# add to the line
		$line .= $temp;
	}

	# we have a new line, let's print it out
	$line =~ s/\0//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}

#       read_unicode
#
# A function to read an Unicode string until we have reached the "for_length" character 
#
# Example usage in script:
# $string = Log2t::BinRead::read_unicode(\*FH, \$ofs, 10 );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       for_length	An integer indicating the amount of characters to read (Unicode) 
# @return       A concentrated string that contains $for_length Unicode encoded characters 
sub read_unicode($$$)
{
	my $fh = shift;
	my $ofs = shift;
        my $for_length = shift;

	my $line;

	# read the file, line by line
	for( my $i; $i < $for_length; $i++ )
	{
	        seek($fh,$$ofs,0);
	        read($fh,$temp,2) or return 0;
		$$ofs+=2;

		$line .= encode('utf-8',$temp);
	}

	# we have a new line, let's print it out
	$line =~ s/\00//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}

#       read_unicode_until
#
# A function to read an unicode string until we reach the end of string
# or the null character
#
# Example usage in script:
# $string = Log2t::BinRead::read_unicode_end(\*FH, \$ofs, 50 );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       max     An integer indicating the maximum characters in string (max * 2 = bytes)
# @return       A concentrated string that contains an Unicode string until a 0x00 is found (or max characters)
sub read_unicode_until($$$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $marker = shift;
	my $max = shift;

	my $tag = 1;
	my $i = 0;
	my $char;
	my $line;

	# read the file, line by line
	while( $tag )
	{
	        seek($fh,$$ofs,0);
	        read($fh,$temp,2) or return 0;
		$$ofs+=2;

		$char = unpack( "v", $temp );
	
	        # check if we have reached the end of the file
		$tag = 0 if $char eq 0x00;

                if( ref( $marker ) eq 'ARRAY' )
                {
                        foreach( @{$marker} )
                        {
                                $tag = 0 if $char == ord(  $_  );
                        }
                }
                else
                {
			#printf STDERR "[MARKER] marker 0x%x and variable 0x%x (char 0x%x - %s)\n", $marker, $temp, $char, $char;
			#print STDERR "[2nd] Marker " . ord( $marker ) . " and compare to " . $char . " \n";
			$tag = 0 if $char == ord( $marker );
                }

		# check if we have reached our max value
		$tag = 0 if $i == $max;

		$i++;
		next unless $tag;

		$line .= encode('utf-8',$temp);
	}

	# we have a new line, let's print it out
	$line =~ s/\00//g;
	$line =~ s/\n//g;
	$line =~ s/\r//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}
#       read_unicode_end
#
# A function to read an ascii string until we reach the end of string
# or the null character
#
# Example usage in script:
# $string = Log2t::BinRead::read_unicode_end(\*FH, \$ofs, 50 );
# 
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @params       max     An integer indicating the maximum characters in string (max * 2 = bytes)
# @return       A concentrated string that contains an Unicode string until a 0x00 is found (or max characters)
sub read_unicode_end($$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $max = shift;

	my $tag = 1;
	my $i = 0;
	my $char;
	my $line;

	# read the file, line by line
	while( $tag )
	{
	        seek($fh,$$ofs,0);
	        read($fh,$temp,2) or return 0;
		$$ofs+=2;

		$char = unpack( "v", $temp );
	
	        # check if we have reached the end of the file
		$tag = 0 if $char eq 0x00;

		# check if we have reached our max value
		$tag = 0 if $i == $max;

		$i++;
		next unless $tag;

		$line .= encode('utf-8',$temp);
	}

	# we have a new line, let's print it out
	$line =~ s/\00//g;
	$line =~ s/[[::cntrl::]]//g;
	
	return $line;			
}

#       read16
#
# A small function to read two bytes or 16 bits from the file and return it
#
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @return two bytes of data
sub read_16($$)
{
	my $fh = shift;
	my $ofs = shift;

        seek($fh,$$ofs,0);
        read($fh,$temp,2) or return 0;
        $$ofs+=2;

	if( $endian eq LITTLE_E )
	{
        	return unpack("v", $temp );
	}
	else
	{
        	return unpack("n", $temp );
	}
}

sub read_short($$)
{
	my $fh = shift;
	my $ofs = shift;

        seek($fh,$$ofs,0);
        read($fh,$temp,2) or return 0;
        $$ofs+=2;

	if( $endian eq LITTLE_E )
	{
        	return unpack("S", $temp );
	}
	else
	{
        	return unpack("s", $temp );
	}
}

#       read_double
#
# A small function to read eight bytes or 64 bits, a double precision number
# and returns the number
#
# http://en.wikipedia.org/wiki/Double_precision
#
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @return four bytes of data
sub read_double($$)
{
	my $fh = shift;
	my $ofs = shift;

	seek($fh,$$ofs,0);
	read($fh,$temp,8);
	$$ofs+=8;

	# the following lines came from the CPAN module Parse::Flash::Cookie
	# Copyright 2007 Andreas Faafeng, all rights reserved.
	#
        # Check special numbers - do not rely on OS/compiler to tell the
        # truth.  
        if ($temp eq POSITIVE_INFINITY) 
	{
                return q{inf};
        } 
	elsif ($temp eq NEGATIVE_INFINITY) 
	{
                return q{-inf};
        } 
	elsif ($temp eq NOT_A_NUMBER) 
	{
                return q{nan};
        }
	
	$endian eq LITTLE_E ? return unpack 'd*', $temp : return unpack 'd*', reverse $temp;
}

#       read32
#
# A small function to read four bytes or 32 bits from the file and return it
#
# @params       FH	a file handle as a reference to a typeglob (\*FH)
# @params       ofs	A reference to the offset variable 
# @return four bytes of data
sub read_32($$)
{
	my $fh = shift;
	my $ofs = shift;

        seek($fh,$$ofs,0);
        read($fh,$temp,4) or return 0;
        $$ofs += 4;

	if( $endian eq LITTLE_E )
	{
        	return unpack("V", $temp );
	}
	else
	{
        	return unpack("N", $temp );
	}
}
sub read_long($$)
{
	my $fh = shift;
	my $ofs = shift;

        seek($fh,$$ofs,0);
        read($fh,$temp,4) or return 0;
        $$ofs += 4;

	if( $endian eq LITTLE_E )
	{
        	return unpack("L", $temp );
	}
	else
	{
        	return unpack("L", $temp );
	}
}

#       read_8
#
# A small function to read one byte or eight bits from the file and return it
# @return one byte of data
sub read_8($$)
{
	my $fh = shift;
	my $ofs = shift;

        seek($fh,$$ofs,0);
        read($fh,$temp,1) or return 0;
        $$ofs++;

        #return $temp; 
        return unpack( "c", $temp ); 
}

# 	read_4
sub read_4($$$)
{
	my $fh = shift;
	my $ofs = shift;
	my $loc = shift;
	my $var;

	seek($fh,$$ofs,0);
	read($fh,$temp,1) or return 0;
	$$ofs++;

	# now check if we are to read the upper or lower part
	$var = unpack("c", $temp );

	if( $loc eq 0 )
	{
		return $var & 0x0f;
	}
	else
	{
		return ($var & 0xf0) >> 4;
	}	
	
}
1;

__END__

=pod

=head1 NAME

Log2t::BinRead - support for reading binary log file in Log2timeline

=head1 METHODS

=over 4

=item set_endian ( TYPE )

This method sets the endian of the binary file.  By default values are returned as if the coding was done in a little endian systems, but that can be changed.  The types are:

=over 4

=item * 0 BIG_E

Represents a big endian ending

=item * 1 LITTLE_E

Represents a little endian ending (the default settings)

=back 

=item read_ascii ( \*FH, \$ofs, $length )

This function returns an ASCII string of length $length read from the binary file FH (accepts FH as a reference to a typeglob of the filehandle).
The variable offset dictates where in the binary file we find the start of the string, the offset variable is a reference, since the offset variable is increased
as each character is read (so the offset variable will be $ofs+$length at the end of the function)

=item read_ascii_end ( \*FH, \$ofs, $max )

This function returns an ASCII string of maximum length $length, from the binary file FH (accepts FH as a reference to a typeglob of the filehandle), but otherwise until an \0 or a null character is seen. The variable offset dictates where in the binary file we find the start of the string, the offset variable is a reference, since the offset variable is increased as each character is read (the offset variable will be set at the end of the string)

=item read_unicode ( \*FH, \$ofs, $length )

This function returns an Unicode encoded string of length $length read from the binary file FH (accepts FH as a reference to a typeglob of the filehandle).
The variable offset dictates where in the binary file we find the start of the string, the offset variable is a reference, since the offset variable is increased
as each character is read (so the offset variable will be $ofs+($length*2) at the end of the function)

=item read_unicode_end ( \*FH, \$ofs, $max )

This function returns an Unicode encoded string of maximum length $length from the binary file FH (accepts FH as a reference to a typeglob of the filehandle), but otherwise until an \00 or a null character is seen. The variable offset dictates where in the binary file we find the start of the string, the offset variable is a reference, since the offset variable is increased as each character is read (the offset variable will be set at the end of the string)

=item read_4 ( \*FH, \$ofs, $loc )

This function reads four bits or a nibble (half a byte) from the file FH (accepts FH as a reference to a typeglob of the filehandle) and return it. The offset is increased by one byte even though the operation returns only a nibble.

The variable $loc defines whether the higher or lower nibble is returned (one byte is read, which is then divided accordingly). Accepted values are:

=over 4

=item * 0 The lower four bits are returned

=item * 1 The upper four bits are returned

=back

=item read_8 ( \*FH, \$ofs )

This function reads 8 bits or one byte from the file FH (accepts FH as a reference to a typeglob of the filehandle) and return it according to the set endian of the file (default is little endian).  The offset is then increased by one.

=item read_16 ( \*FH, \$ofs )

This function reads 16 bits or two bytes from the file FH (accepts FH as a reference to a typeglob of the filehandle) and return it according to the set endian of the file (default is little endian).  The offset is then increased by two.

=item read_32 ( \*FH, \$ofs )

This function reads 32 bits or four bytes from the file FH (accepts FH as a reference to a typeglob of the filehandle) and return it according to the set endian of the file (default is little endian).  The offset is then increased by four.

=back

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

The tool is released under GPL so anyone can contribute to the tool.  Some parts of the code have been copied from other GPL'ed programs, such as RegRipper written by H. Carvey.

=cut
