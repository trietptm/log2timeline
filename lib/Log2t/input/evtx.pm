#################################################################################################
#		EVTX
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or 
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
# 
# This input module implements a parser for Event Log files in Windows Vista,Win7,+ in 
# the windows EVTX format.
#
# The input module uses the Parse::Evtx libraries developed by Andreas Schuster, libraries
# that are included with the framwework with permission from Andreas.  
# 
# The input modules uses part of the code evtxdump.pl written by Andreas Schuster.
# 
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 25/04/11
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
# Copyright (c) 2007-2011 by Andreas Schuster
package Log2t::input::evtx;

use strict;

# add the Log2t libraries
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;	# to manipulate time
#use Log2t::Numbers;	# to manipulate numbers
use Log2t::BinRead;	# methods to read binary files
#use Log2t::Network;	# information about network traffic 

# for reading and parsing the XML schema
use XML::LibXML;
use XML::LibXML::Common;

# include Andreas Schuster EVTX libraries
use Parse::Evtx;
use Parse::Evtx::Chunk;

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# indicate the version number of this input module
$VERSION = '0.5';

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of a Windows Event Log File (EVTX)"; 
}

#       init
#
# The purpose of this subfunction is to prepare the log file or artifact for parsing
# Usually this involves just opening the file (if plain text) or otherwise building a 
# structure that can be used by other functions
#
# This function also accepts parameters for processing (for changing some settings in
# the input module)
#
sub init
{
	# read the paramaters passed to the script
	my $self = shift;

	# the default value of loaded is 0 (not loaded the first event)
	$self->{'loaded'} = 0;
	$self->{'bad_event_counter'} = 0;

	# code taken from evtxdump.pl from Andreas Schuster
	#$self->{'fh'} = IO::File->new($self->{'name'}, "r");

	print STDERR "[EVTX] Preparing to parse the EVTX file\n" if $self->{'debug'};
	$self->{'evtx'} = Parse::Evtx->new('FH' => $self->{'file'});

	if (!defined $self->{'evtx'} ) 
	{
    		# if it's not a complete file, is it a chunk then?
    		$self->{'evtx'} = Parse::Evtx::Chunk->new('FH' => $self->{'file'} );
	};


	# create the ACL list
	$self->{'acl_list'} = {
		'%%1537'	=> 'DELETE',
		'%%1538'	=> 'READ_CONTROL',
		'%%1539'	=> 'WRITE_DAC',
		'%%1541'	=> 'SYNCHRONIZE',
		'%%1542'	=> 'ACCESS_SYS_SEC',
		'%%4416'	=> 'ReadData (or ListDirectory)',
		'%%4417'	=> 'WriteData (or AddFile)',
		'%%4418'	=> 'AppendData',
		'%%4419'	=> 'ReadEA',
		'%%4420'	=> 'WriteEA',
		'%%4421'	=> 'Execute/Traverse',
		'%%4423'	=> 'ReadAttributes',
		'%%4424'	=> 'WriteAttributes',
		'%%4432'	=> 'Query key value',
		'%%4432'	=> 'Set Key Value',
		'%%4434'	=> 'Create Sub Key',
		'%%4435'	=> 'Enumerate sub-keys',
		'%%4436'	=> 'Notify about changes to keys',
		'%%4437'	=> 'Create Link',
		'%%6931'	=> 'Print',
		'%%1553'	=> 'Unknown specific access (bit 1)',
	};

	print STDERR "[EVTX] Preparation completed\n" if $self->{'debug'};

	return 1 if defined $self->{'evtx'};

	return 0;
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now.
#
# @return A version number
sub get_version()
{
        return $VERSION;
}



#       get_time
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
# 
# @return Returns a reference to a hash containing the needed values to print a body file
sub get_time
{
	my $self = shift;

	my %t_line; 	# the timestamp object
        my $text;
	my ($xml,$xml_parsed);
	my ($prop, @prop_array );
	my ($system,$eventdata);
	my (@system_child, @eventdata_child);
	my (%sys,%data);
	my (@attrs);
	my $temp;
	my %data_info = undef;	# login information (in case we have those)
	my $event;

	# code partially borrowed from dumpevtx.pl by Andreas Schuster

	# check if we are about to load up the first event of the file
	if ( $self->{'loaded'} == 0 )
	{
		# try to load first event
		eval
		{
			print STDERR "[EVTX] Fetching the first event\n" if $self->{'debug'};
			$event = $self->{'evtx'}->get_first_event();
		};
		if( $@ )
		{	
			# an empty evtx file
			return 0;
		}

		$self->{'loaded'} += 1;
		return \%t_line;
	}
	else
	{
		# otherwise we are loading up subsequent events
		eval {
			$event = $self->{'evtx'}->get_next_event();
		};
		if( $@ )
		{
			# some error occured, unable to further process the file
			# until a better approached has been developed, we will
			# try to parse the next event, while incrementing a bad
			# counter, and if we reach our limits, we will gracually
			# exit
			print STDERR "[EVTX] Error occured while parsing file: \n$@\n";
			$self->{'bad_event_counter'}++;

			$self->{'bad_event_counter'} == 50 ? return 0 : return \%t_line;
		}
	}		

	# check for the last record
	return undef unless defined $event;

	# get the XML
	$xml = XML::LibXML->new();

	print STDERR "[EVTX] Fetching the XML structure\n" if $self->{'debug'};

	eval
	{
		$temp = $event->get_xml();
	};
	if( $@ )
	{
		# we had an error, unable to get the event in question
		return \%t_line;
	}

	# fix the XML structure (remove "banned" symbols)
	#$temp =~ s/\&/::amb::/g;
	#$temp =~ tr/[]()!/ /;

	$xml_parsed = $xml->parse_string( $temp );

	# now we need to parse the XML structure 
	$prop = $xml_parsed->getDocumentElement();
	@prop_array = $prop->childNodes;

	# go through each of the child nodes
	foreach( @prop_array )
	{
		if( $_->nodeType == ELEMENT_NODE )
		{
			if( lc($_->nodeName) eq 'system' )
			{
				$system = $_;
			}
			else
			{
				# process it further
				#print STDERR "[EVTX] Node (", $_->nodeName, ")\n";

				# get the child nodes of the tag
				@eventdata_child = $_->childNodes;
				foreach my $node( @eventdata_child )
				{
					# initialize the temp variable
					$temp = '';

					if( $node->nodeType == ELEMENT_NODE )
					{
						# initialize the temp variable
						#$temp = '';
						#print STDERR "\tName: ", $node->nodeName, "\n";
	
						# we will go through each of the supplied value
						# check if the node has attributes
						if( $node->hasAttributes() )
						{
							@attrs = $node->attributes();
							foreach my $attr (@attrs)
							{
								#print STDERR "\t\tAttr: (nodename) [", $attr->nodeName, "] => (value) [", $attr->value, "] (text) [", $attr->textContent, "] (nodeText) [", $node->textContent, "] \n";
								eval
								{
									if( $attr->textContent eq 'AccessList' )
									{
										# need to process the ACL
										my $acl = $node->textContent;
										$acl =~ s/\r//g;
										$acl =~ s/\n/-/g;
										$acl =~ s/\t//g;
										$acl =~ s/\s//g;
										my @acls = split( /-/, $acl );

										$temp .= $attr->textContent . ': {';
										$data_info{$attr->value} .= 'AccessList: {';

										foreach( @acls )
										{
											$data_info{$attr->value} .= defined $self->{'acl_list'}->{$_} ? $self->{'acl_list'}->{$_} : $_;
											$temp .= defined $self->{'acl_list'}->{$_} ? $self->{'acl_list'}->{$_} : $_;

											$temp .= ' - ';
											$data_info{$attr->value} .= ' - ';
										}
									
										$temp =~ s/- $//;
										$temp .= '} ';
									}
									elsif( $attr->textContent eq 'AccessReason' )
									{
										# setup: 
										#	ACL:ID - ACL:ID D(....)
										# need to process the ACL
										my $acl = $node->textContent;
										$acl =~ s/\r//g;
										$acl =~ s/\n/-/g;
										$acl =~ s/\t//g;
										$acl =~ s/\s//g;
										my @acls = split( /-/, $acl );

										$temp .= $attr->textContent . ': {';
										$data_info{$attr->value} .= 'AccessReason: {';

										foreach( @acls )
										{
											my ($a,$b) = split(/:/, $_);
											my ($bb,$dd) = split( /D/, $b );
											#print STDERR "R: A $a B $b BB $bb DD $dd\n";


											$data_info{$attr->value} .= defined $self->{'acl_list'}->{$a} ? $self->{'acl_list'}->{$a} . ': Granted by ' . $self->{'acl_list'}->{$bb} . ' D' . $dd: $a . ':'  . $bb . ' D' . $dd;
											$temp .= defined $self->{'acl_list'}->{$a} ? $self->{'acl_list'}->{$a} . ': Granted by ' . $self->{'acl_list'}->{$bb} . ' D' . $dd: $a . ':'  . $bb . ' D' . $dd;

											$temp .= ' - ';
											$data_info{$attr->value} .= ' - ';
										}
									
										$temp =~ s/- $//;
										$temp .= '} ';
									}
									else
									{
										$data_info{$attr->value} = $attr->textContent;
										$temp .= $attr->value . ' = ' . $node->textContent .  '- ';
									}
								};
								if( $@ )
								{
									$data_info{$attr->value} = 'unable to retrieve text content';
									$temp .= $attr->value . ' = ' . $node->textContent .  '- ';
								}

							}

							# remove the last '- ' from the temp variable
							$temp =~ s/- $/ /;
						}
					
						#print STDERR "[EVTX] Now assigning ", $_->nodeName, "/", $node->nodeName, " to ", $node->textContent, " - ", $temp, "\n";
						# set the data variable
						$data{$_->nodeName . '/' . $node->nodeName } .= $temp eq ''? $node->textContent :  $temp;
						$data{$_->nodeName . '/' . $node->nodeName } =~ s/\n//g;
						$data{$_->nodeName . '/' . $node->nodeName } =~ s/\r//g;
					}
				}

			}
	
		}
	}
	# get the two values of interest
	#$system = $prop_array[1];	# contains information about the event, such as date
	#$eventdata = $prop_array[3];	# the actual information contained in the event

	# get the child nodes of the <System> tag
	@system_child = $system->childNodes;
	foreach( @system_child )
	{
		# print out all nodes
		#print STDERR "[EVTX] -> Reading node (sys): ", $_->nodeName, "\n";

		if( $_->nodeName eq 'Provider' )
		{
			@attrs = $_->attributes();
			foreach my $attr (@attrs)
			{
				#print STDERR "\tProvider: ", $attr->nodeName, "\n";

				if( $attr->nodeName eq 'EventSourceName' )
				{
					$sys{'source'} = $attr->value;
				}
				elsif( $attr->nodeName eq 'Name' )
				{
					$sys{'source'} = $attr->value;
				}
			}
		}
		elsif( $_->nodeName eq 'TimeCreated' )
		{
			# extract the timestamp (ISO format)
			@attrs = $_->attributes();

			foreach my $attr (@attrs)
			{
				if( $attr->nodeName eq 'SystemTime' )
				{
					$sys{'date'} = $attr->value; 
				}
			}
		}
		elsif( $_->nodeName eq 'EventID' )
		{
			$sys{'eventid'} = $_->textContent;
		}
		elsif( $_->nodeName eq 'Channel' )
		{
			$sys{'channel'} = $_->textContent;
		}
		elsif( $_->nodeName eq 'Computer' )
		{
			$sys{'computer'} = $_->textContent;
		}

	}

	# get the child nodes of the <EventData> tag
	#@eventdata_child = $eventdata->childNodes;
	#foreach( @eventdata_child )
	#{
	#	if( $_->nodeType == ELEMENT_NODE )
	#	{
	#		# initialize the temp variable
	#		$temp = '';
	#		print STDERR "[EVTX] (data) ", $_->nodeName,  "\n";
	#
	#		# we will go through each of the supplied value
	#		# check if the node has attributes
	#		if( $_->hasAttributes() )
	#		{
	#			@attrs = $_->attributes();
	#			foreach my $attr (@attrs)
	#			{
	#				print STDERR "\tattrib: ", $attr->nodeName, " => ", $attr->value, "\n";
	#				$temp .= $attr->nodeName . ' = ' . $attr->value . ', ';
	#			}
	#		}
	#
	#		# set the data variable
	#		$data{$_->nodeName} = $text eq ''? $_->textContent : $_->textContent . '(' . $temp . ')';
	#		$data{$_->nodeName} =~ s/\n//g;
	#		$data{$_->nodeName} =~ s/\r//g;
	#	}
	#}


	# fix the hostname variable
	$self->{'hostname'} = defined $sys{'computer'} ? $sys{'computer'} : $self->{'hostname'};

	# construct the text
	$text .= $sys{'channel'} . '/' . $sys{'source'} . ' ID [' . $sys{'eventid'} . '] :';

	$text .= 'Logon Type: ' . $sys{'logontype'} if defined $sys{'logontype'};

	foreach ( keys %data )
	{
		$text .= $data{"$_"} eq '' ? $_ . ' -> empty - ' : $_ . ' -> ' . $data{"$_"} . '- ';
	}
	chomp($text);
	$text =~ s/- $//;

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
        %t_line = (
                'time' => { 0 => { 'value' => $sys{'date'}, 'type' => 'Event Logged', 'legacy' => 15 } },
                'desc' => $text,
                'short' => 'Event ID ' . $sys{'channel'} . '/' . $sys{'source'} . ':' . $sys{'eventid'},
                'source' => 'EVTX',
                'sourcetype' => $sys{'channel'},
                'version' => 2,
		'notes' => 'Description of EventIDs can be found here: http://support.microsoft.com/default.aspx?scid=kb;EN-US;947226',
                'extra' => { 'host' => $self->{'hostname'}, 'url' => 'http://eventid.net/display.asp?eventid=' . $sys{'eventid'} . '&source=' . $sys{'source'}, }
        );

	return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help()
{
	return "This input module parses the content of a Windows Event Log
as it is stored in Windows Vista/Win 7/2008 and later versions, that is the 
EVTX binary XML document.

The input module depends upon the library Parse::Evtx developed by Andreas
Schuster, a library that is distributed with log2timeline and slightly modified
to accomodate this input module.\n";

}

#       verify
#
# This function takes as an argument the file name to be parsed (file/dir/artifact) and
# verifies it's structure to determine if it is really of the correct format.
#
# This is needed since there is no need to parse the file if this file/dir is not the file
# that this input module is designed to parse
#
# It is also important to validate the file since the scanner function will try to 
# parse every file it finds, and uses this verify function to determine whether or not
# a particular file/dir/artifact is supported or not. It is therefore very important to 
# implement this function and make it verify the file structure without false positives and
# without taking too long time
#
# @return A reference to a hash that contains an integer indicating whether or not the 
#	file/dir/artifact is supporter by this input module as well as a reason why 
#	it failed (if it failed) 
sub verify
{
	my $self = shift;

	# define an array to keep
	my %return;
	my $line;
	my @words;
	my $ofs = 0;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	# we need to check the following magic value
	# 456c 6646 696c 65

	#unless( $self->{'quick'} )
	#{
	#	# start by reading only a single value
	#	seek($self->{'file'},0,0);
	#	read($self->{'file'},$line,1);
	#
	#	return \%return unless $line eq 'E';
	#}

	$line = Log2t::BinRead::read_ascii( $self->{'file'}, \$ofs, 7 );
	
	# 456c 6646 696c 65 = ElfFile
	if ( $line eq 'ElfFile' )
	{
		$return{'success'} = 1;
	}
	else
	{
		$return{'success'} = 0;
		$return{'msg'} = 'File not of the correct format (wrong magic)' . "\n";
	}

	return \%return;
}

1;


__END__

=pod

=head1 NAME

B<structure> - an input module B<log2timeline> that parses X 

=head1 SYNOPSIS

	my $format = structure;
	require $format_dir . '/' . $format . ".pl" ;

	$format->verify( $log_file );
	$format->prepare_file( $log_file, @ARGV )

        $line = $format->load_line()

	$t_line = $format->parse_line();

	$format->close_file();

=head1 DESCRIPTION

An input module 

=head1 SUBROUTINES

=over 4

=item get_version()

Return the version number of the input module

=item get_description()

Returns a string that contains a short description of the functionality if the input module.  When a list of all available input modules is printed using B<log2timeline> this string is used.  So this string should be a very short description, mostly to say which type of log file/artifact/directory this input module is designed to parse.

=item prepare_file( $file, @ARGV )

The purpose of this subfunction is to prepare the log file or artifact for parsing. Usually this involves just opening the file (if plain text) or otherwise building a structure that can be used by other functions.

This function accepts the path to the log file/directory/artifact to parse as well as an array containing the parameters passed to the input module. These parameters are used to adjust settings of the input module, such as to provide a username and a hostname to include in the timeline.

The function returns an integer indicating whether or not it was successful at preparing the input file/directory/artifact for further processing.

=item load_line()

This function starts by checking if there are any lines in the log file/artifacts that have a date variable inside that needs to be parsed.  It then loads the line (or an index value) in a global variable that can be read by the function parse_line and returns the value 1 to the main script, indicating that a line has been loaded.

When all of the lines in the log file/directory/artifact have been parsed a zero is returned to the main script, indicating that there are no more lines to parse

=item close_file()

A subroutine that closes the file, after it has been parsed and performs any additional operations needed to close the file/directory/artifact that was parsed (such as to disconnect any database connections)

The subroutine returns an integer indicating whether or not it was successful at closing the file.

=item parse_line()

This is the main subroutine of the format file (or often it is).  It depends on the subroutine load_line that loads a line of the log file into a global variable and then parses that line to produce the hash t_line, which is read and sent to the output modules by the main script to produce a timeline or a bodyfile.

The content of the hash t_line is the following:

	%t_line {
		md5,		# MD5 sum of the file
		name,		# the main text that appears in the timeline
		title,		# short description used by some output modules
		source,		# the source of the timeline, usually the same name or similar to the name of the package
		user,		# the username that owns the file or produced the artifact
		host,		# the hostname that the file belongs to
		inode,		# the inode number of the file that contains the artifact
		mode,		# the access rights of the file
		uid,		# the UID of the user that owns the file/artifact
		gid,		# the GID of the user that owns the file/artifact
		size,		# the size of the file/artifact
		atime,		# Time in epoch representing the last ACCESS time
		mtime,		# Time in epoch representing the last MODIFICATION time
		ctime,		# Time in epoch representing the CREATION time (or MFT/INODE modification time)
		crtime		# Time in epoch representing the CREATION time
	}

The subroutine return a reference to the hash (t_line) that will be used by the main script (B<log2timeline>) to produce the actual timeline.  The hash is processed by the main script before forwarding it to an output module for the actual printing of a bodyfile.

=item get_help()

A simple subroutine that returns a string containing the help message for this particular input module. This also contains a longer description of the input module describing each parameter that can be passed to the subroutine.  It sometimes contains a list of all dependencies and possibly some instruction on how to install them on the system to make it easier to implement the input module.

=item verify( $log_file )

This subroutine takes as an argument the file name to be parsed (file/dir/artifact) and verifies it's structure to determine if it is really of the correct format.

This is needed since there is no need to try to parse the file/directory/artifact if the input module is unable to parse it (if it is not designed to parse it)

It is also important to validate the file since the scanner function will try to parse every file it finds, and uses this verify function to determine whether or not a particular file/dir/artifact is supported or not. It is therefore very important to implement this function and make it verify the file structure without false positives and without taking too long time

This subroutine returns a reference to a hash that contains two values
	success		An integer indicating whether not the input module is able to parse the file/directory/artifact
	msg		A message indicating the reason why the input module was not able to parse the file/directory/artifact

=back

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009.

=head1 SEE ALSO

L<log2timeline>

=cut

