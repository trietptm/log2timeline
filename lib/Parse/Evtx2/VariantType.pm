package Parse::Evtx2::VariantType;

use Parse::Evtx2::BXmlNode;
# scalar types
use Parse::Evtx2::VariantType::Type0x00;		# NullType
use Parse::Evtx2::VariantType::Type0x01;		# UCS2-LE string
use Parse::Evtx2::VariantType::Type0x02;		# ANSI string
use Parse::Evtx2::VariantType::Type0x03;		# signed byte
use Parse::Evtx2::VariantType::Type0x04;		# unsigned byte
use Parse::Evtx2::VariantType::Type0x05;		# signed int16
use Parse::Evtx2::VariantType::Type0x06;		# unsigned int16
use Parse::Evtx2::VariantType::Type0x07;		# signed int32
use Parse::Evtx2::VariantType::Type0x08;		# unsigned int32
use Parse::Evtx2::VariantType::Type0x09;		# signed int64
use Parse::Evtx2::VariantType::Type0x0a;		# unsigned int64
use Parse::Evtx2::VariantType::Type0x0b;		# single precision float
use Parse::Evtx2::VariantType::Type0x0c;		# double precision float
use Parse::Evtx2::VariantType::Type0x0d;		# boolean
use Parse::Evtx2::VariantType::Type0x0e;		# binary
use Parse::Evtx2::VariantType::Type0x0f;		# GUID
use Parse::Evtx2::VariantType::Type0x10;		# size_t (Pointer)
use Parse::Evtx2::VariantType::Type0x11;		# FILETIME
use Parse::Evtx2::VariantType::Type0x12;		# SYSTEMTIME
use Parse::Evtx2::VariantType::Type0x13;		# Security ID (SID)
use Parse::Evtx2::VariantType::Type0x14;		# HexInt32
use Parse::Evtx2::VariantType::Type0x15;		# HexInt64
							# Type0x16
							# ...
							# Type0x20        EvtHandle
use Parse::Evtx2::VariantType::Type0x21;		# Binary XML (undocumented)
 							# Type0x22
							# Type0x23		# EvtXml
# array types
use Parse::Evtx2::VariantType::Type0x81;		# array of UCS2-LE strings
							# Type0x82		  array of ANSI strings
use Parse::Evtx2::VariantType::Type0x83;		# array of signed byte
use Parse::Evtx2::VariantType::Type0x84;		# array of unsigned byte
use Parse::Evtx2::VariantType::Type0x85;		# array of signed int16
use Parse::Evtx2::VariantType::Type0x86;		# array of unsigned int16
use Parse::Evtx2::VariantType::Type0x87;		# array of signed int32
use Parse::Evtx2::VariantType::Type0x88;		# array of unsigned int32
use Parse::Evtx2::VariantType::Type0x89;		# array of signed int64
use Parse::Evtx2::VariantType::Type0x8a;		# array of unsigned int64
use Parse::Evtx2::VariantType::Type0x8b;		# array of float
use Parse::Evtx2::VariantType::Type0x8c;		# array of double
							# Type0x8d		  array of boolean *2
							# Type0x8e		  array of binary *2
use Parse::Evtx2::VariantType::Type0x8f;		# array of GUID
							# Type0x90		  array of Pointer *3
use Parse::Evtx2::VariantType::Type0x91;		# array of FILETIME
use Parse::Evtx2::VariantType::Type0x92;		# array of SYSTEMTIME
							# Type0x93		  array of SID *1						
use Parse::Evtx2::VariantType::Type0x94;		# array of HexInt32
use Parse::Evtx2::VariantType::Type0x95;		# array of HexInt64
# Remarks:
# *1 : not supported by Microsoft's Message Compiler (MC.EXE)
# *2 : generation of C# code not supported by MC.EXE, 
#      usage of Uint8 suggested
# *3 : obsolete? will be encoded as HexInt32/64 correspondingly


use Carp;
use Carp::Assert;

use version; our $VERSION = qv('1.1.1');


sub new_variant {
	my $type = shift;
	my $C = shift;		# Chunk
	my $S = shift;		# Start
	my $Len = shift;	# Length
	my $Ctx = shift;	# Context
	
	my $variant;
	if ($type == 0x00) {
		$variant = Parse::Evtx2::VariantType::Type0x00->new($C, $S, $Len);
	} elsif ($type == 0x01) {
		$variant = Parse::Evtx2::VariantType::Type0x01->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x02) {
		$variant = Parse::Evtx2::VariantType::Type0x02->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x03) {
		$variant = Parse::Evtx2::VariantType::Type0x03->new($C, $S, $Len);
	} elsif ($type == 0x04) {
		$variant = Parse::Evtx2::VariantType::Type0x04->new($C, $S, $Len);
	} elsif ($type == 0x05) {
		$variant = Parse::Evtx2::VariantType::Type0x05->new($C, $S, $Len);
	} elsif ($type == 0x06) {
		$variant = Parse::Evtx2::VariantType::Type0x06->new($C, $S, $Len);
	} elsif ($type == 0x07) {
		$variant = Parse::Evtx2::VariantType::Type0x07->new($C, $S, $Len);
	} elsif ($type == 0x08) {
		$variant = Parse::Evtx2::VariantType::Type0x08->new($C, $S, $Len);
	} elsif ($type == 0x09) {
		$variant = Parse::Evtx2::VariantType::Type0x09->new($C, $S, $Len);
	} elsif ($type == 0x0a) {
		$variant = Parse::Evtx2::VariantType::Type0x0a->new($C, $S, $Len);
	} elsif ($type == 0x0b) {
		$variant = Parse::Evtx2::VariantType::Type0x0b->new($C, $S, $Len);
	} elsif ($type == 0x0c) {
		$variant = Parse::Evtx2::VariantType::Type0x0c->new($C, $S, $Len);
	} elsif ($type == 0x0d) {
		$variant = Parse::Evtx2::VariantType::Type0x0d->new($C, $S, $Len);
	} elsif ($type == 0x0e) {
		$variant = Parse::Evtx2::VariantType::Type0x0e->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x0f) {
		$variant = Parse::Evtx2::VariantType::Type0x0f->new($C, $S, $Len);
	} elsif ($type == 0x10) {
		$variant = Parse::Evtx2::VariantType::Type0x10->new($C, $S, $Len);
	} elsif ($type == 0x11) {
		$variant = Parse::Evtx2::VariantType::Type0x11->new($C, $S, $Len);
	} elsif ($type == 0x12) {
		$variant = Parse::Evtx2::VariantType::Type0x12->new($C, $S, $Len);
	} elsif ($type == 0x13) {
		$variant = Parse::Evtx2::VariantType::Type0x13->new($C, $S, $Len);
	} elsif ($type == 0x14) {
		$variant = Parse::Evtx2::VariantType::Type0x14->new($C, $S, $Len);
	} elsif ($type == 0x15) {
		$variant = Parse::Evtx2::VariantType::Type0x15->new($C, $S, $Len);
	} elsif ($type == 0x21) {
		$variant = Parse::Evtx2::VariantType::Type0x21->new($C, $S, $Len);
	} elsif ($type == 0x81) {
		$variant = Parse::Evtx2::VariantType::Type0x81->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x83) {
		$variant = Parse::Evtx2::VariantType::Type0x83->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x84) {
		$variant = Parse::Evtx2::VariantType::Type0x84->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x85) {
		$variant = Parse::Evtx2::VariantType::Type0x85->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x86) {
		$variant = Parse::Evtx2::VariantType::Type0x86->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x87) {
		$variant = Parse::Evtx2::VariantType::Type0x87->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x88) {
		$variant = Parse::Evtx2::VariantType::Type0x88->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x89) {
		$variant = Parse::Evtx2::VariantType::Type0x89->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x8a) {
		$variant = Parse::Evtx2::VariantType::Type0x8a->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x8b) {
		$variant = Parse::Evtx2::VariantType::Type0x8b->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x8c) {
		$variant = Parse::Evtx2::VariantType::Type0x8c->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x8f) {
		$variant = Parse::Evtx2::VariantType::Type0x8f->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x91) {
		$variant = Parse::Evtx2::VariantType::Type0x91->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x92) {
		$variant = Parse::Evtx2::VariantType::Type0x92->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x94) {
		$variant = Parse::Evtx2::VariantType::Type0x94->new($C, $S, $Len, $Ctx);
	} elsif ($type == 0x95) {
		$variant = Parse::Evtx2::VariantType::Type0x95->new($C, $S, $Len, $Ctx);
	} else {
		print $C->get_hexdump($S, $Len);
		my $msg = sprintf("Undefined VariantType 0x%x Start=0x%x, Length=%d",
			$type, $S, $Len);
		confess($msg);
	}
	assert(defined($variant), 
		"VariantType object not defined") if DEBUG;
	return $variant;
}


sub new {
	my $class = shift;
	my $self = {};
	bless $self, $class;
	
	# additional parameters
	$self->{'Chunk'} = shift;		# chunk object
	$self->{'Start'} = shift;		# start offset within chunk
	$self->{'Length'} = shift;		# length of tag, will be trimmed down later
	$self->{'Context'} = shift;		# 0=Value, 1=SubstArray
	$self->{'Type'} = shift;
	assert($self->{'Length'} <= 0xffff - 0x0200) if DEBUG;
	assert($self->{'Start'} + $self->{'Length'} <= 0xffff) if DEBUG;	
	
	# additional variables
	$self->{'String'} = '';
	$self->{'Type'} = 0 unless (defined $self->{'Type'});
	
	$self->{'Chunk'}->push_object($self);
	
	return $self;
}


sub release {
	my $self = shift;
	
	undef $self->{'Chunk'};
	undef $self->{'Start'};
	undef $self->{'Length'};
	undef $self->{'Context'};
	undef $self->{'Type'};
	undef $self->{'String'};
}

sub get_description {
	my $self = shift;
	my $result = '';
	
	if (defined $self->{'Start'}) {
		$result .= sprintf("\n%s at %d, length %d\n", 
			ref($self),
			$self->{'Start'}, $self->{''},
			$self->{'Length'}
		);
	}
	
	return $result;
}

sub get_hexdump {
	my $self = shift;
	
	assert(defined $self->{'Chunk'}, "Chunk undefined") if DEBUG;
	assert(defined $self->{'Start'}, "Start undefied") if DEBUG;
	assert(defined $self->{'Length'}, "Length undefined") if DEBUG;
	$self->{'Chunk'}->get_hexdump($self->{'Start'}, $self->{'Length'});
}


sub get_length {
	my $self = shift;
	
	return $self->{'Length'};
}


sub get_xml {
	my $self = shift;
	
	my $str = $self->{'String'};
	# quote XML special characters
	if ($str =~ /[<>&\'\"]/) {
		$str =~ s/\&/\&amp;/mg;
		$str =~ s/\'/\&apos;/mg;
		$str =~ s/\"/\&quot;/mg;
		$str =~ s/</\&lt;/mg;
		$str =~ s/>/\&gt;/mg;
	}
	
	# remove stray string terminator
	$str =~ s/\x00+//m;
	
	return $str;	
}


sub parse_down {
	# variant types don't have children
}

1;
