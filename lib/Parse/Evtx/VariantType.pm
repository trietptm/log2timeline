package Parse::Evtx::VariantType;

use Parse::Evtx::BXmlNode;
# scalar types
use Parse::Evtx::VariantType::Type0x00;		# NullType
use Parse::Evtx::VariantType::Type0x01;		# UCS2-LE string
use Parse::Evtx::VariantType::Type0x02;		# ANSI string
use Parse::Evtx::VariantType::Type0x03;		# signed byte
use Parse::Evtx::VariantType::Type0x04;		# unsigned byte
use Parse::Evtx::VariantType::Type0x05;		# signed int16
use Parse::Evtx::VariantType::Type0x06;		# unsigned int16
use Parse::Evtx::VariantType::Type0x07;		# signed int32
use Parse::Evtx::VariantType::Type0x08;		# unsigned int32
use Parse::Evtx::VariantType::Type0x09;		# signed int64
use Parse::Evtx::VariantType::Type0x0a;		# unsigned int64
use Parse::Evtx::VariantType::Type0x0b;		# single precision float
use Parse::Evtx::VariantType::Type0x0c;		# double precision float
use Parse::Evtx::VariantType::Type0x0d;		# boolean
use Parse::Evtx::VariantType::Type0x0e;		# binary
use Parse::Evtx::VariantType::Type0x0f;		# GUID
use Parse::Evtx::VariantType::Type0x10;		# size_t
use Parse::Evtx::VariantType::Type0x11;		# FILETIME
use Parse::Evtx::VariantType::Type0x12;		# SYSTEMTIME
use Parse::Evtx::VariantType::Type0x13;		# Security ID (SID)
use Parse::Evtx::VariantType::Type0x14;		# HexInt32
use Parse::Evtx::VariantType::Type0x15;		# HexInt64
							# Type0x16
							# ...
							# Type0x20        EvtHandle
use Parse::Evtx::VariantType::Type0x21;		# Binary XML (undocumented)
 							# Type0x22
							# Type0x23		# EvtXml
# array types
use Parse::Evtx::VariantType::Type0x81;		# array of UCS2-LE strings
							# Type 0x82		  array of ANSI strings
							# ...
use Parse::Evtx::VariantType::Type0x94;		# array of HexInt32
use Parse::Evtx::VariantType::Type0x95;		# array of HexInt64

use Carp;
use Carp::Assert;

use version; our $VERSION = qv('1.0.5');


sub new_variant {
	my $type = shift;
	my $Chunk = shift;
	my $Start = shift;
	my $Length = shift;
	my $Context = shift;
	
	my $variant;
	if ($type == 0x00) {
		$variant = Parse::Evtx::VariantType::Type0x00->new($Chunk, $Start, $Length);
	} elsif ($type == 0x01) {
		$variant = Parse::Evtx::VariantType::Type0x01->new(
			$Chunk, 
			$Start, 
			$Length,
			$Context
		);
	} elsif ($type == 0x02) {
		$variant = Parse::Evtx::VariantType::Type0x02->new(
			$Chunk, 
			$Start, 
			$Length,
			$Context
		);
	} elsif ($type == 0x03) {
		$variant = Parse::Evtx::VariantType::Type0x03->new($Chunk, $Start, $Length);
	} elsif ($type == 0x04) {
		$variant = Parse::Evtx::VariantType::Type0x04->new($Chunk, $Start, $Length);
	} elsif ($type == 0x05) {
		$variant = Parse::Evtx::VariantType::Type0x05->new($Chunk, $Start, $Length);
	} elsif ($type == 0x06) {
		$variant = Parse::Evtx::VariantType::Type0x06->new($Chunk, $Start, $Length);
	} elsif ($type == 0x07) {
		$variant = Parse::Evtx::VariantType::Type0x07->new($Chunk, $Start, $Length);
	} elsif ($type == 0x08) {
		$variant = Parse::Evtx::VariantType::Type0x08->new($Chunk, $Start, $Length);
	} elsif ($type == 0x09) {
		$variant = Parse::Evtx::VariantType::Type0x09->new($Chunk, $Start, $Length);
	} elsif ($type == 0x0a) {
		$variant = Parse::Evtx::VariantType::Type0x0a->new($Chunk, $Start, $Length);
	} elsif ($type == 0x0b) {
		$variant = Parse::Evtx::VariantType::Type0x0b->new($Chunk, $Start, $Length);
	} elsif ($type == 0x0c) {
		$variant = Parse::Evtx::VariantType::Type0x0c->new($Chunk, $Start, $Length);
	} elsif ($type == 0x0d) {
		$variant = Parse::Evtx::VariantType::Type0x0d->new($Chunk, $Start, $Length);
	} elsif ($type == 0x0e) {
		$variant = Parse::Evtx::VariantType::Type0x0e->new(
			$Chunk, 
			$Start, 
			$Length,
			$Context
		);
	} elsif ($type == 0x0f) {
		$variant = Parse::Evtx::VariantType::Type0x0f->new($Chunk, $Start, $Length);
	} elsif ($type == 0x10) {
		$variant = Parse::Evtx::VariantType::Type0x10->new($Chunk, $Start, $Length);
	} elsif ($type == 0x11) {
		$variant = Parse::Evtx::VariantType::Type0x11->new($Chunk, $Start, $Length);
	} elsif ($type == 0x12) {
		$variant = Parse::Evtx::VariantType::Type0x12->new($Chunk, $Start, $Length);
	} elsif ($type == 0x13) {
		$variant = Parse::Evtx::VariantType::Type0x13->new($Chunk, $Start, $Length);
	} elsif ($type == 0x14) {
		$variant = Parse::Evtx::VariantType::Type0x14->new($Chunk, $Start, $Length);
	} elsif ($type == 0x15) {
		$variant = Parse::Evtx::VariantType::Type0x15->new($Chunk, $Start, $Length);
	} elsif ($type == 0x21) {
		$variant = Parse::Evtx::VariantType::Type0x21->new($Chunk, $Start, $Length);
	} elsif ($type == 0x81) {
		$variant = Parse::Evtx::VariantType::Type0x81->new(
			$Chunk, 
			$Start, 
			$Length,
			$Context
		);
	} elsif ($type == 0x94) {
		$variant = Parse::Evtx::VariantType::Type0x94->new(
			$Chunk,
			$Start,
			$Length,
			$Context
		);
	} elsif ($type == 0x95) {
		$variant = Parse::Evtx::VariantType::Type0x95->new(
			$Chunk,
			$Start,
			$Length,
			$Context
		);
	} else {
		print $Chunk->get_hexdump($Start, $Length);
		my $msg = sprintf("Undefined VariantType 0x%x Start=0x%x, Length=%d",
			$type, $Start, $Length);
		confess($msg);
	}
	assert(defined($variant), 
		"undefined VariantType object") if DEBUG;
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
	
	return $self;
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