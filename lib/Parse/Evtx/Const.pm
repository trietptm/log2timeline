package Parse::Evtx::Const;

# This module declares program-wide constants.

use version; our $VERSION = qv('1.0.4');

BEGIN {
	use Exporter;
	our @ISA = qw(Exporter);
	our @EXPORT_OK = qw(
			$EVTX_CHECK_OK
			$EVTX_CHECK_CHECKSUM
			$EVTX_CHECK_HEADERCRC
			$EVTX_CHECK_DATACRC
			$EVTX_HDRFLAG_DIRTY
			$EVTX_HDRFLAG_FULL
		);	
	our %EXPORT_TAGS = (
			all => [qw(
				$EVTX_CHECK_OK
				$EVTX_CHECK_CHECKSUM
				$EVTX_CHECK_HEADERCRC
				$EVTX_CHECK_DATACRC				
				$EVTX_HDRFLAG_DIRTY
				$EVTX_HDRFLAG_FULL
			)],
			checks => [qw(
				$EVTX_CHECK_OK
				$EVTX_CHECK_CHECKSUM
				$EVTX_CHECK_HEADERCRC
				$EVTX_CHECK_DATACRC				
			)],
			hdrflags => [qw(
				$EVTX_HDRFLAG_DIRTY
				$EVTX_HDRFLAG_FULL
			)]
		);
}


# Bitmask for Parse::Evtx::check() and Parse::Evtx::Chunk::check()
our $EVTX_CHECK_OK			= 0x0000;
our $EVTX_CHECK_CHECKSUM	= 0x0001;	# deprecated
our $EVTX_CHECK_HEADERCRC	= 0x0001;
our $EVTX_CHECK_DATACRC		= 0x0002; 

# Status flags to be used in file header
our $EVTX_HDRFLAG_DIRTY		= 0x0001;
our	$EVTX_HDRFLAG_FULL		= 0x0002;

1;