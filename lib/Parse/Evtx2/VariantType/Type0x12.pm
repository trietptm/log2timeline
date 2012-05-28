# SYSTEMTIME
package Parse::Evtx2::VariantType::Type0x12;
use base qw( Parse::Evtx2::VariantType );

# See http://msdn.microsoft.com/en-us/library/ms724950%28VS.85%29.aspx

# typedef struct _SYSTEMTIME {
#   WORD wYear;
#   WORD wMonth;
#   WORD wDayOfWeek;
#   WORD wDay;
#   WORD wHour;
#   WORD wMinute;
#   WORD wSecond;
#   WORD wMilliseconds;
# } SYSTEMTIME, *PSYSTEMTIME;

use Carp::Assert;
#use DateTime;
 
sub parse_self {
	my $self = shift;

 	assert($self->{'Length'} >= 16, "packet too small") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 16);
	my ($year, $month, $dow, $day, $h, $m, $s, $ms) = unpack("s8", $data);
	$self->{'String'} = sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%04dZ",
		$year, $month, $day, $h, $m, $s, $ms);
	$self->{'Length'} = 16;
};
	
1;
