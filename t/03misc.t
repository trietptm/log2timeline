use strict;
use warnings;

use Test::More;

use Log2Timeline;

# test _format_sort
my @unsorted = ( 'evtx', 'oxml', 'exif', 'somerandom', 'iis' );
my @sorted = sort Log2Timeline::_format_sort @unsorted;

# Make sure the array is properly sorted.
is($sorted[0], 'evtx');
is($sorted[1], 'iis');
is($sorted[2], 'oxml');
is($sorted[3], 'somerandom');
is($sorted[4], 'exif');

done_testing();
