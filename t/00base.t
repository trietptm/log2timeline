use strict;
use warnings;

use Test::More;

use_ok('Log2Timeline');

use Log2Timeline;

my $l2t = new Log2Timeline();

isa_ok($l2t, 'Log2Timeline');
can_ok($l2t, 'start');

done_testing();
