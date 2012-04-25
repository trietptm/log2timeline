use strict;
use warnings;

use Test::More;

use_ok('Log2Timeline');
use_ok('Log2t::Common');

use Log2Timeline;
use Log2t::Common;

my $l2t = new Log2Timeline();

can_ok($l2t, 'get_inputs');

can_ok('Log2t::Common', 'get_directory');
can_ok('Log2t::Common', 'list_lists');
can_ok('Log2t::Common', 'list_input');
can_ok('Log2t::Common', 'list_output');

done_testing();
