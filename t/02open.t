use strict;
use warnings;

use Test::More;

use Log2Timeline;

my $l2t = new Log2Timeline();
my $base_path = 'test_data';

$l2t->{'file'} = $base_path . $l2t->{'sep'} . 'syslog.txt';

can_ok($l2t, '_open_file');
can_ok($l2t, '_close_file');

done_testing();
