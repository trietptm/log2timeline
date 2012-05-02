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

eval {
    my $out =  Log2t::Common::list_input;

    # this does not automatically tell us we were successful...
    # since STDERR is also returned if there is an error....
    if ($out =~ m/Parse the content of an OpenXML document/) {
        pass("Able to provide list of input");
    }
    else {
        fail("Unable to provide a list of input module.");
    }
};
if($@) {
    fail("Error in code, unable to list input modules");
}
can_ok('Log2t::Common', 'list_output');

done_testing();
