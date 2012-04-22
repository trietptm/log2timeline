use strict;
use warnings;

use Test::More;

use Log2Timeline;

# test the syslog parsing
my $base_path = 'test_data/';
my $number_of_tests = 0;
my @READ_TIME = undef;
my @READ_DESC = undef;

# test both zones set to UTC
my $l2t = Log2Timeline->new(
    'file'          => $base_path . '/syslog.txt',
    'recursive'     => 0,
    'input'         => 'syslog',
    'time_zone'     => 'UTC',
    'out_time_zone' => 'UTC',
    'offset'        => 0,
    'exclusions'    => '',
    'text'          => 'test',
    'debug'         => 0,
    'digest'        => 0,
    'quick'         => 0,
    'raw'           => 1,
    'detailed_time' => 0,
    'hostname'      => 'nohost',
    'preprocess'    => 0,
);

$l2t->start;

ok($READ_TIME[1] == 1335043063, 'Reading file using UTC as both input and output');
$number_of_tests++;

my $text = '[somepid[102]] log event on [MYmachineNAME] : "There was a bug in the process, causing malfunction in the built-up queue. "';

is($READ_DESC[1], $text, 'Testing correct parsing of content');
$number_of_tests++;

# resetting the test suite
@READ_TIME = undef;
@READ_DESC = undef;

# test zone A to PST8PDT and output to UTC
$l2t = undef;
$l2t = Log2Timeline->new(
    'file'          => $base_path . '/syslog.txt',
    'recursive'     => 0,
    'input'         => 'syslog',
    'time_zone'     => 'PST8PDT',
    'out_time_zone' => 'UTC',
    'offset'        => 0,
    'exclusions'    => '',
    'text'          => 'test',
    'debug'         => 0,
    'digest'        => 0,
    'quick'         => 0,
    'raw'           => 1,
    'detailed_time' => 0,
    'hostname'      => 'nohost',
    'preprocess'    => 0,
);

$l2t->start;

ok($READ_TIME[1] == 1335068263, 'Reading file using PST8PDT as input and UTC as output');
$number_of_tests++;

# we need this function since we use the RAW output option of l2t
sub process_output($) {
  my $t_line = shift;

  push(@READ_TIME, $t_line->{'time'}->{0}->{'value'});
  push(@READ_DESC, $t_line->{'desc'});
}

done_testing( $number_of_tests );
