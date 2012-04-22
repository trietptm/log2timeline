use strict;
use warnings;

use Test::More;

use Log2Timeline;

# test the time offset function
my $base_path = 'test_data/';
my $number_of_tests = 0;
my @READ_TIME = undef;

# test a 100 sec offset to the normal (+100)
my $l2t = Log2Timeline->new(
    'file'          => $base_path . '/syslog.txt',
    'recursive'     => 0,
    'input'         => 'syslog',
    'time_zone'     => 'UTC',
    'out_time_zone' => 'UTC',
    'offset'        => 100,
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

ok($READ_TIME[1] == 1335043163, 'Using 100sec offset.');
$number_of_tests++;

# resetting the test suite
@READ_TIME = undef;

# now use a negative offset
$l2t = undef;
$l2t = Log2Timeline->new(
    'file'          => $base_path . '/syslog.txt',
    'recursive'     => 0,
    'input'         => 'syslog',
    'time_zone'     => 'UTC',
    'out_time_zone' => 'UTC',
    'offset'        => '-100',
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

ok($READ_TIME[1] == 1335042963, 'Using negative 100 as the offset');
$number_of_tests++;

# resetting the test suite
@READ_TIME = undef;

# now use an hour offset
$l2t = undef;
$l2t = Log2Timeline->new(
    'file'          => $base_path . '/syslog.txt',
    'recursive'     => 0,
    'input'         => 'syslog',
    'time_zone'     => 'UTC',
    'out_time_zone' => 'UTC',
    'offset'        => '4h',
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

ok($READ_TIME[1] == 1335057463, 'Using 4h as the offset');
$number_of_tests++;


# we need this function since we use the RAW output option of l2t
sub process_output($) {
  my $t_line = shift;

  push(@READ_TIME, $t_line->{'time'}->{0}->{'value'});
}

done_testing( $number_of_tests );
