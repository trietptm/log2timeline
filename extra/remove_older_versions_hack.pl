#!/usr/bin/perl

use Log2t::Common;
use File::Path;

my $folder = Log2t::Common::get_directory();

# start by removing the main library
if( -f $folder . '/Log2Timeline.pm' )
{
	unlink( $folder . '/Log2Timeline.pm' ) ;
	print STDERR "Main engine removed.\n";
}
else
{
	print STDERR "Main engine not found (Log2Timeline.pm)\n";
}

# start by removing all files
remove_files( $folder . '/Log2t' );

# then to remove the folders
rmtree( $folder . '/Log2t' );

sub remove_files
{
	my $dir = shift;

	opendir( DIR, $dir );

	foreach my $f ( grep { !/^\./ }  readdir( DIR ) )
	{
		if( -f $dir . '/' . $f )
		{
			print STDERR "Removing: $dir/$f\n";
			#unlink( $dir/$f );
		}
		else
		{
			remove_files( $dir . '/' . $f ) if -d $dir . '/' .  $f;
		}
	}
	closedir( DIR );
}

