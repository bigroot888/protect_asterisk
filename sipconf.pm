package SipConf;
use strict;
use warnings;

use Exporter qw(import);

sub ReadFile() {
    open F, '<' ,'/etc/asterisk/sip.conf';
    my @num;
    while(<F>) {
	my $row = $_;
	next if $row =~ /^\;/;
	next if $row =~ /^\[general\]/;
	next if $row =~ /\(\!\)/;
	if ($row =~ /^\[[0-9]*|[a-zA-Z]*\]/) {
	    push(@num, substr($row,1,index($row,']')-1));
	}
    }
    close F;
    return @num;
}

1;