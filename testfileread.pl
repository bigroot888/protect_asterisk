#!/usr/bin/env perl

use warnings;
use strict;

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

print @num;
close F;