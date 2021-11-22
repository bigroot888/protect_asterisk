#!/usr/bin/env perl

use warnings;
use strict;

use sipconf;

my @sip_num = SipConf::ReadFile();

print $sip_num[2];