#!/usr/bin/env perl

use strict;
use warnings;

use Data::Dumper qw(Dumper);
use DateTime;
use Date::Format;
use Date::Parse;

use DBI;
use Proc::Daemon;
use Proc::PID::File;
use sipconf;

$| = 1;

$SIG{'INT'} = $SIG{'QUIT'} = \&exit_serv;

my $fwcmd = "/usr/sbin/iptables";
my $block_type = "REJECT --reject-with icmp-port-unreachable";
my $name_tab = "asterisk";

my $db;
my @sip_num;

Proc::Daemon::Init();

if (Proc::PID::File->running()) {
    &logfile("Alredy running");
    print "Already running\n";
    exit 0;
}

sub qrySelect() {
    my ($db,$query) = @_;
    my $return = 0;
    my $sth = $db->prepare($query);
    $sth->execute();
    $return = $sth->fetchrow_array();
    $sth->finish();
    return $return;
}

sub qrySelect2() {
    my ($db,$query) = @_;
    my $sth = $db->prepare($query);
    $sth->execute();
    return $sth->fetchrow_array();
    $sth->finish();
}

sub IpTablesStart() {
    my ($protocol) = @_;
    system($fwcmd." -N f2b-".$name_tab."-".$protocol);
    system($fwcmd." -A f2b-".$name_tab."-".$protocol." -j RETURN");
    system($fwcmd." -I INPUT -p 5060 -j f2b-".$name_tab."-".$protocol);
}

sub IpTablesStop() {
    my ($protocol) = @_;
    system($fwcmd." -D INPUT -p 5060 -j f2b-".$name_tab."-".$protocol);
    system($fwcmd." -F f2b-".$name_tab."-".$protocol);
    system($fwcmd." -X f2b-".$name_tab."-".$protocol);
}

sub IpTablesBlock() {
    my ($ip) = @_;
    system($fwcmd." -I f2b-".$name_tab."-udp 1 -s ".$ip." -j ".$block_type);
    system($fwcmd." -I f2b-".$name_tab."-tcp 1 -s ".$ip." -j ".$block_type);
    return 0;
}

sub IpTablesUnBlock() {
    my ($ip) = @_;
    system($fwcmd." -D f2b-".$name_tab."-udp -s ".$ip." -j ".$block_type);
    system($fwcmd." -D f2b-".$name_tab."-tcp -s ".$ip." -j ".$block_type);
    return 0;
}

sub checkBlockIp() {
    my ($db,$ip) = @_;
    return &qrySelect($db,"select block from users where ip='".$ip."'");
}

sub unBlockIP() {
    my ($db) = @_;
    my $where = "select ip from users where date_block_end <= datetime('now','localtime') and date_block_end <> ''";

    my @unblockip = &qrySelect2($db,$where);
    foreach my $ip (@unblockip) {
	if (defined $ip) {
    	    &IpTablesUnBlock($ip);
    	    &logfile("Unblock ip: ".$ip);
	}
    }
    my $query = "update users set count=0, block=0, date_block_end='' where ip in (".$where.")";
    $db->do($query);

    return 0;
}

sub checkIp() {
    my ($db,$ip) = @_;
    return &qrySelect($db, "select count(*) from users where ip='".$ip."'");
}

sub getCount() {
    my ($db,$ip) = @_;
    return &qrySelect($db, "select count from users where ip='".$ip."'");
}

sub checkSip() {
    my ($sipnum) = @_;
    foreach my $num (@sip_num) {
	if ($num eq $sipnum) {
	    return 1; 
	}
	else {
	    return 0;
	}
    }
}

sub addIpDb() {
    my ($db, $ip) = @_;
    my $ip_exists = &checkIp($db,$ip);
    if ($ip_exists == 0) {
	$db->do("insert into users values (datetime('now','localtime'),'$ip','1','0','')");
    }
    else {
	$db->do("update users set count=count+1 where ip='".$ip."'");
    }
    return 0;
}

sub blockIpDb() {
    my ($db, $ip) = @_;
    my $date_now = DateTime->now();
    my $dtbe = DateTime::Duration->new(hours => 10,);
    my $dte = $date_now + $dtbe;
    my $date_block_end = $dte->strftime("%Y-%m-%d %H:%M:%S");

    $db->do("update users set block=1, date_block_end='".$date_block_end."' where ip='".$ip."'");

    #system("/usr/bin/fail2ban-client set asterisk banip $ip");
    &IpTablesBlock($ip);

    return 0;
}

sub logfile() {
    my ($string) = @_;
    open (F, '>>/var/log/asterisk/admin-aster.log');
    print F localtime()." :-> ".$string."\n";
    close F;
}

sub exit_serv() {
    $SIG{'INT'} = $SIG{'QUIT'} = \&exit_serv;
    $db->disconnect;
    &logfile("Stop daemon");
    exit 0;
}

&logfile("Start daemon");

my $file_db = "/var/db/users.db";


$db = DBI->connect("DBI:SQLite:dbname=".$file_db."","","", { RaiseError => 1 }) or die &logfile($DBI::errstr);

if (! -f $file_db) {
    my $rv = $db->do("create table if not exists users (date_block date not null default '', ip text,count int, block int not null default 0, date_block_end date default '');");

    if($rv < 0) {
	&logfile($DBI::errstr);
    } else {
	&logfile("Table created successfully");
    }
}

#fail2ban-client set asterisk banip 000.000.000.000

@sip_num = SipConf::ReadFile();

&logfile(Dumper @sip_num);

while (1) {
    my @AST=`/usr/sbin/asterisk -rx 'sip show channels' | grep INVITE`;

    &unBlockIP($db);

    if (@AST ne '') {
        my $new_callid='';
        my $old_callid='';
        foreach my $row (@AST) {
            my @ast=split(' ',$row);
            $new_callid=$ast[2];
            my $curr_num=$ast[1];

            next if &checkSip($curr_num) == 1;

            next if $new_callid eq $old_callid;

            $old_callid=$new_callid;

            my $ip_h = $ast[0];

            my $block = &checkBlockIp($db,$ip_h);
            next if $block == 1;

            my $count = &getCount($db,$ip_h);
            if ($count < 3 ) {
               &addIpDb($db,$ip_h);
               &logfile($ip_h." ".$ast[2]);
            } else {
               &blockIpDb($db,$ip_h);
               &logfile("IP :".$ip_h." block.");
            }
        }
    }
    sleep 1;
}
