#!/usr/bin/perl -W

use 5.12.0;
use strict;
use POSIX;

my $rule_path = "/home/last-g/Workspace/suricata/build/debug/etc/suricata/rules/debug.rules";
my $suricata_pid = `pidof suricata`;
my @content = ();
my $append_flag = shift;

exit unless $append_flag;

open Rule, '<', "$rule_path" or die "Can't open $rule_path: $!";
@content = map {&convert_rule($_)} <Rule>;
close Rule;
open Rule, '>', "$rule_path" or die "Can't open $rule_path: $!";
{
	print Rule @content;
}
close Rule;

say "Successfully rewriten";
kill "USR2", $suricata_pid;

say 'Reloading...';

sub convert_rule($)
{
	my ($rule) = shift;
	return $rule if($rule =~ /^\s*#/);
	return $rule if($rule =~/^\s*$/);
	
	my$re = qr/^\s*
				(?<action>\w+)\s+
				(?<proto>\w+)\s+
				(?<ip_src>\w+)\s+
				(?<port_src>\w+)\s+
				(?<way>[<>-]{2})\s+
				(?<ip_dst>\w+)\s+
				(?<port_dst>\w+)\s*
				(?<rule_data>
					\(
						(?<garbage_1>.*)
						(?<pcre>
							pcre:\s*"\/(?<pcre_data>[^"\/]*[^|"\/])\/(?<pcre_flags>[^"])"\s*;
						)\s*
						(?<ds>dynamic_string\s*;)
						(?<garbage_2>.*)
					\)
				)
	.*$/x;

	if($rule =~ /$re/)
	{
		say "Gotem";
		my $new_data = $+{'pcre_data'} . '|' . "$append_flag";

		$rule = "$+{action} $+{proto} $+{ip_src} $+{port_src} $+{way} $+{ip_dst} $+{port_dst} ".
				"($+{garbage_1}pcre:\"/$new_data/$+{pcre_flags}\"; $+{ds}$+{garbage_2})".
				"$/";
		say "Updating rule to " . $rule;

	}
	else
	{
		say "Pass";
		return $rule;
	}
	return $rule;
}