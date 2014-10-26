package Net::CIDR::Lookup::Test;

use strict;
use warnings;

use base 'Test::Class';
use Test::More;
use Net::CIDR::Lookup;

#-------------------------------------------------------------------------------

sub check_methods : Test(startup => 8) {
    my $t = Net::CIDR::Lookup->new;
    can_ok($t,'add');
    can_ok($t,'add_num');
    can_ok($t,'add_range');
    can_ok($t,'lookup');
    can_ok($t,'lookup_num');
    can_ok($t,'clear');
    can_ok($t,'dump');
    can_ok($t,'walk');
}

sub before : Test(setup) {
    my $self = shift;
    $self->{tree} = Net::CIDR::Lookup->new;
}

#-------------------------------------------------------------------------------

sub add : Tests(5) {
    my $self = shift;
    my $t = $self->{tree};
    is($t->add('192.168.0.129/25', 42), 1, 'add() succeeded');
    is($t->add('1.2.0.0/15', 23), 1, 'add() succeeded');
    is($t->lookup('192.168.0.161'), 42, 'Block 192.168.0.129/25 lookup OK');
    is($t->lookup('1.3.123.234'), 23, 'Block 1.2.0.0/15 lookup OK');
    is($t->lookup('2.3.4.5'), undef, 'No result outside blocks');
}

sub add_range : Tests(6) {
    my $self = shift;
    my $t = $self->{tree};
    is($t->add_range('192.168.0.130-192.170.0.1', 42), 1, 'add_range() succeeded');
    is($t->add_range('1.3.123.234 - 1.3.123.240', 23), 1, 'add_range() succeeded');
    is($t->lookup('192.169.0.22'), 42, 'Range 192.168.0.130 - 192.170.0.1');
    is($t->lookup('1.3.123.235'),  23, 'Range 1.3.123.234 - 1.3.123.240');
    is($t->lookup('2.3.4.5'), undef, 'No result outside blocks');
    my $h = $t->dump;
    is(scalar keys %$h, 19, 'Range expansion: number of keys');
}

sub collision : Tests(1) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.129/25', 42);
    isnt($t->add('192.168.0.160/31', 23), 1, 'Collision: add() failed as expected');
    # TODO errstr?
}

sub benign_collision : Test(1){
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.129/25', 42);
    is($t->add('192.168.0.160/31', 42), 1, 'Benign collision: add() succeeded');
}

sub merger : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.130/25', 42);
    is($t->add('192.168.0.0/25', 42),   1, 'Merger: add() succeeded');
    my $h = $t->dump;
    is(scalar keys %$h, 1, 'Merged block: number of keys');
    my ($k,$v) = each %$h;
    is($k, '192.168.0.0/24', 'Merged block: correct merged net block');
}

sub recursive_merger : Tests(4) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('0.1.1.0/24', 42);
    is($t->add('0.1.0.128/25', 42), 1, 'Recursive merger: add(0.0.0.128/25) succeeded');
    is($t->add('0.1.0.0/25', 42),   1, 'Recursive merger: add(0.0.0.0/25) succeeded');
    my $h = $t->dump;
    is(scalar keys %$h, 1, 'Recursively merged block: number of keys');
    my ($k,$v) = each %$h;
    is($k, '0.1.0.0/23', 'Recursively merged block: correct merged net block');
}

sub nonmerger : Tests(2) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.130/25', 42);
    is($t->add('192.168.0.0/25', 23),   1, 'Non-merger: add() succeeded');
    my $h = $t->dump;
    is(scalar keys %$h, 2, 'Unmerged adjacent blocks: correct number of keys');
}

sub equalrange : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.130/25', 1);
    is($t->add('192.168.0.130/25', 1), 1, 'Equalrange: add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Got single block from two equal inserts');
    is($h->{'192.168.0.128/25'}, 1, 'Got correct block');
}

sub subrange1 : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.1/24', 1);
    is($t->add('192.168.0.1/25', 1), 1, 'Immediate subrange: add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Immediate subrange: resulted in single block');
    is($h->{'192.168.0.0/24'}, 1, 'Immediate subrange: got correct block');
}

sub subrange2 : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.1/24', 1);
    is($t->add('192.168.0.1/28', 1), 1, 'Small subrange: add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Small subrange: resulted in single block');
    is($h->{'192.168.0.0/24'}, 1, 'Small subrange: got correct block');
}

sub superrange1 : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.128/25', 1);
    is($t->add('192.168.0.0/24', 1), 1,   'Immediate superrange: add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Immediate superrange: resulted in single block');
    is($h->{'192.168.0.0/24'}, 1, 'Immediate superrange: got correct block');
}

sub superrange2 : Tests(3) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.160.128/25', 1);
    is($t->add('192.168.160.0/20', 1), 1, 'Big superrange: add() succeeded');
    my $h = $t->dump;
    is(0+keys %$h, 1, 'Big superrange: resulted in single block');
    is($h->{'192.168.160.0/20'}, 1, 'Big superrange: got correct block');
}

sub clear : Tests(1) {
    my $self = shift;
    my $t = $self->{tree};
    $t->add('192.168.0.129/25', 42);
    $t->clear;
    is(scalar keys %{$t->dump}, 0, 'Reinitialized tree');
}

1;

