#!/usr/bin/perl

# Fix the problem: supercop cannot be dynamically linked
#
# Usage: make_ed25519_relocatable.pl work_dir const_file_name...

use strict;
use File::Basename;
use File::Spec::Functions;

my ($work_dir, %consts, $patched_file);

# Parse arguments
die "Invalid number of arguments" if scalar @ARGV < 2;
$work_dir = canonpath(shift @ARGV);
-d $work_dir or die "No such directory: $work_dir\n";

# Parse constants
foreach my $const_file_name (@ARGV) {
    my $const_file = catfile($work_dir, $const_file_name);

    open my $content, $const_file or die "Could not open $const_file: $!";
    while (my $line = <$content>) {
        if ($line =~ /^([^:\s]+):\s+\.\w+\s+(\w+)$/) {
            $consts{$1} = $2;
        }
    }
    close $content;
}

# Patch asm files to be relocatable
my $asm_files_pattern = catfile($work_dir, '*.s');
my @asm_files = <"$asm_files_pattern">;
foreach my $asm_file (@asm_files) {
    my $asm_file_name = basename($asm_file);
    if (grep ( /^$asm_file_name$/, @ARGV)) { next; } # Skip consts.s
    my $content = read_file($asm_file);
    foreach my $const (keys %consts) {
        my $push_instruction = "pushq %r15";
        my $move_instruction = "movq $const\@GOTPCREL(%rip), %r15";
        my $pop_instruction = "popq %r15";
        $content =~ s/^\s*movq\s+$const\s*,\s*(.*)/# patched: $&\nmovq $const\@GOTPCREL(%rip), $1\nmovq ($1), $1/gm;
        $content =~ s/^(\w+\s+)$const([^@].*)/# patched: $&\n$push_instruction\n$move_instruction\n$1(%r15)$2\n$pop_instruction/gm;
    }
    write_file($asm_file, $content);
}

exit;

sub read_file {
    my ($filename) = @_;

    open my $in, '<:encoding(UTF-8)', $filename or die "Could not open '$filename' for reading $!";
    local $/ = undef;
    my $all = <$in>;
    close $in;

    return $all;
}

sub write_file {
    my ($filename, $content) = @_;

    open my $out, '>:encoding(UTF-8)', $filename or die "Could not open '$filename' for writing $!";;
    print $out $content;
    close $out;

    return;
}
