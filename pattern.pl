#!/usr/bin/perl -w
use strict;
 
my $ustart = 65;
my $uend = 90;
my $lstart = 97;
my $lend = 122;
my $nstart = 0;
my $nend = 9;
my $length ;
my $string = "";
my ($upper, $lower, $num);
my $searchflag = 0;
my $searchstring;
 
sub credits(){
    print "\nGenerate/Search Pattern\n\n";
}
 
sub usage(){
    credits();
    print " Usage:\n\n";
    print " pattern.pl <LENGTH> // Will generate a string of given length. \n";
    print "\n";
    print " pattern.pl <LENGTH> <SEARCHSTR> // Will generate a string of given length and display the offsets of the pattern.\n\n";
}
 
sub generate(){
    credits();
    $length = $ARGV[0];
    #print "Generating string for length : " .$length . "\n";
    if(length($string) == $length){
        finish();
    }
    #looping for the uppercase
    for($upper = $ustart; $upper <= $uend;$upper++){
        $string =$string.chr($upper);
        if(length($string) == $length){
            finish();
        }
        #looping for the lowercase
        for($lower = $lstart; $lower <= $lend;$lower++){
            $string =$string.chr($lower);
            if(length($string) == $length){
                finish();
            }
            #looping for the numeral
            for($num = $nstart; $num <= $nend;$num++){
                $string = $string.$num;
                if(length($string) == $length){
                    finish();
                }
                $string = $string.chr($upper);
                if(length($string) == $length){
                    finish();
                }
                if($num != $nend){
                    $string = $string.chr($lower);
                }
                if(length($string) == $length){
                    finish();
                }
            }
        }
    }
}
 
sub search(){
    my $offset = index($string,$searchstring);
    if($offset == -1){
        print "Pattern '".$searchstring."' not found\n";
        exit(1);
    }
    else{
        print "Pattern '".$searchstring."' found at offset(s) : ";
    }
    my $count = $offset;
    print $count." ";
 
    while($length){
        $offset = index($string,$searchstring,$offset+1);
        if($offset == -1){
            print "\n";
            exit(1);
        }
        print $offset ." ";
        $count = $count + $offset;
    }
    print "\n";
    exit(1);
}
 
sub finish(){
    print "String is : \n".$string ."\n\n";
    if($searchflag){
        search();
    }
    exit(1);
}
 
if(!$ARGV[0]){
    usage();
    #print "Going into usage..";
}
elsif ($ARGV[1]){
    $searchflag = 1;
    $searchstring = $ARGV[1];
    generate();
    #print "Going into pattern search...";
}
else {
     generate();
     #print "Going into string generation...";
}
