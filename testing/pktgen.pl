
use Convert::BER;
use Getopt::Std;

my $pktTmpl = 
{ TAG => snmpV3Msg,
  TYPE => SEQUENCE,
  DEF =>
      [ { TAG => msgVersion,
	  TYPE => INTEGER,
	  ENUM => { snmpv3 => 3 },
	  DFLT => 3 },
	{ TAG => msgGlobalData,
	  TYPE => SEQUENCE,
	  DEF => 
	      [ { TAG => msgID,
		  TYPE => INTEGER },
		{ TAG => msgMaxSize,
		  TYPE => INTEGER,
		  DFLT => 1472 },
		{ TAG => msgFlags,
		  TYPE => STRING,
		  SIZE => 1,
		  ENUM => { reportableFlag => 0x04, authFlag => 0x01, 
			     privFlag => 0x02 },
		  DFLT => 0x04 },
		{ TAG => msgSecModel,
		  TYPE => INTEGER,
		  ENUM => { snmpv3 => 3 },
		  DFLT => 3 },
		] },
	{ TAG => msgSecParam,
	  TYPE => STRING,
	  DEF =>
	      [ { TAG => secParams,
		  TYPE => SEQUENCE,
		  DEF =>
		      [ { TAG => msgEngineID,
			  TYPE => STRING },
			{ TAG => msgEngineBoots,
			  TYPE => INTEGER },
			{ TAG => msgEngineTime,
			  TYPE => INTEGER },
			{ TAG => msgUserName,
			  TYPE => STRING },
			{ TAG => msgAuthParam,
			  TYPE => STRING },
			{ TAG => msgPrivParam,
			  TYPE => STRING }, 
			] }, 
		] },
	{ TAG => scopedPDU,
	  TYPE => SEQUENCE,
	  DEF => 
	      [ { TAG => contextEngineID,
		  TYPE => STRING },
		{ TAG => contextName,
		  TYPE => STRING },
		{ TAG => pduData,
		  TYPE => CHOICE,
		  ENUM => { GET => 0, GETNEXT => 1, RESPONSE => 2, SET => 3,
			     TRAP => 4, GETBULK => 5, INFORM => 6, TRAPv2 => 7,
			     REPORT => 8 },
		  DEF =>
		      [ { TAG => reqID,
			  TYPE => INTEGER },
			{ TAG => errStat,
			  TYPE => INTEGER,
			  ENUM => { noError => 0, tooBig => 1, noSuchName => 2,
				    badValue => 3, readOnly => 4, genErr => 5,
				    noAccess => 6, wrongType => 7, wrongLength => 8,
				    wrongEncoding => 9, wrongValue => 10,
				    noCreation => 11, inconsistentValue => 12,
				    resourceUnavailable => 13, commitFailed => 14,
				    undoFailed => 15, authorizationError => 16,
				    notWritable => 17, inconsistentName => 18 },
			  ALIAS => nonRepeaters },
			{ TAG => errInd,
			  TYPE => INTEGER,
			  ALIAS => maxRepetitions },
			{ TAG => varbindList,
			  TYPE => SEQUENCE,
			  DEF => 
			      [ { TAG => varbind,
				  TYPE => SEQUENCE,
				  DEF =>
				      [ { TAG => objectID,
					  TYPE => OBJECT_ID },
					{ TAG => value,
					  TYPE => BER },
					] },
				] },
			] },
		] },
	] };


sub pkt_read_packet_data {
    my $file = shift;
    my %data;
    my ($k,$v);

    open(DATA,$file) or die "could not open packet data file, $file\n";

    while (<DATA>) {
	next if /^\s*$/;
	next if /^\s*\#/;
	chomp;
	next unless ($k,$v) = /(\w+)\s*=>\s*(\"[^\"]*\"|>?&\w+\([^\)]*\)|\S+);/;
	if (exists $data{$k}) {
	    if (ref $data{$k} eq ARRAY) {
		push(@{$data{$k}}, $v);
	    } else {
		$data{$k} = [$data{$k}, $v];
	    }
	} else {
	    $data{$k} = $v;
	}
    }
    
    close DATA;
    
    return \%data;
}

sub pkt_resolve_value {
    my $obj = shift;
    my $val = shift;
    my $tag = $obj->{TAG};
    my $type = $obj->{TYPE};

    for ($type) {
	/INTEGER/ and do {
	    $val = $obj->{ENUM}{$val} 
	       if exists $obj->{ENUM} and exists $obj->{ENUM}{$val};
	    $val ||= 0;
	    last;
	};
	/STRING/ and do {
	    my $size = $obj->{SIZE};
	    $val = $obj->{ENUM}{$val} 
	       if exists $obj->{ENUM} and exists $obj->{ENUM}{$val};
	    if ($val =~ s/^0[xX]//) {
		$size = ($size ? $size * 2 : '*');
		$val = pack("H$size",$val);
	    } elsif ($val =~ /^\d+$/) {
		$size = ($size ? ('c','n','nc','N')[$size-1] : 'N');
		$val = pack($size,$val);
	    } elsif ($val =~ s/^\"(.*)\"/$1/) {
		$size ||= '*';
		$val = pack("a$size",$val);
	    }
	    $val ||= "";
	    last;
	};
	/SEQUENCE|CHOICE/ and do {
	    my $size = $obj->{SIZE};
	    $size = ($size ? $size * 2 : '*');
	    $val = $obj->{ENUM}{$val} 
	       if exists $obj->{ENUM} and exists $obj->{ENUM}{$val};
	    if ($val =~ s/^0[xX]//) {
		my $tval = pack("H$size",$val) ;
		$val = sub {new Convert::BER($tval);};
	    }
	    last;
	};
    }
    $val;
}

sub pkt_compile_ber_encode_arg {
    my $obj = shift;
    my $data = shift;
    my $tag = $obj->{TAG};
    my $type = $obj->{TYPE};
    my $val = $data->{$tag} || $obj->{DFLT};
    my $arg;
    my $rval = pkt_resolve_value($obj,$val);
    
    if (defined $val) {
	if ($type =~ /CHOICE/) {
	    if ($val =~ /^\w+$/) { 
		# CHOICE was specified by symbolic enumeration 
                # $arg is not yet defined because there may be sub-objs
		$type = [ SEQUENCE => $rval ];
	    } else {
		# in this case the entire CHOICE is given by $rval
                # we need to put it in the BER buffer so SEQUENCE will wrap it
                # $arg is defined, no need to look for SEQUENCE sub objects
		$arg = [SEQUENCE => $rval];
	    }
	} else {
	    # simple (non contructed) object
	    $arg = [$type => $rval];
	}
    } 
    # $arg is not defined then we still need to resolve this BER clause
    if (not defined $arg) {
	my $def = $obj->{DEF};
	if (defined $def) {
	    print "handling def of $tag\n";
	    my @sub_args;
	    foreach my $sub_obj (@{$def}) {
		print "\thandling recurse call for $sub_obj->{TAG}\n";
		push(@sub_args,pkt_compile_ber_encode_arg($sub_obj,$data));
	    }
	    if ($type eq 'STRING') {
		$arg = [$type => sub {my $b = new Convert::BER(@sub_args);$b->buffer}];
	    } else {
		$arg = [$type => [ @sub_args ]];
	    }
	} else {
	    warn "no value, default or sub-definition found for $tag\n" if $opt_d;
	    $arg = [$type => $rval];
	}
       
    }
    return @$arg;
}

sub pkt_build_ber_packet {
    my $tmpl = shift;
    my $data = shift;

    my @ber_args = pkt_compile_ber_encode_arg($tmpl,$data);

    my $ber = new Convert::BER();
    $ber->encode(@ber_args);
    print $ber->error;
    $ber;
}

sub pkt_display_packet {
    my $pkt = shift;
    $pkt = join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $pkt->buffer()));
    print "$pkt\n";
}

sub pkt_send_packet {
    my $addr = shift;
    my $pkt = shift;

}
getopts("p:a:dD");

my $pktDataFile = $opt_p || 'packet.txt';
my $destAddr = $opt_a || 'localhost';

my $pktData = pkt_read_packet_data($pktDataFile);

my $packet = pkt_build_ber_packet($pktTmpl,$pktData);

pkt_display_packet($packet) if $opt_d;

pkt_send_packet($destAddr, $packet);








