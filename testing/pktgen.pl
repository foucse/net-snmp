#!/usr/bin/perl
use Getopt::Std;
use Convert::BER(BER_CONSTRUCTOR,BER_CONTEXT);
use SSLeay;
use Socket;

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
			  TYPE => SEQUENCE_OF,
			  DEF => 
			      [ { TAG => varbind,
				  TYPE => SEQUENCE,
				  DEF =>
				      [ { TAG => objectID,
					  TYPE => OBJECT_ID },
					{ TAG => value,
					  TYPE => BER,
				          DFLT => [NULL => 0] },
					] },
				] },
			] },
		] },
	] };

my @pkt_post_process_stack;
sub pkt_push_post_process {
    my $sub = shift;

    unshift(@pkt_post_process_stack,$sub);
}

sub pkt_read_packet_data {
    my $file = shift;
    my %data;
    my ($k,$v);

    open(DATA,$file) or die "could not open packet data file, $file\n";

    while (<DATA>) {
	chomp;
	next if /^\s*\#/;
	next if /^\s*$/;
	$line .= $_;
	next if $line =~ s/\\\s*$//;
	($k,$v) = $line =~ /^\s*(\w+)\s*=>\s*
                              ( <.*>
                              | \'.*\'
                              | \".*\"
                              | \[.*\]
                              | \|?\&\w+\(.*\)
                              | 0[xX][\s0-9A-Fa-f]*
                              | \S+
                              )\s*;/x;
	undef $line;
	unless (defined $k and defined $v) {
	    warn "pkt_read_packet_data: unable to parse line [$file:$.]\n" 
		if $opt_w;
	    next;
	}
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
sub pkt_cvt_hex {
    my $val = shift;
    my $size = shift || '*';

    $val =~ s/0[xX]//;
    $val =~ s/\s*//g;
    
    pack("H$size",$val) ;
}

sub pkt_resolve_field {
    my $obj = shift;
    my $data = shift;
    my $in_seq_of = shift;
    my $tag = $obj->{TAG};
    my $type = $obj->{TYPE};
    my $val;
    my $enum;
    my $seq_of;

    if (exists $data->{$tag}) {
	if (ref $data->{$tag} eq 'ARRAY') {
	    $val = shift @{$data->{$tag}};
	    delete $data->{$tag} unless @{$data->{$tag}};
	} else {
	    $val = $data->{$tag};
	    delete $data->{$tag};
	}
    }

    # if no val given use default unless in SEQUENCE_OF
    $val = $obj->{DFLT} unless defined $val or $in_seq_of;

    print "pkt_resolve_field: resolving [$tag, $type, $val]\n" if $opt_D;

    # resolve function call
    $val = eval($val) if $val =~ /^\&\w+/;
    
    # handle values which is piped through filter function
    my $filter_sub;
    if ($val =~ s/\|\&(\w+\(.*\))//) {
	$filter_sub = $1 ;
	print "pkt_resolve_field: found filter sub $filter_sub [$']\n" 
	    if $filter_sub and $opt_D;
	undef $val unless length $val;
    }

    # if literal octet field convert type to BER
    $type = 'BER' if $val =~ s/^<(.*)>$/$1/;

    # handle enumeration resolution
    my @enums = split(/\s*\|\s*/,$val);
    my $enum_val;
    foreach (@enums) {
	if ($obj->{ENUM} and exists $obj->{ENUM}{$_}) {
	    $enum_val |= $obj->{ENUM}{$_};
	    $enum = 1;
	}
    }
    $val = $enum_val if $enum;

    for ($type) {
	/^NULL/ and do {
	    $val = 0 unless $in_seq_of;
	    last;
	};
	/^INTEGER/ and do {
	    if ($val !~ /^[+-\d]*$/) {
		warn "pkt_resolve_field: unable to resolve INTEGER ENUM $val\n"
		    if $opt_w;
	    }
	    $val ||= 0 unless $in_seq_of;
	    last;
	};
	/^OBJECT_ID/ and do {
	    $val ||= 0 unless $in_seq_of;
	    last;
	};
	/^STRING/ and do {
	    my $size = $obj->{SIZE} || '*';
	    if ($val =~ s/^0[xX]//) {
		$size = $size * 2 unless $size eq  '*';
		$val = pkt_cvt_hex($val, $size);
	    } elsif ($val =~ /^(\".*\"|\'.*\')$/) {
		$val = eval($val);
		$val = pack("a$size",$val);
	    } elsif ($val =~ /^\d+$/) {
		$size = ('c','n','n','N')[$size-1] || 'N';
		$val = pack($size,$val);
	    } elsif ($val =~ /^\S+$/) {
		$val = pack("a$size",$val);
	    } else {
		warn "pkt_resolve_field: bad STRING format ($val)\n" 
		    if defined $val and $opt_w;
	    }
	    $val = "" unless defined $val or $in_seq_of or exists $obj->{DEF};
	    last;
	};
	/^BER/ and do {
	    print "pkt_resolve_field: resolving BER (val=>$val)\n" if $opt_D;
	    my $size = $obj->{SIZE} || '*';
	    if ($val =~ s/^0[xX]//) {
		$size = $size * 2 unless $size eq  '*';
		my $tval = pkt_cvt_hex($val, $size);
		$val = sub {new Convert::BER($tval)};
	    } elsif ($val =~ /^\[.*\]$/) {
		print "pkt_resolve_field: resolving BER $val\n" if $opt_D;
		$val = eval($val);
		$type = shift @{$val};
		$val = shift @{$val};
	    } elsif (ref $val eq 'ARRAY') {
		$type = ${$val}[0];
		$val = ${$val}[1];
	    }
	    last;
	};
	/^SEQUENCE/ and do {
	    print "pkt_resolve_field: resolving SEQUENCE (val=>$val)\n" if $opt_D;
	    $seq_of = 1 if $type =~ s/_OF//;
	    my $size = $obj->{SIZE} || '*';
	    $val =~ s/^(0[xX]\s*[0-9A-Fa-f]{2}|[0-9]{1,3})://;
	    my $ttag = $1;
	    if (defined $ttag) {
		$type = [ SEQUENCE => $ttag ];
	    }
	    if ($val =~ s/^0[xX]//) {
		$size = $size * 2 unless $size eq '*';
		print "pkt_resolve_field: octets (val=>$val, size=>$size)\n" 
		    if $opt_D;
		my $tval = pkt_cvt_hex($val, $size);
		$val = sub {new Convert::BER($tval)};
	    } elsif ($val =~ /^(\".*\"|\'.*\')$/) {
		$val = eval($val);
		my $tval = pack("a$size",$val);
		$val = sub {new Convert::BER($tval)};
	    } elsif ($val =~ /^\S+$/) {
		print "pkt_resolve_field: string (val=>$val)\n" if $opt_D;
		my $tval = pack("a$size",$val);
		$val = sub {new Convert::BER($tval)};
	    } else {
		warn "pkt_resolve_field: bad SEQUENCE format ($val)\n" 
		    if defined $val and $opt_w;
	    }
	    last;
	};
	/CHOICE/ and do {
	    $val =~ s/^(0[xX]\s*[0-9A-Fa-f]{2}|[0-9]{1,3}|\w+)://;
	    (my $ttag = $1) =~ s/\s*//g;
	    $ttag = $val, undef $val if $enum;
	    $ttag = $obj->{ENUM}{$1}, $enum = 1 
		if $obj->{ENUM} and exists $obj->{ENUM}{$1};
	    $type = (($enum or not defined $ttag) ? 
		     [ SEQUENCE => BER_CONSTRUCTOR | BER_CONTEXT | $ttag ] :
		     [ SEQUENCE => $ttag ]);
	    my $size = $obj->{SIZE};
	    $size = ($size ? $size * 2 : '*');
	    if ($val =~ s/^0[xX]//) {
		my $tval = pkt_cvt_hex($val, $size);
		$val = sub {new Convert::BER($tval);};
	    } elsif ($val =~ /^(\".*\"|\'.*\')$/) {
		$val = eval($val);
		my $tval = pack("a$size",$val);
		$val = sub {new Convert::BER($tval)};
	    } elsif ($val =~ /^\S+$/) {
		my $tval = pack("a$size",$val);
		$val = sub {new Convert::BER($tval)};
	    } else {
		warn "pkt_resolve_field: bad CHOICE format (val=>$val)\n" 
		    if defined $val and $opt_w;
	    }
	    last;
	};
    }
    $val = [$filter_sub, $val] if $filter_sub;
    return ($type,$val,$seq_of);
}

sub pkt_compile_ber_encode_arg {
    my $obj = shift;
    my $data = shift;
    my $in_seq_of = shift;
    my ($type,$rval);
    my $arg;
    my $tag = $obj->{TAG};
    my $seq_of;
    my $filter_sub;

    print "pkt_compile_ber_encode_arg: (tag=>$tag, in_seq_of=>$in_seq_of)\n" 
	if $opt_D;
    
    ($type, $rval, $seq_of) = pkt_resolve_field($obj,$data,$in_seq_of);

    print "pkt_compile_ber_encode_arg: resolved [$tag, $type, $rval, $seq_of]\n" 
	if $opt_D;

    # if $rval is an array ref then the first element is a function
    # name and args which will be run as a filter on the resulting
    # field values. If present the second element in the array ref is
    # the resolved value which has supplied by the user. (note:
    # handling this filter function on a 'BER' type is tricky, $rval
    # will be a code ref as well)
    my $filter_sub;
    if (ref $rval eq 'ARRAY') {
	$filter_sub = shift(@{$rval});
	$rval = shift(@{$rval});
	print "pkt_compile_ber_encode_arg: got filter sub $filter_sub\n" 
	    if $opt_D;
    }

    # if $rval is not defined then we still need to look
    # for sub definition and resolve this BER clause
    if (not defined $rval) {
	my $def = $obj->{DEF};
	if (defined $def) {
	    print "pkt_compile_ber_encode_arg: found sub DEF for $tag\n" if $opt_D;
	    # look for sub definition fields in $data at least once,
	    # if we are within a SEQ_OF then look for multiple entries
	    # until no more are found, note: passing seq_arg==1 to 
	    # pkt_compile_ber_encode_arg means don't pass back defaults 
	    # since we only want to add as many as are realy in $data
	    my @sub_args, $sub_args, $seq_arg, $found_some;
	    do {
		$seq_arg = $seq_of||$in_seq_of||0;
		undef $found_some;
		foreach my $sub_obj (@{$def}) {
		    $sub_args =	pkt_compile_ber_encode_arg($sub_obj,$data,$seq_arg);
		    push(@sub_args, @{$sub_args});
		    # if we found one component of a SEQ_OF sub construct then
		    # it is ok to begin allowing defaults (i.e., seq_arg = 0)
		    $found_some++,$seq_arg=0 if @{$sub_args};
		} 
	    } until (not $found_some or not $seq_of);
	    # handle a BER constructed string (e.g., msgSecParam)
	    if ($type eq 'STRING') {
		$arg = 
		    [$type => 
		     sub {new Convert::BER(@sub_args)->buffer}];
	    } else {
		# pass back sub constructs or empty list (probably 
		# meaning a "seq_of" with no elements)
		$arg = (@sub_args ? [$type => [ @sub_args ]] : []);
	    }
	} else {
	    warn "no value, default or DEF found for (tag=>$tag)\n" 
		if $opt_w and not $in_seq_of;
	    $arg = [];
	}
    } else {
	$arg = [$type => $rval];
    }
    if ($filter_sub) {
	my $input_arg = $arg;
	my $sub = $filter_sub;
	$arg = [BER => 
		sub {
		    # provide $ber as 'local' var to filter_sub
		    local $ber = new Convert::BER(@{$input_arg});
		    print "TRYING to call $sub\n";
		    eval $sub;
		    return $ber;
		}];
    }
    return $arg;
}

sub pkt_encode_ber_packet {
    my $tmpl = shift;
    my $data = shift;

    my $ber_args = pkt_compile_ber_encode_arg($tmpl,$data);

    my $ber = new Convert::BER();
    $ber->encode(@{$ber_args});
    
    foreach my $sub (@pkt_post_process_stack) {
	&$sub($ber); # all post process subs are passed 'ber'
    }

    print $ber->error() if $opt_D and $ber->error();

    return $ber;
}

sub pkt_decode_ber_packet {
    my $tmpl = shift;
    my $ber_pkt = shift;
    my $data;

    return $data;
}

sub pkt_display_packet {
    my $pkt = shift;

    $pkt->dump if ref $pkt eq 'Convert::BER' and $opt_D;

    $pkt = $pkt->buffer() if ref $pkt eq 'Convert::BER';

    $pkt = join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $pkt));
    print "$pkt\n";
}

sub pkt_exchange_packet {
    my $pkt = shift;
    my $addr = shift || 'localhost';
    my $port = shift || '161';
    my $timeout = shift || '3';
    my $retries = shift || '3';
    my ($inlen, $outlen, $rin, $rout, $eout, $retry, $count);


    socket(SOCKET, PF_INET, SOCK_DGRAM, getprotobyname('udp')) or
	warn "Could not create socket:$!\n", return undef;
    my $remote_iaddr = inet_aton($addr);
    unless ($remote_iaddr) { warn "Unknown host [$addr]"; return undef; }
    my $remote_paddr = sockaddr_in($port, $remote_iaddr);
    while (1) {
	$outlen = send(SOCKET, $pkt->buffer(), 0, $remote_paddr);
	print "pkt_send_packet: sent $outlen from buffer\n" if $opt_D;
	vec($rin='', fileno(SOCKET),1) = 1;
	# wait for packet, or exception, or timeout
	$count = select($rout=$rin, undef, $eout=$rin, $timeout);
	# abort after too many retries
	warn "pkt_send_packet: Timeout: no response from $host", last if $retry >= $retries;
	# retry if timeout or exception
	$retry++, next
	    unless vec($rout,fileno(SOCKET),1) and !vec($eout,fileno(SOCKET),1);
	# recieve incoming packet
	print"pkt_send_packet:trying recv:select returned $count:$!\n" if $opt_D;
	$remote_paddr = recv(SOCKET, $inbuf, 512,0);
	# check source, ignore if not from original source address
	($port, $remote_iaddr) = sockaddr_in($remote_paddr);
	return(new Convert::BER($inbuf)) if length $inbuf;
    }
    return undef;
}

sub pkt_gen_ku {
    my $proto = shift;
    my $pass = shift;
    my $len = length($pass);

    print "pkt_gen_ku: called ($proto, $pass)\n";
    return undef unless $len;
    
    $meg = 1048576;
    $md = new SSLeay::MD($proto);
    $md->init();
    $pass .= $pass x ($meg / $len);
    $md->update(substr($pass,$offset,$meg));
    my $final = $md->final();

    print "pkt_gen_ku: genrating Ku-$proto (",
       substr($pass,0,$len),"): ",
       join(" ", "0x", map {sprintf "%02X", $_;} 
	    unpack("C*", $final)),
       "\n" if $opt_D;

    return $final;
}

sub pkt_gen_kul {
    my $proto = shift;
    my $ku = shift;
    my $engine_id = shift;

    if ($proto eq 'md5') {
	$blen = 16;
    } elsif ($proto eq 'sha1') {
	$blen = 20;
    } else {
	return undef;
    }
    $ku = substr($ku,0,$blen);
    my $key = "$ku$engine_id$ku";

    $md = new SSLeay::MD($proto);
    $md->init();
    $md->update($key);
    my $final = $md->final();

    print "pkt_gen_kul: generating Kul-$proto (from Ku) : ",
       join(" ", "0x", map {sprintf "%02X", $_;} 
	    unpack("C*", $final)),
       "\n" if $opt_D;

    return $final;
}

sub pkt_find_field_pos {
    my $ber = shift;
    my $field = shift;
    my $tmpl = shift;
    my $tag = $tmpl->{TAG};

    print "pkt_find_field_pos: searching for $field in $tag at ", 
    $ber->pos(), "\n" if $opt_D;
    return $ber->pos() if $tag eq $field;

    my $ber_tag = $ber->unpack_tag();
    my $len = $ber->unpack_length();

    my $def = $tmpl->{DEF};
    if (defined $def) {
	foreach my $sub_obj (@{$def}) {
	    my $result = pkt_find_field_pos($ber,$field,$sub_obj);
	    return $result if defined $result;
	} 
    } else {
	$ber->pos($ber->pos() + $len);
    }
    return undef;
}

sub pkt_auth_param {
    my $auth_proto = shift;
    my $passphrase = shift;
    my $engine_id = shift;

    my $ku = pkt_gen_ku($auth_proto,$passphrase);
    $engine_id = pkt_cvt_hex($engine_id) if $engine_id =~ /^\s*0[xX]/;
    my $kul = pkt_gen_kul($auth_proto,$ku,$engine_id);
    
    my $extAuthKey = pack("a64",$kul);
    my $ipad = pack("C*",map {0x36} (1..64));
    my $k1 = $extAuthKey ^ $ipad;
    my $opad = pack("C*",map {0x5C} (1..64));
    my $k2 = $extAuthKey ^ $opad;

    my $post_sub = 
	sub {
	    my $ber = shift; # all post process subs are passed 'ber'
	    
	    my $md = new SSLeay::MD($auth_proto);
	    $md->update($k1);
	    $md->update($ber->buffer());
	    my $digest = $md->final();

	    $md->init();
	    $md->update($k2);
	    $md->update($digest);
	    $digest = $md->final();

	    $digest = substr($digest,0,12);
	    print "pkt_auth_param:anon: generating authParam : ",
	       join(" ", "0x", map {sprintf "%02X", $_;} 
		    unpack("C*", $digest)),
	    "\n" if $opt_D;	    
	    my $pos = pkt_find_field_pos($ber, 'msgAuthParam', $pktTmpl);
	    return unless defined $pos;
	    my $buffer = $ber->buffer();
	    substr($buffer,$pos+2,12) = $digest;
	    $ber->buffer($buffer);
	};
    pkt_push_post_process($post_sub);
    print "pkt_auth_param: $auth_proto, $passphrase\n" if $opt_D;
    return "0x000000000000000000000000";
}

sub pkt_encrypt_data {
    my $priv_proto = shift;
    my $auth_proto = shift;
    my $passphrase = shift;
    my $engine_id = shift;
    my $buf = $ber->buffer();
    # $buf .= "\0" x (8 - length($buf) % 8) if length($buf) % 8;
    print "pkt_encrypt_data: called [$priv_proto, $passphrase, ",
    length($buf), join(" ", ", 0x", map {sprintf "%02X", $_;} unpack("C*", $buf)),"]\n";

    my $ku = pkt_gen_ku($auth_proto,$passphrase);
    $engine_id = pkt_cvt_hex($engine_id) if $engine_id =~ /^\s*0[xX]/;
    my $kul = pkt_gen_kul($auth_proto,$ku,$engine_id);

    my $des_key = substr($kul,0,8);
    my $pre_iv = substr($kul,8,8); # last 8, this may not be right for SHA
#    my $salt = pack('NN',rand(0xffffffff),rand(0xffffffff));
    my $salt = pack('NN',1,1);
print join(" ", "salt = 0x", map {sprintf "%02X", $_;} unpack("C*", $salt)),"\n";
    my $iv = $pre_iv ^ $salt;
    my $cipher = new SSLeay::Cipher('des-cbc');
    $cipher->init($des_key, $iv, 1);
    my $oldbuf=$buf;
    $buf = $cipher->update($buf);
    $buf .= $cipher->final();
    $cipher->init($des_key, $iv,0);
    my $newbuf = $cipher->update($buf);
    $newbuf .= $cipher->final();
    print "pkt_encrypt_data: called [buflen => ", length($buf), "buf => ", 
    join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $buf)),", iv => ",
    join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $iv)),", key => ",
    join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $kul)),", oldbuf => ",
    join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $oldbuf)),", newbuf => ",
    join(" ", "0x", map {sprintf "%02X", $_;} unpack("C*", $newbuf)),"]\n";
    $ber = new Convert::BER(STRING => $buf);
}

#main

getopts("p:a:w:dD");

my $pktDataFile = $opt_p || 'packet.txt';
my $destAddr = $opt_a || 'localhost';

my $pktData = pkt_read_packet_data($pktDataFile);

my $ber_packet = pkt_encode_ber_packet($pktTmpl,$pktData);

print "warning: input packet data fields ignored [@{keys %$pktData}]\n" if $opt_D and keys %$pktData;

pkt_display_packet($ber_packet) if $opt_d;

$ber_packet = pkt_exchange_packet($ber_packet,$destAddr);

pkt_display_packet($ber_packet) if $opt_d;

my $rspData = pkt_decode_ber_packet($pktTmpl, $ber_packet);












