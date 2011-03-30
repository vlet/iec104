package Net::IEC104;

use 5.008008;
use strict;
use warnings;
use Carp;
use IO::Socket::INET;
use Event::Lib;
use Date::Manip;
use Time::HiRes qw/ gettimeofday tv_interval /;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use Net::IEC104 ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
    'all' => [
        qw(
          &connect &listen &send &main_loop &disconnect
          )
    ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(

);

our $VERSION = '0.03';

###############################################################################

$| = 1;

our $debug         = 0;
our $MAX_ASDU_SIZE = 248;
our $MAX_S_QUEUE   = 100;

our %asdu_type = (

    # Infromation to control direction, ASDU: 1-44
    30 => {
        "size"     => 8,
        "name"     => "M_SP_TB_1",
        type       => "TS",
        "parse_cb" => \&parse_asdu_type_0_44,
        "write_cb" => \&send_asdu_type_0_44
    },
    35 => {
        "size"     => 10,
        "name"     => "M_ME_TE_1",
        type       => "TI",
        "parse_cb" => \&parse_asdu_type_0_44,
        "write_cb" => \&send_asdu_type_0_44
    },
    36 => {
        "size"     => 12,
        "name"     => "M_ME_TF_1",
        type       => "TI",
        "parse_cb" => \&parse_asdu_type_0_44,
        "write_cb" => \&send_asdu_type_0_44
    },
    37 => {
        "size"     => 12,
        "name"     => "M_IT_TB_1",
        type       => "TII",
        "parse_cb" => \&parse_asdu_type_0_44,
        "write_cb" => \&send_asdu_type_0_44
    },

    # System information to controlled direction, ASDU: 100-109
    100 => {
        "size"     => 1,
        "name"     => "C_IC_NA_1",
        type       => "",
        "parse_cb" => \&parse_asdu_type_100,
        "write_cb" => \&send_asdu_type_100
    },
    103 => {
        "size"     => 7,
        "name"     => "C_CS_NA_1",
        type       => "",
        "parse_cb" => \&parse_asdu_type_103,
        "write_cb" => \&send_asdu_type_103
    },
);

# Constructor
sub new {
    my $self  = shift;
    my %h     = @_;
    my $class = ref($self) || $self;
    croak "wrong type of Net::IEC104"
      if ( $h{type} ne "slave" and $h{type} ne "master" );

    $h{retry_timeout} = ( exists $h{retry_timeout} ) ? $h{retry_timeout} : 5;
    $h{ip}   = ( exists $h{ip} )   ? $h{ip}   : "0.0.0.0";
    $h{port} = ( exists $h{port} ) ? $h{port} : "2404";

    bless \%h, $class;
}

# Print debug messages
sub DEBUG {
    my $d = shift;
    if ( $debug >= $d ) {
        print @_;
        if ( $d < 0 ) {
            printf "<-- at %s:%s", (caller)[ 1, 2 ];
        }
        unless ( $_[$#_] =~ /\s$/ ) {
            print "\n";
        }
    }
}

# Pack ip-port pair as ID of connection
sub get_id {
    my $sock = shift;
    return pack( "C4S", split( /\./, $sock->peerhost ), $sock->peerport );
}

# Unpack ip-port pair to printable form
sub sid2hex {
    return join( ".", map { sprintf "%d", $_ } unpack( "C4S", shift ) );
}

# Print hex-codes of raw data
sub raw2hex {
    return join( ",", map { sprintf "%02X", $_ } unpack( "C*", shift ) );
}

# convert from cp56_2a format of time to gettimeofday
sub cp56_2a_2_time {
    my $data = shift;
    my @tm   = unpack( "SC5", $data );
    my $tm   = Date_SecsSince1970GMT(
        $tm[4] & 0xF,
        $tm[3] & 0x1F,
        2000 + ( $tm[5] & 0x7F ),
        $tm[2] & 0x1F,
        $tm[1] & 0x3F,
        int( $tm[0] / 1000 )
    );
    my $ms = ( $tm[0] % 1000 ) * 1000;
    return ( $tm, $ms );
}

# convert from gettimeofday format to cp56_2a
sub time_2_cp56_2a {
    my $tm = shift;
    my $ms = shift;
    $ms = int( $ms / 1000 );
    my @tm = localtime($tm);
    return pack( "SC5",
        ( $tm[0] * 1000 + $ms ),
        $tm[1],
        $tm[2] | ( $tm[8] << 7 ),
        $tm[3] | ( $tm[6] << 5 ),
        ++$tm[4], $tm[5] % 100 );
}

# debug info about connection
sub sidinfo {
    my $self = shift;
    my $sid  = shift;
    my $report;
    my $s = \%{ $self->{sids}{$sid} };

    $report =
        "=====================\n"
      . "TYPE:  "
      . $s->{type} . "\n"
      . sprintf( "IP:    %d.%d.%d.%d\n" . "PORT:  %d\n", unpack( "C4S", $sid ) )
      . "UFUNC: "
      . $s->{ufunc} . "\n"
      . "VS:    "
      . $s->{vs} . "\n"
      . "VR:    "
      . $s->{vr} . "\n"
      . "AS:    "
      . $s->{as} . "\n"
      . "AR:    "
      . $s->{ar} . "\n"
      . "s_queue: "
      . $#{ $s->{s_queue} } . "\n";
    foreach my $timer (
        "t0_timer", "t1_timer", "t2_timer", "t3_timer",
        "ci_timer", "sync_timer"
      )
    {
        $report .= $timer . ": ";
        if ( $s->{$timer}->pending ) {
            $report .= "pending\n";
        }
        else {
            $report .= "not started\n";
        }
    }
    return $report;
}

# public method listen()
# start IEC slave station (server)
sub listen {
    my $self = shift;
    my %h    = @_;
    carp "called without a reference" if ( !ref($self) );

    my $server = IO::Socket::INET->new(
        LocalAddr => $self->{ip},
        LocalPort => $self->{port},
        Proto     => 'tcp',
        ReuseAddr => SO_REUSEADDR,
        Listen    => 1,
        Blocking  => 0,
    ) or carp $@;
    return -1 unless ($server);
    &DEBUG( 1, "Listen on ", $self->{ip}, ":", $self->{port} );
    my $main =
      event_new( $server, EV_READ | EV_PERSIST, \&handle_incoming, $self );
    $main->add;
}

# public method connect()
# start IEC master session
sub connect {
    my $self = shift;
    carp "called without a reference" if ( !ref($self) );

    my $client = IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => $self->{ip},
        PeerPort => $self->{port},
        Blocking => 0
    ) or carp $@;

    my $main = event_new( $client, EV_WRITE, \&on_connect, $self );
    $main->add(2);
}

sub on_connect {
    my ( $e, $type, $self ) = @_;
    my $error = 1;

    if ( $type == EV_TIMEOUT ) {
        &DEBUG( 0, "Can't connect to ",
            $self->{ip}, ":", $self->{port}, ", connection timeout" );
    }
    elsif ( $type == EV_WRITE ) {
        my $client = $e->fh;
        unless ( $client->connected ) {
            &DEBUG( 0, "Can't connect to ",
                $self->{ip}, ":", $self->{port}, ", connection rejected" );
        }
        else {
            $self->{retry_count} = 0;
            $error = 0;
            &DEBUG( 1, "connected to ", $self->{ip}, ":", $self->{port} );
            my $sid  = &get_id($client);
            my $main = event_new( $client, EV_READ | EV_PERSIST,
                \&handle_client, $self, $sid );
            $self->init_new_conn(
                sid   => $sid,
                event => $main,
                type  => "MASTER"
            );
            $main->add;

            $self->frame_u_send( $sid, "STARTDTACT" );
        }
    }

    if ( $error && $self->{persist} ) {
        my $timer = timer_new( \&reconnect, $self );
        $timer->add( $self->{retry_timeout} );
    }
}

# Main event loop
sub main_loop {
    event_mainloop;
}

# Sync time
sub sync_time {
    my ( $cause, $s, $data );
    my $self = shift;
    my $csid = undef;

    if ( $#_ != -1 && defined( $_[0] ) ) {
        $csid = shift;
    }

    if ( $self->{type} eq "master" ) {
        $cause = 6;    # activation
    }
    else {
        $cause = 3;    # sporadic
    }

    foreach my $sid ( keys %{ $self->{sids} } ) {
        next if ( defined($csid) && $csid ne $sid );
        $s = \%{ $self->{sids}{$sid} };
        &DEBUG( 2, "Sync time for CA: ",
            $s->{ca}, ", My current time: ", time() );
        $data =
          pack( "C2S3C", 103, 1, $cause, $s->{ca}, 1, 0 )
          . &time_2_cp56_2a(gettimeofday);
        $self->frame_i_send( $sid, $data );
    }
}

# handle incoming connections
sub handle_incoming {
    my $e      = shift;
    my $etype  = shift;
    my $self   = shift;
    my $h      = $e->fh;
    my $client = $h->accept or croak "$!";
    $client->blocking(0);
    &DEBUG( 1, "accept connection from ",
        $client->peerhost, ":", $client->peerport );

    my $sid = &get_id($client);

    # set up a new event that watches the client socket
    my $event =
      event_new( $client, EV_READ | EV_PERSIST, \&handle_client, $self, $sid );
    $self->init_new_conn(
        sid   => $sid,
        event => $event,
        type  => "SLAVE"
    );
    $event->add;
}

# init new structure for connection
sub init_new_conn {
    my $self = shift;
    my %h    = @_;
    my $sid  = $h{"sid"} or croak $@;

    $self->{sids}{$sid} = ();
    my $s = \%{ $self->{sids}{$sid} };

    $s->{type} = ( $h{type} ) ? $h{type} : "SLAVE";
    $s->{event} = $h{"event"} or croak $@;
    $s->{ufunc} = ( $self->{ufunc} ) ? $self->{ufunc} : "STOPDT";
    $s->{ca} = ( $self->{ca} ) ? $self->{ca} : 1;     # common address of asdu
    $s->{t0} = ( $self->{t0} ) ? $self->{t0} : 30;    # t0 timeout, sec
    $s->{t1} = ( $self->{t1} ) ? $self->{t1} : 15;    # t1 timeout, sec
    $s->{t2} = ( $self->{t2} ) ? $self->{t2} : 10;    # t2 timeout, sec
    $s->{t3} = ( $self->{t3} ) ? $self->{t3} : 20;    # t3 timeout, sec
    $s->{w}  = ( $self->{w} )  ? $self->{w}  : 8;     # w
    $s->{k}  = ( $self->{k} )  ? $self->{k}  : 12;    # k
    $s->{vs} = 0;                                     # Number S sended
    $s->{vr} = 0;                                     # Number S received
    $s->{as} = 0;                                     # Number S ack by me
    $s->{ar} = 0;                                     # Number S ack by peer

    $s->{rcb} =
      ( $self->{read_callback} ) ? $self->{read_callback} : \&default_read_cb;
    $s->{wcb} =
      ( $self->{write_callback} )
      ? $self->{write_callback}
      : \&default_write_cb;

    $s->{ts_fn}  = ( $self->{ts_func_num} )  ? $self->{ts_func_num}  : 30;
    $s->{ti_fn}  = ( $self->{ti_func_num} )  ? $self->{ti_func_num}  : 36;
    $s->{tii_fn} = ( $self->{tii_func_num} ) ? $self->{tii_func_num} : 37;

    $s->{s_queue} = [];       # Send queue
    $s->{r_buf}   = undef;    # Receive buffer

    $s->{t0_timer} = timer_new( \&t0_timer_run, $self, $sid );
    $s->{t1_timer} = timer_new( \&t1_timer_run, $self, $sid );
    $s->{t2_timer} = timer_new( \&t2_timer_run, $self, $sid );
    $s->{t3_timer} = timer_new( \&t3_timer_run, $self, $sid );

    $s->{ci_timeout} =
      ( $self->{ci_timeout} ) ? $self->{ci_timeout} : 5 * 60;  # CI timeout, sec
    $s->{sync_timeout} =
      ( $self->{sync_timeout} )
      ? $self->{sync_timeout}
      : 60 * 60;    # Sync timeout, sec
    $s->{ci_timer}   = timer_new( \&ci_timer_run,   $self, $sid );
    $s->{sync_timer} = timer_new( \&sync_timer_run, $self, $sid );

    $s->{time_diff} = 0;    # diff in time between kp and control station

    $s->{t0_timer}->add( $s->{t0} );    # timeout of init connection
}

# Invoked when the client's socket becomes readable
sub handle_client {
    my $data;

    my $e     = shift;
    my $etype = shift;
    my $self  = shift;
    my $sid   = shift;
    my $h     = $e->fh;
    my $s     = \%{ $self->{sids}{$sid} };

    unless ( $h->connected ) {
        &DEBUG( 9, "client disconnected" );
        $self->disconnect($sid);
        return;
    }
    if ( eof($h) ) {
        &DEBUG( 1, "connection not readable" );
        $self->disconnect($sid);
        return;
    }

    if ( defined( $self->{sids}{$sid}{r_buf} ) ) {
        $data = $s->{r_buf};
        $s->{r_buf} = undef;
    }

    while (<$h>) {
        $data .= $_;
    }

    my ( $start, $length, $bits ) = unpack( "C3", $data );
    while (1) {
        if ( $start != 0x68 || length($data) < 3 ) {

            #error in Net::IEC104 packet
            &DEBUG( 11, raw2hex($data) );
            &DEBUG(
                1,
                "error in Net::IEC104 chunk: START: ",
                $start,
                "; LENGTH: ",
                defined($length) ? $length : 0,
                "; DATA SIZE: ",
                length($data)
            );
            $self->disconnect($sid);
            return;
        }

        # retransmission (part of data will be received in next packet)
        # put data in receive buffer
        if ( $length > length($data) - 2 ) {
            &DEBUG( 2,
"receive fragmented packet, save data in buffer and wait next chunk"
            );
            &DEBUG( 2, "LENGTH: ", length($data) - 2,
                " of ", $length, " bytes" );
            $s->{r_buf} = $data;
            return;
        }
        my $curdata = substr( $data, 0, $length + 2 );
        &DEBUG( 11, raw2hex($curdata) );

        # Receiving packet of any type restart a T3 timer
        if ( $s->{t3_timer}->pending ) {
            $s->{t3_timer}->remove;
        }
        $s->{t3_timer}->add( $s->{t3} );

        if ( ( $bits & 1 ) == 0 ) {

            # frame type I
            $self->frame_i_recv( $sid, $curdata );
        }
        elsif ( ( $bits & 3 ) == 1 ) {

            # frame type S
            $self->frame_s_recv( $sid, $curdata );
        }
        elsif ( ( $bits & 3 ) == 3 ) {

            # frame type U
            $self->frame_u_recv( $sid, $curdata );
        }
        else {
            &DEBUG( 0, "unknown frame type" );
        }
        $data = substr( $data, $length + 2 );
        return unless ($data);
        ( $start, $length, $bits ) = unpack( "C3", $data );
    }
}

# public method disconnect()
# close client or server connection
sub disconnect {
    my $self = shift;
    my ( $e, $h );
    my $csid = undef;

    if ( $#_ != -1 && defined( $_[0] ) ) {
        $csid = shift;
    }

    foreach my $sid ( keys %{ $self->{sids} } ) {
        next if ( defined($csid) && $csid ne $sid );
        $e = $self->{sids}{$sid}{event};
        $h = $e->fh;
        &DEBUG( 1, "disconnected from ", &sid2hex($sid) );
        close $h;
        $e->remove;
        $self->{sids}{$sid}{t0_timer}->remove;
        $self->{sids}{$sid}{t1_timer}->remove;
        $self->{sids}{$sid}{t2_timer}->remove;
        $self->{sids}{$sid}{t3_timer}->remove;
        $self->{sids}{$sid}{ci_timer}->remove;
        $self->{sids}{$sid}{sync_timer}->remove;
        delete $self->{sids}{$sid};

        if ( $self->{type} eq "master" && $self->{persist} != 0 ) {
            &DEBUG( 11, "persist is true, reconnect..." );
            $self->connect();
        }
        else {
            &DEBUG( 11, "persist is not true, dont reconnect..." );
        }
    }
}

sub reconnect {
    my $e     = shift;
    my $etype = shift;
    my $self  = shift;
    my $timer;

    $self->{retry_count}++;
    &DEBUG(
        1, "reconnect to ",
        $self->{ip}, ":", $self->{port}, " after fail... Attempt: ",
        $self->{retry_count}
    );
    $self->connect;
}

# public method send()
# send spontaneous data to all client connections (only for SLAVE)
sub send {
    my $self = shift;
    my $ca   = shift;
    my %h    = @_;
    return if ( $self->{type} ne "slave" );
    foreach my $sid ( keys %{ $self->{sids} } ) {
        next
          if ( !defined( $self->{sids}{$sid} )
            || $self->{sids}{$sid}{ufunc} eq "STOPDT"
            || $self->{sids}{$sid}{ca} != $ca );
        if ( exists $h{"TI"} && $self->{sids}{$sid}{ti_fn} != 0 ) {
            &{ $asdu_type{ $self->{sids}{$sid}{ti_fn} }{write_cb} }( $self,
                $sid, 3, $self->{sids}{$sid}{ti_fn}, $h{"TI"} );
        }
        if ( exists $h{"TS"} && $self->{sids}{$sid}{ts_fn} != 0 ) {
            &{ $asdu_type{ $self->{sids}{$sid}{ts_fn} }{write_cb} }( $self,
                $sid, 3, $self->{sids}{$sid}{ts_fn}, $h{"TS"} );
        }
        if ( exists $h{"TII"} && $self->{sids}{$sid}{tii_fn} != 0 ) {
            &{ $asdu_type{ $self->{sids}{$sid}{tii_fn} }{write_cb} }( $self,
                $sid, 3, $self->{sids}{$sid}{tii_fn}, $h{"TII"} );
        }
    }
}

sub t0_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;

    &DEBUG( 1, "sid: ", &sid2hex($sid), ". t0 timer run" );
    $self->disconnect($sid);
}

sub t1_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;
    &DEBUG( 1, "sid: ", &sid2hex($sid), ". t1 timer run" );
    $self->disconnect($sid);
}

sub t2_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;
    &DEBUG( 2, "t2 timer run" );
    $self->frame_s_send($sid);
}

sub t3_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;
    my $s    = \%{ $self->{sids}{$sid} };
    &DEBUG( 1, "sid: ", &sid2hex($sid), ". t3 timer run" );
    $self->frame_u_send( $sid, "TESTFRACT" );
    unless ( $s->{t1_timer}->pending ) {
        $s->{t1_timer}->add( $s->{t1} );
    }
}

sub ci_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;
    &DEBUG( 1, "sid: ", &sid2hex($sid), ". ci timer run" );
    $self->frame_i_send( $sid,
        pack( "C2S3C2", 100, 1, 6, $self->{sids}{$sid}{ca}, 0, 0, 20 ) );
}

sub sync_timer_run {
    my $e    = shift;
    my $type = shift;
    my $self = shift;
    my $sid  = shift;
    &DEBUG( 1, "sid: ", &sid2hex($sid), ". sync timer run" );
    $self->sync_time($sid);
}

# send frame type U
sub frame_u_send {
    my $self = shift;
    my $sid  = shift;
    my $func = shift;
    my $bits = 3;

    &DEBUG( 3, "send frame type U, function ", $func, ": " );
    if ( $func eq "STARTDTACT" ) {
        $bits |= 1 << 2;
    }
    elsif ( $func eq "STARTDTCON" ) {
        $bits |= 1 << 3;
    }
    elsif ( $func eq "STOPDTACT" ) {
        $bits |= 1 << 4;
    }
    elsif ( $func eq "STOPDTCON" ) {
        $bits |= 1 << 5;
    }
    elsif ( $func eq "TESTFRACT" ) {
        $bits |= 1 << 6;
    }
    elsif ( $func eq "TESTFRCON" ) {
        $bits |= 1 << 7;
    }

    return unless ( defined( $self->{sids}{$sid}{event} ) );
    my $sock = $self->{sids}{$sid}{event}->fh;
    my $data = pack( "C6", 0x68, 4, $bits, 0, 0, 0 );
    &DEBUG( 3, raw2hex($data) );
    print $sock $data;
}

sub frame_u_recv {
    my $self = shift;
    my $sid  = shift;
    my $data = shift;

    my ($bits) = ( unpack( "C3", $data ) )[2];
    &DEBUG( 3, "received frame type U, function " );

    if ( $bits & 1 << 2 ) {

        # STARTDT ACT
        &DEBUG( 3, "STARTDTACT" );
        if ( $self->{sids}{$sid}{type} ne "SLAVE" ) {
            &DEBUG( 0, "master receive STARTDT ACT" );
            return -1;
        }

        # T0 timer removed after init
        $self->{sids}{$sid}{t0_timer}->remove;
        $self->{sids}{$sid}{ufunc} = "STARTDT";
        $self->frame_u_send( $sid, "STARTDTCON" );
    }
    elsif ( $bits & 1 << 3 ) {

        # STARTDT CON
        &DEBUG( 3, "STARTDTCON" );
        if ( $self->{sids}{$sid}{type} ne "MASTER" ) {
            return -1;
        }

        # Slave answer on init -> remove T0 timer
        $self->{sids}{$sid}{t0_timer}->remove;

        $self->{sids}{$sid}{ufunc} = "STARTDT";

        # Connection activated.
        # Sync time
        $self->sync_time($sid);

        # Start common interogation
        $self->frame_i_send( $sid,
            pack( "C2S3C2", 100, 1, 6, $self->{sids}{$sid}{ca}, 0, 0, 20 ) );

    }
    elsif ( $bits & 1 << 4 ) {

        # STOPDT ACT
        &DEBUG( 3, "STOPDTACT" );
        if ( $self->{sids}{$sid}{type} ne "SLAVE" ) {
            return -1;
        }
        $self->{sids}{$sid}{ufunc} = "STOPDT";
        $self->frame_u_send( $sid, "STOPDTCON" );
    }
    elsif ( $bits & 1 << 5 ) {

        # STOPDT CON
        &DEBUG( 3, "STOPDTCON" );
        if ( $self->{sids}{$sid}{type} ne "MASTER" ) {
            return -1;
        }
        $self->{sids}{$sid}{ufunc} = "STOPDT";
    }
    elsif ( $bits & 1 << 6 ) {

        # TESTFR ACT
        &DEBUG( 3, "TESTFRACT" );
        $self->frame_u_send( $sid, "TESTFRCON" );
    }
    elsif ( $bits & 1 << 7 ) {

        # TESTFR CON
        &DEBUG( 3, "TESTFRCON" );
        $self->{sids}{$sid}{t1_timer}->remove;
    }
    else {
        &DEBUG( 3, "unknown" );
        &DEBUG( 0, "Error in received U frame: unknown type" );
    }
}

# send frame type S
sub frame_s_send {
    my $self = shift;
    my $sid  = shift;
    if ( $self->{sids}{$sid}{as} == $self->{sids}{$sid}{vr} ) {
        &DEBUG(
            2,
            "not sending frame type S, AS=VR (",
            $self->{sids}{$sid}{as},
            "=", $self->{sids}{$sid}{vr}, ")"
        );
        return;
    }
    &DEBUG( 3, "send frame type S(", $self->{sids}{$sid}{vr}, ")" );
    my $sock = $self->{sids}{$sid}{event}->fh;
    print $sock pack( "C4S", 0x68, 4, 1, 0, $self->{sids}{$sid}{vr} << 1 );
    $self->{sids}{$sid}{as} = $self->{sids}{$sid}{vr};
}

# receive frame type S
sub frame_s_recv {
    my $self = shift;
    my $sid  = shift;
    my $data = shift;

    my ($nr) = ( unpack( "C2S2", $data ) )[3];
    $nr >>= 1;
    if ( ( ( $self->{sids}{$sid}{vs} - $nr + 32768 ) % 32768 ) >
        $self->{sids}{$sid}{k} )
    {
        &DEBUG(
            0, "wrong N(R) number in S-ack received: ",
            $nr,
            ". Current N(S) = ",
            $self->{sids}{$sid}{vs}
        );
        $self->disconnect($sid);
        return;
    }
    &DEBUG( 3, "received frame type S(", $nr, ")" );
    $self->{sids}{$sid}{ar} = $nr;
    $self->{sids}{$sid}{t1_timer}->remove;

    $self->flush_send_queue($sid);
}

sub flush_send_queue {
    my $ret;
    my $self = shift;
    my $sid  = shift;

    #return if ($#{$self->{sids}{$sid}{s_queue}} == -1);
    #for my $i (0 .. $#{$self->{sids}{$sid}{s_queue}}) {
    #$ret = $self->frame_i_send($sid,undef);
    #last if ($ret != 0);
    #}
    while ( $#{ $self->{sids}{$sid}{s_queue} } != -1 ) {
        last if ( $self->frame_i_send( $sid, undef ) );
    }
}

sub frame_i_send {
    my $self = shift;
    my $sid  = shift;
    my $asdu = shift;

    unless ( exists( $self->{sids}{$sid} ) ) {
        &DEBUG( 0, "frame_i_send(): error, connection ",
            &sid2hex($sid), " already dead\n" );
        for my $j ( 0 .. 3 ) {
            &DEBUG( 0, join( "->", ( caller($j) )[ 0, 1, 2, 3 ] ) );
        }
        return -1;
    }
    if ( $self->{sids}{$sid}{vs} ==
        ( $self->{sids}{$sid}{ar} + $self->{sids}{$sid}{k} ) % 32768 )
    {
        &DEBUG( 2, "reached k, no frames will be sent" );
        if ( $#{ $self->{sids}{$sid}{s_queue} } + 1 > $MAX_S_QUEUE ) {
            &DEBUG( 0, $self->sidinfo($sid) );
            &DEBUG( 0, "send queue overloaded, asdu dropped" );
            $self->disconnect($sid);
            return 2;
        }
        elsif ( defined($asdu) ) {
            push @{ $self->{sids}{$sid}{s_queue} }, $asdu;
            if (   $self->{sids}{$sid}{type} eq "SLAVE"
                && $#{ $self->{sids}{$sid}{s_queue} } > $MAX_S_QUEUE * 0.9 )
            {
                &DEBUG(
                    0, &sid2hex($sid),
                    ", queue increased: ",
                    ( $#{ $self->{sids}{$sid}{s_queue} } + 1 )
                );
            }
            &DEBUG(
                2,
                "asdu queued (No:",
                $#{ $self->{sids}{$sid}{s_queue} } + 1, ")"
            );
        }
        return 1;
    }
    unless ( defined($asdu) ) {
        $asdu = shift( @{ $self->{sids}{$sid}{s_queue} } )
          if ( $#{ $self->{sids}{$sid}{s_queue} } >= 0 );
        unless ( defined($asdu) ) {
            &DEBUG( 0, "Error: empty asdu" );
            return 3;
        }
        else {
            if (   $self->{sids}{$sid}{type} eq "SLAVE"
                && $#{ $self->{sids}{$sid}{s_queue} } > $MAX_S_QUEUE * 0.9 )
            {
                &DEBUG(
                    0, &sid2hex($sid),
                    ", queue reduced: ",
                    ( $#{ $self->{sids}{$sid}{s_queue} } + 1 )
                );
            }
            &DEBUG( 3, "send frame type I from queue: " );
        }
    }
    else {
        &DEBUG( 3, "send frame type I: " );
    }

    $self->{sids}{$sid}{t1_timer}->remove;
    $self->{sids}{$sid}{t1_timer}->add( $self->{sids}{$sid}{t1} );

    my $ns   = $self->{sids}{$sid}{vs} << 1;
    my $nr   = $self->{sids}{$sid}{vr} << 1;
    my $sock = $self->{sids}{$sid}{event}->fh;
    my $data = pack( "C2S2", 0x68, 4 + length($asdu), $ns, $nr ) . $asdu;
    DEBUG( 3, raw2hex($data) );
    print $sock $data;

    $self->{sids}{$sid}{vs} = ( $self->{sids}{$sid}{vs} + 1 ) % 32768;
    return 0;
}

sub frame_i_recv {
    my $self = shift;
    my $sid  = shift;
    my $data = shift;
    DEBUG( 3, "received frame type I " );
    if ( $self->{sids}{$sid}{ufunc} ne "STARTDT" ) {
        DEBUG( 0, "Error: no STARTDT in current connection" );
        return -1;
    }

    my ( $ns, $nr ) = ( unpack( "C2S2", $data ) )[ 2, 3 ];
    $ns >>= 1;
    $nr >>= 1;
    DEBUG( 3, "NS=$ns,NR=$nr" );
    if ( $ns != $self->{sids}{$sid}{vr} ) {
        &DEBUG(
            0,
            "Error: Expect N(S)=",
            $self->{sids}{$sid}{vr},
            ", but receive: ",
            $ns, ". Packet lost or reordered"
        );
        return -1;
    }
    if (   ( $nr != $self->{sids}{$sid}{ar} )
        && ( ( $nr - $self->{sids}{$sid}{ar} + 32768 ) % 32768 ) <=
        $self->{sids}{$sid}{k}
        && ( ( $self->{sids}{$sid}{vs} - $nr + 32768 ) % 32768 ) <=
        $self->{sids}{$sid}{k} )
    {
        $self->{sids}{$sid}{ar} = $nr;
        $self->{sids}{$sid}{t1_timer}->remove;
    }

    $self->{sids}{$sid}{t2_timer}->remove();
    $self->{sids}{$sid}{t2_timer}->add( $self->{sids}{$sid}{t2} );

    $self->{sids}{$sid}{vr} = ( $ns + 1 ) % 32768;
    if (
        ( $self->{sids}{$sid}{vr} - $self->{sids}{$sid}{as} + 32768 ) % 32768 ==
        $self->{sids}{$sid}{w} )
    {
        $self->frame_s_send($sid);
    }

    $self->parse_asdu( $sid, substr( $data, 6 ) );
}

sub parse_asdu {
    my $self = shift;
    my $sid  = shift;
    my $asdu = shift;

    my $i = \%{ $self->{sids}{$sid}{i} };
    my $kps;

    &DEBUG( 12, "parse_asdu(): ", raw2hex($asdu) );
    ( $i->{id}, $kps, $i->{cause}, $i->{ca} ) = unpack( "C2S2", $asdu );
    $i->{sq}   = ( $kps & 1 << 7 ) >> 7;
    $i->{nobj} = $kps & 0x7F;
    $i->{cause} &= 0xFF;
    &DEBUG( 3, "ID: ", sprintf( "%02X", $i->{id} ), ", " );
    &DEBUG( 3, "SQ: ", $i->{sq}, ", " );
    &DEBUG( 3, "NObj: ",  sprintf( "%02X", $i->{nobj} ),  ", " );
    &DEBUG( 3, "Cause: ", sprintf( "%02X", $i->{cause} ), ", " );
    &DEBUG( 3, "C.Addr ASDU: ", sprintf( "%02X", $i->{ca} ) );

    unless ( exists $asdu_type{ $i->{id} } ) {
        &DEBUG( -1, "not implemented type ", $i->{id} );
        return;
    }

    if ( $i->{sq} == 0 ) {

        # Numerous information objects
        for my $j ( 1 .. $i->{nobj} ) {
            my $k = ( $j - 1 ) * ( 3 + $asdu_type{ $i->{id} }{size} );
            ( $i->{obj}{$j}{ioa}, $i->{obj}{$j}{ioa2} ) =
              unpack( "SC", substr( $asdu, 6 + $k, 3 ) );
            $i->{obj}{$j}{data} =
              substr( $asdu, 6 + 3 + $k, $asdu_type{ $i->{id} }{size} );
        }
    }
    else {

        # One object, numerous elements
        # <{TODO}>
        &DEBUG( -1, "not implemented code" );
    }
    &{ $asdu_type{ $i->{id} }{parse_cb} }( $self, $sid );
}

sub default_read_cb {
    DEBUG( 1, "default_read_cb()" );
}

sub default_write_cb {
    DEBUG( 1, "default_write_cb()" );
    return ( "TS" => { "1" => [ "0", gettimeofday ] } );
}

sub parse_asdu_type_100 {
    my $self = shift;
    my $sid  = shift;
    my $s    = \%{ $self->{sids}{$sid} };
    my $i    = \%{ $s->{i} };
    if ( $i->{cause} == 6 ) {
        &DEBUG( 0, &sid2hex($sid), " [100] activation" );

        # drop outgoing queue
        if ( $#{ $self->{sids}{$sid}{s_queue} } >= 0 ) {
            &DEBUG(
                0, &sid2hex($sid), " drop ",
                ( $#{ $self->{sids}{$sid}{s_queue} } + 1 ),
                " asdu from queue because of activation"
            );
            $self->{sids}{$sid}{s_queue} = [];
        }

        # send accept
        $s->{ca} = $i->{ca};
        my $data = pack( "C2S3C",
            100, 1, 7, $i->{ca},
            $i->{obj}{1}{ioa},
            $i->{obj}{1}{ioa2} )
          . $i->{obj}{1}{data};
        $self->frame_i_send( $sid, $data );

        # 1. Send whole database
        my %h = &{ $s->{wcb} }( $self, $s->{ca} );

        if ( exists $h{"TI"} && $s->{ti_fn} != 0 ) {
            &{ $asdu_type{ $s->{ti_fn} }{write_cb} }( $self, $sid, 3,
                $s->{ti_fn}, $h{"TI"} );
        }
        if ( exists $h{"TS"} && $s->{ts_fn} != 0 ) {
            &{ $asdu_type{ $s->{ts_fn} }{write_cb} }( $self, $sid, 3,
                $s->{ts_fn}, $h{"TS"} );
        }
        if ( exists $h{"TII"} && $s->{tii_fn} != 0 ) {
            &{ $asdu_type{ $s->{tii_fn} }{write_cb} }( $self, $sid, 3,
                $s->{tii_fn}, $h{"TII"} );
        }
    }
    elsif ( $i->{cause} == 8 ) {
        &DEBUG( 0, &sid2hex($sid), " [100] deactivation" );

        # <{TODO}>
    }
    elsif ( $i->{cause} == 7 ) {
        &DEBUG( 2, &sid2hex($sid), " [100] accept of activation" );

        $s->{t1_timer}->remove;

        # Start timer Common Interogation
        $s->{ci_timer}->remove;
        $s->{ci_timer}->add( $s->{ci_timeout} );

        # <{TODO}>
    }
    elsif ( $i->{cause} == 9 ) {
        &DEBUG( 2, "[100] accept of deactivation" );

        # <{TODO}>
    }
    elsif ( $i->{cause} == 10 ) {
        &DEBUG( 2, &sid2hex($sid), " [100] close activation" );

        # <{TODO}>
    }
    else {
        &DEBUG( 2, "[100] unknown cause: ", $i->{cause} );
    }
}

sub parse_asdu_type_103 {
    my $self = shift;
    my $sid  = shift;
    my $s    = \%{ $self->{sids}{$sid} };
    my $i    = \%{ $s->{i} };
    if ( $i->{cause} == 6 ) {
        &DEBUG( 2, "[103] activation" );

        # send accept and current time
        $s->{ca} = $i->{ca};
        my $data = pack( "C2S3C",
            103, 1, 7, $i->{ca},
            $i->{obj}{1}{ioa},
            $i->{obj}{1}{ioa2} )
          . &time_2_cp56_2a(gettimeofday);
        $self->frame_i_send( $sid, $data );
    }
    elsif ( $i->{cause} == 3 ) {
        &DEBUG( 2, "[103] sporadic" );

        # Start timer of Sync
        $s->{sync_timer}->remove;
        $s->{sync_timer}->add( $s->{sync_timeout} );
    }
    elsif ( $i->{cause} == 7 ) {
        &DEBUG( 2, "[103] accept of activation" );
        my ( $tm, $ms ) = &cp56_2a_2_time( $i->{obj}{1}{data} );
        my $time_diff = tv_interval( [ $tm, $ms ] );
        &DEBUG( 1, "CA: ", $i->{ca}, "; KP unix time: ",
            $tm, ", Diff: ", $time_diff );
        $s->{time_diff} = $time_diff;

        # Start timer of Sync
        $s->{sync_timer}->remove;
        $s->{sync_timer}->add( $s->{sync_timeout} );
    }
    else {
        &DEBUG( 2, "[103] unknown cause: ", $i->{cause} );
    }
}

sub parse_asdu_type_0_44 {
    my ( $addr, $value, $tm, $ms );
    my $self = shift;
    my $sid  = shift;

    my $s    = \%{ $self->{sids}{$sid} };
    my $i    = \%{ $s->{i} };
    my $type = $asdu_type{ $i->{id} }{type};

    my %result = ( $type => {} );
    for my $j ( 1 .. $i->{nobj} ) {
        if ( $i->{id} == 30 ) {
            $value = unpack( "C", $i->{obj}{$j}{data} );
            $value &= 1;
            ( $tm, $ms ) =
              cp56_2a_2_time( substr( $i->{obj}{$j}{data}, 1, 7 ) );
        }
        elsif ( $i->{id} == 35 ) {
            $value = unpack( "s", $i->{obj}{$j}{data} );
            ( $tm, $ms ) =
              cp56_2a_2_time( substr( $i->{obj}{$j}{data}, 3, 7 ) );
        }
        elsif ( $i->{id} == 36 ) {
            $value = unpack( "f", $i->{obj}{$j}{data} );
            ( $tm, $ms ) =
              cp56_2a_2_time( substr( $i->{obj}{$j}{data}, 5, 7 ) );
        }
        elsif ( $i->{id} == 37 ) {
            $value = unpack( "L", $i->{obj}{$j}{data} );
            ( $tm, $ms ) =
              cp56_2a_2_time( substr( $i->{obj}{$j}{data}, 5, 7 ) );
        }
        $tm += int( $s->{time_diff} );
        $ms += int( ( $s->{time_diff} - int( $s->{time_diff} ) ) * 1000000 );
        if ( $ms > 1000000 ) {
            $ms -= 1000000;
            $tm++;
        }
        elsif ( $ms < 0 ) {
            $ms += 1000000;
            $tm--;
        }
        $addr = $i->{obj}{$j}{ioa} + 65536 * $i->{obj}{$j}{ioa2};

        $result{$type}->{$addr} = [ $value, $tm, $ms ];
        &DEBUG( 8, "ioa: ", $addr, ", val: ", $value, " time: ",
            scalar localtime($tm), ";" );
    }
    &{ $s->{rcb} }( $self, %result );
}

sub send_asdu_type_0_44 {
    my ( $data, $cnt );
    my $self  = shift;
    my $sid   = shift;
    my $cause = shift;
    my $id    = shift;
    my $d     = shift;
    my $ca    = $self->{sids}{$sid}{ca};

    &DEBUG( 3, "send_asdu_type_0_44(): send ", scalar( keys %{$d} ),
        " row(s)" );
    foreach my $key ( keys %{$d} ) {
        $cnt++;
        if ( $id == 30 ) {
            $data .= pack( "SC2",
                ( $key % 65536 ),
                int( $key / 65536 ),
                $d->{$key}->[0] & 1 )
              . &time_2_cp56_2a( $d->{$key}->[1], $d->{$key}->[2] );
        }
        elsif ( $id == 35 ) {
            $data .= pack( "SCSC",
                ( $key % 65536 ),
                int( $key / 65536 ),
                $d->{$key}->[0], 0 )
              . &time_2_cp56_2a( $d->{$key}->[1], $d->{$key}->[2] );
        }
        elsif ( $id == 36 ) {
            $data .= pack( "SCfC",
                ( $key % 65536 ),
                int( $key / 65536 ),
                $d->{$key}->[0], 0 )
              . &time_2_cp56_2a( $d->{$key}->[1], $d->{$key}->[2] );
        }
        elsif ( $id == 37 ) {
            $data .= pack( "SCLC",
                ( $key % 65536 ),
                int( $key / 65536 ),
                $d->{$key}->[0], 0 )
              . &time_2_cp56_2a( $d->{$key}->[1], $d->{$key}->[2] );
        }
        &DEBUG(
            5,               "$cnt|--> IOA:",
            $key,            ", VALUE:",
            $d->{$key}->[0], ", TIME:",
            $d->{$key}->[1], " size of pack: ",
            length($data)
        );
        if ( length($data) >= $MAX_ASDU_SIZE - 6 - 3 - $asdu_type{$id}{size} ) {
            $self->frame_i_send( $sid,
                pack( "C2S2", $id, $cnt, $cause, $ca ) . $data );
            $cnt  = 0;
            $data = "";
        }
    }
    if ($data) {
        $self->frame_i_send( $sid,
            pack( "C2S2", $id, $cnt, $cause, $ca ) . $data );
    }
}

1;

__END__

=head1 NAME

Net::IEC104 - Perl implementation of IEC 60870-5-104 standard (server and client)

=head1 SYNOPSIS

    use Net::IEC104;
    use Time::HiRes;

    sub send_all_data {
        my $self = shift;
        my %DATA = (TI=>{},TS=>{},TII=>{});

        $DATA{TI}->{1}  = [12.34,gettimeofday]; # Tele Information (real value of physical measurement)
        $DATA{TS}->{2}  = [0,gettimeofday];     # Tele Signalization (boolean value)
        $DATA{TII}->{3} = [34567,gettimeofday]; # Tele Information Integral (32-bit counter)

        return %DATA;
    }

    my $srvr_sock = Net::IEC104->new(
        type=>"slave",
        ip=>"127.0.0.1",
        port=>"2404",
        write_callback=>\&send_all_data
    );

    $srvr_sock->listen;
    Net::IEC104::main_loop;

=head1 DESCRIPTION

This module implement IEC 60870-5-104 standard (also known as IEC 870-5-104).
IEC 870-5-104 is a network access for IEC 60870-5-101 using standard transport profiles (TCP/IP),
its application layer is based on IEC 60870-5-101. IEC 60870-5-104 enables communication between
control station and substation via a standard TCP/IP network. The TCP protocol is used for
connection-oriented secure data transmission.

Current implementation supports only ASDU NN 30,35,36,37,100,103. Its enough for now.

=head2 CONSTRUCTOR

Net::IEC104->new(...) accept following variables:

* type - type of station, must be one of "slave" (controlled station) or "master" (control station). Default "slave"

* ip   - ip address to listen on (for slave) or connect to (for master). Default "0.0.0.0"

* port - port of connection. Default 2404

* ca   - common address. Default 1

* write_callback - (slave only) ref to callback function, that returns a list with two vars: reference to class and hash with data. Hash format is as following: %HASH = ("TI" =>  { address=>[value,timestamp,microseconds], ... },"TS" => { address=>[value,timestamp,microseconds], ... },"TII" => { address=>[value,timestamp,microseconds], ... }); This function called when slave receive common interogation request from master (ASDU=100).

* read_callback - (master only) ref to callback function, that receive a list (same format as for write_callback)

* w    - W constant (default  8)

* k    - K constant (default 12)

* ts_func_num  - (slave only) ASDU number used for TS data,  default 30. If 0 - TS  never send

* ti_func_num  - (slave only) ASDU number used for TI data,  default 36. If 0 - TI  never send

* tii_func_num - (slave only) ASDU number used for TII data, default 37. If 0 - TII never send

* t0   - t0 timeout constant (30 sec)

* t1   - t1 timeout constant (15 sec)

* t2   - t2 timeout constant (10 sec)

* t3   - t3 timeout constant (20 sec)

* persist - (master only) 0 - do not reconnect after disconection, 1 - reconnect after disconnection

=head2 METHODS

connect()   - master only method. Connect to slave. After succeful connection, its activate transmission (STARTDT)
    and send common interogation request to slave (ASDU=100).

listen()    - slave only method. Start listen for masters connections.

send(CA,%HASH) - slave only method. Send spontaneous data to all masters connected to server with common address CA. %HASH format same as for write_callback function.

main_loop() - start event cycle. ( stub that call Lib::Event::even_mainloop() )

=head2 EXPORT

None by default.

=head1 EXAMPLES

=head2 client

    use Net::IEC104;

    # Print to stdout all received data;
    sub take_data_cb {
        my $self = shift;
        my %hash = @_;
        foreach my $key (keys %hash) {
            print $key,"\n";
            foreach my $addr (keys %{$hash{$key}}) {
                print "\t";
                print "address:\t",      $addr, "\n\t";
                print "value:\t",        $hash{$key}->{$addr}->[0], "\n\t";
                print "seconds:\t",      $hash{$key}->{$addr}->[1], "\n";
                print "microseconds:\t", $hash{$key}->{$addr}->[2], "\n";
            }
        
    }

    my $master = Net::IEC104->new(
                type => "master",
                ip   => 127.0.0.1,
                port => 2404,
                ca   => 1,
                w    => 8,
                k    => 12,
                persist => 1,
                read_callback => \&take_data_cb,
    );
  
    $master->connect();
    Net::IEC104::main_loop();

=head1 SEE ALSO

Idea and design of implementation of library based on OpenMRTS project (http://sourceforge.net/projects/mrts/) written by Sitkarev Grigoriy.

=head1 AUTHOR

Vladimir Lettiev, E<lt>thecrux@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008-2011 by Vladimir Lettiev

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
