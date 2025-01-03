use crate::twamp_defs::*;
use chrono::Utc;
use std::io::prelude::*;
use std::mem;
use std::net::Ipv4Addr;
use std::net::TcpStream;
use std::time::Duration;

pub fn connect_to_server(
    twamp_server_ip: String,
    twamp_server_port: u16,
) -> Result<TcpStream, String> {
    // Creating a TCP connection to TWAMP Server.
    let socket = TcpStream::connect((twamp_server_ip, twamp_server_port));

    // Perfrom match expression on socket result. Return the error if socket is not connected. Otherwise move forward.
    let mut socket = match socket {
        Ok(socket) => socket,
        Err(e) => return Err(format!("Failed to connect to TWAMP Server: {}", e)),
    };

    // Receive a message from the TWAMP Server with a timeout of 500 ms.
    let mut read_buffer: [u8; 1024] = [0; 1024];

    // Set the timeout of 500 ms.
    let res = socket.set_read_timeout(Some(Duration::from_millis(500)));

    // Perform match expression on set_read_timeout result. Return the error if timeout is not set. Otherwise move forward.
    match res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to set read timeout on the tcp socket: {}",
                e
            ))
        }
    }

    // Wait for 50 ms before reading the data from socket.
    std::thread::sleep(Duration::from_millis(50));

    // Read the data from the socket.
    let bytes_received = socket
        .read(&mut read_buffer)
        .expect("Failed to read data from the TWAMP Server ... ");

    // The bytes received must be equal to TwampMessageServerGreeting size.
    if bytes_received != mem::size_of::<TwampMessageServerGreeting>() {
        return Err(
            "Invalid Greeting Message size received from the TWAMP Server ... ".to_string(),
        );
    }

    // Read the data into TwampMessageServerGreeting struct.
    let greeting_message =
    TwampMessageServerGreeting::from_bytes(&read_buffer).expect("Failed to parse server greeting message ... ");

    println!(
        "Server Greeting message received from TWAMP Server: {:?}",
        greeting_message
    );

    // Create a TwampMessageSetupResponse message and send it over the socket.
    let mut twamp_message_setup_response = TwampMessageSetupResponse {
        mode: [0; 4],
        key_id: [0; 80],
        token: [0; 64],
        client_iv: [0; 16],
    };

    // Copy the mode from greeting_message to twamp_message_setup_response.
    twamp_message_setup_response
        .mode
        .copy_from_slice(&greeting_message.modes);

    // Convert the twamp_message_setup_response to byte array and send it to TWAMP Server.
    let twamp_message_setup_response_bytes = twamp_message_setup_response.to_bytes();

    // Send the TwampMessageSetupResponse to the TWAMP Server.
    let res = socket.write(&twamp_message_setup_response_bytes);

    // Perform match expression on write result. Return the error if write fails. Otherwise move forward.
    match res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to send TwampMessageSetupResponse to the TWAMP Server: {}",
                e
            ))
        }
    };

    // Wait for 50 ms before reading the data from socket.
    std::thread::sleep(Duration::from_millis(50));

    // Read the data from the socket.
    let bytes_received = socket
        .read(&mut read_buffer)
        .expect("Failed to read data from the TWAMP Server ... ");

    if bytes_received != mem::size_of::<TwampMessageServerStart>() {
        return Err(
            "Invalid TwampMessageServerStart size received from the TWAMP Server ... ".to_string(),
        );
    }

    let twamp_message_server_start = TwampMessageServerStart::from_bytes(&read_buffer)
        .expect("Failed to parse TwampMessageServerStart ... ");

    if twamp_message_server_start.accept != 0 {
        return Err("Invalid accept value in TwampMessageServerStart ... ".to_string());
    }

    println!("Connection successful with TWAMP Server ... ");
    Ok(socket)
}

pub fn request_tw_session(tcp_stream: &mut TcpStream, local_ip: &Ipv4Addr) -> Result<u16, String> {
    // Check if tcp stream is connected.
    if !tcp_stream.peer_addr().is_ok() {
        return Err("TCP Stream is not connected ... ".to_string());
    }

    // Create a TwampMessageRequestSession message and send it to TWAMP server.
    let twamp_message_request_session = TwampMessageRequestSession {
        first_octet: TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_REQUEST_SESSION,
        ipvn_mbz: 0,
        conf_sender: 0,
        conf_receiver: 0,
        schedule_slots: 0,
        packets: 0,
        sender_port: SESSION_SENDER_LOCAL_PORT,
        receiver_port: SESSION_SENDER_REMOTE_PORT,
        sender_address: [local_ip.to_bits(), 0, 0, 0],
        receiver_address: [0; 4],
        sid: [0; 16],
        padding_length: 0,
        start_time: TwampTime::get_current_time_twamp_format(),
        timeout: TwampTime::create_instance(0, 0),
        type_p_descriptor: 0,
        mbz_: [0; 8],
        hwmac: [0; 16],
    };

    // Convert the twamp_message_request_session to byte array and send it to TWAMP Server.
    let twamp_message_request_session_bytes = twamp_message_request_session.to_bytes();

    // Send the TwampMessageRequestSession to the TWAMP Server.
    let res = tcp_stream.write(&twamp_message_request_session_bytes);

    // Perform match expression on write result. Return the error if write fails. Otherwise move forward.
    match res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to send TwampMessageRequestSession to the TWAMP Server: {}",
                e
            ))
        }
    };

    // Wait for 50 ms before reading the data from socket.
    std::thread::sleep(Duration::from_millis(50));

    // Read the data from the socket.
    let mut read_buffer: [u8; 1024] = [0; 1024];
    let bytes_received = tcp_stream
        .read(&mut read_buffer)
        .expect("Failed to read data from the TWAMP Server ... ");

    // Check if the bytes received are equal to TwampMessageAcceptSession size.
    if bytes_received != mem::size_of::<TwampMessageAcceptSession>() {
        return Err(
            "Invalid TwampMessageAcceptSession size received from the TWAMP Server ... "
                .to_string(),
        );
    }

    // Parse the TwampMessageAcceptSession from the bytes received.
    let twamp_message_accept_session = TwampMessageAcceptSession::from_bytes(&read_buffer)
        .expect("Failed to parse TwampMessageAcceptSession ... ");

    // Check if the TWAMP server accepted the session request.
    if twamp_message_accept_session.accept != 0 {
        return Err("TWAMP server rejected Request TW session command ... ".to_string());
    }

    // Print SID received from TWAMP server.
    let sid = String::from_utf8(twamp_message_accept_session.sid.to_vec())
        .expect("Failed to convert SID to string ... ");
    println!("Received SID from TWAMP Server: {sid}");

    Ok(twamp_message_accept_session.port)
}

pub fn start_session(
    tcp_stream: &mut TcpStream,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
    number_of_packets: u16,
    packet_size: u16,
    interpacket_interval: u16,
) -> Result<(), String> {
    // Check if tcp stream is connected.
    if !tcp_stream.peer_addr().is_ok() {
        return Err("TCP Stream is not connected ... ".to_string());
    }

    // Create TwampMessageStartSession message and send it to TWAMP server.
    let twamp_message_start_sessions = TwampMessageStartSessions {
        first_octet: TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_START_SESSION,
        mbz: [0; 15],
        hwmac: [0; 16],
    };

    // Convert the twamp_message_start_sessions to byte array and send it to TWAMP Server.
    let twamp_message_start_sessions_bytes = twamp_message_start_sessions.to_bytes();

    // Send the TwampMessageStartSessions to the TWAMP Server.
    let res = tcp_stream.write(&twamp_message_start_sessions_bytes);

    // Perform match expression on write result. Return the error if write fails. Otherwise move forward.
    match res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to send TwampMessageStartSessions to the TWAMP Server: {}",
                e
            ))
        }
    };

    // Wait for 50 ms before reading the data from socket.
    std::thread::sleep(Duration::from_millis(50));

    // Read the data from the socket.
    let mut read_buffer: [u8; 1024] = [0; 1024];
    let bytes_received = tcp_stream
        .read(&mut read_buffer)
        .expect("Failed to read data from the TWAMP Server ... ");

    // Check if the bytes received are equal to TwampMessageStartAck size.
    if bytes_received != mem::size_of::<TwampMessageStartAck>() {
        return Err(
            "Invalid TwampMessageStartAck size received from the TWAMP Server ... ".to_string(),
        );
    }

    // Parse the TwampMessageStartAck from the bytes received.
    let twamp_message_start_ack = TwampMessageStartAck::from_bytes(&read_buffer)
        .expect("Failed to parse TwampMessageStartAck ... ");

    // Check if the TWAMP server accepted the session start request.
    if twamp_message_start_ack.accept != 0 {
        return Err("TWAMP server rejected Start session request ... ".to_string());
    }

    // Print the Start Session Acknowledgement received from TWAMP server.
    println!("Received Start Session Acknowledgement from TWAMP Server ... ");

    let start_test_res = start_test(
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        number_of_packets,
        packet_size,
        interpacket_interval,
    );
    match start_test_res {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to start the TWAMP test: {}", e)),
    }

    Ok(())
}

pub fn stop_session(tcp_stream: &mut TcpStream) -> Result<(), String> {
    // Check if tcp stream is connected.
    if !tcp_stream.peer_addr().is_ok() {
        return Err("TCP Stream is not connected ... ".to_string());
    }

    let twamp_message_stop_sessions = TwampMessageStopSessions {
        first_octet: TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_STOP_SESSION,
        accept: 0,
        mbz: [0; 2],
        number_of_sessions: 1,
        mbz_: [0; 8],
        hwmac: [0; 16],
    };

    // Convert the twamp_message_stop_sessions to byte array and send it to TWAMP Server.
    let twamp_message_stop_sessions_bytes = twamp_message_stop_sessions.to_bytes();

    // Send the TwampMessageStopSessions to the TWAMP Server.
    let res = tcp_stream.write(&twamp_message_stop_sessions_bytes);

    // Perform match expression on write result. Return the error if write fails. Otherwise move forward.
    match res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to send TwampMessageStopSessions to the TWAMP Server: {}",
                e
            ))
        }
    };

    println!("Sent Stop Session request to the TWAMP Server ... ");

    Ok(())
}

fn receive_test_packet(
    udp_socket: &std::net::UdpSocket,
    rx_bytes: &mut [u8; TWAMP_MAX_TEST_PACKET_SIZE as usize],
    test_start_time: i64,
    twamp_test_packet_stats: &mut [TwampTestPacketStats; MAX_NUMBER_OF_PACKETS_TO_TEST as usize],
) -> Result<(), String> {
    // Try to receive the packet from the TWAMP server. (session reflector).
    let res = udp_socket.recv_from(rx_bytes);
    match res {
        Ok(_) => (),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                return Err(format!(
                    "Failed to receive test packet from the TWAMP Server: {}",
                    e
                ));
            }
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
        }
    }

    // Timestamp the received packet as soon as it is received.
    let session_sender_rx_timestamp = Utc::now().timestamp_millis();

    let twamp_message_reflector_res = TwampMessageReflector::from_bytes(rx_bytes);
    match twamp_message_reflector_res {
        Ok(_) => (),
        Err(e) => {
            return Err(format!(
                "Failed to parse received TWAMP test message: {}",
                e
            ))
        }
    }

    let twamp_message_reflector = twamp_message_reflector_res.unwrap();
    //println!("Received TWAMP test packet from the TWAMP Server: {:?}", twamp_message_reflector);

    let session_sender_tx_timestamp = twamp_message_reflector
        .sender_timestamp
        .convert_twamp_time_to_epoch_time();
    let session_reflector_rx_timestamp = twamp_message_reflector
        .receive_timestamp
        .convert_twamp_time_to_epoch_time();
    let session_reflector_tx_timestamp = twamp_message_reflector
        .timestamp
        .convert_twamp_time_to_epoch_time();

    if session_sender_tx_timestamp < test_start_time {
        return Err(format!("Received test packet sender time stamp is less then test start time. Test start time: {} Received session sender tx time stamp: {}", test_start_time, session_sender_tx_timestamp));
    }

    let uplink_time = session_reflector_rx_timestamp - session_sender_tx_timestamp;
    let downlink_time = session_sender_rx_timestamp - session_reflector_tx_timestamp;
    let reflector_delay = session_reflector_tx_timestamp - session_reflector_rx_timestamp;
    let round_trip_time =
        (session_sender_rx_timestamp - session_sender_tx_timestamp) - reflector_delay;

    println!(
        "Packet Sequence Number: {}",
        twamp_message_reflector.sequence_number
    );
    println!("- Uplink Time: {} milliseconds", uplink_time);
    println!("- Downlink Time: {} milliseconds", downlink_time);
    println!("- Round Trip Time: {} milliseconds", round_trip_time);
    println!("- Reflector Delay: {} milliseconds", reflector_delay);
    println!("");

    let twamp_test_packet_stat = TwampTestPacketStats {
        sequence_number: twamp_message_reflector.sequence_number as i64,
        uplink_time: uplink_time,
        downlink_time: downlink_time,
        round_trip_time: round_trip_time,
        reflector_delay: reflector_delay,
    };

    if twamp_message_reflector.sequence_number < MAX_NUMBER_OF_PACKETS_TO_TEST as u32 {
        twamp_test_packet_stats[twamp_message_reflector.sequence_number as usize] =
            twamp_test_packet_stat;
    }

    Ok(())
}

fn start_test(
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
    number_of_packets: u16,
    packet_size: u16,
    interpacket_interval: u16,
) -> Result<(), String> {
    // Create a UDP socket to send the test packets.
    let res = std::net::UdpSocket::bind((local_ip, local_port));
    match res {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to bind UDP socket: {}", e)),
    }

    let udp_socket = res.unwrap();

    // Set UDP socket as non-blocking.
    let res = udp_socket.set_nonblocking(true);
    match res {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to set UDP socket as non-blocking: {}", e)),
    }

    // Start packet transmission/reception.
    let mut tx_bytes: [u8; TWAMP_MAX_TEST_PACKET_SIZE as usize] =
        [0; TWAMP_MAX_TEST_PACKET_SIZE as usize];
    let mut rx_bytes: [u8; TWAMP_MAX_TEST_PACKET_SIZE as usize] =
        [0; TWAMP_MAX_TEST_PACKET_SIZE as usize];

    let test_start_time = Utc::now().timestamp_millis();
    let mut t0 = Utc::now().timestamp_millis() + interpacket_interval as i64;
    let mut t1 = 0;

    let mut twamp_test_packet_stats: [TwampTestPacketStats;
        MAX_NUMBER_OF_PACKETS_TO_TEST as usize] =
        [TwampTestPacketStats::default(); MAX_NUMBER_OF_PACKETS_TO_TEST as usize];

    for i in 0..number_of_packets {
        let twamp_message_test = TwampMessageTest {
            sequence_number: i as u32,
            error_estimate: TwampMessageErrorEstimate::create_instance(0xBF, 0xFF),
            timestamp: TwampTime::get_current_time_twamp_format(),
        };

        // Copy the twamp_message_test structure to tx_bytes array.
        twamp_message_test.to_bytes(&mut tx_bytes);

        // Send the twamp test packet to the TWAMP server (session reflector).
        let res = udp_socket.send_to(&tx_bytes[0..packet_size as usize], (remote_ip, remote_port));
        match res {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "Failed to send test packet to the TWAMP Server: {}",
                    e
                ))
            }
        }

        loop {
            // Receive the test packet from the TWAMP server (session reflector).
            let res = receive_test_packet(
                &udp_socket,
                &mut rx_bytes,
                test_start_time,
                &mut twamp_test_packet_stats,
            );
            match res {
                Ok(_) => (),
                Err(e) => return Err(format!("{}", e)),
            }

            t1 = Utc::now().timestamp_millis();
            std::thread::sleep(Duration::from_micros(10));
            if t1 >= t0 {
                break;
            }
        }

        t0 = t0 + interpacket_interval as i64;
    }

    println!(
        "All test packets sent to the TWAMP Server. Waiting for the remaining Rx test packets ... "
    );

    // Receive the remaining TWAMP test packets.
    t0 = Utc::now().timestamp_millis() + TWAMP_TEST_PACKET_RX_WAIT_TIME_MS as i64;
    loop {
        // Receive the test packet from the TWAMP server (session reflector).
        let res = receive_test_packet(
            &udp_socket,
            &mut rx_bytes,
            test_start_time,
            &mut twamp_test_packet_stats,
        );
        match res {
            Ok(_) => (),
            Err(e) => return Err(format!("{}", e)),
        }

        t1 = Utc::now().timestamp_millis();
        std::thread::sleep(Duration::from_micros(10));
        if t1 >= t0 {
            break;
        }
    }

    // Calculate the test statistics.
    let mut test_packets_received: u32 = 0;
    let mut max_round_trip_time: i64 = i64::MIN;
    let mut max_uplink_time: i64 = i64::MIN;
    let mut max_downlink_time: i64 = i64::MIN;
    let mut max_reflector_delay: i64 = i64::MIN;
    let mut min_round_trip_time: i64 = i64::MAX;
    let mut min_uplink_time: i64 = i64::MAX;
    let mut min_downlink_time: i64 = i64::MAX;
    let mut min_reflector_delay: i64 = i64::MAX;

    for i in 0..number_of_packets {
        if twamp_test_packet_stats[i as usize].sequence_number >= 0 {
            test_packets_received += 1;

            if twamp_test_packet_stats[i as usize].round_trip_time > max_round_trip_time {
                max_round_trip_time = twamp_test_packet_stats[i as usize].round_trip_time;
            }

            if twamp_test_packet_stats[i as usize].uplink_time > max_uplink_time {
                max_uplink_time = twamp_test_packet_stats[i as usize].uplink_time;
            }

            if twamp_test_packet_stats[i as usize].downlink_time > max_downlink_time {
                max_downlink_time = twamp_test_packet_stats[i as usize].downlink_time;
            }

            if twamp_test_packet_stats[i as usize].reflector_delay > max_reflector_delay {
                max_reflector_delay = twamp_test_packet_stats[i as usize].reflector_delay;
            }

            if twamp_test_packet_stats[i as usize].round_trip_time < min_round_trip_time {
                min_round_trip_time = twamp_test_packet_stats[i as usize].round_trip_time;
            }

            if twamp_test_packet_stats[i as usize].uplink_time < min_uplink_time {
                min_uplink_time = twamp_test_packet_stats[i as usize].uplink_time;
            }

            if twamp_test_packet_stats[i as usize].downlink_time < min_downlink_time {
                min_downlink_time = twamp_test_packet_stats[i as usize].downlink_time;
            }

            if twamp_test_packet_stats[i as usize].reflector_delay < min_reflector_delay {
                min_reflector_delay = twamp_test_packet_stats[i as usize].reflector_delay;
            }
        }
    }

    println!("TWAMP test completed ...");
    println!("-------------- Results --------------");
    println!("Total number of test packets sent: {}", number_of_packets);
    println!(
        "Total number of test packets received: {}",
        test_packets_received
    );
    println!("Max Round Trip Time: {} ms", max_round_trip_time);
    println!("Max Uplink Time: {} ms", max_uplink_time);
    println!("Max Downlink Time: {} ms", max_downlink_time);
    println!("Max Reflector Delay: {} ms", max_reflector_delay);
    println!("Min Round Trip Time: {} ms", min_round_trip_time);
    println!("Min Uplink Time: {} ms", min_uplink_time);
    println!("Min Downlink Time: {} ms", min_downlink_time);
    println!("Min Reflector Delay: {} ms", min_reflector_delay);
    println!("-------------------------------------");

    Ok(())
}
