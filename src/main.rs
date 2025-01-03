mod twamp_client;
mod twamp_defs;
mod twamp_server;

use std::env;
use std::net::Ipv4Addr;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;
use twamp_client::{connect_to_server, request_tw_session, start_session, stop_session};
use twamp_defs::*;
use twamp_server::handle_client;
use std::sync::mpsc::TryRecvError;

fn main() {
    // Collect the command-line arguments into a vector
    let args: Vec<String> = env::args().collect();

    // Check the number of command-line arguments.
    if args.len() < 2 {
        println!("Usage: twampr -h for help ... ");
        println!("Usage: twampr <mode> <twamp_server_ip> <twamp_server_port> <local_ip> <twamp_test_packet_size> <number_of_twamp_test_packets> <interpacket_interval_ms>");
        return;
    }

    // Parse the arguments.
    let twamp_mode: &str = args[1].as_str();

    if twamp_mode == "-h" {
        println!("------------------------------------------------------------------");
        println!("Usage: twampr <mode> <twamp_server_ip> <twamp_server_port> <local_ip> <twamp_test_packet_size> <number_of_twamp_test_packets> <interpacket_interval_ms>");
        println!("mode: -h for help, -c for client, -s for server");
        println!("twamp_server_ip: IP address of the TWAMP server. ");
        println!("twamp_server_port: Port of the TWAMP server. ");
        println!("local_ip: Local IP address of the client. ");
        println!("twamp_test_packet_size: Size of the TWAMP test packet. ");
        println!("number_of_twamp_test_packets: Number of TWAMP test packets to send. ");
        println!("interpacket_interval_ms: Interpacket interval in milliseconds. ");
        println!("------------------------------------------------------------------");
        return;
    }

    if twamp_mode == "-c" {
        // Check the number of command-line arguments.
        if args.len() != 8 {
            println!("Invalid number of arguments ... ");
            println!("Usage: twampr <mode> <twamp_server_ip> <twamp_server_port> <local_ip> <twamp_test_packet_size> <number_of_twamp_test_packets> <interpacket_interval_ms>");
            return;
        }

        let twamp_server_ip = args[2]
            .parse::<Ipv4Addr>()
            .expect("Invalid Twamp Server IP Address ... ");
        let twamp_server_port = args[3]
            .parse::<u16>()
            .expect("Invalid Twamp Server Port ... ");
        let local_ip = args[4]
            .parse::<Ipv4Addr>()
            .expect("Invalid Local Ip Address ... ");
        let packet_size = args[5].parse::<u16>().expect("Invalid Packet Size ... ");
        let number_of_packets = args[6]
            .parse::<u16>()
            .expect("Invalid Number of Packets ... ");
        let interpacket_interval = args[7]
            .parse::<u16>()
            .expect("Invalid Interpacket Interval ... ");

        // Perform validation on the arguments.
        if packet_size < TWAMP_MIN_TEST_PACKET_SIZE || packet_size > TWAMP_MAX_TEST_PACKET_SIZE {
            panic!(
                "Invalid Packet Size. It must be between {} and {} bytes ... ",
                TWAMP_MIN_TEST_PACKET_SIZE, TWAMP_MAX_TEST_PACKET_SIZE
            );
        }

        if number_of_packets > MAX_NUMBER_OF_PACKETS_TO_TEST {
            panic!(
                "Invalid Number of Packets. It must be less than or equal to {} ... ",
                MAX_NUMBER_OF_PACKETS_TO_TEST
            );
        }

        if interpacket_interval > MAX_INTERPACKET_INTERVAL {
            panic!("Invalid Interpacket Interval. It must be less than or equal to {} milliseconds ... ", MAX_INTERPACKET_INTERVAL);
        }

        // Connect to TWAMP server.
        let connect_to_server_res =
            connect_to_server(twamp_server_ip.to_string(), twamp_server_port);
        match connect_to_server_res {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }

        let mut tcp_stream = connect_to_server_res.unwrap();

        // Request TWAMP session.
        let req_tw_sess_res = request_tw_session(&mut tcp_stream, &local_ip);
        match req_tw_sess_res {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }

        let remote_port = req_tw_sess_res.unwrap();
        println!("TWAMP session request accepted by the TWAMP server ... ");
        println!("Local IP: {:?}", local_ip);
        println!("Local Port: {:?}", SESSION_SENDER_LOCAL_PORT);
        println!("Remote IP: {:?}", twamp_server_ip);
        println!("Remote Port: {:?}", remote_port);

        // Start the TWAMP test.
        let start_session_res = start_session(
            &mut tcp_stream,
            local_ip,
            twamp_server_ip,
            SESSION_SENDER_LOCAL_PORT,
            remote_port,
            number_of_packets,
            packet_size,
            interpacket_interval,
        );
        match start_session_res {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }

        let stop_session_res = stop_session(&mut tcp_stream);
        match stop_session_res {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }

        println!("TWAMP test completed successfully ... ");
    } else if twamp_mode == "-s" {
        // Check the number of command-line arguments.
        if args.len() != 3 {
            println!("Invalid number of arguments ... ");
            println!("Usage: twampr <mode> <local_port>");
            return;
        }

        let local_port = args[2].parse::<u16>().expect("Invalid Local Port ... ");

        // Create a TCP listener on any Ip address and specific port.
        let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), local_port))
            .expect("TWAMP server start failed: Unable to bind to address ... ");

        // Print the server details.
        println!("TWAMP server started on port:{} ... ", local_port);

        // Get the server start time.
        let server_start_time = TwampTime::get_current_time_twamp_format();

        // Create a vector to store the control requests.
        let mut control_requests: Vec<ControlRequest> = Vec::new();

        let (tx, rx) = std::sync::mpsc::channel();

        // Start a thread to handle the incoming connections.
        let tcp_handler = std::thread::spawn(move || {
            
            let mut buffer: [u8; 1024] = [0; 1024];
            loop {
                let res: Result<TcpStream, TryRecvError> = rx.try_recv();
                match res {
                    Ok(stream) => {
                        stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                        let control_request = ControlRequest {
                            tcp_stream: stream,
                            state: ControlRequestState::RequestReceived,
                            twamp_control_mode: TwampControlMode::Unauthenticated,
                        };

                        control_requests.push(control_request);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => (),
                    Err(e) => {
                        // Print the error message.
                        println!(
                            "Unable to receive TCP stream object from main thread. Error: {} ... ",
                            e
                        );
                    }
                }

                for control_request in control_requests.iter_mut() {
                    let res = handle_client(control_request, &mut buffer, &server_start_time);
                    match res {
                        Ok(_) => (),
                        Err(e) => {
                            // Print the error message.
                            println!("Error: {} ... ", e);
                        }
                    }
                }

                // Remove control request from the vector if client connection becomes invalid.
                control_requests.retain(|control_request| {
                    control_request.state != ControlRequestState::ConnectionInvalid
                });

                // Save CPU cycles.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });

        // Accept incoming connections.
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // Print the client details.
                    println!("Client connected from {} ... ", stream.peer_addr().unwrap());

                    let res = tx.send(stream);
                    match res {
                        Ok(_) => (),
                        Err(e) => {
                            // Print the error message.
                            println!("Unable to send TCP stream object to tcp handler thread. Error: {} ... ", e);
                        }
                    }
                }
                Err(e) => {
                    // Print the error message.
                    println!("Error: {} ... ", e);
                }
            }
        }
    } else {
        panic!("Invalid mode. Use -h for help ... ");
    }
}
