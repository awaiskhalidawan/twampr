mod twamp_defs;
mod twamp_client;

use std::env;
use std::net::Ipv4Addr;
use twamp_defs::*;
use twamp_client::{connect_to_server, request_tw_session, start_session, stop_session};

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
        println!("TWAMP server mode is not implemented yet. Will be available soon. ");
    } else {
        panic!("Invalid mode. Use -h for help ... ");
    }
}
