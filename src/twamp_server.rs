use crate::twamp_defs::*;
use std::io::{prelude::*, ErrorKind};
use rand::Rng;

pub fn handle_client(control_request: &mut ControlRequest, buffer: &mut [u8; 1024], server_start_time: &TwampTime) -> Result<(), String>{
    match control_request.state {
        ControlRequestState::Undefined => {
            return Err("Undefined control request state.".to_string());
        },
        ControlRequestState::ConnectionInvalid => {
            return Err(format!("The client is in connection invalid state. It should have been removed from the list already. "));
        },
        ControlRequestState::RequestReceived => {
            // Send the greeting message to client.
            let mut server_greeting_message = TwampMessageServerGreeting {
                unused: [0; 12],
                modes: [0; 4],
                challenge: [0; 16],
                salt: [0; 16],
                count: 4096,
                mbz: [0; 12]
            };

            server_greeting_message.modes[3] = control_request.twamp_control_mode as u8;

            let res = server_greeting_message.to_bytes(buffer);
            if res.is_err() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Unable to convert TWAMP server greeting message to bytes: {}", res.err().unwrap()));
            }

            let write_size = res.ok().unwrap();

            let res = control_request.tcp_stream.write(&buffer[0..write_size]);

            if res.is_err() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Unable to send TWAMP server greeting message to client. Error: {}", res.err().unwrap()));
            }

            control_request.state = ControlRequestState::GreetingMessageSent;
            println!("TWAMP server greeting message sent to client ...");
        },
        ControlRequestState::GreetingMessageSent => {
            // Try to receive the response from client.
            let res = control_request.tcp_stream.read(buffer);
            if res.is_err() {
                let err = res.err().unwrap();
                if err.kind() != ErrorKind::WouldBlock {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to read TWAMP setup response message. Error: {}", err));
                }
                return Ok(());
            }

            let bytes_received = res.ok().unwrap();
            if bytes_received == 0 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Zero bytes received from client for TWAMP setup response message. "));
            }

            if bytes_received != std::mem::size_of::<TwampMessageSetupResponse>() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Invalid TWAMP setup response message size received from client. "));
            }

            let res = TwampMessageSetupResponse::from_bytes(buffer);
            if res.is_err() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Unable to convert TWAMP setup response message from received bytes. Error: {}", res.err().unwrap()));
            }

            let setup_response_message = res.ok().unwrap();
            if setup_response_message.mode[3] & 0x07 == 0x00 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Client is not willing to communicate further. Invalidating connection ..."));
            }

            if setup_response_message.mode[3] & 0x07 != control_request.twamp_control_mode as u8 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Received mode in TWAMP setup response message is not equal to the mode sent by server in TWAMP greeting message. "));
            }

            let twamp_message_server_start = TwampMessageServerStart {
                mbz: [0; 15],
                accept: AcceptValue::Ok as u8,
                server_iv: [0; 16],
                start_time: TwampTime::create_instance(server_start_time.seconds, server_start_time.fraction),
                mbz_: [0; 8]
            };

            let res = twamp_message_server_start.to_bytes(buffer);
            if res.is_err() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Unable to convert TWAMP server start message to bytes: {}", res.err().unwrap()));
            }

            let write_size = res.ok().unwrap();

            let res = control_request.tcp_stream.write(&buffer[0..write_size]);
            if res.is_err() {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Unable to send TWAMP server start message to client. Error: {}", res.err().unwrap()));
            }
            
            control_request.state = ControlRequestState::ControlConnectionSetupComplete;
            println!("TWAMP server start message sent to client ...");
        },
        ControlRequestState::ControlConnectionSetupComplete => {
            // Try to receive the response from client.
            let res = control_request.tcp_stream.read(buffer);            
            if res.is_err() {
                let err = res.err().unwrap();
                if err.kind() != ErrorKind::WouldBlock {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to read TWAMP session control (request/start/stop) message. Error: {} ... ", err));
                }
                return Ok(());
            }

            let bytes_received = res.ok().unwrap();
            if bytes_received == 0 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Zero bytes received from client for TWAMP session control (request/start/stop) message. "));
            }

            let first_octet = buffer[0];
            
            if first_octet == TwampControlPacketType::RequestSession as u8 {
                // Request session message received.
                if bytes_received != std::mem::size_of::<TwampMessageRequestSession>() {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Invalid TWAMP request session message size received from the client ... "));
                }

                let res = TwampMessageRequestSession::from_bytes(buffer);
                if res.is_err() {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to convert TWAMP request session message from received bytes. Error: {} ", res.err().unwrap()));
                }

                let twamp_message_request_session = res.unwrap();
                if twamp_message_request_session.packets != 0 {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Number of packets must be zero in TWAMP request session message. Packets: {}", twamp_message_request_session.packets));
                }

                // Generate SID for this session. (Format: {epoch_time_ms}_{two_digit_random_number})
                let random_number = rand::thread_rng().gen_range(1..100);
                let sid = format!("{}_{}", chrono::Utc::now().timestamp_millis().to_string(), random_number.to_string());
                println!("Generated SID: {}", sid);

                // Create test session.
                let receiver_port = 1234 as u16;
                
                // Send accept session message to client.
                let mut accept_session_message = TwampMessageAcceptSession {
                    accept: 0,
                    mbz: 0,
                    port: receiver_port,
                    sid: [0; 16],
                    mbz_: [0; 12],
                    hwmac: [0; 16]
                };

                if receiver_port == 0 {
                    accept_session_message.accept = AcceptValue::TemporaryResourceLimitations as u8;                    
                } else {
                    accept_session_message.accept = AcceptValue::Ok as u8;
                    accept_session_message.sid[0..sid.len()].copy_from_slice(sid.as_bytes());
                }

                let res = accept_session_message.to_bytes(buffer);
                if res.is_err() {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to convert TWAMP accept session message to bytes: {}", res.err().unwrap()));
                }

                let write_size = res.ok().unwrap();
                let res = control_request.tcp_stream.write(&buffer[0..write_size]);

                if res.is_err() {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to send TWAMP accept session message client. Error: {}", res.err().unwrap()));
                }

                println!("TWAMP accept session message sent to client ... ");
            } else if first_octet == TwampControlPacketType::StartSession as u8 {

            } else if first_octet == TwampControlPacketType::StopSession as u8 {
                
            } else {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Invalid Twamp control packet type received: {}", first_octet));
            }
        }
    };

    Ok(())
}