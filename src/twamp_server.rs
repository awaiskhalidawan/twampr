use crate::twamp_defs::*;
use std::io::prelude::*;
use rand::Rng;

pub fn handle_client(control_request: &mut ControlRequest, buffer: &mut [u8; 1024], server_start_time: &TwampTime) -> Result<(), String>{
    match control_request.state {
        ControlRequestState::Undefined => {
            return Err("Undefined control request state.".to_string());
        },
        ControlRequestState::ConnectionInvalid => {
            return Err(format!("The client in connection invalid should have been removed from the list already. "));
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

            let res = control_request.tcp_stream.write(&server_greeting_message.to_bytes());
            match res {
                Ok(_) => {
                    control_request.state = ControlRequestState::GreetingMessageSent;
                },
                Err(e) => {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to send greeting message to client. Error: {} ... ", e));
                }
            }
        },
        ControlRequestState::GreetingMessageSent => {
            // Try to receive the response from client.
            let res = control_request.tcp_stream.read(buffer);
            match res {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("No response received from client against server greeting message. "));
                    }

                    if bytes_read != std::mem::size_of::<TwampMessageSetupResponse>() {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("Invalid response received from client against server greeting message. "));
                    }

                    let setup_response_message_res = TwampMessageSetupResponse::from_bytes(buffer);
                    if setup_response_message_res.is_err() {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("Unable to parse setup response message."));
                    }

                    let setup_response_message = setup_response_message_res.unwrap();
                    if setup_response_message.mode[3] & 0x07 == 0x00 {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("Client is not willing to communicate further. "));
                    }

                    if setup_response_message.mode[3] & 0x07 != control_request.twamp_control_mode as u8 {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("Received mode is not equal to the mode sent by server in greeting message. "));
                    }

                    let twamp_message_server_start = TwampMessageServerStart {
                        mbz: [0; 15],
                        accept: AcceptValue::Ok as u8,
                        server_iv: [0; 16],
                        start_time: *server_start_time,
                        mbz_: [0; 8]
                    };

                    let res = control_request.tcp_stream.write(&twamp_message_server_start.to_bytes());
                    match res {
                        Ok(_) => {
                            control_request.state = ControlRequestState::ControlConnectionSetupComplete;
                            println!("Control connection setup complete ... ");
                        },
                        Err(e) => {
                            control_request.state = ControlRequestState::ConnectionInvalid;
                            return Err(format!("Unable to send server start message to client. Error: {} ... ", e));
                        }
                    }                    
                },
                Err(e) => {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to read setup response message. Error: {} ... ", e));
                }
            }
        },
        ControlRequestState::ControlConnectionSetupComplete => {
            // Try to receive the response from client.
            let res = control_request.tcp_stream.read(buffer);
            let mut bytes_received: usize = 0;
            match res {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        control_request.state = ControlRequestState::ConnectionInvalid;
                        return Err(format!("No response received from client against server start message. "));
                    }
                    bytes_received = bytes_read;
                },
                Err(e) => {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to read session control message. Error: {} ... ", e));
                }
            }

            let first_octet = buffer[0];
            
            if first_octet == TwampControlPacketType::RequestSession as u8 {
                // Request session message received.
                if bytes_received != std::mem::size_of::<TwampMessageRequestSession>() {
                    return Err(format!("Invalid request session message size received from the TWAMP client ... "));
                }

                let res = TwampMessageRequestSession::from_bytes(buffer);
                match res {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(format!("Unable to create request session message from received bytes. Error: {} ", e));
                    }
                }

                let twamp_message_request_session = res.unwrap();
                if twamp_message_request_session.packets != 0 {
                    return Err(format!("Number of packets must be zero in request session command. Packets: {}", twamp_message_request_session.packets));
                }

                // Generate SID for this session.
                let random_number = rand::thread_rng().gen_range(1..100);
                let sid = format!("{}_{}", chrono::Utc::now().timestamp_millis().to_string(), random_number.to_string());

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
                    return Err(format!("Unable to convert accept session message to bytes: {}", res.err().unwrap()));
                }

                let write_size = res.ok().unwrap();
                let res = control_request.tcp_stream.write(&buffer[0..write_size]);

                match res {
                    Ok(_) => {
                        println!("Accept Session Message sent to client ... ");
                    },
                    Err(e) => {
                        return Err(format!("Unable to send accept session message client. Error: {}", e));
                    }
                }
            } else if first_octet == TwampControlPacketType::StartSession as u8 {

            } else if first_octet == TwampControlPacketType::StopSession as u8 {
                
            } else {
                return Err(format!("Invalid Twamp control packet type received: {}", first_octet));
            }
        }
    };

    Ok(())
}