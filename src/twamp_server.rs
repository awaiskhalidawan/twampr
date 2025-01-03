use crate::twamp_defs::*;
use std::io::prelude::*;

pub fn handle_client(control_request: &mut ControlRequest, buffer: &mut [u8; 1024], server_start_time: &TwampTime) -> Result<(), String>{
    match control_request.state {
        ControlRequestState::Undefined => {
            return Err("Undefined control request state.".to_string());
        },
        ControlRequestState::ConnectionInvalid => (),
        ControlRequestState::RequestReceived => {
            // Send the greeting message to client.
            let mut server_greeting_message = TwampMessageServerGreeting {
                unused: [0; 12],
                modes: [0; 4],
                challenge: [0; 16],
                salt: [0; 16],
                count: (1 << 12),
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
                        accept: 0,
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
                    return Err(format!("Unable to read client greeting message. Error: {} ... ", e));
                }
            }
        },
        ControlRequestState::ControlConnectionSetupComplete => ()
    };

    Ok(())
}