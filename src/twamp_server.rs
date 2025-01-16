use crate::twamp_defs::*;
use rand::Rng;
use std::{fmt::{format, write}, io::{prelude::*, ErrorKind}};

pub fn send_twamp_control_message<T: Serialize>(message: &mut T, control_request: &mut ControlRequest,  buffer: &mut [u8]) -> Result<(), String> {
    let res = message.to_bytes(buffer);
    if res.is_err() {
        control_request.state = ControlRequestState::ConnectionInvalid;
        return Err(format!("Unable to serialize TWAMP message: {}", res.err().unwrap()));
    }

    let write_size = res.ok().unwrap();

    let res = control_request.tcp_stream.write(&buffer[0..write_size]);
    if res.is_err() {
        control_request.state = ControlRequestState::ConnectionInvalid;
        return Err(format!("Unable to send TWAMP message to client. Error: {}", res.err().unwrap()));
    }

    let sent_bytes = res.unwrap();
    if sent_bytes != write_size {
        panic!("Unable to send complete TWAMP message to client. Sent bytes: {}  Total bytes: {}", sent_bytes, write_size);
    }

    // Message sent successfully to the client.
    Ok(())
}

pub fn receive_twamp_control_message<T: Deserialize>(control_request: &mut ControlRequest, rx_buffer: &mut [u8]) -> Result<Option<T>, String> {
    // Try to receive a message from client.
    let res = control_request.tcp_stream.read(rx_buffer);
    if res.is_err() {
        let err = res.err().unwrap();
        if err.kind() != ErrorKind::WouldBlock {
            control_request.state = ControlRequestState::ConnectionInvalid;
            return Err(format!("Unable to read data from socket. Error: {}", err));
        }

        // Read timeout has occured. It means that there are no bytes to be received on socket.
        return Ok(Option::None);
    }

    // Some bytes are received. We check that if they are equal to the desired message size.
    let mut bytes_received = res.ok().unwrap();

    control_request.bytes_received += bytes_received;

    // Copy the received bytes into the buffer if the received bytes are less than message size.
    if control_request.bytes_received < std::mem::size_of::<T>() {
        control_request.rx_buffer
            [(control_request.bytes_received - bytes_received)..control_request.bytes_received]
            .copy_from_slice(&rx_buffer[0..bytes_received]);
        control_request.use_rx_buffer = true;

        // Not all the bytes are received yet. Wait for next iteration.
        return Ok(Option::None);
    }

    if control_request.use_rx_buffer {
        control_request.rx_buffer
            [(control_request.bytes_received - bytes_received)..control_request.bytes_received]
            .copy_from_slice(&rx_buffer[0..bytes_received]);
    }

    bytes_received = control_request.bytes_received; 
    control_request.bytes_received = 0;
    control_request.use_rx_buffer = false;

    // Number of received bytes must be equal to the message size.
    if bytes_received != std::mem::size_of::<T>() {
        return Err(format!("Number of received bytes: {} are not equal to message size: {}", 
                            bytes_received,
                            std::mem::size_of::<T>()));
    }

    // Desired message size successfully received. Now select the buffer to be used for deserialization.
    let selected_rx_buffer = if control_request.use_rx_buffer {
        &control_request.rx_buffer[0..control_request.rx_buffer.len()]
    } else {
        &rx_buffer[0..rx_buffer.len()]
    };

    let res = T::from_bytes(selected_rx_buffer);
    if res.is_err() {
        control_request.state = ControlRequestState::ConnectionInvalid;
        return Err(format!("Unable to deserialize TWAMP message. Error: {}", res.err().unwrap()));
    }

    Ok(Option::Some(res.unwrap()))
}

pub fn handle_client(
    control_request: &mut ControlRequest,
    buffer: &mut [u8],
    server_start_time: &TwampTime,
) -> Result<(), String> {
    match control_request.state {
        ControlRequestState::Undefined => {
            return Err("Undefined control request state.".to_string());
        }
        ControlRequestState::ConnectionInvalid => {
            return Err(format!("The client is in connection invalid state. "));
        }
        ControlRequestState::RequestReceived => {
            // Send the greeting message to client.
            let mut server_greeting_message = TwampMessageServerGreeting {
                unused: [0; 12],
                modes: [0; 4],
                challenge: [0; 16],
                salt: [0; 16],
                count: 4096,
                mbz: [0; 12],
            };

            server_greeting_message.modes[3] = control_request.twamp_control_mode as u8;

            let res = send_twamp_control_message(&mut server_greeting_message, control_request, buffer);
            if res.is_err() {
                return Err(format!("{}", res.err().unwrap()));                
            }

            control_request.state = ControlRequestState::GreetingMessageSent;
            println!("TWAMP server greeting message sent to client ...");
        }
        ControlRequestState::GreetingMessageSent => {
            // Try to receive TWAMP message setup response from client.
            let res = receive_twamp_control_message::<TwampMessageSetupResponse>(control_request, buffer);
            if res.is_err() {
                return Err(res.err().unwrap());
            }

            let res = res.unwrap();
            if res.is_none() {
                // No error has occurred but not all the required number of bytes are received. Wait for next iteration.
                return Ok(());
            }

            let setup_response_message = res.unwrap();

            if setup_response_message.mode[3] & 0x07 == 0x00 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!(
                    "Client is not willing to communicate further. Invalidating connection ..."
                ));
            }

            if setup_response_message.mode[3] & 0x07 != control_request.twamp_control_mode as u8 {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!("Received mode in TWAMP setup response message is not equal to the mode sent by server in TWAMP greeting message. "));
            }

            let mut twamp_message_server_start = TwampMessageServerStart {
                mbz: [0; 15],
                accept: AcceptValue::Ok as u8,
                server_iv: [0; 16],
                start_time: TwampTime::create_instance(
                    server_start_time.seconds,
                    server_start_time.fraction,
                ),
                mbz_: [0; 8],
            };

            let res = send_twamp_control_message::<TwampMessageServerStart>(&mut twamp_message_server_start, control_request, buffer);
            if res.is_err() {
                return Err(format!("{}", res.err().unwrap()));
            }

            control_request.state = ControlRequestState::ControlConnectionSetupComplete;
            println!("TWAMP server start message sent to client ...");
        }
        ControlRequestState::ControlConnectionSetupComplete => {
            // Try to receive the response from client.
            let res = control_request.tcp_stream.peek(&mut buffer[0..1]);
            if res.is_err() {
                let err = res.err().unwrap();
                if err.kind() != ErrorKind::WouldBlock {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Unable to peek TWAMP session control code byte from socket. Error: {} ... ", err));
                }
                return Ok(());
            }

            let first_octet = buffer[0];

            if first_octet == TwampControlPacketType::RequestSession as u8 {
                let res = receive_twamp_control_message::<TwampMessageRequestSession>(control_request, buffer);
                if res.is_err() {
                    return Err(res.err().unwrap());
                }
    
                let res = res.unwrap();
                if res.is_none() {
                    // No error has occurred but not all the required number of bytes are received. Wait for next iteration.
                    return Ok(());
                }

                let twamp_message_request_session = res.unwrap();
                if twamp_message_request_session.packets != 0 {
                    control_request.state = ControlRequestState::ConnectionInvalid;
                    return Err(format!("Number of packets must be zero in TWAMP request session message. Packets: {}", twamp_message_request_session.packets));
                }

                // Generate SID for this session. (Format: {epoch_time_ms}_{two_digit_random_number})
                let random_number = rand::thread_rng().gen_range(1..100);
                let sid = format!(
                    "{}_{}",
                    chrono::Utc::now().timestamp_millis().to_string(),
                    random_number.to_string()
                );
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
                    hwmac: [0; 16],
                };

                if receiver_port == 0 {
                    accept_session_message.accept = AcceptValue::TemporaryResourceLimitations as u8;
                } else {
                    accept_session_message.accept = AcceptValue::Ok as u8;
                    accept_session_message.sid[0..sid.len()].copy_from_slice(sid.as_bytes());
                }

                let res = send_twamp_control_message(&mut accept_session_message, control_request, buffer);
                if res.is_err() {
                    return Err(format!("{}", res.err().unwrap()));
                }

                println!("TWAMP accept session message sent to client ... ");
            } else if first_octet == TwampControlPacketType::StartSession as u8 {
                let res = receive_twamp_control_message::<TwampMessageStartSessions>(control_request, buffer);
                if res.is_err() {
                    return Err(res.err().unwrap());
                }
    
                let res = res.unwrap();
                if res.is_none() {
                    // No error has occurred but not all the required number of bytes are received. Wait for next iteration.
                    return Ok(());
                }

                // Send message start ack to client.
                let mut twamp_message_start_ack = TwampMessageStartAck {
                    accept: AcceptValue::Ok as u8,
                    mbz: [0; 15],
                    hwmac: [0; 16],
                };

                let res = send_twamp_control_message(&mut twamp_message_start_ack, control_request, buffer);
                if res.is_err() {
                    return Err(format!("{}", res.err().unwrap()));                
                }

                println!("TWAMP message start ack sent to client ... ");
            } else if first_octet == TwampControlPacketType::StopSession as u8 {
                let res = receive_twamp_control_message::<TwampMessageStopSessions>(control_request, buffer);
                if res.is_err() {
                    return Err(res.err().unwrap());
                }
    
                let res = res.unwrap();
                if res.is_none() {
                    // No error has occurred but not all the required number of bytes are received. Wait for next iteration.
                    return Ok(());
                }

                let res = res.unwrap();
                
                // Remove test session. Compare test session count as well.
            } else {
                control_request.state = ControlRequestState::ConnectionInvalid;
                return Err(format!(
                    "Invalid Twamp control packet type received: {}",
                    first_octet
                ));
            }
        }
    };

    Ok(())
}
