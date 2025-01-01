use std::mem;

pub const TWAMP_CONTROL_MODE_UNAUTHENTICATED: u8 = 0x01;
pub const TWAMP_CONTROL_MODE_AUTHENTICATED: u8 = 0x02;
pub const TWAMP_CONTROL_MODE_ENCRYPTED: u8 = 0x04;
pub const TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_REQUEST_SESSION: u8 = 0x05;
pub const TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_START_SESSION: u8 = 0x02;
pub const TWAMP_CONTROL_PROTOCOL_PACKET_TYPE_STOP_SESSION: u8 = 0x03;
pub const SESSION_SENDER_LOCAL_PORT: u16 = 7400;
pub const SESSION_SENDER_REMOTE_PORT: u16 = 7400;

pub const TWAMP_MIN_TEST_PACKET_SIZE: u16 = 50;       // Twamp min test packet size.
pub const TWAMP_MAX_TEST_PACKET_SIZE: u16 = 2000;     // Twamp max test packet size.
pub const MAX_NUMBER_OF_PACKETS_TO_TEST: u16 = 100;   // Max number of packets to be used in test.
pub const MAX_INTERPACKET_INTERVAL: u16 = 100;        // Interpacket interval in milliseconds.

pub const TWAMP_TEST_PACKET_RX_WAIT_TIME_MS: u16 = 5000;   // Waiting for test packets to be received in milliseconds.

#[derive(Debug)]
pub struct GreetingMessage {
    unused: [u8; 12],
    pub modes: [u8; 4],
    challange: [u8; 16],
    salt: [u8; 16],
    count: u32,
    mbz: [u8; 12]
}

impl GreetingMessage {    
    // Method to parse bytes into GreetingMessage
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < mem::size_of::<GreetingMessage>() {
            return Err("Invalid bytes array length. ".to_string());
        }

        Ok(Self {
            unused: bytes[0..12].try_into().unwrap(),
            modes: bytes[12..16].try_into().unwrap(),
            challange: bytes[16..32].try_into().unwrap(),
            salt: bytes[32..48].try_into().unwrap(),
            count: u32::from_be_bytes(bytes[48..52].try_into().unwrap()),
            mbz: bytes[52..64].try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub struct TwampMessageSetupResponse {
    pub mode: [u8; 4],
    pub key_id: [u8; 80],
    pub token: [u8; 64],
    pub client_iv: [u8; 16]
}

impl TwampMessageSetupResponse {
    // Method to convert TwampMessageSetupResponse into a byte array.
    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<TwampMessageSetupResponse>()] {
        let mut bytes = [0u8; std::mem::size_of::<TwampMessageSetupResponse>()];
        bytes[0..4].copy_from_slice(&self.mode);
        bytes[4..84].copy_from_slice(&self.key_id);
        bytes[84..148].copy_from_slice(&self.token);
        bytes[148..164].copy_from_slice(&self.client_iv);
        bytes
    }
}

#[derive(Debug)]
pub struct TwampTime {
    pub seconds: u32,
    pub fraction: u32
}

impl TwampTime {
    pub fn get_current_time_twamp_format() -> Self {
        let now = chrono::Utc::now();
        let seconds: u32 = (now.timestamp() as u32) + (2208988800 as u32);
        let fraction: u32 = (((now.timestamp_subsec_nanos() as f32) / (1000000000 as f32)) * (u32::MAX as f32)) as u32;
        Self {
            seconds,
            fraction
        }
    }

    pub fn create_instance(seconds: u32, fraction: u32) -> Self {
        Self {
            seconds,
            fraction
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&self.seconds.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.fraction.to_be_bytes());
        bytes
    }

    pub fn convert_twamp_time_to_epoch_time(&self) -> i64 {
        if self.seconds < 2208988800 {
            return 0;
        }

        let mut res: i64 = (self.seconds - 2208988800) as i64 * 1000;           // Convert seconds to milliseconds.
        res += ((self.fraction as f32 / u32::MAX as f32) * 1000 as f32) as i64; // Convert fraction to milliseconds.
        res
    }
}

#[derive(Debug)]
pub struct TwampMessageServerStart {
    pub mbz: [u8; 15],
    pub accept: u8,
    pub server_iv: [u8; 16],
    pub start_time: TwampTime,
    pub mbz_: [u8; 8]
}

impl TwampMessageServerStart {    
    // Method to parse bytes into TwampMessageServerStart
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < mem::size_of::<TwampMessageServerStart>() {
            return Err("Invalid bytes array length. ".to_string());
        }

        Ok(Self {
            mbz: bytes[0..15].try_into().unwrap(),
            accept: bytes[15],
            server_iv: bytes[16..32].try_into().unwrap(),
            start_time: TwampTime {
                seconds: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
                fraction: u32::from_be_bytes(bytes[36..40].try_into().unwrap())
            },
            mbz_: bytes[40..48].try_into().unwrap(),
        })
    }
}

pub struct TwampMessageRequestSession {
    pub first_octet: u8,
    pub ipvn_mbz: u8,
    pub conf_sender: u8,
    pub conf_receiver: u8,
    pub schedule_slots: u32,
    pub packets: u32,
    pub sender_port: u16,
    pub receiver_port: u16,
    pub sender_address: [u32; 4],
    pub receiver_address: [u32; 4],
    pub sid: [u8; 16],
    pub padding_length: u32,
    pub start_time: TwampTime,
    pub timeout: TwampTime,
    pub type_p_descriptor: u32,
    pub mbz_: [u8; 8],
    pub hwmac: [u8; 16]
}

impl TwampMessageRequestSession {
    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<TwampMessageRequestSession>()] {
        let mut bytes = [0u8; std::mem::size_of::<TwampMessageRequestSession>()];
        bytes[0] = self.first_octet;
        bytes[1] = self.ipvn_mbz;
        bytes[2] = self.conf_sender;
        bytes[3] = self.conf_receiver;
        bytes[4..8].copy_from_slice(&self.schedule_slots.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.packets.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.sender_port.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.receiver_port.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.sender_address[0].to_be_bytes());
        bytes[20..24].copy_from_slice(&self.sender_address[1].to_be_bytes());
        bytes[24..28].copy_from_slice(&self.sender_address[2].to_be_bytes());
        bytes[28..32].copy_from_slice(&self.sender_address[3].to_be_bytes());
        bytes[32..36].copy_from_slice(&self.receiver_address[0].to_be_bytes());
        bytes[36..40].copy_from_slice(&self.receiver_address[1].to_be_bytes());
        bytes[40..44].copy_from_slice(&self.receiver_address[2].to_be_bytes());
        bytes[44..48].copy_from_slice(&self.receiver_address[3].to_be_bytes());
        bytes[48..64].copy_from_slice(&self.sid);
        bytes[64..68].copy_from_slice(&self.padding_length.to_be_bytes());
        bytes[68..76].copy_from_slice(&self.start_time.to_bytes());
        bytes[76..84].copy_from_slice(&self.timeout.to_bytes());
        bytes[84..88].copy_from_slice(&self.type_p_descriptor.to_be_bytes());
        bytes[88..96].copy_from_slice(&self.mbz_);
        bytes[96..112].copy_from_slice(&self.hwmac);
        bytes
    }
}


pub struct TwampMessageAcceptSession {
    pub accept: u8,
    mbz: u8,
    pub port: u16,
    pub sid: [u8; 16],
    mbz_: [u8; 12],
    hwmac: [u8; 16]
}

impl TwampMessageAcceptSession {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < mem::size_of::<TwampMessageAcceptSession>() {
            return Err("Invalid bytes array length. ".to_string());
        }

        Ok(Self {
            accept: bytes[0],
            mbz: bytes[1],
            port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            sid: bytes[4..20].try_into().unwrap(),
            mbz_: bytes[20..32].try_into().unwrap(),
            hwmac: bytes[32..48].try_into().unwrap()
        })
    }
}

pub struct TwampMessageStartSessions {
    pub first_octet: u8,
    pub mbz: [u8; 15],
    pub hwmac: [u8; 16]
}

impl TwampMessageStartSessions {
    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<TwampMessageStartSessions>()] {
        let mut bytes = [0u8; std::mem::size_of::<TwampMessageStartSessions>()];
        bytes[0] = self.first_octet;
        bytes[1..16].copy_from_slice(&self.mbz);
        bytes[16..32].copy_from_slice(&self.hwmac);
        bytes
    }
}


pub struct TwampMessageStartAck {
    pub accept: u8,
    mbz: [u8; 15],
    hwmac: [u8; 16]
}

impl TwampMessageStartAck {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < mem::size_of::<TwampMessageStartAck>() {
            return Err("Invalid bytes array length. ".to_string());
        }

        Ok(Self {
            accept: bytes[0],
            mbz: bytes[1..16].try_into().unwrap(),
            hwmac: bytes[16..32].try_into().unwrap()
        })
    }
}


pub struct TwampMessageStopSessions {
    pub first_octet: u8,
    pub accept: u8,
    pub mbz: [u8; 2],
    pub number_of_sessions: u32,
    pub mbz_: [u8; 8],
    pub hwmac: [u8; 16]
}

impl TwampMessageStopSessions {
    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<TwampMessageStopSessions>()] {
        let mut bytes = [0u8; std::mem::size_of::<TwampMessageStopSessions>()];
        bytes[0] = self.first_octet;
        bytes[1] = self.accept;
        bytes[2..4].copy_from_slice(&self.mbz);
        bytes[4..8].copy_from_slice(&self.number_of_sessions.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.mbz_);
        bytes[16..32].copy_from_slice(&self.hwmac);
        bytes
    }
}

pub struct TwampTestResult {
    pub min_dlt: f64,
    pub max_dlt: f64,
    pub avg_dlt: f64,
    pub std_dev_dlt: f64,
    pub min_upt: f64,
    pub max_upt: f64,
    pub avg_upt: f64,
    pub std_dev_upt: f64,
    pub min_rtt: f64,
    pub max_rtt: f64,
    pub avg_rtt: f64,
    pub std_dev: f64,
    pub avg_jitter: f64,
    pub min_jitter: f64,
    pub max_jitter: f64,
    pub received_packets: i32,
    pub total_packets: i32,
    pub test_packet_size: i32,
    pub rtt_vals: Vec<f64>,
    pub dlt_vals: Vec<f64>,
    pub upt_vals: Vec<f64>,
    pub test_timestamp: String
}


#[derive(Debug)]
pub struct TwampMessageErrorEstimate {
    s_z_scale: u8,
    multiplier: u8
}

impl TwampMessageErrorEstimate {
    pub fn create_instance(s_z_scale: u8, multiplier: u8) -> Self {
        Self {
            s_z_scale,
            multiplier
        }
    }

    pub fn to_bytes(&self) -> [u8; std::mem::size_of::<TwampMessageErrorEstimate>()] {
        let mut bytes = [0u8; std::mem::size_of::<TwampMessageErrorEstimate>()];
        bytes[0] = self.s_z_scale;
        bytes[1] = self.multiplier;
        bytes
    }
}

pub struct TwampMessageTest {
    pub sequence_number: u32,
    pub timestamp: TwampTime,
    pub error_estimate: TwampMessageErrorEstimate
}

impl TwampMessageTest {
    pub fn to_bytes(&self, bytes: &mut [u8; TWAMP_MAX_TEST_PACKET_SIZE as usize]) {
        bytes[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.timestamp.to_bytes());
        bytes[12..14].copy_from_slice(&self.error_estimate.to_bytes());
    }
}

#[derive(Debug)]
pub struct TwampMessageReflector {
    pub sequence_number: u32,
    pub timestamp: TwampTime,
    pub error_estimate: TwampMessageErrorEstimate,
    mbz: [u8; 2],
    pub receive_timestamp: TwampTime,
    pub sender_sequence_number: u32,
    pub sender_timestamp: TwampTime,
    pub sender_error_estimate: TwampMessageErrorEstimate,
    mbz_: [u8; 2],
    pub sender_ttl: u8
}

impl TwampMessageReflector {
    pub fn from_bytes (bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < mem::size_of::<TwampMessageReflector>() {
            return Err("Invalid bytes array length. ".to_string());
        }

        Ok(Self {
            sequence_number: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            timestamp: TwampTime::create_instance(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), u32::from_be_bytes(bytes[8..12].try_into().unwrap())),
            error_estimate: TwampMessageErrorEstimate::create_instance(bytes[12], bytes[13]),
            mbz: bytes[14..16].try_into().unwrap(),
            receive_timestamp: TwampTime::create_instance(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), u32::from_be_bytes(bytes[20..24].try_into().unwrap())),
            sender_sequence_number: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
            sender_timestamp: TwampTime::create_instance(u32::from_be_bytes(bytes[28..32].try_into().unwrap()), u32::from_be_bytes(bytes[32..36].try_into().unwrap())),
            sender_error_estimate: TwampMessageErrorEstimate::create_instance(bytes[36], bytes[37]),
            mbz_: bytes[38..40].try_into().unwrap(),
            sender_ttl: bytes[40]
        })
    } 
}

#[derive(Copy, Debug, Clone)]
pub struct TwampTestPacketStats {
    pub sequence_number: i64,
    pub uplink_time: i64,
    pub downlink_time: i64,
    pub round_trip_time: i64,
    pub reflector_delay: i64,
}

impl TwampTestPacketStats {
    pub fn default() -> Self {
        Self {
            sequence_number: -1,
            uplink_time: 0,
            downlink_time: 0,
            round_trip_time: 0,
            reflector_delay: 0
        }
    }
}