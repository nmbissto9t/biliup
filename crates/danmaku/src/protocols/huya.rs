//! Huya live danmaku protocol implementation.
//!
//! Huya uses TARS binary protocol over WebSocket:
//! - Registration: WSUserInfo wrapped in WebSocketCommand (iCmdType=1)
//! - Messages: WebSocketCommand with iCmdType=7 for push messages
//! - Danmaku messages have message type 1400
 
use std::time::Duration;
 
use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use tracing::debug;
 
use crate::codec::tars::{TarsInputStream, TarsOutputStream};
use crate::error::{DanmakuError, Result};
use crate::message::{ChatMessage, DEFAULT_COLOR, DanmakuEvent};
use crate::protocols::{
    ConnectionInfo, DecodeResult, HeartbeatConfig, Platform, PlatformContext, RegistrationData,
};
 
/// WebSocket URL for Huya danmaku.
const WSS_URL: &str = "wss://cdnws.api.huya.com/";
 
/// User agent for Huya requests.
const USER_AGENT_STRING: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
 
/// WebSocket command types.
#[allow(dead_code)]
mod cmd_type {
    pub const REGISTER_REQ: i32 = 1;
    pub const REGISTER_RSP: i32 = 2;
    pub const HEARTBEAT: i32 = 5;
    pub const HEARTBEAT_ACK: i32 = 6;
    pub const MSG_PUSH_REQ: i32 = 7;
}
 
/// Heartbeat packet (pre-encoded TARS).
const HEARTBEAT: &[u8] = &[
    0x00, 0x03, 0x1d, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x69, 0x10, 0x03, 0x2c, 0x3c, 0x4c, 0x56,
    0x08, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x75, 0x69, 0x66, 0x0f, 0x4f, 0x6e, 0x55, 0x73, 0x65,
    0x72, 0x48, 0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61, 0x74, 0x7d, 0x00, 0x00, 0x3c, 0x08, 0x00,
    0x01, 0x06, 0x04, 0x74, 0x52, 0x65, 0x71, 0x1d, 0x00, 0x00, 0x2f, 0x0a, 0x0a, 0x0c, 0x16, 0x00,
    0x26, 0x00, 0x36, 0x07, 0x61, 0x64, 0x72, 0x5f, 0x77, 0x61, 0x70, 0x46, 0x00, 0x0b, 0x12, 0x03,
    0xae, 0xf0, 0x0f, 0x22, 0x03, 0xae, 0xf0, 0x0f, 0x3c, 0x42, 0x6d, 0x52, 0x02, 0x60, 0x5c, 0x60,
    0x01, 0x7c, 0x82, 0x00, 0x0b, 0xb0, 0x1f, 0x9c, 0xac, 0x0b, 0x8c, 0x98, 0x0c, 0xa8, 0x0c, 0x20,
];
 
/// Convert Huya's `iFontColor` into an RGB integer.
///
/// Huya sends `-1` (or `0`) for ordinary danmaku that has no custom color, so any
/// non-positive value falls back to the default white. Real colors are plain
/// 0xRRGGBB integers; the high byte is masked off to stay within 24 bits.
fn normalize_font_color(value: i64) -> u32 {
    if value <= 0 {
        DEFAULT_COLOR
    } else {
        (value & 0x00FF_FFFF) as u32
    }
}
 
/// Huya live danmaku protocol.
pub struct Huya {
    client: reqwest::Client,
}
 
impl Huya {
    /// Create a new Huya protocol handler.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
 
    /// Build default headers.
    fn default_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_STRING));
        headers
    }
 
    /// Extract room ID from URL.
    fn extract_room_id(url: &str) -> Option<String> {
        // https://www.huya.com/123456 or https://huya.com/roomname
        let re = Regex::new(r"huya\.com/([^/?]+)").ok()?;
        re.captures(url)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }
 
    /// Get UID from room page.
    async fn get_room_uid(&self, room_id: &str) -> Result<u64> {
        let url = format!("https://www.huya.com/{}", room_id);
        let headers = Self::default_headers();
 
        let resp = self
            .client
            .get(&url)
            .headers(headers)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .text()
            .await?;
 
        // Extract UID from page: "uid":"123456" or "uid":123456
        let re = Regex::new(r#"uid['"]*:\s*['"]*(\d+)['"]*"#)
            .map_err(|e| DanmakuError::Decode(e.to_string()))?;
 
        re.captures(&resp)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u64>().ok())
            .ok_or_else(|| DanmakuError::Decode("Failed to extract UID from Huya page".to_string()))
    }
 
    /// Build WSUserInfo TARS structure.
    fn build_ws_user_info(uid: u64) -> Vec<u8> {
        let mut oos = TarsOutputStream::new();
 
        // WSUserInfo fields:
        // 0: lUid (int64)
        // 1: bAnonymous (bool)
        // 2: sGuid (string)
        // 3: sToken (string)
        // 4: lTid (int64)
        // 5: lSid (int64)
        // 6: lGroupId (int64)
        // 7: lGroupType (int64)
 
        oos.write_int64(0, uid as i64);
        oos.write_bool(1, false); // Not anonymous
        oos.write_string(2, ""); // sGuid
        oos.write_string(3, ""); // sToken
        oos.write_int64(4, 0); // lTid
        oos.write_int64(5, 0); // lSid
        oos.write_int64(6, uid as i64); // lGroupId = uid
        oos.write_int64(7, 3); // lGroupType = 3
 
        oos.get_buffer().to_vec()
    }
 
    /// Build WebSocketCommand TARS structure.
    fn build_ws_command(cmd_type: i32, data: &[u8]) -> Vec<u8> {
        let mut oos = TarsOutputStream::new();
 
        // WebSocketCommand fields:
        // 0: iCmdType (int32)
        // 1: vData (bytes)
 
        oos.write_int32(0, cmd_type);
        oos.write_bytes(1, data);
 
        oos.get_buffer().to_vec()
    }
 
    /// Parse a WebSocket message.
    fn parse_message(data: &[u8]) -> Vec<DanmakuEvent> {
        let mut events = Vec::new();
 
        // Parse WebSocketCommand
        let mut ios = TarsInputStream::new(data);
 
        let cmd_type = ios.read_int32(0).unwrap_or(0);
 
        if cmd_type == cmd_type::MSG_PUSH_REQ {
            // Read vData (bytes at tag 1)
            if let Some(inner_data) = ios.read_bytes(1) {
                // Parse inner message
                let mut inner_ios = TarsInputStream::new(&inner_data);
 
                // Check message type at tag 1
                let msg_type = inner_ios.read_int64(1).unwrap_or(0);
 
                if msg_type == 1400 {
                    // Danmaku message - read message body at tag 2
                    if let Some(msg_data) = inner_ios.read_bytes(2) {
                        if let Some(event) = Self::parse_danmaku(&msg_data) {
                            events.push(event);
                        }
                    }
                } else {
                    // 临时抓包：除弹幕外的消息（礼物、进场等）还没有解析，原样记下来。
                    // 只有打开 raw 时才会写进 XML 的 <o> 里；用来摸清礼物包的格式。
                    let body = inner_ios.read_bytes(2).unwrap_or_default();
                    events.push(DanmakuEvent::Other {
                        raw_data: format_raw_frame(msg_type, &body),
                    });
                }
            }
        } else if cmd_type == cmd_type::REGISTER_RSP {
            debug!("Huya register response received");
        } else if cmd_type == cmd_type::HEARTBEAT_ACK {
            debug!("Huya heartbeat ack received");
        }
 
        events
    }
 
    /// Parse a danmaku message.
    fn parse_danmaku(data: &[u8]) -> Option<DanmakuEvent> {
        let mut ios = TarsInputStream::new(data);
 
        // MessageNotice:
        //   tag 0: sender struct, nickname at inner tag 2
        //   tag 1: lTid (int64)
        //   tag 2: lSid (int64)  —— 旧实现把这个当成用户名来读
        //   tag 3: sContent
        let name = ios
            .read_struct(0, |user| user.read_string(2).unwrap_or_default())
            .unwrap_or_default();
        let content = ios.read_string(3).unwrap_or_default();
 
        //   tag 6: BulletFormat struct, inner tag 0 = iFontColor
        let color = ios
            .read_struct(6, |fmt| fmt.read_int64(0))
            .flatten()
            .map(normalize_font_color)
            .unwrap_or(DEFAULT_COLOR);
 
        if content.is_empty() {
            return None;
        }
 
        let mut chat = ChatMessage::new(content).with_color(color);
        if !name.is_empty() {
            chat = chat.with_name(name);
        }
 
        Some(DanmakuEvent::Chat(chat))
    }
}
 
/// 临时抓包用：把一条还没解析的消息记成一行文本
/// `huya type=<消息类型> len=<字节数> strings=<能读出的文字> hex=<十六进制>`。
fn format_raw_frame(msg_type: i64, body: &[u8]) -> String {
    const MAX_BYTES: usize = 2048;
    let shown = &body[..body.len().min(MAX_BYTES)];
    let hex: String = shown.iter().map(|b| format!("{b:02x}")).collect();
    let more = if body.len() > MAX_BYTES { "..." } else { "" };
 
    // 顺便把里面能读出来的文字（昵称、礼物名等）抽出来，方便一眼看出是什么消息
    let text: String = String::from_utf8_lossy(shown)
        .chars()
        .map(|c| if c.is_control() || c == '\u{FFFD}' { '\u{1}' } else { c })
        .collect();
    let strings: Vec<&str> = text
        .split('\u{1}')
        .filter(|t| t.chars().count() >= 2)
        .collect();
 
    format!(
        "huya type={msg_type} len={} strings=[{}] hex={hex}{more}",
        body.len(),
        strings.join(" | ")
    )
}
 
impl Default for Huya {
    fn default() -> Self {
        Self::new()
    }
}
 
#[async_trait]
impl Platform for Huya {
    fn name(&self) -> &'static str {
        "Huya"
    }
 
    async fn get_connection_info(
        &self,
        url: &str,
        context: &PlatformContext,
    ) -> Result<ConnectionInfo> {
        // Get room ID
        let room_id = if let Some(ref id) = context.room_id {
            id.clone()
        } else {
            Self::extract_room_id(url)
                .ok_or_else(|| DanmakuError::Decode("Invalid Huya URL".to_string()))?
        };
 
        // Get UID from room page
        let uid = self.get_room_uid(&room_id).await?;
        debug!("Huya room UID: {}", uid);
 
        // Build registration packet
        let user_info = Self::build_ws_user_info(uid);
        let reg_packet = Self::build_ws_command(cmd_type::REGISTER_REQ, &user_info);
 
        Ok(ConnectionInfo::new(WSS_URL)
            .with_registration(vec![RegistrationData::Binary(reg_packet)])
            .with_headers(Self::default_headers()))
    }
 
    fn heartbeat_config(&self) -> HeartbeatConfig {
        HeartbeatConfig::binary(HEARTBEAT.to_vec(), Duration::from_secs(60))
    }
 
    fn decode_message(&self, msg: &[u8]) -> Result<DecodeResult> {
        let events = Self::parse_message(msg);
        Ok(DecodeResult::with_events(events))
    }
}
 
#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::tars::{TarsInputStream, TarsOutputStream};
    use crate::message::DanmakuEvent;
 
    #[test]
    fn test_extract_room_id() {
        assert_eq!(
            Huya::extract_room_id("https://www.huya.com/123456"),
            Some("123456".to_string())
        );
        assert_eq!(
            Huya::extract_room_id("https://huya.com/kpl"),
            Some("kpl".to_string())
        );
    }
 
    #[test]
    fn test_build_ws_user_info() {
        let data = Huya::build_ws_user_info(12345);
        assert!(!data.is_empty());
 
        // Verify structure
        let mut ios = TarsInputStream::new(&data);
        assert_eq!(ios.read_int64(0), Some(12345));
    }
 
    #[test]
    fn test_build_ws_command() {
        let user_info = Huya::build_ws_user_info(12345);
        let cmd = Huya::build_ws_command(cmd_type::REGISTER_REQ, &user_info);
 
        assert!(!cmd.is_empty());
 
        // Verify structure
        let mut ios = TarsInputStream::new(&cmd);
        assert_eq!(ios.read_int32(0), Some(cmd_type::REGISTER_REQ));
    }
 
    fn encode_message_notice(nick: &str, sid: i64, content: &str) -> Vec<u8> {
        let mut oos = TarsOutputStream::new();
        oos.write_struct_begin(0);
        oos.write_int64(0, 42);
        oos.write_string(2, nick);
        oos.write_struct_end();
        oos.write_int64(1, 1);
        oos.write_int64(2, sid);
        oos.write_string(3, content);
        oos.get_buffer().to_vec()
    }
 
    #[test]
    fn parse_danmaku_reads_nested_nick_when_sid_nonzero() {
        let data = encode_message_notice("nickname", 99, "hello danmaku");
        let event = Huya::parse_danmaku(&data).expect("danmaku");
        match event {
            DanmakuEvent::Chat(chat) => {
                assert_eq!(chat.name.as_deref(), Some("nickname"));
                assert_eq!(chat.content, "hello danmaku");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
 
    /// Same layout as the real frames: sender (0), tid (1), sid (2), content (3),
    /// then optionally the BulletFormat struct at tag 6 with iFontColor at inner tag 0.
    fn encode_with_font_color(content: &str, font_color: Option<i64>) -> Vec<u8> {
        let mut oos = TarsOutputStream::new();
        oos.write_struct_begin(0);
        oos.write_int64(0, 42);
        oos.write_string(2, "nick");
        oos.write_struct_end();
        oos.write_int64(1, 1);
        oos.write_int64(2, 0);
        oos.write_string(3, content);
        // a tag-4 / tag-5 pair sits between content and the format struct in real frames
        oos.write_int64(4, 0);
        oos.write_struct_begin(5);
        oos.write_int64(0, 8150354);
        oos.write_int64(3, 16731238);
        oos.write_struct_end();
        if let Some(color) = font_color {
            oos.write_struct_begin(6);
            oos.write_int64(0, color);
            oos.write_int64(1, 4);
            oos.write_struct_end();
        }
        oos.get_buffer().to_vec()
    }
 
    fn chat_color(data: &[u8]) -> u32 {
        match Huya::parse_danmaku(data).expect("danmaku") {
            DanmakuEvent::Chat(chat) => chat.color,
            other => panic!("unexpected {other:?}"),
        }
    }
 
    #[test]
    fn parse_danmaku_reads_font_color() {
        // values taken from real Huya frames
        assert_eq!(chat_color(&encode_with_font_color("a", Some(1751616))), 1751616);
        assert_eq!(chat_color(&encode_with_font_color("a", Some(16763904))), 16763904);
        assert_eq!(chat_color(&encode_with_font_color("a", Some(15673460))), 15673460);
    }
 
    #[test]
    fn parse_danmaku_defaults_to_white_without_font_color() {
        // -1 / 0 mean "no custom color"; a missing struct must not break parsing either
        assert_eq!(chat_color(&encode_with_font_color("a", Some(-1))), DEFAULT_COLOR);
        assert_eq!(chat_color(&encode_with_font_color("a", Some(0))), DEFAULT_COLOR);
        assert_eq!(chat_color(&encode_with_font_color("a", None)), DEFAULT_COLOR);
    }
 
    #[test]
    fn normalize_font_color_masks_to_rgb() {
        assert_eq!(normalize_font_color(0x01FF_CC00), 0x00FF_CC00);
        assert_eq!(normalize_font_color(-5), DEFAULT_COLOR);
    }
 
    #[test]
    fn parse_danmaku_reads_content_when_sid_is_zero() {
        let data = encode_message_notice("alice", 0, "zero sid");
        let event = Huya::parse_danmaku(&data).expect("danmaku");
        match event {
            DanmakuEvent::Chat(chat) => {
                assert_eq!(chat.name.as_deref(), Some("alice"));
                assert_eq!(chat.content, "zero sid");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
 
    fn encode_push(msg_type: i64, body: &[u8]) -> Vec<u8> {
        let mut inner = TarsOutputStream::new();
        inner.write_int64(1, msg_type);
        inner.write_bytes(2, body);
        let mut outer = TarsOutputStream::new();
        outer.write_int32(0, cmd_type::MSG_PUSH_REQ);
        outer.write_bytes(1, inner.get_buffer());
        outer.get_buffer().to_vec()
    }
 
    #[test]
    fn non_danmaku_messages_are_kept_as_raw_frames() {
        let events = Huya::parse_message(&encode_push(6501, "送礼人Bob\u{1}小礼物".as_bytes()));
        assert_eq!(events.len(), 1);
        match &events[0] {
            DanmakuEvent::Other { raw_data } => {
                assert!(raw_data.starts_with("huya type=6501 len="), "{raw_data}");
                assert!(raw_data.contains("送礼人Bob"), "{raw_data}");
                assert!(raw_data.contains("hex=e980"), "{raw_data}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
 
    #[test]
    fn danmaku_messages_are_not_duplicated_as_raw_frames() {
        let body = encode_message_notice("alice", 0, "hi");
        let events = Huya::parse_message(&encode_push(1400, &body));
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], DanmakuEvent::Chat(_)));
    }
 
    #[test]
    fn raw_frame_truncates_long_bodies() {
        let body = vec![0xAB; 5000];
        let line = format_raw_frame(1, &body);
        assert!(line.contains("len=5000"));
        assert!(line.ends_with("..."));
    }
}
