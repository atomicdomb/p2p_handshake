//Little and Big Endian conversion helper functions - These are fairly standard
pub fn parse_frombytes_be<'a, T>(buff: &Vec<u8>) -> Result<(T, Vec<u8>), std::io::Error>
where
    T: FromEndian + Sized,
{
    let size = core::mem::size_of::<T>();
    match read_drop_slice(buff, size) {
        Ok((res, remaining)) => Ok((FromEndian::from_be(&res), remaining)),
        Err(e) => Err(e),
    }
}
pub fn parse_frombytes_le<'a, T>(buff: &Vec<u8>) -> Result<(T, Vec<u8>), std::io::Error>
where
    T: FromEndian + Sized,
{
    let size = core::mem::size_of::<T>();
    match read_drop_slice(buff, size) {
        Ok((res, remaining)) => Ok((FromEndian::from_le(&res), remaining)),
        Err(e) => Err(e),
    }
}
pub fn read_drop_slice(buff: &Vec<u8>, size: usize) -> Result<(&[u8], Vec<u8>), std::io::Error> {
    if buff.len() >= size {
        Ok((&buff[0..size], buff[size..].to_vec()))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Buffer too small",
        ))
    }
}

pub trait FromEndian {
    fn from_be(msg: &[u8]) -> Self
    where
        Self: Sized;
    fn from_le(msg: &[u8]) -> Self
    where
        Self: Sized;
}
impl FromEndian for i32 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        i32::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        i32::from_le_bytes(bytes)
    }
}
impl FromEndian for i64 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        i64::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        i64::from_le_bytes(bytes)
    }
}
impl FromEndian for u16 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(msg);
        u16::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(msg);
        u16::from_le_bytes(bytes)
    }
}
impl FromEndian for u32 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        u32::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        u32::from_le_bytes(bytes)
    }
}
impl FromEndian for u64 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        u64::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        u64::from_le_bytes(bytes)
    }
}