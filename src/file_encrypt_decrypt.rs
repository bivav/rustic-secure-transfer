use ring::digest;

pub struct EncryptDecrypt {}

impl EncryptDecrypt {
    pub fn get_hash(file_content: &[u8]) -> Vec<u8> {
        let digest_value = digest::digest(&digest::SHA256, file_content);
        digest_value.as_ref().to_vec()
    }

}