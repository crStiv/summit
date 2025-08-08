use alloy_primitives::Address;

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionRequest {
    // EIP-6110
    Deposit(DepositRequest),
    // EIP-7002
    Withdrawal(WithdrawalRequest),
}

impl TryFrom<&[u8]> for ExecutionRequest {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err("ExecutionRequest cannot be empty");
        }

        // Use the leading byte to determine request type
        // See: https://docs.rs/alloy/latest/alloy/eips/eip7685/struct.Requests.html
        match bytes[0] {
            0x00 => {
                // Deposit request - parse without the leading type byte
                let deposit = DepositRequest::try_from(&bytes[1..])?;
                Ok(ExecutionRequest::Deposit(deposit))
            }
            0x01 => {
                // Withdrawal request - parse without the leading type byte
                let withdrawal = WithdrawalRequest::try_from(&bytes[1..])?;
                Ok(ExecutionRequest::Withdrawal(withdrawal))
            }
            _request_type => {
                Err("Unknown execution request type")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawalRequest {
    pub source_address: Address,            // Address that initiated the withdrawal
    pub validator_pubkey: [u8; 48],         // Validator BLS public key
    pub amount: u64,                        // Amount in gwei
}

impl TryFrom<&[u8]> for WithdrawalRequest {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // EIP-7002: Withdrawal request data is exactly 76 bytes (without leading type byte)
        // Format: source_address(20) + validator_pubkey(48) + amount(8) = 76 bytes

        if bytes.len() != 76 {
            return Err("WithdrawalRequest must be exactly 76 bytes");
        }

        // Extract source_address (20 bytes)
        let source_address_bytes: [u8; 20] = bytes[0..20].try_into()
            .map_err(|_| "Failed to parse source_address")?;
        let source_address = Address::from(source_address_bytes);

        // Extract validator_pubkey (48 bytes)
        let validator_pubkey: [u8; 48] = bytes[20..68].try_into()
            .map_err(|_| "Failed to parse validator_pubkey")?;

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[68..76].try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        Ok(WithdrawalRequest {
            source_address,
            validator_pubkey,
            amount,
        })
    }
}

// https://eth2book.info/latest/part2/deposits-withdrawals/withdrawal-processing/
#[derive(Debug, Clone, PartialEq)]
pub struct DepositRequest {
    pub pubkey: [u8; 48],                   // Validator BLS public key
    pub withdrawal_credentials: [u8; 32],   // Either hash of the BLS pubkey, or Ethereum address
    pub amount: u64,                        // Amount in gwei
    pub signature: [u8; 96],                // BLS signature
    pub index: u64,                         // Deposit index
}

impl TryFrom<&[u8]> for DepositRequest {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // EIP-6110: Deposit request data is exactly 192 bytes (without leading type byte)
        // Format: pubkey(48) + withdrawal_credentials(32) + amount(8) + signature(96) + index(8) = 192 bytes

        if bytes.len() != 192 {
            return Err("DepositRequest must be exactly 192 bytes");
        }

        // Extract pubkey (48 bytes)
        let pubkey: [u8; 48] = bytes[0..48].try_into()
            .map_err(|_| "Failed to parse pubkey")?;

        // Extract withdrawal_credentials (32 bytes)
        let withdrawal_credentials: [u8; 32] = bytes[48..80].try_into()
            .map_err(|_| "Failed to parse withdrawal_credentials")?;

        // Extract amount (8 bytes, little-endian u64)
        let amount_bytes: [u8; 8] = bytes[80..88].try_into()
            .map_err(|_| "Failed to parse amount")?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract signature (96 bytes)
        let signature: [u8; 96] = bytes[88..184].try_into()
            .map_err(|_| "Failed to parse signature")?;

        // Extract index (8 bytes, little-endian u64)
        let index_bytes: [u8; 8] = bytes[184..192].try_into()
            .map_err(|_| "Failed to parse index")?;
        let index = u64::from_le_bytes(index_bytes);

        Ok(DepositRequest {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            index,
        })
    }
}