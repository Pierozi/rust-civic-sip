use std::fmt;

pub struct CivicError {
    pub code: usize,
    pub message: String,
}

impl fmt::Display for CivicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err_msg = match self.code {
            1 => "UNKNOWN error",

            100_400 => "CIVIC backend request incorrect 400",
            100_401 => "CIVIC backend Unauthorized",
            100_403 => "CIVIC backend Forbidden",
            100_404 => "CIVIC backend server not found",
            100_500 => "CIVIC backend server error",

            200_100 => "JWT Signature fail",
            200_101 => "JWT Bad Signature",

            200_200 => "AES decryption error",

            _ => "Sorry, something is wrong! Please Try Again!",
        };

        write!(f, "{}", err_msg)
    }
}

// A unique format for dubugging output
impl fmt::Debug for CivicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CivicError {{ code: {}, message: {} }}",
            self.code, self.message
        )
    }
}

impl std::convert::From<reqwest::Error> for CivicError {
    fn from(error: reqwest::Error) -> Self {
        CivicError {
            code: 1,
            message: error.to_string(),
        }
    }
}
