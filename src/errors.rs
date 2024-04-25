use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GrapevineError {
    InputsEmpty,
}

impl std::fmt::Display for GrapevineError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineError::InputsEmpty => write!(f, "No private input provided to F circuit!")
        }
    }
}

impl std::error::Error for GrapevineError {}
