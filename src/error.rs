use cosmwasm_std::{StdError, StdResult};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized,
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.

    #[error("Name [{name:?}] is already registered")]
    // The msg param is strictly for internal testing
    NameRegistered { name: String },

    #[error("Name serialization failed due to {cause:?}")]
    NameSerializationFailure { cause: StdError },

    #[error("Name not found")]
    NameNotFound,
    
    #[error("Invalid fields: {fields:?}")]
    InvalidFields { fields: Vec<String> },
}

/// A simple abstraction to wrap an error response just by passing the message
pub fn std_err_result<T>(msg: impl Into<String>) -> StdResult<T> {
    Err(StdError::generic_err(msg))
}
