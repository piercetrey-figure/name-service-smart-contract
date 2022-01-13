use cosmwasm_std::{Binary, Addr, Coin, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::State;

/// A message sent to initialize the contract state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub name: String,
    pub fee_amount: String,
    pub fee_collection_address: String,
}

/// A message sent to register a name with the name service
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Register { name: String, },
}

/// A message sent to query contract config state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    QueryRequest {},
    ResolveName { name: String },
}

/// A type alias for contract state.
pub type QueryResponse = State;

/// Migrate the contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {
}