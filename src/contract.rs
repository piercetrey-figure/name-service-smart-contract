use crate::core::error::ContractError;
use crate::core::msg::{ExecuteMsg, InitMsg, MigrateMsg, QueryMsg};
use crate::execute::register_name::register_name;
use crate::instantiate::instantiate_contract::instantiate_contract;
use crate::migrate::migrate_contract::migrate_contract;
use crate::query::query_address_by_name::query_address_by_name;
use crate::query::query_names_by_address::query_names_by_address;
use crate::query::query_state::query_state;
use crate::query::query_version::query_version;
use crate::query::search_for_names::search_for_names;
use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use provwasm_std::{ProvenanceMsg, ProvenanceQuery};

/// Creates the contract on the chain, populating all relevant fields in the state and registering
/// a name for the contract.
#[entry_point]
pub fn instantiate(
    deps: DepsMut<ProvenanceQuery>,
    env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    instantiate_contract(deps, env, info, msg)
}

/// Pulls various data about registered names, the contract state, or the contract version.
#[entry_point]
pub fn query(
    deps: Deps<ProvenanceQuery>,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::QueryRequest {} => query_state(deps),
        QueryMsg::QueryAddressByName { name } => query_address_by_name(deps, name),
        QueryMsg::QueryNamesByAddress { address } => query_names_by_address(deps, address),
        QueryMsg::SearchForNames { search } => search_for_names(deps, search),
        QueryMsg::Version {} => query_version(deps),
    }
}

/// Execution entrypoints for enacting the contract's purpose: registering names to addresses.
#[entry_point]
pub fn execute(
    deps: DepsMut<ProvenanceQuery>,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    match msg {
        ExecuteMsg::Register { name } => register_name(deps, info, name),
    }
}

/// Allows modification of the contract's state and internal codebase.
#[entry_point]
pub fn migrate(
    deps: DepsMut<ProvenanceQuery>,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, ContractError> {
    migrate_contract(deps, msg)
}
