use crate::core::error::ContractError;
use crate::core::state::meta_read;
use cosmwasm_std::{to_binary, Binary, Deps};
use provwasm_std::ProvenanceQuery;

pub fn query_address_by_name(
    deps: Deps<ProvenanceQuery>,
    name: String,
) -> Result<Binary, ContractError> {
    let meta_storage = meta_read(deps.storage);
    let name_meta = meta_storage.load(name.as_bytes())?;
    Ok(to_binary(&name_meta)?)
}
