use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, to_binary};
use provwasm_std::{NameBinding, ProvenanceMsg, add_attribute, bind_name};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InitMsg, MigrateMsg, QueryMsg };
use crate::state::{NameMeta, State, config, config_read, meta, meta_read};

/// Initialize the contract
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<Response<ProvenanceMsg>, StdError> {
    // Ensure no funds were sent with the message
    if !info.funds.is_empty() {
        let err = "purchase funds are not allowed to be sent during init";
        return Err(StdError::generic_err(err));
    }

    // Create and save contract config state. The name is used for setting attributes on user accounts
    config(deps.storage).save(&State {
        name: msg.name.clone(),
        fee_amount: msg.fee_amount.clone(),
        fee_collection_address: msg.fee_collection_address.clone(),
    })?;

    // Create a message that will bind a restricted name to the contract address.
    let bind_name_msg = bind_name(
        &msg.name,
        env.contract.address,
        NameBinding::Restricted,
    )?;

    // Dispatch messages and emit event attributes
    Ok(Response::new()
        .add_message(bind_name_msg)
        .add_attribute("action", "init"))
}

/// Query contract state.
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::QueryRequest {} => {
            let state = config_read(deps.storage).load()?;
            let json = to_binary(&state)?;
            Ok(json)
        }
        QueryMsg::ResolveName { name } => {
            let meta_storage = meta_read(deps.storage);
            let name_meta = meta_storage.load(name.as_bytes())?;
            let json = to_binary(&name_meta)?;
            Ok(json)
        },
    }
}

/// Handle purchase messages.
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    match msg {
        ExecuteMsg::Register { name} => try_register(deps, env, info, name),
    }
}

// register a name
fn try_register(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    name: String,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    let config = config(deps.storage).load()?;

    let add_attribute_message = add_attribute(info.sender.clone(), config.name, Binary(name.clone().into()), provwasm_std::AttributeValueType::String)?;

    let mut meta_storage = meta(deps.storage);

    let name_meta = NameMeta {
        name: name.clone(),
        address: info.sender.into_string(),
    };

    meta_storage.save(name.clone().as_bytes(), &name_meta)?;

    // Return a response that will dispatch the marker messages and emit events.
    Ok(Response::new()
        .add_message(add_attribute_message)
        .add_attribute("action", "name_register")
        .add_attribute("name", name)
    )
}

/// Called when migrating a contract instance to a new code ID.
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use crate::msg::QueryResponse;

    use super::*;
    use cosmwasm_std::testing::{mock_env, mock_info};
    use cosmwasm_std::{CosmosMsg, from_binary};
    use provwasm_mocks::mock_dependencies;
    use provwasm_std::{AttributeValueType, NameMsgParams, ProvenanceMsgParams, AttributeMsgParams};

    #[test]
    fn valid_init() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create valid config state
        let res = instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InitMsg {
                name: "wallet.pb".into(),
                fee_amount: "100000000000".into(),
                fee_collection_address: "tp123".into()
            },
        )
        .unwrap();

        // Ensure a message was created to bind the name to the contract address.
        assert_eq!(res.messages.len(), 1);
        match &res.messages[0].msg {
            CosmosMsg::Custom(msg) => match &msg.params {
                ProvenanceMsgParams::Name(p) => match &p {
                    NameMsgParams::BindName { name, .. } => assert_eq!(name, "wallet.pb"),
                    _ => panic!("unexpected name params"),
                },
                _ => panic!("unexpected provenance params"),
            },
            _ => panic!("unexpected cosmos message"),
        }
    }

    #[test]
    fn query_test() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create config state
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("feebucket", &[]),
            InitMsg {
                name: "wallet.pb".into(),
                fee_amount: "100000000000".into(),
                fee_collection_address: "tp123".into()
            },
        )
        .unwrap(); // Panics on error

        // Call the smart contract query function to get stored state.
        let bin = query(deps.as_ref(), mock_env(), QueryMsg::QueryRequest {}).unwrap();
        let resp: QueryResponse = from_binary(&bin).unwrap();

        // Ensure the expected init fields were properly stored.
        assert_eq!(resp.name, "wallet.pb");
    }

    #[test]
    fn handle_valid_register() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create config state
        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            InitMsg {
                name: "wallet.pb".into(),
                fee_amount: "100000000000".into(),
                fee_collection_address: "tp123".into()
            },
        )
        .unwrap();

        let m_info = mock_info("somedude", &[]);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            m_info.clone(),
            ExecuteMsg::Register {
                name: "mycoolname".into(),
            },
        )
        .unwrap();

        // Ensure we have the attribute message
        assert_eq!(res.messages.len(), 1);

        res.messages.into_iter().for_each(|msg| match msg.msg {
            CosmosMsg::Custom(ProvenanceMsg { params, .. }) => {
                match params {
                    ProvenanceMsgParams::Attribute(AttributeMsgParams::AddAttribute { name, value, value_type, .. }) => {
                        assert_eq!(name, "wallet.pb");
                        assert_eq!(value, Binary("mycoolname".into()));
                        assert_eq!(value_type, AttributeValueType::String)
                    }
                    _ => panic!("unexpected provenance message type")
                }
            }
            _ => panic!("unexpected message type"),
        });

        // Ensure we got the name event attribute value
        let attribute = res.attributes.into_iter().find(|attr| attr.key == "name").unwrap();
        assert_eq!(attribute.value, "mycoolname");
    }
}
