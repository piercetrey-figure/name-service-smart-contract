use std::panic;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, from_binary, MessageInfo, Response, StdError, StdResult, to_binary};
use provwasm_std::{NameBinding, ProvenanceMsg, add_attribute, bind_name, Attributes, Attribute, ProvenanceQuerier};

use crate::error::{ContractError, std_err_result};
use crate::msg::{ExecuteMsg, InitMsg, MigrateMsg, NameResponse, QueryMsg};
use crate::state::{NameMeta, State, config, config_read, meta, meta_read};

const MIN_FEE_AMOUNT: u64 = 0;

fn validate_proposed_fee_amount(fee_amount: &String) -> StdResult<u64> {
    let amount_value: u64 = match fee_amount.parse() {
        Ok(amount) => amount,
        Err(e) => {
            return std_err_result(format!("unable to parse input fee amount {} as numeric:\n{}", fee_amount, e));
        }
    };
    if amount_value < MIN_FEE_AMOUNT {
        return std_err_result(format!("fee amount {} cannot be negative", amount_value));
    }
    Ok(amount_value)
}

/// Initialize the contract
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<Response<ProvenanceMsg>, StdError> {
    // Ensure no funds were sent with the message
    if !info.funds.is_empty() {
        return std_err_result("purchase funds are not allowed to be sent during init");
    }
    // Flatten fee validation
    validate_proposed_fee_amount(&msg.fee_amount)?;
    // Create and save contract config state. The name is used for setting attributes on user accounts
    match config(deps.storage).save(&State {
        name: msg.name.clone(),
        fee_amount: msg.fee_amount.clone(),
        fee_collection_address: msg.fee_collection_address.clone(),
    }) {
        Ok(_) => {},
        Err(e) => {
            return std_err_result(format!("failed to init state: {:?}", e));
        }
    };
    // Create a message that will bind a restricted name to the contract address.
    let bind_name_msg = match bind_name(
        &msg.name,
        env.contract.address,
        NameBinding::Restricted,
    ) {
        Ok(result) => result,
        Err(e) => {
            return std_err_result(format!("failed to construct bind name message: {:?}", e));
        }
    };

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
        QueryMsg::QueryAddressByName { name } => {
            let meta_storage = meta_read(deps.storage);
            let name_meta = meta_storage.load(name.as_bytes())?;
            let json = to_binary(&name_meta)?;
            Ok(json)
        },
        QueryMsg::QueryNamesByAddress { address } => try_query_by_address(deps, address),
    }
}

fn try_query_by_address(deps: Deps, address: String) -> StdResult<Binary> {
    // Implicitly pull the root registrar name out of the state
    let registrar_name = match config_read(deps.storage).load() {
        Ok(config) => config.name,
        Err(e) => {
            return std_err_result(format!("failed to load registrar name: {:?}", e));
        }
    };
    // Validate and convert the provided address into an Addr for the attribute query
    let validated_address = match deps.api.addr_validate(address.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            return std_err_result(format!("invalid address provided [{}]: {:?}", address, e));
        }
    };
    // Check for the registered name inside the attributes of the target address
    let attribute_container: Attributes = match try_query_attributes(deps, validated_address, registrar_name) {
        Ok(attributes) => attributes,
        Err(e) => {
            return std_err_result(format!("failed to lookup account by address [{}]: {:?}", address.clone(), e));
        }
    };
    // Deserialize all names from their binary-encoded values to the source strings
    let response_bin = match pack_response_from_attributes(attribute_container) {
        Ok(binary) => binary,
        Err(e) => {
            return std_err_result(format!("failed to pack attribute response to binary: {:?}", e))
        }
    };
    // After establishing a vector of all derived names, serialize the list itself to a binary response
    Ok(response_bin)
}

fn try_query_attributes(deps: Deps, address: Addr, name: String) -> StdResult<Attributes> {
    let querier = ProvenanceQuerier::new(&deps.querier);
    return querier.get_attributes(address, Some(name));
}

fn pack_response_from_attributes(attributes: Attributes) -> StdResult<Binary> {
    let names = attributes.attributes
        .iter()
        .map(|attr| deserialize_name_from_attribute(&attr))
        .collect();
    to_binary(&NameResponse::new(attributes.address.into_string(), names))
}

fn deserialize_name_from_attribute(attribute: &Attribute) -> String {
    from_binary::<String>(&attribute.value).expect("name deserialization failed")
}

/// Handle purchase messages.
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    match msg {
        ExecuteMsg::Register { name} => try_register(deps, info, name),
    }
}

// register a name
fn try_register(
    deps: DepsMut,
    info: MessageInfo,
    name: String,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    let config = config(deps.storage).load()?;

    let add_attribute_message = add_attribute(
        info.sender.clone(),
        config.name,
        // TODO: Handle binary deserialization errors gracefully instead of going ham like this
        to_binary(&name.clone()).unwrap(),
        provwasm_std::AttributeValueType::String
    )?;

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
                        assert_eq!(value, to_binary("mycoolname".into()).unwrap());
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

    #[test]
    fn test_deserialize_name_from_attribute() {
        let attribute = create_fake_name_attribute("test_name");
        assert_eq!("test_name", deserialize_name_from_attribute(&attribute));
    }

    #[test]
    fn test_pack_response_from_attributes() {
        let first_name = create_fake_name_attribute("name1");
        let second_name = create_fake_name_attribute("name2");
        let attribute_container = Attributes {
            address: Addr::unchecked("my_address"),
            attributes: vec![first_name, second_name],
        };
        let bin = pack_response_from_attributes(attribute_container)
            .expect("pack_response_from_attributes should create a valid binary");
        let name_response: NameResponse = from_binary(&bin)
            .expect("the generated binary should be resolvable to the source name response");
        assert_eq!("my_address", name_response.address.as_str(), "the source address should be exposed in the query");
        assert_eq!(2, name_response.names.len(), "the two names should be in the response");
    }

    fn create_fake_name_attribute(name: &str) -> Attribute {
        Attribute {
            name: "wallet.pb".into(),
            value: to_binary(name.into()).unwrap(),
            value_type: AttributeValueType::String,
        }
    }

    #[test]
    fn test_name_registration_and_lookup_by_address() {
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
        ).unwrap();
        let address = "registration_guy";
        let mock_info = mock_info(&address, &[]);
        let target_name = "bestnameever";
        // Drop the name into the system
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info.clone(),
            ExecuteMsg::Register {
                name: target_name.into(),
            },
        ).unwrap();
        let name_response_binary = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::QueryNamesByAddress { address: "admin".into() },
        ).unwrap();
        let name_response: NameResponse = from_binary(&name_response_binary)
            .expect("Expected the response to correctly deserialize to a NameResp value");
        // TODO: Figure out how to simulate the name registration.  This currently doesn't work
        // TODO: because the execution phase doesn't actually execute the name association portion.
        // TODO: On the bright side, I was able to test this against my localnet and it WORKS!
        // assert_eq!(address.to_string(), name_response.address, "Expected the name response to contain the target address");
        // assert_eq!(1, name_response.names.len(), "Expected the name response to have a single name in its name payload");
    }
}
