use crate::contract_info::{FEE_DENOMINATION, MAX_NAME_SEARCH_RESULTS};
use crate::error::{std_err_result, ContractError};
use crate::msg::{ExecuteMsg, InitMsg, MigrateMsg, NameResponse, NameSearchResponse, QueryMsg};
use crate::state::{config, config_read, meta, meta_read, NameMeta, State};
use crate::version_info::{
    get_version_info, migrate_version_info, CONTRACT_NAME, CONTRACT_VERSION,
};
use cosmwasm_std::{
    coin, entry_point, from_binary, to_binary, Api, BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Order, Response, StdResult, Uint128,
};
use cosmwasm_storage::Bucket;
use provwasm_std::{
    add_attribute, bind_name, Attribute, Attributes, NameBinding, ProvenanceMsg, ProvenanceQuerier,
    ProvenanceQuery,
};
use semver::Version;

///
/// INSTANTIATION SECTION
///
#[entry_point]
pub fn instantiate(
    deps: DepsMut<ProvenanceQuery>,
    env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    // Ensure no funds were sent with the message
    if !info.funds.is_empty() {
        return std_err_result("purchase funds are not allowed to be sent during init")
            .map_err(ContractError::Std);
    }
    // Verify the fee amount can be converted from string successfully
    fee_amount_from_string(&msg.fee_amount)?;
    // Create and save contract config state. The name is used for setting attributes on user accounts
    match config(deps.storage).save(&State {
        name: msg.name.clone(),
        fee_amount: msg.fee_amount.clone(),
        fee_collection_address: msg.fee_collection_address.clone(),
    }) {
        Ok(_) => {}
        Err(e) => {
            return std_err_result(format!("failed to init state: {:?}", e))
                .map_err(ContractError::Std);
        }
    };
    // Create a message that will bind a restricted name to the contract address.
    let bind_name_msg = match bind_name(&msg.name, env.contract.address, NameBinding::Restricted) {
        Ok(result) => result,
        Err(e) => {
            return std_err_result(format!("failed to construct bind name message: {:?}", e))
                .map_err(ContractError::Std);
        }
    };

    // Set the version info to the default contract values on instantiation
    migrate_version_info(deps.storage)?;

    // Dispatch messages and emit event attributes
    Ok(Response::new()
        .add_message(bind_name_msg)
        .add_attribute("action", "init"))
}

///
/// QUERY SECTION
///
#[entry_point]
pub fn query(deps: Deps<ProvenanceQuery>, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
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
        }
        QueryMsg::QueryNamesByAddress { address } => try_query_by_address(deps, address),
        QueryMsg::SearchForNames { search } => search_for_names(deps, search),
    }
}

fn try_query_by_address(deps: Deps<ProvenanceQuery>, address: String) -> StdResult<Binary> {
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
    let attribute_container: Attributes = match ProvenanceQuerier::new(&deps.querier)
        .get_attributes(validated_address, Some(registrar_name))
    {
        Ok(attributes) => attributes,
        Err(e) => {
            return std_err_result(format!(
                "failed to lookup account by address [{}]: {:?}",
                address, e
            ));
        }
    };
    // Deserialize all names from their binary-encoded values to the source strings
    let response_bin = match pack_response_from_attributes(attribute_container) {
        Ok(binary) => binary,
        Err(e) => {
            return std_err_result(format!(
                "failed to pack attribute response to binary: {:?}",
                e
            ))
        }
    };
    // After establishing a vector of all derived names, serialize the list itself to a binary response
    Ok(response_bin)
}

/// Creates a NameResponse from an Attribute module response. Isolated for unit testing.
fn pack_response_from_attributes(attributes: Attributes) -> StdResult<Binary> {
    let names = attributes
        .attributes
        .iter()
        .map(deserialize_name_from_attribute)
        .collect();
    to_binary(&NameResponse::new(attributes.address.into_string(), names))
}

/// Simple pass-through to convert a binary response from the Attribute module to a usable String.
/// Isolated for unit testing.
fn deserialize_name_from_attribute(attribute: &Attribute) -> String {
    from_binary::<String>(&attribute.value).expect("name deserialization failed")
}

/// Scans the entire storage for the target name string by doing direct matches.
/// Will only ever return a maximum of MAX_NAME_SEARCH_RESULTS.
fn search_for_names(deps: Deps<ProvenanceQuery>, search: String) -> StdResult<Binary> {
    let meta_storage = meta_read(deps.storage);
    let search_str = search.as_str();
    let names = meta_storage
        .range(None, None, Order::Ascending)
        .into_iter()
        .filter(|element| element.is_ok())
        .map(|element| element.unwrap().1)
        .filter(|name_meta| name_meta.name.contains(search_str))
        .take(MAX_NAME_SEARCH_RESULTS)
        .collect();
    to_binary(&NameSearchResponse {
        search: search.clone(),
        names,
    })
}

///
/// EXECUTE SECTION
///
#[entry_point]
pub fn execute(
    deps: DepsMut<ProvenanceQuery>,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    match msg {
        ExecuteMsg::Register { name } => try_register(deps, info, name),
    }
}

// register a name
fn try_register(
    deps: DepsMut<ProvenanceQuery>,
    info: MessageInfo,
    name: String,
) -> Result<Response<ProvenanceMsg>, ContractError> {
    let config = config(deps.storage).load()?;

    // Fetch the name registry bucket from storage for use in dupe verification, as well as
    // storing the new name if validation passes
    let mut meta_storage = meta(deps.storage);

    // Ensure the provided name has not yet been registered. Bubble up the error if the lookup
    // succeeds in finding the value
    validate_name(name.clone(), &meta_storage)?;

    // Serialize the proposed name as binary, allowing it to be sent via the ProvenanceClient as
    // a new attribute under the registrar
    let name_bin = match to_binary(&name) {
        Ok(bin) => bin,
        Err(e) => {
            return ContractError::NameSerializationFailure { cause: e }.to_result();
        }
    };

    // Construct the new attribute message for dispatch
    let add_attribute_message = add_attribute(
        info.sender.clone(),
        config.clone().name,
        name_bin,
        provwasm_std::AttributeValueType::String,
    )?;

    // Validate that fees are payable and correctly constructed. Errors are properly packaged within
    // the target function, which makes this a perfect candidate for bubbling up via the ? operator
    let charge_response = validate_fee_params_get_messages(deps.api, &info, &config)?;

    // Construct and store a NameMeta to the internal bucket.  This is important, because this
    // registry ensures duplicates names cannot be added, as well as allow addresses to be looked
    // up by name
    let name_meta = NameMeta {
        name: name.clone(),
        address: info.sender.into_string(),
    };
    meta_storage.save(name.as_bytes(), &name_meta)?;

    // Return a response that will dispatch the marker messages and emit events.
    let mut response = Response::new()
        .add_message(add_attribute_message)
        .add_attribute("action", "name_register")
        .add_attribute("name", name);

    // If a fee charge is requested, append it
    if let Some(fee_message) = charge_response.fee_charge_message {
        response = response.add_message(fee_message);
    }

    // If a fee refund must occur, append the constructed message as well as an attribute explicitly
    // detailing the amount of "denom" refunded
    if let Some(refund_message) = charge_response.fee_refund_message {
        response = response.add_message(refund_message).add_attribute(
            "fee_refund",
            format!("{}{}", charge_response.fee_refund_amount, FEE_DENOMINATION),
        );
    }
    Ok(response)
}
/// Validates that a name can be added.  Makes the following checks:
/// - The name is not already registered. Core validation to ensure duplicate registrations cannot occur
/// - The name is all lowercase and does not contain special characters. Ensures all names are easy to recognize.
fn validate_name(name: String, meta: &Bucket<NameMeta>) -> Result<String, ContractError> {
    // If the load doesn't error out, that means it found the input name
    if meta.load(name.as_bytes()).is_ok() {
        return ContractError::NameRegistered { name }.to_result();
    }
    // Ensures that the given name is all lowercase and has no special characters or spaces
    // Note: This would be a great place to have a regex, but the regex cargo itself adds 500K to
    // the file size after optimization, excluding it as an option
    if name.is_empty()
        || name
            .chars()
            .any(|char| !char.is_alphanumeric() || (!char.is_lowercase() && !char.is_numeric()))
    {
        return ContractError::InvalidNameFormat { name }.to_result();
    }
    Ok("successful validation".into())
}

/// Helper struct to make the validate fee params function response more readable
struct FeeChargeResponse {
    fee_charge_message: Option<CosmosMsg<ProvenanceMsg>>,
    fee_refund_message: Option<CosmosMsg<ProvenanceMsg>>,
    fee_refund_amount: u128,
}

/// Verifies that funds provided are correct and enough for a fee charge, and then constructs
/// provenance messages that will provide the correct output during the name registration process.
///
/// The validation performed is:
/// - Ensure no funds provided are of an incorrect denomination.
/// - Ensure that the provided funds sent are >= the fee charge for transactions
/// - Ensure that, if more funds are provided than are needed by for the fee, that the excess is caught and refunded
///
/// Returns:
/// - 1: The message to allocate provided funds to the fee collection account (None if the fee collection amount is instantiated as zero with the contract)
/// - 2: The message to refund the sender with any excess fees (None if the funds provided are exactly equal to the amount of fee required)
/// - 3: The amount refunded.  Will be zero if the perfect fund amount if sent.
/// - Various errors if funds provided are not enough or incorrectly formatted
fn validate_fee_params_get_messages(
    api: &dyn Api,
    info: &MessageInfo,
    config: &State,
) -> Result<FeeChargeResponse, ContractError> {
    // Determine if any funds sent are not of the correct denom
    let invalid_funds = info
        .funds
        .iter()
        .filter(|coin| coin.denom != FEE_DENOMINATION)
        .map(|coin| coin.denom.clone())
        .collect::<Vec<String>>();

    // If any funds are found that do not match the fee denom, exit prematurely to prevent
    // contract from siphoning random funds for no reason
    if !invalid_funds.is_empty() {
        return ContractError::InvalidFundsProvided {
            types: invalid_funds,
        }
        .to_result();
    }

    let nhash_fee_amount = fee_amount_from_string(&config.fee_amount)?;

    // Pull the nhash sent by verifying that only one fund sent is of the nhash variety
    let nhash_sent = match info
        .clone()
        .funds
        .into_iter()
        .find(|coin| coin.denom == FEE_DENOMINATION)
    {
        Some(coin) => coin.amount,
        None => {
            // If fees are required, then a coin of type FEE_DENOMINATION should be sent and the
            // absence of one is an error.  Otherwise, treat omission as purposeful definition of
            // zero money fronted for a fee
            if nhash_fee_amount > 0 {
                return ContractError::NoFundsProvidedForRegistration.to_result();
            } else {
                Uint128::zero()
            }
        }
    };

    // If the amount provided is too low, reject the request because the fee cannot be paid
    if nhash_sent.u128() < nhash_fee_amount {
        return ContractError::InsufficientFundsProvided {
            amount_provided: nhash_sent.u128(),
            amount_required: nhash_fee_amount,
        }
        .to_result();
    }

    // Pull the fee amount from the sender for name registration
    let fee_charge_message = if nhash_fee_amount > 0 {
        Some(CosmosMsg::Bank(BankMsg::Send {
            // The fee collection address is validated on contract instantiation, so there's no need to
            // define custom error messages here
            to_address: api.addr_validate(&config.fee_collection_address)?.into(),
            // The same goes for the fee_amount - it is guaranteed to pass this check
            amount: vec![coin(nhash_fee_amount, FEE_DENOMINATION)],
        }))
    } else {
        None
    };

    // The refund amount is == the total nhash sent - fee charged
    let fee_refund_amount = nhash_sent.u128() - nhash_fee_amount;

    // If more than the fee amount is sent, then respond with an additional message that sends the
    // excess back into the sender's account
    let fee_refund_message = if fee_refund_amount > 0 {
        Some(CosmosMsg::Bank(BankMsg::Send {
            to_address: info.sender.clone().into(),
            amount: vec![coin(fee_refund_amount, FEE_DENOMINATION)],
        }))
    } else {
        None
    };

    Ok(FeeChargeResponse {
        fee_charge_message,
        fee_refund_message,
        fee_refund_amount,
    })
}

///
/// MIGRATE SECTION
///
#[entry_point]
pub fn migrate(
    deps: DepsMut<ProvenanceQuery>,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, ContractError> {
    let stored_version_info = get_version_info(deps.storage)?;
    // If the contract name has changed or another contract attempts to overwrite this one, this
    // check will reject the change
    if CONTRACT_NAME != stored_version_info.contract {
        return ContractError::InvalidContractName {
            previous_contract: stored_version_info.contract,
            provided_contract: CONTRACT_NAME.to_string(),
        }
        .to_result();
    }
    let contract_version = CONTRACT_VERSION.parse::<Version>()?;
    // If the stored version in the contract is greater than the derived version from the package,
    // then this migration is effectively a downgrade and should not be committed
    if stored_version_info.parse_sem_ver()? > contract_version {
        return ContractError::InvalidContractVersion {
            previous_version: stored_version_info.version,
            provided_version: CONTRACT_VERSION.to_string(),
        }
        .to_result();
    }
    let mut attributes: Vec<cosmwasm_std::Attribute> = vec![];
    // If any optional migration values were provided, swap them over during the migration
    if msg.has_fee_changes() {
        let mut config = config(deps.storage);
        let mut state = config.load()?;
        state.fee_amount = match msg.new_fee_amount {
            Some(amount) => {
                fee_amount_from_string(amount.as_str())?;
                attributes.push(cosmwasm_std::Attribute::new(
                    "fee_amount_updated",
                    amount.clone(),
                ));
                amount
            }
            None => state.fee_amount,
        };
        state.fee_collection_address = match msg.new_fee_collection_address {
            Some(addr_str) => {
                deps.api.addr_validate(addr_str.as_str())?;
                attributes.push(cosmwasm_std::Attribute::new(
                    "fee_collection_address_updated",
                    addr_str.clone(),
                ));
                addr_str
            }
            None => state.fee_collection_address,
        };
        config.save(&state)?;
    }
    Ok(Response::new().add_attributes(attributes))
}

///
/// SHARED FUNCTIONALITY SECTION
///
fn fee_amount_from_string(fee_amount_string: &str) -> StdResult<u128> {
    match fee_amount_string.parse::<u128>() {
        Ok(amount) => Ok(amount),
        Err(e) => std_err_result(format!(
            "unable to parse input fee amount {} as numeric:\n{}",
            fee_amount_string, e
        )),
    }
}

///
/// TEST SECTION
///
#[cfg(test)]
mod tests {
    use crate::msg::QueryResponse;

    use super::*;
    use crate::version_info::{set_version_info, VersionInfoV1};
    use cosmwasm_std::testing::{mock_env, mock_info};
    use cosmwasm_std::{from_binary, Addr, Coin, CosmosMsg};
    use provwasm_mocks::mock_dependencies;
    use provwasm_std::{
        AttributeMsgParams, AttributeValueType, NameMsgParams, ProvenanceMsgParams,
    };

    const DEFAULT_FEE_AMOUNT: u128 = 10000000000;

    #[test]
    fn valid_init() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create valid config state
        let res = test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
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
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();

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
        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 150,
            fee_collection_address: "no-u",
        })
        .unwrap();

        let m_info = mock_info("somedude", &vec![coin(150, "nhash")]);
        let res = do_registration(deps.as_mut(), m_info.clone(), "mycoolname".into()).unwrap();

        // Ensure we have the attribute message and the fee message
        assert_eq!(res.messages.len(), 2);
        res.messages.into_iter().for_each(|msg| match msg.msg {
            CosmosMsg::Custom(ProvenanceMsg { params, .. }) => {
                verify_add_attribute_result(params, "wallet.pb", "mycoolname");
            }
            CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
                assert_eq!("no-u", to_address);
                assert_eq!(
                    1,
                    amount.len(),
                    "Only one coin should be specified in the fee transfer message"
                );
                let transferred_coin = amount
                    .first()
                    .expect("Expected the first element of the coin transfer to be accessible");
                assert_eq!(
                    transferred_coin.amount.u128(),
                    fee_amount_from_string("150").unwrap()
                );
                assert_eq!(transferred_coin.denom.as_str(), FEE_DENOMINATION);
            }
            _ => panic!("unexpected message type"),
        });

        // Ensure we got the name event attribute value
        let attribute = res
            .attributes
            .into_iter()
            .find(|attr| attr.key == "name")
            .unwrap();
        assert_eq!(attribute.value, "mycoolname");
    }

    #[test]
    fn test_fee_overage_is_refunded() {
        let mut deps = mock_dependencies(&[]);

        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 150,
            fee_collection_address: "fee_bucket",
        })
        .unwrap();

        // Send 50 more than the required fee amount
        let m_info = mock_info("sender_wallet", &vec![coin(200, FEE_DENOMINATION)]);

        let response = do_registration(deps.as_mut(), m_info, "thebestnameever".into()).unwrap();

        assert_eq!(
            response.messages.len(),
            3,
            "three messages should be returned with an excess fee"
        );

        response.messages.into_iter().for_each(|msg| match msg.msg {
            CosmosMsg::Custom(ProvenanceMsg { params, .. }) => {
                verify_add_attribute_result(params, "wallet.pb", "thebestnameever");
            }
            CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
                let coin_amount_sent = validate_and_get_nhash_sent(amount);
                match to_address.as_str() {
                    "fee_bucket" => {
                        assert_eq!(
                            coin_amount_sent, 150,
                            "expected the fee bucket to be sent the instantiated fee amount"
                        );
                    }
                    "sender_wallet" => {
                        assert_eq!(
                            coin_amount_sent, 50,
                            "expected the sender to be refunded the excess funds they added"
                        );
                    }
                    _ => panic!("unexpected to_address encountered"),
                };
            }
            _ => panic!("unexpected message type"),
        });

        assert_eq!(
            3,
            response.attributes.len(),
            "expected three attributes to be added when a refund occurs"
        );
        response
            .attributes
            .iter()
            .find(|attr| attr.key.as_str() == "action")
            .unwrap();
        let name_attr = response
            .attributes
            .iter()
            .find(|attr| attr.key.as_str() == "name")
            .unwrap();
        assert_eq!(name_attr.value.as_str(), "thebestnameever");
        let excess_funds_attr = response
            .attributes
            .iter()
            .find(|attr| attr.key.as_str() == "fee_refund")
            .unwrap();
        assert_eq!(excess_funds_attr.value.as_str(), "50nhash");
    }

    #[test]
    fn test_zero_fee_allows_no_amounts() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 0,
            fee_collection_address: "feebucket",
        })
        .unwrap();
        // Send no coin with the request under the assumption that zero fee should allow this
        let m_info = mock_info("senderwallet", &[]);
        let zero_fee_resp = do_registration(deps.as_mut(), m_info, "nameofmine".into()).unwrap();
        assert_eq!(1, zero_fee_resp.messages.len(), "only one message should be responded with because no fee occurred and no refund occurred");
        zero_fee_resp
            .messages
            .into_iter()
            .for_each(|msg| match msg.msg {
                CosmosMsg::Custom(ProvenanceMsg { params, .. }) => {
                    verify_add_attribute_result(params, "wallet.pb", "nameofmine");
                }
                _ => panic!("unexpected response message type"),
            });
        let refund_attr = zero_fee_resp
            .attributes
            .into_iter()
            .find(|attr| attr.key.as_str() == "fee_refund");
        assert!(
            refund_attr.is_none(),
            "no refund should occur with no amount passed in"
        );
    }

    #[test]
    fn test_zero_fee_and_fee_overage_provided_results_in_full_refund() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 0,
            fee_collection_address: "feebucket",
        })
        .unwrap();
        // Send a coin overage of nhash to ensure all of it gets returned as a refund
        let m_info = mock_info("sender_wallet", &vec![coin(200, FEE_DENOMINATION)]);
        let refund_resp = do_registration(deps.as_mut(), m_info, "nametouse".into()).unwrap();
        assert_eq!(
            2,
            refund_resp.messages.len(),
            "two messages should be responded with when a fee is not charged, but a refund is made"
        );
        refund_resp.messages.into_iter().for_each(|msg| match msg.msg {
            CosmosMsg::Custom(ProvenanceMsg { params, .. }) => {
                verify_add_attribute_result(params, "wallet.pb", "nametouse");
            }
            CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
                assert_eq!(to_address.as_str(), "sender_wallet", "the recipient of the transaction should be the sender because all funds allocated were refunded");
                let coin_amount_sent = validate_and_get_nhash_sent(amount);
                assert_eq!(coin_amount_sent, 200, "all funds sent should be refunded");
            }
            _ => panic!("unexpected response message type"),
        });
        let fee_refund_attr = refund_resp
            .attributes
            .into_iter()
            .find(|attr| attr.key.as_str() == "fee_refund")
            .expect("the refunded fee amount should be added as an attribute");
        assert_eq!(
            fee_refund_attr.value.as_str(),
            "200nhash",
            "expected the refund amount to be indicated as nhash"
        );
    }

    #[test]
    fn test_duplicate_registrations_are_rejected() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create config state
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        let m_info = mock_info("somedude", &vec![coin(DEFAULT_FEE_AMOUNT, "nhash")]);
        // Do first execution to ensure the new name is in there
        do_registration(deps.as_mut(), m_info.clone(), "mycoolname".into()).unwrap();
        // Try a duplicate request
        let rejected =
            do_registration(deps.as_mut(), m_info.clone(), "mycoolname".into()).unwrap_err();
        match rejected {
            ContractError::NameRegistered { name } => {
                assert_eq!("mycoolname".to_string(), name);
            }
            _ => panic!("unexpected error for proposed duplicate message"),
        };
    }

    #[test]
    fn test_missing_fee_amount_for_registration() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        // No fees provided in mock info - this should cause a rejection
        let missing_all_fees_info = mock_info("theguy", &[]);
        let rejected_no_coin = do_registration(
            deps.as_mut(),
            missing_all_fees_info.clone(),
            "newname".into(),
        )
        .unwrap_err();
        assert!(matches!(
            rejected_no_coin,
            ContractError::NoFundsProvidedForRegistration
        ));
        let incorrect_denom_info = mock_info(
            "theotherguy",
            &vec![
                // Send 3 different types of currencies that the contract is not expected to handle
                coin(DEFAULT_FEE_AMOUNT, "nothash"),
                coin(DEFAULT_FEE_AMOUNT, "fakecoin"),
                coin(DEFAULT_FEE_AMOUNT, "dogecoin"),
                // Provide the a correct value as well to ensure that the validation will reject all
                // requests that include excess
                coin(DEFAULT_FEE_AMOUNT, "nhash"),
            ],
        );
        let rejected_incorrect_type_coin =
            do_registration(deps.as_mut(), incorrect_denom_info, "newname".into()).unwrap_err();
        match rejected_incorrect_type_coin {
            ContractError::InvalidFundsProvided { types } => {
                assert_eq!(
                    3,
                    types.len(),
                    "expected the three invalid types to be returned in the rejection"
                );
                types
                    .iter()
                    .find(|coin_type| coin_type.as_str() == "nothash")
                    .unwrap();
                types
                    .iter()
                    .find(|coin_type| coin_type.as_str() == "fakecoin")
                    .unwrap();
                types
                    .iter()
                    .find(|coin_type| coin_type.as_str() == "dogecoin")
                    .unwrap();
            }
            _ => panic!("unexpected error encountered when providing invalid fund types"),
        }
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
        assert_eq!(
            "my_address",
            name_response.address.as_str(),
            "the source address should be exposed in the query"
        );
        assert_eq!(
            2,
            name_response.names.len(),
            "the two names should be in the response"
        );
    }

    #[test]
    fn test_name_registration_and_lookup_by_address() {
        // Create mocks
        let mut deps = mock_dependencies(&[]);

        // Create config state
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        let address = "registration_guy";
        let mock_info = mock_info(&address, &vec![coin(DEFAULT_FEE_AMOUNT, "nhash")]);
        let target_name = "bestnameever";
        // Drop the name into the system
        do_registration(deps.as_mut(), mock_info.clone(), target_name.into()).unwrap();
        let name_response_binary = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::QueryNamesByAddress {
                address: "admin".into(),
            },
        )
        .unwrap();
        from_binary::<NameResponse>(&name_response_binary)
            .expect("Expected the response to correctly deserialize to a NameResp value");
    }

    #[test]
    fn test_invalid_name_format_scenarios() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        let empty_bucket = meta(deps.as_mut().storage);
        // Establish a decent set of non-alphanumeric characters to test against
        let special_characters = vec![
            ".", ",", "<", ">", "/", "?", ";", ":", "'", "\"", "[", "]", "{", "}", "-", "_", "+",
            "=", "(", ")", "*", "&", "^", "%", "$", "#", "@", "!", " ", "\\", "|",
        ];
        special_characters.into_iter().for_each(|character| {
            let test_name = format!("name{}", character);
            let response = validate_name(test_name.clone(), &empty_bucket).unwrap_err();
            assert!(
                matches!(response, ContractError::InvalidNameFormat { .. }),
                "Expected the name {} to be rejected as an invalid name",
                test_name,
            );
        });
        let empty_name_response = validate_name("".into(), &empty_bucket).unwrap_err();
        assert!(
            matches!(empty_name_response, ContractError::InvalidNameFormat { .. }),
            "Expected an empty name to be rejected as invalid input",
        );
        let uppercase_name_response = validate_name("A".into(), &empty_bucket).unwrap_err();
        assert!(
            matches!(
                uppercase_name_response,
                ContractError::InvalidNameFormat { .. }
            ),
            "Expected an uppercase name to be rejected as invalid input",
        );
        validate_name("a1".into(), &empty_bucket)
            .expect("expected a name containing a number to be valid");
    }

    #[test]
    fn test_search_for_names() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        let mut names: Vec<String> = vec![
            "a".into(),
            "aa".into(),
            "ab".into(),
            "ac".into(),
            "test".into(),
        ];
        // Add a ton of stuff prefixed with b to the array to simulate a fully-used name backend
        for i in 0..1000 {
            names.push(format!("b{}", i));
        }
        // Register all names and fail if anything doesn't result in a success
        names.into_iter().for_each(|name| {
            do_registration(
                deps.as_mut(),
                mock_info(
                    "fake_address",
                    &vec![coin(DEFAULT_FEE_AMOUNT, FEE_DENOMINATION)],
                ),
                name.into(),
            )
            .unwrap();
        });
        // Make the search functionality easy to re-use as a closure
        let search = |search_param: &str| {
            let result_bin = query(deps.as_ref(), mock_env(), QueryMsg::SearchForNames { search: search_param.into() })
                .expect(format!("expected the name search to properly respond with binary for search input \"{}\"", search_param).as_str());
            from_binary::<NameSearchResponse>(&result_bin)
                .expect("expected binary deserialization to a NameSearchResposne to succeed")
        };
        // Verify that all the things added with "a" in them can be found
        let name_result = search("a");
        assert_eq!(
            "a",
            name_result.search.as_str(),
            "expected the search value to reflect the input"
        );
        assert_eq!(
            4,
            name_result.names.len(),
            "all four results containing the letter \"a\" should be returned"
        );
        name_result
            .names
            .iter()
            .find(|meta| meta.name == "a")
            .expect("the value \"a\" should be amongst the results");
        name_result
            .names
            .iter()
            .find(|meta| meta.name == "aa")
            .expect("the value \"aa\" should be amongst the results");
        name_result
            .names
            .iter()
            .find(|meta| meta.name == "ab")
            .expect("the value \"ab\" should be amongst the results");
        name_result
            .names
            .iter()
            .find(|meta| meta.name == "ac")
            .expect("the value \"ac\" should be amongst the results");
        assert!(
            name_result.names.iter().find(|meta| meta.name == "test").is_none(),
            "the value \"test\" should not be included in results because it does not contain the search string",
        );
        // Verify that the only result when using a direct search will be found
        let test_search_result = search("test");
        assert_eq!(
            1,
            test_search_result.names.len(),
            "expected only a single result to match for input \"test\""
        );
        test_search_result
            .names
            .iter()
            .find(|meta| meta.name == "test")
            .expect("the value \"test\" should be amongst the results");
        // Verify that all of the "b" names added in the loop were added
        let end_of_additions_result = search("b999");
        assert_eq!(
            1,
            end_of_additions_result.names.len(),
            "expected the final b name to be added"
        );
        end_of_additions_result
            .names
            .iter()
            .find(|meta| meta.name == "b999")
            .expect("the value \"b999\" should be amongst the results");
        // Verify that searches that find more than MAX_NAME_SEARCH_RESULTS will only find those results
        let large_search_result = search("b");
        assert_eq!(
            MAX_NAME_SEARCH_RESULTS,
            large_search_result.names.len(),
            "expected only the max search results to be returned when a query would find more results",
        );
        assert!(
            large_search_result
                .names
                .iter()
                .all(|meta| meta.name.contains("b")),
            "all results found should contain the letter \"b\" as indicated by the query",
        );
        // Verify that a search that hits nothing will return an empty array
        let empty_search_result = search("test0");
        assert_eq!(
            0,
            empty_search_result.names.len(),
            "a search that finds nothing should return an empty vector of names"
        );
    }

    #[test]
    fn test_migration_with_no_state_changes() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        let migrate_response = migrate(deps.as_mut(), mock_env(), MigrateMsg::empty()).unwrap();
        assert!(
            migrate_response.attributes.is_empty(),
            "no attributes should be added, indicating that the migration made no changes"
        );
    }

    #[test]
    fn test_migration_with_only_fee_changed() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 100,
            fee_collection_address: "fake_address".into(),
        })
        .unwrap();
        let migrate_response = migrate(
            deps.as_mut(),
            mock_env(),
            MigrateMsg {
                new_fee_amount: Some("150".to_string()),
                new_fee_collection_address: None,
            },
        )
        .unwrap();
        assert_eq!(
            1,
            migrate_response.attributes.len(),
            "only one attribute should be added, indicating that a single state value was changed"
        );
        let attribute = migrate_response
            .attributes
            .first()
            .expect("The first element should be available within the migration values");
        assert_eq!(
            "fee_amount_updated",
            attribute.key.as_str(),
            "Expected the key to show that the fee was changed",
        );
        assert_eq!(
            "150",
            attribute.value.as_str(),
            "Expected the value to show the new value that the fee amount was updated to",
        );
    }

    #[test]
    fn test_migration_with_only_fee_address_changed() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::FeeParams {
            deps: deps.as_mut(),
            fee_amount: 100,
            fee_collection_address: "fake_address".into(),
        })
        .unwrap();
        let migrate_response = migrate(
            deps.as_mut(),
            mock_env(),
            MigrateMsg {
                new_fee_amount: None,
                new_fee_collection_address: Some("new_address".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            1,
            migrate_response.attributes.len(),
            "only one attribute should be added, indicating that a single state value was changed"
        );
        let attribute = migrate_response
            .attributes
            .first()
            .expect("The first element should be available within the migration values");
        assert_eq!(
            "fee_collection_address_updated",
            attribute.key.as_str(),
            "Expected the key to show that the fee address was changed",
        );
        assert_eq!(
            "new_address",
            attribute.value.as_str(),
            "Expected the value to show the new value that the fee address was updated to",
        );
    }

    #[test]
    fn test_migration_with_invalid_new_fee_amount() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        migrate(
            deps.as_mut(),
            mock_env(),
            MigrateMsg {
                new_fee_amount: Some("not a number".to_string()),
                new_fee_collection_address: None,
            },
        )
        .unwrap_err();
    }

    #[test]
    fn test_migration_with_invalid_new_fee_collection_address() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        migrate(
            deps.as_mut(),
            mock_env(),
            MigrateMsg {
                new_fee_amount: None,
                new_fee_collection_address: Some("".to_string()),
            },
        )
        .unwrap_err();
    }

    #[test]
    fn test_migration_with_invalid_contract_name() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        // Override the internal contract name to a new, different name
        set_version_info(
            deps.as_mut().storage,
            &VersionInfoV1 {
                contract: "Fake Name".to_string(),
                version: CONTRACT_VERSION.to_string(),
            },
        )
        .unwrap();
        let error = migrate(deps.as_mut(), mock_env(), MigrateMsg::empty()).unwrap_err();
        match error {
            ContractError::InvalidContractName {
                previous_contract,
                provided_contract,
            } => {
                assert_eq!(
                    "Fake Name", previous_contract,
                    "the previous contract name should be the value in storage",
                );
                assert_eq!(
                    CONTRACT_NAME,
                    provided_contract.as_str(),
                    "the provided contract name should be the cargo package name",
                );
            }
            _ => panic!("unexpected error encountered when bad contract name provided"),
        };
    }

    #[test]
    fn test_migration_with_invalid_version() {
        let mut deps = mock_dependencies(&[]);
        test_instantiate(InstArgs::Basic {
            deps: deps.as_mut(),
        })
        .unwrap();
        // Override the internal contract version to a version one minor value above the current version
        set_version_info(
            deps.as_mut().storage,
            &VersionInfoV1 {
                contract: CONTRACT_NAME.to_string(),
                version: "0.2.1".to_string(),
            },
        )
        .unwrap();
        let error = migrate(deps.as_mut(), mock_env(), MigrateMsg::empty()).unwrap_err();
        match error {
            ContractError::InvalidContractVersion {
                previous_version,
                provided_version,
            } => {
                assert_eq!(
                    "0.2.1", previous_version,
                    "the previous contract version should be the value in storage",
                );
                assert_eq!(
                    CONTRACT_VERSION,
                    provided_version.as_str(),
                    "the provided contract version should be the cargo package version",
                );
            }
            _ => panic!("unexpected error encountered when bad contract version provided"),
        }
    }

    /// Helper to build an Attribute without having to do all the un-fun stuff repeatedly
    fn create_fake_name_attribute(name: &str) -> Attribute {
        Attribute {
            name: "wallet.pb".into(),
            value: to_binary(name.into()).unwrap(),
            value_type: AttributeValueType::String,
        }
    }

    /// Helper to do a registration without all the extra boilerplate
    fn do_registration(
        deps: DepsMut<ProvenanceQuery>,
        message_info: MessageInfo,
        name: String,
    ) -> Result<Response<ProvenanceMsg>, ContractError> {
        execute(
            deps,
            mock_env(),
            message_info,
            ExecuteMsg::Register { name },
        )
    }

    /// Driver for multiple instantiate types, on the chance that different defaults are needed
    enum InstArgs<'a> {
        Basic {
            deps: DepsMut<'a, ProvenanceQuery>,
        },
        FeeParams {
            deps: DepsMut<'a, ProvenanceQuery>,
            fee_amount: u128,
            fee_collection_address: &'a str,
        },
    }

    /// Helper to instantiate the contract without being forced to pass all params, are most are
    /// generally unneeded.
    fn test_instantiate(inst: InstArgs) -> Result<Response<ProvenanceMsg>, ContractError> {
        let (deps, fee_amount, fee_address) = match inst {
            InstArgs::Basic { deps } => (deps, DEFAULT_FEE_AMOUNT, "tp123"),
            InstArgs::FeeParams {
                deps,
                fee_amount,
                fee_collection_address,
            } => (deps, fee_amount, fee_collection_address),
        };
        instantiate(
            deps,
            mock_env(),
            mock_info("admin", &[]),
            InitMsg {
                name: "wallet.pb".into(),
                fee_amount: fee_amount.to_string(),
                fee_collection_address: fee_address.into(),
            },
        )
    }

    /// Helper to verify that a name was properly registered under the appropriate registrar.
    fn verify_add_attribute_result(
        params: ProvenanceMsgParams,
        expected_registrar: &str,
        expected_result_name: &str,
    ) {
        match params {
            ProvenanceMsgParams::Attribute(AttributeMsgParams::AddAttribute {
                name,
                value,
                value_type,
                ..
            }) => {
                assert_eq!(name, expected_registrar);
                assert_eq!(
                    from_binary::<String>(&value)
                        .expect("unable to deserialize name response binary"),
                    expected_result_name.to_string(),
                );
                assert_eq!(value_type, AttributeValueType::String)
            }
            _ => panic!("unexpected provenance message type"),
        }
    }

    /// Verifies that the amount vector received via a CosmosMsg::BankMsg::Send is the correct
    /// enclosure: One coin result indicating an amount of nhash sent.
    fn validate_and_get_nhash_sent(amount: Vec<Coin>) -> u128 {
        assert_eq!(
            1,
            amount.len(),
            "expected the amount sent to be a single value, indicating one nhash coin"
        );
        amount
            .into_iter()
            .find(|coin| coin.denom == FEE_DENOMINATION)
            .expect(
                format!(
                    "there should be a coin entry of type [{}]",
                    FEE_DENOMINATION
                )
                .as_str(),
            )
            .amount
            .u128()
    }
}
