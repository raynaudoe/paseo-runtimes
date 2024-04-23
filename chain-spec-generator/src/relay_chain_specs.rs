use hex_literal::hex;
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use pallet_staking::Forcing;
use paseo_runtime_constants::currency::UNITS as PAS;
use polkadot_primitives::{AccountId, AssignmentId, ValidatorId};
use polkadot_runtime_parachains::configuration::HostConfiguration;
use sc_chain_spec::{ChainSpec, ChainType, NoExtension};
use sc_consensus_grandpa::AuthorityId as GrandpaId;
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_beefy::ecdsa_crypto::AuthorityId as BeefyId;
use sp_core::{crypto::UncheckedInto, sr25519};
use sp_runtime::{AccountId32, Perbill};

use crate::common::{get_account_id_from_seed, get_from_seed, testnet_accounts};

pub type PaseoChainSpec =
    sc_chain_spec::GenericChainSpec<paseo_runtime::RuntimeGenesisConfig, NoExtension>;

const DEFAULT_PROTOCOL_ID: &str = "pas";

/// Returns the properties for the [`PaseoChainSpec`].
pub fn paseo_chain_spec_properties() -> serde_json::map::Map<String, serde_json::Value> {
    serde_json::json!({
        "tokenDecimals": 10,
        "ss58Format": 42,
        "tokenSymbol": "PAS"
    })
    .as_object()
    .expect("Map given; qed")
    .clone()
}

fn default_parachains_host_configuration() -> HostConfiguration<polkadot_primitives::BlockNumber> {
    use polkadot_primitives::{MAX_CODE_SIZE, MAX_POV_SIZE};

    polkadot_runtime_parachains::configuration::HostConfiguration {
        validation_upgrade_cooldown: 2u32,
        validation_upgrade_delay: 2,
        code_retention_period: 1200,
        max_code_size: MAX_CODE_SIZE,
        max_pov_size: MAX_POV_SIZE,
        max_head_data_size: 32 * 1024,
        group_rotation_frequency: 20,
        paras_availability_period: 4,
        max_upward_queue_count: 8,
        max_upward_queue_size: 1024 * 1024,
        max_downward_message_size: 1024 * 1024,
        max_upward_message_size: 50 * 1024,
        max_upward_message_num_per_candidate: 5,
        hrmp_sender_deposit: 0,
        hrmp_recipient_deposit: 0,
        hrmp_channel_max_capacity: 8,
        hrmp_channel_max_total_size: 8 * 1024,
        hrmp_max_parachain_inbound_channels: 4,
        hrmp_channel_max_message_size: 1024 * 1024,
        hrmp_max_parachain_outbound_channels: 4,
        hrmp_max_message_num_per_candidate: 5,
        dispute_period: 6,
        no_show_slots: 2,
        n_delay_tranches: 25,
        needed_approvals: 2,
        relay_vrf_modulo_samples: 2,
        zeroth_delay_tranche_width: 0,
        minimum_validation_upgrade_delay: 5,
        ..Default::default()
    }
}
fn paseo_session_keys(
    babe: BabeId,
    grandpa: GrandpaId,
    im_online: ImOnlineId,
    para_validator: ValidatorId,
    para_assignment: AssignmentId,
    authority_discovery: AuthorityDiscoveryId,
    beefy: BeefyId,
) -> paseo_runtime::SessionKeys {
    paseo_runtime::SessionKeys {
        babe,
        grandpa,
        im_online,
        para_validator,
        para_assignment,
        authority_discovery,
        beefy,
    }
}

/// Helper function to generate stash, controller and session key from seed
pub fn get_authority_keys_from_seed(
	seed: &str,
) -> (
	AccountId,
	AccountId,
	BabeId,
	GrandpaId,
	ImOnlineId,
	ValidatorId,
	AssignmentId,
	AuthorityDiscoveryId,
	BeefyId,
) {
	let keys = get_authority_keys_from_seed_no_beefy(seed);
	(keys.0, keys.1, keys.2, keys.3, keys.4, keys.5, keys.6, keys.7, get_from_seed::<BeefyId>(seed))
}

/// Helper function to generate stash, controller and session key from seed
pub fn get_authority_keys_from_seed_no_beefy(
    seed: &str,
) -> (
    AccountId,
    AccountId,
    BabeId,
    GrandpaId,
    ImOnlineId,
    ValidatorId,
    AssignmentId,
    AuthorityDiscoveryId,
) {
    (
        get_account_id_from_seed::<sr25519::Public>(&format!("{}//stash", seed)),
        get_account_id_from_seed::<sr25519::Public>(seed),
        get_from_seed::<BabeId>(seed),
        get_from_seed::<GrandpaId>(seed),
        get_from_seed::<ImOnlineId>(seed),
        get_from_seed::<ValidatorId>(seed),
        get_from_seed::<AssignmentId>(seed),
        get_from_seed::<AuthorityDiscoveryId>(seed),
    )
}

pub fn paseo_genesis(
    wasm_binary: &[u8],
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        BabeId,
        GrandpaId,
        ImOnlineId,
        ValidatorId,
        AssignmentId,
        AuthorityDiscoveryId,
        BeefyId
    )>,
    root_key: AccountId,
    endowed_accounts: Vec<AccountId>,
) -> paseo_runtime::RuntimeGenesisConfig {
    const ENDOWMENT: u128 = 1_000_000 * PAS; // 1M PAS
    const STASH: u128 = 1_000_00 * PAS; // 100k PAS

    paseo_runtime::RuntimeGenesisConfig {
        system: paseo_runtime::SystemConfig {
            code: wasm_binary.to_vec(),
            ..Default::default()
        },
        indices: paseo_runtime::IndicesConfig { indices: vec![] },
        balances: paseo_runtime::BalancesConfig {
            balances: endowed_accounts
                .iter()
                .filter(|k| root_key.ne(k)) // Root key has a separate endowment
                .map(|k| (k.clone(), ENDOWMENT))
                .collect(),
        },
        session: paseo_runtime::SessionConfig {
            keys: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        paseo_session_keys(
                            x.2.clone(),
                            x.3.clone(),
                            x.4.clone(),
                            x.5.clone(),
                            x.6.clone(),
                            x.7.clone(),
                            x.8.clone()
                        ),
                    )
                })
                .collect::<Vec<_>>(),
        },
        staking: paseo_runtime::StakingConfig {
            minimum_validator_count: 2,
            validator_count: initial_authorities.len() as u32,
            stakers: initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        STASH,
                        paseo_runtime::StakerStatus::Validator,
                    )
                })
                .collect(),
            invulnerables: initial_authorities.iter().map(|x| x.0.clone()).collect(),
            force_era: Forcing::NotForcing,
            slash_reward_fraction: Perbill::from_percent(10),
            min_nominator_bond: 2_500_000_000_000, // 250 PAS
            min_validator_bond: STASH,
            max_validator_count: Some(200),
            ..Default::default()
        },
        babe: paseo_runtime::BabeConfig {
            authorities: Default::default(),
            epoch_config: Some(paseo_runtime::BABE_GENESIS_EPOCH_CONFIG),
            ..Default::default()
        },
        grandpa: Default::default(),
        im_online: Default::default(),
        authority_discovery: paseo_runtime::AuthorityDiscoveryConfig {
            keys: vec![],
            ..Default::default()
        },
        claims: paseo_runtime::ClaimsConfig {
            claims: vec![],
            vesting: vec![],
        },
        vesting: paseo_runtime::VestingConfig { vesting: vec![] },
        treasury: Default::default(),
        hrmp: Default::default(),
        configuration: paseo_runtime::ConfigurationConfig {
            config: default_parachains_host_configuration(),
        },
        paras: Default::default(),
        xcm_pallet: Default::default(),
        nomination_pools: Default::default(),
        sudo: paseo_runtime::SudoConfig {
            key: Some(root_key),
        },
        beefy: Default::default()
    }
}

fn paseo_local_genesis(wasm_binary: &[u8]) -> paseo_runtime::RuntimeGenesisConfig {
    paseo_genesis(
        wasm_binary,
        // initial authorities
        vec![get_authority_keys_from_seed("Alice"),get_authority_keys_from_seed("Charlie"),get_authority_keys_from_seed("Bob")],
        //root key
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        // endowed accounts
        testnet_accounts(),
    )
}

fn paseo_config_genesis(wasm_binary: &[u8]) -> paseo_runtime::RuntimeGenesisConfig {
    type Sessions = (
        AccountId,
        AccountId,
        BabeId,
        GrandpaId,
        ImOnlineId,
        ValidatorId,
        AssignmentId,
        AuthorityDiscoveryId,
        BeefyId
    );

    let root_key: AccountId32 =
        hex!("7e939ef17e229e9a29210d95cb0b607e0030d54899c05f791a62d5c6f4557659").into();

    let initial_paseo_validators: Vec<Sessions> = vec![
        (
            // sp 1
            hex!("82c3105dbd4bb206428d8a8b7ea1f19965a0668dd583b06c3b75daa181fe654c").into(), // stash account (sr25519/1)
            hex!("82c3105dbd4bb206428d8a8b7ea1f19965a0668dd583b06c3b75daa181fe654c").into(), // stash account  (sr25519/1)
            hex!("72063de1c8f732b53b183606fecf96b4f0d42c644951e396fed6041787c41c67").unchecked_into(), // babe key (sr25519/2)
            hex!("9708c671cb55085433f70e3b40e8bcd01b583c366eda4db70f3e38ebcfc620cf").unchecked_into(), // grandpa key (ed25519)
            hex!("0a989f835eb6e1d45434e564fb4e0a6d5894a107f8c9e29b271979780f8d6910").unchecked_into(), // im online key (sr25519/2)
            hex!("1ed5fe5425f3a74f2d0f667d72845b9228b21ca9c08e85e63b6ac0ab1ed0ca75").unchecked_into(), // validator key (sr25519/2)
            hex!("20cd2d63940fc368e687bff8fdb0ef1f7ab703dd566f89c2a634fe6730767c5c").unchecked_into(), // assignment key (sr25519/2)
            hex!("c830f08626a96404ed6d8cdf52defd4b8ff0cd659fc1b8fb320712c4b6ca7a0a").unchecked_into(), // authority discovery key (sr25519/2)
            get_from_seed::<BeefyId>("1")
        ),
        (
            // sp 2
            hex!("74b6c7c8fdf1e3bfd09c0bdd8216f3c4073f66e2687f99b3c50a564ea5b87f58").into(), // stash account (sr25519/1)
            hex!("74b6c7c8fdf1e3bfd09c0bdd8216f3c4073f66e2687f99b3c50a564ea5b87f58").into(), // stash account  (sr25519/1)
            hex!("5a56df50f4197d1edd6e624394cef09717aef66a657636edc691dde21363d764").unchecked_into(), // babe key (sr25519/2)
            hex!("a3cf8d3c2c941369dde9a3f0084aa6509f40e9baeda0a9ddfddd5ad504277686").unchecked_into(), // grandpa key (ed25519)
            hex!("fcde5fbd90ed973195ab021790dc892eca91bc4348a27b97669e4422a655b805").unchecked_into(), // im online key (sr25519/2)
            hex!("a87fc9378370017ec1be5d2a6a344e0fdfa603a037e52f3a9ccf1abff4488e7b").unchecked_into(), // validator key (sr25519/2)
            hex!("f0920097d80f4c5c2b9b45a9b8be677c1a8c39b3ce54eb29e922230501569e35").unchecked_into(), // assignment key (sr25519/2)
            hex!("d4bab8e9f0591aee33a7ef8f41b8b4af0ba5de69f4042558ba94d3a48123c573").unchecked_into(), // authority discovery key (sr25519/2)
            get_from_seed::<BeefyId>("2")
        ),
        (
            // amfc 1
            hex!("32eebacd223f4aef33d98a667a68f9e371f40384257c6d31030952b9d94e1152").into(), // stash account (sr25519/1)
            hex!("32eebacd223f4aef33d98a667a68f9e371f40384257c6d31030952b9d94e1152").into(), // stash account  (sr25519/1)
            hex!("b8b2d23a3c069d8bc316b2a0d296b5e30362850f8684e1bc0287bd07607b9448").unchecked_into(), // babe key (sr25519/2)
            hex!("7d8263d31a65749fb2403e25292d07ac9eae5851a2fe9910f765070349990218").unchecked_into(), // grandpa key (ed25519)
            hex!("72004b35bd03cc799c606ecc252b6071256309d305ac4b72217e25390a046e11").unchecked_into(), // im online key (sr25519/2)
            hex!("de4dfc809481e8b5a0cc1693157e26ccf7263de36919375d750441fc25eb1f05").unchecked_into(), // validator key (sr25519/2)
            hex!("0af57ee1bf0cfbb83d33969dff7143ebfe26aed71648562938808341c782074d").unchecked_into(), // assignment key (sr25519/2)
            hex!("7ae20128cba89a63a33a892fa723f3124b934c42bd61a5d4a7fde129b829e206").unchecked_into(), // authority discovery key (sr25519/2)
            get_from_seed::<BeefyId>("3")
        ),
        (
            // amfc 2
            hex!("444344632a4c87aec511c05c11a7506b75c57e6be8126cb65f78a23044c01900").into(), // stash account (sr25519/1)
            hex!("444344632a4c87aec511c05c11a7506b75c57e6be8126cb65f78a23044c01900").into(), // stash account  (sr25519/1)
            hex!("f4e1380cc76c60f4c421786886dc5098b47e9f134b9ded433cd6da6a1bb92966").unchecked_into(), // babe key (sr25519/2)
            hex!("53a12d8d226f80be461f18382c4ea35651453fa9cbdcba29b0efc14666d4f1c6").unchecked_into(), // grandpa key (ed25519)
            hex!("5467a46fa49bf85da193f3b97bfa524c0cbc56f75d2857950b330d133f62ad5c").unchecked_into(), // im online key (sr25519/2)
            hex!("b2dfedccc5fcfd5006f5e0b93fbc0149cae00874e16373d06b2286521a2a317f").unchecked_into(), // validator key (sr25519/2)
            hex!("fa7afeb74fe6defd6e384e457ed9bbe4d2fe00d9f263e80cb99b3078dd23b568").unchecked_into(), // assignment key (sr25519/2)
            hex!("76552222c64285c84c073cf7a87326a9fd7dd8df5223d68302174e2b2ae59419").unchecked_into(), // authority discovery key (sr25519/2)
            get_from_seed::<BeefyId>("4")
        ),
    ];

    let mut endowed_accounts = initial_paseo_validators.iter()
    .map(|validator| validator.0.clone()) 
    .collect::<Vec<_>>(); 

    // Add Faucet
    endowed_accounts.push(hex!("e21bb02f2a82cb1113ff10693093377672925b23f047624c0cfa7a24a8609841").into());


    paseo_genesis(
        wasm_binary,
        // initial authorities
        initial_paseo_validators,
        //root key
        root_key.clone(),
        // endowed accounts
        endowed_accounts,
    )
}

/// Paseo local config (multivalidator Alice + Bob)
pub fn paseo_local_config() -> Result<Box<dyn ChainSpec>, String> {
    let wasm_binary = paseo_runtime::WASM_BINARY.ok_or("Paseo development wasm not available")?;

    Ok(Box::new(PaseoChainSpec::from_genesis(
        "Paseo Local Testnet",
        "paseo-local",
        ChainType::Local,
        move || paseo_local_genesis(wasm_binary),
        vec![],
        None,
        Some(DEFAULT_PROTOCOL_ID),
        None,
        Some(paseo_chain_spec_properties()),
        Default::default(),
    )))
}

/// Paseo config
pub fn paseo_config() -> Result<Box<dyn ChainSpec>, String> {
    let wasm_binary = paseo_runtime::WASM_BINARY.ok_or("Paseo wasm not available")?;

    Ok(Box::new(PaseoChainSpec::from_genesis(
        "Paseo Testnet",
        "paseo",
        ChainType::Live,
        move || paseo_config_genesis(wasm_binary),
        vec![],
        None,
        Some(DEFAULT_PROTOCOL_ID),
        None,
        Some(paseo_chain_spec_properties()),
        Default::default(),
    )))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_parachains_host_configuration_is_consistent() {
        default_parachains_host_configuration().panic_if_not_consistent();
    }
}
