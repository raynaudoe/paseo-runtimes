// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
	AccountId, AllPalletsWithSystem, AssetConversion, Assets, Authorship, Balance, Balances,
	CollatorSelection, ForeignAssets, NativeAndAssets, ParachainInfo, ParachainSystem, PolkadotXcm,
	PoolAssets, PriceForParentDelivery, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin,
	TrustBackedAssetsInstance, WeightToFee, XcmpQueue,
};
use crate::ForeignAssetsInstance;
use assets_common::{
	matching::{FromSiblingParachain, IsForeignConcreteAsset},
	TrustBackedAssetsAsLocation,
};
use frame_support::{
	parameter_types,
	traits::{
		tokens::imbalance::ResolveAssetTo, ConstU32, Contains, Equals, Everything, Nothing,
		PalletInfoAccess,
	},
};
use frame_system::EnsureRoot;
use pallet_xcm::XcmPassthrough;
use parachains_common::{
	impls::ToStakingPot,
	xcm_config::{
		AllSiblingSystemParachains, AssetFeeAsExistentialDepositMultiplier,
		ConcreteAssetFromSystem, ParentRelayOrSiblingParachains, RelayOrOtherSystemParachains,
	},
};
use paseo_runtime_constants::system_parachain;
use polkadot_parachain_primitives::primitives::Sibling;
use sp_runtime::traits::{AccountIdConversion, ConvertInto};
use system_parachains_constants::TREASURY_PALLET_ID;
use xcm::latest::prelude::*;
use xcm_builder::{
	AccountId32Aliases, AllowExplicitUnpaidExecutionFrom, AllowKnownQueryResponses,
	AllowSubscriptionsFrom, AllowTopLevelPaidExecutionFrom, DenyReserveTransferToRelayChain,
	DenyThenTry, DescribeAllTerminal, DescribeFamily, EnsureXcmOrigin, FrameTransactionalProcessor,
	FungibleAdapter, FungiblesAdapter, GlobalConsensusParachainConvertsFor, HashedDescription,
	IsConcrete, LocalMint, NoChecking, ParentAsSuperuser, ParentIsPreset, RelayChainAsNative,
	SiblingParachainAsNative, SiblingParachainConvertsVia, SignedAccountId32AsNative,
	SignedToAccountId32, SovereignSignedViaLocation, StartsWith, StartsWithExplicitGlobalConsensus,
	TakeWeightCredit, TrailingSetTopicAsId, UsingComponents, WeightInfoBounds, WithComputedOrigin,
	WithUniqueTopic, XcmFeeManagerFromComponents, XcmFeeToAccount,
};

use xcm_executor::{
	traits::{ConvertLocation, WithOriginFilter},
	XcmExecutor,
};

parameter_types! {
	pub const DotLocation: Location = Location::parent();
	pub const DotLocationV3: xcm::v3::Location = xcm::v3::Location::parent();
	pub const RelayNetwork: Option<NetworkId> = Some(NetworkId::Polkadot);
	pub RelayChainOrigin: RuntimeOrigin = cumulus_pallet_xcm::Origin::Relay.into();
	pub UniversalLocation: InteriorLocation =
		[GlobalConsensus(RelayNetwork::get().unwrap()), Parachain(ParachainInfo::parachain_id().into())].into();
	pub UniversalLocationNetworkId: NetworkId = UniversalLocation::get().global_consensus().unwrap();
	pub TrustBackedAssetsPalletIndex: u8 = <Assets as PalletInfoAccess>::index() as u8;
	pub TrustBackedAssetsPalletLocation: Location =
		PalletInstance(TrustBackedAssetsPalletIndex::get()).into();
	pub TrustBackedAssetsPalletLocationV3: xcm::v3::Location =
		xcm::v3::Junction::PalletInstance(TrustBackedAssetsPalletIndex::get()).into();
	pub CheckingAccount: AccountId = PolkadotXcm::check_account();
	pub FellowshipLocation: Location = Location::new(1, Parachain(system_parachain::COLLECTIVES_ID));
	pub const GovernanceLocation: Location = Location::parent();
	pub RelayTreasuryLocation: Location = (Parent, PalletInstance(paseo_runtime_constants::TREASURY_PALLET_ID)).into();
	pub TreasuryAccount: AccountId = TREASURY_PALLET_ID.into_account_truncating();
	pub PoolAssetsPalletLocation: Location =
		PalletInstance(<PoolAssets as PalletInfoAccess>::index() as u8).into();
	pub StakingPot: AccountId = CollatorSelection::account_id();
	// Test [`crate::tests::treasury_pallet_account_not_none`] ensures that the result of location
	// conversion is not `None`.
	pub RelayTreasuryPalletAccount: AccountId =
		LocationToAccountId::convert_location(&RelayTreasuryLocation::get())
			.unwrap_or(TreasuryAccount::get());
}

/// Type for specifying how a `Location` can be converted into an `AccountId`. This is used
/// when determining ownership of accounts for asset transacting and when attempting to use XCM
/// `Transact` in order to determine the dispatch Origin.
pub type LocationToAccountId = (
	// The parent (Relay-chain) origin converts to the parent `AccountId`.
	ParentIsPreset<AccountId>,
	// Sibling parachain origins convert to AccountId via the `ParaId::into`.
	SiblingParachainConvertsVia<Sibling, AccountId>,
	// Straight up local `AccountId32` origins just alias directly to `AccountId`.
	AccountId32Aliases<RelayNetwork, AccountId>,
	// Foreign locations alias into accounts according to a hash of their standard description.
	HashedDescription<AccountId, DescribeFamily<DescribeAllTerminal>>,
	// Different global consensus parachain sovereign account.
	// (Used for over-bridge transfers and reserve processing)
	GlobalConsensusParachainConvertsFor<UniversalLocation, AccountId>,
);

/// Means for transacting the native currency on this chain.
pub type FungibleTransactor = FungibleAdapter<
	// Use this currency:
	Balances,
	// Use this currency when it is a fungible asset matching the given location or name:
	IsConcrete<DotLocation>,
	// Convert an XCM `Location` into a local account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We don't track any teleports of `Balances`.
	(),
>;

/// `AssetId`/`Balance` converter for `TrustBackedAssets`.
pub type TrustBackedAssetsConvertedConcreteId =
	assets_common::TrustBackedAssetsConvertedConcreteId<TrustBackedAssetsPalletLocation, Balance>;

/// Means for transacting assets besides the native currency on this chain.
pub type FungiblesTransactor = FungiblesAdapter<
	// Use this fungibles implementation:
	Assets,
	// Use this currency when it is a fungible asset matching the given location or name:
	TrustBackedAssetsConvertedConcreteId,
	// Convert an XCM `Location` into a local account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We only want to allow teleports of known assets. We use non-zero issuance as an indication
	// that this asset is known.
	LocalMint<parachains_common::impls::NonZeroIssuance<AccountId, Assets>>,
	// The account to use for tracking teleports.
	CheckingAccount,
>;

/// `AssetId`/`Balance` converter for `ForeignAssets`
pub type ForeignAssetsConvertedConcreteId = assets_common::ForeignAssetsConvertedConcreteId<
	(
		// Ignore `TrustBackedAssets` explicitly
		StartsWith<TrustBackedAssetsPalletLocation>,
		// Ignore assets that start explicitly with our `GlobalConsensus(NetworkId)`, means:
		// - foreign assets from our consensus should be: `Location {parents: 1, X*(Parachain(xyz),
		//   ..)}`
		// - foreign assets outside our consensus with the same `GlobalConsensus(NetworkId)` won't
		//   be accepted here
		StartsWithExplicitGlobalConsensus<UniversalLocationNetworkId>,
	),
	Balance,
>;

/// Means for transacting foreign assets from different global consensus.
pub type ForeignFungiblesTransactor = FungiblesAdapter<
	// Use this fungibles implementation:
	ForeignAssets,
	// Use this currency when it is a fungible asset matching the given location or name:
	ForeignAssetsConvertedConcreteId,
	// Convert an XCM `Location` into a local account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We dont need to check teleports here.
	NoChecking,
	// The account to use for tracking teleports.
	CheckingAccount,
>;

/// `AssetId`/`Balance` converter for `PoolAssets`.
pub type PoolAssetsConvertedConcreteId =
	assets_common::PoolAssetsConvertedConcreteId<PoolAssetsPalletLocation, Balance>;

/// Means for transacting asset conversion pool assets on this chain.
pub type PoolFungiblesTransactor = FungiblesAdapter<
	// Use this fungibles implementation:
	PoolAssets,
	// Use this currency when it is a fungible asset matching the given location or name:
	PoolAssetsConvertedConcreteId,
	// Convert an XCM `Location` into a local account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We only want to allow teleports of known assets. We use non-zero issuance as an indication
	// that this asset is known.
	LocalMint<parachains_common::impls::NonZeroIssuance<AccountId, PoolAssets>>,
	// The account to use for tracking teleports.
	CheckingAccount,
>;

/// Means for transacting assets on this chain.
pub type AssetTransactors =
	(FungibleTransactor, FungiblesTransactor, ForeignFungiblesTransactor, PoolFungiblesTransactor);

/// This is the type we use to convert an (incoming) XCM origin into a local `Origin` instance,
/// ready for dispatching a transaction with Xcm's `Transact`. There is an `OriginKind` which can
/// biases the kind of local `Origin` it will become.
pub type XcmOriginToTransactDispatchOrigin = (
	// Sovereign account converter; this attempts to derive an `AccountId` from the origin location
	// using `LocationToAccountId` and then turn that into the usual `Signed` origin. Useful for
	// foreign chains who want to have a local sovereign account on this chain which they control.
	SovereignSignedViaLocation<LocationToAccountId, RuntimeOrigin>,
	// Native converter for Relay-chain (Parent) location; will convert to a `Relay` origin when
	// recognised.
	RelayChainAsNative<RelayChainOrigin, RuntimeOrigin>,
	// Native converter for sibling Parachains; will convert to a `SiblingPara` origin when
	// recognised.
	SiblingParachainAsNative<cumulus_pallet_xcm::Origin, RuntimeOrigin>,
	// Superuser converter for the Relay-chain (Parent) location. This will allow it to issue a
	// transaction from the Root origin.
	ParentAsSuperuser<RuntimeOrigin>,
	// Native signed account converter; this just converts an `AccountId32` origin into a normal
	// `RuntimeOrigin::Signed` origin of the same 32-byte value.
	SignedAccountId32AsNative<RelayNetwork, RuntimeOrigin>,
	// Xcm origins can be represented natively under the Xcm pallet's Xcm origin.
	XcmPassthrough<RuntimeOrigin>,
);

parameter_types! {
	pub const MaxInstructions: u32 = 100;
	pub const MaxAssetsIntoHolding: u32 = 64;
	pub XcmAssetFeesReceiver: Option<AccountId> = Authorship::author();
}

pub struct FellowshipEntities;
impl Contains<Location> for FellowshipEntities {
	fn contains(location: &Location) -> bool {
		matches!(
			location.unpack(),
			(
				1,
				[
					Parachain(system_parachain::COLLECTIVES_ID),
					Plurality { id: BodyId::Technical, .. }
				]
			)
		)
	}
}

pub struct ParentOrParentsPlurality;
impl Contains<Location> for ParentOrParentsPlurality {
	fn contains(location: &Location) -> bool {
		matches!(location.unpack(), (1, []) | (1, [Plurality { .. }]))
	}
}

/// A call filter for the XCM Transact instruction. This is a temporary measure until we properly
/// account for proof size weights.
///
/// Calls that are allowed through this filter must:
/// 1. Have a fixed weight;
/// 2. Cannot lead to another call being made;
/// 3. Have a defined proof size weight, e.g. no unbounded vecs in call parameters.
pub struct SafeCallFilter;
impl Contains<RuntimeCall> for SafeCallFilter {
	fn contains(call: &RuntimeCall) -> bool {
		#[cfg(feature = "runtime-benchmarks")]
		{
			if matches!(call, RuntimeCall::System(frame_system::Call::remark_with_event { .. })) {
				return true;
			}
		}

		matches!(
			call,
			RuntimeCall::PolkadotXcm(
				pallet_xcm::Call::force_xcm_version { .. }
					| pallet_xcm::Call::force_default_xcm_version { .. }
			) | RuntimeCall::System(
				frame_system::Call::set_heap_pages { .. }
					| frame_system::Call::set_code { .. }
					| frame_system::Call::set_code_without_checks { .. }
					| frame_system::Call::kill_prefix { .. },
			) | RuntimeCall::ParachainSystem(..)
				| RuntimeCall::Timestamp(..)
				| RuntimeCall::Balances(..)
				| RuntimeCall::CollatorSelection(
					pallet_collator_selection::Call::set_desired_candidates { .. }
						| pallet_collator_selection::Call::set_candidacy_bond { .. }
						| pallet_collator_selection::Call::register_as_candidate { .. }
						| pallet_collator_selection::Call::leave_intent { .. }
						| pallet_collator_selection::Call::set_invulnerables { .. }
						| pallet_collator_selection::Call::add_invulnerable { .. }
						| pallet_collator_selection::Call::remove_invulnerable { .. },
				) | RuntimeCall::Session(pallet_session::Call::purge_keys { .. })
				| RuntimeCall::XcmpQueue(..)
				| RuntimeCall::DmpQueue(..)
				| RuntimeCall::Assets(
					pallet_assets::Call::create { .. }
						| pallet_assets::Call::force_create { .. }
						| pallet_assets::Call::start_destroy { .. }
						| pallet_assets::Call::destroy_accounts { .. }
						| pallet_assets::Call::destroy_approvals { .. }
						| pallet_assets::Call::finish_destroy { .. }
						| pallet_assets::Call::mint { .. }
						| pallet_assets::Call::burn { .. }
						| pallet_assets::Call::transfer { .. }
						| pallet_assets::Call::transfer_keep_alive { .. }
						| pallet_assets::Call::force_transfer { .. }
						| pallet_assets::Call::freeze { .. }
						| pallet_assets::Call::thaw { .. }
						| pallet_assets::Call::freeze_asset { .. }
						| pallet_assets::Call::thaw_asset { .. }
						| pallet_assets::Call::transfer_ownership { .. }
						| pallet_assets::Call::set_team { .. }
						| pallet_assets::Call::set_metadata { .. }
						| pallet_assets::Call::clear_metadata { .. }
						| pallet_assets::Call::force_set_metadata { .. }
						| pallet_assets::Call::force_clear_metadata { .. }
						| pallet_assets::Call::force_asset_status { .. }
						| pallet_assets::Call::approve_transfer { .. }
						| pallet_assets::Call::cancel_approval { .. }
						| pallet_assets::Call::force_cancel_approval { .. }
						| pallet_assets::Call::transfer_approved { .. }
						| pallet_assets::Call::touch { .. }
						| pallet_assets::Call::refund { .. },
				) | RuntimeCall::ForeignAssets(
				pallet_assets::Call::create { .. }
					| pallet_assets::Call::force_create { .. }
					| pallet_assets::Call::start_destroy { .. }
					| pallet_assets::Call::destroy_accounts { .. }
					| pallet_assets::Call::destroy_approvals { .. }
					| pallet_assets::Call::finish_destroy { .. }
					| pallet_assets::Call::mint { .. }
					| pallet_assets::Call::burn { .. }
					| pallet_assets::Call::transfer { .. }
					| pallet_assets::Call::transfer_keep_alive { .. }
					| pallet_assets::Call::force_transfer { .. }
					| pallet_assets::Call::freeze { .. }
					| pallet_assets::Call::thaw { .. }
					| pallet_assets::Call::freeze_asset { .. }
					| pallet_assets::Call::thaw_asset { .. }
					| pallet_assets::Call::transfer_ownership { .. }
					| pallet_assets::Call::set_team { .. }
					| pallet_assets::Call::set_metadata { .. }
					| pallet_assets::Call::clear_metadata { .. }
					| pallet_assets::Call::force_set_metadata { .. }
					| pallet_assets::Call::force_clear_metadata { .. }
					| pallet_assets::Call::force_asset_status { .. }
					| pallet_assets::Call::approve_transfer { .. }
					| pallet_assets::Call::cancel_approval { .. }
					| pallet_assets::Call::force_cancel_approval { .. }
					| pallet_assets::Call::transfer_approved { .. }
					| pallet_assets::Call::touch { .. }
					| pallet_assets::Call::refund { .. },
			) | RuntimeCall::Nfts(
				pallet_nfts::Call::create { .. }
					| pallet_nfts::Call::force_create { .. }
					| pallet_nfts::Call::destroy { .. }
					| pallet_nfts::Call::mint { .. }
					| pallet_nfts::Call::force_mint { .. }
					| pallet_nfts::Call::burn { .. }
					| pallet_nfts::Call::transfer { .. }
					| pallet_nfts::Call::lock_item_transfer { .. }
					| pallet_nfts::Call::unlock_item_transfer { .. }
					| pallet_nfts::Call::lock_collection { .. }
					| pallet_nfts::Call::transfer_ownership { .. }
					| pallet_nfts::Call::set_team { .. }
					| pallet_nfts::Call::force_collection_owner { .. }
					| pallet_nfts::Call::force_collection_config { .. }
					| pallet_nfts::Call::approve_transfer { .. }
					| pallet_nfts::Call::cancel_approval { .. }
					| pallet_nfts::Call::clear_all_transfer_approvals { .. }
					| pallet_nfts::Call::lock_item_properties { .. }
					| pallet_nfts::Call::set_attribute { .. }
					| pallet_nfts::Call::force_set_attribute { .. }
					| pallet_nfts::Call::clear_attribute { .. }
					| pallet_nfts::Call::approve_item_attributes { .. }
					| pallet_nfts::Call::cancel_item_attributes_approval { .. }
					| pallet_nfts::Call::set_metadata { .. }
					| pallet_nfts::Call::clear_metadata { .. }
					| pallet_nfts::Call::set_collection_metadata { .. }
					| pallet_nfts::Call::clear_collection_metadata { .. }
					| pallet_nfts::Call::set_accept_ownership { .. }
					| pallet_nfts::Call::set_collection_max_supply { .. }
					| pallet_nfts::Call::update_mint_settings { .. }
					| pallet_nfts::Call::set_price { .. }
					| pallet_nfts::Call::buy_item { .. }
					| pallet_nfts::Call::pay_tips { .. }
					| pallet_nfts::Call::create_swap { .. }
					| pallet_nfts::Call::cancel_swap { .. }
					| pallet_nfts::Call::claim_swap { .. },
			) | RuntimeCall::Uniques(
				pallet_uniques::Call::create { .. }
					| pallet_uniques::Call::force_create { .. }
					| pallet_uniques::Call::destroy { .. }
					| pallet_uniques::Call::mint { .. }
					| pallet_uniques::Call::burn { .. }
					| pallet_uniques::Call::transfer { .. }
					| pallet_uniques::Call::freeze { .. }
					| pallet_uniques::Call::thaw { .. }
					| pallet_uniques::Call::freeze_collection { .. }
					| pallet_uniques::Call::thaw_collection { .. }
					| pallet_uniques::Call::transfer_ownership { .. }
					| pallet_uniques::Call::set_team { .. }
					| pallet_uniques::Call::approve_transfer { .. }
					| pallet_uniques::Call::cancel_approval { .. }
					| pallet_uniques::Call::force_item_status { .. }
					| pallet_uniques::Call::set_attribute { .. }
					| pallet_uniques::Call::clear_attribute { .. }
					| pallet_uniques::Call::set_metadata { .. }
					| pallet_uniques::Call::clear_metadata { .. }
					| pallet_uniques::Call::set_collection_metadata { .. }
					| pallet_uniques::Call::clear_collection_metadata { .. }
					| pallet_uniques::Call::set_accept_ownership { .. }
					| pallet_uniques::Call::set_collection_max_supply { .. }
					| pallet_uniques::Call::set_price { .. }
					| pallet_uniques::Call::buy_item { .. }
			) | RuntimeCall::PoolAssets(..)
				| RuntimeCall::AssetConversion(..)
		)
	}
}

pub type Barrier = TrailingSetTopicAsId<
	DenyThenTry<
		DenyReserveTransferToRelayChain,
		(
			TakeWeightCredit,
			// Expected responses are OK.
			AllowKnownQueryResponses<PolkadotXcm>,
			// Allow XCMs with some computed origins to pass through.
			WithComputedOrigin<
				(
					// If the message is one that immediately attempts to pay for execution, then
					// allow it.
					AllowTopLevelPaidExecutionFrom<Everything>,
					// The locations listed below get free execution.
					// Parent, its pluralities (i.e. governance bodies), the Fellows plurality and
					// sibling bridge hub get free execution.
					AllowExplicitUnpaidExecutionFrom<(
						ParentOrParentsPlurality,
						FellowshipEntities,
						Equals<RelayTreasuryLocation>,
						Equals<bridging::SiblingBridgeHub>,
					)>,
					// Subscriptions for version tracking are OK.
					AllowSubscriptionsFrom<ParentRelayOrSiblingParachains>,
				),
				UniversalLocation,
				ConstU32<8>,
			>,
		),
	>,
>;

pub type AssetFeeAsExistentialDepositMultiplierFeeCharger = AssetFeeAsExistentialDepositMultiplier<
	Runtime,
	WeightToFee,
	pallet_assets::BalanceToAssetBalance<Balances, Runtime, ConvertInto, TrustBackedAssetsInstance>,
	TrustBackedAssetsInstance,
>;

/// Locations that will not be charged fees in the executor,
/// either execution or delivery.
/// We only waive fees for system functions, which these locations represent.
pub type WaivedLocations = (
	RelayOrOtherSystemParachains<AllSiblingSystemParachains, Runtime>,
	Equals<RelayTreasuryLocation>,
	FellowshipEntities,
);

/// Cases where a remote origin is accepted as trusted Teleporter for a given asset:
///
/// - DOT with the parent Relay Chain and sibling system parachains; and
/// - Sibling parachains' assets from where they originate (as `ForeignCreators`).
pub type TrustedTeleporters = (
	ConcreteAssetFromSystem<DotLocation>,
	IsForeignConcreteAsset<FromSiblingParachain<parachain_info::Pallet<Runtime>>>,
);

/// Multiplier used for dedicated `TakeFirstAssetTrader` with `ForeignAssets` instance.
pub type ForeignAssetFeeAsExistentialDepositMultiplierFeeCharger =
	AssetFeeAsExistentialDepositMultiplier<
		Runtime,
		WeightToFee,
		pallet_assets::BalanceToAssetBalance<Balances, Runtime, ConvertInto, ForeignAssetsInstance>,
		ForeignAssetsInstance,
	>;

pub struct XcmConfig;
impl xcm_executor::Config for XcmConfig {
	type RuntimeCall = RuntimeCall;
	type XcmSender = XcmRouter;
	type AssetTransactor = AssetTransactors;
	type OriginConverter = XcmOriginToTransactDispatchOrigin;
	// Until we can bridge to westend, no reserves from now.
	type IsReserve = ();
	type IsTeleporter = TrustedTeleporters;
	type UniversalLocation = UniversalLocation;
	type Barrier = Barrier;
	type Weigher = WeightInfoBounds<
		crate::weights::xcm::AssetHubPolkadotXcmWeight<RuntimeCall>,
		RuntimeCall,
		MaxInstructions,
	>;
	type Trader = (
		UsingComponents<WeightToFee, DotLocation, AccountId, Balances, ToStakingPot<Runtime>>,
		// This trader allows to pay with any assets exchangeable to DOT with
		// [`AssetConversion`].
		cumulus_primitives_utility::SwapFirstAssetTrader<
			DotLocationV3,
			AssetConversion,
			WeightToFee,
			NativeAndAssets,
			(
				TrustBackedAssetsAsLocation<TrustBackedAssetsPalletLocation, Balance>,
				ForeignAssetsConvertedConcreteId,
			),
			ResolveAssetTo<StakingPot, NativeAndAssets>,
			AccountId,
		>,
		// This trader allows to pay with `is_sufficient=true` "Trust Backed" assets from dedicated
		// `pallet_assets` instance - `Assets`.
		cumulus_primitives_utility::TakeFirstAssetTrader<
			AccountId,
			AssetFeeAsExistentialDepositMultiplierFeeCharger,
			TrustBackedAssetsConvertedConcreteId,
			Assets,
			cumulus_primitives_utility::XcmFeesTo32ByteAccount<
				FungiblesTransactor,
				AccountId,
				XcmAssetFeesReceiver,
			>,
		>,
		// This trader allows to pay with `is_sufficient=true` "Foreign" assets from dedicated
		// `pallet_assets` instance - `ForeignAssets`.
		cumulus_primitives_utility::TakeFirstAssetTrader<
			AccountId,
			ForeignAssetFeeAsExistentialDepositMultiplierFeeCharger,
			ForeignAssetsConvertedConcreteId,
			ForeignAssets,
			cumulus_primitives_utility::XcmFeesTo32ByteAccount<
				ForeignFungiblesTransactor,
				AccountId,
				XcmAssetFeesReceiver,
			>,
		>,
	);
	type ResponseHandler = PolkadotXcm;
	type AssetTrap = PolkadotXcm;
	type AssetClaims = PolkadotXcm;
	type SubscriptionService = PolkadotXcm;
	type PalletInstancesInfo = AllPalletsWithSystem;
	type MaxAssetsIntoHolding = MaxAssetsIntoHolding;
	type AssetLocker = ();
	type AssetExchanger = ();
	type FeeManager = XcmFeeManagerFromComponents<
		WaivedLocations,
		XcmFeeToAccount<Self::AssetTransactor, AccountId, RelayTreasuryPalletAccount>,
	>;
	type MessageExporter = ();
	type UniversalAliases = Nothing;
	type CallDispatcher = WithOriginFilter<SafeCallFilter>;
	type SafeCallFilter = SafeCallFilter;
	type Aliasers = Nothing;
	type TransactionalProcessor = FrameTransactionalProcessor;
}

/// Converts a local signed origin into an XCM multilocation.
/// Forms the basis for local origins sending/executing XCMs.
pub type LocalOriginToLocation = SignedToAccountId32<RuntimeOrigin, AccountId, RelayNetwork>;

/// For routing XCM messages which do not cross local consensus boundary.
type LocalXcmRouter = (
	// Two routers - use UMP to communicate with the relay chain:
	cumulus_primitives_utility::ParentAsUmp<ParachainSystem, PolkadotXcm, PriceForParentDelivery>,
	// ..and XCMP to communicate with the sibling chains.
	XcmpQueue,
);

/// The means for routing XCM messages which are not for local execution into the right message
/// queues.
pub type XcmRouter = WithUniqueTopic<
	// The means for routing XCM messages which are not for local execution into the right message
	// queues.
	LocalXcmRouter,
>;

impl pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// We want to disallow users sending (arbitrary) XCMs from this chain.
	type SendXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, ()>;
	type XcmRouter = XcmRouter;
	// We support local origins dispatching XCM executions in principle...
	type ExecuteXcmOrigin = EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
	// ... but disallow generic XCM execution. As a result only teleports and reserve transfers are
	// allowed.
	type XcmExecuteFilter = Nothing;
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type XcmTeleportFilter = Everything;
	type XcmReserveTransferFilter = Everything;
	type Weigher = WeightInfoBounds<
		crate::weights::xcm::AssetHubPolkadotXcmWeight<RuntimeCall>,
		RuntimeCall,
		MaxInstructions,
	>;
	type UniversalLocation = UniversalLocation;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	const VERSION_DISCOVERY_QUEUE_SIZE: u32 = 100;
	type AdvertisedXcmVersion = pallet_xcm::CurrentXcmVersion;
	type Currency = Balances;
	type CurrencyMatcher = ();
	type TrustedLockers = ();
	type SovereignAccountOf = LocationToAccountId;
	type MaxLockers = ConstU32<8>;
	type WeightInfo = crate::weights::pallet_xcm::WeightInfo<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type ReachableDest = ReachableDest;
	type AdminOrigin = EnsureRoot<AccountId>;
	type MaxRemoteLockConsumers = ConstU32<0>;
	type RemoteLockConsumerIdentifier = ();
}

impl cumulus_pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type XcmExecutor = XcmExecutor<XcmConfig>;
}

pub type ForeignCreatorsSovereignAccountOf = (
	SiblingParachainConvertsVia<Sibling, AccountId>,
	AccountId32Aliases<RelayNetwork, AccountId>,
	ParentIsPreset<AccountId>,
);

/// Simple conversion of `u32` into an `AssetId` for use in benchmarking.
pub struct XcmBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_assets::BenchmarkHelper<xcm::v3::Location> for XcmBenchmarkHelper {
	fn create_asset_id_parameter(id: u32) -> xcm::v3::Location {
		xcm::v3::Location::new(1, xcm::v3::Junction::Parachain(id))
	}
}

/// All configuration related to bridging
pub mod bridging {
	use super::*;

	parameter_types! {
		/// Price of every byte of the Polkadot -> Kusama message. Can be adjusted via
		/// governance `set_storage` call.
		pub storage XcmBridgeHubRouterByteFee: Balance = 10;

		pub SiblingBridgeHubParaId: u32 = 1002;
		pub SiblingBridgeHub: Location = Location::new(1, Parachain(SiblingBridgeHubParaId::get()));
		/// Router expects payment with this `AssetId`.
		/// (`AssetId` has to be aligned with `BridgeTable`)
		pub XcmBridgeHubRouterFeeAssetId: AssetId = DotLocation::get().into();
	}

	/// Benchmarks helper for bridging configuration.
	#[cfg(feature = "runtime-benchmarks")]
	pub struct BridgingBenchmarksHelper;

	#[cfg(feature = "runtime-benchmarks")]
	impl BridgingBenchmarksHelper {
		pub fn prepare_universal_alias() -> Option<(Location, Junction)> {
			None
		}
	}
}

#[test]
fn foreign_pallet_has_correct_local_account() {
	use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};
	use xcm_executor::traits::ConvertLocation;

	const COLLECTIVES_PARAID: u32 = 1001;
	const FELLOWSHIP_SALARY_PALLET_ID: u8 = 64;
	let fellowship_salary =
		(Parent, Parachain(COLLECTIVES_PARAID), PalletInstance(FELLOWSHIP_SALARY_PALLET_ID));
	let account = LocationToAccountId::convert_location(&fellowship_salary.into()).unwrap();
	let polkadot = Ss58AddressFormat::try_from("polkadot").unwrap();
	let address = Ss58Codec::to_ss58check_with_version(&account, polkadot);
	assert_eq!(address, "13w7NdvSR1Af8xsQTArDtZmVvjE8XhWNdL4yed3iFHrUNCnS");
}
