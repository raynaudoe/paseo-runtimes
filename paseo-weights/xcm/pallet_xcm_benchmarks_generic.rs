// Copyright (C) Parity Technologies and the various Polkadot contributors, see Contributions.md
// for a list of specific contributors.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Autogenerated weights for `pallet_xcm_benchmarks::generic`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2024-09-12, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `zur1-vm-benchpas-001`, CPU: `AMD EPYC 9354 32-Core Processor`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("./paseo-chain-spec.json")`, DB CACHE: 1024

// Executed Command:
// ./polkadot
// benchmark
// pallet
// --chain=./paseo-chain-spec.json
// --steps=50
// --repeat=20
// --pallet=pallet_xcm_benchmarks::generic
// --extrinsic=*
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./paseo-weights/xcm/pallet_xcm_benchmarks_generic.rs
// --header=./file_header.txt

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_xcm_benchmarks::generic`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_xcm_benchmarks::generic::WeightInfo for WeightInfo<T> {
	/// Storage: `Dmp::DeliveryFeeFactor` (r:1 w:0)
	/// Proof: `Dmp::DeliveryFeeFactor` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `XcmPallet::SupportedVersion` (r:1 w:0)
	/// Proof: `XcmPallet::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueues` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueues` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Dmp::DownwardMessageQueueHeads` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueueHeads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn report_holding() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `215`
		//  Estimated: `3680`
		// Minimum execution time: 47_081_000 picoseconds.
		Weight::from_parts(51_557_000, 0)
			.saturating_add(Weight::from_parts(0, 3680))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	fn buy_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 500_000 picoseconds.
		Weight::from_parts(681_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	/// Storage: `XcmPallet::Queries` (r:1 w:0)
	/// Proof: `XcmPallet::Queries` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn query_response() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `3465`
		// Minimum execution time: 3_225_000 picoseconds.
		Weight::from_parts(3_755_000, 0)
			.saturating_add(Weight::from_parts(0, 3465))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	fn transact() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 4_667_000 picoseconds.
		Weight::from_parts(7_031_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn refund_surplus() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 891_000 picoseconds.
		Weight::from_parts(951_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn set_error_handler() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 551_000 picoseconds.
		Weight::from_parts(820_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn set_appendix() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 531_000 picoseconds.
		Weight::from_parts(702_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn clear_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 511_000 picoseconds.
		Weight::from_parts(842_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn descend_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 781_000 picoseconds.
		Weight::from_parts(931_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn clear_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 591_000 picoseconds.
		Weight::from_parts(991_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	/// Storage: `Dmp::DeliveryFeeFactor` (r:1 w:0)
	/// Proof: `Dmp::DeliveryFeeFactor` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `XcmPallet::SupportedVersion` (r:1 w:0)
	/// Proof: `XcmPallet::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueues` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueues` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Dmp::DownwardMessageQueueHeads` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueueHeads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn report_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `215`
		//  Estimated: `3680`
		// Minimum execution time: 44_647_000 picoseconds.
		Weight::from_parts(47_341_000, 0)
			.saturating_add(Weight::from_parts(0, 3680))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `XcmPallet::AssetTraps` (r:1 w:1)
	/// Proof: `XcmPallet::AssetTraps` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn claim_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `23`
		//  Estimated: `3488`
		// Minimum execution time: 5_538_000 picoseconds.
		Weight::from_parts(5_928_000, 0)
			.saturating_add(Weight::from_parts(0, 3488))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	fn trap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 501_000 picoseconds.
		Weight::from_parts(781_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	/// Storage: `XcmPallet::VersionNotifyTargets` (r:1 w:1)
	/// Proof: `XcmPallet::VersionNotifyTargets` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DeliveryFeeFactor` (r:1 w:0)
	/// Proof: `Dmp::DeliveryFeeFactor` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `XcmPallet::SupportedVersion` (r:1 w:0)
	/// Proof: `XcmPallet::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueues` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueues` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueueHeads` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueueHeads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn subscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `114`
		//  Estimated: `3579`
		// Minimum execution time: 26_811_000 picoseconds.
		Weight::from_parts(32_089_000, 0)
			.saturating_add(Weight::from_parts(0, 3579))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	/// Storage: `XcmPallet::VersionNotifyTargets` (r:0 w:1)
	/// Proof: `XcmPallet::VersionNotifyTargets` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn unsubscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 2_394_000 picoseconds.
		Weight::from_parts(3_476_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	fn burn_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 861_000 picoseconds.
		Weight::from_parts(1_251_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn expect_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 651_000 picoseconds.
		Weight::from_parts(952_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn expect_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 671_000 picoseconds.
		Weight::from_parts(821_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn expect_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 582_000 picoseconds.
		Weight::from_parts(782_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn expect_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 671_000 picoseconds.
		Weight::from_parts(1_001_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	/// Storage: `Dmp::DeliveryFeeFactor` (r:1 w:0)
	/// Proof: `Dmp::DeliveryFeeFactor` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `XcmPallet::SupportedVersion` (r:1 w:0)
	/// Proof: `XcmPallet::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueues` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueues` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Dmp::DownwardMessageQueueHeads` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueueHeads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn query_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `215`
		//  Estimated: `3680`
		// Minimum execution time: 51_979_000 picoseconds.
		Weight::from_parts(59_189_000, 0)
			.saturating_add(Weight::from_parts(0, 3680))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	fn expect_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 6_470_000 picoseconds.
		Weight::from_parts(6_780_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	/// Storage: `Dmp::DeliveryFeeFactor` (r:1 w:0)
	/// Proof: `Dmp::DeliveryFeeFactor` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `XcmPallet::SupportedVersion` (r:1 w:0)
	/// Proof: `XcmPallet::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Dmp::DownwardMessageQueues` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueues` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// Storage: `Dmp::DownwardMessageQueueHeads` (r:1 w:1)
	/// Proof: `Dmp::DownwardMessageQueueHeads` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn report_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `215`
		//  Estimated: `3680`
		// Minimum execution time: 44_166_000 picoseconds.
		Weight::from_parts(46_970_000, 0)
			.saturating_add(Weight::from_parts(0, 3680))
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	fn clear_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 541_000 picoseconds.
		Weight::from_parts(601_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn set_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 481_000 picoseconds.
		Weight::from_parts(531_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn clear_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 511_000 picoseconds.
		Weight::from_parts(831_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn set_fees_mode() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 630_000 picoseconds.
		Weight::from_parts(961_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
	fn unpaid_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 541_000 picoseconds.
		Weight::from_parts(841_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
}
