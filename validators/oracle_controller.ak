use aiken/collection/list
use aiken/interval.{Finite, Interval, between}
use aiken/primitive/bytearray
use cardano/address.{Address, Script, from_script, from_verification_key}
use cardano/assets.{add, from_lovelace, lovelace_of, quantity_of, zero}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, placeholder}

use er_validator/helpers as h
use er_validator/types.{PoolDatum}

fn get_bounds(validity_range: Interval) -> (Int, Int) {
  expect Finite(lb) = validity_range.lower_bound.bound_type
  expect Finite(ub) = validity_range.upper_bound.bound_type
  (lb, ub)
}

// ═══════════════════════════════════════════════════════════
//  Admin script for REE/ADA oracle UTxO
// ═══════════════════════════════════════════════════════════
//
//  Charli3-style anchor NFT oracle. The anchor NFT uniquely
//  identifies the current/latest oracle UTxO. When anyone
//  updates the rate, the anchor NFT moves from the old UTxO
//  to the new UTxO at the same script address.
//
//  Security model:
//  - Update: permissionless. Anyone can spend the oracle UTxO
//    to produce a successor at the same address, provided the
//    new datum mirrors the live DEX pool reserves and respects
//    the rate-limit interval.
//  - Retire: admin-only. The admin can spend the oracle UTxO
//    without producing a successor, effectively shutting down.
//  - The anchor NFT enforces continuity: you cannot spend
//    the oracle UTxO without producing a successor at the
//    same address that also holds the anchor NFT (Update).
//  - er_pyth.ak validates the UTxO by checking:
//      (a) Address payment credential == pool_anchor_policy (script hash)
//      (b) Anchor NFT quantity == 1
//      (c) Freshness bounds
//  - Output datum is validated to be a well-formed PoolDatum
//    with positive rational components (defense in depth).

pub type AnchorRed {
  Update
  Retire
}

validator oracle_controller(
  admin_pkh: ByteArray,
  anchor_name: ByteArray,
  pool_address: Address,
  pool_nft_policy: ByteArray,
  pool_nft_name: ByteArray,
  ree_policy: ByteArray,
  ree_name: ByteArray,
  min_update_interval_ms: Int,
  seed_oref: OutputReference,
) {
  // ── Mint: create the anchor NFT (once only) or burn it ──
  mint(_red, policy_id: ByteArray, tx: Transaction) {
    expect bytearray.length(admin_pkh) == 28
    expect bytearray.length(anchor_name) > 0
    expect bytearray.length(pool_nft_policy) == 28
    expect bytearray.length(pool_nft_name) > 0
    expect min_update_interval_ms > 0

    // Admin must sign.
    expect list.any(tx.extra_signatories, fn(pk) { pk == admin_pkh })

    let mint_qty = quantity_of(tx.mint, policy_id, anchor_name)

    if mint_qty == 1 {
      // One-shot: must be the FIRST mint. We enforce this by
      // requiring consumption of a unique seed UTxO that can only
      // be spent once, plus verifying no input already holds the
      // anchor NFT (defense in depth).
      expect list.any(tx.inputs, fn(i) { i.output_reference == seed_oref })

      let already_exists =
        list.any(tx.inputs, fn(i) {
          quantity_of(i.output.value, policy_id, anchor_name) > 0
        })
      expect !already_exists

      // The minted NFT must go to an output at this validator's
      // address (Script(policy_id)) with a well-formed datum.
      let valid_outputs =
        list.filter(
          tx.outputs,
          fn(o) {
            when o.address.payment_credential is {
              Script(hash) ->
                hash == policy_id &&
                  quantity_of(o.value, policy_id, anchor_name) == 1
              _ -> False
            }
          },
        )
      expect [anchored_output] = valid_outputs
      expect InlineDatum(d) = anchored_output.datum
      expect datum: PoolDatum = d
      expect h.check_pos_rational(datum.r_num, datum.r_denom)

      // created_at must be within tx validity range (prevents stale/future).
      let (lb, ub) = get_bounds(tx.validity_range)
      expect datum.created_at >= lb
      expect datum.created_at <= ub

      True
    } else if mint_qty == -1 {
      // Burn: admin can destroy the anchor NFT permanently.
      True
    } else {
      fail @"oracle_controller: invalid mint quantity"
    }
  }

  // ── Spend: update or retire ──
  spend(datum_opt: Option<PoolDatum>, red: AnchorRed, oref: OutputReference, tx: Transaction) {
    expect bytearray.length(admin_pkh) == 28
    expect bytearray.length(anchor_name) > 0
    expect bytearray.length(pool_nft_policy) == 28
    expect bytearray.length(pool_nft_name) > 0

    // Find the input being spent and extract its policy ID
    // (the script hash doubles as the NFT policy).
    let own_input_opt =
      list.find(tx.inputs, fn(i) { i.output_reference == oref })
    expect Some(own_input) = own_input_opt
    let own_address = own_input.output.address
    expect Script(own_policy_id) = own_address.payment_credential

    when red is {
      Update -> {
        // Permissionless: anyone can update the oracle datum.
        // The spent input must hold the anchor NFT.
        expect quantity_of(own_input.output.value, own_policy_id, anchor_name) == 1

        // Read the old datum to enforce rate-limit.
        expect Some(old_datum) = datum_opt

        // Exactly one output at the same address must hold
        // the anchor NFT (continuity).
        let anchored_outputs =
          list.filter(
            tx.outputs,
            fn(o) {
              o.address == own_address &&
                quantity_of(o.value, own_policy_id, anchor_name) == 1
            },
          )
        expect [_] = anchored_outputs

        // Output datum must be well-formed.
        expect Some(anchored_output) = list.head(anchored_outputs)
        expect InlineDatum(d) = anchored_output.datum
        expect datum: PoolDatum = d
        expect h.check_pos_rational(datum.r_num, datum.r_denom)

        // Rate-limit: new datum must be at least min_update_interval_ms
        // after the previous one (prevents DoS by rapid spending).
        expect datum.created_at >= old_datum.created_at + min_update_interval_ms

        // Verify the datum matches the DEX pool reserves exactly.
        // We require the Pool NFT (e.g. Minswap MSP) to uniquely
        // identify the legitimate pool UTxO and reject donations
        // or fake UTxOs at the same address.
        let pool_ref_opt =
          list.find(
            tx.reference_inputs,
            fn(i) {
              i.output.address == pool_address &&
                quantity_of(i.output.value, pool_nft_policy, pool_nft_name) == 1 &&
                quantity_of(i.output.value, ree_policy, ree_name) > 0
            },
          )
        expect Some(pool_ref) = pool_ref_opt
        let ada_reserve = lovelace_of(pool_ref.output.value)
        let ree_reserve = quantity_of(pool_ref.output.value, ree_policy, ree_name)
        expect datum.r_num == ada_reserve
        expect datum.r_denom == ree_reserve

        // Verify created_at is within the tx validity range so the
        // datum timestamp is honest (prevents stale/future griefing).
        let (lb, ub) = get_bounds(tx.validity_range)
        expect datum.created_at >= lb
        expect datum.created_at <= ub

        True
      }
      Retire -> {
        // Admin-only: spend the oracle UTxO and burn the anchor NFT.
        expect list.any(tx.extra_signatories, fn(pk) { pk == admin_pkh })
        expect quantity_of(own_input.output.value, own_policy_id, anchor_name) == 1
        // The NFT must be burned in this tx (permanent destruction).
        expect quantity_of(tx.mint, own_policy_id, anchor_name) == -1
        True
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════
//  Test fixtures
// ═══════════════════════════════════════════════════════════

const test_admin_pkh: ByteArray =
  #"a36234ef3749a2c94136b6345bceff450791ef1ebc99e918f16f8075"

// The script hash doubles as the NFT minting policy.
const test_script_hash: ByteArray =
  #"f1e9f10d06ac319b53b5bf72e723e92d4aa3ef6d4f5414b109359b2b"

const test_anchor_name: ByteArray = "REE/ADA"

// Testnet pool params (preprod or mainnet values passed at deploy time)
const test_pool_address: Address = from_script(#"aabbccddeeff00112233445566778899aabbccddeeff001122334455")
const test_pool_nft_policy: ByteArray = #"aabbccddeeff00112233445566778899aabbccddeeff001122334456"
const test_pool_nft_name: ByteArray = "MSP"
const test_ree_policy: ByteArray = #"e7befada6a028d4bd20ae87edecf1ca04d65a1ff57b9f84f0d9847d2"
const test_ree_name: ByteArray = "REE"

const test_min_update_interval: Int = 900_000  // 15 minutes

const test_seed_oref: OutputReference =
  OutputReference {
    transaction_id: placeholder.id,
    output_index: 42,
  }

fn make_seed_input() -> Input {
  Input {
    output_reference: test_seed_oref,
    output: Output {
      address: from_verification_key(#"aabbccddeeff00112233445566778899aabbccddeeff00112233"),
      value: from_lovelace(2_000_000),
      datum: InlineDatum(Void),
      reference_script: None,
    },
  }
}

fn make_oracle_datum() -> PoolDatum {
  PoolDatum { r_num: 500, r_denom: 1000, created_at: 0 }
}

fn make_oracle_datum_at(ts: Int) -> PoolDatum {
  PoolDatum { r_num: 500, r_denom: 1000, created_at: ts }
}

fn make_oracle_value() {
  from_lovelace(2_000_000) |> add(test_script_hash, test_anchor_name, 1)
}

fn make_oracle_output(datum: PoolDatum) -> Output {
  Output {
    address: from_script(test_script_hash),
    value: make_oracle_value(),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn make_oracle_input(datum: PoolDatum) -> Input {
  let oref = OutputReference { transaction_id: placeholder.id, output_index: 0 }
  Input {
    output_reference: oref,
    output: make_oracle_output(datum),
  }
}

fn make_pool_ref_input(ada_amount: Int, ree_amount: Int) -> Input {
  let oref = OutputReference { transaction_id: placeholder.id, output_index: 99 }
  Input {
    output_reference: oref,
    output: Output {
      address: test_pool_address,
      value: from_lovelace(ada_amount)
        |> add(test_ree_policy, test_ree_name, ree_amount)
        |> add(test_pool_nft_policy, test_pool_nft_name, 1),
      datum: InlineDatum(Void),
      reference_script: None,
    },
  }
}

fn make_spend_tx_at(
  input: Input,
  outputs: List<Output>,
  signers: List<ByteArray>,
  ref_inputs: List<Input>,
  lb: Int,
  ub: Int,
  mint_value,
) -> Transaction {
  Transaction {
    ..placeholder,
    inputs: [input],
    outputs: outputs,
    extra_signatories: signers,
    reference_inputs: ref_inputs,
    validity_range: between(lb, ub),
    mint: mint_value,
  }
}

// ═══════════════════════════════════════════════════════════
//  Happy path
// ═══════════════════════════════════════════════════════════

test update_happy_path() {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  // Successor is 15min after old datum; tx validity covers that exact moment.
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

// ═══════════════════════════════════════════════════════════
//  Update adversarial tests
// ═══════════════════════════════════════════════════════════

test update_missing_anchor_in_output() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let bad_out = Output {
    ..make_oracle_output(new_datum),
    value: from_lovelace(2_000_000),
  }
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [bad_out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_missing_anchor_in_input() fail {
  let old_datum = make_oracle_datum()
  let input =
    Input {
      ..make_oracle_input(old_datum),
      output: Output {
        ..make_oracle_output(old_datum),
        value: from_lovelace(2_000_000),
      },
    }
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_multiple_anchored_outputs() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out1 = make_oracle_output(new_datum)
  let out2 = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out1, out2], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_bad_datum_r_num_zero() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = PoolDatum { ..make_oracle_datum_at(test_min_update_interval), r_num: 0 }
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(0, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_bad_datum_r_denom_zero() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = PoolDatum { ..make_oracle_datum_at(test_min_update_interval), r_denom: 0 }
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 0)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_missing_pool_ref() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  let tx = make_spend_tx_at(input, [out], [], [], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_mismatched_ada_reserve() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  // Pool has 999 ADA but datum says 500
  let pool_ref = make_pool_ref_input(999, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_mismatched_ree_reserve() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  // Pool has 2000 REE but datum says 1000
  let pool_ref = make_pool_ref_input(500, 2000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_too_soon() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  // New datum only 1 min after old one — violates 15 min rate limit
  let new_datum = make_oracle_datum_at(60_000)
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], 60_000, 60_000, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_created_at_before_lb() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  // created_at is 1 ms before tx validity lower bound
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval + 1, test_min_update_interval + 1, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_created_at_after_ub() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  // created_at is 1 ms after tx validity upper bound
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  let pool_ref = make_pool_ref_input(500, 1000)
  let tx = make_spend_tx_at(input, [out], [], [pool_ref], test_min_update_interval - 1, test_min_update_interval - 1, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

test update_pool_ref_missing_ree() fail {
  let old_datum = make_oracle_datum()
  let input = make_oracle_input(old_datum)
  let oref = input.output_reference
  let new_datum = make_oracle_datum_at(test_min_update_interval)
  let out = make_oracle_output(new_datum)
  // Pool ref at correct address but holds 0 REE tokens
  let bad_pool_ref =
    Input {
      ..make_pool_ref_input(500, 1000),
      output: Output {
        ..make_pool_ref_input(500, 1000).output,
        value: from_lovelace(500),
      },
    }
  let tx = make_spend_tx_at(input, [out], [], [bad_pool_ref], test_min_update_interval, test_min_update_interval, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Some(old_datum), Update, oref, tx)
}

// ═══════════════════════════════════════════════════════════
//  Mint tests
// ═══════════════════════════════════════════════════════════

fn make_mint_tx(outputs: List<Output>, signers: List<ByteArray>, inputs: List<Input>, mint_value) -> Transaction {
  Transaction {
    ..placeholder,
    inputs: inputs,
    outputs: outputs,
    extra_signatories: signers,
    mint: mint_value,
    validity_range: between(0, 0),
  }
}

test mint_happy_path() {
  let datum = make_oracle_datum()
  let out = make_oracle_output(datum)
  let seed = make_seed_input()
  let tx = make_mint_tx([out], [test_admin_pkh], [seed], add(zero, test_script_hash, test_anchor_name, 1))
  oracle_controller.mint(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Void, test_script_hash, tx)
}

test mint_already_exists() fail {
  let datum = make_oracle_datum()
  let existing_input = make_oracle_input(datum)
  let seed = make_seed_input()
  let out = make_oracle_output(datum)
  let tx = make_mint_tx([out], [test_admin_pkh], [seed, existing_input], add(zero, test_script_hash, test_anchor_name, 1))
  oracle_controller.mint(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Void, test_script_hash, tx)
}

test mint_non_admin_fails() fail {
  let datum = make_oracle_datum()
  let out = make_oracle_output(datum)
  let seed = make_seed_input()
  let tx = make_mint_tx([out], [#"00000000000000000000000000000000000000000000000000000000"], [seed], add(zero, test_script_hash, test_anchor_name, 1))
  oracle_controller.mint(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Void, test_script_hash, tx)
}

test mint_created_at_out_of_bounds() fail {
  // created_at = 1 but tx validity is [0, 0]
  let datum = PoolDatum { ..make_oracle_datum(), created_at: 1 }
  let out = make_oracle_output(datum)
  let seed = make_seed_input()
  let tx = make_mint_tx([out], [test_admin_pkh], [seed], add(zero, test_script_hash, test_anchor_name, 1))
  oracle_controller.mint(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Void, test_script_hash, tx)
}

test mint_missing_seed_fails() fail {
  let datum = make_oracle_datum()
  let out = make_oracle_output(datum)
  // No seed input provided
  let tx = make_mint_tx([out], [test_admin_pkh], [], add(zero, test_script_hash, test_anchor_name, 1))
  oracle_controller.mint(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, Void, test_script_hash, tx)
}

// ═══════════════════════════════════════════════════════════
//  Retire tests
// ═══════════════════════════════════════════════════════════

const burn_mint = add(zero, test_script_hash, test_anchor_name, -1)

test retire_happy_path() {
  let datum = make_oracle_datum()
  let input = make_oracle_input(datum)
  let oref = input.output_reference
  // Retire: admin burns the anchor NFT and claims assets
  let tx = make_spend_tx_at(input, [], [test_admin_pkh], [], 0, 0, burn_mint)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, None, Retire, oref, tx)
}

test retire_non_admin_fails() fail {
  let datum = make_oracle_datum()
  let input = make_oracle_input(datum)
  let oref = input.output_reference
  let tx = make_spend_tx_at(input, [], [#"00000000000000000000000000000000000000000000000000000000"], [], 0, 0, burn_mint)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, None, Retire, oref, tx)
}

test retire_without_burn_fails() fail {
  let datum = make_oracle_datum()
  let input = make_oracle_input(datum)
  let oref = input.output_reference
  // Admin signs but forgets to burn the NFT
  let tx = make_spend_tx_at(input, [], [test_admin_pkh], [], 0, 0, zero)
  oracle_controller.spend(test_admin_pkh, test_anchor_name, test_pool_address, test_pool_nft_policy, test_pool_nft_name, test_ree_policy, test_ree_name, test_min_update_interval, test_seed_oref, None, Retire, oref, tx)
}
