# reed protocol — exchange rate validators

On-chain validators for reed's dual-rate oracle system on Cardano. Built with [Aiken](https://aiken-lang.org/) and Plutus V3.

## Validators

### [er_pyth.ak]

Validates the `Er2Red` redeemer (REE/ADA and USD/ADA rate fractions) against two independent rate sources before allowing the exchange rate script to withdraw:

- **USD/ADA** from [Pyth Lazer](https://docs.pyth.network/price-feeds/lazer) price feeds — checks publisher count, freshness, confidence interval, and exponent bounds
- **REE/ADA** from an on-chain pool oracle UTxO — checks anchor NFT authenticity, datum freshness, and positive rational validation

### [oracle_controller.ak]

Manages the REE/ADA pool oracle UTxO on-chain using an anchor NFT:

- **Mint** — creates the anchor NFT at a unique seed UTxO
- **Update** — anyone can update the oracle datum, provided it matches live DEX pool reserves exactly and respects a rate-limit interval
- **Retire** — burns the anchor NFT permanently
 
## Tests
 
```sh
aiken check
Each validator includes tests for happy paths, parameter sanity, adversarial oracle data, pool datum edge cases, redeemer mismatches, and access control.

Dependencies
Aiken Standard Library v3.0.0
Pyth Lazer Cardano SDK

License
Apache-2.0
