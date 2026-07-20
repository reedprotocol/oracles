pub type Er2Red {
  r_num: Int,
  r_denom: Int,
  u_num: Int,
  u_denom: Int,
}

pub type PoolDatum {
  r_num: Int,
  r_denom: Int,
  created_at: Int,
}

pub type ErPythParams {
  pyth_policy_id: ByteArray,
  pyth_feed_id: Int,
  pyth_freshness_us: Int,
  pyth_min_publishers: Int,
  pool_anchor_policy: ByteArray,
  pool_anchor_name: ByteArray,
  pool_freshness_ms: Int,
  max_tx_range_ms: Int,
  max_confidence_bps: Int,
  admin_pkh: ByteArray,
}
