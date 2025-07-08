import { FRAGMENT as LeavesSwapRequestFragment } from "../objects/LeavesSwapRequest.js";

export const RequestSwapLeaves = `
  mutation RequestSwapLeaves(
    $adaptor_pubkey: PublicKey!
    $total_amount_sats: Long!
    $target_amount_sats: Long!
    $fee_sats: Long!
    $user_leaves: [UserLeafInput!]!
    $idempotency_key: String!
    $target_amount_sats_list: [Long!]
  ) {
    request_leaves_swap(input: {
      adaptor_pubkey: $adaptor_pubkey
      total_amount_sats: $total_amount_sats
      target_amount_sats: $target_amount_sats
      fee_sats: $fee_sats
      user_leaves: $user_leaves
      idempotency_key: $idempotency_key
      target_amount_sats_list: $target_amount_sats_list
    }) {
      request {
        ...LeavesSwapRequestFragment
      }
    }
  }
  ${LeavesSwapRequestFragment}
`;
