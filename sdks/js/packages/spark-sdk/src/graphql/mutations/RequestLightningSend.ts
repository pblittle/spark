import { FRAGMENT as RequestLightningSendOutputFragment } from "../objects/LightningSendRequest.js";
export const RequestLightningSend = `
  mutation RequestLightningSend(
    $encoded_invoice: String!
    $idempotency_key: String!
    $amount_sats: Long
  ) {
    request_lightning_send(input: {
      encoded_invoice: $encoded_invoice
      idempotency_key: $idempotency_key
      amount_sats: $amount_sats
    }) {
      request {
        ...LightningSendRequestFragment
      }
    }
  }
  ${RequestLightningSendOutputFragment}
`;
