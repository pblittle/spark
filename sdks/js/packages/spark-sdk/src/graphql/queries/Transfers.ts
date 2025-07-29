import { FRAGMENT as TransferFragment } from "../objects/Transfer.js";

export const GetTransfers = `
  query Transfers($transfer_spark_ids: [UUID!]!) {
    transfers(transfer_spark_ids: $transfer_spark_ids) {
      ...TransferFragment
    }
  }
  ${TransferFragment}
`;
