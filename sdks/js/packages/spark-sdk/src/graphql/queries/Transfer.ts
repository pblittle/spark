import { FRAGMENT as TransferFragment } from "../objects/Transfer.js";

export const GetTransfer = `
  query Transfer($transfer_spark_id: UUID!) {
    transfer(transfer_spark_id: $transfer_spark_id) {
      ...TransferFragment
    }
  }
  ${TransferFragment}
`;
