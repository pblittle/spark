
// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved





interface RequestLightningSendInput {


    encodedInvoice: string;

    idempotencyKey: string;

    /**
 * The amount you will pay for this invoice in sats. It should ONLY be set when the invoice amount is
 * zero.
**/
amountSats?: number | undefined;




}

export const RequestLightningSendInputFromJson = (obj: any): RequestLightningSendInput => {
    return {
        encodedInvoice: obj["request_lightning_send_input_encoded_invoice"],
        idempotencyKey: obj["request_lightning_send_input_idempotency_key"],
        amountSats: obj["request_lightning_send_input_amount_sats"],

        } as RequestLightningSendInput;

}
export const RequestLightningSendInputToJson = (obj: RequestLightningSendInput): any => {
return {
request_lightning_send_input_encoded_invoice: obj.encodedInvoice,
request_lightning_send_input_idempotency_key: obj.idempotencyKey,
request_lightning_send_input_amount_sats: obj.amountSats,

        }

}





export default RequestLightningSendInput;
