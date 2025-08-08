import { useState, useEffect } from "react";
import { Text } from "react-native";
import { Worklet } from "react-native-bare-kit";
import b4a from "b4a";

export default function () {
  const [response, setReponse] = useState<string | null>(null);

  useEffect(() => {
    const worklet = new Worklet();

    const source = `
    const { IPC } = BareKit

    IPC.on('data', (data) => console.log(data.toString()))
    IPC.write(Buffer.from('Hello from Bare!'))

    const spark = require('@buildonspark/spark-frost-bare-addon')

    const hello = spark.hello()
    console.log('hello:', hello)

    const dummy = spark.createDummyTx(
      'bcrt1qnuyejmm2l4kavspq0jqaw0fv07lg6zv3z9z3te',
      10000n
    )
    console.log('dummy txid', dummy.txid)
    `;

    worklet.start("/app.js", source);

    const { IPC } = worklet;

    IPC.on("data", (data: Uint8Array) => setReponse(b4a.toString(data)));
    IPC.write(b4a.from("Hello from React Native!"));
  }, []);

  return <Text>{response}</Text>;
}
