const binding = require('./index.js')
const secp256k1 = require('@noble/secp256k1')

function hexToUint8Array(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('Expected a string')
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even length')
  }
  const arr = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16)
    if (isNaN(byte)) {
      throw new Error(`Invalid hex byte: ${hex.slice(i, i + 2)}`)
    }
    arr[i / 2] = byte
  }
  return arr
}

function uint8ArrayToHex(arr) {
  if (!(arr instanceof Uint8Array)) {
    throw new TypeError('Expected a Uint8Array')
  }
  return Array.from(arr)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function log(msg, ...args) {
  console.log(`index.js: ${msg}`, ...args)
}

log('binding.hello()', binding.hello())

console.log('\n')

log(
  `binding.createDummyTx("bcrt1qnuyejmm2l4kavspq0jqaw0fv07lg6zv3z9z3te", 10000n):`
)
const successResult = binding.createDummyTx(
  'bcrt1qnuyejmm2l4kavspq0jqaw0fv07lg6zv3z9z3te',
  10000n
)
log('dummyTx:', successResult)

console.log('\n')

try {
  log(`binding.createDummyTx("this_address_will_error", 10000n):`)
  const errResult = binding.createDummyTx('this_address_will_error', 10000n)
} catch (e) {
  log(e)
}

console.log('\n')

try {
  log(`binding.createDummyTx("bcrt1qnuyejmm2l4kavspq0jqaw0fv07lg6zv3z9z3te"):`)
  const errResult = binding.createDummyTx(
    'bcrt1qnuyejmm2l4kavspq0jqaw0fv07lg6zv3z9z3te'
  )
} catch (e) {
  log(e)
}

console.log('\n')

const plaintext = new Uint8Array([1, 2, 3, 4])
// Dummy public key (65-byte uncompressed secp256k1 full of 0x02 values just for example)
const pk = new Uint8Array(33).fill(2)
try {
  log('binding.encryptEcies(plaintext, pk):')
  const cipher = binding.encryptEcies(plaintext, pk)
  log('ciphertext length', cipher.length)
} catch (e) {
  log(e)
}

console.log('\n')

const privKey = new Uint8Array(32).fill(1)
const pubKey = secp256k1.getPublicKey(privKey, true)
const pt2 = new Uint8Array([10, 11, 12])
try {
  log('binding.encryptEcies(pt2, pubKey):')
  const ct2 = binding.encryptEcies(pt2, pubKey)
  log('binding.decryptEcies(ct2, privKey):')
  const dec2 = binding.decryptEcies(ct2, privKey)
  log('decrypt success:', Buffer.from(dec2).equals(Buffer.from(pt2)))
} catch (e) {
  log(e)
}

console.log('\n')

log('signFrost smoke test (expect error)')
try {
  binding.signFrost(
    new Uint8Array([1, 2, 3]),
    {
      secretKey: new Uint8Array([0]),
      publicKey: new Uint8Array([0]),
      verifyingKey: new Uint8Array([0])
    },
    { hiding: new Uint8Array([0]), binding: new Uint8Array([0]) },
    { hiding: new Uint8Array([0]), binding: new Uint8Array([0]) },
    {},
    null
  )
} catch (e) {
  log('signFrost returned error as expected', e.message || e)
}

console.log('\n')

log('signFrost with valid params')

// input {"message":"309cfa947e5132b6a8dfec4f7c5a2b118f6a6339b29bb5f9eda67772cc4ca2ab","keyPackage":{"secretKey":"ea55351bebc990fb9e2c20f6e4172334c37c2ee644bd77830b2181da7dc4d991","publicKey":"035e8f0057ae1d51ff2e88586bd5bf2e16bd87a3c4aac68945cbc96017e080e26e","verifyingKey":"0265c8a4fd5613f89fbd88713ae6707d5bde332a35fc69bae105a10bbb93431480"},"nonce":{"binding":"1b1cce7906d81a968deebf5ba8c8e2e72d05bfebfdab899326fd5d97dd4e8aef","hiding":"977e1e21064e00f0ca089e923fc303375fe370f7b62c954cd76cde5a6ef0dc9c"},"selfCommitment":{"binding":"035e38cdc33fd24dee735dc398dafd4d8c9e44da6aa45576b184786b517b8d61f1","hiding":"02e15ecb9c56f12ba55f47264f3dd21748b578dc5ffd26201547103e02fb281864"},"statechainCommitments":{"0000000000000000000000000000000000000000000000000000000000000002":{"binding":"0259f706606ecf5ef4fa02f5109c1e498c75b4c679d3410e6248a343bdf6419921","hiding":"024acf3d72ce07efaf55f2229895faa936a9c8aa635198953096b7c30ad69492ea"},"0000000000000000000000000000000000000000000000000000000000000003":{"binding":"03e9ba1827a469d925cc286f18a7cd1122bcd866f6263f8c49f0441f9d61226e32","hiding":"021cf1b3646f95cc6b2f8fd60290733b97bcafab8f0c513289c319bada58c5e01e"}},"adaptorPubKey":""}
// expected: 2ee25c78d61fc3ae8e4c91059369f23fd7a04ea54a43afe1f681276a063659e2
try {
  const message = hexToUint8Array(
    '309cfa947e5132b6a8dfec4f7c5a2b118f6a6339b29bb5f9eda67772cc4ca2ab'
  )
  const keyPackage = {
    secretKey: hexToUint8Array(
      'ea55351bebc990fb9e2c20f6e4172334c37c2ee644bd77830b2181da7dc4d991'
    ),
    publicKey: hexToUint8Array(
      '035e8f0057ae1d51ff2e88586bd5bf2e16bd87a3c4aac68945cbc96017e080e26e'
    ),
    verifyingKey: hexToUint8Array(
      '0265c8a4fd5613f89fbd88713ae6707d5bde332a35fc69bae105a10bbb93431480'
    )
  }
  const nonce = {
    hiding: hexToUint8Array(
      '977e1e21064e00f0ca089e923fc303375fe370f7b62c954cd76cde5a6ef0dc9c'
    ),
    binding: hexToUint8Array(
      '1b1cce7906d81a968deebf5ba8c8e2e72d05bfebfdab899326fd5d97dd4e8aef'
    )
  }
  const selfCommitment = {
    hiding: hexToUint8Array(
      '02e15ecb9c56f12ba55f47264f3dd21748b578dc5ffd26201547103e02fb281864'
    ),
    binding: hexToUint8Array(
      '035e38cdc33fd24dee735dc398dafd4d8c9e44da6aa45576b184786b517b8d61f1'
    )
  }
  const statechainCommitments = [
    [
      '0000000000000000000000000000000000000000000000000000000000000003',
      {
        hiding: hexToUint8Array(
          '021cf1b3646f95cc6b2f8fd60290733b97bcafab8f0c513289c319bada58c5e01e'
        ),
        binding: hexToUint8Array(
          '03e9ba1827a469d925cc286f18a7cd1122bcd866f6263f8c49f0441f9d61226e32'
        )
      }
    ],
    [
      '0000000000000000000000000000000000000000000000000000000000000002',
      {
        hiding: hexToUint8Array(
          '024acf3d72ce07efaf55f2229895faa936a9c8aa635198953096b7c30ad69492ea'
        ),
        binding: hexToUint8Array(
          '0259f706606ecf5ef4fa02f5109c1e498c75b4c679d3410e6248a343bdf6419921'
        )
      }
    ]
  ]
  const adaptorPubKey = null

  const result = binding.signFrost(
    message,
    keyPackage,
    nonce,
    selfCommitment,
    statechainCommitments,
    adaptorPubKey
  )
  log('signFrost result:', result)
  const hexResult = uint8ArrayToHex(result)
  if (
    hexResult !==
    '2ee25c78d61fc3ae8e4c91059369f23fd7a04ea54a43afe1f681276a063659e2'
  ) {
    throw new Error(`Unexpected result: ${hexResult}`)
  } else {
    log('signFrost success')
  }
} catch (e) {
  log('signFrost error:', e.message || e)
}

console.log('\n')

console.log('\n')

log('aggregateFrost smoke test (expect error)')

try {
  binding.aggregateFrost(
    new Uint8Array([1, 2, 3]),
    [
      {
        secretKey: new Uint8Array([0]),
        publicKey: new Uint8Array([0]),
        verifyingKey: new Uint8Array([0])
      }
    ],
    { hiding: new Uint8Array([0]), binding: new Uint8Array([0]) },
    { hiding: new Uint8Array([0]), binding: new Uint8Array([0]) },
    {},
    null
  )
} catch (e) {
  log('aggregateFrost returned error as expected', e.message || e)
}
