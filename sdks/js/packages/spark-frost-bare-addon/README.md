# Bare addon for Spark SDK

This package provides Spark frost signer bindings for use in [Bare runtime](https://bare.pears.com/). The WASM bindings used for Node.js and browsers in spark-sdk are not supported in all Bare environments (e.g. < iOS 18.4).

Running bare with `yarn bare` and `yarn bare-make` is recommended to use the version installed in the workspaces. Alternatively you can install globally with npm:

```sh
npm i -g bare bare-make
```

# Build

```sh
yarn build

# Test the addon
yarn bare index.js
```

On MacOS be sure to prioritize the system toolchain instead of homebrew, otherwise you'll encounter errors for bare-make commands:

```sh
export PATH="/usr/bin:$PATH"
```

As mentioned in the [simple bare addon guide](https://github.com/holepunchto/bare-snippets/tree/main/addon-support) run the following:

```sh
yarn

cd spark-frost-bare-addon

# To build for spark-bare-expo-react-native-app
yarn bare-make generate --platform ios --arch arm64 --simulator && yarn bare-make build && yarn bare-make install
# This seems to be necessary to build/install an additional target, otherwise it reuses the previous target:
rm -rf build

yarn bare-make generate --platform ios --arch arm64 && yarn bare-make build && yarn bare-make install
rm -rf build

yarn bare-make generate --platform ios --arch x64 && yarn bare-make build && yarn bare-make install
rm -rf build

# Target the current platform
yarn bare-make generate && yarn bare-make build && yarn bare-make install

# Test the addon
yarn bare index.js
```
