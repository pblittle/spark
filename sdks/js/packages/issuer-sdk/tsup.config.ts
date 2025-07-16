import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/proto/spark.ts",
  ],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  inject: ['./buffer.js'],
});
