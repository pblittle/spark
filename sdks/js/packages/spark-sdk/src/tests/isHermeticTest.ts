export const isHermeticTest = Boolean(
  typeof process !== "undefined" && process?.env?.HERMETIC_TEST === "true",
);
